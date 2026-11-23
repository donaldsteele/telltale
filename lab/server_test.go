//go:build lab

package lab

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/donaldsteele/bubbles/pkg/bubblesclient"
	"github.com/donaldsteele/bubbles/pkg/protocol"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/donaldsteele/telltale/internal/redact"
	"github.com/donaldsteele/telltale/internal/server"
	"github.com/donaldsteele/telltale/lab/labkit"
)

// The end-to-end test of server mode. compose.server.yml brings up a
// telltale server (scripts/build.sh's binaries), a bubbles server, a
// Debian 12 machine and an Ubuntu 24.04 machine on which every temporary
// directory but /root is mounted noexec. The owner's part goes through the
// web UI's real forms (the one-time setup code, CSRF tokens, the
// confirmation pages), the chat admin's through bubbles' admin API, and the
// assistant's through telltale mcp on the host.

const (
	e2eProject = "telltale-lab-e2e"
	e2eCompose = "compose.server.yml"
	e2ePort    = "8443"
	e2eChannel = "telltale-alerts"
	// e2eVisitLimit bounds one visit, from Check now to its report. The
	// first visit of a machine verifies its packages against the archives.
	e2eVisitLimit = 25 * time.Minute
)

// What the breaks change: the root key the root-key break adds
// (breaks/root-key/apply.sh), and the sshd drop-in in which
// regress-root-login turns root login back on, as finding key and line.
const (
	plantedKeyLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIEEHeD7aE8BzppJ7cPpeQnB7ZqgTT21bHJP6e40Gsq0 lab-attacker@nowhere"
	dropInKey      = "snap.persist:/etc/ssh/sshd_config.d/00-lab.conf"
	dropInLine     = "PermitRootLogin yes"
)

func TestServerEndToEnd(t *testing.T) {
	if labkit.Emulated() {
		t.Skipf("the end-to-end test runs on the host's architecture only, not TELLTALE_LAB_ARCH=%s", labkit.Arch)
	}
	for _, d := range []string{"debian12", "ubuntu2404"} {
		if !wantDistro(d) {
			t.Skipf("TELLTALE_LAB_DISTROS leaves out %s", d)
		}
	}
	labkit.RequireFree(t)
	began := time.Now()
	phase := func(what string, since time.Time) {
		t.Logf("timing: %s took %v", what, time.Since(since).Round(time.Second))
	}

	// Images and binaries.
	start := time.Now()
	debImage := labkit.Build(t, "debian12", "clean")
	ubuImage := labkit.Build(t, "ubuntu2404", "noexec")
	bubImage := bubblesImage(t)
	baseImage := serverBaseImage(t)
	dist := buildDist(t)
	phase("images and scripts/build.sh", start)

	// The server's configuration: it listens on its fixed address on the
	// lab network, which is also the address machines see it connect from.
	labkit.Networks(t)
	serverIP := lastHost(labkit.Subnet(t))
	cfgDir := t.TempDir()
	cfg := filepath.Join(cfgDir, "telltale.toml")
	writeFile(t, cfg, fmt.Sprintf("listen = %q\ndata_dir = \"/var/lib/telltale\"\nbin_dir = \"/opt/telltale/collector\"\n", serverIP.String()+":"+e2ePort), 0o644)
	cache := filepath.Join(labkit.CacheDir(), "server-pkgcache")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	e := &e2eLab{t: t, serverIP: serverIP.String(), env: []string{
		"TELLTALE_LAB_SERVER_IMAGE=" + baseImage,
		"TELLTALE_LAB_ARCH=" + runtime.GOARCH,
		"TELLTALE_LAB_UID=" + strconv.Itoa(os.Getuid()),
		"TELLTALE_LAB_GID=" + strconv.Itoa(os.Getgid()),
		"TELLTALE_PASSPHRASE=" + randomText(t),
		"TELLTALE_LAB_DIST_DIR=" + dist,
		"TELLTALE_LAB_CONFIG=" + cfg,
		"TELLTALE_LAB_PKGCACHE=" + cache,
		"TELLTALE_LAB_SERVER_IP=" + serverIP.String(),
		"TELLTALE_LAB_BUBBLES_IMAGE=" + bubImage,
		"TELLTALE_LAB_DEBIAN12_IMAGE=" + debImage,
		"TELLTALE_LAB_UBUNTU2404_NOEXEC_IMAGE=" + ubuImage,
	}, ctrs: map[string]string{}}
	e.up()

	// The server prints its certificate's fingerprint and the one-time
	// setup code at start.
	start = time.Now()
	var certFP, setupCode, sshLine string
	waitFor(t, 2*time.Minute, "the server to print its fingerprint and setup code", func() bool {
		log := e.logs("server")
		certFP = firstGroup(certFPRE, log)
		setupCode = firstGroup(setupCodeRE, log)
		sshLine = firstGroup(sshKeyRE, log)
		return certFP != "" && setupCode != "" && sshLine != ""
	})
	if !strings.HasSuffix(sshLine, "machines see this server as "+e.serverIP) {
		t.Fatalf("the server says %q; machines must see it as %s", sshLine, e.serverIP)
	}
	base := "https://" + e.serverIP + ":" + e2ePort
	e.ui = newBrowser(t, base, certFP)
	waitFor(t, time.Minute, "the web UI", func() bool { _, err := e.ui.try(http.MethodGet, "/setup", nil); return err == nil })
	phase("server start", start)

	// The owner sets the admin password with the setup code, logs in,
	// makes new machines manual-only (so no scheduled visit runs between
	// the test's steps), and makes a token for telltale mcp.
	p := e.ui.get("/")
	if p.path != "/setup" {
		t.Fatalf("a new server sends the browser to %s, want /setup", p.path)
	}
	password := randomText(t)
	p = e.ui.post("/setup", url.Values{"csrf": {csrfOf(t, p)}, "code": {setupCode}, "password": {password}, "repeat": {password}})
	if p.path != "/login" {
		t.Fatalf("setup ended on %s (%d), want /login:\n%s", p.path, p.status, p.text())
	}
	p = e.ui.post("/login", url.Values{"csrf": {csrfOf(t, p)}, "password": {password}})
	if p.path != "/" || !strings.Contains(p.body, `action="/logout"`) {
		t.Fatalf("login ended on %s (%d):\n%s", p.path, p.status, p.text())
	}
	p = e.ui.get("/settings")
	p = e.ui.post("/settings/general", url.Values{"csrf": {csrfOf(t, p)}, "schedule": {server.ScheduleManual}, "alert_level": {"urgent"}}).want(t, http.StatusOK)
	if !strings.Contains(p.body, "Settings saved.") || !strings.Contains(p.body, `<option value="`+server.ScheduleManual+`" selected>`) {
		t.Fatalf("the manual schedule was not saved:\n%s", p.text())
	}
	p = e.ui.get("/settings")
	p = e.ui.post("/settings/tokens", url.Values{"csrf": {csrfOf(t, p)}, "name": {"lab-e2e"}})
	token := codeByID(t, p, "api-token")
	mcpCmd := strings.Fields(codeByID(t, p, "mcp-command"))
	if len(mcpCmd) != 8 || mcpCmd[3] != base || mcpCmd[7] != "SHA256:"+certFP {
		t.Fatalf("the token page's command is %q; want the server %s and the fingerprint SHA256:%s", mcpCmd, base, certFP)
	}

	// Pairing with bubbles: telltale shows the fingerprint of the server
	// at the address the owner typed, the chat admin reads the one in
	// bubbles' Admin > Overview and they compare; telltale asks for a
	// token and shows a code; the chat admin approves the request with
	// that code, adding telltale's bot to the alert channel.
	start = time.Now()
	e.bub = startBubblesAdmin(t, e)
	channel := e.bub.createChannel(e2eChannel)
	caFP := e.bub.overview().CAFingerprint
	p = e.ui.get("/settings/bubbles")
	p = e.ui.post("/settings/bubbles/inspect", url.Values{"csrf": {csrfOf(t, p)}, "address": {e.bub.ip}})
	shown := firstGroup(fpStartRE, p.body) + firstGroup(fpRestRE, p.body)
	if hexDigits(shown) == "" || hexDigits(shown) != hexDigits(strings.TrimPrefix(strings.ToLower(caFP), "sha256:")) {
		t.Fatalf("telltale shows the fingerprint %q; bubbles' overview says %q", shown, caFP)
	}
	p = e.ui.post("/settings/bubbles/pair", url.Values{"csrf": {csrfOf(t, p)}, "candidate": {hiddenOf(t, p, "candidate")}, "confirm": {"yes"}})
	code := firstGroup(pairCodeRE, p.body)
	if code == "" {
		t.Fatalf("no pairing code on %s:\n%s", p.path, p.text())
	}
	e.bub.approve(code, caFP, channel)
	waitFor(t, time.Minute, "telltale to be connected to bubbles with #"+e2eChannel, func() bool {
		return strings.Contains(e.ui.get("/settings/bubbles").body, "Alerts go to <strong>#"+e2eChannel+"</strong>")
	})
	phase("bubbles pairing", start)

	// Enrolment and the first visit of each machine, then the snapshot.
	deb := e.machine("debian12")
	ubu := e.machine("ubuntu2404-noexec")
	for _, d := range []string{"/run", "/var/tmp", "/tmp", "/dev/shm"} {
		if opts := e.mustExec(ubu, "findmnt -no OPTIONS "+d); !strings.Contains(opts, "noexec") {
			t.Fatalf("%s on %s is mounted %q, want noexec", d, ubu.name, strings.TrimSpace(opts))
		}
	}
	for _, m := range []*e2eMachine{deb, ubu} {
		start = time.Now()
		e.enrol(m)
		var stop func() []string
		if m == ubu {
			stop = e.watchCollector(m)
		}
		p := e.checkNow(m)
		if stop != nil {
			// Every other temporary directory is noexec: the collector
			// has to have run from one of its own under /root.
			ran := stop()
			if len(ran) == 0 {
				t.Errorf("%s: the collector was not seen running", m.name)
			}
			for _, r := range ran {
				if !regexp.MustCompile(`^/root/telltale\.[A-Za-z0-9]{8}/telltale$`).MatchString(r) {
					t.Errorf("%s: the collector ran as %s, want /root/telltale.XXXXXXXX/telltale", m.name, r)
				}
			}
			t.Logf("%s: the collector ran as %q", m.name, ran)
		}
		e.checkFirstReport(m, p)
		phase("enrolment and first visit of "+m.name, start)
		e.markClean(m)
	}

	// The break: a root key added and root login turned back on.
	for _, b := range []string{"root-key", "regress-root-login"} {
		e.apply(deb, b)
	}
	start = time.Now()
	p = e.checkNow(deb)
	phase("visit of debian12 with the breaks", start)
	keyFinding := e.checkBroken(deb, p)
	start = time.Now()
	e.checkNow(ubu) // still clean against its snapshot, and sends nothing
	phase("second visit of ubuntu2404-noexec", start)
	if fs := findingsOf(e.ui.get(ubu.path())); slices.ContainsFunc(fs, urgent) {
		t.Errorf("%s: urgent findings against its own snapshot:\n%s", ubu.name, describe(fs))
	}

	// bubbles got one critical alert for each urgent finding, keyed by
	// machine and finding, carrying the redacted changed line and no other
	// content from the machine. The two breaks make three: the root key,
	// root login re-enabled against the snapshot (the regression rule), and
	// the sshd drop-in the second break edits, a persistence file that
	// changed with no package to explain it.
	rootKeyAlert := "telltale:debian12:" + keyFinding
	sshAlert := "telltale:debian12:check:TT-SSH-001"
	dropInAlert := "telltale:debian12:" + dropInKey
	want := []string{rootKeyAlert, sshAlert, dropInAlert}
	var got map[string]protocol.Message
	waitFor(t, time.Minute, "the alerts in #"+e2eChannel, func() bool {
		got = e.bub.alerts(channel)
		return len(got) >= len(want)
	})
	for k, msg := range got {
		t.Logf("alert %s:\n%s", k, msg.Body)
	}
	if len(got) != len(want) || slices.ContainsFunc(want, func(k string) bool { return got[k].Alert == nil }) {
		t.Fatalf("alerts in #%s: %s\nwant exactly %s", e2eChannel, alertKeys(got), strings.Join(want, ", "))
	}
	for _, k := range want {
		if a := got[k].Alert; a.Severity != protocol.SeverityCritical || a.State != protocol.AlertOpen {
			t.Errorf("alert %s is %s and %s, want critical and open", k, a.Severity, a.State)
		}
	}
	e.checkAlertContent(deb, got[rootKeyAlert], got[sshAlert], got[dropInAlert])

	// telltale mcp, on the host, pinned to the server's certificate, gives
	// the same findings.
	start = time.Now()
	e.checkMCP(filepath.Join(dist, "bin"), mcpCmd[3], mcpCmd[7], token, keyFinding)
	phase("telltale mcp", start)

	// The key goes; the next visit resolves its alert, and only that one.
	e.mustExec(deb, "sed -i '/lab-attacker@nowhere/d' /root/.ssh/authorized_keys")
	start = time.Now()
	p = e.checkNow(deb)
	phase("visit of debian12 with the key removed", start)
	fs := findingsOf(p)
	if slices.ContainsFunc(fs, func(f e2eFinding) bool { return strings.Contains(f.key, "root_key") }) {
		t.Errorf("the root key was removed, but the machine page still lists:\n%s", describe(fs))
	}
	if !slices.ContainsFunc(fs, func(f e2eFinding) bool { return f.key == "check:TT-SSH-001" && f.class == "tampering" }) {
		t.Errorf("root login is still on, but the machine page does not list check:TT-SSH-001 as tampering:\n%s", describe(fs))
	}
	waitFor(t, time.Minute, "the root key's alert to be resolved", func() bool {
		got = e.bub.alerts(channel)
		a := got[rootKeyAlert].Alert
		return a != nil && a.State == protocol.AlertResolved
	})
	if len(got) != len(want) || slices.ContainsFunc(want[1:], func(k string) bool { return got[k].Alert == nil || got[k].Alert.State != protocol.AlertOpen }) {
		t.Errorf("after the key was removed, the alerts are %s; want only %s resolved and the others still open", alertKeys(got), rootKeyAlert)
	}
	phase("the whole test", began)
}

// e2eLab is one run of compose.server.yml.
type e2eLab struct {
	t        *testing.T
	env      []string
	serverIP string
	ctrs     map[string]string // service name: container ID
	ui       *browser
	bub      *bubblesAdmin
	// markers identify what the owner added for the server: its key
	// and its Match block.
	markers []string
}

// e2eMachine is a lab machine of the Compose project, once enrolled.
type e2eMachine struct {
	name, ctr, ip string
	id            int64
}

func (m *e2eMachine) path() string { return "/machines/" + strconv.FormatInt(m.id, 10) }

func (e *e2eLab) compose(args ...string) (string, error) {
	cmd := exec.Command("docker", append([]string{"compose", "-p", e2eProject, "-f", e2eCompose}, args...)...)
	cmd.Env = append(os.Environ(), e.env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// up starts the project and takes it down again when the test ends.
func (e *e2eLab) up() {
	t := e.t
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := e.compose("logs", "--no-color", "--tail", "60", "server", "bubbles")
			t.Logf("last output of the server and bubbles:\n%s", out)
		}
		if out, err := e.compose("down", "--volumes", "--remove-orphans", "--timeout", "5"); err != nil {
			t.Errorf("docker compose down: %v\n%s", err, out)
		}
	})
	if out, err := e.compose("up", "--detach", "--quiet-pull"); err != nil {
		t.Fatalf("docker compose up: %v\n%s", err, out)
	}
}

// ctr is the container of a service.
func (e *e2eLab) ctr(service string) string {
	if id, ok := e.ctrs[service]; ok {
		return id
	}
	out, err := e.compose("ps", "--quiet", service)
	id := strings.TrimSpace(out)
	if err != nil || id == "" || strings.ContainsAny(id, " \n") {
		e.t.Fatalf("no container for %s: %v\n%s", service, err, out)
	}
	e.ctrs[service] = id
	return id
}

func (e *e2eLab) logs(service string) string {
	out, _ := exec.Command("docker", "logs", e.ctr(service)).CombinedOutput()
	return string(out)
}

// ip is a service's address on the lab network.
func (e *e2eLab) ip(service string) string {
	out, err := exec.Command("docker", "inspect", "--format", `{{(index .NetworkSettings.Networks "`+labkit.NetworkName+`").IPAddress}}`, e.ctr(service)).Output()
	ip := strings.TrimSpace(string(out))
	if err != nil || ip == "" {
		e.t.Fatalf("%s has no address on %s: %v", service, labkit.NetworkName, err)
	}
	return ip
}

// mustExec runs a shell script as root in the machine, with args as $1...,
// and fails the test when it fails.
func (e *e2eLab) mustExec(m *e2eMachine, script string, args ...string) string {
	e.t.Helper()
	cmd := exec.Command("docker", append([]string{"exec", m.ctr, "sh", "-c", script + " 2>&1", "sh"}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		e.t.Fatalf("%s: `%s`: %v\n%s", m.name, script, err, out)
	}
	return string(out)
}

// machine is the Compose service of that name, not enrolled yet.
func (e *e2eLab) machine(service string) *e2eMachine {
	m := &e2eMachine{name: service, ctr: e.ctr(service), ip: e.ip(service)}
	waitFor(e.t, 30*time.Second, "sshd on "+service, func() bool {
		out, err := exec.Command("docker", "exec", m.ctr, "ss", "-ltn").Output()
		return err == nil && strings.Contains(string(out), ":22 ")
	})
	return m
}

// enrol enrols the machine in the owner's steps: the server fetches the
// host key and shows its fingerprint, which is compared with the machine's
// own; the owner confirms, and adds the two snippets the server shows,
// exactly as shown, then checks sshd's configuration and reloads it (sshd
// runs without systemd in the lab: SIGHUP is its reload).
func (e *e2eLab) enrol(m *e2eMachine) {
	t := e.t
	p := e.ui.get("/enrol")
	p = e.ui.post("/enrol", url.Values{"csrf": {csrfOf(t, p)}, "name": {m.name}, "addr": {m.ip}})
	fp := html.UnescapeString(firstGroup(hostFPRE, p.body))
	keyFile := firstGroup(keyFileRE, p.body)
	if fp == "" || keyFile == "" {
		t.Fatalf("%s: no host key fingerprint to compare:\n%s", m.name, p.text())
	}
	if own := e.mustExec(m, "ssh-keygen -lf "+keyFile); !strings.Contains(own, " "+fp+" ") {
		t.Fatalf("%s: the server fetched the host key %s; the machine's own %s is %s", m.name, fp, keyFile, strings.TrimSpace(own))
	}
	p = e.ui.post("/enrol/confirm", url.Values{"csrf": {csrfOf(t, p)}, "pending": {hiddenOf(t, p, "pending")}, "confirm": {"yes"}})
	id := firstGroup(regexp.MustCompile(`^/machines/(\d+)/enrolled$`), p.path)
	if id == "" {
		t.Fatalf("%s: enrolment ended on %s (%d):\n%s", m.name, p.path, p.status, p.text())
	}
	m.id, _ = strconv.ParseInt(id, 10, 64)
	keys := codeByID(t, p, "snippet-keys")
	block := codeByID(t, p, "snippet-sshd")
	if reload := codeByID(t, p, "snippet-reload"); reload != "sshd -t && systemctl reload ssh" {
		t.Fatalf("%s: the reload step is %q", m.name, reload)
	}
	before := e.sshListener(m)
	e.mustExec(m, `set -e
umask 077
mkdir -p /root/.ssh
printf '%s\n' "$1" >> /root/.ssh/authorized_keys
printf '\n%s\n' "$2" >> /etc/ssh/sshd_config
/usr/sbin/sshd -t
kill -HUP "$(pgrep -o -x sshd)"`, keys, block)
	e.waitReload(m, before)
	// Root may log in from the server's address, by key only, and from
	// nowhere else.
	if out := e.mustExec(m, "/usr/sbin/sshd -T -C user=root,host=server,addr="+e.serverIP+" | grep -i '^permitrootlogin '"); !strings.Contains(out, "permitrootlogin without-password") {
		t.Fatalf("%s: root login from the server: %q", m.name, out)
	}
	if out := e.mustExec(m, "/usr/sbin/sshd -T -C user=root,host=other,addr=192.0.2.1 | grep -i '^permitrootlogin '"); !strings.Contains(out, "permitrootlogin no") {
		t.Fatalf("%s: root login from another address: %q", m.name, out)
	}
	for _, f := range strings.Fields(keys) {
		if strings.HasPrefix(f, "AAAA") && !slices.Contains(e.markers, f) {
			e.markers = append(e.markers, f)
		}
	}
	match := "Match Address " + e.serverIP
	if !strings.HasPrefix(block, match+"\n") {
		t.Fatalf("%s: the sshd block is %q, want one for %s", m.name, block, e.serverIP)
	}
	if !slices.Contains(e.markers, match) {
		e.markers = append(e.markers, match)
	}
	if !strings.Contains(p.body, `action="`+m.path()+`/check"`) {
		t.Fatalf("%s: the snippets page has no Check now:\n%s", m.name, p.text())
	}
}

// checkNow presses Check now on the machine page and waits for the visit's
// report. It fails the test when the visit failed or left anything on the
// machine.
func (e *e2eLab) checkNow(m *e2eMachine) page {
	t := e.t
	p := e.ui.get(m.path())
	before := reportIDs(p.body)
	p = e.ui.post(m.path()+"/check", url.Values{"csrf": {csrfOf(t, p)}}).want(t, http.StatusOK)
	if flash := firstGroup(flashRE, p.body); flash != "The visit is done. The report below is the new one." &&
		flash != "The visit has started. Reload this page in a minute or two to see its report." {
		t.Fatalf("%s: Check now was refused (%q):\n%s", m.name, flash, p.text())
	}
	deadline := time.Now().Add(e2eVisitLimit)
	for {
		p = e.ui.get(m.path())
		running := strings.Contains(p.body, "A visit is running now.")
		if ids := reportIDs(p.body); !running && len(ids) > len(before) {
			break
		}
		if !running && strings.Contains(p.body, "The last visit failed.") {
			t.Fatalf("%s: the visit failed:\n%s", m.name, p.text())
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: no report %v after Check now", m.name, e2eVisitLimit)
		}
		time.Sleep(2 * time.Second)
	}
	if strings.Contains(p.body, "The last visit failed.") || strings.Contains(p.body, "A telltale collector was left on the machine") {
		t.Errorf("%s: after the visit the machine page says:\n%s", m.name, p.text())
	}
	if left := strings.TrimSpace(e.mustExec(m, "find /run /var/tmp /root /tmp /dev/shm -maxdepth 1 -name 'telltale.*'")); left != "" {
		t.Errorf("%s: the visit left on the machine:\n%s", m.name, left)
	}
	// Nor anything wrong with the visit itself: no leftover, and the
	// collector ran from the directory the visit made (visit.own_dir_mismatch).
	for _, f := range findingsOf(p) {
		if strings.HasPrefix(f.key, "visit.") {
			t.Errorf("%s: a finding about the visit: %s %s\n%s", m.name, f.class, f.key, f.text)
		}
	}
	return p
}

// watchCollector records the program of every "telltale collect" process
// on the machine until the returned function is called.
func (e *e2eLab) watchCollector(m *e2eMachine) func() []string {
	const marker = "telltale-lab-watch"
	cmd := exec.Command("docker", "exec", m.ctr, "sh", "-c",
		`while :; do ps -eo args= | grep -E '^/[^ ]+/telltale collect( |$)'; sleep 0.05; done`, marker)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	return func() []string {
		exec.Command("docker", "exec", m.ctr, "pkill", "-f", marker).Run()
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			cmd.Process.Kill()
			<-done
		}
		var ran []string
		for _, l := range strings.Split(out.String(), "\n") {
			if f := strings.Fields(l); len(f) > 0 && !slices.Contains(ran, f[0]) {
				ran = append(ran, f[0])
			}
		}
		return ran
	}
}

// checkFirstReport checks a machine's first report, taken without a
// snapshot: a clean machine has nothing urgent, and the key line and Match
// block the owner added for the server are expected, so they are not
// findings, a root-key note included.
func (e *e2eLab) checkFirstReport(m *e2eMachine, p page) {
	t := e.t
	fs := findingsOf(p)
	t.Logf("%s: first report:\n%s", m.name, describe(fs))
	for _, f := range fs {
		if strings.HasPrefix(f.key, "pkg.") {
			t.Logf("%s: %s:\n%s", m.name, f.key, strings.Join(strings.Fields(f.text), " "))
		}
	}
	if !strings.Contains(p.body, "Latest report") {
		t.Fatalf("%s: no report on the machine page:\n%s", m.name, p.text())
	}
	// The server verified the machine's packages against the archives,
	// which it reaches over the egress network; the machine cannot.
	meta := firstGroup(regexp.MustCompile(`(?s)<div class="meta">(.*?)</div>`), p.body)
	if !regexp.MustCompile(`Compared against:</strong> (Debian|Ubuntu) packages, checklist`).MatchString(meta) ||
		strings.Contains(meta, "package verification did not run") || strings.Contains(meta, "no package reference") ||
		strings.Contains(meta, "verification stopped before") || strings.Contains(meta, "package source could not be used") {
		t.Errorf("%s: the first report was not compared with the distribution's packages:\n%s", m.name, meta)
	}
	for _, f := range fs {
		if urgent(f) {
			t.Errorf("%s: a clean machine has an urgent finding: %s %s", m.name, f.class, f.key)
		}
		if strings.Contains(f.key, "root_key") || f.key == "check:TT-SSH-001" || e.mentionsSnippets(f.text) {
			t.Errorf("%s: what the owner added for the server is a finding: %s %s", m.name, f.class, f.key)
		}
	}
}

// mentionsSnippets reports whether text shows the server's own key or its
// Match block.
func (e *e2eLab) mentionsSnippets(text string) bool {
	return slices.ContainsFunc(e.markers, func(m string) bool { return strings.Contains(text, m) })
}

// markClean takes the snapshot from the machine's latest report, through
// the review page.
func (e *e2eLab) markClean(m *e2eMachine) {
	t := e.t
	p := e.ui.get(m.path())
	clean := html.UnescapeString(firstGroup(regexp.MustCompile(`href="(/machines/\d+/clean\?report=\d+)"`), p.body))
	if clean == "" {
		t.Fatalf("%s: no link to take the snapshot:\n%s", m.name, p.text())
	}
	p = e.ui.get(clean)
	p = e.ui.post(m.path()+"/clean", url.Values{"csrf": {csrfOf(t, p)}, "report": {hiddenOf(t, p, "report")}, "confirm": {"yes"}})
	if !strings.Contains(p.body, "Snapshot taken. Every later visit is compared with it.") {
		t.Fatalf("%s: taking the snapshot ended on %s:\n%s", m.name, p.path, p.text())
	}
}

// apply plants a break on the machine.
func (e *e2eLab) apply(m *e2eMachine, name string) {
	// Only a machine with no route out may get anything planted.
	if out, err := exec.Command("docker", "inspect", "--format", "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}", m.ctr).Output(); err != nil ||
		strings.TrimSpace(string(out)) != labkit.NetworkName {
		e.t.Fatalf("%s is on the networks %q, not only on %s: nothing is planted on it (%v)", m.name, strings.TrimSpace(string(out)), labkit.NetworkName, err)
	}
	script, err := os.ReadFile(filepath.Join("breaks", name, "apply.sh"))
	if err != nil {
		e.t.Fatal(err)
	}
	before := e.sshListener(m)
	if out, err := exec.Command("docker", "cp", filepath.Join("breaks", name), m.ctr+":/lab/"+name).CombinedOutput(); err != nil {
		e.t.Fatalf("copy %s to %s: %v\n%s", name, m.name, err, out)
	}
	e.mustExec(m, "sh /lab/"+name+"/apply.sh && rm -rf /lab/"+name)
	if strings.Contains(string(script), "-HUP") {
		e.waitReload(m, before)
	}
}

// sshListener names the sockets sshd listens on port 22 with (their
// inodes); "" when it does not listen.
func (e *e2eLab) sshListener(m *e2eMachine) string {
	out, _ := exec.Command("docker", "exec", m.ctr, "ss", "-Hltne", "sport = :22").Output()
	var inos []string
	for _, g := range regexp.MustCompile(`\bino:([0-9]+)`).FindAllStringSubmatch(string(out), -1) {
		inos = append(inos, g[1])
	}
	slices.Sort(inos)
	return strings.Join(inos, " ")
}

// waitReload waits for sshd to have reloaded after a SIGHUP: it starts
// itself again with the same PID, so the sign is a new listening socket,
// and then that the server's container gets sshd's banner from it.
func (e *e2eLab) waitReload(m *e2eMachine, before string) {
	waitFor(e.t, 30*time.Second, "sshd to reload on "+m.name, func() bool {
		now := e.sshListener(m)
		if now == "" || now == before {
			return false
		}
		out, err := exec.Command("docker", "exec", e.ctr("server"), "bash", "-c", `exec 3<>"/dev/tcp/$1/22" && head -c 4 <&3`, "bash", m.ip).Output()
		return err == nil && string(out) == "SSH-"
	})
}

// checkBroken checks the machine page after the breaks and returns the key
// of the planted root key's finding.
func (e *e2eLab) checkBroken(m *e2eMachine, p page) string {
	t := e.t
	fs := findingsOf(p)
	t.Logf("%s: report with the breaks:\n%s", m.name, describe(fs))
	var key string
	for _, f := range fs {
		switch {
		case strings.HasPrefix(f.key, "snap.root_key:/root/.ssh/authorized_keys:"):
			if f.class != "backdoor" || !strings.Contains(f.text, "lab-attacker@nowhere") || key != "" {
				t.Errorf("%s: root key finding %s (%s) is not the one planted key as a backdoor sign:\n%s", m.name, f.key, f.class, f.text)
			}
			key = f.key
		case f.key == "check:TT-SSH-001":
			if f.class != "tampering" {
				t.Errorf("%s: check:TT-SSH-001 is %s, want tampering", m.name, f.class)
			}
		case f.key == dropInKey:
			if f.class != "backdoor" || !strings.Contains(f.text, dropInLine) {
				t.Errorf("%s: %s (%s) is not the drop-in's changed line as a backdoor sign:\n%s", m.name, f.key, f.class, f.text)
			}
		case strings.Contains(f.key, "root_key"):
			t.Errorf("%s: another root key finding: %s %s", m.name, f.class, f.key)
		case urgent(f):
			t.Errorf("%s: an urgent finding the breaks do not explain: %s %s", m.name, f.class, f.key)
		}
		if e.mentionsSnippets(f.text) {
			t.Errorf("%s: finding %s shows what the owner added for the server:\n%s", m.name, f.key, f.text)
		}
	}
	if key == "" || !slices.ContainsFunc(fs, func(f e2eFinding) bool { return f.key == "check:TT-SSH-001" }) ||
		!slices.ContainsFunc(fs, func(f e2eFinding) bool { return f.key == dropInKey }) {
		t.Fatalf("%s: the machine page does not list the root key, root login re-enabled and the changed drop-in:\n%s", m.name, describe(fs))
	}
	return key
}

// checkAlertContent checks that each alert carries, of the machine's
// files, only the one changed line, as redaction leaves it.
func (e *e2eLab) checkAlertContent(m *e2eMachine, rootKey, ssh, dropIn protocol.Message) {
	t := e.t
	for _, l := range []string{plantedKeyLine, dropInLine} {
		if red, n := redact.Line(make([]byte, 32), l); n != 0 || red != l {
			t.Fatalf("redaction changes the line %q: %q", l, red)
		}
	}
	for _, msg := range []protocol.Message{rootKey, ssh, dropIn} {
		if e.mentionsSnippets(msg.Body) {
			t.Errorf("alert %s shows the server's own key line or Match block:\n%s", msg.Alert.DedupeKey, msg.Body)
		}
	}
	// Each alert's first code line is the line the break changed, once;
	// for the checklist item it is the setting's value before and after.
	for _, c := range []struct {
		msg   protocol.Message
		line  string
		exact bool
	}{{rootKey, plantedKeyLine, true}, {dropIn, dropInLine, true}, {ssh, dropInLine, false}} {
		lines := codeLines(c.msg.Body)
		if len(lines) == 0 || (c.exact && lines[0] != c.line) || (!c.exact && !strings.Contains(lines[0], c.line)) {
			t.Errorf("alert %s does not show the changed line %q first:\n%s", c.msg.Alert.DedupeKey, c.line, c.msg.Body)
		}
		if n := strings.Count(c.msg.Body, c.line); n != 1 {
			t.Errorf("alert %s shows the changed line %d times:\n%s", c.msg.Alert.DedupeKey, n, c.msg.Body)
		}
		// No other line of the files the breaks touched.
		for _, f := range []string{"/root/.ssh/authorized_keys", "/etc/ssh/sshd_config.d/00-lab.conf", "/etc/ssh/sshd_config"} {
			for _, l := range strings.Split(e.mustExec(m, "cat "+f), "\n") {
				l = strings.TrimSpace(l)
				if len(l) >= 8 && !strings.HasPrefix(l, "#") && l != c.line && strings.Contains(c.msg.Body, l) {
					t.Errorf("alert %s carries another line of %s: %q", c.msg.Alert.DedupeKey, f, l)
				}
			}
		}
	}
}

// checkMCP runs telltale mcp on the host and checks latest_report.
func (e *e2eLab) checkMCP(binDir, srv, fp, token, keyFinding string) {
	t := e.t
	tokFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokFile, token+"\n", 0o600)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.Command(filepath.Join(binDir, "telltale-linux-"+runtime.GOARCH), "mcp", "--server", srv, "--token-file", tokFile, "--fingerprint", fp)
	cmd.Stderr = &stderr
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "telltale-lab", Version: "e2e"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("telltale mcp: %v\n%s", err, stderr.String())
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "latest_report", Arguments: map[string]any{"machine": "debian12"}})
	if err != nil || res.IsError {
		t.Fatalf("latest_report: %v %s\n%s", err, toolText(res), stderr.String())
	}
	var out struct {
		Machine struct{ Name string }
		Report  struct {
			Findings []struct{ Key, Severity string }
		}
	}
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("latest_report: %v\n%s", err, b)
	}
	want := map[string]string{keyFinding: "backdoor sign", "check:TT-SSH-001": "tampering", dropInKey: "backdoor sign"}
	for _, f := range out.Report.Findings {
		if sev, ok := want[f.Key]; ok {
			if f.Severity != sev {
				t.Errorf("latest_report: %s is %q, want %q", f.Key, f.Severity, sev)
			}
			delete(want, f.Key)
		}
	}
	if out.Machine.Name != "debian12" || len(want) > 0 {
		t.Errorf("latest_report for %q lacks %v:\n%s", out.Machine.Name, want, b)
	}
}

func toolText(res *mcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text + "\n")
		}
	}
	return b.String()
}

// Pages of the web UI.

var (
	certFPRE    = regexp.MustCompile(`what your browser shows\):\s*\n\s*([0-9A-F:]{95})\s`)
	setupCodeRE = regexp.MustCompile(`one-time setup code to set the admin password:\s*\n\s*([A-Z2-7]{5}(?:-[A-Z2-7]{5}){3})\s`)
	sshKeyRE    = regexp.MustCompile(`(SSH key fingerprint SHA256:\S+; machines see this server as \S+)`)
	csrfRE      = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	hostFPRE    = regexp.MustCompile(`<p class="fingerprint">([^<]+)</p>`)
	keyFileRE   = regexp.MustCompile(`<pre><code>ssh-keygen -lf (/etc/ssh/ssh_host_[a-z0-9]+_key\.pub)</code></pre>`)
	fpStartRE   = regexp.MustCompile(`<p class="fingerprint fpbig">([^<]*)</p>`)
	fpRestRE    = regexp.MustCompile(`<p class="mono small fprest">([^<]*)</p>`)
	pairCodeRE  = regexp.MustCompile(`<p class="paircode mono">([^<]+)</p>`)
	historyRE   = regexp.MustCompile(`<td><a href="/machines/\d+\?report=(\d+)">`)
	findingRE   = regexp.MustCompile(`(?s)<article class="finding (\w+)">(.*?)</article>`)
	findingKey  = regexp.MustCompile(`ID <code>([^<]*)</code>`)
	tagRE       = regexp.MustCompile(`<[^>]*>`)
	flashRE     = regexp.MustCompile(`<p class="flash" role="status">([^<]*)</p>`)
)

// browser is the owner's browser: cookies, the Origin a browser sends with
// a form, and the server's certificate pinned to the fingerprint it printed.
type browser struct {
	t    *testing.T
	base string
	c    *http.Client
}

func newBrowser(t *testing.T, base, certFP string) *browser {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		// The certificate is self-signed; it is pinned instead.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || server.Fingerprint(cs.PeerCertificates[0].Raw) != certFP {
				return errors.New("not the certificate the server printed at start")
			}
			return nil
		},
	}}
	t.Cleanup(tr.CloseIdleConnections)
	return &browser{t: t, base: base, c: &http.Client{Jar: jar, Transport: tr, Timeout: 2 * time.Minute}}
}

// page is a response after its redirects.
type page struct {
	status int
	path   string
	body   string
}

// text is the page without its markup, for failure messages.
func (p page) text() string {
	s := html.UnescapeString(tagRE.ReplaceAllString(p.body, " "))
	return strings.Join(strings.Fields(s), " ")
}

func (p page) want(t *testing.T, status int) page {
	t.Helper()
	if p.status != status {
		t.Fatalf("%s: HTTP %d, want %d:\n%s", p.path, p.status, status, p.text())
	}
	return p
}

func (b *browser) try(method, path string, form url.Values) (page, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, b.base+path, body)
	if err != nil {
		return page{}, err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", b.base)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	resp, err := b.c.Do(req)
	if err != nil {
		return page{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return page{}, err
	}
	return page{status: resp.StatusCode, path: resp.Request.URL.Path, body: string(data)}, nil
}

func (b *browser) get(path string) page {
	b.t.Helper()
	p, err := b.try(http.MethodGet, path, nil)
	if err != nil {
		b.t.Fatalf("GET %s: %v", path, err)
	}
	return p
}

func (b *browser) post(path string, form url.Values) page {
	b.t.Helper()
	p, err := b.try(http.MethodPost, path, form)
	if err != nil {
		b.t.Fatalf("POST %s: %v", path, err)
	}
	return p
}

func firstGroup(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

func csrfOf(t *testing.T, p page) string {
	t.Helper()
	return hiddenOf(t, p, "csrf")
}

func hiddenOf(t *testing.T, p page, name string) string {
	t.Helper()
	v := firstGroup(regexp.MustCompile(`name="`+regexp.QuoteMeta(name)+`" value="([^"]*)"`), p.body)
	if v == "" {
		t.Fatalf("%s (%d) has no %s field:\n%s", p.path, p.status, name, p.text())
	}
	return html.UnescapeString(v)
}

func codeByID(t *testing.T, p page, id string) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)<code id="` + regexp.QuoteMeta(id) + `">(.*?)</code>`).FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("%s (%d) has no %s:\n%s", p.path, p.status, id, p.text())
	}
	return html.UnescapeString(m[1])
}

// reportIDs are the report IDs in the machine page's history.
func reportIDs(body string) []string {
	var ids []string
	for _, m := range historyRE.FindAllStringSubmatch(body, -1) {
		if !slices.Contains(ids, m[1]) {
			ids = append(ids, m[1])
		}
	}
	return ids
}

// e2eFinding is a finding as the machine page shows it.
type e2eFinding struct {
	class, key, text string
}

func findingsOf(p page) []e2eFinding {
	var fs []e2eFinding
	for _, m := range findingRE.FindAllStringSubmatch(p.body, -1) {
		text := html.UnescapeString(tagRE.ReplaceAllString(m[2], "\n"))
		fs = append(fs, e2eFinding{class: m[1], key: html.UnescapeString(firstGroup(findingKey, m[2])), text: text})
	}
	return fs
}

func urgent(f e2eFinding) bool { return f.class == "tampering" || f.class == "backdoor" }

func describe(fs []e2eFinding) string {
	var b strings.Builder
	for _, f := range fs {
		fmt.Fprintf(&b, "  %-10s %s\n", f.class, f.key)
	}
	if len(fs) == 0 {
		b.WriteString("  (no findings)\n")
	}
	return b.String()
}

// bubbles, as its chat admin uses it.

type bubblesAdmin struct {
	t    *testing.T
	ip   string
	base string
	c    *http.Client
}

var bubblesPasswordRE = regexp.MustCompile(`Password:\s+(\S+)`)

// startBubblesAdmin waits for bubbles to start and signs in as its admin,
// with the generated password it printed at first start.
func startBubblesAdmin(t *testing.T, e *e2eLab) *bubblesAdmin {
	ip := e.ip("bubbles")
	var der []byte
	waitFor(t, 2*time.Minute, "bubbles to start", func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		d, _, err := bubblesclient.FetchCA(ctx, "http://"+ip+":28226")
		der = d
		return err == nil && bubblesPasswordRE.MatchString(e.logs("bubbles"))
	})
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	t.Cleanup(tr.CloseIdleConnections)
	b := &bubblesAdmin{t: t, ip: ip, base: "https://" + ip + ":28225", c: &http.Client{Jar: jar, Transport: tr, Timeout: time.Minute}}
	pw := firstGroup(bubblesPasswordRE, e.logs("bubbles"))
	b.call(http.MethodPost, "/api/v1/auth/login", protocol.LoginRequest{Username: "admin", Password: pw}, nil)
	return b
}

func (b *bubblesAdmin) call(method, path string, in, out any) {
	b.t.Helper()
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			b.t.Fatal(err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, b.base+path, body)
	if err != nil {
		b.t.Fatal(err)
	}
	req.Header.Set("Origin", b.base)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatalf("bubbles %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode/100 != 2 {
		b.t.Fatalf("bubbles %s %s: HTTP %d: %s", method, path, resp.StatusCode, data)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			b.t.Fatalf("bubbles %s %s: %v\n%s", method, path, err, data)
		}
	}
}

func (b *bubblesAdmin) createChannel(name string) string {
	var ch protocol.Channel
	b.call(http.MethodPost, "/api/v1/channels", protocol.CreateChannelRequest{Name: name, Kind: protocol.ChannelPublic}, &ch)
	if ch.ID == "" {
		b.t.Fatalf("bubbles made channel %s without an id", name)
	}
	return ch.ID
}

func (b *bubblesAdmin) overview() protocol.AdminOverview {
	var ov protocol.AdminOverview
	b.call(http.MethodGet, "/api/v1/admin/overview", nil, &ov)
	return ov
}

// approve approves the pairing request that shows code, after checking
// that it came from the telltale server, under the fingerprint compared.
func (b *bubblesAdmin) approve(code, caFP, channel string) {
	t := b.t
	var req protocol.PendingPairing
	waitFor(t, 30*time.Second, "the pairing request in bubbles", func() bool {
		var list protocol.PendingPairingList
		b.call(http.MethodGet, "/api/v1/admin/pairing-requests", nil, &list)
		for _, r := range list.Items {
			if strings.ReplaceAll(r.Code, " ", "") == strings.ReplaceAll(code, " ", "") {
				req = r
				return true
			}
		}
		return false
	})
	if req.AppName != "telltale" || req.CAFingerprint != caFP {
		t.Fatalf("the pairing request with code %s is from %q under %q; want telltale under %q", code, req.AppName, req.CAFingerprint, caFP)
	}
	b.call(http.MethodPost, "/api/v1/admin/pairing-requests/"+url.PathEscape(req.ID)+"/approve", protocol.ApprovePairingRequest{ChannelIDs: []string{channel}}, nil)
}

// alerts are the alert messages in the channel, by dedupe key.
func (b *bubblesAdmin) alerts(channel string) map[string]protocol.Message {
	var page protocol.AlertPage
	b.call(http.MethodGet, "/api/v1/alerts?channel_id="+url.QueryEscape(channel)+"&limit=100", nil, &page)
	out := map[string]protocol.Message{}
	for _, m := range page.Items {
		if m.Alert != nil {
			out[m.Alert.DedupeKey] = m
		}
	}
	return out
}

func alertKeys(m map[string]protocol.Message) string {
	var keys []string
	for k, v := range m {
		keys = append(keys, k+" ("+v.Alert.Severity+", "+v.Alert.State+")")
	}
	slices.Sort(keys)
	if len(keys) == 0 {
		return "none"
	}
	return strings.Join(keys, ", ")
}

// codeLines are the lines of the fenced code blocks in a Markdown text.
func codeLines(md string) []string {
	var out []string
	in := ""
	for _, l := range strings.Split(md, "\n") {
		t := strings.TrimSpace(l)
		switch {
		case in == "" && strings.HasPrefix(t, "```"):
			in = t[:len(t)-len(strings.TrimLeft(t, "`"))]
		case in != "" && t == in:
			in = ""
		case in != "":
			out = append(out, l)
		}
	}
	return out
}

// Images and binaries.

// bubblesImage is the bubbles server image of the version telltale's go.mod
// requires, telltale-lab/bubbles:<version>. When it is missing it is built
// from bubbles' own deploy/docker/Dockerfile in a clean checkout of that
// version's tag: $TELLTALE_LAB_BUBBLES_SRC, or ~/code/bubbles. bubbles.env
// pins the version and the tag's commit; the checkout must be at it.
func bubblesImage(t *testing.T) string {
	gomod, err := os.ReadFile("../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	ver := firstGroup(regexp.MustCompile(`(?m)^\s*github\.com/donaldsteele/bubbles\s+(v[0-9][^\s]*)`), string(gomod))
	if ver == "" {
		t.Fatal("go.mod does not require github.com/donaldsteele/bubbles")
	}
	pin, err := os.ReadFile("bubbles.env")
	if err != nil {
		t.Fatal(err)
	}
	pinVer := firstGroup(regexp.MustCompile(`(?m)^BUBBLES_VERSION=(\S+)$`), string(pin))
	pinCommit := firstGroup(regexp.MustCompile(`(?m)^BUBBLES_COMMIT=([0-9a-f]{40})$`), string(pin))
	if pinVer != ver || pinCommit == "" {
		t.Fatalf("lab/bubbles.env pins bubbles %q (commit %q) but go.mod requires %s: update the version and the commit its tag points at", pinVer, pinCommit, ver)
	}
	tag := "telltale-lab/bubbles:" + ver
	if exec.Command("docker", "image", "inspect", tag).Run() == nil {
		return tag
	}
	src := os.Getenv("TELLTALE_LAB_BUBBLES_SRC")
	if src == "" {
		home, _ := os.UserHomeDir()
		src = filepath.Join(home, "code", "bubbles")
	}
	if _, err := os.Stat(filepath.Join(src, "deploy", "docker", "Dockerfile")); err != nil {
		t.Fatalf("the image %s is missing and %s is not a bubbles checkout to build it from: clone it (git clone --branch %s https://github.com/donaldsteele/bubbles DIR) and set TELLTALE_LAB_BUBBLES_SRC=DIR", tag, src, ver)
	}
	git := func(args ...string) string {
		out, err := exec.Command("git", append([]string{"-C", src}, args...)...).Output()
		if err != nil {
			t.Fatalf("git %s in %s: %v", strings.Join(args, " "), src, err)
		}
		return strings.TrimSpace(string(out))
	}
	if head, want := git("rev-parse", "HEAD"), git("rev-parse", ver+"^{commit}"); head != want || want != pinCommit {
		t.Fatalf("%s is at %s and its tag %s at %s, not at the commit lab/bubbles.env pins (%s): check out the tag", src, head, ver, want, pinCommit)
	}
	if dirty := git("status", "--porcelain"); dirty != "" {
		t.Fatalf("%s has local changes; the lab builds bubbles %s only from a clean checkout:\n%s", src, ver, dirty)
	}
	start := time.Now()
	if out, err := exec.Command("docker", "build", "-q", "-f", filepath.Join(src, "deploy", "docker", "Dockerfile"),
		"--build-arg", "VERSION="+ver, "--label", labkit.Label, "-t", tag, src).CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", tag, err, out)
	}
	t.Logf("built %s from %s in %v", tag, src, time.Since(start).Round(time.Second))
	return tag
}

// serverBaseImage is what the server container runs on: the debian12 lab
// image's base with CA certificates (package verification fetches over
// HTTPS) and nothing else; the server binary comes from the bin directory.
func serverBaseImage(t *testing.T) string {
	df, err := os.ReadFile(filepath.Join("images", "debian12", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	from := firstGroup(regexp.MustCompile(`(?m)^(FROM \S+@sha256:[0-9a-f]{64})\s*$`), string(df))
	if from == "" {
		t.Fatal("images/debian12/Dockerfile has no FROM pinned by digest")
	}
	dockerfile := from + "\nRUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*\nLABEL " + labkit.Label + "\n"
	sum := sha256.Sum256([]byte(dockerfile))
	tag := "telltale-lab/server-base:" + hex.EncodeToString(sum[:])[:12]
	if exec.Command("docker", "image", "inspect", tag).Run() == nil {
		return tag
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "Dockerfile"), dockerfile, 0o644)
	if out, err := exec.Command("docker", "build", "-q", "--label", labkit.Label, "-t", tag, dir).CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", tag, err, out)
	}
	return tag
}

// buildDist runs scripts/build.sh into a temporary directory and returns
// it: bin/ holds the full binaries, which run the server and mcp, and
// collector/ the collector build the server copies to the machines, as the
// .deb lays them out. The packages are not needed here (TELLTALE_DEB=0).
func buildDist(t *testing.T) string {
	out := filepath.Join(t.TempDir(), "dist")
	cmd := exec.Command("bash", "scripts/build.sh")
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "TELLTALE_DIST_DIR="+out, "VERSION=0.0.0-lab", "TELLTALE_DEB=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("scripts/build.sh: %v\n%s", err, b)
	}
	for _, dir := range []string{"bin", "collector"} {
		for _, arch := range []string{"amd64", "arm64"} {
			if _, err := os.Stat(filepath.Join(out, dir, "telltale-linux-"+arch)); err != nil {
				t.Fatalf("scripts/build.sh made no %s/telltale-linux-%s: %v", dir, arch, err)
			}
		}
	}
	return out
}

// lastHost is the last host address of an IPv4 subnet: Docker hands out
// addresses from the bottom, so a fixed one is taken from the top.
func lastHost(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	n := binary.BigEndian.Uint32(a[:]) | (uint32(1)<<(32-p.Bits()) - 1)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n-1)
	return netip.AddrFrom4(b)
}

func hexDigits(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'f' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func randomText(t *testing.T) string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func writeFile(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}
