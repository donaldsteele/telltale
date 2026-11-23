package config

import (
	"github.com/donaldsteele/telltale/internal/visit"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func parse(t *testing.T, text string) (*Config, error) {
	t.Helper()
	return Parse(strings.NewReader(text))
}

func TestConfigRequiresListen(t *testing.T) {
	for name, text := range map[string]string{
		"missing":  "data_dir = \"/var/lib/telltale\"\n",
		"empty":    "listen = \"\"\n",
		"no port":  "listen = \"192.0.2.10\"\n",
		"no host":  "listen = \":8443\"\n",
		"a name":   "listen = \"telltale.example:8443\"\n",
		"bad port": "listen = \"192.0.2.10:http\"\n",
	} {
		if _, err := parse(t, text); err == nil || !strings.Contains(err.Error(), "listen") {
			t.Errorf("%s: err = %v, want one about listen", name, err)
		}
	}
	c, err := parse(t, "listen = \"192.0.2.10:8443\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "192.0.2.10:8443" {
		t.Errorf("Listen = %q", c.Listen)
	}
	if c.DataDir != DefaultDataDir {
		t.Errorf("DataDir = %q, want the default %q", c.DataDir, DefaultDataDir)
	}
}

func TestConfigFullFile(t *testing.T) {
	text := `# telltale server
listen = "192.0.2.10:8443"   # the LAN address
server_addr = "192.0.2.11"

data_dir = "/srv/telltale"
bin_dir = "/usr/lib/telltale"
key_file = "/etc/telltale/data.key"
`
	c, err := parse(t, text)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "192.0.2.10:8443" || c.ServerAddr != "192.0.2.11" || c.DataDir != "/srv/telltale" || c.BinDir != "/usr/lib/telltale" || c.Unlock.KeyFile != "/etc/telltale/data.key" {
		t.Errorf("parsed %+v", c)
	}
}

func TestConfigRejectsBadLines(t *testing.T) {
	for name, tc := range map[string]struct{ text, want string }{
		"unknown key":   {"listen = \"192.0.2.10:8443\"\nlisten_all = \"yes\"\n", "line 2: unknown key \"listen_all\""},
		"duplicate key": {"listen = \"192.0.2.10:8443\"\n\nlisten = \"192.0.2.11:8443\"\n", "line 3: \"listen\" is set twice (first on line 1)"},
		"no quotes":     {"listen = 192.0.2.10:8443\n", "line 1:"},
		"no equals":     {"listen \"192.0.2.10:8443\"\n", "line 1:"},
		"trailing junk": {"listen = \"192.0.2.10:8443\" x\n", "line 1:"},
		"open quote":    {"listen = \"192.0.2.10:8443\n", "line 1:"},
		"backslash":     {"listen = \"192.0.2.10:8443\"\ndata_dir = \"C:\\data\"\n", "line 2:"},
		"control byte":  {"listen = \"192.0.2.10:8443\"\ndata_dir = \"/srv/\x1b[31m\"\n", "line 2:"},
		"section":       {"[server]\nlisten = \"192.0.2.10:8443\"\n", "line 1:"},
		"relative dir":  {"listen = \"192.0.2.10:8443\"\ndata_dir = \"data\"\n", "data_dir"},
	} {
		_, err := parse(t, tc.text)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, tc.want)
		}
	}
}

func TestConfigServerAddrDefaultsAndValidation(t *testing.T) {
	// A literal, specific listen address is the server's address too.
	c, err := parse(t, "listen = \"192.0.2.10:8443\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.ServerAddr != "192.0.2.10" {
		t.Errorf("ServerAddr = %q, want the listen host", c.ServerAddr)
	}
	c, err = parse(t, "listen = \"[2001:db8::10]:8443\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.ServerAddr != "2001:db8::10" {
		t.Errorf("ServerAddr = %q, want the listen host", c.ServerAddr)
	}
	// A wildcard listen address says nothing about where machines see the
	// server from.
	for _, l := range []string{"0.0.0.0:8443", "[::]:8443"} {
		if _, err := parse(t, "listen = \""+l+"\"\n"); err == nil || !strings.Contains(err.Error(), "server_addr") {
			t.Errorf("listen %s without server_addr: err = %v, want one asking for server_addr", l, err)
		}
		c, err := parse(t, "listen = \""+l+"\"\nserver_addr = \"192.0.2.10\"\n")
		if err != nil {
			t.Errorf("listen %s with server_addr: %v", l, err)
		} else if c.ServerAddr != "192.0.2.10" {
			t.Errorf("ServerAddr = %q", c.ServerAddr)
		}
	}
	// server_addr goes into sshd's Match Address and from=: one literal IP.
	for _, bad := range []string{"server.example", "192.0.2.0/24", "192.0.2.*", "0.0.0.0", "fe80::1%eth0", "192.0.2.10 192.0.2.11"} {
		if _, err := parse(t, "listen = \"192.0.2.10:8443\"\nserver_addr = \""+bad+"\"\n"); err == nil || !strings.Contains(err.Error(), "server_addr") {
			t.Errorf("server_addr %q: err = %v, want a refusal", bad, err)
		}
	}
	// An IPv4-mapped address is written the way sshd sees it.
	c, err = parse(t, "listen = \"192.0.2.10:8443\"\nserver_addr = \"::ffff:192.0.2.12\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.ServerAddr != "192.0.2.12" {
		t.Errorf("ServerAddr = %q, want the canonical form", c.ServerAddr)
	}
	if len(c.Warnings) != 0 {
		t.Errorf("warnings for a LAN address: %q", c.Warnings)
	}
}

// A loopback listen address is no address machines can reach, so it is
// never taken as server_addr by default: the enrolment snippets would only
// fail. Set explicitly it is allowed, with a warning.
func TestConfigLoopbackServerAddr(t *testing.T) {
	for _, l := range []string{"127.0.0.1:8443", "[::1]:8443", "127.0.0.53:8443"} {
		if _, err := parse(t, "listen = \""+l+"\"\n"); err == nil || !strings.Contains(err.Error(), "server_addr") || !strings.Contains(err.Error(), "loopback") {
			t.Errorf("listen %s without server_addr: err = %v, want a refusal asking for server_addr", l, err)
		}
		c, err := parse(t, "listen = \""+l+"\"\nserver_addr = \"192.0.2.10\"\n")
		if err != nil {
			t.Errorf("listen %s with a LAN server_addr: %v", l, err)
		} else if len(c.Warnings) != 0 {
			t.Errorf("listen %s with a LAN server_addr: warnings %q", l, c.Warnings)
		}
	}
	for _, a := range []string{"127.0.0.1", "::1"} {
		c, err := parse(t, "listen = \"192.0.2.10:8443\"\nserver_addr = \""+a+"\"\n")
		if err != nil {
			t.Fatalf("server_addr %s set explicitly: %v", a, err)
		}
		if c.ServerAddr != a || len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "loopback") || !strings.Contains(c.Warnings[0], a) {
			t.Errorf("server_addr %s: %+v, want it kept with one warning naming it", a, c)
		}
	}
}

// The shipped unit makes everything but its state directory read-only
// (ProtectSystem=strict), so a key_file the server creates on first use
// must be under a path the unit lets it write.
func TestExampleKeyFileWritableUnderUnit(t *testing.T) {
	ex, err := os.ReadFile("../../deploy/telltale.toml.example")
	if err != nil {
		t.Fatal(err)
	}
	unit, err := os.ReadFile("../../deploy/systemd/telltale.service")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^#?key_file = "([^"]+)"`).FindSubmatch(ex)
	if m == nil {
		t.Fatal("the example has no key_file line")
	}
	keyFile := string(m[1])
	if !strings.Contains(string(unit), "ProtectSystem=strict") {
		t.Fatal("the unit no longer says ProtectSystem=strict; revisit this test")
	}
	var writable []string
	for _, l := range regexp.MustCompile(`(?m)^ReadWritePaths=(.+)$`).FindAllSubmatch(unit, -1) {
		writable = append(writable, strings.Fields(string(l[1]))...)
	}
	for _, l := range regexp.MustCompile(`(?m)^StateDirectory=(.+)$`).FindAllSubmatch(unit, -1) {
		for _, d := range strings.Fields(string(l[1])) {
			writable = append(writable, "/var/lib/"+d)
		}
	}
	ok := false
	for _, d := range writable {
		if strings.HasPrefix(keyFile, strings.TrimSuffix(d, "/")+"/") {
			ok = true
		}
	}
	if !ok {
		t.Errorf("key_file %s is not under a path the unit can write (%v)", keyFile, writable)
	}
	if strings.Contains(string(ex), "/etc/telltale/data.key") || strings.Contains(string(unit), "/etc/telltale/data.key") {
		t.Error("the example or the unit still names /etc/telltale/data.key")
	}
}

func TestConfigWildcard(t *testing.T) {
	for l, want := range map[string]bool{
		"0.0.0.0:8443":     true,
		"[::]:8443":        true,
		"192.0.2.10:8443":  false,
		"127.0.0.1:8443":   false,
		"[2001:db8::1]:80": false,
	} {
		text := "listen = \"" + l + "\"\nserver_addr = \"192.0.2.10\"\n"
		c, err := parse(t, text)
		if err != nil {
			t.Fatalf("%s: %v", l, err)
		}
		if got := c.AllInterfaces(); got != want {
			t.Errorf("%s: AllInterfaces = %v, want %v", l, got, want)
		}
	}
}

func TestLoadNamesTheFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "telltale.toml")
	if err := os.WriteFile(p, []byte("listen = \"192.0.2.10:8443\"\nbogus = \"1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), p+": line 2") {
		t.Errorf("err = %v, want the file and line", err)
	}
}

// The example file shipped in deploy/ parses and documents every key.
func TestExampleDocumentsEveryKey(t *testing.T) {
	b, err := os.ReadFile("../../deploy/telltale.toml.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(strings.NewReader(string(b))); err != nil {
		t.Errorf("the example does not parse: %v", err)
	}
	// Uncommented, every documented setting parses too.
	var lines []string
	for _, l := range strings.Split(string(b), "\n") {
		if regexp.MustCompile(`^#[a-z_]+ = "`).MatchString(l) {
			l = strings.TrimPrefix(l, "#")
		}
		lines = append(lines, l)
	}
	c, err := Parse(strings.NewReader(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatalf("the example with every setting uncommented does not parse: %v", err)
	}
	for k := range keys {
		if !strings.Contains(string(b), k+" = ") || !strings.Contains(string(b), "# "+k+" ") {
			t.Errorf("the example does not document %s", k)
		}
	}
	if c.Unlock.KeyFile == "" || c.BinDir == "" || c.ServerAddr == "" {
		t.Errorf("uncommented example: %+v", c)
	}
}

// The unit bounds the server's memory, and stops it as a whole when the
// kernel has to kill part of it, so that a machine sending far too much
// cannot take the host down with the server.
func TestUnitBoundsMemory(t *testing.T) {
	unit, err := os.ReadFile("../../deploy/systemd/telltale.service")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"MemoryMax=4G", "Environment=GOMEMLIMIT=3GiB", "OOMPolicy=stop", "Restart=on-failure", "RestartSec=30s", "LoadCredential=passphrase:/etc/telltale/passphrase"} {
		if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(want) + `$`).Match(unit) {
			t.Errorf("the unit has no %s line", want)
		}
	}
}

// max_collection_mib bounds what one visit may send; 64 by default.
func TestConfigMaxCollection(t *testing.T) {
	const base = "listen = \"192.0.2.10:8443\"\n"
	c, err := Parse(strings.NewReader(base))
	if err != nil || c.MaxCollectionBytes != visit.DefaultMaxCollection || visit.DefaultMaxCollection != 64<<20 {
		t.Fatalf("default: %d, %v (default constant %d)", c.MaxCollectionBytes, err, visit.DefaultMaxCollection)
	}
	c, err = Parse(strings.NewReader(base + "max_collection_mib = \"384\"\n"))
	if err != nil || c.MaxCollectionBytes != 384<<20 {
		t.Fatalf("384: %d, %v", c.MaxCollectionBytes, err)
	}
	for _, bad := range []string{"0", "-1", "8", "4096", "many", "256MiB", "1e3", ""} {
		_, err := Parse(strings.NewReader(base + "max_collection_mib = \"" + bad + "\"\n"))
		if bad == "" {
			continue // an empty value is caught as any empty value is, or means unset
		}
		if err == nil || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "max_collection_mib") {
			t.Errorf("max_collection_mib = %q: %v", bad, err)
		}
	}
	ex, err := os.ReadFile("../../deploy/telltale.toml.example")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ex), "#max_collection_mib = \"64\"") {
		t.Error("the example configuration does not show max_collection_mib")
	}
}

// The Go runtime is told to keep its heap below the unit's MemoryMax, so
// that it collects garbage harder before the kernel has to kill the service.
func TestUnitSetsGoMemoryLimitBelowMemoryMax(t *testing.T) {
	unit, err := os.ReadFile("../../deploy/systemd/telltale.service")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^Environment=GOMEMLIMIT=(\d+)GiB$`).FindSubmatch(unit)
	x := regexp.MustCompile(`(?m)^MemoryMax=(\d+)G$`).FindSubmatch(unit)
	if m == nil || x == nil {
		t.Fatalf("GOMEMLIMIT %q, MemoryMax %q", m, x)
	}
	limit, _ := strconv.Atoi(string(m[1]))
	most, _ := strconv.Atoi(string(x[1]))
	if limit <= 0 || limit >= most || limit*2 < most {
		t.Errorf("GOMEMLIMIT %d GiB against MemoryMax %d GiB", limit, most)
	}
}
