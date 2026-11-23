package config

import (
	"os"
	"path/filepath"
	"regexp"
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
