package collect

import (
	"os"
	"strings"
	"testing"
)

func TestCollectAllFixtureRoot(t *testing.T) {
	c, err := All(Options{Root: "testdata/root1", ProcRoot: "testdata/proc1", SysRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if c.Schema != 1 {
		t.Errorf("schema = %d", c.Schema)
	}
	if c.Host.OSID == "" || c.Time.IsZero() {
		t.Errorf("host/time empty: %+v %v", c.Host, c.Time)
	}
	if len(c.Files) == 0 || len(c.Accounts.Users) == 0 || len(c.Persist) == 0 ||
		len(c.Runtime.Processes) == 0 || len(c.Packages.Installed) == 0 || c.Firewall.UFWEnabled == nil {
		t.Errorf("empty section: files=%d users=%d persist=%d procs=%d pkgs=%d ufw=%v",
			len(c.Files), len(c.Accounts.Users), len(c.Persist), len(c.Runtime.Processes),
			len(c.Packages.Installed), c.Firewall.UFWEnabled)
	}
}

func TestCollectAsNonRootListsSkips(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	c, err := All(Options{Root: "/", ProcRoot: "/proc", SysRoot: "/sys"})
	if err != nil {
		t.Fatal(err)
	}
	if c.AsRoot {
		t.Fatal("AsRoot true for non-root")
	}
	var shadow, fw, priv bool
	for _, s := range c.Skipped {
		shadow = shadow || (s.Check == "accounts" && strings.Contains(s.Reason, "shadow"))
		fw = fw || s.Check == "firewall"
		priv = priv || s.Check == "privileges"
	}
	if !shadow || !fw || !priv {
		t.Errorf("missing skips shadow=%v firewall=%v privileges=%v: %+v", shadow, fw, priv, c.Skipped)
	}
}
