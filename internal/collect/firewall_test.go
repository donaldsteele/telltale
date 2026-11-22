package collect

import (
	"errors"
	"os"
	"testing"

	"github.com/google/nftables"
)

func TestFirewallUFWConf(t *testing.T) {
	for val, want := range map[string]bool{"yes": true, "\"no\"": false} {
		root := t.TempDir()
		writeTree(t, root, map[string]string{"etc/ufw/ufw.conf": "# c\nENABLED=" + val + "\nLOGLEVEL=low\n"})
		fw, _ := Firewall(root)
		if fw.UFWEnabled == nil || *fw.UFWEnabled != want {
			t.Errorf("%s: %v", val, fw.UFWEnabled)
		}
	}
	fw, _ := Firewall(t.TempDir())
	if fw.UFWEnabled != nil {
		t.Error("missing conf must be nil")
	}
}

func TestFirewallNetlinkSkipWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	fw, skips := Firewall(t.TempDir())
	if fw.Backend != "unknown" || len(skips) == 0 {
		t.Errorf("%+v %v", fw, skips)
	}
}

func TestFirewallInjectedError(t *testing.T) {
	old := nftList
	nftList = func() (nftSnapshot, error) { return nftSnapshot{}, errors.New("boom") }
	defer func() { nftList = old }()
	fw, skips := Firewall(t.TempDir())
	if fw.Backend != "unknown" || len(skips) != 1 {
		t.Errorf("%+v %v", fw, skips)
	}
}

func TestFirewallInputPolicySelection(t *testing.T) {
	drop, accept := nftables.ChainPolicyDrop, nftables.ChainPolicyAccept
	in := nftables.ChainHookInput
	fwd := nftables.ChainHookForward
	mk := func(fam nftables.TableFamily, hook *nftables.ChainHook, pol *nftables.ChainPolicy) nftChain {
		return nftChain{Family: fam, Hook: hook, Policy: pol, Rules: 2}
	}
	cases := []struct {
		name   string
		chains []nftChain
		want   string
	}{
		{"inet drop + ip accept", []nftChain{mk(nftables.TableFamilyIPv4, in, &accept), mk(nftables.TableFamilyINet, in, &drop)}, "drop"},
		{"ip only", []nftChain{mk(nftables.TableFamilyIPv4, in, &accept)}, "accept"},
		{"no input", []nftChain{mk(nftables.TableFamilyINet, fwd, &drop), mk(nftables.TableFamilyINet, nil, nil)}, "none"},
		{"empty", nil, "none"},
		{"ip6 ignored", []nftChain{mk(nftables.TableFamilyIPv6, in, &drop)}, "none"},
	}
	for _, c := range cases {
		if got := inputPolicy(c.chains); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
	old := nftList
	nftList = func() (nftSnapshot, error) {
		return nftSnapshot{Tables: 2, Chains: []nftChain{mk(nftables.TableFamilyINet, in, &drop), mk(nftables.TableFamilyINet, nil, nil)}}, nil
	}
	defer func() { nftList = old }()
	fw, _ := Firewall(t.TempDir())
	if fw.Backend != "nftables" || fw.Tables != 2 || fw.Rules != 4 || fw.InputPolicy != "drop" {
		t.Errorf("%+v", fw)
	}
}
