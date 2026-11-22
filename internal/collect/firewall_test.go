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
	in, fwd := nftables.ChainHookInput, nftables.ChainHookForward
	mk := func(fam nftables.TableFamily, hook *nftables.ChainHook, pol *nftables.ChainPolicy, rules int) nftChain {
		return nftChain{Family: fam, Hook: hook, Policy: pol, Rules: rules}
	}
	inet, ip4, ip6 := nftables.TableFamilyINet, nftables.TableFamilyIPv4, nftables.TableFamilyIPv6
	cases := []struct {
		name      string
		chains    []nftChain
		want      string
		inputRule int
	}{
		{"ip drop + inet accept", []nftChain{mk(inet, in, &accept, 0), mk(ip4, in, &drop, 1)}, "drop", 1},
		{"ip6 only drop", []nftChain{mk(ip6, in, &drop, 2)}, "drop", 2},
		{"inet accept with 3 rules", []nftChain{mk(inet, in, &accept, 3), mk(inet, fwd, &drop, 9)}, "accept", 3},
		{"no input chains", []nftChain{mk(inet, fwd, &drop, 5), mk(inet, nil, nil, 4)}, "none", 0},
		{"empty", nil, "none", 0},
	}
	old := nftList
	defer func() { nftList = old }()
	for _, c := range cases {
		nftList = func() (nftSnapshot, error) { return nftSnapshot{Tables: 2, Chains: c.chains}, nil }
		fw, _ := Firewall(t.TempDir())
		if fw.Backend != "nftables" || fw.InputPolicy != c.want || fw.InputRules != c.inputRule {
			t.Errorf("%s: %+v", c.name, fw)
		}
	}
}
