package collect

import (
	"errors"
	"os"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
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

// Chains that services manage themselves change all day: fail2ban adds and
// removes bans, Docker and libvirt rewrite theirs as containers and networks
// come and go. They are left out of the counts, so that the snapshot
// comparison sees only rules somebody wrote. A rule gone from a chain the
// owner's firewall manages still shows.
func TestFirewallLeavesOutManagedChains(t *testing.T) {
	drop := nftables.ChainPolicyDrop
	in, fwd := nftables.ChainHookInput, nftables.ChainHookForward
	ip4 := nftables.TableFamilyIPv4
	base := func() nftSnapshot {
		return nftSnapshot{
			TableNames: []string{"filter", "nat"},
			Chains: []nftChain{
				{Family: ip4, Table: "filter", Name: "INPUT", Hook: in, Policy: &drop, Rules: 4},
				{Family: ip4, Table: "filter", Name: "FORWARD", Hook: fwd, Policy: &drop, Rules: 3},
				{Family: ip4, Table: "filter", Name: "ufw-user-input", Rules: 6},
				{Family: ip4, Table: "filter", Name: "DOCKER-USER", Rules: 2},
			},
		}
	}
	collect := func(s nftSnapshot) model.Firewall {
		old := nftList
		defer func() { nftList = old }()
		nftList = func() (nftSnapshot, error) { return s, nil }
		fw, _ := Firewall(t.TempDir())
		return fw
	}
	want := collect(base())
	if want.Rules != 15 || want.InputRules != 4 || want.Tables != 2 {
		t.Fatalf("baseline %+v", want)
	}

	busy := base()
	busy.TableNames = append(busy.TableNames, "f2b-table", "libvirt_network", "netavark")
	for _, c := range []nftChain{
		{Table: "filter", Name: "f2b-sshd", Rules: 37},
		{Table: "filter", Name: "DOCKER", Rules: 12},
		{Table: "filter", Name: "DOCKER-ISOLATION-STAGE-1", Rules: 5},
		{Table: "nat", Name: "DOCKER", Rules: 9},
		{Table: "filter", Name: "LIBVIRT_INP", Rules: 4},
		{Table: "filter", Name: "CNI-FORWARD", Rules: 3},
		{Table: "filter", Name: "KUBE-SERVICES", Rules: 80},
		{Table: "filter", Name: "NETAVARK_FORWARD", Rules: 7},
		{Table: "f2b-table", Name: "f2b-chain", Hook: in, Rules: 21},
		{Table: "libvirt_network", Name: "guest_input", Hook: in, Rules: 6},
		{Table: "netavark", Name: "INPUT", Hook: in, Rules: 2},
	} {
		c.Family = ip4
		busy.Chains = append(busy.Chains, c)
	}
	if got := collect(busy); got != want {
		t.Errorf("managed chains change the summary:\n got %+v\nwant %+v", got, want)
	}

	// A deny rule gone from the owner's own chain, and a rule gone from
	// DOCKER-USER (the one Docker chain the owner writes), are counted.
	for _, name := range []string{"ufw-user-input", "DOCKER-USER"} {
		less := base()
		for i := range less.Chains {
			if less.Chains[i].Name == name {
				less.Chains[i].Rules--
			}
		}
		if got := collect(less); got.Rules != want.Rules-1 {
			t.Errorf("%s lost a rule: %d rules, want %d", name, got.Rules, want.Rules-1)
		}
	}
}
