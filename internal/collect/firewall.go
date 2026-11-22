package collect

import (
	"fmt"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/google/nftables"
)

const firewallCheck = "firewall"

type nftChain struct {
	Family nftables.TableFamily
	Hook   *nftables.ChainHook
	Policy *nftables.ChainPolicy
	Rules  int
}

type nftSnapshot struct {
	Tables int
	Chains []nftChain
}

// nftList reads the live ruleset over netlink; tests replace it.
var nftList = func() (nftSnapshot, error) {
	var s nftSnapshot
	c, err := nftables.New()
	if err != nil {
		return s, err
	}
	defer c.CloseLasting()
	tables, err := c.ListTables()
	if err != nil {
		return s, err
	}
	s.Tables = len(tables)
	chains, err := c.ListChains()
	if err != nil {
		return s, err
	}
	for _, ch := range chains {
		rules, err := c.GetRules(ch.Table, ch)
		if err != nil {
			return s, err
		}
		s.Chains = append(s.Chains, nftChain{Family: ch.Table.Family, Hook: ch.Hooknum, Policy: ch.Policy, Rules: len(rules)})
	}
	return s, nil
}

func policyName(p *nftables.ChainPolicy) string {
	if p != nil && *p == nftables.ChainPolicyDrop {
		return "drop"
	}
	return "accept" // nftables default for a base chain without an explicit policy
}

// inputPolicy returns the strictest policy across all input base chains in
// inet, ip and ip6 (drop beats accept), and the number of rules in them.
// The policy is "none" when there is no such chain.
func inputPolicy(chains []nftChain) (string, int) {
	got, rules := "none", 0
	for _, c := range chains {
		switch c.Family {
		case nftables.TableFamilyINet, nftables.TableFamilyIPv4, nftables.TableFamilyIPv6:
		default:
			continue
		}
		if c.Hook == nil || *c.Hook != *nftables.ChainHookInput {
			continue
		}
		rules += c.Rules
		if p := policyName(c.Policy); got == "none" || p == "drop" {
			got = p
		}
	}
	return got, rules
}

// Firewall reports the live nftables ruleset and ufw's configuration.
func Firewall(root string) (model.Firewall, []model.Skip) {
	var skips []model.Skip
	fw := model.Firewall{Backend: "unknown", InputPolicy: "none"}
	snap, err := nftList()
	if err != nil {
		skips = append(skips, model.Skip{Check: firewallCheck, Reason: "nftables: " + err.Error()})
	} else {
		fw.Backend = "nftables"
		fw.Tables = snap.Tables
		for _, c := range snap.Chains {
			fw.Rules += c.Rules
		}
		fw.InputPolicy, fw.InputRules = inputPolicy(snap.Chains)
	}
	b, err := readRaw(root, "/etc/ufw/ufw.conf", 64<<10)
	if err != nil {
		if !isNotExist(err) {
			skips = append(skips, model.Skip{Check: firewallCheck, Reason: fmt.Sprintf("/etc/ufw/ufw.conf: %v", err)})
		}
		return fw, skips
	}
	for _, l := range splitLines(b) {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok || strings.TrimSpace(k) != "ENABLED" {
			continue
		}
		on := strings.EqualFold(unquote(strings.TrimSpace(v)), "yes")
		fw.UFWEnabled = &on
	}
	return fw, skips
}
