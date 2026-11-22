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

// inputPolicy returns the policy of the input base chain, preferring family
// inet over ip, and the strictest when several exist; "none" when absent.
func inputPolicy(chains []nftChain) string {
	for _, fam := range []nftables.TableFamily{nftables.TableFamilyINet, nftables.TableFamilyIPv4} {
		got := ""
		for _, c := range chains {
			if c.Family != fam || c.Hook == nil || *c.Hook != *nftables.ChainHookInput {
				continue
			}
			if p := policyName(c.Policy); got == "" || p == "drop" {
				got = p
			}
		}
		if got != "" {
			return got
		}
	}
	return "none"
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
		fw.InputPolicy = inputPolicy(snap.Chains)
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
