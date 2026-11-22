package sshglob

import "testing"

func TestPattern(t *testing.T) {
	cases := map[string]string{
		"/etc/ssh/sshd_config.d/*.conf": "/etc/ssh/sshd_config.d/*.conf",
		"/etc/ssh/evil/[!a]*":           "/etc/ssh/evil/[^a]*",
		"/x/[!]a]":                      `/x/[^\]a]`,
		"/x/[]a]":                       `/x/[\]a]`,
		"/x/[a!]":                       "/x/[a!]",
		`/x/\[!a]`:                      `/x/\[!a]`,
		"/x/[^a]":                       "/x/[^a]",
	}
	for in, want := range cases {
		if got := Pattern(in); got != want {
			t.Errorf("Pattern(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatch(t *testing.T) {
	cases := []struct {
		pat, name string
		want      bool
	}{
		{"/etc/ssh/evil/[!a]*", "/etc/ssh/evil/b.conf", true},
		{"/etc/ssh/evil/[!a]*", "/etc/ssh/evil/a.conf", false},
		{"/etc/ssh/sshd_config.d/*.conf", "/etc/ssh/sshd_config.d/10-a.conf", true},
		// glob(3): a wildcard never matches a leading dot.
		{"/etc/ssh/sshd_config.d/*.conf", "/etc/ssh/sshd_config.d/.hidden.conf", false},
		{"/etc/ssh/sshd_config.d/.*.conf", "/etc/ssh/sshd_config.d/.hidden.conf", true},
		{"/etc/ssh/sshd_config.d/?hidden.conf", "/etc/ssh/sshd_config.d/.hidden.conf", false},
		{"/etc/ssh/*/x.conf", "/etc/ssh/.d/x.conf", false},
		{"/etc/ssh/[", "/etc/ssh/[", false}, // malformed: no match
	}
	for _, c := range cases {
		if got := Match(c.pat, c.name); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pat, c.name, got, c.want)
		}
	}
}
