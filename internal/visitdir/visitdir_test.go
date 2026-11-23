package visitdir

import "testing"

func TestIs(t *testing.T) {
	for s, want := range map[string]bool{
		"/run/telltale.ABCDEFGH":       true,
		"/var/tmp/telltale.a1b2c3d4":   true,
		"/root/telltale.a1b2c3d4":      true,
		"/tmp/telltale.a1b2c3d4":       true,
		"/run/telltale.ABCDEFGH\n":     false,
		"/run/telltale.ABCDEFGH\n/etc": false,
		"/etc\n/run/telltale.ABCDEFGH": false,
		"/run/telltale.ABCDEFGH\r":     false,
		"/run/telltale.ABCDEFGHI":      false,
		"/usr/telltale.ABCDEFGH":       false,
		"/run/telltale.ABCD/FGH":       false,
		"/run/telltale.ABCDEFG":        false,
	} {
		if got := Is(s); got != want {
			t.Errorf("Is(%q) = %v, want %v", s, got, want)
		}
	}
}
