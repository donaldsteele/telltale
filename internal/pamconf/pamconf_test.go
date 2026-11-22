package pamconf

import "testing"

func TestParseLine(t *testing.T) {
	for _, tc := range []struct {
		in, mod string
		quiet   bool
		ok      bool
	}{
		{"auth optional pam_lab.so", "pam_lab.so", false, true},
		{"auth [success=1 default=ignore] pam_unix.so nullok", "pam_unix.so", false, true},
		{"-session optional pam_systemd.so", "pam_systemd.so", true, true},
		{"auth include runuser", "", false, false},
		{"session substack common-session", "", false, false},
		{"@include common-auth", "", false, false},
		{"auth optional", "", false, false},
		{"bogus optional pam_x.so", "", false, false},
	} {
		m, q, ok := ParseLine(tc.in)
		if m != tc.mod || q != tc.quiet || ok != tc.ok {
			t.Errorf("%q: got %q %v %v", tc.in, m, q, ok)
		}
	}
}

func TestCandidatesAreCleaned(t *testing.T) {
	got := Candidates("../../../../tmp/x.so", nil)
	if got[0] != "/tmp/x.so" {
		t.Errorf("got %v", got)
	}
	if got := Candidates("/opt//a/../x.so", nil); len(got) != 1 || got[0] != "/opt/x.so" {
		t.Errorf("abs: %v", got)
	}
	if got := Candidates("pam_x.so", []string{"/usr/lib/x86_64-linux-gnu/security"}); got[0] != "/lib/security/pam_x.so" || got[len(got)-1] != "/usr/lib/x86_64-linux-gnu/security/pam_x.so" {
		t.Errorf("bare: %v", got)
	}
}
