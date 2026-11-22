package pkgverify

import (
	"context"
	"strings"
	"testing"
	"time"
)

// clockFixture serves bookworm (dated mainAt) with the tool package and
// bookworm-security (dated secAt, valid for a week), and returns the options
// for a machine whose clock says clock and whose tool package claims a
// version no source has.
func clockVerify(t *testing.T, mainAt, secAt, clock time.Time) *Result {
	t.Helper()
	signer := readFakeKey(t)
	files := map[string][]byte{}
	tool := fakePkg{"tool", "1.0-1", "amd64", toolDeb(t, "xz")}
	for k, v := range fakeSuite(t, signer, mainAt, "/debian", "bookworm", "",
		map[string][]byte{"main/binary-amd64/Packages.xz": xzBytes(t, []byte(stanza(tool.name, tool.version, tool.arch, poolName(tool), tool.deb)))}) {
		files[k] = v
	}
	files["/debian/"+poolName(tool)] = tool.deb
	for k, v := range fakeSuite(t, signer, secAt, "/debian", "bookworm-security", "Valid-Until: "+secAt.Add(7*24*time.Hour).Format(time.RFC1123)+"\n",
		map[string][]byte{"main/binary-amd64/Packages.xz": xzBytes(t, []byte(""))}) {
		files[k] = v
	}
	srv := newArchiveServer(t, files)
	a := &Archive{BaseURL: srv.URL + "/debian", Suites: []string{"bookworm", "bookworm-security"}, Components: []string{"main"},
		Keyring: fakePublicKeyring(t), Client: srv.Client(), Now: fixedClock(clock)}
	old := testFinder(srv, fakePublicKeyring(t), fakePublicKeyring(t))
	old.Now = fixedClock(clock)
	c := toolCollection(nil)
	c.Packages.Installed[0].Version = "1.0-9" // trojaned: a version no source has
	return Verify(context.Background(), c, Options{Archives: []*Archive{a}, Old: old, Now: fixedClock(clock)})
}

// Root can set the machine's clock. Whether the host's signed indexes are
// usable must not depend on it, or moving the clock would turn "no trusted
// source has this version" (a backdoor sign) into "the archive could not be
// reached" (one note). Time is taken from the newest signed Date among the
// indexes just fetched; the clock only yields a note when it disagrees.
func TestVerifyTimeComesFromTheSignedIndexes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		clock time.Time
		skew  bool
	}{
		{"correct clock", recordedNow.Add(time.Hour), false},
		{"correct clock, indexes not re-signed for three days", recordedNow.Add(3 * 24 * time.Hour), false},
		{"clock 8 days forward (past the security Valid-Until)", recordedNow.Add(8 * 24 * time.Hour), true},
		{"clock 2 days back (signatures dated in the future)", recordedNow.Add(-48 * time.Hour), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := clockVerify(t, recordedNow, recordedNow, tc.clock)
			if len(res.Unverifiable) != 4 {
				t.Fatalf("unverifiable = %+v, want the package's 4 files", res.Unverifiable)
			}
			for _, v := range res.Unverifiable {
				if v.Kind != KindNotFound {
					t.Errorf("%s: kind %q (%s), want %q whatever the clock says", v.Path, v.Kind, v.Reason, KindNotFound)
				}
			}
			if len(res.Errors) != 0 {
				t.Errorf("errors = %q, want none", res.Errors)
			}
			switch {
			case !tc.skew && res.ClockSkew != nil:
				t.Errorf("clock skew %+v reported for a correct clock", res.ClockSkew)
			case tc.skew && (res.ClockSkew == nil || !res.ClockSkew.Clock.Equal(tc.clock) || !res.ClockSkew.Signed.Equal(recordedNow)):
				t.Errorf("clock skew = %+v, want clock %s against signed date %s", res.ClockSkew, tc.clock, recordedNow)
			}
		})
	}
}

// A replayed, expired index stays refused: its Valid-Until is compared with
// the newest signed Date, so setting the clock back does not revive it.
func TestVerifyStaleIndexIsRefusedWhateverTheClock(t *testing.T) {
	stale := recordedNow.Add(-10 * 24 * time.Hour) // valid until three days ago
	for name, clock := range map[string]time.Time{"correct clock": recordedNow, "clock set back into its validity": stale.Add(24 * time.Hour)} {
		t.Run(name, func(t *testing.T) {
			res := clockVerify(t, recordedNow, stale, clock)
			if len(res.Unverifiable) == 0 {
				t.Fatal("no unverifiable verdicts")
			}
			for _, v := range res.Unverifiable {
				if v.Kind != KindUnreachable {
					t.Errorf("%s: kind %q, want %q", v.Path, v.Kind, KindUnreachable)
				}
			}
			if len(res.Errors) == 0 || !strings.Contains(strings.Join(res.Errors, "\n"), "Valid-Until") {
				t.Errorf("errors = %q, want the expired Valid-Until", res.Errors)
			}
		})
	}
}

// An index whose signature was made more than a day after the newest signed
// Date is refused: nothing vouches for that time.
func TestVerifySignatureFarAfterTheSignedDate(t *testing.T) {
	signer := readFakeKey(t)
	rel := "Origin: Fake\nLabel: Fake\nSuite: bookworm\nCodename: bookworm\nDate: " + recordedNow.Add(-72*time.Hour).Format(time.RFC1123) +
		"\nSHA256:\n " + sha256hex(nil) + " 0 main/binary-amd64/Packages\n"
	srv := newArchiveServer(t, map[string][]byte{"/debian/dists/bookworm/InRelease": clearsignWith(t, signer, []byte(rel), recordedNow)})
	a := &Archive{BaseURL: srv.URL + "/debian", Suites: []string{"bookworm"}, Components: []string{"main"}, Keyring: fakePublicKeyring(t), Client: srv.Client()}
	res := Verify(context.Background(), toolCollection(nil), Options{Archives: []*Archive{a}, Now: fixedClock(recordedNow)})
	if len(res.Verified) != 0 || len(res.Unverifiable) == 0 || res.Unverifiable[0].Kind != KindBadSignature || !strings.Contains(res.Unverifiable[0].Reason, "more than a day after") {
		t.Errorf("verified %+v, unverifiable %+v; want the index refused as a bad signature", res.Verified, res.Unverifiable)
	}
}

// A replayed index that had already expired at the newest signed date is
// refused; it does not make a correct clock look wrong.
func TestVerifyStaleIndexIsNoWitnessAgainstTheClock(t *testing.T) {
	if res := clockVerify(t, recordedNow, recordedNow.Add(-10*24*time.Hour), recordedNow.Add(time.Hour)); res.ClockSkew != nil {
		t.Errorf("clock skew %+v reported for a correct clock", res.ClockSkew)
	}
}
