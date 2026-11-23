package judge

import (
	"slices"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify"
	"github.com/donaldsteele/telltale/internal/pkgverify/vendorkeys"
	"github.com/donaldsteele/telltale/internal/repokeys"
)

func pgpKey(t *testing.T, name string) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity(name, "", name+"@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func repoTrust(t *testing.T, url, suite, origin string, keys ...*openpgp.Entity) model.RepoTrust {
	t.Helper()
	tr := model.RepoTrust{URL: url, Suite: suite, Components: []string{"main"}, KeyOrigin: origin}
	for _, k := range keys {
		b, err := repokeys.Blob(k)
		if err != nil {
			t.Fatal(err)
		}
		tr.Keys = append(tr.Keys, b)
	}
	return tr
}

// runWith is run with a vendor table given.
func runWith(c *model.Collection, s *model.Snapshot, r *pkgverify.Result, v *vendorkeys.Table) *model.Report {
	if s != nil && s.Collection != nil {
		inventoried(s.Collection)
	}
	return Judge(Input{Collection: inventoried(c), Snapshot: s, Context: ctx, Pkg: r, Now: now, Vendors: v})
}

const vendorRepo = "https://repo.vendor.test/apt"

// vendorMachine has lab-vendor installed from a third-party repository.
func vendorMachine(version, content string, trust ...model.RepoTrust) *model.Collection {
	c := clean()
	c.Packages.Installed = append(c.Packages.Installed, pkg("lab-vendor", version, "/opt/lab-vendor/agent"))
	c.Files = append(c.Files, file("/opt/lab-vendor/agent", content, 0o755))
	c.Packages.RepoTrust = trust
	return c
}

func TestRepoKeyChangedNote(t *testing.T) {
	oldKey, newKey := pgpKey(t, "old"), pgpKey(t, "new")
	origin := model.KeyOriginSignedBy + " /usr/share/keyrings/vendor.gpg"
	none := &vendorkeys.Table{}
	old := vendorMachine("1.0", "agent 1.0", repoTrust(t, vendorRepo, "stable", origin, oldKey))
	const key = "pkg.repo_key_changed:" + vendorRepo

	// The same key as at the snapshot: nothing to say.
	same := vendorMachine("1.0", "agent 1.0", repoTrust(t, vendorRepo, "stable", origin, oldKey))
	absent(t, runWith(same, snapOf(clone(old)), archive(), none), key)
	// No snapshot: nothing to compare with.
	absent(t, runWith(clone(same), nil, archive(), none), key)

	// The machine now trusts another key for the repository, and the
	// package was upgraded from it. The index is signed by a key the
	// snapshot does not know, so the new version is not confirmed.
	cur := vendorMachine("2.0", "agent 2.0", repoTrust(t, vendorRepo, "stable", origin, newKey))
	res := archive()
	res.Unverifiable = []pkgverify.FileVerdict{{Path: "/opt/lab-vendor/agent", Package: "lab-vendor", Version: "2.0", Actual: h("agent 2.0"),
		Reason: pkgverify.ReasonNotOfficial + "; source not trusted: " + vendorRepo, Kind: pkgverify.KindUntrusted}}
	r := runWith(cur, snapOf(clone(old)), res, none)
	f := must(t, r, key, model.SevNote)
	for _, want := range []string{"rotat", "swapped"} {
		if !strings.Contains(f.Why, want) {
			t.Errorf("Why does not mention %q: %s", want, f.Why)
		}
	}
	if !strings.Contains(evidenceText(f), repokeys.Fingerprint(oldKey)) || !strings.Contains(evidenceText(f), repokeys.Fingerprint(newKey)) {
		t.Errorf("evidence lacks the old and new fingerprints: %+v", f.Evidence)
	}
	// The note changes nothing about the upgrade: it stays unconfirmed.
	if explained(r, "explained:lab-vendor") != nil {
		t.Errorf("an upgrade signed by a changed key was explained")
	}
	if up := find(r, "snap.pkg_upgraded:lab-vendor"); up == nil || up.Severity < model.SevNote {
		t.Errorf("the unconfirmed upgrade is not reported: %v", keys(r))
	}

	// A key added beside the old one is a change too.
	both := vendorMachine("1.0", "agent 1.0", repoTrust(t, vendorRepo, "stable", origin, oldKey, newKey))
	must(t, runWith(both, snapOf(clone(old)), archive(), none), key, model.SevNote)
	// Another suite of the same repository is compared on its own.
	other := vendorMachine("1.0", "agent 1.0", repoTrust(t, vendorRepo, "stable", origin, oldKey), repoTrust(t, vendorRepo, "beta", origin, newKey))
	absent(t, runWith(other, snapOf(clone(old)), archive(), none), key)
}

// A third-party upgrade a trusted key confirmed is explained like one from
// the distribution, and the changed-key note alone does not alter that.
func TestThirdPartyUpgradeConfirmedIsExplained(t *testing.T) {
	k := pgpKey(t, "vendor")
	origin := model.KeyOriginSignedBy + " /usr/share/keyrings/vendor.gpg"
	old := vendorMachine("1.0", "agent 1.0", repoTrust(t, vendorRepo, "stable", origin, k))
	cur := vendorMachine("2.0", "agent 2.0", repoTrust(t, vendorRepo, "stable", origin, k))
	for i := range cur.Files {
		if cur.Files[i].Path == "/opt/lab-vendor/agent" {
			cur.Files[i].CTime = changed
		}
	}
	v := pkgverify.FileVerdict{Path: "/opt/lab-vendor/agent", Package: "lab-vendor", Version: "2.0", Expected: h("agent 2.0"), Actual: h("agent 2.0"), Source: pkgverify.SourceThirdParty}
	r := runWith(cur, snapOf(clone(old)), archive(v), &vendorkeys.Table{})
	if len(r.Findings) != 0 {
		t.Errorf("findings %v", keys(r))
	}
	if explained(r, "explained:lab-vendor") == nil {
		t.Errorf("the confirmed third-party upgrade is not explained: %+v", r.Explained)
	}
}

func TestRepoKeyNotVendorNote(t *testing.T) {
	pinned, pinned2, stranger := pgpKey(t, "pinned"), pgpKey(t, "pinned2"), pgpKey(t, "stranger")
	pub := func(es ...*openpgp.Entity) openpgp.EntityList {
		var out openpgp.EntityList
		for _, e := range es {
			out = append(out, repokeys.Entities([]model.KeyBlob{mustBlob(t, e)})...)
		}
		return out
	}
	table := &vendorkeys.Table{Vendors: []*vendorkeys.Vendor{vendorkeys.NewVendor("Example Vendor", []string{vendorRepo}, pub(pinned, pinned2))}}
	origin := model.KeyOriginSignedBy + " /usr/share/keyrings/vendor.gpg"
	const key = "pkg.repo_key_not_vendor:" + vendorRepo

	// The machine trusts exactly a pinned key: nothing to say.
	absent(t, runWith(vendorMachine("1.0", "a", repoTrust(t, vendorRepo, "stable", origin, pinned)), nil, archive(), table), key)
	// It trusts a key the vendor never published for that address.
	f := must(t, runWith(vendorMachine("1.0", "a", repoTrust(t, vendorRepo, "stable", origin, stranger)), nil, archive(), table), key, model.SevNote)
	if !strings.Contains(evidenceText(f), repokeys.Fingerprint(stranger)) || !strings.Contains(f.Title+f.Why, "Example Vendor") {
		t.Errorf("the note does not name the key and the vendor: %s / %s / %+v", f.Title, f.Why, f.Evidence)
	}
	// A key beside the vendor's own, in the source's keyring.
	must(t, runWith(vendorMachine("1.0", "a", repoTrust(t, vendorRepo, "stable", origin, pinned, stranger)), nil, archive(), table), key, model.SevNote)
	// With a snapshot too.
	old := vendorMachine("1.0", "a", repoTrust(t, vendorRepo, "stable", origin, stranger))
	must(t, runWith(clone(old), snapOf(old), archive(), table), key, model.SevNote)
	// A source that names no key accepts the whole global keyring, the
	// distribution's keys included: that alone is not a strange key for
	// the vendor, as long as the vendor's key is among them.
	absent(t, runWith(vendorMachine("1.0", "a", repoTrust(t, vendorRepo, "stable", model.KeyOriginGlobal, pinned, stranger)), nil, archive(), table), key)
	must(t, runWith(vendorMachine("1.0", "a", repoTrust(t, vendorRepo, "stable", model.KeyOriginGlobal, stranger)), nil, archive(), table), key, model.SevNote)
	// Another address is not the vendor's.
	absent(t, runWith(vendorMachine("1.0", "a", repoTrust(t, vendorRepo+"x", "stable", origin, stranger)), nil, archive(), table), "pkg.repo_key_not_vendor:"+vendorRepo+"x")
}

func mustBlob(t *testing.T, e *openpgp.Entity) model.KeyBlob {
	t.Helper()
	b, err := repokeys.Blob(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func evidenceText(f *model.Finding) string {
	var b strings.Builder
	for _, e := range f.Evidence {
		b.WriteString(e.Path + " " + e.Before + " " + e.After + " " + e.Detail + "\n")
	}
	return b.String()
}

// A vendor package links a job into /etc/cron.daily from its postinst, the
// way Chrome's does: the link is nobody's, the job it runs is the package's
// file. An upgrade that changes the job changes what the link runs. When a
// trusted source confirms the new job, that is the package's upgrade, not a
// changed scheduled job; when nothing confirms it, or the link itself leads
// somewhere else now, it stays a backdoor sign.
func TestCronLinkToAPackageFileFollowsAConfirmedUpgrade(t *testing.T) {
	const link, job = "/etc/cron.daily/lab-vendor", "/opt/lab-vendor/cron/lab-vendor"
	const key = "snap.persist:" + link
	machine := func(version, content, target string) *model.Collection {
		c := clean()
		c.Packages.Installed = append(c.Packages.Installed, pkg("lab-vendor", version, job))
		f := file(job, content, 0o755)
		if version != "1.0" {
			f.CTime, f.MTime = changed, changed
		}
		c.Files = append(c.Files, f)
		lines := append([]string{target}, strings.Split(content, "\n")...)
		c.Persist = append(c.Persist, model.PersistFile{Path: link, Kind: model.PersistKindCron, Mode: 0o120777, SHA256: h(content), Lines: lines, MTime: taken})
		return c
	}
	old := machine("1.0", "#!/bin/sh\n# 1.0\nexit 0", job)
	cur := machine("2.0", "#!/bin/sh\n# 2.0\nexit 0", job)
	confirmed := func() *pkgverify.Result {
		return archive(pkgverify.FileVerdict{Path: job, Package: "lab-vendor", Version: "2.0", Expected: h("#!/bin/sh\n# 2.0\nexit 0"), Actual: h("#!/bin/sh\n# 2.0\nexit 0"), Source: pkgverify.SourceThirdParty})
	}

	r := runWith(clone(cur), snapOf(clone(old)), confirmed(), &vendorkeys.Table{})
	absent(t, r, key)
	if e := explained(r, "explained:lab-vendor"); e == nil || !hasEvidencePath(e, link) {
		t.Errorf("the link's changed job is not shown with the confirmed upgrade: %+v", r.Explained)
	}

	// No trusted source confirmed the new version.
	res := archive()
	res.Unverifiable = []pkgverify.FileVerdict{{Path: job, Package: "lab-vendor", Version: "2.0", Actual: h("#!/bin/sh\n# 2.0\nexit 0"), Reason: pkgverify.ReasonNotOfficial, Kind: pkgverify.KindUntrusted}}
	must(t, runWith(clone(cur), snapOf(clone(old)), res, &vendorkeys.Table{}), key, model.SevBackdoor)

	// The verdict is about other content than the job has now.
	stale := confirmed()
	stale.Verified[0].Actual, stale.Verified[0].Expected = h("other"), h("other")
	must(t, runWith(clone(cur), snapOf(clone(old)), stale, &vendorkeys.Table{}), key, model.SevBackdoor)

	// The link was pointed at another file, however well that one verifies.
	moved := machine("2.0", "#!/bin/sh\n# 2.0\nexit 0", "/opt/lab-vendor/cron/../cron/lab-vendor")
	must(t, runWith(moved, snapOf(clone(old)), confirmed(), &vendorkeys.Table{}), key, model.SevBackdoor)

	// The link reads as before, but a directory on the way to its target is
	// a link now and leads elsewhere: the job the link runs is another file
	// than at the snapshot, even one that matches the package.
	const elsewhere = "/srv/x/lab-vendor"
	redirected := machine("2.0", "#!/bin/sh\n# 2.0\nexit 0", job)
	redirected.Files = slices.DeleteFunc(redirected.Files, func(e model.FileEntry) bool { return e.Path == job })
	there := file(elsewhere, "#!/bin/sh\n# 2.0\nexit 0", 0o755)
	there.CTime, there.MTime = changed, changed
	redirected.Files = append(redirected.Files, dirAt("/opt"), dirAt("/opt/lab-vendor"), symlinkAt("/opt/lab-vendor/cron", "/srv/x", changed), dirAt("/srv"), dirAt("/srv/x"), there)
	res = confirmed()
	res.Verified[0].Path, res.Verified[0].Listed = elsewhere, []string{job}
	must(t, runWith(redirected, snapOf(clone(old)), res, &vendorkeys.Table{}), key, model.SevBackdoor)
}
