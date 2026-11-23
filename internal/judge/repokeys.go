package judge

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify/vendorkeys"
)

// repoKeys reports what the keys the machine accepts for its third-party
// APT repositories say, compared with what telltale trusts:
//
//   - pkg.repo_key_changed:<url>: the keys differ from the ones the snapshot
//     recorded for that repository and suite.
//   - pkg.repo_key_not_vendor:<url>: the address is a well-known vendor's and
//     the machine accepts a key for it that is not one of the vendor's
//     pinned keys.
//
// Both are notes. Neither decides how a package version is judged: a
// version is confirmed only by an index that verifies with a trusted key
// (the snapshot's, a pinned vendor key, or --keys), never by a key the
// machine holds now.
func (j *judge) repoKeys() {
	cur := j.c.Packages.RepoTrust
	if len(cur) == 0 {
		return
	}
	var old []model.RepoTrust
	if j.old != nil {
		old = j.old.Packages.RepoTrust
	}
	vendors := j.in.Vendors
	if vendors == nil {
		vendors, _ = vendorkeys.Builtin() // an unreadable table is package verification's to report
	}

	type suiteDiff struct {
		suite          string
		added, removed []string
		origin, was    string
	}
	changed := map[string][]suiteDiff{}
	type strange struct {
		suite, origin string
		keys          []string
		vendor        *vendorkeys.Vendor
		vendors       []*vendorkeys.Vendor
	}
	notVendor := map[string][]strange{}
	var urls []string
	note := func(u string) {
		if !slices.Contains(urls, u) {
			urls = append(urls, u)
		}
	}
	for _, t := range cur {
		now := t.Fingerprints()
		for _, o := range old {
			if o.URL != t.URL || o.Suite != t.Suite {
				continue
			}
			was := o.Fingerprints()
			d := suiteDiff{suite: t.Suite, origin: t.KeyOrigin, was: o.KeyOrigin}
			for _, fp := range now {
				if !slices.Contains(was, fp) {
					d.added = append(d.added, fp)
				}
			}
			for _, fp := range was {
				if !slices.Contains(now, fp) {
					d.removed = append(d.removed, fp)
				}
			}
			if len(d.added)+len(d.removed) > 0 {
				changed[t.URL] = append(changed[t.URL], d)
				note(t.URL)
			}
			break
		}
		// A vendor may have more than one entry for an address (one per
		// key file): a key any of them knows is the vendor's.
		if vs := vendors.Match(t.URL); len(vs) > 0 {
			var unknown []string
			known := false
			for _, fp := range now {
				if slices.ContainsFunc(vs, func(v *vendorkeys.Vendor) bool { return v.Known(fp) }) {
					known = true
				} else {
					unknown = append(unknown, fp)
				}
			}
			// A source that names no key accepts the whole global keyring,
			// the distribution's own keys included; that is how the source
			// is written, not a strange key for this vendor, unless the
			// vendor's key is not there at all.
			if len(unknown) > 0 && !(t.KeyOrigin == model.KeyOriginGlobal && known) {
				notVendor[t.URL] = append(notVendor[t.URL], strange{suite: t.Suite, origin: t.KeyOrigin, keys: unknown, vendor: vs[0], vendors: vs})
				note(t.URL)
			}
		}
	}
	sort.Strings(urls)
	list := func(fps []string) string {
		if len(fps) > 8 {
			return strings.Join(fps[:8], ", ") + fmt.Sprintf(" and %d more", len(fps)-8)
		}
		return strings.Join(fps, ", ")
	}
	for _, u := range urls {
		if ds := changed[u]; len(ds) > 0 {
			f := &model.Finding{
				Key: "pkg.repo_key_changed:" + u, ID: "TT-PKG-011", Source: srcPackage, Severity: model.SevNote,
				Title: fmt.Sprintf("The signing key this machine trusts for the repository %s is not the one in the snapshot", u),
				Why: "When the snapshot was taken, the machine accepted packages from this repository only when signed with the key recorded then. It accepts a different key now. " +
					"Either the vendor rotated its key (check the vendor's site for the new fingerprint), or the repository and its key were swapped together so that other packages install as if they were the vendor's. " +
					"telltale still verifies this repository only with the snapshot's key, a built-in vendor key or one you pass with --keys: a version signed by the new key alone stays unconfirmed.",
				Fix: command([]string{u}, func(q []string) string {
					return "grep -rn -- " + q[0] + " /etc/apt/sources.list /etc/apt/sources.list.d/   # find which keyring the source names, then compare its fingerprint with the vendor's site: gpg --show-keys --with-fingerprint KEYRING. If the vendor rotated the key, take a new snapshot or scan with --keys DIR"
				}),
				Refs: []string{"T1195.002", "T1553"},
			}
			for _, d := range ds {
				if len(d.added) > 0 {
					f.Evidence = append(f.Evidence, model.Evidence{Path: u, Before: list(d.removed), After: list(d.added),
						Detail: fmt.Sprintf("suite %s: trusted now and not in the snapshot (%s); the snapshot had %s", d.suite, d.origin, snapshotKeys(d.removed, d.was))})
				} else {
					f.Evidence = append(f.Evidence, model.Evidence{Path: u, Before: list(d.removed),
						Detail: fmt.Sprintf("suite %s: in the snapshot (%s) and no longer trusted by the machine (%s)", d.suite, d.was, d.origin)})
				}
			}
			j.add(f)
		}
		if ss := notVendor[u]; len(ss) > 0 {
			v := ss[0].vendor
			f := &model.Finding{
				Key: "pkg.repo_key_not_vendor:" + u, ID: "TT-PKG-012", Source: srcPackage, Severity: model.SevNote,
				Title: fmt.Sprintf("This machine trusts a key for %s that is not one of %s's published keys", u, v.Name),
				Why: "The address is a " + v.Name + " repository, and telltale knows the fingerprints of the keys " + v.Name + " signs it with. " +
					"The machine accepts packages from it signed with another key. A mirror or a caching proxy that re-signs the repository does that, and so does someone who swapped the key to install their own packages under the vendor's name. " +
					"It may also be a key the vendor introduced after this telltale was built. Packages signed only with that key are not confirmed.",
				Fix: command([]string{u}, func(q []string) string {
					var fps []string
					for _, k := range ss[0].vendors {
						fps = append(fps, k.Fingerprints...)
					}
					return "grep -rn -- " + q[0] + " /etc/apt/sources.list /etc/apt/sources.list.d/   # find which keyring the source names; compare with the vendor's published fingerprints (" + strings.Join(fps, ", ") + ") and remove a key you did not add"
				}),
				Refs: []string{"T1195.002", "T1553"},
			}
			for _, s := range ss {
				f.Evidence = append(f.Evidence, model.Evidence{Path: u, After: list(s.keys),
					Detail: fmt.Sprintf("suite %s: trusted by the machine (%s), not among the %s keys built into telltale", s.suite, s.origin, s.vendor.Name)})
			}
			j.add(f)
		}
	}
}

func snapshotKeys(removed []string, origin string) string {
	if len(removed) == 0 {
		return "the same keys and fewer (" + origin + ")"
	}
	return strings.Join(removed, ", ") + " (" + origin + ")"
}
