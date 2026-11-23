package judge

import (
	"strings"

	"github.com/donaldsteele/telltale/internal/diff"
	"github.com/donaldsteele/telltale/internal/heuristics"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify"
)

// VerifyScope sets what package verification of c looks at, and which keys
// vouch for third-party repositories, given the machine's snapshot (nil when
// there is none). Carry mode's scan and the server both call it, so they
// verify the same things:
//   - ExtraPaths gains the targets of startup links into package-owned files
//     outside the system directories. Such links are only notes, so the
//     target is verified to catch a tampered one. A target is named where it
//     really is, which is the path package verification reports it under.
//   - With a snapshot, OnlyPaths is the package-owned paths that changed
//     since it (under both merged-/usr spellings, and where a path really is
//     when a directory on the way is a link) plus every changed or added
//     dpkg maintainer script.
//   - RepoTrust is the snapshot's record of the keys third-party
//     repositories were signed with when the machine was clean, and nothing
//     else. The collection just taken holds the same kind of record
//     (c.Packages.RepoTrust); that is the examined machine's word and is
//     never used.
func VerifyScope(opt *pkgverify.Options, snap *model.Snapshot, c *model.Collection) {
	opt.ExtraPaths = append(opt.ExtraPaths, heuristics.PackageLinkTargets(c, c.Packages.Owners())...)
	opt.OnlyPaths, opt.RepoTrust = nil, nil
	if snap == nil {
		return
	}
	opt.OnlyPaths = changedOwnedPaths(snap, c)
	if snap.Collection != nil {
		opt.RepoTrust = snap.Collection.Packages.RepoTrust
	}
}

const dpkgInfo = "/var/lib/dpkg/info/"

// changedOwnedPaths is what package verification must look at when a
// snapshot says what the machine looked like before: the package-owned paths
// that changed, plus every changed or added dpkg maintainer script.
func changedOwnedPaths(snap *model.Snapshot, cur *model.Collection) map[string]bool {
	return changedOwnedIn(diff.Compare(snap, cur, nil), snap, cur)
}

// changedOwnedIn is changedOwnedPaths for changes already compared.
func changedOwnedIn(chs []diff.Change, snap *model.Snapshot, cur *model.Collection) map[string]bool {
	owned := map[string]bool{}
	for _, col := range []*model.Collection{cur, snap.Collection} {
		if col == nil {
			continue
		}
		// Owners applies the merged-/usr aliases (/bin/ls is /usr/bin/ls).
		// A package path behind a directory that is a link is recorded,
		// and so changes, where it really is: those paths are verified too.
		// Asking for more to be verified can only find more.
		owners, _ := col.Packages.PhysicalOwners(model.Inventory(col.Files))
		for p := range owners {
			owned[p] = true
		}
	}
	only := map[string]bool{}
	for _, ch := range chs {
		switch ch.Kind {
		case diff.FileModified, diff.FileAdded, diff.FileRemoved, diff.PersistChanged:
			if owned[ch.Subject] {
				only[ch.Subject] = true
			}
		}
		if ch.Kind == diff.FileModified || ch.Kind == diff.FileAdded {
			if isMaintainerScript(ch.Subject) {
				only[ch.Subject] = true
			}
		}
	}
	return only
}

func isMaintainerScript(p string) bool {
	if !strings.HasPrefix(p, dpkgInfo) || strings.Contains(p[len(dpkgInfo):], "/") {
		return false
	}
	for _, ext := range pkgverify.MaintainerScripts {
		if strings.HasSuffix(p, "."+ext) {
			return true
		}
	}
	return false
}
