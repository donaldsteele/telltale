package judge

import (
	"slices"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/checklist"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify"
)

const bootLine = "BOOT_IMAGE=/boot/vmlinuz-6.1.0-25-amd64 root=UUID=1234 ro quiet"

// A changed kernel command line is a backdoor sign, with the line before and
// after: init= runs anything as the first process, module.sig_enforce=0
// lets unsigned modules in.
func TestJudgeKernelCommandLineChanged(t *testing.T) {
	old := clean()
	old.Runtime.Cmdline = bootLine
	if r := run(clone(old), snapOf(old), nil); find(r, "snap.cmdline") != nil {
		t.Fatal("unchanged command line reported")
	}
	for _, added := range []string{"init=/dev/shm/.i", "module.sig_enforce=0"} {
		cur := clone(old)
		cur.Runtime.Cmdline = bootLine + " " + added
		r, rb := rebaseRun(cur, snapOf(old), nil)
		f := must(t, r, "snap.cmdline", model.SevBackdoor)
		if len(f.Evidence) == 0 || f.Evidence[0].Before != bootLine || f.Evidence[0].After != cur.Runtime.Cmdline {
			t.Errorf("evidence %+v", f.Evidence)
		}
		// Accepting it rolls the command line forward and nothing else.
		s, ok := rb.Accept["snap.cmdline"]
		if !ok || !s.Cmdline {
			t.Fatalf("accept scope %+v ok=%v", s, ok)
		}
		rolled := RollForward(snapOf(old), cur, checklist.Evaluate(cur, ctx), s)
		if rolled.Collection.Runtime.Cmdline != cur.Runtime.Cmdline {
			t.Errorf("rolled command line %q", rolled.Collection.Runtime.Cmdline)
		}
		if r := run(cur, rolled, nil); find(r, "snap.cmdline") != nil {
			t.Error("still reported after it was accepted")
		}
		if rb.Routine.Cmdline {
			t.Error("a changed command line rolls forward by itself")
		}
	}
	// A snapshot or a collection without one (not collected) says nothing.
	cur := clone(old)
	cur.Runtime.Cmdline = ""
	if r := run(cur, snapOf(old), nil); find(r, "snap.cmdline") != nil {
		t.Error("a command line that was not collected is reported as changed")
	}
}

// Only the kernel image named in BOOT_IMAGE= changed, and a kernel package
// the signed archive confirms came with it: a note.
func TestJudgeKernelCommandLineAfterKernelUpgrade(t *testing.T) {
	old, cur := kernelUpdate()
	old.Runtime.Cmdline = bootLine
	cur.Runtime.Cmdline = strings.Replace(bootLine, "6.1.0-25", "6.1.0-27", 1)
	var vs []pkgverify.FileVerdict
	for _, p := range kernelPaths {
		for _, e := range cur.Files {
			if e.Path == p {
				vs = append(vs, pkgverify.FileVerdict{Path: p, Package: "linux-image-6.1.0-27-amd64", Version: "6.1.115-1", Expected: e.SHA256, Actual: e.SHA256, Source: "archive"})
			}
		}
	}
	r := run(cur, snapOf(old), archive(vs...))
	must(t, r, "snap.cmdline", model.SevNote)

	// The same with no confirmed kernel change behind it.
	must(t, run(cur, snapOf(old), nil), "snap.cmdline", model.SevBackdoor)
	// And with anything else changed besides the image.
	cur.Runtime.Cmdline += " init=/bin/sh"
	must(t, run(cur, snapOf(old), archive(vs...)), "snap.cmdline", model.SevBackdoor)
}

// The firewall is still active, but lets more in than at the snapshot.
func TestJudgeFirewallSummaryChanged(t *testing.T) {
	old := clean()
	old.Firewall = model.Firewall{Backend: "nftables", InputPolicy: "drop", Tables: 2, Rules: 12, InputRules: 5, UFWEnabled: old.Firewall.UFWEnabled}
	if r := run(clone(old), snapOf(old), nil); find(r, "snap.firewall") != nil {
		t.Fatal("unchanged firewall reported")
	}
	for _, tc := range []struct {
		name string
		set  func(f *model.Firewall)
		sev  model.Severity
	}{
		{"input policy opened", func(f *model.Firewall) { f.InputPolicy = "accept" }, model.SevWeak},
		{"input rules removed", func(f *model.Firewall) { f.InputRules, f.Rules = 2, 9 }, model.SevWeak},
		{"rules removed elsewhere", func(f *model.Firewall) { f.Rules = 10 }, model.SevWeak},
		{"rules added", func(f *model.Firewall) { f.InputRules, f.Rules = 6, 13 }, model.SevNote},
		{"policy tightened", func(f *model.Firewall) { f.InputPolicy = "reject" }, model.SevNote},
	} {
		cur := clone(old)
		tc.set(&cur.Firewall)
		r, rb := rebaseRun(cur, snapOf(old), nil)
		f := must(t, r, "snap.firewall", tc.sev)
		if len(f.Evidence) == 0 || f.Evidence[0].Before == f.Evidence[0].After || !strings.Contains(f.Evidence[0].Before, "12 rules") {
			t.Errorf("%s: evidence %+v", tc.name, f.Evidence)
		}
		s, ok := rb.Accept["snap.firewall"]
		if !ok || !s.Firewall {
			t.Fatalf("%s: accept scope %+v ok=%v", tc.name, s, ok)
		}
		rolled := RollForward(snapOf(old), cur, checklist.Evaluate(cur, ctx), s)
		if r := run(cur, rolled, nil); find(r, "snap.firewall") != nil {
			t.Errorf("%s: still reported after it was accepted", tc.name)
		}
	}
}

// Places that run code, or decide what is trusted, and were only notes.
func TestJudgeMorePersistenceLocations(t *testing.T) {
	for _, p := range []string{
		"/etc/udev/rules.d/99-x.rules", "/etc/apt/apt.conf.d/99x", "/etc/apt/sources.list.d/x.list", "/etc/apt/trusted.gpg.d/x.gpg",
		"/etc/logrotate.d/x", "/etc/NetworkManager/dispatcher.d/99-x", "/etc/tmpfiles.d/x.conf", "/etc/xdg/autostart/x.desktop",
		"/etc/polkit-1/rules.d/49-x.rules", "/etc/sudo.conf", "/etc/nftables.conf", "/etc/ssl/certs/evil.pem",
	} {
		old := clean()
		cur := clone(old)
		cur.Files = append(cur.Files, file(p, "planted", 0o644))
		f := must(t, run(cur, snapOf(old), nil), "snap.file_added:"+p, model.SevBackdoor)
		if strings.Contains(f.Why, "probably routine") {
			t.Errorf("%s: %q", p, f.Why)
		}
		// Changed, not only added.
		old.Files = append(old.Files, file(p, "as it was", 0o644))
		must(t, run(cur, snapOf(old), nil), "snap.file_modified:"+p, model.SevBackdoor)
	}
	// A neighbour that is none of them stays a note.
	old := clean()
	cur := clone(old)
	cur.Files = append(cur.Files, file("/etc/apt/listchanges.conf", "x", 0o644))
	must(t, run(cur, snapOf(old), nil), "snap.file_added:/etc/apt/listchanges.conf", model.SevNote)
}

// A CA certificate added by a ca-certificates upgrade the signed archive
// confirms is explained; one added next to it from somewhere else is not.
func TestJudgeCACertificates(t *testing.T) {
	const (
		crt    = "/usr/share/ca-certificates/mozilla/New_Root.crt"
		pem    = "/etc/ssl/certs/New_Root.pem"
		hash   = "/etc/ssl/certs/0a1b2c3d.0"
		bundle = "/etc/ssl/certs/ca-certificates.crt"
	)
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed, pkg("ca-certificates", "20230311", "/usr/share/ca-certificates/mozilla/Old_Root.crt"))
	old.Files = append(old.Files, file("/usr/share/ca-certificates/mozilla/Old_Root.crt", "old root", 0o644), file(bundle, "old root", 0o644))

	cur := clone(old)
	for i := range cur.Packages.Installed {
		if pk := &cur.Packages.Installed[i]; pk.Name == "ca-certificates" {
			pk.Version, pk.Files = "20240203", append(pk.Files, crt)
		}
	}
	nf := file(crt, "new root", 0o644)
	cur.Files = append(cur.Files, nf, symlinkAt(pem, crt, changed), symlinkAt(hash, "New_Root.pem", changed))
	setFile(cur, file(bundle, "old root\nnew root", 0o644))
	v := pkgverify.FileVerdict{Path: crt, Package: "ca-certificates", Version: "20240203", Expected: nf.SHA256, Actual: nf.SHA256, Source: "archive"}

	r := run(cur, snapOf(old), archive(v))
	for _, p := range []string{pem, hash, bundle} {
		for _, f := range r.Findings {
			if hasEvidencePath(&f, p) || strings.HasSuffix(f.Key, ":"+p) {
				t.Errorf("%s ranked as %s (%s) after a confirmed ca-certificates upgrade", p, f.Key, f.Severity)
			}
		}
	}
	if g := explained(r, "explained:ca-certificates"); g == nil || !hasEvidencePath(g, pem) || !hasEvidencePath(g, bundle) {
		t.Errorf("the upgrade does not show its certificates: %+v", g)
	}

	// A certificate from outside the package, linked in during the same
	// upgrade: a backdoor sign.
	evil := clone(cur)
	evil.Files = append(evil.Files, file("/usr/local/share/ca-certificates/evil.crt", "evil root", 0o644),
		symlinkAt("/etc/ssl/certs/evil.pem", "/usr/local/share/ca-certificates/evil.crt", changed))
	must(t, run(evil, snapOf(old), archive(v)), "snap.file_added:/etc/ssl/certs/evil.pem", model.SevBackdoor)

	// Without a confirmed upgrade nothing in the certificate store is
	// explained: not the links, not the rebuilt bundle.
	r = run(cur, snapOf(old), nil)
	must(t, r, "snap.file_added:"+pem, model.SevBackdoor)
	must(t, r, "snap.file_modified:"+bundle, model.SevBackdoor)
	same := clone(cur)
	setVersion(same, "ca-certificates", "20230311")
	if ks := keys(run(same, snapOf(old), archive())); !slices.Contains(ks, "snap.file_modified:"+bundle) {
		t.Errorf("bundle changed with no upgrade: %v", ks)
	}
}

// apt autoremove of an old kernel, on its own: the boot menu is rewritten
// and the .old links move. That is a note the owner accepts, never a
// critical alert, and never something that rolls forward by itself.
func TestJudgeKernelAutoremoveBootFilesAreNotes(t *testing.T) {
	old := clean()
	old.Runtime.Cmdline = strings.Replace(bootLine, "6.1.0-25", "6.1.0-27", 1)
	old.Packages.Installed = append(old.Packages.Installed,
		pkg("linux-image-6.1.0-25-amd64", "6.1.106-3", "/boot/vmlinuz-6.1.0-25-amd64"),
		pkg("linux-image-6.1.0-27-amd64", "6.1.115-1", "/boot/vmlinuz-6.1.0-27-amd64"))
	old.Files = append(old.Files,
		file("/boot/vmlinuz-6.1.0-25-amd64", "k25", 0o644), file("/boot/initrd.img-6.1.0-25-amd64", "initrd 25", 0o644),
		file("/boot/vmlinuz-6.1.0-27-amd64", "k27", 0o644), file("/boot/initrd.img-6.1.0-27-amd64", "initrd 27", 0o644),
		file("/boot/grub/grub.cfg", "menu 25 27", 0o444),
		symlinkAt("/boot/vmlinuz.old", "vmlinuz-6.1.0-25-amd64", taken), symlinkAt("/boot/initrd.img.old", "initrd.img-6.1.0-25-amd64", taken))

	cur := clone(old)
	removePkg(cur, "linux-image-6.1.0-25-amd64")
	cur.Files = slices.DeleteFunc(cur.Files, func(e model.FileEntry) bool { return strings.Contains(e.Path, "6.1.0-25") })
	setFile(cur, file("/boot/grub/grub.cfg", "menu 27", 0o444))
	setFile(cur, symlinkAt("/boot/vmlinuz.old", "vmlinuz-6.1.0-27-amd64", changed))
	setFile(cur, symlinkAt("/boot/initrd.img.old", "initrd.img-6.1.0-27-amd64", changed))

	r, rb := rebaseRun(cur, snapOf(old), archive())
	boot := []string{"/boot/grub/grub.cfg", "/boot/vmlinuz.old", "/boot/initrd.img.old"}
	for _, p := range boot {
		f := must(t, r, "snap.file_modified:"+p, model.SevNote)
		if !strings.Contains(f.Why, "linux-image-6.1.0-25-amd64") || !strings.Contains(f.Why, "removed") {
			t.Errorf("%s: why %q", p, f.Why)
		}
		if slices.Contains(rb.Routine.Paths, p) {
			t.Errorf("%s rolls forward by itself", p)
		}
		if s, ok := rb.Accept["snap.file_modified:"+p]; !ok || !slices.Contains(s.Paths, p) {
			t.Errorf("%s cannot be accepted: %+v", p, s)
		}
	}
	if sev := severest(r); sev > model.SevWeak {
		t.Errorf("a kernel autoremove raised %s: %v", sev, keys(r))
	}
	if g := explained(r, "explained:linux-image-6.1.0-25-amd64"); g != nil {
		for _, p := range boot {
			if hasEvidencePath(g, p) {
				t.Errorf("%s is folded into the removal, which rolls forward by itself", p)
			}
		}
	}

	// A malicious boot change made under cover of the removal still shows:
	// the command line the machine boots with is compared on its own.
	evil := clone(cur)
	evil.Runtime.Cmdline += " init=/dev/shm/.i"
	must(t, run(evil, snapOf(old), archive()), "snap.cmdline", model.SevBackdoor)

	// No kernel was removed: the same boot files changing is a backdoor sign.
	same := clone(cur)
	same.Packages.Installed = clone(old).Packages.Installed
	rr := run(same, snapOf(old), archive())
	for _, p := range boot {
		must(t, rr, "snap.file_modified:"+p, model.SevBackdoor)
	}

	// Another kernel's initramfs is not what a removal rewrites.
	setFile(cur, file("/boot/initrd.img-6.1.0-27-amd64", "initrd 27 + implant", 0o644))
	must(t, run(cur, snapOf(old), archive()), "snap.file_modified:/boot/initrd.img-6.1.0-27-amd64", model.SevBackdoor)
}
