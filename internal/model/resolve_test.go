package model

import "testing"

func inv(entries ...FileEntry) map[string]*FileEntry { return Inventory(entries) }

func dirs(paths ...string) []FileEntry {
	var out []FileEntry
	for _, p := range paths {
		out = append(out, FileEntry{Path: p, Type: "dir"})
	}
	return out
}

func lnk(p, target string) FileEntry { return FileEntry{Path: p, Type: "symlink", Target: target} }
func reg(p string) FileEntry         { return FileEntry{Path: p, Type: "file"} }

func TestResolveInInventory(t *testing.T) {
	const multi = "/usr/lib/x86_64-linux-gnu"
	merged := append(dirs("/usr", "/usr/lib", multi, "/etc", "/opt", "/opt/q", "/opt/q/a", "/opt/q/a/b"),
		lnk("/lib", "usr/lib"), reg(multi+"/libssl.so.3"), reg("/opt/q/a/libssl.so.3"),
		lnk(multi+"/libz.so.1", "libz.so.1.2.13"), reg(multi+"/libz.so.1.2.13"))
	for _, tc := range []struct {
		name  string
		files []FileEntry
		path  string
		want  string // "" means not resolvable
	}{
		{"plain file", merged, multi + "/libssl.so.3", multi + "/libssl.so.3"},
		{"package link to its library", merged, multi + "/libz.so.1", multi + "/libz.so.1.2.13"},
		{"merged /usr: /lib is a real link", merged, "/lib/x86_64-linux-gnu/libz.so.1", multi + "/libz.so.1.2.13"},
		{"dots and doubled slashes", merged, "/usr//lib/./x86_64-linux-gnu/libssl.so.3", multi + "/libssl.so.3"},
		{"dot-dot in a real directory", merged, multi + "/../x86_64-linux-gnu/libssl.so.3", multi + "/libssl.so.3"},
		{"dot-dot above the root stays at the root", merged, "/../../usr/lib/x86_64-linux-gnu/libssl.so.3", multi + "/libssl.so.3"},
		// The reviewer's probe: lexically this is the real libssl; the kernel
		// opens /opt/q/a/libssl.so.3.
		{"dot-dot through a directory link", append(merged[:len(merged):len(merged)],
			lnk(multi+"/libq.so.1", "qdir/../libssl.so.3"), lnk(multi+"/qdir", "/opt/q/a/b")),
			multi + "/libq.so.1", "/opt/q/a/libssl.so.3"},
		{"relative target with dot-dot through a relative directory link", append(merged[:len(merged):len(merged)],
			lnk("/etc/x", "../usr/lib/x86_64-linux-gnu/up/../libssl.so.3"), lnk(multi+"/up", "../../../opt/q/a/b")),
			"/etc/x", "/opt/q/a/libssl.so.3"},
		{"the same, when the real file is not in the inventory", append(dirs("/usr", "/usr/lib", multi),
			reg(multi+"/libssl.so.3"), lnk(multi+"/libq.so.1", "qdir/../libssl.so.3"), lnk(multi+"/qdir", "/opt/q/a/b")),
			multi + "/libq.so.1", ""},
		// Non-merged: /lib is a directory of its own, so the /usr spelling
		// of a /lib path says nothing about it.
		{"non-merged machine: no /usr fallback", append(dirs("/lib", "/lib/x86_64-linux-gnu", "/usr", "/usr/lib", multi),
			reg(multi+"/ossl/libssl.so.3"), lnk("/lib/x86_64-linux-gnu/ossl", "/opt/q")),
			"/lib/x86_64-linux-gnu/ossl/libssl.so.3", ""},
		{"non-merged machine: its own file", append(dirs("/lib", "/lib/x86_64-linux-gnu"), reg("/lib/x86_64-linux-gnu/libc.so.6")),
			"/lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6"},
		{"missing component", merged, multi + "/nothing.so", ""},
		{"missing directory", merged, "/srv/x/lib.so", ""},
		{"a file in the middle of the path", merged, multi + "/libssl.so.3/x", ""},
		{"link loop", append(dirs("/usr"), lnk("/usr/a", "b"), lnk("/usr/b", "a")), "/usr/a", ""},
		{"empty link target", append(dirs("/usr"), lnk("/usr/a", "")), "/usr/a", ""},
		{"relative path", merged, "usr/lib", ""},
		{"the root", merged, "/", "/"},
	} {
		got, ok := ResolveInInventory(inv(tc.files...), tc.path, LinkHops)
		if ok != (tc.want != "") || got != tc.want {
			t.Errorf("%s: %s resolved to %q (ok %v), want %q", tc.name, tc.path, got, ok, tc.want)
		}
	}
}

func TestResolveHopLimit(t *testing.T) {
	// A chain of links a1 -> a2 -> ... -> file: 8 links resolve, 9 do not.
	chain := func(n int) map[string]*FileEntry {
		files := append(dirs("/usr"), reg("/usr/end"))
		for i := 1; i <= n; i++ {
			target := "a" + string(rune('0'+i+1))
			if i == n {
				target = "end"
			}
			files = append(files, lnk("/usr/a"+string(rune('0'+i)), target))
		}
		return inv(files...)
	}
	if got, ok := ResolveInInventory(chain(8), "/usr/a1", LinkHops); !ok || got != "/usr/end" {
		t.Errorf("8 links: %q, %v", got, ok)
	}
	if got, ok := ResolveInInventory(chain(9), "/usr/a1", LinkHops); ok {
		t.Errorf("9 links resolved to %q", got)
	}
}

func TestResolveToInventoryEdge(t *testing.T) {
	files := inv(append(dirs("/etc", "/etc/systemd", "/etc/systemd/system", "/usr"),
		lnk("/etc/resolv.conf", "../run/systemd/resolve/stub-resolv.conf"),
		lnk("/etc/systemd/system/gone.service", "/etc/systemd/system/removed.service"),
		lnk("/etc/systemd/system/sneaky.service", "/run/systemd/x/../../../var/tmp/evil.service"),
		lnk("/etc/systemd/system/qdir", "/var/tmp/q"),
		lnk("/etc/systemd/system/via.service", "qdir/../real.service"),
		lnk("/etc/systemd/system/loop.service", "loop.service"))...)
	for p, want := range map[string]string{
		"/etc/resolv.conf":                   "/run/systemd/resolve/stub-resolv.conf",
		"/etc/systemd/system/gone.service":   "/etc/systemd/system/removed.service",
		"/etc/systemd/system/sneaky.service": "", // ".." beyond what the inventory knows
		"/etc/systemd/system/via.service":    "", // would be /var/tmp/real.service: ".." past the edge
		"/etc/systemd/system/loop.service":   "",
	} {
		got, ok := ResolveToInventoryEdge(files, p, LinkHops)
		if ok != (want != "") || got != want {
			t.Errorf("%s: edge %q (ok %v), want %q", p, got, ok, want)
		}
	}
}

func TestResolveDangling(t *testing.T) {
	files := inv(append(dirs("/usr", "/usr/lib", "/usr/lib/systemd", "/usr/lib/systemd/system", "/etc"),
		reg("/usr/lib/systemd/system/here.service"),
		lnk("/etc/gone", "/usr/lib/systemd/system/removed.service"),
		lnk("/etc/here", "/usr/lib/systemd/system/here.service"),
		lnk("/etc/deep", "/usr/lib/nothing/removed.service"),
		lnk("/etc/up", "/usr/lib/nothing/.."),
		lnk("/etc/via", "/etc/gone"))...)
	for p, want := range map[string]string{
		"/etc/gone": "/usr/lib/systemd/system/removed.service",
		"/etc/via":  "/usr/lib/systemd/system/removed.service",
		"/etc/here": "", // resolves
		"/etc/deep": "", // a directory on the way is missing
		"/etc/up":   "",
	} {
		got, ok := ResolveDangling(files, p, LinkHops)
		if ok != (want != "") || got != want {
			t.Errorf("%s: dangling at %q (ok %v), want %q", p, got, ok, want)
		}
	}
}

func TestPhysicalOwners(t *testing.T) {
	pk := Packages{Installed: []Package{
		{Name: "chrome", Files: []string{"/opt/google/chrome/cron/google-chrome", "/opt/google"}},
		{Name: "coreutils", Files: []string{"/usr/bin/ls"}},
		{Name: "other", Files: []string{"/data/opt/google/taken"}},
		{Name: "chrome2", Files: []string{"/opt/google/taken"}},
	}}
	files := inv(append(dirs("/data", "/data/opt", "/data/opt/google", "/data/opt/google/chrome", "/data/opt/google/chrome/cron", "/usr", "/usr/bin"),
		lnk("/opt", "/data/opt"), reg("/data/opt/google/chrome/cron/google-chrome"), reg("/usr/bin/ls"))...)
	owners, literal := pk.PhysicalOwners(files)
	const phys, lit = "/data/opt/google/chrome/cron/google-chrome", "/opt/google/chrome/cron/google-chrome"
	if owners[phys] != "chrome" || owners[lit] != "chrome" || literal[phys] != lit {
		t.Errorf("owners[phys]=%q owners[lit]=%q literal[phys]=%q", owners[phys], owners[lit], literal[phys])
	}
	if owners["/data/opt/google"] != "chrome" {
		t.Errorf("the directory itself: %q", owners["/data/opt/google"])
	}
	if owners["/data/opt/google/taken"] != "other" || literal["/data/opt/google/taken"] != "" {
		t.Errorf("a path dpkg lists for another package keeps that owner: %q", owners["/data/opt/google/taken"])
	}
	if _, ok := literal["/usr/bin/ls"]; ok || owners["/usr/bin/ls"] != "coreutils" {
		t.Errorf("a path that is where dpkg says needs no second entry")
	}
	// Without the inventory nothing is added.
	if o, l := pk.PhysicalOwners(nil); len(l) != 0 || o[phys] != "" {
		t.Errorf("no inventory: %v", l)
	}
}
