package pkgverify

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

const (
	// maxConffileText is the largest conffile whose package default text is
	// kept for a diff.
	maxConffileText = 256 << 10
	// maxControlSize bounds a decompressed control.tar.
	maxControlSize = 64 << 20
	// maxConffilesList bounds the control member that lists conffiles.
	maxConffilesList = 1 << 20
	// maxArMembers bounds the members of a .deb; dpkg writes three.
	maxArMembers = 16
	// zstdWindow bounds the zstd decoder's window and memory.
	zstdWindow = 512 << 20
)

var (
	// maxTarEntries bounds the entries of a data.tar; a variable so tests
	// can lower it.
	maxTarEntries = 200_000
	// maxUnpackedSize bounds a decompressed data.tar. Files are hashed as
	// they stream past, so this bounds time, not memory.
	maxUnpackedSize int64 = 32 << 30
)

// ErrMalformedDeb means a .deb could not be read as one.
var ErrMalformedDeb = errors.New("malformed .deb")

// DebFile is one regular file a .deb installs.
type DebFile struct {
	SHA256 string `json:"sha256"`
	// Mode holds the permission bits, including setuid, setgid and sticky.
	Mode uint32 `json:"mode"`
	// Text is the content of a conffile of at most 256 KiB, else nil.
	Text []byte `json:"text,omitempty"`
	// Conffile is true when the package's own control data lists the file
	// as a conffile.
	Conffile bool `json:"conffile,omitempty"`
	// ScriptModes are modes the package's own postinst sets on the file
	// with a literal chmod, as Debian packages do for setuid and setgid
	// helpers when no dpkg-statoverride exists.
	ScriptModes []uint32 `json:"script_modes,omitempty"`
	// ScriptOverrides are the dpkg-statoverride entries the package's own
	// postinst adds for the file with a literal command.
	ScriptOverrides []ScriptOverride `json:"script_overrides,omitempty"`
}

// ScriptOverride is one literal "dpkg-statoverride --add OWNER GROUP MODE
// PATH" in a package's maintainer script.
type ScriptOverride struct {
	Owner string `json:"owner"`
	Group string `json:"group"`
	Mode  uint32 `json:"mode"`
}

// DebFiles reads a .deb (an ar archive holding control.tar and data.tar,
// compressed with xz, zstd, gzip or bzip2, or not at all) and returns every
// regular file in data.tar by absolute path ("/usr/bin/su"), with its SHA-256
// and mode. Hard links get their target's hash; directories, symlinks and
// devices are left out. Which files are conffiles comes from the package's
// own control.tar. Paths that are absolute, climb out with "..", or occur
// twice make the whole package malformed.
//
// Files are hashed as they stream past; only conffile text is held in
// memory. The caller is expected to have checked the .deb's hash against a
// signed index first: the decompressors allocate what the stream declares,
// within the limits set here.
func DebFiles(r io.ReaderAt, size int64) (map[string]DebFile, error) {
	members, err := arMembers(r, size)
	if err != nil {
		return nil, err
	}
	if len(members) == 0 || members[0].name != "debian-binary" {
		return nil, fmt.Errorf("%w: first member is not debian-binary", ErrMalformedDeb)
	}
	var version [8]byte
	n, _ := r.ReadAt(version[:min(int64(len(version)), members[0].size)], members[0].off)
	if !bytes.HasPrefix(version[:n], []byte("2.")) {
		return nil, fmt.Errorf("%w: unsupported format version %q", ErrMalformedDeb, version[:n])
	}
	var control, data *arMember
	for i := range members[1:] {
		m := &members[i+1]
		switch {
		case control == nil && strings.HasPrefix(m.name, "control.tar"):
			control = m
		case data == nil && strings.HasPrefix(m.name, "data.tar"):
			data = m
		}
	}
	if control == nil || data == nil {
		return nil, fmt.Errorf("%w: control.tar or data.tar missing", ErrMalformedDeb)
	}
	ctl, err := readControl(r, control)
	if err != nil {
		return nil, err
	}
	return readData(r, data, ctl)
}

type arMember struct {
	name      string
	off, size int64
}

// arMembers lists the members of a common-format ar archive.
func arMembers(r io.ReaderAt, size int64) ([]arMember, error) {
	var magic [8]byte
	if size < int64(len(magic)) {
		return nil, fmt.Errorf("%w: too short", ErrMalformedDeb)
	}
	if _, err := r.ReadAt(magic[:], 0); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedDeb, err)
	}
	if string(magic[:]) != "!<arch>\n" {
		return nil, fmt.Errorf("%w: not an ar archive", ErrMalformedDeb)
	}
	var out []arMember
	for off := int64(len(magic)); off < size; {
		if len(out) == maxArMembers {
			return nil, fmt.Errorf("%w: more than %d members", ErrMalformedDeb, maxArMembers)
		}
		var h [60]byte
		if size-off < int64(len(h)) {
			return nil, fmt.Errorf("%w: truncated member header", ErrMalformedDeb)
		}
		if _, err := r.ReadAt(h[:], off); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformedDeb, err)
		}
		if h[58] != '`' || h[59] != '\n' {
			return nil, fmt.Errorf("%w: bad member header", ErrMalformedDeb)
		}
		name := strings.TrimSuffix(strings.TrimRight(string(h[:16]), " "), "/")
		msize, err := strconv.ParseInt(strings.TrimSpace(string(h[48:58])), 10, 64)
		if err != nil || msize < 0 {
			return nil, fmt.Errorf("%w: bad member size", ErrMalformedDeb)
		}
		start := off + int64(len(h))
		if msize > size-start {
			return nil, fmt.Errorf("%w: member %q is truncated", ErrMalformedDeb, name)
		}
		out = append(out, arMember{name: name, off: start, size: msize})
		off = start + msize + msize%2
	}
	return out, nil
}

// decompressor opens member m, choosing the decompressor from its name.
func decompressor(r io.ReaderAt, m *arMember, base string) (io.ReadCloser, error) {
	sr := bufio.NewReaderSize(io.NewSectionReader(r, m.off, m.size), 64<<10)
	switch strings.TrimPrefix(m.name, base) {
	case "":
		return io.NopCloser(sr), nil
	case ".xz":
		xr, err := xz.NewReader(sr)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrMalformedDeb, m.name, err)
		}
		return io.NopCloser(xr), nil
	case ".zst":
		zr, err := zstd.NewReader(sr, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true),
			zstd.WithDecoderMaxWindow(zstdWindow), zstd.WithDecoderMaxMemory(zstdWindow))
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrMalformedDeb, m.name, err)
		}
		return zr.IOReadCloser(), nil
	case ".gz":
		gr, err := gzip.NewReader(sr)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrMalformedDeb, m.name, err)
		}
		return gr, nil
	case ".bz2":
		return io.NopCloser(bzip2.NewReader(sr)), nil
	}
	return nil, fmt.Errorf("%w: unsupported member %q", ErrMalformedDeb, m.name)
}

// control is what DebFiles uses from a package's control.tar.
type control struct {
	conffiles map[string]bool
	// modes set by the postinst: absolute ones, and bits added to the
	// packaged mode ("chmod u+s").
	setModes map[string][]uint32
	addBits  map[string]uint32
	// statoverrides the postinst adds.
	overrides map[string][]ScriptOverride
}

// overridesFor returns the statoverrides the postinst adds for p or its
// merged-/usr alias.
func (c *control) overridesFor(p string) []ScriptOverride {
	var out []ScriptOverride
	for _, q := range []string{p, usrAlias(p)} {
		for _, o := range c.overrides[q] {
			if q != "" && !slices.Contains(out, o) {
				out = append(out, o)
			}
		}
	}
	return out
}

// modesFor returns the modes the postinst gives p (or its merged-/usr
// alias), whose packaged mode is mode.
func (c *control) modesFor(p string, mode uint32) []uint32 {
	var out []uint32
	for _, q := range []string{p, usrAlias(p)} {
		if q == "" {
			continue
		}
		for _, m := range c.setModes[q] {
			if !slices.Contains(out, m) {
				out = append(out, m)
			}
		}
		if b, ok := c.addBits[q]; ok && !slices.Contains(out, mode|b) {
			out = append(out, mode|b)
		}
	}
	return out
}

// readControl reads the conffiles list and the postinst of control.tar.
func readControl(r io.ReaderAt, m *arMember) (*control, error) {
	dec, err := decompressor(r, m, "control.tar")
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	lr := &io.LimitedReader{R: dec, N: maxControlSize + 1}
	tr := tar.NewReader(lr)
	c := &control{conffiles: map[string]bool{}, setModes: map[string][]uint32{}, addBits: map[string]uint32{}, overrides: map[string][]ScriptOverride{}}
	for n := 0; ; n++ {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if lr.N <= 0 {
			return nil, fmt.Errorf("%w: control.tar larger than %d bytes", ErrMalformedDeb, maxControlSize)
		}
		if err != nil {
			return nil, fmt.Errorf("%w: control.tar: %v", ErrMalformedDeb, err)
		}
		if n == 1000 {
			return nil, fmt.Errorf("%w: control.tar has too many entries", ErrMalformedDeb)
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if hdr.Typeflag != tar.TypeReg || (name != "conffiles" && name != "postinst") {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxConffilesList+1))
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrMalformedDeb, name, err)
		}
		if len(b) > maxConffilesList {
			return nil, fmt.Errorf("%w: %s larger than %d bytes", ErrMalformedDeb, name, maxConffilesList)
		}
		if name == "postinst" {
			c.scriptCommands(string(b))
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			// Newer dpkg prefixes flags: "remove-on-upgrade /etc/foo".
			f := strings.Fields(line)
			if len(f) == 0 {
				continue
			}
			if p := f[len(f)-1]; strings.HasPrefix(p, "/") {
				c.conffiles[p] = true
			}
		}
	}
	return c, nil
}

var (
	octalMode  = regexp.MustCompile(`^0?[0-7]{3,4}$`)
	addSetBits = map[string]uint32{"u+s": 0o4000, "g+s": 0o2000, "ug+s": 0o6000, "+s": 0o6000}
	// shellSeparator splits a line into simple commands.
	shellSeparator = regexp.MustCompile(`;|&&|\|\||\|`)
	// redirection is a word that redirects output or input ("2>/dev/null",
	// ">&2", or a bare "2>" whose target is the next word).
	redirection  = regexp.MustCompile(`^[0-9]*(?:>>?|<)(?:&[0-9-]|[^&<>].*)?$`)
	bareRedirect = regexp.MustCompile(`^[0-9]*(?:>>?|<)$`)
	safeName     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.+-]*$`)
)

// shellExpansion holds the characters through which a shell word can stand
// for something other than itself.
const shellExpansion = "$`*?[]{}()~\\\"'<>&;|"

// scriptWords splits a maintainer script into the words of its simple
// commands, without comments and redirections.
func scriptWords(script string) [][]string {
	var out [][]string
	for _, line := range strings.Split(script, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		for _, cmd := range shellSeparator.Split(line, -1) {
			var words []string
			f := strings.Fields(cmd)
			for i := 0; i < len(f); i++ {
				switch {
				case bareRedirect.MatchString(f[i]):
					i++ // and its target
				case redirection.MatchString(f[i]):
				default:
					words = append(words, f[i])
				}
			}
			if len(words) > 0 {
				out = append(out, words)
			}
		}
	}
	return out
}

var (
	// assignLine is an unindented line that only assigns a variable.
	assignLine = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=(\S*)$`)
	// assignAny finds every assignment to a variable anywhere in a line.
	assignAny = regexp.MustCompile(`(?:^|[\s;&|(!])(?:export\s+|local\s+|readonly\s+|declare\s+(?:-\S+\s+)*)?([A-Za-z_][A-Za-z0-9_]*)\+?=`)
	// setsVars finds commands that give variables values another way.
	setsVars = regexp.MustCompile(`(?:^|[\s;&|(!])(?:read|for|unset|local|export|readonly|declare|getopts|typeset)\s+((?:-\S+\s+)*[A-Za-z_][A-Za-z0-9_]*(?:\s+[A-Za-z_][A-Za-z0-9_]*)*)`)
	// varRef is a whole word that is one variable: $NAME or ${NAME}.
	varRef = regexp.MustCompile(`^\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})$`)
)

// scriptConstants returns the script's variables that are constants: set
// exactly once in the whole script, by an unindented line that does nothing
// but assign a literal value, and never read, looped over, unset or given a
// value any other way. Debian maintainer scripts name paths and groups this
// way ("LAUNCHER=/usr/lib/dbus-1.0/dbus-daemon-launch-helper").
func scriptConstants(script string) map[string]string {
	count := map[string]int{}
	other := map[string]bool{}
	value := map[string]string{}
	for _, line := range strings.Split(script, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimRight(line, " \t\r")
		for _, m := range assignAny.FindAllStringSubmatch(line, -1) {
			count[m[1]]++
		}
		for _, m := range setsVars.FindAllStringSubmatch(line, -1) {
			for _, w := range strings.Fields(m[1]) {
				if !strings.HasPrefix(w, "-") {
					other[w] = true
				}
			}
		}
		if m := assignLine.FindStringSubmatch(line); m != nil {
			if v, ok := literal(m[2], nil); ok {
				value[m[1]] = v
			}
		}
	}
	out := map[string]string{}
	for k, v := range value {
		if count[k] == 1 && !other[k] {
			out[k] = v
		}
	}
	return out
}

// literal returns w without one pair of plain surrounding quotes, and
// whether what remains is free of shell expansion. A whole word that is one
// of the script's constants ($NAME or ${NAME}, unquoted or in double quotes)
// is replaced by its value.
func literal(w string, consts map[string]string) (string, bool) {
	single := false
	if len(w) >= 2 && (w[0] == '"' || w[0] == '\'') && w[len(w)-1] == w[0] {
		single = w[0] == '\''
		w = w[1 : len(w)-1]
	}
	if m := varRef.FindStringSubmatch(w); m != nil && !single {
		v, ok := consts[m[1]+m[2]]
		return v, ok
	}
	return w, w != "" && !strings.ContainsAny(w, shellExpansion)
}

// literalPaths returns ws as absolute paths, or nil if any of them is not
// a literal clean absolute path ("--" is skipped).
func literalPaths(ws []string, consts map[string]string) []string {
	var out []string
	for _, w := range ws {
		if w == "--" {
			continue
		}
		p, ok := literal(w, consts)
		if !ok || !validTablePath(p) {
			return nil
		}
		out = append(out, p)
	}
	return out
}

// scriptCommands records what a maintainer script does to file modes with
// literal commands: "chmod MODE PATH..." (an octal or u+s/g+s mode) and
// "dpkg-statoverride [--update] --add OWNER GROUP MODE PATH". Arguments must
// be literal or one of the script's constants; a command with any other
// variable, substitution, glob, brace or escape among its arguments counts
// for none of them; recursive changes are ignored.
func (c *control) scriptCommands(script string) {
	consts := scriptConstants(script)
	for _, f := range scriptWords(script) {
		cmd := slices.IndexFunc(f, func(s string) bool {
			return s == "chmod" || strings.HasSuffix(s, "/chmod") || s == "dpkg-statoverride" || strings.HasSuffix(s, "/dpkg-statoverride")
		})
		if cmd < 0 {
			continue
		}
		args := f[cmd+1:]
		if strings.HasSuffix(f[cmd], "dpkg-statoverride") {
			c.scriptOverride(args, consts)
			continue
		}
		for len(args) > 0 && strings.HasPrefix(args[0], "-") {
			if args[0] != "-f" && args[0] != "--" {
				args = nil // -R and friends: not a single file's mode
				break
			}
			args = args[1:]
		}
		if len(args) < 2 {
			continue
		}
		var set uint32
		add, isAdd := addSetBits[args[0]]
		if !isAdd {
			if !octalMode.MatchString(args[0]) {
				continue
			}
			m, err := strconv.ParseUint(args[0], 8, 32)
			if err != nil {
				continue
			}
			set = uint32(m)
		}
		for _, p := range literalPaths(args[1:], consts) {
			if isAdd {
				c.addBits[p] |= add
			} else if !slices.Contains(c.setModes[p], set) {
				c.setModes[p] = append(c.setModes[p], set)
			}
		}
	}
}

// scriptOverride records "dpkg-statoverride [options] --add OWNER GROUP
// MODE PATH" when every argument is literal.
func (c *control) scriptOverride(args []string, consts map[string]string) {
	var pos []string
	adding := false
	for _, a := range args {
		switch {
		case a == "--add":
			adding = true
		case a == "--update" || a == "--quiet" || strings.HasPrefix(a, "--force"):
		case strings.HasPrefix(a, "-"):
			return // --remove, --list, --admindir ... or anything unknown
		default:
			pos = append(pos, a)
		}
	}
	if !adding || len(pos) != 4 {
		return
	}
	owner, ok1 := literal(pos[0], consts)
	group, ok2 := literal(pos[1], consts)
	mode, ok3 := literal(pos[2], consts)
	paths := literalPaths(pos[3:], consts)
	if !ok1 || !ok2 || !ok3 || !safeName.MatchString(owner) || !safeName.MatchString(group) || !octalMode.MatchString(mode) || len(paths) != 1 {
		return
	}
	m, err := strconv.ParseUint(mode, 8, 32)
	if err != nil {
		return
	}
	o := ScriptOverride{Owner: owner, Group: group, Mode: uint32(m)}
	if !slices.Contains(c.overrides[paths[0]], o) {
		c.overrides[paths[0]] = append(c.overrides[paths[0]], o)
	}
}

// readData hashes every regular file in the data.tar member.
func readData(r io.ReaderAt, m *arMember, ctl *control) (map[string]DebFile, error) {
	conffiles := ctl.conffiles
	dec, err := decompressor(r, m, "data.tar")
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	lr := &io.LimitedReader{R: dec, N: maxUnpackedSize + 1}
	tr := tar.NewReader(lr)
	files := map[string]DebFile{}
	for n := 1; ; n++ {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if lr.N <= 0 {
			return nil, fmt.Errorf("%w: data.tar larger than %d bytes", ErrMalformedDeb, maxUnpackedSize)
		}
		if err != nil {
			return nil, fmt.Errorf("%w: data.tar: %v", ErrMalformedDeb, err)
		}
		if n > maxTarEntries {
			return nil, fmt.Errorf("%w: data.tar has more than %d entries", ErrMalformedDeb, maxTarEntries)
		}
		p, err := debPath(hdr.Name)
		if err != nil {
			return nil, err
		}
		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeGNUSparse:
		case tar.TypeLink:
			target, err := debPath(hdr.Linkname)
			if err != nil {
				return nil, err
			}
			f, ok := files[target]
			if !ok {
				return nil, fmt.Errorf("%w: hard link %q to %q, which is not an earlier regular file", ErrMalformedDeb, p, target)
			}
			if _, dup := files[p]; dup {
				return nil, fmt.Errorf("%w: %q occurs twice", ErrMalformedDeb, p)
			}
			f.Mode = uint32(hdr.Mode) & 0o7777
			if f.Conffile = conffiles[p]; !f.Conffile {
				f.Text = nil
			}
			f.ScriptModes = ctl.modesFor(p, f.Mode)
			f.ScriptOverrides = ctl.overridesFor(p)
			files[p] = f
			continue
		default: // directories, symlinks, devices, FIFOs
			continue
		}
		if p == "/" {
			return nil, fmt.Errorf("%w: regular file at the root", ErrMalformedDeb)
		}
		if _, dup := files[p]; dup {
			return nil, fmt.Errorf("%w: %q occurs twice", ErrMalformedDeb, p)
		}
		f := DebFile{Mode: uint32(hdr.Mode) & 0o7777, Conffile: conffiles[p]}
		f.ScriptModes = ctl.modesFor(p, f.Mode)
		f.ScriptOverrides = ctl.overridesFor(p)
		h := sha256.New()
		if f.Conffile && hdr.Size <= maxConffileText {
			b, err := io.ReadAll(io.LimitReader(tr, maxConffileText+1))
			if err != nil {
				return nil, fmt.Errorf("%w: %s: %v", ErrMalformedDeb, p, err)
			}
			h.Write(b)
			f.Text = b
		} else if _, err := io.Copy(h, tr); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrMalformedDeb, p, err)
		}
		f.SHA256 = hex.EncodeToString(h.Sum(nil))
		files[p] = f
	}
	return files, nil
}

// debPath turns a data.tar member name ("./usr/bin/su") into the absolute
// path it installs to, refusing names that are absolute or climb out.
func debPath(name string) (string, error) {
	bad := func(why string) (string, error) {
		return "", fmt.Errorf("%w: member %q: %s", ErrMalformedDeb, name, why)
	}
	if name == "" || strings.ContainsRune(name, 0) {
		return bad("unusable name")
	}
	if strings.HasPrefix(name, "/") {
		return bad("absolute path")
	}
	n := strings.TrimSuffix(strings.TrimPrefix(name, "./"), "/")
	if n == "" || n == "." {
		return "/", nil
	}
	for _, seg := range strings.Split(n, "/") {
		switch seg {
		case "..":
			return bad("climbs out with ..")
		case "", ".":
			return bad("not a clean path")
		}
	}
	return "/" + n, nil
}
