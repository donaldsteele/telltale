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
	c := &control{conffiles: map[string]bool{}, setModes: map[string][]uint32{}, addBits: map[string]uint32{}}
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
			c.scriptChmods(string(b))
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
)

// shellExpansion holds the characters through which a shell word can stand
// for something other than itself.
const shellExpansion = "$`*?[]{}()~\\\"'<>"

// scriptChmods records the literal "chmod MODE PATH..." commands of a
// maintainer script: an octal or u+s/g+s mode and absolute paths, each
// optionally in plain quotes. A command with any variable, substitution,
// glob, brace or escape among its arguments counts for none of them;
// recursive changes are ignored.
func (c *control) scriptChmods(script string) {
	for _, line := range strings.Split(script, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		for _, cmd := range strings.FieldsFunc(line, func(r rune) bool { return r == ';' || r == '&' || r == '|' }) {
			f := strings.Fields(cmd)
			i := slices.IndexFunc(f, func(s string) bool { return s == "chmod" || strings.HasSuffix(s, "/chmod") })
			if i < 0 {
				continue
			}
			args := f[i+1:]
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
			paths := make([]string, 0, len(args)-1)
			for _, p := range args[1:] {
				if len(p) >= 2 && (p[0] == '"' || p[0] == '\'') && p[len(p)-1] == p[0] {
					p = p[1 : len(p)-1]
				}
				if !validTablePath(p) || strings.ContainsAny(p, shellExpansion) {
					paths = nil
					break
				}
				paths = append(paths, p)
			}
			for _, p := range paths {
				if isAdd {
					c.addBits[p] |= add
				} else if !slices.Contains(c.setModes[p], set) {
					c.setModes[p] = append(c.setModes[p], set)
				}
			}
		}
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
