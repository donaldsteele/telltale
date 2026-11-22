package collect

import (
	"strconv"
	"strings"
)

// The account databases are read the way glibc's files backend (nss_files)
// reads them, so telltale sees the accounts the machine actually logs in
// with: a line's leading blanks are skipped, empty and '#' lines are
// ignored, short lines are accepted with the missing trailing fields empty
// where glibc accepts them, and a line glibc rejects is reported as
// malformed. Lookups by name use the first line for that name, so later
// lines for the same name are reported as duplicates. The field rules
// follow glibc's STRING_FIELD, INT_FIELD, INT_FIELD_MAYBE_NULL and
// STRING_LIST parsers.

// nssLine is one line of a database worth parsing, with its 1-based number.
type nssLine struct {
	n    int
	text string
}

func isCSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

// nssLines splits a database into the lines glibc parses. Only '\n' ends a
// line, as for glibc; a '\r' stays part of the last field.
func nssLines(b []byte) []nssLine {
	var out []nssLine
	for i, l := range strings.Split(string(b), "\n") {
		j := 0
		for j < len(l) && isCSpace(l[j]) {
			j++
		}
		if j == len(l) || l[j] == '#' {
			continue
		}
		out = append(out, nssLine{n: i + 1, text: l[j:]})
	}
	return out
}

type fieldParser struct {
	s   string
	pos int
}

func (p *fieldParser) atEnd() bool { return p.pos >= len(p.s) }

// stringField reads up to the next ':' and consumes it (STRING_FIELD).
func (p *fieldParser) stringField() string {
	start := p.pos
	for p.pos < len(p.s) && p.s[p.pos] != ':' {
		p.pos++
	}
	f := p.s[start:p.pos]
	if p.pos < len(p.s) {
		p.pos++
	}
	return f
}

// strtoul mimics C's strtoul in base 10: leading white space and a sign
// are allowed, a minus negates modulo 2^64, overflow saturates. n is the
// number of bytes used, 0 when there were no digits.
func strtoul(s string) (v uint64, n int) {
	i := 0
	for i < len(s) && isCSpace(s[i]) {
		i++
	}
	neg := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	start := i
	overflow := false
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		d := uint64(s[i] - '0')
		if v > (^uint64(0)-d)/10 {
			overflow = true
		}
		v = v*10 + d
		i++
	}
	if i == start {
		return 0, 0
	}
	if overflow {
		return ^uint64(0), i
	}
	if neg {
		v = -v
	}
	return v, i
}

// intField is INT_FIELD: a number that must be there, then ':' or the end.
func (p *fieldParser) intField() (uint64, bool) {
	v, n := strtoul(p.s[p.pos:])
	if n == 0 {
		return 0, false
	}
	p.pos += n
	if !p.atEnd() {
		if p.s[p.pos] != ':' {
			return 0, false
		}
		p.pos++
	}
	return v, true
}

// intFieldMaybeNull is INT_FIELD_MAYBE_NULL: the field may be empty (def),
// but the line may not end before it. Values are stored through an int,
// as glibc does for the shadow fields.
func (p *fieldParser) intFieldMaybeNull(def int64, last bool) (int64, bool) {
	v, present, ok := p.rawFieldMaybeNull(last)
	if !present {
		return def, ok
	}
	return int64(int32(v)), ok
}

// rawFieldMaybeNull is INT_FIELD_MAYBE_NULL without the conversion.
func (p *fieldParser) rawFieldMaybeNull(last bool) (v uint64, present, ok bool) {
	if p.atEnd() {
		return 0, false, false
	}
	v, n := strtoul(p.s[p.pos:])
	p.pos += n
	if !p.atEnd() {
		if last || p.s[p.pos] != ':' {
			return 0, false, false
		}
		p.pos++
	}
	return v, n > 0, true
}

// maxID is the first id glibc refuses: (uid_t)-1 and anything that does
// not fit in 32 bits make it drop the line.
const maxID = 1<<32 - 1

// idField reads a user or group id: required (INT_FIELD) or, for the NIS
// compatibility entries, possibly empty; out of range rejects the line.
func (p *fieldParser) idField(nis bool) (int, bool) {
	var v uint64
	ok := false
	if nis {
		v, _, ok = p.rawFieldMaybeNull(false)
	} else {
		v, ok = p.intField()
	}
	if !ok || v >= maxID {
		return 0, false
	}
	return int(v), true
}

// list is parse_list: comma-separated names up to term (or the end), each
// with leading blanks skipped, empty ones dropped; term is consumed.
func (p *fieldParser) list(term byte) []string {
	var out []string
	for {
		for p.pos < len(p.s) && isCSpace(p.s[p.pos]) {
			p.pos++
		}
		start := p.pos
		for p.pos < len(p.s) && p.s[p.pos] != ',' && (term == 0 || p.s[p.pos] != term) {
			p.pos++
		}
		if p.pos > start {
			out = append(out, p.s[start:p.pos])
		}
		if p.pos >= len(p.s) {
			return out
		}
		c := p.s[p.pos]
		p.pos++
		if c != ',' {
			return out
		}
	}
}

func nisName(name string) bool { return strings.HasPrefix(name, "+") || strings.HasPrefix(name, "-") }

type pwLine struct {
	name, passwd, gecos, home, shell string
	uid, gid                         int
}

// parsePasswd parses an /etc/passwd line as glibc's _nss_files_parse_pwent.
func parsePasswd(line string) (pwLine, bool) {
	p := &fieldParser{s: line}
	var r pwLine
	r.name = p.stringField()
	if p.atEnd() && nisName(r.name) {
		return r, true
	}
	r.passwd = p.stringField()
	var ok bool
	if r.uid, ok = p.idField(nisName(r.name)); !ok {
		return r, false
	}
	if r.gid, ok = p.idField(nisName(r.name)); !ok {
		return r, false
	}
	r.gecos = p.stringField()
	r.home = p.stringField()
	r.shell = p.s[p.pos:]
	return r, true
}

type spLine struct {
	name, passwd        string
	lastChange, maxDays int
}

// parseShadow parses an /etc/shadow line as glibc's _nss_files_parse_spent.
func parseShadow(line string) (spLine, bool) {
	p := &fieldParser{s: line}
	r := spLine{lastChange: -1, maxDays: -1}
	r.name = p.stringField()
	if p.atEnd() && nisName(r.name) {
		return r, true
	}
	r.passwd = p.stringField()
	lst, ok := p.intFieldMaybeNull(-1, false)
	if !ok {
		return r, false
	}
	if _, ok = p.intFieldMaybeNull(-1, false); !ok { // min
		return r, false
	}
	max, ok := p.intFieldMaybeNull(-1, false)
	if !ok {
		return r, false
	}
	r.lastChange, r.maxDays = int(lst), int(max)
	for p.pos < len(p.s) && isCSpace(p.s[p.pos]) {
		p.pos++
	}
	if p.atEnd() {
		return r, true // the old form, without warn, inact, expire and flag
	}
	for i := 0; i < 3; i++ { // warn, inact, expire
		if _, ok = p.intFieldMaybeNull(-1, false); !ok {
			return r, false
		}
	}
	if !p.atEnd() {
		if _, ok = p.intFieldMaybeNull(-1, true); !ok { // flag
			return r, false
		}
	}
	return r, true
}

type grLine struct {
	name    string
	gid     int
	members []string
}

// parseGroup parses an /etc/group line as glibc's _nss_files_parse_grent.
func parseGroup(line string) (grLine, bool) {
	p := &fieldParser{s: line}
	var r grLine
	r.name = p.stringField()
	if p.atEnd() && nisName(r.name) {
		return r, true
	}
	p.stringField() // password
	var ok bool
	if r.gid, ok = p.idField(nisName(r.name)); !ok {
		return r, false
	}
	r.members = p.list(0)
	return r, true
}

type sgLine struct {
	name, passwd    string
	admins, members []string
}

// parseGShadow parses an /etc/gshadow line as glibc's
// _nss_files_parse_sgent; every field after the name is optional.
func parseGShadow(line string) (sgLine, bool) {
	p := &fieldParser{s: line}
	var r sgLine
	r.name = p.stringField()
	if p.atEnd() && nisName(r.name) {
		return r, true
	}
	r.passwd = p.stringField()
	r.admins = p.list(':')
	r.members = p.list(0)
	return r, true
}

// accountDB tracks the lines of one database: the first line for a name
// counts, later ones are duplicates, rejected lines are malformed.
type accountDB struct {
	file       string
	seen       map[string]bool
	duplicates map[string]bool
	acc        *accountsReport
}

type accountsReport struct {
	duplicates, malformed []string
}

func newAccountDB(file string, rep *accountsReport) *accountDB {
	return &accountDB{file: file, seen: map[string]bool{}, duplicates: map[string]bool{}, acc: rep}
}

// first reports whether name is seen for the first time, recording a
// duplicate otherwise.
func (d *accountDB) first(name string) bool {
	if !d.seen[name] {
		d.seen[name] = true
		return true
	}
	if !d.duplicates[name] {
		d.duplicates[name] = true
		d.acc.duplicates = append(d.acc.duplicates, d.file+":"+name)
	}
	return false
}

// malformed records a line glibc rejects, or one it uses that names no
// account (note says what it claims; never a hash).
func (d *accountDB) malformed(n int, note string) {
	e := d.file + ":" + strconv.Itoa(n)
	if note != "" {
		e += " (" + note + ")"
	}
	d.acc.malformed = append(d.acc.malformed, e)
}
