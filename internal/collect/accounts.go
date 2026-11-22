package collect

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/redact"
)

const accountsCheck = "accounts"

// Accounts reads passwd, shadow, group and gshadow under root the way
// glibc's files backend does (see nssfiles.go). Shadow and gshadow are
// reduced to password states; the hashes themselves are never kept.
func Accounts(root string, key []byte) (model.Accounts, []model.Skip) {
	var acc model.Accounts
	var skips []model.Skip
	var rep accountsReport
	skip := func(path, reason string) {
		skips = append(skips, model.Skip{Check: accountsCheck, Reason: path + ": " + reason})
	}

	shadow := map[string]spLine{}
	sh, err := readRaw(root, "/etc/shadow", 4<<20)
	switch {
	case err == nil:
		db := newAccountDB("/etc/shadow", &rep)
		for _, l := range nssLines(sh) {
			s, ok := parseShadow(l.text)
			switch {
			case !ok:
				db.malformed(l.n, "")
			case s.name == "":
				db.malformed(l.n, "empty name")
			case db.first(s.name):
				shadow[s.name] = s
			}
		}
	case !isNotExist(err):
		skip("/etc/shadow", err.Error())
	}

	pw, err := readRaw(root, "/etc/passwd", 4<<20)
	if err != nil {
		skip("/etc/passwd", err.Error())
	}
	db := newAccountDB("/etc/passwd", &rep)
	for _, l := range nssLines(pw) {
		f, ok := parsePasswd(l.text)
		switch {
		case !ok:
			db.malformed(l.n, "")
			continue
		case f.name == "":
			// glibc uses it: an empty-name uid 0 line placed first is what
			// getpwuid(0) returns.
			db.malformed(l.n, fmt.Sprintf("empty name, uid %d", f.uid))
			continue
		case !db.first(f.name):
			continue
		}
		u := model.User{Name: f.name, UID: f.uid, GID: f.gid, Home: f.home, Shell: f.shell}
		u.Password = model.PasswordState{Algo: "none", LastChange: -1, MaxDays: -1}
		if f.passwd != "x" && !strings.HasPrefix(f.passwd, "##") {
			// The passwd field is not a shadow reference: it is the hash itself.
			u.Password = reduceShadow(key, []string{f.name, f.passwd})
		} else if s, ok := shadow[f.name]; ok {
			u.Password = reduceShadow(key, []string{s.name, s.passwd, strconv.Itoa(s.lastChange), "", strconv.Itoa(s.maxDays)})
		}
		acc.Users = append(acc.Users, u)
	}

	// gshadow is reduced to whether a usable group password is set and who
	// administers or belongs to the group; the hash itself is never kept.
	var gshadow map[string]model.GroupShadow
	gs, err := readRaw(root, "/etc/gshadow", 4<<20)
	switch {
	case err == nil:
		gshadow = map[string]model.GroupShadow{}
		db := newAccountDB("/etc/gshadow", &rep)
		for _, l := range nssLines(gs) {
			s, _ := parseGShadow(l.text)
			if s.name == "" {
				db.malformed(l.n, "empty name")
				continue
			}
			if !db.first(s.name) {
				continue
			}
			set := s.passwd != "" && !strings.HasPrefix(s.passwd, "!") && !strings.HasPrefix(s.passwd, "*")
			gshadow[s.name] = model.GroupShadow{PasswordSet: set, Admins: s.admins, Members: s.members}
		}
	case !isNotExist(err):
		skip("/etc/gshadow", err.Error())
	}

	gr, err := readRaw(root, "/etc/group", 4<<20)
	if err != nil {
		skip("/etc/group", err.Error())
	}
	db = newAccountDB("/etc/group", &rep)
	for _, l := range nssLines(gr) {
		f, ok := parseGroup(l.text)
		switch {
		case !ok:
			db.malformed(l.n, "")
			continue
		case f.name == "":
			// initgroups honours its members.
			note := fmt.Sprintf("empty name, gid %d", f.gid)
			if len(f.members) > 0 {
				note += ", members " + strings.Join(f.members, ",")
			}
			db.malformed(l.n, note)
			continue
		case !db.first(f.name):
			continue
		}
		g := model.Group{Name: f.name, GID: f.gid, Members: f.members}
		if gshadow != nil {
			s := gshadow[f.name]
			g.Shadow = &s
		}
		acc.Groups = append(acc.Groups, g)
	}
	sort.Strings(rep.duplicates)
	acc.Duplicates, acc.Malformed = rep.duplicates, rep.malformed
	return acc, skips
}

func reduceShadow(key []byte, f []string) model.PasswordState {
	h := f[1]
	p := model.PasswordState{
		Known:      true,
		Locked:     strings.HasPrefix(h, "!") || strings.HasPrefix(h, "*"),
		Algo:       shadowAlgo(h),
		LastChange: -1,
		MaxDays:    -1,
	}
	p.Set = strings.TrimLeft(h, "!*") != ""
	if p.Set {
		p.Digest = redact.Digest(key, h)
	}
	if len(f) > 2 {
		if n, err := strconv.Atoi(f[2]); err == nil {
			p.LastChange = n
		}
	}
	if len(f) > 4 {
		if n, err := strconv.Atoi(f[4]); err == nil {
			p.MaxDays = n
		}
	}
	return p
}

// shadowAlgo names the hash algorithm of a shadow password field.
func shadowAlgo(field string) string {
	h := strings.TrimLeft(field, "!")
	switch {
	case strings.HasPrefix(h, "$y$"):
		return "yescrypt"
	case strings.HasPrefix(h, "$6$"):
		return "sha512"
	case strings.HasPrefix(h, "$5$"):
		return "sha256"
	case strings.HasPrefix(h, "$1$"):
		return "md5"
	case strings.HasPrefix(h, "$2a$"), strings.HasPrefix(h, "$2b$"), strings.HasPrefix(h, "$2y$"):
		return "bcrypt"
	case len(h) == 13 && !strings.HasPrefix(h, "$") && !strings.HasPrefix(h, "*"):
		return "des"
	}
	return "none"
}
