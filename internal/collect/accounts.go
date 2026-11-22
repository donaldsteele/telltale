package collect

import (
	"strconv"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/redact"
)

const accountsCheck = "accounts"

// Accounts reads passwd, group and shadow under root. Shadow is reduced to a
// PasswordState; the hash itself is never kept.
func Accounts(root string, key []byte) (model.Accounts, []model.Skip) {
	var acc model.Accounts
	var skips []model.Skip
	skip := func(path, reason string) {
		skips = append(skips, model.Skip{Check: accountsCheck, Reason: path + ": " + reason})
	}

	shadow := map[string][]string{}
	sh, err := readRaw(root, "/etc/shadow", 4<<20)
	switch {
	case err == nil:
		for _, line := range splitLines(sh) {
			f := strings.Split(line, ":")
			if len(f) >= 2 && f[0] != "" {
				shadow[f[0]] = f
			}
		}
	case !isNotExist(err):
		skip("/etc/shadow", err.Error())
	}

	pw, err := readRaw(root, "/etc/passwd", 4<<20)
	if err != nil {
		skip("/etc/passwd", err.Error())
	}
	for _, line := range splitLines(pw) {
		f := strings.Split(line, ":")
		if len(f) < 7 || strings.HasPrefix(line, "#") {
			continue
		}
		u := model.User{Name: f[0], Home: f[5], Shell: f[6]}
		u.UID, _ = strconv.Atoi(f[2])
		u.GID, _ = strconv.Atoi(f[3])
		u.Password = model.PasswordState{Algo: "none", LastChange: -1, MaxDays: -1}
		if f[1] != "x" && !strings.HasPrefix(f[1], "##") {
			// The passwd field is not a shadow reference: it is the hash itself.
			u.Password = reduceShadow(key, []string{f[0], f[1]})
		} else if s, ok := shadow[f[0]]; ok {
			u.Password = reduceShadow(key, s)
		}
		acc.Users = append(acc.Users, u)
	}

	gr, err := readRaw(root, "/etc/group", 4<<20)
	if err != nil {
		skip("/etc/group", err.Error())
	}
	for _, line := range splitLines(gr) {
		f := strings.Split(line, ":")
		if len(f) < 4 || strings.HasPrefix(line, "#") {
			continue
		}
		g := model.Group{Name: f[0]}
		g.GID, _ = strconv.Atoi(f[2])
		if f[3] != "" {
			g.Members = strings.Split(f[3], ",")
		}
		acc.Groups = append(acc.Groups, g)
	}
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
