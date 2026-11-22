package judge

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/donaldsteele/telltale/internal/model"
)

// Fix commands are text for a person to read and run; telltale never runs
// them. Every value that comes from the examined machine (paths, account,
// group and package names) is single-quoted, and a value holding a control
// character or bytes that are not text gets no command at all, only words,
// so a hostile name can neither break out of the quoting nor rewrite the
// terminal it is pasted into. Anything that removes or rewrites a file first
// copies it, with its directory structure, to the evidence directory.

const (
	evidenceDir = "/root/telltale-evidence"
	ctrlNote    = "no command is given because a name involved contains control characters or bytes that are not text: see the evidence and handle it by hand"
)

// unsafeText reports whether s must not be pasted into a command line.
func unsafeText(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// sq single-quotes s for a POSIX shell.
func sq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// command builds a command from machine values: build gets them quoted. If
// any value is unsafe, the result is ctrlNote instead.
func command(vals []string, build func(q []string) string) string {
	q := make([]string, len(vals))
	for i, v := range vals {
		if unsafeText(v) {
			return ctrlNote
		}
		q[i] = sq(v)
	}
	return build(q)
}

// keep copies the quoted paths q to the evidence directory.
func keep(q ...string) string {
	return "mkdir -p " + evidenceDir + " && cp -a --parents " + strings.Join(q, " ") + " " + evidenceDir + "/"
}

// fixReinstall puts back a package file: the file on disk is kept as
// evidence first (when it exists), then dpkg installs the package's copy.
func fixReinstall(p, pkg string, exists bool) string {
	if !exists {
		return command([]string{pkg}, func(q []string) string { return "apt-get install --reinstall " + q[0] })
	}
	return command([]string{p, pkg}, func(q []string) string {
		return keep(q[0]) + " && apt-get install --reinstall " + q[1]
	})
}

// fixDeleteLines removes the given lines (numbers in the current file) in one
// sed pass, after saving the file.
func fixDeleteLines(p string, lines []int, note string) string {
	ls := append([]int(nil), lines...)
	sort.Ints(ls)
	addr := make([]string, len(ls))
	for i, n := range ls {
		addr[i] = strconv.Itoa(n) + "d"
	}
	return command([]string{p}, func(q []string) string {
		s := keep(q[0]) + " && sed -i '" + strings.Join(addr, ";") + "' " + q[0]
		if note != "" {
			s += "   # " + note
		}
		return s
	})
}

// fixRemove deletes a file (or directory) that should not be there, after
// saving it.
func fixRemove(p string, dir bool) string {
	return command([]string{p}, func(q []string) string {
		rm := "rm -- "
		if dir {
			rm = "rm -r -- "
		}
		return keep(q[0]) + " && " + rm + q[0] + "   # only if you did not put it there"
	})
}

// fixKeepOnly saves a file and says what to do next in words.
func fixKeepOnly(p, then string) string {
	return command([]string{p}, func(q []string) string { return keep(q[0]) + "   # " + then })
}

// fixRestoreMeta sets mode and owner back to what the snapshot recorded.
// gid < 0 leaves the group alone.
func fixRestoreMeta(p string, mode uint32, modeChanged bool, uid uint32, gid int64, ownerChanged bool) string {
	return command([]string{p}, func(q []string) string {
		var parts []string
		if modeChanged {
			parts = append(parts, fmt.Sprintf("chmod %04o %s", mode&0o7777, q[0]))
		}
		if ownerChanged {
			owner := strconv.FormatUint(uint64(uid), 10)
			if gid >= 0 {
				owner += ":" + strconv.FormatInt(gid, 10)
			}
			parts = append(parts, "chown "+owner+" "+q[0])
		}
		return strings.Join(parts, " && ") + "   # back to the snapshot's mode and owner, if you did not change them on purpose"
	})
}

func fixDowngrade(pkg, version string) string {
	return command([]string{pkg + "=" + version}, func(q []string) string {
		return "apt-get install " + q[0] + "   # back to the version in the snapshot (or a newer one)"
	})
}

// fixPurge removes a package that should not be there. The list of its files
// is saved first; dpkg -L reads this machine's own records.
func fixPurge(pkg string) string {
	return command([]string{pkg, evidenceDir + "/" + pkg + ".files"}, func(q []string) string {
		return "mkdir -p " + evidenceDir + " && dpkg -L " + q[0] + " > " + q[1] + " && apt-get purge " + q[0] +
			"   # only if you did not install it; copy any of its files you want to examine before purging"
	})
}

func fixInstall(pkg string) string {
	return command([]string{pkg}, func(q []string) string { return "apt-get install " + q[0] })
}

func fixUserAdded(name string, uid0 bool) string {
	return command([]string{name}, func(q []string) string {
		del := "userdel "
		if uid0 {
			del = "userdel -f " // root's processes would otherwise block it
		}
		return keep("/etc/passwd", "/etc/shadow", "/etc/group") + " && " + del + q[0] + "   # check first that you did not create this account yourself"
	})
}

// fixUserChanged undoes the account fields that changed.
func fixUserChanged(name string, old, cur *model.User) string {
	if old == nil || cur == nil {
		return ""
	}
	vals := []string{name, old.Shell, old.Home}
	return command(vals, func(q []string) string {
		var steps []string
		var mod []string
		if old.Shell != cur.Shell {
			mod = append(mod, "-s "+q[1])
		}
		if old.Home != cur.Home {
			mod = append(mod, "-d "+q[2])
		}
		if len(mod) > 0 {
			steps = append(steps, "usermod "+strings.Join(mod, " ")+" "+q[0])
		}
		if old.UID != cur.UID || old.GID != cur.GID {
			steps = append(steps, fmt.Sprintf("set the user id back to %d and the group id to %d with vipw (usermod refuses while the account's processes run)", old.UID, old.GID))
		}
		if old.Password.Digest != cur.Password.Digest || old.Password.Locked != cur.Password.Locked || old.Password.Set != cur.Password.Set {
			steps = append(steps, "passwd -l "+q[0]+" if you did not change its password (locks it until you set a new one)")
		}
		if len(steps) == 0 {
			return ""
		}
		return keep("/etc/passwd", "/etc/shadow") + "   # then: " + strings.Join(steps, "; ")
	})
}

func fixGroupMembers(group string, added []string) string {
	vals := append([]string{group}, added...)
	return command(vals, func(q []string) string {
		cmds := []string{keep("/etc/group", "/etc/gshadow")}
		for _, m := range q[1:] {
			cmds = append(cmds, "gpasswd -d "+m+" "+q[0])
		}
		return strings.Join(cmds, " && ") + "   # only for members you did not add"
	})
}

func fixModule(name, file string) string {
	vals := []string{name}
	if file != "" {
		vals = append(vals, file)
	}
	return command(vals, func(q []string) string {
		s := "modinfo -- " + q[0]
		if len(q) > 1 {
			s = keep(q[1]) + " && " + s
		}
		return s + "   # then unload it with rmmod only after confirming it is not yours"
	})
}

// fixProcess saves a running program and shows what it has open. pid is a
// number, so nothing needs quoting.
func fixProcess(pid int) string {
	p := strconv.Itoa(pid)
	return "mkdir -p " + evidenceDir + " && cp /proc/" + p + "/exe " + evidenceDir + "/" + p + ".exe; ls -l /proc/" + p + "/cwd /proc/" + p +
		"/fd   # investigate; stop it with 'kill -STOP " + p + "' if you do not recognise it"
}
