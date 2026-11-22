package checklist

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/model"
)

const reloadSSH = " && systemctl reload ssh"

// items is the checklist, in report order.
var items = []Item{
	// SSH server.
	{
		ID:     "TT-SSH-001",
		Title:  "SSH root login is off (key login from the telltale server only)",
		Why:    "If root may log in over SSH, anyone who learns the root password or plants a root key gets straight in as root. The only exception expected is key login from the telltale server's own address.",
		Fix:    sedSSHD("PermitRootLogin", "no"),
		Check:  checkRootLogin,
		fixFor: fixRootLogin,
	},
	sshdItem("TT-SSH-002", "PermitEmptyPasswords", "no", isWord("no"),
		"SSH refuses accounts with empty passwords",
		"With this on, an account that has no password can be logged into over the network by anyone who knows its name."),
	sshdItem("TT-SSH-003", "PasswordAuthentication", "no", func(string) bool { return true },
		"SSH password login is noted (key-only login is stronger)",
		"Password login lets attackers guess passwords over the network; key-only login does not. This is noted, not failed, because many machines rely on it."),
	sshdItem("TT-SSH-004", "X11Forwarding", "no", isWord("no"),
		"SSH X11 forwarding is off",
		"X11 forwarding lets a logged-in session reach back into the user's desktop, and is rarely needed on a server."),
	sshdItem("TT-SSH-005", "MaxAuthTries", "4", atMost(4),
		"SSH allows at most 4 login attempts per connection",
		"More attempts per connection make password guessing faster."),
	sshdItem("TT-SSH-006", "HostbasedAuthentication", "no", isWord("no"),
		"SSH host-based login is off",
		"Host-based login trusts other machines to vouch for users, so taking over one machine opens this one."),
	sshdItem("TT-SSH-007", "IgnoreRhosts", "yes", isWord("yes"),
		"SSH ignores .rhosts files",
		"A .rhosts file lets a user grant password-free access from other machines; attackers drop one to get back in."),
	{
		ID:     "TT-SSH-008",
		Title:  "sshd configuration files are mode 0644 or stricter and owned by root",
		Why:    "Anyone who can write the SSH server configuration can let themselves in, for example by turning root login back on.",
		Fix:    "chown root:root /etc/ssh/sshd_config && chmod 644 /etc/ssh/sshd_config",
		Check:  checkSSHDFiles,
		fixFor: fixSSHDFiles,
	},
	{
		ID:     "TT-SSH-009",
		Title:  "No sshd Match block loosens a checked setting",
		Why:    "A Match block can quietly turn root login or empty passwords back on for chosen users or addresses while the global settings look hardened. Only the telltale server's own block (key login for root from its address) is expected.",
		Fix:    `grep -n -i -A 8 '^[[:space:]]*match[[:space:]]' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf`,
		Check:  checkMatchBlocks,
		fixFor: fixMatchBlocks,
	},
	sshdItem("TT-SSH-010", "PermitUserEnvironment", "no", isWord("no"),
		"SSH ignores users' environment files",
		"With this on, a user's ~/.ssh/environment can set LD_PRELOAD and similar variables for their sessions, a known way to run hidden code."),
	sshdItem("TT-SSH-011", "StrictModes", "yes", isWord("yes"),
		"SSH checks the permissions of users' key files",
		"Without this check, sshd accepts authorized_keys files that other users can write, so anyone can add their own key."),

	// Accounts.
	{
		ID:     "TT-ACCT-001",
		Title:  "Only root has UID 0",
		Why:    "Any account with UID 0 is root under another name, a classic hidden way back in.",
		Fix:    `awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | xargs -r -n1 userdel -f`,
		Check:  checkUID0,
		fixFor: fixUID0,
	},
	{
		ID:     "TT-ACCT-002",
		Title:  "No account has an empty password",
		Why:    "An account with an empty password can be logged into by anyone who knows its name.",
		Fix:    `awk -F: '$2 == "" {print $1}' /etc/shadow | xargs -r -n1 passwd -l`,
		Check:  checkEmptyPasswords,
		fixFor: fixEmptyPasswords,
	},
	{
		ID:     "TT-ACCT-003",
		Title:  "System accounts have no login shell",
		Why:    "Service accounts (UID below 1000) never need to log in; giving one a shell is a quiet way to add a login nobody watches.",
		Fix:    `awk -F: '$3 > 0 && $3 < 1000 && $1 !~ /^(sync|shutdown|halt)$/ && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd | xargs -r -n1 usermod -s /usr/sbin/nologin`,
		Check:  checkSystemShells,
		fixFor: fixSystemShells,
	},
	{
		ID:     "TT-ACCT-004",
		Title:  "Passwords are hashed with yescrypt or SHA-512",
		Why:    "Older hashes (MD5, DES, SHA-256) can be cracked quickly by anyone who gets a copy of /etc/shadow.",
		Fix:    `sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs && awk -F: '$2 != "" && $2 !~ /^[!*]/ && $2 !~ /^\$(y|6)\$/ {print $1}' /etc/shadow | xargs -r -n1 passwd -e`,
		Check:  checkHashAlgo,
		fixFor: fixHashAlgo,
	},

	// sudo.
	{
		ID:     "TT-SUDO-001",
		Title:  "No sudo rule skips the password (NOPASSWD)",
		Why:    "A NOPASSWD rule turns anyone who gets into that account, even without its password, into root. Before removing it, give each account it covers a password, or nobody may be able to become root.",
		Fix:    `grep -rl NOPASSWD /etc/sudoers /etc/sudoers.d | xargs -r sed -i 's/NOPASSWD[[:space:]]*:/PASSWD:/g' && visudo -c`,
		Check:  sudoRuleCheck(noPasswdRe, "NOPASSWD"),
		fixFor: fixNoPasswd,
	},
	{
		ID:     "TT-SUDO-002",
		Title:  "sudo always asks for authentication (no !authenticate)",
		Why:    "A Defaults !authenticate line makes sudo hand out root without asking for any password.",
		Fix:    `grep -rl '!authenticate' /etc/sudoers /etc/sudoers.d | xargs -r sed -i 's/![[:space:]]*authenticate/authenticate/g' && visudo -c`,
		Check:  sudoRuleCheck(notAuthRe, "!authenticate"),
		fixFor: sudoRuleFix(notAuthRe, `s/![[:space:]]*authenticate/authenticate/g`),
	},
	{
		ID:     "TT-SUDO-003",
		Title:  "sudoers files are mode 0440 and owned by root",
		Why:    "Anyone who can write a sudoers file can give themselves root.",
		Fix:    "chown root:root /etc/sudoers && chmod 440 /etc/sudoers",
		Check:  checkSudoersFiles,
		fixFor: fixSudoersFiles,
	},

	// Files.
	fileModeItem("TT-FILE-001", "/etc/shadow", 0o640, "shadow",
		"/etc/shadow is mode 0640 or stricter, owned by root, group shadow",
		"/etc/shadow holds the password hashes; anyone who can read it can try to crack them offline, and anyone who can write it can set any password.",
		"chmod 640 /etc/shadow && chown root:shadow /etc/shadow"),
	fileModeItem("TT-FILE-002", "/etc/passwd", 0o644, "root",
		"/etc/passwd is mode 0644 or stricter and owned by root",
		"Anyone who can write /etc/passwd can add an account with UID 0.",
		"chmod 644 /etc/passwd && chown root:root /etc/passwd"),
	fileModeItem("TT-FILE-003", "/etc/group", 0o644, "root",
		"/etc/group is mode 0644 or stricter and owned by root",
		"Anyone who can write /etc/group can add themselves to the sudo or shadow group.",
		"chmod 644 /etc/group && chown root:root /etc/group"),
	fileModeItem("TT-FILE-004", "/etc/gshadow", 0o640, "shadow",
		"/etc/gshadow is mode 0640 or stricter, owned by root, group shadow",
		"/etc/gshadow holds group passwords and administrators; write access lets someone join any group.",
		"chmod 640 /etc/gshadow && chown root:shadow /etc/gshadow"),
	{
		ID:     "TT-FILE-005",
		Title:  "No world-writable files in system paths",
		Why:    "A world-writable program, library or config file in a system path can be replaced by any local user, and root will run their version.",
		Fix:    `find /bin /sbin /usr /lib /etc /boot /root -xdev \( -type f -o -type d ! -perm -1000 \) -perm -0002 -exec chmod o-w {} +`,
		Check:  checkWorldWritable,
		fixFor: fixWorldWritable,
	},
	{
		ID:     "TT-FILE-006",
		Title:  "cron directories are mode 0700 and owned by root",
		Why:    "Readable cron directories show attackers which jobs run as root; writable ones let them add their own.",
		Fix:    "chmod 700 " + strings.Join(cronDirs, " ") + " && chown root:root " + strings.Join(cronDirs, " "),
		Check:  checkCronDirs,
		fixFor: fixCronDirs,
	},

	// Firewall.
	{
		ID:     "TT-FW-001",
		Title:  "A firewall is active",
		Why:    "Without a firewall, every service that listens on the network can be reached, including one an attacker starts.",
		Fix:    "apt-get install -y ufw && ufw allow ssh && ufw --force enable",
		Check:  checkFirewall,
		fixFor: fixFirewall,
	},

	// Kernel.
	sysctlItem("TT-KERN-001", "kernel.randomize_va_space", "2", equals("2"),
		"Memory layout randomisation is fully on",
		"Randomising where programs and libraries sit in memory makes many exploits fail."),
	sysctlItem("TT-KERN-002", "fs.suid_dumpable", "0", equals("0"),
		"setuid programs do not dump core",
		"A core dump of a setuid program can contain password hashes or keys that an ordinary user can then read."),
	sysctlItem("TT-KERN-003", "kernel.kptr_restrict", "1", atLeastSysctl(1),
		"Kernel addresses are hidden from users",
		"Kernel addresses help an attacker aim a kernel exploit, for example one used to load a rootkit."),
	sysctlItem("TT-KERN-004", "kernel.dmesg_restrict", "1", equals("1"),
		"Only root can read the kernel log",
		"The kernel log reveals addresses and hardware details that help an attacker aim an exploit."),
	sysctlItem("TT-KERN-005", "net.ipv4.conf.all.accept_redirects", "0", equals("0"),
		"ICMP redirects are ignored",
		"Accepting redirects lets someone on the network reroute this machine's traffic through themselves."),
	sysctlItem("TT-KERN-006", "net.ipv4.conf.all.send_redirects", "0", equals("0"),
		"ICMP redirects are not sent",
		"Only a router needs to send redirects; on other machines it helps an attacker who has taken over the network path."),
	sysctlItem("TT-KERN-007", "net.ipv4.conf.all.accept_source_route", "0", equals("0"),
		"Source-routed packets are refused",
		"Source routing lets a sender choose the path of a packet, which helps get past firewalls."),
	sysctlItem("TT-KERN-008", "net.ipv4.tcp_syncookies", "1", equals("1"),
		"TCP SYN cookies are on",
		"SYN cookies keep the machine reachable during a SYN flood."),
	sysctlItem("TT-KERN-009", "fs.protected_symlinks", "1", equals("1"),
		"Symlink protection is on",
		"Without it, a local user can plant symlinks in shared directories such as /tmp that trick root into overwriting files."),
	sysctlItem("TT-KERN-010", "fs.protected_hardlinks", "1", equals("1"),
		"Hard link protection is on",
		"Without it, a local user can hard-link files they do not own, such as /etc/shadow, into places root later writes or exposes."),
	sysctlItem("TT-KERN-011", "net.ipv6.conf.all.accept_redirects", "0", equals("0"),
		"IPv6 ICMP redirects are ignored",
		"Accepting redirects lets someone on the network reroute this machine's IPv6 traffic through themselves."),
	sysctlItem("TT-KERN-012", "kernel.yama.ptrace_scope", "1", atLeastSysctl(1),
		"Processes cannot trace unrelated processes",
		"With unrestricted ptrace, any program a user runs can read the memory of their other programs, such as SSH agents and password prompts."),

	// Services and packages.
	absentItem("TT-SVC-001", []string{"telnetd", "inetutils-telnetd", "telnetd-ssl"},
		"No telnet server is installed",
		"Telnet sends passwords in clear text and is a common way back in once installed."),
	absentItem("TT-SVC-002", []string{"rsh-server", "rsh-redone-server"},
		"No rsh or rlogin server is installed",
		"rsh and rlogin send everything in clear text and can trust other machines without a password."),
	absentItem("TT-SVC-003", []string{"tftpd-hpa", "tftpd", "atftpd"},
		"No TFTP server is installed",
		"TFTP has no authentication at all; anyone who can reach it can read, and often write, its files."),
	absentItem("TT-SVC-004", []string{"nis", "ypserv", "ypbind-mt", "yp-tools"},
		"No NIS packages are installed",
		"NIS shares account data over the network without encryption, including password hashes."),
	presentItem("TT-SVC-005", "auditd", "apt-get install -y auditd && systemctl enable --now auditd",
		"auditd is installed",
		"The audit daemon records logins, privilege use and changes to key files, the trail you need after a break-in."),
	{
		ID:     "TT-SVC-006",
		Title:  "AppArmor is enabled",
		Why:    "AppArmor confines services to what they need, so a compromised service cannot freely read or change the rest of the system.",
		Fix:    "apt-get install -y apparmor && systemctl enable --now apparmor",
		Check:  checkAppArmor,
		fixFor: fixAppArmor,
	},
	presentItem("TT-SVC-007", "unattended-upgrades", "apt-get install -y unattended-upgrades",
		"Security updates install automatically (unattended-upgrades)",
		"Most break-ins use holes that already have a fix; installing security updates automatically closes them without waiting for someone to remember."),
}

// --- SSH ---

// sshdNames maps lower-cased keywords to their usual spelling.
var sshdNames = map[string]string{
	"permitrootlogin":         "PermitRootLogin",
	"permitemptypasswords":    "PermitEmptyPasswords",
	"passwordauthentication":  "PasswordAuthentication",
	"x11forwarding":           "X11Forwarding",
	"maxauthtries":            "MaxAuthTries",
	"hostbasedauthentication": "HostbasedAuthentication",
	"ignorerhosts":            "IgnoreRhosts",
	"permituserenvironment":   "PermitUserEnvironment",
	"strictmodes":             "StrictModes",
}

// sedSSHD sets name to value in the global section of sshd_config: the lines
// before the first Match line, so no Match block (including the telltale
// server's own) is touched.
func sedSSHD(name, value string) string {
	return fmt.Sprintf(`sed -i '0,/^[[:space:]]*[Mm][Aa][Tt][Cc][Hh][[:space:]]/s/^#\?%s.*/%s %s/' /etc/ssh/sshd_config`, name, name, value) + reloadSSH
}

func firstWord(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return strings.ToLower(f[0])
	}
	return ""
}

func redacted(v string) bool { return strings.HasPrefix(v, "<redacted") }

// sourceNote says where a value came from when it is not a config line.
func sourceNote(s sshdSetting) string {
	switch s.Path {
	case "":
		return " (default)"
	case cmdlineSource:
		return " " + cmdlineSource
	}
	return ""
}

func isWord(w string) func(string) bool { return func(v string) bool { return v == w } }

func atMost(n int) func(string) bool {
	return func(v string) bool {
		i, err := strconv.Atoi(v)
		return err == nil && i >= 0 && i <= n
	}
}

// rootLoginValue normalises a PermitRootLogin value; without-password is the
// old name of prohibit-password.
func rootLoginValue(v string) string {
	v = firstWord(v)
	if v == "without-password" {
		return "prohibit-password"
	}
	return v
}

// sshdLineFix rewrites the line that set s, or adds the setting at the top
// of sshd_config when s is the default (the top is always the global
// section, and the first value wins there).
func sshdLineFix(cfg *sshdConfig, s sshdSetting, name, value string) string {
	if !escape.Quotable(s.Path) {
		return nulNote(s.Path)
	}
	if s.Path == "" {
		return fmt.Sprintf("sed -i%s '1i %s %s' %s", followFlag(cfg.links[mainSSHDConfig]), name, value, mainSSHDConfig)
	}
	return fmt.Sprintf("sed -i%s '%ds/.*/%s %s/' %s", followFlag(cfg.links[s.Path]), s.Line, name, value, shellQuote(s.Path))
}

// cmdlineFix is for a value set with -o on a running sshd's command line,
// which overrides sshd_config: the option has to go where that sshd is
// started.
func cmdlineFix(v sshdView, name string) string {
	return fmt.Sprintf("# sshd (pid %d) is started with -o %s=..., which overrides sshd_config: remove it where that sshd is started, then restart it\n"+
		"grep -rn -i -- %s /etc/default/ssh /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system 2>/dev/null", v.pid, name, name)
}

func followFlag(link bool) string {
	if link {
		return " --follow-symlinks"
	}
	return ""
}

// rootLoginIn judges root login in one view.
func rootLoginIn(v sshdView, ctx model.ScanContext) (bool, string) {
	g := v.effective("")["permitrootlogin"]
	gv := rootLoginValue(g.Value)
	obs := "PermitRootLogin " + gv + sourceNote(g)
	pass := gv == "no"
	if ctx.ServerAddr != "" {
		sv := rootLoginValue(v.effective(ctx.ServerAddr)["permitrootlogin"].Value)
		obs += "; from the telltale server " + ctx.ServerAddr + ": " + sv
		pass = pass && (sv == "prohibit-password" || sv == "no")
	}
	return pass, obs
}

func checkRootLogin(c *model.Collection, ctx model.ScanContext) (bool, string, string) {
	views, why := sshdViews(c)
	if why != "" {
		return false, "", why
	}
	_, firstObs := rootLoginIn(views[0], ctx)
	for _, v := range views {
		if pass, obs := rootLoginIn(v, ctx); !pass {
			return false, obs, ""
		}
	}
	return true, firstObs, ""
}

// serverBlockFix appends the enrolment block that lets the telltale server
// log in as root by key from its own address.
func serverBlockFix(addr string) string {
	return `printf '\nMatch Address %s\n    PermitRootLogin prohibit-password\n' ` + shellQuote(addr) + " >> " + mainSSHDConfig
}

// serverBlockBefore inserts the enrolment block just before Match block b,
// so it is the first applying block for the server's address (among
// applying Match blocks the first value wins). It returns "" when the
// address has characters that cannot go into a sed script safely.
func serverBlockBefore(cfg *sshdConfig, b matchBlock, addr string) string {
	if addr == "" || strings.Trim(addr, "0123456789abcdefABCDEF.:") != "" || !escape.Quotable(b.Path) {
		return ""
	}
	return fmt.Sprintf(`sed -i%s -e '%di Match Address %s' -e '%di\    PermitRootLogin prohibit-password' %s`,
		followFlag(cfg.links[b.Path]), b.Line, addr, b.Line, shellQuote(b.Path))
}

func fixRootLogin(c *model.Collection, ctx model.ScanContext) string {
	views, why := sshdViews(c)
	if why != "" {
		return ""
	}
	for _, v := range views {
		if pass, _ := rootLoginIn(v, ctx); !pass {
			return fixRootLoginIn(v, ctx)
		}
	}
	return ""
}

// fixRootLoginIn turns root login off for everyone, keeps or restores key
// login from the telltale server, and never cuts the server off:
//   - the server's value comes from the global section or the default, which
//     the fix turns to "no": the server's Match block is appended;
//   - it comes from the server's own block: that line is set to
//     prohibit-password;
//   - it comes from another applying block (Match all, or a broader address
//     block) that would leave the server with "no" or a looser value: the
//     server's block is inserted before that block, so it wins.
func fixRootLoginIn(v sshdView, ctx model.ScanContext) string {
	var edits []string
	insert, before, block := "", "", ""
	g := v.effective("")["permitrootlogin"]
	globalBad := rootLoginValue(g.Value) != "no"
	if globalBad {
		switch g.Path {
		case cmdlineSource:
			return cmdlineFix(v, "PermitRootLogin")
		case "":
			insert = sshdLineFix(v.cfg, g, "PermitRootLogin", "no")
		default:
			edits = append(edits, sshdLineFix(v.cfg, g, "PermitRootLogin", "no"))
		}
	}
	if ctx.ServerAddr != "" {
		s := v.effective(ctx.ServerAddr)["permitrootlogin"]
		sv := rootLoginValue(s.Value)
		serverOK := sv == "no" || sv == "prohibit-password"
		b, inBlock := v.cfg.blockOf(s)
		switch {
		case s.Path == cmdlineSource:
			// Only the command line can change it (handled above for "").
		case !inBlock:
			if globalBad {
				block = serverBlockFix(ctx.ServerAddr)
			}
		case isServerBlock(b.Criteria, ctx.ServerAddr):
			if !serverOK {
				edits = append(edits, sshdLineFix(v.cfg, s, "PermitRootLogin", "prohibit-password"))
			}
		case b.Everyone && globalBad, !b.Everyone && !serverOK:
			if before = serverBlockBefore(v.cfg, b, ctx.ServerAddr); before == "" {
				block = serverBlockFix(ctx.ServerAddr)
			}
		}
	}
	// Inserting a line shifts the ones below it, so line edits go first,
	// then the insert lower in the file, then the one at line 1; appending
	// moves nothing.
	cmds := edits
	for _, c := range []string{before, insert, block} {
		if c != "" {
			cmds = append(cmds, c)
		}
	}
	if len(cmds) == 0 {
		return ""
	}
	var run, notes []string
	for _, c := range cmds {
		if strings.HasPrefix(c, "#") {
			notes = append(notes, c)
		} else {
			run = append(run, c)
		}
	}
	if len(run) == 0 {
		return joinNotes("", notes)
	}
	return joinNotes(strings.Join(run, " && ")+reloadSSH, notes)
}

// sshdItem checks one keyword's effective value for clients that no Match
// block names, in every running sshd.
func sshdItem(id, name, want string, ok func(v string) bool, title, why string) Item {
	key := strings.ToLower(name)
	return Item{
		ID:    id,
		Title: title,
		Why:   why,
		Fix:   sedSSHD(name, want),
		Check: func(c *model.Collection, _ model.ScanContext) (bool, string, string) {
			views, skip := sshdViews(c)
			if skip != "" {
				return false, "", skip
			}
			var firstObs string
			for i, v := range views {
				s := v.effective("")[key]
				if redacted(s.Value) {
					return false, "", name + " was redacted in the collected text, so its value is unknown"
				}
				obs := name + " " + s.Value + sourceNote(s)
				if !ok(firstWord(s.Value)) {
					return false, obs, ""
				}
				if i == 0 {
					firstObs = obs
				}
			}
			return true, firstObs, ""
		},
		fixFor: func(c *model.Collection, _ model.ScanContext) string {
			views, skip := sshdViews(c)
			if skip != "" {
				return ""
			}
			for _, v := range views {
				s := v.effective("")[key]
				switch {
				case ok(firstWord(s.Value)):
					continue
				case s.Path == cmdlineSource:
					return cmdlineFix(v, name)
				}
				return withReload(sshdLineFix(v.cfg, s, name, want))
			}
			return ""
		},
	}
}

func sshdPaths(c *model.Collection) []string {
	var ps []string
	for _, pf := range c.Persist {
		if pf.Kind == model.PersistKindSSHD {
			ps = append(ps, pf.Path)
		}
	}
	return sortedUnique(ps)
}

// badModes returns the paths whose permissions exceed maxPerm or whose owner
// is not root, described, and the first path that could not be checked.
func badModes(c *model.Collection, paths []string, maxPerm uint32) (bad, badPaths []string, unknown string) {
	for _, p := range paths {
		e, why := fileStat(c, p)
		if why != "" {
			e, why = persistMeta(c, p, why)
		}
		if why != "" {
			if unknown == "" {
				unknown = why
			}
			continue
		}
		if e.Mode&0o7777&^maxPerm != 0 || e.UID != 0 {
			bad = append(bad, p+" "+describeOwner(c, e, false))
			badPaths = append(badPaths, p)
		}
	}
	return bad, badPaths, unknown
}

// persistMeta falls back to the mode and owner recorded with a collected
// persistence file (not a symlink) at p; why is kept when there is none.
func persistMeta(c *model.Collection, p, why string) (model.FileEntry, string) {
	for _, pf := range c.Persist {
		if pf.Path == p && pf.Mode != 0 && !isSymlinkMode(pf.Mode) {
			return model.FileEntry{Path: p, Mode: pf.Mode, UID: pf.UID}, ""
		}
	}
	return model.FileEntry{}, why
}

func checkSSHDFiles(c *model.Collection, _ model.ScanContext) (bool, string, string) {
	if why := sshdBlocked(c); why != "" {
		return false, "", why
	}
	paths := sshdPaths(c)
	if len(paths) == 0 {
		return false, "", "no sshd configuration collected"
	}
	bad, _, unknown := badModes(c, paths, 0o644)
	switch {
	case len(bad) > 0:
		return false, strings.Join(bad, "; "), ""
	case unknown != "":
		return false, "", unknown
	}
	return true, "all sshd configuration files 0644 or stricter, owned by root", ""
}

func fixSSHDFiles(c *model.Collection, _ model.ScanContext) string {
	_, paths, _ := badModes(c, sshdPaths(c), 0o644)
	if len(paths) == 0 {
		return ""
	}
	return overPaths(paths, func(q string) string { return "chown root:root " + q + " && chmod 644 " + q })
}

// looseSetting is a Match-block setting that loosens a checked keyword.
type looseSetting struct {
	Criteria []string
	Key      string
	Set      sshdSetting
}

// loosens reports whether value for key is weaker than the checklist wants.
func loosens(key, value string) bool {
	v := firstWord(value)
	switch key {
	case "permitrootlogin":
		return rootLoginValue(v) != "no"
	case "permitemptypasswords", "x11forwarding", "hostbasedauthentication":
		return v == "yes"
	case "ignorerhosts", "strictmodes":
		return v != "yes"
	case "permituserenvironment":
		return v != "no"
	case "maxauthtries":
		return !atMost(4)(v)
	}
	return false
}

// isServerBlock reports whether Match criteria name exactly the telltale
// server's address (the block enrolment asks the owner to add).
func isServerBlock(crit []string, serverAddr string) bool {
	if serverAddr == "" || len(crit) != 2 || !strings.EqualFold(crit[0], "address") {
		return false
	}
	want, err := netip.ParseAddr(serverAddr)
	if err != nil {
		return strings.EqualFold(crit[1], serverAddr)
	}
	want = want.Unmap()
	if pfx, err := netip.ParsePrefix(crit[1]); err == nil {
		return pfx.IsSingleIP() && pfx.Addr().Unmap() == want
	}
	got, err := netip.ParseAddr(crit[1])
	return err == nil && got.Unmap() == want
}

// looseMatchSettings lists loosening settings in Match blocks that do not
// apply to every connection (those are judged with the global values),
// excepting root key login in the telltale server's own block. Keywords not
// allowed in Match blocks are left out: sshd refuses to start with one there.
func looseMatchSettings(cfg *sshdConfig, ctx model.ScanContext) []looseSetting {
	var out []looseSetting
	for _, b := range cfg.blocks() {
		if b.Everyone {
			continue
		}
		server := isServerBlock(b.Criteria, ctx.ServerAddr)
		for i, k := range b.Keys {
			s := b.Settings[i]
			if !matchAllowed[k] || !loosens(k, s.Value) {
				continue
			}
			if server && k == "permitrootlogin" && rootLoginValue(s.Value) == "prohibit-password" {
				continue
			}
			out = append(out, looseSetting{Criteria: b.Criteria, Key: k, Set: s})
		}
	}
	return out
}

func checkMatchBlocks(c *model.Collection, ctx model.ScanContext) (bool, string, string) {
	views, why := sshdViews(c)
	if why != "" {
		return false, "", why
	}
	loose := looseMatchSettings(views[0].cfg, ctx)
	if len(loose) == 0 {
		return true, "no Match block loosens a checked setting", ""
	}
	var obs []string
	for _, l := range loose {
		obs = append(obs, "Match "+strings.Join(l.Criteria, " ")+": "+sshdNames[l.Key]+" "+l.Set.Value)
	}
	return false, strings.Join(obs, "; "), ""
}

// fixMatchBlocks comments out each loosening line; one sed per file so line
// numbers stay valid.
func fixMatchBlocks(c *model.Collection, ctx model.ScanContext) string {
	views, why := sshdViews(c)
	if why != "" {
		return ""
	}
	cfg := views[0].cfg
	var order []string
	lines := map[string][]int{}
	for _, l := range looseMatchSettings(cfg, ctx) {
		if _, ok := lines[l.Set.Path]; !ok {
			order = append(order, l.Set.Path)
		}
		lines[l.Set.Path] = append(lines[l.Set.Path], l.Set.Line)
	}
	if len(order) == 0 {
		return ""
	}
	var cmds, notes []string
	for _, p := range order {
		if !escape.Quotable(p) {
			notes = append(notes, nulNote(p))
			continue
		}
		cmd := "sed -i" + followFlag(cfg.links[p])
		for _, n := range lines[p] {
			cmd += fmt.Sprintf(" -e '%ds/^/#/'", n)
		}
		cmds = append(cmds, cmd+" "+shellQuote(p))
	}
	if len(cmds) == 0 {
		return joinNotes("", notes)
	}
	return joinNotes(strings.Join(cmds, " && ")+reloadSSH, notes)
}

// --- Accounts ---

func checkUID0(c *model.Collection, _ model.ScanContext) (bool, string, string) {
	extra, skip := uid0Extra(c)
	if skip != "" {
		return false, "", skip
	}
	if len(extra) > 0 {
		return false, "UID 0 besides root: " + strings.Join(extra, ", "), ""
	}
	return true, "only root has UID 0", ""
}

func uid0Extra(c *model.Collection) ([]string, string) {
	us := accounts(c)
	if len(us) == 0 {
		return nil, "no accounts collected"
	}
	var extra []string
	for _, u := range us {
		if u.UID == 0 && u.Name != "root" {
			extra = append(extra, u.Name)
		}
	}
	return sortedUnique(extra), ""
}

// perUser runs cmd for each account name; a name with a NUL byte is left out
// and named in a comment instead.
func perUser(names []string, cmd string) string {
	cmd, notes := perUserCmd(names, cmd)
	return joinNotes(cmd, notes)
}

func perUserCmd(names []string, cmd string) (string, []string) {
	kept, notes := splitNUL(names)
	cmds := make([]string, len(kept))
	for i, n := range kept {
		cmds[i] = cmd + " " + shellQuote(n)
	}
	return strings.Join(cmds, " && "), notes
}

// splitNotes separates a fix text into its command lines and its comment
// lines. Commands are never extended on a comment's line.
func splitNotes(s string) (cmd string, notes []string) {
	var cmds []string
	for _, l := range strings.Split(s, "\n") {
		switch {
		case l == "":
		case strings.HasPrefix(l, "#"):
			notes = append(notes, l)
		default:
			cmds = append(cmds, l)
		}
	}
	return strings.Join(cmds, "\n"), notes
}

// andThen chains two fix texts with && and puts every comment line after the
// command, so nothing is ever appended to a comment.
func andThen(a, b string) string {
	ca, na := splitNotes(a)
	cb, nb := splitNotes(b)
	cmd := ca
	switch {
	case ca == "":
		cmd = cb
	case cb != "":
		cmd = ca + " && " + cb
	}
	return joinNotes(cmd, append(na, nb...))
}

// withReload appends the sshd reload to the command of a fix text, leaving
// any comment lines after it; a text with no command gets no reload.
func withReload(s string) string {
	c, notes := splitNotes(s)
	if c == "" {
		return s
	}
	return joinNotes(c+reloadSSH, notes)
}

func fixUID0(c *model.Collection, _ model.ScanContext) string {
	extra, _ := uid0Extra(c)
	return perUser(extra, "userdel -f")
}

func emptyPasswords(c *model.Collection) ([]string, string) {
	if why := shadowMissing(c); why != "" {
		return nil, why
	}
	var names []string
	for _, u := range accounts(c) {
		if !u.Password.Set && !u.Password.Locked {
			names = append(names, u.Name)
		}
	}
	return sortedUnique(names), ""
}

func checkEmptyPasswords(c *model.Collection, _ model.ScanContext) (bool, string, string) {
	names, skip := emptyPasswords(c)
	if skip != "" {
		return false, "", skip
	}
	if len(names) > 0 {
		return false, "empty password: " + strings.Join(names, ", "), ""
	}
	return true, "every account has a password or is locked", ""
}

func fixEmptyPasswords(c *model.Collection, _ model.ScanContext) string {
	names, _ := emptyPasswords(c)
	return perUser(names, "passwd -l")
}

// systemShells returns system accounts with a login shell, as "name (shell)"
// and bare names. sync, shutdown and halt run their one command as their
// shell by design.
func systemShells(c *model.Collection) (desc, names []string, skip string) {
	us := accounts(c)
	if len(us) == 0 {
		return nil, nil, "no accounts collected"
	}
	for _, u := range us {
		if u.UID <= 0 || u.UID >= 1000 {
			continue
		}
		switch u.Name {
		case "sync", "shutdown", "halt":
			continue
		}
		if strings.HasSuffix(u.Shell, "nologin") || strings.HasSuffix(u.Shell, "false") {
			continue
		}
		desc = append(desc, fmt.Sprintf("%s (%s)", u.Name, u.Shell))
		names = append(names, u.Name)
	}
	return sortedUnique(desc), sortedUnique(names), ""
}

func checkSystemShells(c *model.Collection, _ model.ScanContext) (bool, string, string) {
	desc, _, skip := systemShells(c)
	if skip != "" {
		return false, "", skip
	}
	if len(desc) > 0 {
		return false, "system accounts with a login shell: " + strings.Join(desc, ", "), ""
	}
	return true, "no system account has a login shell", ""
}

func fixSystemShells(c *model.Collection, _ model.ScanContext) string {
	_, names, _ := systemShells(c)
	return perUser(names, "usermod -s /usr/sbin/nologin")
}

func weakHashes(c *model.Collection) (desc, names []string, skip string) {
	if why := shadowMissing(c); why != "" {
		return nil, nil, why
	}
	for _, u := range accounts(c) {
		if !u.Password.Set || u.Password.Algo == "yescrypt" || u.Password.Algo == "sha512" {
			continue
		}
		desc = append(desc, fmt.Sprintf("%s (%s)", u.Name, u.Password.Algo))
		names = append(names, u.Name)
	}
	return sortedUnique(desc), sortedUnique(names), ""
}

func checkHashAlgo(c *model.Collection, _ model.ScanContext) (bool, string, string) {
	desc, _, skip := weakHashes(c)
	if skip != "" {
		return false, "", skip
	}
	if len(desc) > 0 {
		return false, "weak password hash: " + strings.Join(desc, ", "), ""
	}
	return true, "every password hash is yescrypt or SHA-512", ""
}

func fixHashAlgo(c *model.Collection, _ model.ScanContext) string {
	_, names, _ := weakHashes(c)
	if len(names) == 0 {
		return ""
	}
	return andThen(`sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs`, perUser(names, "passwd -e"))
}

// --- sudo ---

var (
	noPasswdRe = regexp.MustCompile(`\bNOPASSWD\s*:`)
	notAuthRe  = regexp.MustCompile(`!\s*authenticate\b`)
)

func sudoFiles(c *model.Collection) []model.PersistFile {
	var out []model.PersistFile
	for _, pf := range c.Persist {
		if pf.Kind == model.PersistKindSudoers {
			out = append(out, pf)
		}
	}
	return out
}

// sudoContent drops a sudoers comment: a line starting with "#" (other than
// #include/#includedir) or a "#" after whitespace that does not start a
// numeric UID/GID such as "#1000".
func sudoContent(line string) string {
	t := strings.TrimSpace(line)
	if strings.HasPrefix(t, "#") && !strings.HasPrefix(t, "#include") {
		return ""
	}
	for i := 1; i < len(t); i++ {
		if t[i] == '#' && (t[i-1] == ' ' || t[i-1] == '\t') && !(i+1 < len(t) && t[i+1] >= '0' && t[i+1] <= '9') {
			return t[:i]
		}
	}
	return t
}

// sudoMatches returns the sudoers files with a non-comment line matching re,
// whether any of them is a symlink, and the first file whose text was not
// kept.
func sudoMatches(c *model.Collection, re *regexp.Regexp) (hits []string, link bool, unknown string) {
	for _, pf := range sudoFiles(c) {
		lines, ok := persistText(pf)
		if !ok {
			if unknown == "" {
				unknown = pf.Path + ": text not kept, cannot be checked"
			}
			continue
		}
		for _, l := range lines {
			if re.MatchString(sudoContent(l)) {
				hits = append(hits, pf.Path)
				link = link || isSymlinkMode(pf.Mode)
				break
			}
		}
	}
	return hits, link, unknown
}

func sudoRuleCheck(re *regexp.Regexp, what string) func(*model.Collection, model.ScanContext) (bool, string, string) {
	return func(c *model.Collection, _ model.ScanContext) (bool, string, string) {
		if len(sudoFiles(c)) == 0 {
			return false, "", "no sudoers files collected"
		}
		hits, _, unknown := sudoMatches(c, re)
		switch {
		case len(hits) > 0:
			return false, what + " in " + strings.Join(hits, ", "), ""
		case unknown != "":
			return false, "", unknown
		}
		return true, "no " + what + " in sudoers", ""
	}
}

func sudoRuleFix(re *regexp.Regexp, script string) func(*model.Collection, model.ScanContext) string {
	return func(c *model.Collection, _ model.ScanContext) string {
		hits, link, _ := sudoMatches(c, re)
		if len(hits) == 0 {
			return ""
		}
		return overPaths(hits, func(q string) string { return "sed -i" + followFlag(link) + " '" + script + "' " + q + " && visudo -c" })
	}
}

// sudoUserList returns the user list that starts a sudoers user spec: the
// first word, continued across spaces after (or before) commas, as in
// "alice, ubuntu ALL=(ALL) ALL".
func sudoUserList(t string) []string {
	f := strings.Fields(t)
	if len(f) == 0 {
		return nil
	}
	list := f[0]
	for i := 1; i < len(f) && (strings.HasSuffix(list, ",") || strings.HasPrefix(f[i], ",")); i++ {
		list += f[i]
	}
	var out []string
	for _, w := range strings.Split(list, ",") {
		if w = strings.TrimSpace(w); w != "" {
			out = append(out, w)
		}
	}
	return out
}

// noPasswdUsers returns the local accounts named on NOPASSWD rules (users,
// and members of %groups) and whether a rule covers ALL users. Negations,
// #uids and aliases are not expanded; root is left out (it needs no sudo).
func noPasswdUsers(c *model.Collection) (users []model.User, all bool) {
	names := map[string]bool{}
	for _, pf := range sudoFiles(c) {
		lines, ok := persistText(pf)
		if !ok {
			continue
		}
		for _, l := range lines {
			t := sudoContent(l)
			if !noPasswdRe.MatchString(t) || strings.HasPrefix(t, "Defaults") {
				continue
			}
			for _, who := range sudoUserList(t) {
				switch {
				case who == "ALL":
					all = true
				case strings.HasPrefix(who, "%"):
					for _, u := range groupMembers(c, strings.TrimPrefix(strings.TrimPrefix(who, "%:"), "%")) {
						names[u] = true
					}
				case who[0] == '!' || who[0] == '#' || isSudoAlias(who):
				default:
					names[who] = true
				}
			}
		}
	}
	for _, u := range accounts(c) {
		if names[u.Name] && u.Name != "root" {
			users = append(users, u)
		}
	}
	return users, all
}

// isSudoAlias reports whether a sudoers name is an alias (upper case,
// digits and underscores, starting with a letter).
func isSudoAlias(s string) bool {
	for i, r := range s {
		if !(r >= 'A' && r <= 'Z' || i > 0 && (r >= '0' && r <= '9' || r == '_')) {
			return false
		}
	}
	return true
}

// groupMembers returns the listed members of group name plus the accounts
// whose primary group it is.
func groupMembers(c *model.Collection, name string) []string {
	var out []string
	for _, g := range c.Accounts.Groups {
		if g.Name != name {
			continue
		}
		out = append(out, g.Members...)
		for _, u := range accounts(c) {
			if u.GID == g.GID {
				out = append(out, u.Name)
			}
		}
	}
	return out
}

// fixNoPasswd turns NOPASSWD into PASSWD, first setting a password for each
// covered account that has none (a cloud image's default user is often
// locked, as is root, and would otherwise lose its only way to root).
func fixNoPasswd(c *model.Collection, ctx model.ScanContext) string {
	base := sudoRuleFix(noPasswdRe, `s/NOPASSWD[[:space:]]*:/PASSWD:/g`)(c, ctx)
	if base == "" {
		return ""
	}
	users, all := noPasswdUsers(c)
	var b strings.Builder
	if all {
		b.WriteString("# a NOPASSWD rule covers ALL users: every user with a locked password must get one before this change\n")
	}
	if shadowMissing(c) != "" {
		var names []string
		for _, u := range users {
			names = append(names, u.Name)
		}
		if len(names) > 0 {
			b.WriteString("# check that " + escapeAll(names) + " can give sudo a password before running this, or nobody may be able to become root\n")
		}
		return b.String() + base
	}
	var need []string
	for _, u := range users {
		if !u.Password.Set || u.Password.Locked {
			need = append(need, u.Name)
		}
	}
	if len(need) == 0 {
		return b.String() + base
	}
	verb := "has"
	if len(need) > 1 {
		verb = "have"
	}
	fmt.Fprintf(&b, "# %s %s no usable password: without NOPASSWD sudo asks for one, so set it first or nobody may be able to become root\n", escapeAll(need), verb)
	return b.String() + andThen(perUser(need, "passwd"), base)
}

func sudoPaths(c *model.Collection) []string {
	var ps []string
	for _, pf := range sudoFiles(c) {
		ps = append(ps, pf.Path)
	}
	return sortedUnique(ps)
}

func checkSudoersFiles(c *model.Collection, _ model.ScanContext) (bool, string, string) {
	paths := sudoPaths(c)
	if len(paths) == 0 {
		return false, "", "no sudoers files collected"
	}
	bad, _, unknown := badModes(c, paths, 0o440)
	switch {
	case len(bad) > 0:
		return false, strings.Join(bad, "; "), ""
	case unknown != "":
		return false, "", unknown
	}
	return true, "all sudoers files 0440 or stricter, owned by root", ""
}

func fixSudoersFiles(c *model.Collection, _ model.ScanContext) string {
	_, paths, _ := badModes(c, sudoPaths(c), 0o440)
	if len(paths) == 0 {
		return ""
	}
	return overPaths(paths, func(q string) string { return "chown root:root " + q + " && chmod 440 " + q })
}

// --- Files ---

// fileModeItem checks that p's permissions are within maxPerm, its owner is
// root, and its group is root or group.
func fileModeItem(id, p string, maxPerm uint32, group, title, why, fix string) Item {
	return Item{
		ID:    id,
		Title: title,
		Why:   why,
		Fix:   fix,
		Check: func(c *model.Collection, _ model.ScanContext) (bool, string, string) {
			e, skip := fileStat(c, p)
			if skip != "" {
				return false, "", skip
			}
			okGroup := e.GID == 0
			if !okGroup && group != "root" {
				gid, known := groupID(c, group)
				if !known {
					return false, "", "group " + group + " is not in the collected groups"
				}
				okGroup = e.GID == gid
			}
			pass := e.Mode&0o7777&^maxPerm == 0 && e.UID == 0 && okGroup
			return pass, describeOwner(c, e, true), ""
		},
	}
}

func worldWritable(c *model.Collection) []string {
	var bad []string
	for _, e := range c.Files {
		if e.Mode&0o002 == 0 {
			continue
		}
		if e.Type == "file" || (e.Type == "dir" && e.Mode&0o1000 == 0) {
			bad = append(bad, e.Path)
		}
	}
	return sortedUnique(bad)
}

func checkWorldWritable(c *model.Collection, _ model.ScanContext) (bool, string, string) {
	if len(c.Files) == 0 {
		return false, "", "no file inventory collected"
	}
	if bad := worldWritable(c); len(bad) > 0 {
		return false, "world-writable: " + listCap(bad, 10), ""
	}
	return true, "no world-writable files or unprotected world-writable directories", ""
}

func fixWorldWritable(c *model.Collection, _ model.ScanContext) string {
	bad := worldWritable(c)
	if len(bad) == 0 || len(bad) > 20 {
		return ""
	}
	return overPaths(bad, func(q string) string { return "chmod o-w " + q })
}

var cronDirs = []string{"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"}

func badCronDirs(c *model.Collection) (bad, paths []string, found bool, unknown string) {
	for _, d := range cronDirs {
		if _, ok := findFile(c, d); !ok {
			continue // not on this machine
		}
		e, why := fileStat(c, d)
		if why != "" {
			if unknown == "" {
				unknown = why
			}
			continue
		}
		found = true
		if e.Mode&0o7777&^0o700 != 0 || e.UID != 0 {
			bad = append(bad, d+" "+describeOwner(c, e, false))
			paths = append(paths, d)
		}
	}
	return bad, paths, found, unknown
}

func checkCronDirs(c *model.Collection, _ model.ScanContext) (bool, string, string) {
	bad, _, found, unknown := badCronDirs(c)
	switch {
	case len(bad) > 0:
		return false, strings.Join(bad, "; "), ""
	case unknown != "":
		return false, "", unknown
	case !found:
		return false, "", "no cron directories in the file inventory"
	}
	return true, "cron directories 0700, owned by root", ""
}

func fixCronDirs(c *model.Collection, _ model.ScanContext) string {
	_, paths, _, _ := badCronDirs(c)
	if len(paths) == 0 {
		return ""
	}
	return overPaths(paths, func(q string) string { return "chmod 700 " + q + " && chown root:root " + q })
}

// --- Firewall ---

// checkFirewall: active means an nftables input chain that drops by default
// or has rules (firewalld-style accept-plus-reject setups count), or ufw
// enabled.
func checkFirewall(c *model.Collection, _ model.ScanContext) (bool, string, string) {
	fw := c.Firewall
	pass := fw.InputPolicy == "drop" || fw.InputRules > 0 || (fw.UFWEnabled != nil && *fw.UFWEnabled)
	if !pass && (fw.Backend == "unknown" || fw.Backend == "") && fw.UFWEnabled == nil {
		return false, "", "could not read firewall state"
	}
	var parts []string
	if fw.Backend == "nftables" {
		policy := fw.InputPolicy
		if policy == "" {
			policy = "none"
		}
		parts = append(parts, fmt.Sprintf("nftables input policy %s, %d input rules", policy, fw.InputRules))
	} else {
		parts = append(parts, "nftables not readable")
	}
	switch {
	case fw.UFWEnabled == nil:
		parts = append(parts, "ufw not configured")
	case *fw.UFWEnabled:
		parts = append(parts, "ufw enabled")
	default:
		parts = append(parts, "ufw disabled")
	}
	return pass, strings.Join(parts, "; "), ""
}

// fixFirewall enables ufw without locking anyone out: it allows every port
// sshd listens on first, and lists the other ports reachable from the network
// for the person to decide on before the firewall goes up.
func fixFirewall(c *model.Collection, _ model.ScanContext) string {
	ssh := sshPorts(c)
	var b strings.Builder
	if other := otherTCPPorts(c, ssh); len(other) > 0 {
		s := make([]string, len(other))
		for i, p := range other {
			s[i] = strconv.Itoa(p)
		}
		fmt.Fprintf(&b, "# also listening on TCP: %s (allow the ones that must stay reachable before enabling)\n", strings.Join(s, ", "))
	}
	if c.Firewall.UFWEnabled == nil {
		b.WriteString("apt-get install -y ufw && ")
	}
	for _, p := range ssh {
		fmt.Fprintf(&b, "ufw allow %d/tcp && ", p)
	}
	b.WriteString("ufw --force enable")
	return b.String()
}

// --- Kernel ---

func equals(want string) func(string) bool { return func(v string) bool { return v == want } }

func atLeastSysctl(n int) func(string) bool {
	return func(v string) bool {
		i, err := strconv.Atoi(v)
		return err == nil && i >= n
	}
}

// sysctlMissing explains why key has no value.
func sysctlMissing(c *model.Collection, key string) string {
	if len(c.Sysctl) == 0 {
		return "no kernel settings collected"
	}
	for _, s := range c.Skipped {
		if strings.HasPrefix(s.Reason, "sysctl "+key+":") {
			return "could not read " + strings.TrimPrefix(s.Reason, "sysctl ")
		}
	}
	return key + " is not present on this kernel"
}

func sysctlItem(id, key, want string, ok func(string) bool, title, why string) Item {
	return Item{
		ID:    id,
		Title: title,
		Why:   why,
		Fix:   fmt.Sprintf("sysctl -w %s=%s && echo '%s = %s' > /etc/sysctl.d/99-telltale-%s.conf", key, want, key, want, key),
		Check: func(c *model.Collection, _ model.ScanContext) (bool, string, string) {
			v, present := c.Sysctl[key]
			if !present {
				return false, "", sysctlMissing(c, key)
			}
			return ok(v), key + " = " + v, ""
		},
	}
}

// --- Services and packages ---

func installed(c *model.Collection, names []string) []string {
	var out []string
	for _, n := range names {
		for _, p := range c.Packages.Installed {
			if p.Name == n {
				out = append(out, n)
				break
			}
		}
	}
	return out
}

func absentItem(id string, pkgs []string, title, why string) Item {
	return Item{
		ID:    id,
		Title: title,
		Why:   why,
		Fix:   "apt-get purge " + pkgs[0],
		Check: func(c *model.Collection, _ model.ScanContext) (bool, string, string) {
			if len(c.Packages.Installed) == 0 {
				return false, "", "no package list collected"
			}
			if got := installed(c, pkgs); len(got) > 0 {
				return false, "installed: " + strings.Join(got, ", "), ""
			}
			return true, "not installed", ""
		},
		fixFor: func(c *model.Collection, _ model.ScanContext) string {
			if got := installed(c, pkgs); len(got) > 0 {
				return "apt-get purge " + strings.Join(got, " ")
			}
			return ""
		},
	}
}

func presentItem(id, pkg, fix, title, why string) Item {
	return Item{
		ID:    id,
		Title: title,
		Why:   why,
		Fix:   fix,
		Check: func(c *model.Collection, _ model.ScanContext) (bool, string, string) {
			if len(c.Packages.Installed) == 0 {
				return false, "", "no package list collected"
			}
			if len(installed(c, []string{pkg})) > 0 {
				return true, pkg + " installed", ""
			}
			return false, pkg + " not installed", ""
		},
	}
}

// checkAppArmor reads /sys/module/apparmor/parameters/enabled, collected as
// apparmor.enabled; the file is absent when the kernel has no AppArmor.
func checkAppArmor(c *model.Collection, _ model.ScanContext) (bool, string, string) {
	v, ok := c.Sysctl["apparmor.enabled"]
	if !ok {
		why := sysctlMissing(c, "apparmor.enabled")
		if !strings.HasSuffix(why, "not present on this kernel") {
			return false, "", why
		}
		return false, "AppArmor is not in the running kernel", ""
	}
	return v == "Y", "AppArmor enabled = " + v, ""
}

// fixAppArmor: when the kernel command line turns AppArmor off, installing
// the package does not help; the boot setting must go (then reboot).
func fixAppArmor(c *model.Collection, _ model.ScanContext) string {
	if strings.Contains(" "+c.Runtime.Cmdline+" ", " apparmor=0 ") {
		return "sed -i 's/[[:space:]]*apparmor=0//g' /etc/default/grub && update-grub"
	}
	return ""
}
