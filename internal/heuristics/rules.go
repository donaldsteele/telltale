package heuristics

import "github.com/donaldsteele/telltale/internal/model"

// Rule describes one kind of finding the heuristics give, for the
// documentation: docs/checks.md is generated from Rules by tools/docgen.
// The tests hold the list to the code: every finding key the package can
// make has a rule, every rule's key is made, and a finding's ID and
// severity are those of its rule.
type Rule struct {
	ID       string           // TT-HEUR-...; one ID can cover several keys
	Key      string           // the start of the finding key, e.g. "heur.uid0:"
	Severity model.Severity   // the severity it usually has
	Other    []model.Severity // other severities it can have, explained in When
	Title    string           // what it flags
	Why      string           // why it matters
	When     string           // when the severity differs, or ""
}

// Rules returns every rule, in ID order.
func Rules() []Rule {
	return []Rule{
		{ID: idUID0, Key: "heur.uid0:", Severity: model.SevBackdoor,
			Title: "An account other than root has user id 0",
			Why:   "User id 0 is root, whatever the account is called. A second account with id 0 is a classic hidden way back in: it logs in as root under another name."},
		{ID: idEmptyPass, Key: "heur.empty_password:", Severity: model.SevWeak,
			Title: "An account has an empty password",
			Why:   "Wherever password logins are allowed, anyone can log in as that account without knowing anything. Shown only when the password could be read, which usually needs root."},
		{ID: idSystemShell, Key: "heur.system_shell:", Severity: model.SevNote,
			Title: "A system account has a login shell",
			Why:   "Accounts that run services should not be able to log in. A shell on one can be a quiet way back in."},
		{ID: idLDPreload, Key: "heur.ld_preload", Severity: model.SevBackdoor,
			Title: "/etc/ld.so.preload exists",
			Why:   "Every program on the machine loads the libraries it lists. Userland rootkits use it to hide files, processes and connections from the machine's own tools."},
		{ID: idProcExe, Key: "heur.proc_exe:", Severity: model.SevBackdoor, Other: []model.Severity{model.SevNote},
			Title: "A program runs from a temporary or hidden place, or was deleted while running",
			Why:   "Software that belongs on a machine is installed in system directories and stays on disk. Programs running from /tmp, /var/tmp, /dev/shm, a hidden directory or a deleted file are typical of malware.",
			When:  "A note when the program sits in a hidden directory in its own user's home (developer tools such as ~/.vscode-server do that); a backdoor sign everywhere else."},
		{ID: idProcExe, Key: "heur.stale_exe:", Severity: model.SevNote,
			Title: "A program still runs the version from before a package upgrade",
			Why:   "Its file was replaced by an upgrade while it ran: the deleted file was the old version, and the file now at that path belongs to a package and is newer than the process. Restart it to run the new version."},
		{ID: idForcedCmd, Key: "heur.forced_command", Severity: model.SevBackdoor,
			Title: "An SSH key forces a command",
			Why:   "A command= option in authorized_keys runs a fixed program on every login with that key. It can hide a backdoor behind a key that looks harmless. The telltale server's own key is recognised and never reported."},
		{ID: idRootKey, Key: "heur.root_key", Severity: model.SevNote,
			Title: "A key lets root log in over SSH",
			Why:   "Listed so you can check every key that gives root access. The telltale server's own key is recognised. With a snapshot these notes are left out, and keys added since the snapshot are reported from the comparison instead, as backdoor signs."},
		{ID: idSetuid, Key: "heur.unowned_setuid:", Severity: model.SevBackdoor, Other: []model.Severity{model.SevNote},
			Title: "A setuid or setgid program belongs to no package",
			Why:   "A setuid program runs with its owner's rights, often root's, whoever starts it. One that no package installed may be a planted root shell.",
			When:  "A note under /usr/local, where people install their own programs."},
		{ID: idSetuid, Key: "heur.unowned_caps:", Severity: model.SevBackdoor, Other: []model.Severity{model.SevNote},
			Title: "A program with file capabilities belongs to no package",
			Why:   "File capabilities give a program part of root's power (reading any file, raw network access) without the setuid bit. One that no package installed may be a planted way to escalate.",
			When:  "A note under /usr/local."},
		{ID: idSetuid, Key: "heur.setuid_packaged_copy:", Severity: model.SevNote,
			Title: "An exact copy of a package's setuid program sits elsewhere",
			Why:   "It grants nothing the original does not, but check that you made the copy."},
		{ID: idImmutable, Key: "heur.immutable:", Severity: model.SevBackdoor,
			Title: "A file is marked immutable or append-only",
			Why:   "These flags stop even root from changing or deleting a file. Attackers set them to protect a backdoor from removal; ordinary systems rarely set them on system files."},
		{ID: idModule, Key: "heur.module:", Severity: model.SevBackdoor,
			Title: "A loaded kernel module comes from no installed package",
			Why:   "Code in the kernel can hide anything from anything running on the machine. Modules built locally (DKMS drivers, for example) also show here; accept them once you have checked them."},
		{ID: idListener, Key: "heur.unowned_listener:", Severity: model.SevNote,
			Title: "A program that no package installed listens on a port",
			Why:   "A backdoor often waits for connections. Listed so you can check each one; ports of the same program are grouped."},
		{ID: idCrossView, Key: "heur.crossview:", Severity: model.SevTampering,
			Title: "The machine's own tools hide something telltale can see",
			Why:   "telltale reads /proc, /proc/net and the filesystem itself and compares what it finds with what ps, ss, ls and lsmod print. A process, port, file or module that it sees and a tool leaves out is strong evidence of a rootkit."},
		{ID: idPersistLink, Key: "heur.persist_link:", Severity: model.SevBackdoor, Other: []model.Severity{model.SevWeak},
			Title: "A startup link leads outside the system directories",
			Why:   "A cron job, systemd unit or other startup file that is a symbolic link into /tmp, a home or another place outside /usr, /lib and /etc runs whatever is put there. Linking a unit in from /var/tmp is a known trick. Links are followed as the kernel follows them, not as their text reads.",
			When:  "A weak setting when the link masks a security service (auditd, AppArmor, ufw, nftables, fail2ban) by pointing it at /dev/null."},
		{ID: idPersistLink, Key: "heur.persist_link_pkg:", Severity: model.SevNote,
			Title: "A startup link runs a package's own file outside the system directories",
			Why:   "Some vendors do this (Chrome links a daily cron job into /opt). The file it runs is still checked against its package, and a file that does not match is reported on its own."},
		{ID: idPersistLink, Key: "heur.persist_link_dangling:", Severity: model.SevNote,
			Title: "A startup link points at a file that does not exist",
			Why:   "Nothing runs now, but whoever can create the missing file decides what runs next."},
		{ID: idPersistLink, Key: "heur.user_unit:", Severity: model.SevNote,
			Title: "A user's own systemd unit starts at login",
			Why:   "Enabled with systemctl --user. Listed with the command it runs, so you can check it; its contents are judged like any other startup file."},
		{ID: idDiversion, Key: "heur.local_diversion:", Severity: model.SevBackdoor, Other: []model.Severity{model.SevNote},
			Title: "A system file is diverted by hand, or by a package that is not installed",
			Why:   "A dpkg diversion makes package updates install their copy of a file under another name, so the file at the original path is never replaced and is not the packaged one. It is a way to keep a replaced system program in place.",
			When:  "A note for exactly the diversions Ubuntu's own minimised images make (/usr/bin/man and /sbin/initctl), on Ubuntu."},
		{ID: idPersistCallback, Key: "heur.persist_callback:", Severity: model.SevBackdoor,
			Title: "A startup file connects out, or downloads code and runs it",
			Why:   "A cron job, unit, shell start-up file or similar that opens a reverse shell (/dev/tcp, nc -e, socat exec:, a scripting one-liner) or pipes a download into a shell is the commonest persistence there is. Accepting it covers only the lines seen; a new matching line is a finding again."},
		{ID: idPAM, Key: "heur.pam_unowned:", Severity: model.SevBackdoor,
			Title: "A PAM module used at login belongs to no package",
			Why:   "PAM modules run inside every login and see every password typed. One that no package installed may record passwords or let a secret password in."},
		{ID: idPAM, Key: "heur.pam_path_escape:", Severity: model.SevBackdoor,
			Title: "A PAM module name climbs out of the module directory",
			Why:   "A name with .. in it makes PAM load a library from somewhere else, where no package check looks."},
		{ID: idPAM, Key: "heur.pam_missing:", Severity: model.SevNote,
			Title: "The PAM configuration names a module that is not on the machine",
			Why:   "Usually left over from a removed package. Whoever can create the file decides what runs at login."},
		{ID: idFlooded, Key: "heur.persist_flooded:", Severity: model.SevNote,
			Title: "A user's systemd unit directory holds more than telltale reads",
			Why:   "Anyone can fill their own unit directory. telltale reads at most 2,000 entries and 8 MiB of text from one user's directory, and 64 MiB from all users' together, so that no user can make a scan run out of memory or time. What lies past that was not read, and a unit hidden there was not seen. Thousands of files in such a directory are themselves unusual: look at what fills it."},
	}
}
