// Package model holds the data types shared by collection, checks, findings,
// snapshots and reports.
package model

import (
	"path"
	"strings"
	"time"
)

// Schema versions for the JSON documents written by telltale.
const CollectionSchema, SnapshotSchema, ReportSchema = 1, 1, 1

// Collection is everything gathered from one host in one pass.
type Collection struct {
	Schema  int       `json:"schema"`
	Host    Host      `json:"host"`
	Time    time.Time `json:"time"`
	AsRoot  bool      `json:"as_root"`
	Skipped []Skip    `json:"skipped,omitempty"`
	// SweepIncomplete lists path prefixes where the setuid/capability sweep
	// stopped early, so files under them were not all looked at.
	SweepIncomplete []string          `json:"sweep_incomplete,omitempty"`
	Files           []FileEntry       `json:"files"`
	Accounts        Accounts          `json:"accounts"`
	Persist         []PersistFile     `json:"persist"`
	Runtime         Runtime           `json:"runtime"`
	Packages        Packages          `json:"packages"`
	Firewall        Firewall          `json:"firewall"`
	CrossView       []CrossViewResult `json:"cross_view,omitempty"`
	Sysctl          map[string]string `json:"sysctl,omitempty"`
	// LinkerCache lists every file the dynamic linker's cache
	// (/etc/ld.so.cache) sends programs to, sorted; nil when there is no
	// cache or it could not be parsed.
	LinkerCache []string `json:"linker_cache,omitempty"`
}

// Host identifies the machine a collection came from.
type Host struct {
	Hostname    string `json:"hostname"`
	OSID        string `json:"os_id"`
	OSVersionID string `json:"os_version_id"`
	OSPretty    string `json:"os_pretty"`
	Arch        string `json:"arch"`
	Kernel      string `json:"kernel"`
}

// Skip records a check that could not run and why.
type Skip struct {
	Check  string `json:"check"`
	Reason string `json:"reason"`
}

// SkipCheckSSHDConfig is the Skip.Check of a part of the sshd configuration
// the collector could not read or follow (an unreadable file, Include nested
// deeper than sshd allows). The collected configuration is then incomplete
// and must not be judged.
const SkipCheckSSHDConfig = "sshd_config"

// SkipCheckModules is the Skip.Check of the loaded kernel modules when they
// were not examined (see Runtime.SharedKernel).
const SkipCheckModules = "modules"

// SkipCheckLinkerCache is the Skip.Check of a dynamic linker cache that could
// not be read (see Collection.LinkerCache).
const SkipCheckLinkerCache = "linker_cache"

// FileEntry describes one path that was stat'ed during collection.
// Type: file|dir|symlink|other. Caps: hex of security.capability or "".
// Flags: inode flags from FS_IOC_GETFLAGS.
type FileEntry struct {
	Path   string    `json:"path"`
	Type   string    `json:"type"`
	Target string    `json:"target"`
	SHA256 string    `json:"sha256"`
	Caps   string    `json:"caps"`
	Err    string    `json:"err"`
	Mode   uint32    `json:"mode"`
	UID    uint32    `json:"uid"`
	GID    uint32    `json:"gid"`
	Flags  uint32    `json:"flags"`
	Size   int64     `json:"size"`
	MTime  time.Time `json:"mtime"`
	CTime  time.Time `json:"ctime"`
	// Supplementary marks an entry added outside the file scan (the file a
	// deleted program was started from, the target of a startup link). It
	// exists only while something refers to it, so a snapshot comparison
	// never reports it as added or removed.
	Supplementary bool `json:"supplementary,omitempty"`
	// Swept marks an entry found by the setuid/capability sweep rather than the
	// system-path walk. The sweep can stop early, so a one-sided swept entry
	// under Collection.SweepIncomplete is not evidence of a change.
	Swept bool   `json:"swept,omitempty"`
	MD5   string `json:"md5,omitempty"` // only for supplementary entries
}

// Accounts holds local users and groups, read the way glibc's files
// backend reads them: the first line for a name is the one that counts.
// Duplicates lists "<file>:<name>" for every name that appears on more than
// one line; Malformed lists "<file>:<line number>" for every line glibc
// would reject (never the line's content, which may hold a password hash).
type Accounts struct {
	Users      []User   `json:"users"`
	Groups     []Group  `json:"groups"`
	Duplicates []string `json:"duplicates,omitempty"`
	Malformed  []string `json:"malformed,omitempty"`
}

// User is one passwd entry plus its password state.
type User struct {
	Name     string        `json:"name"`
	UID      int           `json:"uid"`
	GID      int           `json:"gid"`
	Home     string        `json:"home"`
	Shell    string        `json:"shell"`
	Password PasswordState `json:"password"`
}

// PasswordState describes the shadow entry for a user. Digest is kept for
// comparison only.
type PasswordState struct {
	// Known is true when the state was decided from a readable passwd field
	// or a shadow row; false when it could not be determined.
	Known      bool   `json:"known"`
	Set        bool   `json:"set"`
	Locked     bool   `json:"locked"`
	Algo       string `json:"algo"`
	Digest     string `json:"digest"`
	LastChange int    `json:"last_change"`
	MaxDays    int    `json:"max_days"`
}

// Group is one group entry. Shadow is its /etc/gshadow entry, nil when
// gshadow was not read.
type Group struct {
	Name    string       `json:"name"`
	GID     int          `json:"gid"`
	Members []string     `json:"members"`
	Shadow  *GroupShadow `json:"shadow,omitempty"`
}

// GroupShadow is a group's /etc/gshadow entry without the password hash:
// whether a usable group password is set, the group administrators and the
// members listed there. A group with no gshadow line has the zero value.
type GroupShadow struct {
	PasswordSet bool     `json:"password_set"`
	Admins      []string `json:"admins,omitempty"`
	Members     []string `json:"members,omitempty"`
}

// Persistence location kinds (values of PersistFile.Kind).
const (
	PersistKindSudoers        = "sudoers"
	PersistKindSSHD           = "sshd"
	PersistKindSSHClient      = "sshclient"
	PersistKindAuthorizedKeys = "authorized_keys"
	PersistKindCron           = "cron"
	PersistKindAt             = "at"
	PersistKindSystemdUnit    = "systemd_unit"
	PersistKindSystemdEnabled = "systemd_enabled"
	PersistKindRC             = "rc"
	PersistKindProfile        = "profile"
	PersistKindShellRC        = "shellrc"
	PersistKindLDPreload      = "ld_preload"
	PersistKindLDConf         = "ld_conf"
	PersistKindPAM            = "pam"
	PersistKindHosts          = "hosts"
	PersistKindResolver       = "resolver"
	PersistKindModulesLoad    = "modules_load"
	PersistKindModprobe       = "modprobe"
)

// PersistFile is a persistence-relevant file, stored as redacted text lines.
type PersistFile struct {
	Path       string    `json:"path"`
	Kind       string    `json:"kind"`
	SHA256     string    `json:"sha256"`
	Lines      []string  `json:"lines"`
	Redactions int       `json:"redactions"`
	Mode       uint32    `json:"mode"`
	UID        uint32    `json:"uid"`
	MTime      time.Time `json:"mtime"`
	// Signals are callback or download-and-run commands found in the raw text
	// before redaction: pattern ids and line numbers only, never the text.
	Signals []PersistSignal `json:"signals,omitempty"`
}

// Runtime is the live state of the machine.
type Runtime struct {
	Processes []Process      `json:"processes"`
	Sockets   []Socket       `json:"sockets"`
	Modules   []KernelModule `json:"modules"`
	// SharedKernel is true when the machine is a container: the kernel and
	// its modules belong to the host, so Modules is left empty.
	SharedKernel bool    `json:"shared_kernel,omitempty"`
	Cmdline      string  `json:"cmdline"`
	Mounts       []Mount `json:"mounts"`
}

// Process is one running process as seen through /proc.
type Process struct {
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	UID        int    `json:"uid"`
	Exe        string `json:"exe"`
	ExeSHA256  string `json:"exe_sha256"`
	Cmdline    string `json:"cmdline"`
	Comm       string `json:"comm"`
	ExeDeleted bool   `json:"exe_deleted"`
	// Started is when the process began (zero when unknown).
	Started time.Time `json:"started,omitempty"`
}

// Socket is one open network socket.
type Socket struct {
	Proto     string `json:"proto"`
	Local     string `json:"local"`
	Remote    string `json:"remote"`
	State     string `json:"state"`
	Inode     uint64 `json:"inode"`
	PID       int    `json:"pid"`
	Listening bool   `json:"listening"`
}

// KernelModule is one loaded kernel module. File is the path under
// /lib/modules if found, else "".
type KernelModule struct {
	Name  string `json:"name"`
	File  string `json:"file"`
	Taint string `json:"taint"`
	Size  int    `json:"size"`
}

// Mount is one mounted filesystem.
type Mount struct {
	Path    string `json:"path"`
	FSType  string `json:"fstype"`
	Options string `json:"options"`
	Source  string `json:"source"`
}

// Packages holds the dpkg view of the machine.
type Packages struct {
	Installed []Package `json:"installed"`
	// Residual lists packages that were removed but not purged (dpkg state
	// config-files): name, version, architecture and status only. Their
	// files are gone, but dpkg keeps their postrm script and runs it on purge.
	Residual []Package   `json:"residual,omitempty"`
	Sources  []AptSource `json:"sources"`
	// Diversions come from /var/lib/dpkg/diversions.
	Diversions []Diversion `json:"diversions,omitempty"`
	// StatOverrides come from /var/lib/dpkg/statoverride.
	StatOverrides []StatOverride `json:"stat_overrides,omitempty"`
}

// Package is one installed dpkg package.
// Conffiles: path -> md5 from dpkg status.
// LocalMD5: path -> md5 from /var/lib/dpkg/info (untrusted).
// ObsoleteConffiles: conffiles dpkg status marks obsolete, still on disk
// but no longer shipped by the installed version.
type Package struct {
	Name              string            `json:"name"`
	Version           string            `json:"version"`
	Arch              string            `json:"arch"`
	Status            string            `json:"status"`
	Files             []string          `json:"files"`
	Conffiles         map[string]string `json:"conffiles,omitempty"`
	LocalMD5          map[string]string `json:"local_md5,omitempty"`
	ObsoleteConffiles []string          `json:"obsolete_conffiles,omitempty"`
}

// LocalDiversion is the Diversion.Package of a diversion an administrator
// made with dpkg-divert --local.
const LocalDiversion = ":"

// Diversion is one dpkg-divert entry: every package except Package installs
// its file Path at DivertTo instead. Package is LocalDiversion when the
// diversion applies to every package.
type Diversion struct {
	Path     string `json:"path"`
	DivertTo string `json:"divert_to"`
	Package  string `json:"package"`
}

// StatOverride is one dpkg-statoverride entry: dpkg gives Path this owner,
// group and mode instead of the package's. Owner and Group are names or
// "#<id>".
type StatOverride struct {
	Path  string `json:"path"`
	Owner string `json:"owner"`
	Group string `json:"group"`
	Mode  uint32 `json:"mode"`
}

// AptSource is one apt source entry.
type AptSource struct {
	File       string   `json:"file"`
	SignedBy   string   `json:"signed_by"`
	Types      []string `json:"types"`
	URIs       []string `json:"uris"`
	Suites     []string `json:"suites"`
	Components []string `json:"components"`
}

// Owners returns path -> package name for every path in every installed
// package's Files. When two packages list the same path, the first in
// Installed order wins.
func (p Packages) Owners() map[string]string {
	owners := make(map[string]string)
	for _, pkg := range p.Installed {
		for _, f := range pkg.Files {
			for _, a := range append([]string{f}, usrAlias(f)...) {
				if _, ok := owners[a]; !ok {
					owners[a] = pkg.Name
				}
			}
		}
	}
	return owners
}

// Firewall summarises the packet filter state.
// UFWEnabled is nil when unknown.
type Firewall struct {
	Backend     string `json:"backend"`
	InputPolicy string `json:"input_policy"`
	Tables      int    `json:"tables"`
	Rules       int    `json:"rules"`
	InputRules  int    `json:"input_rules"`
	UFWEnabled  *bool  `json:"ufw_enabled,omitempty"`
}

// CrossViewResult compares one tool's view of processes or files with another
// view, listing items hidden from the tool and items only the tool shows.
type CrossViewResult struct {
	Tool           string   `json:"tool"`
	Ran            bool     `json:"ran"`
	SkipReason     string   `json:"skip_reason"`
	HiddenFromTool []string `json:"hidden_from_tool"`
	ExtraInTool    []string `json:"extra_in_tool"`
}

var mergedDirs = []string{"bin", "sbin", "lib", "lib32", "lib64", "libx32"}

// usrAlias returns the other spelling of a path on merged-/usr systems,
// where /bin is /usr/bin and so on.
func usrAlias(f string) []string {
	for _, d := range mergedDirs {
		if strings.HasPrefix(f, "/"+d+"/") {
			return []string{"/usr" + f}
		}
		if strings.HasPrefix(f, "/usr/"+d+"/") {
			return []string{strings.TrimPrefix(f, "/usr")}
		}
	}
	return nil
}

// LinkTarget returns the cleaned absolute target of a collected symlink (a
// relative target is resolved against the link's directory). ok is false for
// entries that are not symlinks or have no target.
func (p PersistFile) LinkTarget() (target string, ok bool) {
	if p.Mode&0o170000 != 0o120000 || len(p.Lines) == 0 {
		return "", false
	}
	target = p.Lines[0] // exactly as the kernel reads it: no trimming
	if target == "" {
		return "", false
	}
	if !path.IsAbs(target) {
		target = path.Join(path.Dir(p.Path), target)
	}
	return path.Clean(target), true
}

// TargetRedacted reports whether the link's target text had a secret-like
// part replaced by a digest marker: it is then not the text the link holds
// and must not be resolved.
func (p PersistFile) TargetRedacted() bool {
	return len(p.Lines) > 0 && strings.Contains(p.Lines[0], "<redacted ")
}

// PersistSignal marks one command in a persistence file that matched a
// callback or download-and-run pattern. Line is the first physical line of
// the command (1-based); Pattern is a persistsig id.
type PersistSignal struct {
	Line    int    `json:"line"`
	Pattern string `json:"pattern"`
}
