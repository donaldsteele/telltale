// Package model holds the data types shared by collection, checks, findings,
// snapshots and reports.
package model

import "time"

// Schema versions for the JSON documents written by telltale.
const CollectionSchema, SnapshotSchema, ReportSchema = 1, 1, 1

// Collection is everything gathered from one host in one pass.
type Collection struct {
	Schema    int               `json:"schema"`
	Host      Host              `json:"host"`
	Time      time.Time         `json:"time"`
	AsRoot    bool              `json:"as_root"`
	Skipped   []Skip            `json:"skipped,omitempty"`
	Files     []FileEntry       `json:"files"`
	Accounts  Accounts          `json:"accounts"`
	Persist   []PersistFile     `json:"persist"`
	Runtime   Runtime           `json:"runtime"`
	Packages  Packages          `json:"packages"`
	Firewall  Firewall          `json:"firewall"`
	CrossView []CrossViewResult `json:"cross_view,omitempty"`
	Sysctl    map[string]string `json:"sysctl,omitempty"`
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
}

// Accounts holds local users and groups.
type Accounts struct {
	Users  []User  `json:"users"`
	Groups []Group `json:"groups"`
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
	Set        bool   `json:"set"`
	Locked     bool   `json:"locked"`
	Algo       string `json:"algo"`
	Digest     string `json:"digest"`
	LastChange int    `json:"last_change"`
	MaxDays    int    `json:"max_days"`
}

// Group is one group entry.
type Group struct {
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members"`
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
}

// Runtime is the live state of the machine.
type Runtime struct {
	Processes []Process      `json:"processes"`
	Sockets   []Socket       `json:"sockets"`
	Modules   []KernelModule `json:"modules"`
	Cmdline   string         `json:"cmdline"`
	Mounts    []Mount        `json:"mounts"`
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
	Installed []Package   `json:"installed"`
	Sources   []AptSource `json:"sources"`
}

// Package is one installed dpkg package.
// Conffiles: path -> md5 from dpkg status.
// LocalMD5: path -> md5 from /var/lib/dpkg/info (untrusted).
type Package struct {
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Arch      string            `json:"arch"`
	Status    string            `json:"status"`
	Files     []string          `json:"files"`
	Conffiles map[string]string `json:"conffiles,omitempty"`
	LocalMD5  map[string]string `json:"local_md5,omitempty"`
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
			if _, ok := owners[f]; !ok {
				owners[f] = pkg.Name
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
