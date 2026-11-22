package collect

import (
	"errors"

	"golang.org/x/sys/unix"
)

// errKernelFS is returned when a path that someone else chose leads, through
// any symlink on the way, into a kernel pseudo-filesystem. Reading such a
// file can consume (kmsg, trace_pipe) or block, so it is never read.
var errKernelFS = errors.New("kernel pseudo-filesystem, not read")

// fstatfsFn is unix.Fstatfs; tests replace it.
var fstatfsFn = unix.Fstatfs

// Filesystem magic numbers x/sys does not define.
const (
	configfsMagic = 0x62656570
	mqueueMagic   = 0x19800202
)

var kernelFSMagic = map[uint32]bool{
	unix.PROC_SUPER_MAGIC:    true,
	unix.SYSFS_MAGIC:         true,
	unix.DEBUGFS_MAGIC:       true,
	unix.TRACEFS_MAGIC:       true,
	unix.SECURITYFS_MAGIC:    true,
	configfsMagic:            true,
	unix.CGROUP_SUPER_MAGIC:  true,
	unix.CGROUP2_SUPER_MAGIC: true,
	unix.BPF_FS_MAGIC:        true,
	unix.PSTOREFS_MAGIC:      true,
	unix.EFIVARFS_MAGIC:      true,
	unix.DEVPTS_SUPER_MAGIC:  true,
	mqueueMagic:              true,
	unix.BINFMTFS_MAGIC:      true,
}

// kernelFS reports whether the open descriptor is on a kernel pseudo-
// filesystem. A descriptor whose filesystem cannot be determined is refused.
func kernelFS(fd int) bool {
	var st unix.Statfs_t
	if err := fstatfsFn(fd, &st); err != nil {
		return true
	}
	return kernelFSMagic[uint32(st.Type)]
}
