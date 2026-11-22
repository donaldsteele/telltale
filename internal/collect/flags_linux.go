package collect

import (
	"encoding/hex"
	"errors"

	"golang.org/x/sys/unix"
)

// inodeFlags returns the FS_IOC_GETFLAGS value for an open descriptor, or 0
// when the filesystem does not support it.
func inodeFlags(fd int) uint32 {
	f, err := unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS)
	if err != nil {
		return 0
	}
	return f
}

// fileCaps returns the hex of the security.capability xattr, or "" when absent
// or unreadable.
func fileCaps(path string) string {
	buf := make([]byte, 64)
	for {
		n, err := unix.Lgetxattr(path, "security.capability", buf)
		if errors.Is(err, unix.ERANGE) {
			buf = make([]byte, len(buf)*4)
			continue
		}
		if err != nil || n <= 0 {
			return ""
		}
		return hex.EncodeToString(buf[:n])
	}
}
