//go:build !windows

package security

import (
	"syscall"

	"ssrok/internal/constants"
)

func (al *AuditLogger) hasEnoughDiskSpace() bool {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(al.logDir, &stat); err != nil {
		return true
	}

	available := stat.Bavail * uint64(stat.Bsize)
	return int64(available) > constants.MinDiskSpaceRequired
}
