//go:build windows

package security

import (
	"golang.org/x/sys/windows"

	"ssrok/internal/constants"
)

func (al *AuditLogger) hasEnoughDiskSpace() bool {
	pathPtr, err := windows.UTF16PtrFromString(al.logDir)
	if err != nil {
		return true
	}

	var freeBytes uint64
	if err := windows.GetDiskFreeSpaceEx(pathPtr, &freeBytes, nil, nil); err != nil {
		return true
	}

	return int64(freeBytes) > constants.MinDiskSpaceRequired
}
