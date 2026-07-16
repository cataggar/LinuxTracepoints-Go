//go:build windows

package generator

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

const allLockBytes = ^uint32(0)

func tryLockFile(file *os.File) (bool, error) {
	overlapped := new(windows.Overlapped)
	err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, allLockBytes, allLockBytes, overlapped,
	)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return false, nil
	}
	return false, err
}

func unlockFile(file *os.File) error {
	return windows.UnlockFileEx(
		windows.Handle(file.Fd()), 0, allLockBytes, allLockBytes, new(windows.Overlapped),
	)
}
