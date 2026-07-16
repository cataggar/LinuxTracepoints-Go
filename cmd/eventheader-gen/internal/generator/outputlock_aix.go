//go:build aix

package generator

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func tryLockFile(file *os.File) (bool, error) {
	lock := unix.Flock_t{
		Type:   unix.F_WRLCK,
		Whence: 0,
		Start:  0,
		Len:    0,
	}
	for {
		err := unix.FcntlFlock(file.Fd(), unix.F_SETLK, &lock)
		if err == nil {
			return true, nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EAGAIN) {
			return false, nil
		}
		return false, err
	}
}

func unlockFile(file *os.File) error {
	lock := unix.Flock_t{
		Type:   unix.F_UNLCK,
		Whence: 0,
		Start:  0,
		Len:    0,
	}
	return unix.FcntlFlock(file.Fd(), unix.F_SETLK, &lock)
}
