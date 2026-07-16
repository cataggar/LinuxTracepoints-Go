//go:build !aix && !android && !darwin && !dragonfly && !freebsd && !illumos && !ios && !linux && !netbsd && !openbsd && !solaris && !windows

package generator

import (
	"errors"
	"os"
)

var errAdvisoryLockUnsupported = errors.New("OS advisory output locks are unsupported on this platform")

func tryLockFile(*os.File) (bool, error) {
	return false, errAdvisoryLockUnsupported
}

func unlockFile(*os.File) error {
	return errAdvisoryLockUnsupported
}
