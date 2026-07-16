package generator

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const outputLockTimeout = 10 * time.Second

var errOutputLockTimeout = errors.New("timed out waiting for output lock")

func acquireOutputLock(output string) (func(), error) {
	return acquireOutputLockTimeout(output, outputLockTimeout)
}

func acquireOutputLockTimeout(output string, timeout time.Duration) (func(), error) {
	lockPath := filepath.Join(filepath.Dir(output), "."+filepath.Base(output)+".lock")
	lock, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("lock output %q: %w", output, err)
	}
	deadline := time.Now().Add(timeout)
	for {
		acquired, err := tryLockFile(lock)
		if err != nil {
			lock.Close()
			return nil, fmt.Errorf("lock output %q: %w", output, err)
		}
		if acquired {
			return func() {
				_ = unlockFile(lock)
				_ = lock.Close()
			}, nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			lock.Close()
			return nil, fmt.Errorf("%w for %q after %s", errOutputLockTimeout, output, timeout)
		}
		delay := 10 * time.Millisecond
		if remaining < delay {
			delay = remaining
		}
		timer := time.NewTimer(delay)
		<-timer.C
	}
}
