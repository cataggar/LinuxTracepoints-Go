//go:build linux

package generator

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

func replaceExistingOutput(
	tempName string,
	initial outputState,
	hooks *replacementHooks,
) (preserveTemp bool, err error) {
	staged, err := readOutputState(tempName)
	if err != nil {
		return false, err
	}
	if hooks != nil && hooks.beforeCommit != nil {
		hooks.beforeCommit()
	}
	if err := exchangeOutputPaths(tempName, initial.path); err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) ||
			errors.Is(err, unix.EOPNOTSUPP) {
			return false, fmt.Errorf(
				"refusing to replace existing output %q: atomic path exchange is unavailable: %w",
				initial.path, err)
		}
		return false, fmt.Errorf("atomically exchange generated output %q: %w", initial.path, err)
	}
	if hooks != nil && hooks.afterCommit != nil {
		hooks.afterCommit()
	}

	previous, err := readOutputState(tempName)
	if err != nil {
		return true, fmt.Errorf("inspect exchanged prior output %q (preserved at %q): %w",
			initial.path, tempName, err)
	}
	if sameOutputState(initial, previous) {
		return false, nil
	}

	current, err := readOutputState(initial.path)
	if err != nil {
		return true, fmt.Errorf("%w; prior output preserved at %q: %v",
			concurrentModificationError(initial.path), tempName, err)
	}
	if !sameOutputState(staged, current) {
		return false, concurrentModificationError(initial.path)
	}
	if err := exchangeOutputPaths(tempName, initial.path); err != nil {
		return true, fmt.Errorf("%w; restore prior output from %q: %v",
			concurrentModificationError(initial.path), tempName, err)
	}

	restored, restoreErr := readOutputState(initial.path)
	displaced, displacedErr := readOutputState(tempName)
	if restoreErr == nil && displacedErr == nil &&
		sameOutputState(previous, restored) && sameOutputState(staged, displaced) {
		return false, concurrentModificationError(initial.path)
	}

	// A path replacement raced with the rollback. If the rollback displaced that
	// newer path, exchange it back rather than leaving it clobbered.
	if restoreErr == nil && displacedErr == nil && sameOutputState(previous, restored) {
		if exchangeErr := exchangeOutputPaths(tempName, initial.path); exchangeErr == nil {
			return false, concurrentModificationError(initial.path)
		}
	}
	return true, fmt.Errorf("%w; rollback could not be verified (recovery file %q)",
		concurrentModificationError(initial.path), tempName)
}

func exchangeOutputPaths(left, right string) error {
	return unix.Renameat2(
		unix.AT_FDCWD, left,
		unix.AT_FDCWD, right,
		unix.RENAME_EXCHANGE,
	)
}
