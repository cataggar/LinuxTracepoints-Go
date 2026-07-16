//go:build !linux && !windows

package generator

import "fmt"

func replaceExistingOutput(
	tempName string,
	initial outputState,
	hooks *replacementHooks,
) (preserveTemp bool, err error) {
	if hooks != nil && hooks.beforeCommit != nil {
		hooks.beforeCommit()
	}
	current, readErr := readOutputState(initial.path)
	if readErr != nil {
		return false, readErr
	}
	if !sameOutputState(initial, current) {
		return false, concurrentModificationError(initial.path)
	}
	return false, fmt.Errorf(
		"refusing to replace existing output %q: this platform has no atomic conditional replacement primitive",
		initial.path,
	)
}
