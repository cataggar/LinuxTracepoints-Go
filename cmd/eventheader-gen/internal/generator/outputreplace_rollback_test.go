package generator

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestRollbackReplaceFileRemovesVerifiedGeneratedState(t *testing.T) {
	seam := newReplaceFileRollbackSeam("generated", "prior")

	err := seam.rollback()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(seam.files[seam.target].data); got != "prior" {
		t.Fatalf("target state = %q, want prior state", got)
	}
	if len(seam.removed) != 1 || string(seam.removed[0].actual.data) != "generated" {
		t.Fatalf("removed states = %v, want only generated state", seam.removed)
	}
	seam.assertOnlyVerifiedStatesRemoved(t)
}

func TestRollbackReplaceFileRestoresLateReplacement(t *testing.T) {
	seam := newReplaceFileRollbackSeam("generated", "prior", "newer")

	err := seam.rollback()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(seam.files[seam.target].data); got != "newer" {
		t.Fatalf("target state = %q, want newest replacement", got)
	}
	seam.assertOnlyVerifiedStatesRemoved(t)
}

func TestRollbackReplaceFileRestoresRepeatedLateReplacements(t *testing.T) {
	seam := newReplaceFileRollbackSeam("generated", "prior", "newer-1", "newer-2", "newer-3")

	err := seam.rollback()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(seam.files[seam.target].data); got != "newer-3" {
		t.Fatalf("target state = %q, want newest replacement", got)
	}
	seam.assertOnlyVerifiedStatesRemoved(t)
}

func TestRollbackReplaceFileExhaustionPreservesRecovery(t *testing.T) {
	races := make([]string, replaceFileRollbackRaceLimit)
	for index := range races {
		races[index] = fmt.Sprintf("newer-%d", index+1)
	}
	seam := newReplaceFileRollbackSeam("generated", "prior", races...)

	err := seam.rollback()
	if err == nil ||
		!strings.Contains(err.Error(), "concurrent modification") ||
		!strings.Contains(err.Error(), "rollback exhausted") ||
		!strings.Contains(err.Error(), "preserved recovery paths") {
		t.Fatalf("rollback error = %v, want explicit exhaustion with recovery paths", err)
	}
	lastRecovery := fmt.Sprintf("%s.recovery-%d", seam.temp, replaceFileRollbackRaceLimit-1)
	if got := string(seam.files[lastRecovery].data); got != races[len(races)-1] {
		t.Fatalf("preserved recovery state = %q, want %q", got, races[len(races)-1])
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%q", lastRecovery)) {
		t.Fatalf("rollback error %q does not list %q", err, lastRecovery)
	}
	seam.assertOnlyVerifiedStatesRemoved(t)
}

type replaceFileRollbackSeam struct {
	files    map[string]outputState
	races    []outputState
	removed  []removedRollbackState
	replaces int
	temp     string
	target   string
	backup   string
}

type removedRollbackState struct {
	actual   outputState
	expected outputState
}

func newReplaceFileRollbackSeam(generated, prior string, races ...string) *replaceFileRollbackSeam {
	seam := &replaceFileRollbackSeam{
		files:  make(map[string]outputState),
		temp:   "output.tmp",
		target: "output.go",
		backup: "output.tmp.previous",
	}
	seam.files[seam.target] = rollbackTestState(generated)
	seam.files[seam.backup] = rollbackTestState(prior)
	for _, race := range races {
		seam.races = append(seam.races, rollbackTestState(race))
	}
	return seam
}

func (seam *replaceFileRollbackSeam) rollback() error {
	return rollbackReplaceFile(
		seam.temp,
		seam.target,
		seam.backup,
		seam.files[seam.target],
		seam.files[seam.backup],
		replaceFileRollbackOps{
			replace:        seam.replace,
			read:           seam.read,
			same:           sameRollbackTestState,
			removeVerified: seam.removeVerified,
		},
	)
}

func (seam *replaceFileRollbackSeam) replace(target, replacement, backup string) error {
	replacementState, ok := seam.files[replacement]
	if !ok {
		return fmt.Errorf("replacement %q is missing", replacement)
	}
	if seam.replaces < len(seam.races) {
		seam.files[target] = seam.races[seam.replaces]
	}
	targetState, ok := seam.files[target]
	if !ok {
		return errors.New("target is missing")
	}
	seam.replaces++
	seam.files[target] = replacementState
	delete(seam.files, replacement)
	seam.files[backup] = targetState
	return nil
}

func (seam *replaceFileRollbackSeam) read(path string) (outputState, error) {
	state, ok := seam.files[path]
	if !ok {
		return outputState{}, fmt.Errorf("%q is missing", path)
	}
	return state, nil
}

func (seam *replaceFileRollbackSeam) removeVerified(path string, expected outputState) error {
	actual, err := seam.read(path)
	if err != nil {
		return err
	}
	seam.removed = append(seam.removed, removedRollbackState{actual: actual, expected: expected})
	if !sameRollbackTestState(actual, expected) {
		return errors.New("attempted to remove an unverified state")
	}
	delete(seam.files, path)
	return nil
}

func (seam *replaceFileRollbackSeam) assertOnlyVerifiedStatesRemoved(t *testing.T) {
	t.Helper()
	for _, removed := range seam.removed {
		if !sameRollbackTestState(removed.actual, removed.expected) {
			t.Fatalf("removed state %q without matching expected state %q",
				removed.actual.data, removed.expected.data)
		}
	}
}

func rollbackTestState(value string) outputState {
	return outputState{exists: true, data: []byte(value)}
}

func sameRollbackTestState(left, right outputState) bool {
	return left.exists == right.exists && bytes.Equal(left.data, right.data)
}
