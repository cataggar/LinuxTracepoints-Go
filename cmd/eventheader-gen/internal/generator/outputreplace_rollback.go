package generator

import (
	"fmt"
	"strings"
)

const replaceFileRollbackRaceLimit = 8

type replaceFileRollbackOps struct {
	replace        func(target, replacement, backup string) error
	read           func(path string) (outputState, error)
	same           func(left, right outputState) bool
	removeVerified func(path string, expected outputState) error
}

func rollbackReplaceFile(
	tempName string,
	targetName string,
	replacementName string,
	expectedTarget outputState,
	replacement outputState,
	ops replaceFileRollbackOps,
) error {
	for race := 0; ; race++ {
		displacedName := fmt.Sprintf("%s.recovery-%d", tempName, race)
		if err := ops.replace(targetName, replacementName, displacedName); err != nil {
			return fmt.Errorf("%v; restore output from %q (recovery path %q): %w",
				concurrentModificationError(targetName), replacementName, displacedName, err)
		}

		displaced, err := ops.read(displacedName)
		if err != nil {
			return fmt.Errorf("%v; inspect displaced output preserved at %q: %w",
				concurrentModificationError(targetName), displacedName, err)
		}
		if ops.same(expectedTarget, displaced) {
			if err := ops.removeVerified(displacedName, expectedTarget); err != nil {
				return fmt.Errorf("%v; remove verified displaced output %q: %w",
					concurrentModificationError(targetName), displacedName, err)
			}
			return nil
		}

		if race+1 == replaceFileRollbackRaceLimit {
			return fmt.Errorf(
				"%v; rollback exhausted after %d concurrent replacements; preserved recovery paths: %s",
				concurrentModificationError(targetName),
				replaceFileRollbackRaceLimit,
				quoteRecoveryPaths(displacedName),
			)
		}

		replacementName = displacedName
		expectedTarget = replacement
		replacement = displaced
	}
}

func quoteRecoveryPaths(paths ...string) string {
	quoted := make([]string, len(paths))
	for index, path := range paths {
		quoted[index] = fmt.Sprintf("%q", path)
	}
	return strings.Join(quoted, ", ")
}
