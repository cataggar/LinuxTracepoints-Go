package eventheader

import (
	"fmt"
	"strconv"
)

const (
	// TracepointFields is the exact user_events field declaration used by all
	// EventHeader tracepoints.
	TracepointFields = "u8 eventheader_flags; u8 version; u16 id; u16 tag; u8 opcode; u8 level"
	// MaxTracepointName is the maximum EventHeader tracepoint name length,
	// excluding its terminating NUL.
	MaxTracepointName = 255
	// MaxProviderGroupLength conservatively reserves room for the longest
	// level, keyword, and group-option syntax.
	MaxProviderGroupLength = 233
)

// TracepointName returns provider_LnKkeyword[Ggroup] using lowercase hex.
func TracepointName(provider string, level Level, keyword uint64, group string) (string, error) {
	if err := validateProvider(provider); err != nil {
		return "", err
	}
	if level < LevelCritical || level > LevelVerbose {
		return "", fmt.Errorf("%w: %d", ErrInvalidLevel, level)
	}
	if err := validateGroup(group); err != nil {
		return "", err
	}
	// C and Rust require provider+group to be strictly less than 234.
	if len(provider)+len(group) > MaxProviderGroupLength {
		return "", fmt.Errorf("%w: provider and group total %d bytes; maximum is %d", ErrInvalidName, len(provider)+len(group), MaxProviderGroupLength)
	}

	name := provider + "_L" + strconv.FormatUint(uint64(level), 16) + "K" + strconv.FormatUint(keyword, 16)
	if group != "" {
		name += "G" + group
	}
	if len(name) > MaxTracepointName {
		return "", fmt.Errorf("%w: tracepoint name is %d bytes; maximum is %d", ErrInvalidName, len(name), MaxTracepointName)
	}
	return name, nil
}

func validateProvider(name string) error {
	if name == "" || !isASCIILetter(name[0]) && name[0] != '_' {
		return fmt.Errorf("%w: provider %q must start with an ASCII letter or underscore", ErrInvalidName, name)
	}
	for i := 1; i < len(name); i++ {
		if !isASCIILetter(name[i]) && (name[i] < '0' || name[i] > '9') && name[i] != '_' {
			return fmt.Errorf("%w: provider %q is not an ASCII identifier", ErrInvalidName, name)
		}
	}
	return nil
}

func validateGroup(group string) error {
	for i := range len(group) {
		if (group[i] < 'a' || group[i] > 'z') && (group[i] < '0' || group[i] > '9') {
			return fmt.Errorf("%w: group %q must contain only lowercase ASCII letters and digits", ErrInvalidName, group)
		}
	}
	return nil
}

func isASCIILetter(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}
