package userevents

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const maxEventDescriptionSize = 512

var (
	// ErrUnsupported indicates that user_events is unavailable on this
	// platform or kernel.
	ErrUnsupported = errors.New("userevents: unsupported")

	// ErrClosed indicates an operation on a closed registration or data file.
	ErrClosed = errors.New("userevents: closed")

	// ErrDisabled indicates that the tracepoint is not currently enabled.
	ErrDisabled = errors.New("userevents: disabled")

	// ErrInvalidArgument indicates an invalid name, field description, or
	// registration option.
	ErrInvalidArgument = errors.New("userevents: invalid argument")
)

// RegisterFlags controls kernel registration behavior.
type RegisterFlags uint16

const (
	// RegisterPersist keeps the tracepoint after the last registration closes.
	// It requires CAP_PERFMON or CAP_SYS_ADMIN.
	RegisterPersist RegisterFlags = 1 << iota

	// RegisterMultiFormat permits multiple field formats for the same logical
	// name. The kernel exposes them in the user_events_multi subsystem.
	RegisterMultiFormat

	validRegisterFlags = RegisterPersist | RegisterMultiFormat
)

// RegisterOptions configures a tracepoint registration.
type RegisterOptions struct {
	Flags RegisterFlags
}

func makeRegistrationCommand(name, fields string, options RegisterOptions) ([]byte, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	if options.Flags&^validRegisterFlags != 0 {
		return nil, fmt.Errorf("%w: unknown registration flags %#x", ErrInvalidArgument, options.Flags&^validRegisterFlags)
	}
	if !utf8.ValidString(fields) {
		return nil, fmt.Errorf("%w: fields are not valid UTF-8", ErrInvalidArgument)
	}
	if strings.ContainsAny(fields, "\x00\r\n") {
		return nil, fmt.Errorf("%w: fields contain a prohibited control character", ErrInvalidArgument)
	}

	fields = strings.TrimSpace(fields)
	command := name
	if fields != "" {
		command += " " + fields
	}
	if len(command)+1 > maxEventDescriptionSize {
		return nil, fmt.Errorf(
			"%w: registration command is %d bytes; maximum is %d",
			ErrInvalidArgument,
			len(command),
			maxEventDescriptionSize-1,
		)
	}

	return append([]byte(command), 0), nil
}

func makeDeleteCommand(name string) ([]byte, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	if len(name)+1 > maxEventDescriptionSize {
		return nil, fmt.Errorf(
			"%w: event name is %d bytes; maximum is %d",
			ErrInvalidArgument,
			len(name),
			maxEventDescriptionSize-1,
		)
	}
	return append([]byte(name), 0), nil
}

func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: event name is empty", ErrInvalidArgument)
	}
	for _, char := range name {
		if char > 0x7f ||
			!((char >= 'a' && char <= 'z') ||
				(char >= 'A' && char <= 'Z') ||
				(char >= '0' && char <= '9') ||
				char == '_') {
			return fmt.Errorf("%w: event name %q contains an invalid character", ErrInvalidArgument, name)
		}
	}
	return nil
}
