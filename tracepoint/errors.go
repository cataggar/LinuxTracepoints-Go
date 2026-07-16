package tracepoint

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalid indicates malformed metadata or data.
	ErrInvalid = errors.New("invalid tracepoint data")
	// ErrTruncated indicates that input ended before a complete value was read.
	ErrTruncated = errors.New("truncated tracepoint data")
	// ErrUnsupported indicates a recognized but unsupported representation.
	ErrUnsupported = errors.New("unsupported tracepoint data")
	// ErrLimit indicates that a configured resource limit was exceeded.
	ErrLimit = errors.New("tracepoint limit exceeded")
	// ErrUnknownID indicates that no event metadata is available for an ID.
	ErrUnknownID = errors.New("unknown tracepoint ID")
	// ErrIncomparableClocks indicates timestamps from clocks without a known
	// relationship.
	ErrIncomparableClocks = errors.New("incomparable tracepoint clocks")
)

// DecodeError adds a byte offset and decoding stage to an underlying error.
// Its Unwrap method permits errors.Is and errors.As.
type DecodeError struct {
	Offset int
	Stage  string
	Err    error
}

// Error implements error.
func (e *DecodeError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Stage == "" {
		return fmt.Sprintf("tracepoint offset %d: %v", e.Offset, e.Err)
	}
	return fmt.Sprintf("tracepoint %s at offset %d: %v", e.Stage, e.Offset, e.Err)
}

// Unwrap returns the underlying error.
func (e *DecodeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}
