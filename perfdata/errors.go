package perfdata

import (
	"errors"
	"fmt"

	"github.com/cataggar/LinuxTracepoints-Go/tracepoint"
)

var (
	ErrNeedReaderAt           = errors.New("perfdata: seek format requires io.ReaderAt")
	ErrUnsupportedCompression = errors.New("perfdata: compressed data is unsupported")
)

// DecodeError identifies a fatal outer framing failure.
type DecodeError struct {
	Offset      int64
	RecordIndex uint64
	Stage       string
	Err         error
}

func (e *DecodeError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("perfdata %s at offset %d (record %d): %v", e.Stage, e.Offset, e.RecordIndex, e.Err)
}

func (e *DecodeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func invalid(stage, text string) error {
	return &DecodeError{Stage: stage, Err: fmt.Errorf("%w: %s", tracepoint.ErrInvalid, text)}
}
