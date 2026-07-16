package perfdata

import (
	"errors"
	"fmt"
	"io"

	"github.com/cataggar/LinuxTracepoints-Go/tracepoint"
)

// MergeOptions controls a bounded stable merge. EpochOffsets maps reader
// indexes to signed offsets converting that reader's timestamps to Unix
// nanoseconds. ReaderOffsets is an equivalent pointer-keyed form.
type MergeOptions struct {
	MaxReaders    int
	EpochOffsets  map[int]int64
	ReaderOffsets map[*Reader]int64
}

// MergedReader performs a stable one-record-lookahead merge. Inputs must
// remain open and must not be read independently while the merge is active.
type MergedReader struct {
	readers []*Reader
	offsets []tracepoint.Optional[int64]
	heads   []tracepoint.Record
	times   []int64
	ready   []bool
	done    []bool
	closed  bool
}

// Merge creates a stable timestamp merge. Ties retain input-reader order.
func Merge(readers []*Reader, opts MergeOptions) (*MergedReader, error) {
	max := opts.MaxReaders
	if max == 0 {
		max = 64
	}
	if max < 0 || len(readers) > max {
		return nil, fmt.Errorf("%w: too many merge readers", tracepoint.ErrLimit)
	}
	m := &MergedReader{
		readers: append([]*Reader(nil), readers...), offsets: make([]tracepoint.Optional[int64], len(readers)),
		heads: make([]tracepoint.Record, len(readers)), times: make([]int64, len(readers)),
		ready: make([]bool, len(readers)), done: make([]bool, len(readers)),
	}
	seen := make(map[*Reader]struct{}, len(readers))
	for i, reader := range readers {
		if reader == nil {
			return nil, fmt.Errorf("%w: nil merge reader", tracepoint.ErrInvalid)
		}
		if _, ok := seen[reader]; ok {
			return nil, fmt.Errorf("%w: duplicate merge reader", tracepoint.ErrInvalid)
		}
		seen[reader] = struct{}{}
		if offset, ok := opts.EpochOffsets[i]; ok {
			m.offsets[i] = some(offset)
		} else if offset, ok := opts.ReaderOffsets[reader]; ok {
			m.offsets[i] = some(offset)
		} else if reader.clock.EpochOffsetKnown {
			m.offsets[i] = some(reader.clock.EpochOffset)
		} else {
			return nil, tracepoint.ErrIncomparableClocks
		}
	}
	return m, nil
}

// Next returns the earliest absolute timestamp. A reader is advanced only
// after its previous record has been returned.
func (m *MergedReader) Next() (tracepoint.Record, error) {
	if m == nil || m.closed {
		return tracepoint.Record{}, io.EOF
	}
	for i := range m.readers {
		if m.done[i] || m.ready[i] {
			continue
		}
		record, err := m.readers[i].Next()
		if errors.Is(err, io.EOF) {
			m.done[i] = true
			continue
		}
		if err != nil {
			return tracepoint.Record{}, err
		}
		t := record.Timestamp
		t.EpochOffset, t.EpochOffsetKnown = m.offsets[i].Value, true
		absolute, ok := t.UnixNano()
		if !ok {
			return tracepoint.Record{}, tracepoint.ErrIncomparableClocks
		}
		record.Timestamp = t
		m.heads[i], m.times[i], m.ready[i] = record, absolute, true
	}
	best := -1
	for i := range m.readers {
		if m.ready[i] && (best < 0 || m.times[i] < m.times[best]) {
			best = i
		}
	}
	if best < 0 {
		return tracepoint.Record{}, io.EOF
	}
	record := m.heads[best]
	m.heads[best] = tracepoint.Record{}
	m.ready[best] = false
	return record, nil
}

// Close releases lookahead records without closing input readers.
func (m *MergedReader) Close() error {
	if m == nil || m.closed {
		return nil
	}
	m.closed = true
	m.heads, m.readers, m.ready, m.done = nil, nil, nil, nil
	return nil
}
