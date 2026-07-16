package perfdata

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/cataggar/LinuxTracepoints-Go/tracefs"
	"github.com/cataggar/LinuxTracepoints-Go/tracepoint"
)

var (
	magicLittle = [8]byte{'P', 'E', 'R', 'F', 'I', 'L', 'E', '2'}
	magicBig    = [8]byte{'2', 'E', 'L', 'I', 'F', 'R', 'E', 'P'}
)

// Open opens a seek-mode perf.data file. Reader does not own r.
func Open(r io.ReaderAt, size int64, opts Options) (*Reader, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil input", ErrNeedReaderAt)
	}
	limits, err := defaultLimits(opts.Limits)
	if err != nil {
		return nil, err
	}
	if size < 16 {
		return nil, &DecodeError{Offset: 0, Stage: "file header", Err: tracepoint.ErrTruncated}
	}
	p := newReader(opts, limits)
	p.at, p.fileSize = r, size
	first := make([]byte, 16)
	if err := readAtFull(r, first, 0); err != nil {
		return nil, &DecodeError{Offset: 0, Stage: "file header", Err: err}
	}
	if err := p.setOrder(first[:8]); err != nil {
		return nil, err
	}
	headerSize := p.order.Uint64(first[8:])
	if headerSize == 16 {
		return nil, fmt.Errorf("%w: input is pipe-mode", ErrNeedReaderAt)
	}
	if headerSize < 104 || headerSize > uint64(size) || headerSize > uint64(math.MaxInt) {
		return nil, &DecodeError{Offset: 8, Stage: "file header", Err: fmt.Errorf("%w: invalid header size %d", tracepoint.ErrInvalid, headerSize)}
	}
	header := make([]byte, int(headerSize))
	if err := readAtFull(r, header, 0); err != nil {
		return nil, &DecodeError{Offset: 0, Stage: "file header", Err: err}
	}
	if err := p.parseSeekHeader(header); err != nil {
		return nil, err
	}
	return p, nil
}

// OpenPipe opens a pipe-mode perf stream. Reader does not own r.
func OpenPipe(r io.Reader, opts Options) (*Reader, error) {
	if r == nil {
		return nil, invalid("pipe header", "nil input")
	}
	limits, err := defaultLimits(opts.Limits)
	if err != nil {
		return nil, err
	}
	p := newReader(opts, limits)
	p.pipe, p.stream, p.dataEnd = true, r, -1
	first := make([]byte, 16)
	if _, err := io.ReadFull(r, first); err != nil {
		return nil, &DecodeError{Offset: 0, Stage: "pipe header", Err: classifyEOF(err)}
	}
	if err := p.setOrder(first[:8]); err != nil {
		return nil, err
	}
	headerSize := p.order.Uint64(first[8:])
	if headerSize != 16 {
		if headerSize >= 104 {
			return nil, ErrNeedReaderAt
		}
		return nil, &DecodeError{Offset: 8, Stage: "pipe header", Err: fmt.Errorf("%w: invalid header size %d", tracepoint.ErrInvalid, headerSize)}
	}
	p.offset = 16
	return p, nil
}

func newReader(opts Options, limits Limits) *Reader {
	return &Reader{
		opts: opts, limits: limits, byID: make(map[uint64]*eventDesc),
		formats: make(map[uint32]*tracefs.Format), features: make(map[uint16][]byte),
		clock: ClockInfo{ID: -1},
	}
}

func (r *Reader) setOrder(magic []byte) error {
	switch {
	case bytes.Equal(magic, magicLittle[:]):
		r.order, r.byteOrder = binary.LittleEndian, tracepoint.ByteOrderLittle
	case bytes.Equal(magic, magicBig[:]):
		r.order, r.byteOrder = binary.BigEndian, tracepoint.ByteOrderBig
	default:
		return &DecodeError{Offset: 0, Stage: "magic", Err: fmt.Errorf("%w: not PERFILE2", tracepoint.ErrInvalid)}
	}
	return nil
}

func (r *Reader) parseSeekHeader(h []byte) error {
	attrEntrySize := r.order.Uint64(h[16:24])
	attrs := sectionAt(r.order, h, 24)
	data := sectionAt(r.order, h, 40)
	eventTypes := sectionAt(r.order, h, 56)
	for name, s := range map[string]fileSection{"attrs": attrs, "data": data, "event-types": eventTypes} {
		if err := r.checkSection(s); err != nil {
			return &DecodeError{Offset: 0, Stage: name + " section", Err: err}
		}
	}
	if eventTypes.size != 0 {
		if eventTypes.size > uint64(r.limits.MaxFeatureBytes) {
			return limitError("event-types section", "section exceeds limit")
		}
		if err := r.addMetadata(int64(eventTypes.size)); err != nil {
			return err
		}
		r.eventTypes = make([]byte, int(eventTypes.size))
		if err := readAtFull(r.at, r.eventTypes, int64(eventTypes.offset)); err != nil {
			return &DecodeError{Offset: int64(eventTypes.offset), Stage: "event-types section", Err: err}
		}
	}
	if data.offset > uint64(math.MaxInt64) || data.size > uint64(math.MaxInt64) {
		return invalid("data section", "offset is not representable")
	}
	r.offset, r.dataEnd = int64(data.offset), int64(data.offset+data.size)

	if attrs.size != 0 {
		if attrEntrySize < 80 || attrEntrySize > uint64(math.MaxInt) || attrs.size%attrEntrySize != 0 {
			return invalid("attrs section", "invalid attr entry size")
		}
		count := attrs.size / attrEntrySize
		if count > uint64(r.limits.MaxAttrs) {
			return limitError("attrs section", "too many attributes")
		}
		for i := uint64(0); i < count; i++ {
			entryOff := attrs.offset + i*attrEntrySize
			entry := make([]byte, int(attrEntrySize))
			if err := readAtFull(r.at, entry, int64(entryOff)); err != nil {
				return &DecodeError{Offset: int64(entryOff), Stage: "attribute", Err: err}
			}
			attrSize := len(entry) - 16
			if err := r.addMetadata(int64(len(entry))); err != nil {
				return err
			}
			attr, err := r.parseAttr(entry[:attrSize])
			if err != nil {
				return withOffset(err, int64(entryOff), "attribute")
			}
			idsSection := sectionAt(r.order, entry, attrSize)
			if err := r.checkSection(idsSection); err != nil {
				return &DecodeError{Offset: int64(entryOff + uint64(attrSize)), Stage: "attribute IDs", Err: err}
			}
			ids, err := r.readIDs(idsSection)
			if err != nil {
				return err
			}
			if err := r.addDescriptor(attr, "", ids); err != nil {
				return withOffset(err, int64(entryOff), "attribute")
			}
		}
	}

	var flags [4]uint64
	for i := range flags {
		flags[i] = r.order.Uint64(h[72+i*8:])
	}
	descPos := data.offset + data.size
	for bit := uint16(0); bit < 256; bit++ {
		if flags[bit/64]&(uint64(1)<<(bit%64)) == 0 {
			continue
		}
		if descPos > uint64(r.fileSize) || uint64(r.fileSize)-descPos < 16 {
			return &DecodeError{Offset: int64(descPos), Stage: "feature descriptor", Err: tracepoint.ErrTruncated}
		}
		var desc [16]byte
		if err := readAtFull(r.at, desc[:], int64(descPos)); err != nil {
			return &DecodeError{Offset: int64(descPos), Stage: "feature descriptor", Err: err}
		}
		descPos += 16
		s := sectionAt(r.order, desc[:], 0)
		if err := r.loadFeatureAt(bit, s); err != nil {
			return err
		}
	}
	r.attachFormats()
	return nil
}

type fileSection struct{ offset, size uint64 }

func sectionAt(order binary.ByteOrder, b []byte, at int) fileSection {
	return fileSection{order.Uint64(b[at : at+8]), order.Uint64(b[at+8 : at+16])}
}

func (r *Reader) checkSection(s fileSection) error {
	if s.offset > uint64(r.fileSize) || s.size > uint64(r.fileSize)-s.offset {
		return fmt.Errorf("%w: section [%d,%d) outside %d-byte file", tracepoint.ErrTruncated, s.offset, s.offset+s.size, r.fileSize)
	}
	if s.size > uint64(math.MaxInt) {
		return fmt.Errorf("%w: section is not representable", tracepoint.ErrLimit)
	}
	return nil
}

func (r *Reader) readIDs(s fileSection) ([]uint64, error) {
	if s.size%8 != 0 {
		return nil, invalid("attribute IDs", "ID section size is not a multiple of 8")
	}
	count := s.size / 8
	if count > uint64(r.limits.MaxIDs) || len(r.byID) > r.limits.MaxIDs-int(count) {
		return nil, limitError("attribute IDs", "too many IDs")
	}
	if err := r.addMetadata(int64(s.size)); err != nil {
		return nil, err
	}
	data := make([]byte, int(s.size))
	if err := readAtFull(r.at, data, int64(s.offset)); err != nil {
		return nil, &DecodeError{Offset: int64(s.offset), Stage: "attribute IDs", Err: err}
	}
	ids := make([]uint64, count)
	for i := range ids {
		ids[i] = r.order.Uint64(data[i*8:])
	}
	return ids, nil
}

func (r *Reader) loadFeatureAt(index uint16, s fileSection) error {
	if err := r.checkSection(s); err != nil {
		return &DecodeError{Offset: int64(s.offset), Stage: fmt.Sprintf("feature %d", index), Err: err}
	}
	if s.size > uint64(r.limits.MaxFeatureBytes) {
		return limitError(fmt.Sprintf("feature %d", index), "feature exceeds limit")
	}
	if index == FeatureCompressed {
		return ErrUnsupportedCompression
	}
	data := make([]byte, int(s.size))
	if err := readAtFull(r.at, data, int64(s.offset)); err != nil {
		return &DecodeError{Offset: int64(s.offset), Stage: fmt.Sprintf("feature %d", index), Err: err}
	}
	if err := r.applyFeature(index, data); err != nil {
		if errors.Is(err, ErrUnsupportedCompression) {
			return err
		}
		return withOffset(err, int64(s.offset), fmt.Sprintf("feature %d", index))
	}
	return nil
}

func (r *Reader) applyFeature(index uint16, data []byte) error {
	if err := r.addMetadata(int64(len(data))); err != nil {
		return err
	}
	owned := append([]byte(nil), data...)
	r.features[index] = owned
	switch index {
	case FeatureCompressed:
		return ErrUnsupportedCompression
	case FeatureTracingData:
		if err := r.parseTracingData(owned); err != nil {
			return err
		}
	case FeatureEventDesc:
		if err := r.parseEventDesc(owned); err != nil {
			return err
		}
	case FeatureClockID:
		if len(owned) < 8 {
			return invalid("CLOCKID", "feature is shorter than 8 bytes")
		}
		r.clock.ResolutionNS = r.order.Uint64(owned)
	case FeatureClockData:
		if err := r.parseClockData(owned); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reader) addMetadata(n int64) error {
	if n < 0 || r.metadataBytes > r.limits.MaxMetadataBytes-n {
		return limitError("metadata", "total metadata exceeds limit")
	}
	r.metadataBytes += n
	return nil
}

func readAtFull(r io.ReaderAt, b []byte, off int64) error {
	n, err := r.ReadAt(b, off)
	if n != len(b) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return classifyEOF(err)
	}
	return err
}

func classifyEOF(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return tracepoint.ErrTruncated
	}
	return err
}

func limitError(stage, text string) error {
	return &DecodeError{Stage: stage, Err: fmt.Errorf("%w: %s", tracepoint.ErrLimit, text)}
}

func withOffset(err error, off int64, stage string) error {
	var de *DecodeError
	if errors.As(err, &de) {
		copy := *de
		copy.Offset = off
		if copy.Stage == "" {
			copy.Stage = stage
		}
		return &copy
	}
	return &DecodeError{Offset: off, Stage: stage, Err: err}
}
