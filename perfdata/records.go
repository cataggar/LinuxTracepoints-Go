package perfdata

import (
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	eventdecode "github.com/cataggar/LinuxTracepoints-Go/eventheader/decode"
	"github.com/cataggar/LinuxTracepoints-Go/tracefs"
	"github.com/cataggar/LinuxTracepoints-Go/tracepoint"
)

const (
	recordHeaderAttr        = 64
	recordHeaderTracingData = 66
	recordFinishedRound     = 68
	recordHeaderFeature     = 80
	recordCompressed        = 81
	recordFinishedInit      = 82
	recordCompressed2       = 83
)

// Next returns the next data record in file order.
func (r *Reader) Next() (tracepoint.Record, error) {
	if r == nil || r.closed {
		return tracepoint.Record{}, io.EOF
	}
	if r.terminal != nil {
		return tracepoint.Record{}, r.terminal
	}
	for {
		raw, typ, misc, err := r.readOuter()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				r.terminal = err
			}
			return tracepoint.Record{}, err
		}
		r.current = RecordDetails{Type: typ, Misc: misc, Size: uint16(len(raw))}
		metadata, err := r.processPipeMetadata(typ, raw)
		if err != nil {
			r.terminal = r.fatal("metadata record", err)
			return tracepoint.Record{}, r.terminal
		}
		raw = r.buf
		r.index++
		if metadata && !r.opts.KeepMetadataRecords {
			continue
		}
		record := r.decodeRecord(typ, misc, raw)
		return record, nil
	}
}

func (r *Reader) readOuter() ([]byte, uint32, uint16, error) {
	start := r.offset
	var header [8]byte
	if r.pipe {
		n, err := io.ReadFull(r.stream, header[:])
		if err != nil {
			if errors.Is(err, io.EOF) && n == 0 {
				return nil, 0, 0, io.EOF
			}
			return nil, 0, 0, r.fatalAt(start, "record header", tracepoint.ErrTruncated)
		}
	} else {
		if r.offset == r.dataEnd {
			return nil, 0, 0, io.EOF
		}
		if r.offset > r.dataEnd || r.dataEnd-r.offset < 8 {
			return nil, 0, 0, r.fatalAt(start, "record header", tracepoint.ErrTruncated)
		}
		if err := readAtFull(r.at, header[:], r.offset); err != nil {
			return nil, 0, 0, r.fatalAt(start, "record header", err)
		}
	}
	typ, misc, size := r.order.Uint32(header[:4]), r.order.Uint16(header[4:6]), r.order.Uint16(header[6:8])
	if size < 8 || int(size) > r.limits.MaxRecordBytes {
		return nil, 0, 0, r.fatalAt(start, "record header", fmt.Errorf("%w: invalid record size %d", tracepoint.ErrInvalid, size))
	}
	if !r.pipe && int64(size) > r.dataEnd-r.offset {
		return nil, 0, 0, r.fatalAt(start, "record body", tracepoint.ErrTruncated)
	}
	if cap(r.buf) < int(size) {
		r.buf = make([]byte, int(size))
	} else {
		r.buf = r.buf[:int(size)]
	}
	copy(r.buf, header[:])
	if size > 8 {
		var err error
		if r.pipe {
			_, err = io.ReadFull(r.stream, r.buf[8:])
			err = classifyEOF(err)
		} else {
			err = readAtFull(r.at, r.buf[8:], r.offset+8)
		}
		if err != nil {
			return nil, 0, 0, r.fatalAt(start+8, "record body", err)
		}
	}
	r.offset += int64(size)
	return r.buf, typ, misc, nil
}

func (r *Reader) processPipeMetadata(typ uint32, raw []byte) (bool, error) {
	switch typ {
	case recordCompressed, recordCompressed2:
		return true, ErrUnsupportedCompression
	case recordHeaderAttr:
		if len(raw) < 8+64 {
			return true, tracepoint.ErrTruncated
		}
		size := r.order.Uint32(raw[12:16])
		if size == 0 {
			size = 64
		}
		if size < 64 || int(size) > len(raw)-8 {
			return true, fmt.Errorf("%w: invalid HEADER_ATTR size", tracepoint.ErrInvalid)
		}
		attr, err := r.parseAttr(raw[8 : 8+int(size)])
		if err != nil {
			return true, err
		}
		idBytes := raw[8+int(size):]
		if len(idBytes)%8 != 0 || len(idBytes)/8 > r.limits.MaxIDs {
			return true, fmt.Errorf("%w: invalid HEADER_ATTR IDs", tracepoint.ErrInvalid)
		}
		ids := make([]uint64, len(idBytes)/8)
		for i := range ids {
			ids[i] = r.order.Uint64(idBytes[i*8:])
		}
		if err := r.addMetadata(int64(len(raw) - 8)); err != nil {
			return true, err
		}
		if err := r.addDescriptor(attr, "", ids); err != nil {
			return true, err
		}
		r.attachFormats()
		return true, nil
	case recordHeaderTracingData:
		if len(raw) < 12 {
			return true, tracepoint.ErrTruncated
		}
		size := uint64(r.order.Uint32(raw[8:12]))
		if size > uint64(r.limits.MaxFeatureBytes) || size > uint64(math.MaxInt) {
			return true, tracepoint.ErrLimit
		}
		post, err := r.readPost(size)
		if err != nil {
			return true, err
		}
		if err := r.applyFeature(FeatureTracingData, post); err != nil {
			return true, err
		}
		return true, nil
	case 71: // PERF_RECORD_AUXTRACE has an out-of-record data block.
		if len(raw) < 16 {
			return false, tracepoint.ErrTruncated
		}
		size := r.order.Uint64(raw[8:16])
		if _, err := r.readPost(size); err != nil {
			return false, err
		}
		r.current.PostDataSize = size
		return false, nil
	case recordHeaderFeature:
		if len(raw) < 16 {
			return true, tracepoint.ErrTruncated
		}
		index := r.order.Uint64(raw[8:16])
		if index >= 256 {
			return true, fmt.Errorf("%w: feature index %d", tracepoint.ErrInvalid, index)
		}
		if err := r.applyFeature(uint16(index), raw[16:]); err != nil {
			return true, err
		}
		r.attachFormats()
		return true, nil
	case recordFinishedRound, recordFinishedInit:
		return true, nil
	default:
		return false, nil
	}
}

func (r *Reader) readPost(size uint64) ([]byte, error) {
	if size > uint64(r.limits.MaxPostRecordBytes) || size > uint64(math.MaxInt) {
		return nil, tracepoint.ErrLimit
	}
	start := len(r.buf)
	r.buf = append(r.buf, make([]byte, int(size))...)
	post := r.buf[start:]
	var err error
	if r.pipe {
		_, err = io.ReadFull(r.stream, post)
		err = classifyEOF(err)
	} else if int64(size) > r.dataEnd-r.offset {
		err = tracepoint.ErrTruncated
	} else {
		err = readAtFull(r.at, post, r.offset)
	}
	if err != nil {
		r.buf = r.buf[:start]
		return nil, err
	}
	r.offset += int64(size)
	return post, nil
}

func (r *Reader) decodeRecord(typ uint32, misc uint16, raw []byte) tracepoint.Record {
	switch typ {
	case RecordSample:
		return r.decodeSample(raw)
	case RecordLost, RecordLostSamples:
		return r.decodeLost(typ, raw)
	case RecordComm, RecordExit, RecordThrottle, RecordUnthrottle, RecordFork,
		RecordMmap, RecordMmap2, RecordSwitch, RecordSwitchCPUWide:
		return r.decodeKnown(typ, misc, raw)
	default:
		record := r.rawRecord(typ, raw)
		wire := raw
		if len(raw) >= 8 {
			size := int(r.order.Uint16(raw[6:8]))
			if size >= 8 && size <= len(raw) {
				wire = raw[:size]
			}
		}
		if typ < 64 {
			r.applySuffix(&record, wire)
		}
		return record
	}
}

func (r *Reader) decodeSample(raw []byte) tracepoint.Record {
	if r.sampleIDOffset < 0 || r.sampleIDOffset+8 > len(raw) {
		return r.corrupt(raw, "sample has no usable ID", tracepoint.ErrUnknownID)
	}
	id := r.order.Uint64(raw[r.sampleIDOffset:])
	desc := r.byID[id]
	if desc == nil {
		return r.corrupt(raw, fmt.Sprintf("unknown perf sample ID %d", id), tracepoint.ErrUnknownID)
	}
	sample, envelope, err := r.parseSample(raw, desc.attr)
	if err != nil {
		return r.corrupt(raw, "invalid perf sample", err)
	}
	if sample.ID.Present && sample.Identifier.Present && sample.ID.Value != sample.Identifier.Value {
		return r.corrupt(raw, "sample ID and identifier disagree", tracepoint.ErrInvalid)
	}
	r.current.ID = sample.ID
	if !r.current.ID.Present {
		r.current.ID = sample.Identifier
	}
	r.current.StreamID, r.current.Sample = sample.StreamID, sample
	if desc.format == nil || len(sample.Raw) == 0 {
		record := r.rawRecord(RecordSample, raw)
		applyEnvelope(&record, envelope)
		if desc.name != "" {
			record.Identity.Name = desc.name
		}
		r.addUnsupportedDiagnostic(&record, sample)
		return record
	}
	options := tracefs.DecodeOptions{
		ByteOrder: r.payloadByteOrder(), LongSize: r.longSize, Timestamp: envelope.Timestamp,
		CPU: envelope.CPU, PID: envelope.PID, TID: envelope.TID,
		MaxArrayElements: r.limits.MaxArrayElements,
	}
	ordinary, err := tracefs.Decode(desc.format, sample.Raw, options)
	if err != nil {
		return r.corrupt(raw, "tracefs payload could not be decoded", err)
	}
	if len(desc.format.Fields) != 0 && desc.format.Fields[0].Name == "eventheader_flags" {
		offset := desc.format.Fields[0].Offset
		if offset < 0 || offset > len(sample.Raw) {
			return r.corrupt(raw, "EventHeader field offset is invalid", tracepoint.ErrTruncated)
		}
		event, decodeErr := eventdecode.Decode(desc.format.Name, sample.Raw[offset:])
		if decodeErr != nil {
			return r.corrupt(raw, "EventHeader payload could not be decoded", decodeErr)
		}
		event.Timestamp, event.CPU, event.PID, event.TID, event.Raw = envelope.Timestamp, envelope.CPU, envelope.PID, envelope.TID, raw
		if event.Event != nil && ordinary.Event != nil {
			event.Event.Common = ordinary.Event.Common
		}
		event.Diagnostics = append(ordinary.Diagnostics, event.Diagnostics...)
		r.addUnsupportedDiagnostic(&event, sample)
		return event
	}
	ordinary.Raw = raw
	r.addUnsupportedDiagnostic(&ordinary, sample)
	return ordinary
}

func (r *Reader) addUnsupportedDiagnostic(record *tracepoint.Record, sample *SampleDetails) {
	if sample.UnsupportedSampleBits == 0 {
		return
	}
	record.Diagnostics = append(record.Diagnostics, tracepoint.Diagnostic{
		Severity: tracepoint.SeverityWarning, Stage: "sample",
		Message: fmt.Sprintf("sample bits %#x retained as trailing data", sample.UnsupportedSampleBits),
		Err:     fmt.Errorf("%w: sample fields after RAW", tracepoint.ErrUnsupported),
	})
}

type envelope struct {
	Timestamp tracepoint.Timestamp
	CPU       tracepoint.Optional[uint32]
	PID       tracepoint.Optional[int32]
	TID       tracepoint.Optional[int32]
}

func (r *Reader) parseSample(raw []byte, attr Attr) (*SampleDetails, envelope, error) {
	c := wireCursor{data: raw, pos: 8, order: r.order}
	s := &SampleDetails{}
	var e envelope
	var err error
	if attr.SampleType&SampleIdentifier != 0 {
		s.Identifier, err = c.optional64()
	}
	if err == nil && attr.SampleType&SampleIP != 0 {
		s.IP, err = c.optional64()
	}
	if err == nil && attr.SampleType&SampleTID != 0 {
		var pid, tid uint32
		pid, tid, err = c.pair32()
		e.PID, e.TID = some(int32(pid)), some(int32(tid))
	}
	if err == nil && attr.SampleType&SampleTime != 0 {
		var v uint64
		v, err = c.u64()
		e.Timestamp = r.timestamp(v)
	}
	if err == nil && attr.SampleType&SampleAddr != 0 {
		s.Address, err = c.optional64()
	}
	if err == nil && attr.SampleType&SampleID != 0 {
		s.ID, err = c.optional64()
	}
	if err == nil && attr.SampleType&SampleStreamID != 0 {
		s.StreamID, err = c.optional64()
	}
	if err == nil && attr.SampleType&SampleCPU != 0 {
		var cpu uint32
		cpu, _, err = c.pair32()
		e.CPU = some(cpu)
	}
	if err == nil && attr.SampleType&SamplePeriod != 0 {
		s.Period, err = c.optional64()
	}
	if err == nil && attr.SampleType&SampleRead != 0 {
		err = r.parseRead(&c, attr.ReadFormat, s)
	}
	if err == nil && attr.SampleType&SampleCallchain != 0 {
		var count uint64
		count, err = c.u64()
		if err == nil && (count > uint64(r.limits.MaxCallchain) || count > uint64(c.remaining()/8)) {
			err = fmt.Errorf("%w: callchain count %d", tracepoint.ErrLimit, count)
		}
		if err == nil {
			s.Callchain = make([]uint64, count)
			for i := range s.Callchain {
				s.Callchain[i], err = c.u64()
				if err != nil {
					break
				}
			}
		}
	}
	if err == nil && attr.SampleType&SampleRaw != 0 {
		var size uint32
		size, err = c.u32()
		if err == nil {
			if uint64(size) > uint64(c.remaining()) {
				err = tracepoint.ErrTruncated
			} else {
				s.Raw = c.data[c.pos : c.pos+int(size)]
				c.pos += int(size)
				c.pos = (c.pos + 7) &^ 7
				if c.pos > len(c.data) {
					err = tracepoint.ErrTruncated
				}
			}
		}
	}
	if err != nil {
		return nil, e, err
	}
	const supported = SampleIdentifier | SampleIP | SampleTID | SampleTime | SampleAddr |
		SampleID | SampleStreamID | SampleCPU | SamplePeriod | SampleRead | SampleCallchain | SampleRaw
	s.UnsupportedSampleBits = attr.SampleType &^ supported
	s.TrailingSampleData = c.data[c.pos:]
	return s, e, nil
}

func (r *Reader) parseRead(c *wireCursor, format uint64, s *SampleDetails) error {
	const known uint64 = 0x1f
	if format&^known != 0 {
		return fmt.Errorf("%w: read_format %#x", tracepoint.ErrUnsupported, format)
	}
	group := format&(1<<3) != 0
	count := uint64(1)
	var err error
	if group {
		count, err = c.u64()
		if err != nil {
			return err
		}
	}
	if count > uint64(r.limits.MaxReadValues) || count > uint64(c.remaining()/8) {
		return fmt.Errorf("%w: read count %d", tracepoint.ErrLimit, count)
	}
	s.Read = make([]ReadValue, count)
	if !group {
		s.Read[0].Value, err = c.u64()
		if err != nil {
			return err
		}
	}
	if format&1 != 0 {
		s.TimeEnabled, err = c.optional64()
		if err != nil {
			return err
		}
	}
	if format&2 != 0 {
		s.TimeRunning, err = c.optional64()
		if err != nil {
			return err
		}
	}
	for i := range s.Read {
		if group {
			s.Read[i].Value, err = c.u64()
			if err != nil {
				return err
			}
		}
		if format&4 != 0 {
			s.Read[i].ID, err = c.optional64()
			if err != nil {
				return err
			}
		}
		if format&16 != 0 {
			s.Read[i].Lost, err = c.optional64()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Reader) payloadByteOrder() tracepoint.ByteOrder {
	if r.tracing.ByteOrder != tracepoint.ByteOrderUnknown {
		return r.tracing.ByteOrder
	}
	return r.byteOrder
}

func (r *Reader) decodeLost(typ uint32, raw []byte) tracepoint.Record {
	min := 16
	if typ == RecordLost {
		min = 24
	}
	if len(raw) < min {
		return r.corrupt(raw, "lost record is truncated", tracepoint.ErrTruncated)
	}
	layout, err := r.resolveSuffix(raw)
	if err != nil {
		return r.corrupt(raw, "invalid sample_id_all suffix", err)
	}
	if layout.start < min {
		return r.corrupt(raw, "lost record overlaps sample_id_all suffix", tracepoint.ErrTruncated)
	}
	var id, count uint64
	if typ == RecordLost {
		id, count = r.order.Uint64(raw[8:]), r.order.Uint64(raw[16:])
	} else {
		count = r.order.Uint64(raw[8:])
	}
	record := tracepoint.Record{
		Kind: tracepoint.RecordLost, Identity: tracepoint.Identity{System: "perf", Name: perfRecordName(typ)},
		Lost: &tracepoint.LostRecord{Count: count}, Raw: raw,
	}
	if typ == RecordLost {
		r.current.ID = some(id)
		if d := r.byID[id]; d != nil && d.name != "" {
			record.Identity.Name = d.name
		}
	}
	r.applySuffixLayout(&record, raw, layout)
	if r.current.ID.Present {
		if d := r.byID[r.current.ID.Value]; d != nil && d.name != "" {
			record.Identity.Name = d.name
		}
	}
	return record
}

func (r *Reader) decodeKnown(typ uint32, misc uint16, raw []byte) tracepoint.Record {
	record := r.rawRecord(typ, raw)
	layout, err := r.resolveSuffix(raw)
	if err != nil {
		return r.corrupt(raw, "invalid sample_id_all suffix", err)
	}
	bodyEnd := layout.start
	if bodyEnd < 8 {
		return r.corrupt(raw, "invalid sample_id_all suffix", tracepoint.ErrTruncated)
	}
	switch typ {
	case RecordComm:
		if bodyEnd < 16 {
			return r.corrupt(raw, "COMM is truncated", tracepoint.ErrTruncated)
		}
		record.PID, record.TID = some(int32(r.order.Uint32(raw[8:]))), some(int32(r.order.Uint32(raw[12:])))
		name, ok := terminated(raw[16:bodyEnd])
		if !ok {
			return r.corrupt(raw, "COMM name is not terminated", tracepoint.ErrInvalid)
		}
		r.current.Comm = &CommDetails{Name: name}
	case RecordExit, RecordFork:
		if bodyEnd < 32 {
			return r.corrupt(raw, "task record is truncated", tracepoint.ErrTruncated)
		}
		record.PID, record.TID = some(int32(r.order.Uint32(raw[8:]))), some(int32(r.order.Uint32(raw[16:])))
		r.current.Task = &TaskDetails{ParentPID: int32(r.order.Uint32(raw[12:])), ParentTID: int32(r.order.Uint32(raw[20:]))}
		record.Timestamp = r.timestamp(r.order.Uint64(raw[24:]))
	case RecordThrottle, RecordUnthrottle:
		if bodyEnd < 32 {
			return r.corrupt(raw, "throttle record is truncated", tracepoint.ErrTruncated)
		}
		record.Timestamp = r.timestamp(r.order.Uint64(raw[8:]))
		r.current.ID, r.current.StreamID = some(r.order.Uint64(raw[16:])), some(r.order.Uint64(raw[24:]))
	case RecordMmap:
		if bodyEnd < 40 {
			return r.corrupt(raw, "MMAP is truncated", tracepoint.ErrTruncated)
		}
		record.PID, record.TID = some(int32(r.order.Uint32(raw[8:]))), some(int32(r.order.Uint32(raw[12:])))
		name, ok := terminated(raw[40:bodyEnd])
		if !ok {
			return r.corrupt(raw, "MMAP name is not terminated", tracepoint.ErrInvalid)
		}
		r.current.Mmap = &MmapDetails{Address: r.order.Uint64(raw[16:]), Length: r.order.Uint64(raw[24:]), PageOffset: r.order.Uint64(raw[32:]), Filename: name}
	case RecordMmap2:
		if bodyEnd < 72 {
			return r.corrupt(raw, "MMAP2 is truncated", tracepoint.ErrTruncated)
		}
		record.PID, record.TID = some(int32(r.order.Uint32(raw[8:]))), some(int32(r.order.Uint32(raw[12:])))
		name, ok := terminated(raw[72:bodyEnd])
		if !ok {
			return r.corrupt(raw, "MMAP2 name is not terminated", tracepoint.ErrInvalid)
		}
		details := &MmapDetails{Address: r.order.Uint64(raw[16:]), Length: r.order.Uint64(raw[24:]), PageOffset: r.order.Uint64(raw[32:]), Protection: r.order.Uint32(raw[64:]), Flags: r.order.Uint32(raw[68:]), Filename: name}
		if misc&(1<<14) != 0 {
			size := int(raw[40])
			if size > 20 {
				return r.corrupt(raw, "MMAP2 build ID is invalid", tracepoint.ErrInvalid)
			}
			details.BuildID = append([]byte(nil), raw[44:44+size]...)
		} else {
			details.Major, details.Minor = r.order.Uint32(raw[40:]), r.order.Uint32(raw[44:])
			details.Inode, details.Generation = r.order.Uint64(raw[48:]), r.order.Uint64(raw[56:])
		}
		r.current.Mmap = details
	case RecordSwitch:
		r.current.Switch = &SwitchDetails{Out: misc&(1<<13) != 0, Preempt: misc&(1<<14) != 0}
	case RecordSwitchCPUWide:
		if bodyEnd < 16 {
			return r.corrupt(raw, "SWITCH_CPU_WIDE is truncated", tracepoint.ErrTruncated)
		}
		r.current.Switch = &SwitchDetails{Out: misc&(1<<13) != 0, Preempt: misc&(1<<14) != 0, NextPrevPID: some(int32(r.order.Uint32(raw[8:]))), NextPrevTID: some(int32(r.order.Uint32(raw[12:])))}
	}
	r.applySuffixLayout(&record, raw, layout)
	if r.current.ID.Present {
		if d := r.byID[r.current.ID.Value]; d != nil && d.name != "" {
			record.Identity.Name = d.name
		}
	}
	return record
}

func (r *Reader) applySuffix(record *tracepoint.Record, raw []byte) {
	layout, err := r.resolveSuffix(raw)
	if err != nil {
		record.Diagnostics = append(record.Diagnostics, diagnostic("sample_id_all", err))
		return
	}
	r.applySuffixLayout(record, raw, layout)
}

func (r *Reader) applySuffixLayout(record *tracepoint.Record, raw []byte, layout suffixLayout) {
	if !r.sampleIDAll {
		return
	}
	c := wireCursor{data: raw, pos: layout.start, order: r.order}
	var id, identifier tracepoint.Optional[uint64]
	var err error
	if layout.mask&SampleTID != 0 {
		var pid, tid uint32
		pid, tid, err = c.pair32()
		record.PID, record.TID = some(int32(pid)), some(int32(tid))
	}
	if err == nil && layout.mask&SampleTime != 0 {
		var time uint64
		time, err = c.u64()
		record.Timestamp = r.timestamp(time)
	}
	if err == nil && layout.mask&SampleID != 0 {
		id, err = c.optional64()
	}
	if err == nil && layout.mask&SampleStreamID != 0 {
		r.current.StreamID, err = c.optional64()
	}
	if err == nil && layout.mask&SampleCPU != 0 {
		var cpu uint32
		cpu, _, err = c.pair32()
		record.CPU = some(cpu)
	}
	if err == nil && layout.mask&SampleIdentifier != 0 {
		identifier, err = c.optional64()
	}
	if err != nil {
		record.Diagnostics = append(record.Diagnostics, diagnostic("sample_id_all", err))
		return
	}
	if id.Present {
		r.current.ID = id
	} else if identifier.Present {
		r.current.ID = identifier
	}
	if id.Present && identifier.Present && id.Value != identifier.Value {
		record.Diagnostics = append(record.Diagnostics, diagnostic("sample_id_all", fmt.Errorf("%w: ID and identifier disagree", tracepoint.ErrInvalid)))
	}
	if r.current.ID.Present {
		if d := r.byID[r.current.ID.Value]; d != nil && d.name != "" {
			record.Identity.Name = d.name
		}
	}
}

type suffixLayout struct {
	start int
	mask  uint64
}

func (r *Reader) resolveSuffix(raw []byte) (suffixLayout, error) {
	if !r.sampleIDAll {
		return suffixLayout{start: len(raw)}, nil
	}
	mask := r.suffixMask
	if r.suffixIDAll {
		if len(raw) < 16 {
			return suffixLayout{}, tracepoint.ErrTruncated
		}
		identifier := r.order.Uint64(raw[len(raw)-8:])
		desc := r.byID[identifier]
		if desc == nil {
			return suffixLayout{}, fmt.Errorf("%w: unknown terminal perf identifier %d", tracepoint.ErrUnknownID, identifier)
		}
		if !desc.attr.SampleIDAll || desc.attr.SampleType&SampleIdentifier == 0 {
			return suffixLayout{}, fmt.Errorf("%w: terminal identifier has no suffix layout", tracepoint.ErrInvalid)
		}
		mask = desc.attr.SampleType & (SampleTID | SampleTime | SampleID | SampleStreamID | SampleCPU | SampleIdentifier)
	}
	size := 0
	for _, bit := range []uint64{SampleTID, SampleTime, SampleID, SampleStreamID, SampleCPU, SampleIdentifier} {
		if mask&bit != 0 {
			size += 8
		}
	}
	start := len(raw) - size
	if start < 8 {
		return suffixLayout{}, tracepoint.ErrTruncated
	}
	return suffixLayout{start: start, mask: mask}, nil
}

func (r *Reader) rawRecord(typ uint32, raw []byte) tracepoint.Record {
	return tracepoint.Record{Kind: tracepoint.RecordRaw, Identity: tracepoint.Identity{System: "perf", Name: perfRecordName(typ)}, Raw: raw}
}

func (r *Reader) corrupt(raw []byte, reason string, err error) tracepoint.Record {
	return tracepoint.Record{
		Kind: tracepoint.RecordCorrupt, Identity: tracepoint.Identity{System: "perf", Name: "corrupt"},
		Corrupt: &tracepoint.CorruptRecord{Reason: reason}, Raw: raw,
		Diagnostics: []tracepoint.Diagnostic{diagnostic("record", err)},
	}
}

func diagnostic(stage string, err error) tracepoint.Diagnostic {
	return tracepoint.Diagnostic{Severity: tracepoint.SeverityError, Stage: stage, Message: "record could not be decoded", Err: err}
}

func applyEnvelope(record *tracepoint.Record, e envelope) {
	record.Timestamp, record.CPU, record.PID, record.TID = e.Timestamp, e.CPU, e.PID, e.TID
}

func perfRecordName(typ uint32) string {
	names := map[uint32]string{
		1: "PERF_RECORD_MMAP", 2: "PERF_RECORD_LOST", 3: "PERF_RECORD_COMM",
		4: "PERF_RECORD_EXIT", 5: "PERF_RECORD_THROTTLE", 6: "PERF_RECORD_UNTHROTTLE",
		7: "PERF_RECORD_FORK", 9: "PERF_RECORD_SAMPLE", 10: "PERF_RECORD_MMAP2",
		13: "PERF_RECORD_LOST_SAMPLES", 14: "PERF_RECORD_SWITCH", 15: "PERF_RECORD_SWITCH_CPU_WIDE",
		64: "PERF_RECORD_HEADER_ATTR", 66: "PERF_RECORD_HEADER_TRACING_DATA",
		68: "PERF_RECORD_FINISHED_ROUND", 71: "PERF_RECORD_AUXTRACE",
		80: "PERF_RECORD_HEADER_FEATURE", 82: "PERF_RECORD_FINISHED_INIT",
	}
	if name := names[typ]; name != "" {
		return name
	}
	return fmt.Sprintf("PERF_RECORD_%d", typ)
}

func terminated(b []byte) (string, bool) {
	if at := strings.IndexByte(string(b), 0); at >= 0 {
		return string(b[:at]), true
	}
	return "", false
}

func some[T any](v T) tracepoint.Optional[T] { return tracepoint.Optional[T]{Value: v, Present: true} }

type wireCursor struct {
	data  []byte
	pos   int
	order interface {
		Uint32([]byte) uint32
		Uint64([]byte) uint64
	}
}

func (c *wireCursor) remaining() int { return len(c.data) - c.pos }
func (c *wireCursor) u32() (uint32, error) {
	if c.pos < 0 || c.remaining() < 4 {
		return 0, tracepoint.ErrTruncated
	}
	v := c.order.Uint32(c.data[c.pos:])
	c.pos += 4
	return v, nil
}
func (c *wireCursor) u64() (uint64, error) {
	if c.pos < 0 || c.remaining() < 8 {
		return 0, tracepoint.ErrTruncated
	}
	v := c.order.Uint64(c.data[c.pos:])
	c.pos += 8
	return v, nil
}
func (c *wireCursor) pair32() (uint32, uint32, error) {
	a, e := c.u32()
	if e != nil {
		return 0, 0, e
	}
	b, e := c.u32()
	return a, b, e
}
func (c *wireCursor) optional64() (tracepoint.Optional[uint64], error) {
	v, e := c.u64()
	if e != nil {
		return tracepoint.Optional[uint64]{}, e
	}
	return some(v), nil
}

func (r *Reader) fatal(stage string, err error) error { return r.fatalAt(r.offset, stage, err) }
func (r *Reader) fatalAt(offset int64, stage string, err error) error {
	return &DecodeError{Offset: offset, RecordIndex: r.index, Stage: stage, Err: err}
}
