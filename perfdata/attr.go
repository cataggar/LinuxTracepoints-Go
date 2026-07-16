package perfdata

import (
	"bytes"
	"fmt"
	"math"

	"github.com/cataggar/LinuxTracepoints-Go/tracepoint"
)

func (r *Reader) parseAttr(raw []byte) (Attr, error) {
	if len(raw) < 64 {
		return Attr{}, fmt.Errorf("%w: perf_event_attr is %d bytes, minimum is 64", tracepoint.ErrTruncated, len(raw))
	}
	size := r.order.Uint32(raw[4:8])
	if size == 0 {
		size = 64
	}
	if size < 64 || uint64(size) > uint64(len(raw)) {
		return Attr{}, fmt.Errorf("%w: perf_event_attr size %d outside %d-byte container", tracepoint.ErrInvalid, size, len(raw))
	}
	data := raw[:size]
	a := Attr{
		Type: r.order.Uint32(data[0:4]), Size: size,
		Config: r.order.Uint64(data[8:16]), SamplePeriod: r.order.Uint64(data[16:24]),
		SampleType: r.order.Uint64(data[24:32]), ReadFormat: r.order.Uint64(data[32:40]),
		Raw: append([]byte(nil), data...),
	}
	var flags uint64
	for i, b := range data[40:48] {
		if r.byteOrder == tracepoint.ByteOrderBig {
			b = reverseByte(b)
		}
		flags |= uint64(b) << (8 * i)
	}
	a.Options = flags
	a.SampleIDAll = flags&(1<<18) != 0
	a.UseClockID = flags&(1<<25) != 0
	a.WakeupEvents = r.order.Uint32(data[48:52])
	a.BreakpointType = r.order.Uint32(data[52:56])
	if len(data) >= 64 {
		a.Config1 = r.order.Uint64(data[56:64])
	}
	if len(data) >= 72 {
		a.Config2 = r.order.Uint64(data[64:72])
	}
	if len(data) >= 80 {
		a.BranchSampleType = r.order.Uint64(data[72:80])
	}
	if len(data) >= 96 {
		a.SampleRegsUser = r.order.Uint64(data[80:88])
		a.SampleStackUser = r.order.Uint32(data[88:92])
		a.ClockID = int32(r.order.Uint32(data[92:96]))
	}
	if len(data) >= 104 {
		a.SampleRegsIntr = r.order.Uint64(data[96:104])
	}
	if len(data) >= 112 {
		a.AuxWatermark = r.order.Uint32(data[104:108])
		a.SampleMaxStack = r.order.Uint16(data[108:110])
	}
	if len(data) >= 120 {
		a.AuxSampleSize = r.order.Uint32(data[112:116])
	}
	if len(data) >= 128 {
		a.SigData = r.order.Uint64(data[120:128])
	}
	if len(data) >= 136 {
		a.Config3 = r.order.Uint64(data[128:136])
	}
	if len(data) > 136 {
		a.UnknownTail = append([]byte(nil), data[136:]...)
	}
	return a, nil
}

func reverseByte(x byte) byte {
	x = (x&0x55)<<1 | (x&0xaa)>>1
	x = (x&0x33)<<2 | (x&0xcc)>>2
	return x<<4 | x>>4
}

func (r *Reader) addDescriptor(attr Attr, name string, ids []uint64) error {
	if attr.UseClockID {
		if r.clock.IDKnown && r.clock.ID != attr.ClockID {
			return fmt.Errorf("%w: inconsistent attribute clock IDs", tracepoint.ErrInvalid)
		}
		if !r.clock.IDKnown {
			r.setClockID(attr.ClockID)
		}
	}
	offset := sampleLookupOffset(attr.SampleType)
	suffix := attr.SampleType & (SampleTID | SampleTime | SampleID | SampleStreamID | SampleCPU | SampleIdentifier)
	if !r.layoutSet {
		r.layoutSet, r.sampleIDOffset = true, offset
	} else if r.sampleIDOffset != offset {
		return fmt.Errorf("%w: inconsistent sample ID lookup offset", tracepoint.ErrInvalid)
	}
	if attr.SampleIDAll {
		if r.noSampleIDAll {
			return fmt.Errorf("%w: mixed sample_id_all settings make record suffixes ambiguous", tracepoint.ErrInvalid)
		}
		hasIdentifier := suffix&SampleIdentifier != 0
		if r.suffixLayoutSet {
			if r.suffixMask != suffix {
				if !r.suffixIDAll || !hasIdentifier {
					return fmt.Errorf("%w: inconsistent sample_id_all suffix layout", tracepoint.ErrInvalid)
				}
			}
			r.suffixIDAll = r.suffixIDAll && hasIdentifier
		} else {
			r.suffixIDAll = hasIdentifier
		}
		r.suffixLayoutSet, r.suffixMask, r.sampleIDAll = true, suffix, true
	} else {
		if r.suffixLayoutSet {
			return fmt.Errorf("%w: mixed sample_id_all settings make record suffixes ambiguous", tracepoint.ErrInvalid)
		}
		r.noSampleIDAll = true
	}

	var existing *eventDesc
	for _, id := range ids {
		if d := r.byID[id]; d != nil {
			if !attrsCompatible(d.attr, attr) {
				return fmt.Errorf("%w: incompatible duplicate perf ID %d", tracepoint.ErrInvalid, id)
			}
			if existing != nil && existing != d {
				return fmt.Errorf("%w: IDs merge distinct attributes", tracepoint.ErrInvalid)
			}
			existing = d
		}
	}
	if existing == nil {
		if len(r.attrs) >= r.limits.MaxAttrs {
			return fmt.Errorf("%w: too many attributes", tracepoint.ErrLimit)
		}
		existing = &eventDesc{attr: cloneAttr(attr), name: name}
		r.attrs = append(r.attrs, existing)
	} else if name != "" {
		if existing.name != "" && existing.name != name {
			return fmt.Errorf("%w: incompatible names for duplicate perf ID", tracepoint.ErrInvalid)
		}
		existing.name = name
	}
	seen := make(map[uint64]bool, len(existing.ids))
	for _, id := range existing.ids {
		seen[id] = true
	}
	for _, id := range ids {
		if !seen[id] {
			if len(r.byID) >= r.limits.MaxIDs {
				return fmt.Errorf("%w: too many IDs", tracepoint.ErrLimit)
			}
			existing.ids = append(existing.ids, id)
			seen[id] = true
		}
		r.byID[id] = existing
	}
	return nil
}

func attrsCompatible(a, b Attr) bool {
	return a.Type == b.Type && a.Config == b.Config && a.SampleType == b.SampleType &&
		a.ReadFormat == b.ReadFormat && a.Options == b.Options &&
		a.WakeupEvents == b.WakeupEvents && a.BreakpointType == b.BreakpointType &&
		a.Config1 == b.Config1 && a.Config2 == b.Config2 &&
		a.BranchSampleType == b.BranchSampleType &&
		a.SampleRegsUser == b.SampleRegsUser && a.SampleStackUser == b.SampleStackUser &&
		a.SampleRegsIntr == b.SampleRegsIntr && a.AuxWatermark == b.AuxWatermark &&
		a.SampleMaxStack == b.SampleMaxStack && a.AuxSampleSize == b.AuxSampleSize &&
		a.SigData == b.SigData && a.Config3 == b.Config3 &&
		bytes.Equal(a.UnknownTail, b.UnknownTail)
}

func sampleLookupOffset(sampleType uint64) int {
	if sampleType&SampleIdentifier != 0 {
		return 8
	}
	if sampleType&SampleID == 0 {
		return -1
	}
	n := 1
	for _, bit := range []uint64{SampleIP, SampleTID, SampleTime, SampleAddr} {
		if sampleType&bit != 0 {
			n++
		}
	}
	return n * 8
}

func (r *Reader) parseEventDesc(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("%w: EVENT_DESC header", tracepoint.ErrTruncated)
	}
	count, attrSize := r.order.Uint32(data), r.order.Uint32(data[4:])
	if uint64(count) > uint64(r.limits.MaxAttrs) || attrSize < 64 || uint64(attrSize) > uint64(math.MaxInt) {
		return fmt.Errorf("%w: invalid EVENT_DESC counts", tracepoint.ErrLimit)
	}
	pos := 8
	for i := uint32(0); i < count; i++ {
		if int(attrSize) > len(data)-pos || len(data)-pos-int(attrSize) < 8 {
			return fmt.Errorf("%w: EVENT_DESC entry %d", tracepoint.ErrTruncated, i)
		}
		attr, err := r.parseAttr(data[pos : pos+int(attrSize)])
		if err != nil {
			return err
		}
		pos += int(attrSize)
		nids := r.order.Uint32(data[pos:])
		nameSize := r.order.Uint32(data[pos+4:])
		pos += 8
		if nids > uint32(r.limits.MaxIDs) || uint64(nameSize) > uint64(len(data)-pos) {
			return fmt.Errorf("%w: invalid EVENT_DESC entry %d", tracepoint.ErrInvalid, i)
		}
		nameBytes := data[pos : pos+int(nameSize)]
		pos += int(nameSize)
		nul := bytes.IndexByte(nameBytes, 0)
		if nul < 0 {
			return fmt.Errorf("%w: EVENT_DESC name is not NUL-terminated", tracepoint.ErrInvalid)
		}
		if uint64(nids) > uint64((len(data)-pos)/8) {
			return fmt.Errorf("%w: EVENT_DESC IDs", tracepoint.ErrTruncated)
		}
		ids := make([]uint64, nids)
		for j := range ids {
			ids[j] = r.order.Uint64(data[pos+j*8:])
		}
		pos += len(ids) * 8
		if err := r.addDescriptor(attr, string(nameBytes[:nul]), ids); err != nil {
			return err
		}
	}
	return nil
}

func cloneAttr(a Attr) Attr {
	a.Raw = append([]byte(nil), a.Raw...)
	a.UnknownTail = append([]byte(nil), a.UnknownTail...)
	return a
}
