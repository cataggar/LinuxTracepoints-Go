package perfdata

import (
	"bytes"
	"fmt"
	"math"
	"strconv"

	"github.com/cataggar/LinuxTracepoints-Go/tracefs"
	"github.com/cataggar/LinuxTracepoints-Go/tracepoint"
)

var tracingSignature = []byte{23, 8, 68, 't', 'r', 'a', 'c', 'i', 'n', 'g'}

func (r *Reader) parseTracingData(data []byte) error {
	if len(data) < len(tracingSignature) || !bytes.Equal(data[:len(tracingSignature)], tracingSignature) {
		return fmt.Errorf("%w: invalid tracing-data signature", tracepoint.ErrInvalid)
	}
	t := TracingData{Raw: data}
	pos := len(tracingSignature)
	version, next, ok := nulString(data, pos)
	if !ok {
		return fmt.Errorf("%w: tracing-data version", tracepoint.ErrTruncated)
	}
	t.Version, pos = version, next
	if len(data)-pos < 6 {
		return fmt.Errorf("%w: tracing-data source description", tracepoint.ErrTruncated)
	}
	switch data[pos] {
	case 0:
		t.ByteOrder = tracepoint.ByteOrderLittle
	case 1:
		t.ByteOrder = tracepoint.ByteOrderBig
	default:
		return fmt.Errorf("%w: tracing-data endian marker %d", tracepoint.ErrInvalid, data[pos])
	}
	pos++
	t.LongSize = int(data[pos])
	pos++
	if t.LongSize != 4 && t.LongSize != 8 {
		return fmt.Errorf("%w: tracing-data long size %d", tracepoint.ErrInvalid, t.LongSize)
	}
	dataOrder := orderFor(t.ByteOrder)
	t.PageSize = dataOrder.Uint32(data[pos:])
	pos += 4
	if t.PageSize == 0 {
		return fmt.Errorf("%w: tracing-data page size is zero", tracepoint.ErrInvalid)
	}
	var err error
	t.HeaderPage, pos, err = readNamed64(data, pos, "header_page\x00", dataOrder, r.limits.MaxFeatureBytes)
	if err != nil {
		return err
	}
	t.HeaderEvent, pos, err = readNamed64(data, pos, "header_event\x00", dataOrder, r.limits.MaxFeatureBytes)
	if err != nil {
		return err
	}
	if len(data)-pos < 4 {
		return fmt.Errorf("%w: tracing-data ftrace count", tracepoint.ErrTruncated)
	}
	ftraceCount := dataOrder.Uint32(data[pos:])
	pos += 4
	if uint64(ftraceCount) > uint64((len(data)-pos)/8) || uint64(ftraceCount) > uint64(r.limits.MaxAttrs) {
		return fmt.Errorf("%w: tracing-data ftrace count", tracepoint.ErrLimit)
	}
	t.Ftrace = make([][]byte, ftraceCount)
	for i := range t.Ftrace {
		t.Ftrace[i], pos, err = readBlock(data, pos, 8, dataOrder, r.limits.MaxFeatureBytes)
		if err != nil {
			return fmt.Errorf("ftrace format %d: %w", i, err)
		}
		format, parseErr := tracefs.ParseFormat(t.Ftrace[i], tracefs.ParseOptions{System: "ftrace", LongSize: t.LongSize, MaxFormatBytes: r.limits.MaxFormatBytes, MaxFields: r.limits.MaxFormatFields})
		if parseErr != nil {
			return fmt.Errorf("ftrace format %d: %w", i, parseErr)
		}
		if old := r.formats[format.ID]; old != nil {
			return fmt.Errorf("%w: duplicate tracefs format ID %d", tracepoint.ErrInvalid, format.ID)
		}
		r.formats[format.ID] = format
	}
	if len(data)-pos < 4 {
		return fmt.Errorf("%w: tracing-data system count", tracepoint.ErrTruncated)
	}
	systemCount := dataOrder.Uint32(data[pos:])
	pos += 4
	if uint64(systemCount) > uint64(r.limits.MaxAttrs) {
		return fmt.Errorf("%w: too many tracing-data systems", tracepoint.ErrLimit)
	}
	formatCount := 0
	for i := uint32(0); i < systemCount; i++ {
		system, n, ok := nulString(data, pos)
		if !ok {
			return fmt.Errorf("%w: tracing-data system name", tracepoint.ErrTruncated)
		}
		pos = n
		if len(data)-pos < 4 {
			return fmt.Errorf("%w: tracing-data event count", tracepoint.ErrTruncated)
		}
		eventCount := dataOrder.Uint32(data[pos:])
		pos += 4
		if uint64(eventCount) > uint64(r.limits.MaxAttrs-formatCount) {
			return fmt.Errorf("%w: too many tracing formats", tracepoint.ErrLimit)
		}
		for j := uint32(0); j < eventCount; j++ {
			var formatBytes []byte
			formatBytes, pos, err = readBlock(data, pos, 8, dataOrder, r.limits.MaxFeatureBytes)
			if err != nil {
				return fmt.Errorf("tracing format %s/%d: %w", system, j, err)
			}
			format, parseErr := tracefs.ParseFormat(formatBytes, tracefs.ParseOptions{System: system, LongSize: t.LongSize, MaxFormatBytes: r.limits.MaxFormatBytes, MaxFields: r.limits.MaxFormatFields})
			if parseErr != nil {
				return fmt.Errorf("tracing format %s/%d: %w", system, j, parseErr)
			}
			if old := r.formats[format.ID]; old != nil {
				return fmt.Errorf("%w: duplicate tracefs format ID %d", tracepoint.ErrInvalid, format.ID)
			}
			r.formats[format.ID] = format
			formatCount++
		}
	}
	t.Kallsyms, pos, err = readBlock(data, pos, 4, dataOrder, r.limits.MaxFeatureBytes)
	if err != nil {
		return fmt.Errorf("tracing kallsyms: %w", err)
	}
	t.Printk, pos, err = readBlock(data, pos, 4, dataOrder, r.limits.MaxFeatureBytes)
	if err != nil {
		return fmt.Errorf("tracing printk: %w", err)
	}
	if versionAtLeast06(t.Version) {
		t.SavedCmdline, pos, err = readBlock(data, pos, 8, dataOrder, r.limits.MaxFeatureBytes)
		if err != nil {
			return fmt.Errorf("tracing saved_cmdline: %w", err)
		}
	}
	t.Trailing = append([]byte(nil), data[pos:]...)
	r.tracing, r.longSize, r.pageSize = t, t.LongSize, t.PageSize
	r.attachFormats()
	return nil
}

func readNamed64(data []byte, pos int, name string, order uintReader, max int64) ([]byte, int, error) {
	if len(data)-pos < len(name) || string(data[pos:pos+len(name)]) != name {
		return nil, pos, fmt.Errorf("%w: missing tracing-data %q", tracepoint.ErrInvalid, name[:len(name)-1])
	}
	return readBlock(data, pos+len(name), 8, order, max)
}

type uintReader interface {
	Uint32([]byte) uint32
	Uint64([]byte) uint64
}

func readBlock(data []byte, pos, width int, order interface {
	Uint32([]byte) uint32
	Uint64([]byte) uint64
}, max int64) ([]byte, int, error) {
	if pos < 0 || width > len(data)-pos {
		return nil, pos, tracepoint.ErrTruncated
	}
	var size uint64
	if width == 4 {
		size = uint64(order.Uint32(data[pos:]))
	} else {
		size = order.Uint64(data[pos:])
	}
	pos += width
	if size > uint64(max) {
		return nil, pos, tracepoint.ErrLimit
	}
	if size > uint64(len(data)-pos) || size > uint64(math.MaxInt) {
		return nil, pos, tracepoint.ErrTruncated
	}
	out := data[pos : pos+int(size)]
	return out, pos + int(size), nil
}

func nulString(data []byte, pos int) (string, int, bool) {
	if pos < 0 || pos > len(data) {
		return "", pos, false
	}
	at := bytes.IndexByte(data[pos:], 0)
	if at < 0 {
		return "", pos, false
	}
	return string(data[pos : pos+at]), pos + at + 1, true
}

func versionAtLeast06(version string) bool {
	value, err := strconv.ParseFloat(version, 64)
	return err == nil && value >= 0.6
}

func orderFor(order tracepoint.ByteOrder) uintReader {
	if order == tracepoint.ByteOrderBig {
		return bigOrder{}
	}
	return littleOrder{}
}

type littleOrder struct{}

func (littleOrder) Uint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
func (littleOrder) Uint64(b []byte) uint64 {
	return uint64(littleOrder{}.Uint32(b)) | uint64(littleOrder{}.Uint32(b[4:]))<<32
}

type bigOrder struct{}

func (bigOrder) Uint32(b []byte) uint32 {
	return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
}
func (bigOrder) Uint64(b []byte) uint64 {
	return uint64(bigOrder{}.Uint32(b[4:])) | uint64(bigOrder{}.Uint32(b))<<32
}

func (r *Reader) attachFormats() {
	for _, d := range r.attrs {
		if d.attr.Type == 2 {
			d.format = r.formats[uint32(d.attr.Config)]
		}
	}
}
