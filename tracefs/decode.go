package tracefs

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/cataggar/LinuxTracepoints-Go/tracepoint"
)

const defaultMaxArrayElements = 4096

// DecodeOptions supplies source metadata which is not present in an ordinary
// tracefs event payload. ByteOrder and LongSize must be set explicitly.
type DecodeOptions struct {
	// ByteOrder is the explicit source byte order.
	ByteOrder tracepoint.ByteOrder
	// LongSize is the explicit source sizeof(long), either 4 or 8.
	LongSize int
	// Timestamp supplies the enclosing record timestamp.
	Timestamp tracepoint.Timestamp
	// CPU supplies the enclosing record CPU.
	CPU tracepoint.Optional[uint32]
	// PID supplies the enclosing record process ID.
	PID tracepoint.Optional[int32]
	// TID supplies the enclosing record thread ID.
	TID tracepoint.Optional[int32]
	// MaxArrayElements limits decoded array values; zero selects 4096.
	MaxArrayElements int
}

// Decode decodes one ordinary tracefs event payload. The returned Record.Raw,
// Field.Value.Raw, and binary values borrow data. They remain valid only while
// the input remains unchanged; use tracepoint.CloneRecord for ownership.
//
// A malformed individual field is returned as an invalid value with a
// diagnostic, allowing unrelated fields to decode. Errors are reserved for
// invalid decoder configuration or metadata.
func Decode(format *Format, data []byte, options DecodeOptions) (tracepoint.Record, error) {
	record := tracepoint.Record{Kind: tracepoint.RecordEvent, Raw: data}
	if format == nil {
		return record, &tracepoint.DecodeError{Offset: 0, Stage: "metadata", Err: fmt.Errorf("%w: nil format", tracepoint.ErrInvalid)}
	}
	if options.ByteOrder != tracepoint.ByteOrderLittle && options.ByteOrder != tracepoint.ByteOrderBig {
		return record, &tracepoint.DecodeError{Offset: 0, Stage: "options", Err: fmt.Errorf("%w: byte order is required", tracepoint.ErrInvalid)}
	}
	if options.LongSize != 4 && options.LongSize != 8 {
		return record, &tracepoint.DecodeError{Offset: 0, Stage: "options", Err: fmt.Errorf("%w: long size must be 4 or 8", tracepoint.ErrInvalid)}
	}
	if format.LongSize != options.LongSize {
		return record, &tracepoint.DecodeError{Offset: 0, Stage: "options", Err: fmt.Errorf("%w: decoder long size %d differs from format long size %d", tracepoint.ErrInvalid, options.LongSize, format.LongSize)}
	}
	maxArray := options.MaxArrayElements
	if maxArray == 0 {
		maxArray = defaultMaxArrayElements
	}
	if maxArray < 0 {
		return record, &tracepoint.DecodeError{Offset: 0, Stage: "options", Err: fmt.Errorf("%w: negative array limit", tracepoint.ErrInvalid)}
	}

	record.Identity = tracepoint.Identity{System: format.System, Name: format.Name, ID: format.ID}
	record.Timestamp = options.Timestamp
	record.CPU = options.CPU
	record.PID = options.PID
	record.TID = options.TID
	event := &tracepoint.EventRecord{}
	record.Event = event
	event.Common = decodeFields(format.Common, data, options.ByteOrder, maxArray, &record.Diagnostics)
	event.Fields = decodeFields(format.Fields, data, options.ByteOrder, maxArray, &record.Diagnostics)
	return record, nil
}

// Decode decodes data using f.
func (f *Format) Decode(data []byte, options DecodeOptions) (tracepoint.Record, error) {
	return Decode(f, data, options)
}

func decodeFields(formats []FieldFormat, data []byte, order tracepoint.ByteOrder, maxArray int, recordDiagnostics *[]tracepoint.Diagnostic) []tracepoint.Field {
	fields := make([]tracepoint.Field, len(formats))
	for i := range formats {
		field := tracepoint.Field{Name: formats[i].Name, Offset: formats[i].Offset}
		value, diagnostic := decodeField(formats[i], data, order, maxArray)
		field.Value = value
		if diagnostic != nil {
			field.Diagnostics = []tracepoint.Diagnostic{*diagnostic}
			field.Value.Diagnostics = []tracepoint.Diagnostic{*diagnostic}
			*recordDiagnostics = append(*recordDiagnostics, *diagnostic)
		}
		fields[i] = field
	}
	return fields
}

func decodeField(field FieldFormat, data []byte, order tracepoint.ByteOrder, maxArray int) (tracepoint.Value, *tracepoint.Diagnostic) {
	value := tracepoint.Value{
		Kind:      tracepoint.ValueNull,
		ByteOrder: order,
		Format:    field.Declaration,
		Width:     width32(field.Width),
	}
	raw, err := fieldBytes(field, data)
	if err != nil {
		return value, fieldDiagnostic(field, err)
	}
	value.Raw = raw
	if field.Location != LocationNone {
		return decodeLocation(field, data, raw, order, maxArray)
	}
	return decodeDirect(field, raw, order, maxArray)
}

func fieldBytes(field FieldFormat, data []byte) ([]byte, error) {
	if field.Offset < 0 || field.Offset > len(data) {
		return nil, fmt.Errorf("%w: field %q starts at %d in %d-byte record", tracepoint.ErrTruncated, field.Name, field.Offset, len(data))
	}
	size := field.Size
	if size == 0 {
		size = len(data) - field.Offset
	}
	if size < 0 || size > len(data)-field.Offset {
		return nil, fmt.Errorf("%w: field %q needs %d bytes at %d", tracepoint.ErrTruncated, field.Name, size, field.Offset)
	}
	return data[field.Offset : field.Offset+size], nil
}

func decodeLocation(field FieldFormat, data, descriptor []byte, order tracepoint.ByteOrder, maxArray int) (tracepoint.Value, *tracepoint.Diagnostic) {
	value := tracepoint.Value{
		Kind:      tracepoint.ValueNull,
		ByteOrder: order,
		Format:    field.Declaration,
		Width:     width32(field.Size),
		Raw:       descriptor,
	}
	var offset, length int
	switch len(descriptor) {
	case 2:
		offset = int(readUint(descriptor, order))
		if field.Location == LocationRelative {
			if offset > math.MaxInt-field.Offset-field.Size {
				return value, fieldDiagnostic(field, fmt.Errorf("%w: relative location overflows", tracepoint.ErrInvalid))
			}
			offset += field.Offset + field.Size
		}
		if offset < 0 || offset > len(data) {
			return value, fieldDiagnostic(field, fmt.Errorf("%w: dynamic offset %d outside %d-byte record", tracepoint.ErrTruncated, offset, len(data)))
		}
		nul := indexNUL(data[offset:])
		if nul < 0 {
			return value, fieldDiagnostic(field, fmt.Errorf("%w: 2-byte dynamic value has no NUL terminator", tracepoint.ErrTruncated))
		}
		length = nul + 1
	case 4:
		location := readUint(descriptor, order)
		offset = int(location & 0xffff)
		length = int(location >> 16)
		if field.Location == LocationRelative {
			if offset > math.MaxInt-field.Offset-field.Size {
				return value, fieldDiagnostic(field, fmt.Errorf("%w: relative location overflows", tracepoint.ErrInvalid))
			}
			offset += field.Offset + field.Size
		}
	default:
		return value, fieldDiagnostic(field, fmt.Errorf("%w: dynamic descriptor is %d bytes", tracepoint.ErrInvalid, len(descriptor)))
	}
	if offset < 0 || offset > len(data) || length < 0 || length > len(data)-offset {
		return value, fieldDiagnostic(field, fmt.Errorf("%w: dynamic range [%d,%d) outside %d-byte record", tracepoint.ErrTruncated, offset, offset+length, len(data)))
	}
	dynamicField := field
	dynamicField.Offset = offset
	dynamicField.Size = length
	dynamicField.Location = LocationNone
	value, diagnostic := decodeDirect(dynamicField, data[offset:offset+length], order, maxArray)
	if field.Location == LocationData {
		value.Encoding = tracepoint.EncodingDataLoc
	} else {
		value.Encoding = tracepoint.EncodingRelLoc
	}
	value.Format = field.Declaration
	return value, diagnostic
}

func decodeDirect(field FieldFormat, raw []byte, order tracepoint.ByteOrder, maxArray int) (tracepoint.Value, *tracepoint.Diagnostic) {
	base := tracepoint.Value{
		Raw:       raw,
		ByteOrder: order,
		Format:    field.Declaration,
		Width:     width32(field.Width),
	}
	if field.Kind == FieldOpaque {
		base.Kind = tracepoint.ValueBinary
		base.Binary = raw
		base.Encoding = tracepoint.EncodingBinary
		base.Width = width32(len(raw))
		base.Valid = true
		return base, nil
	}
	if field.Kind == FieldChar && (field.ArrayLen >= 0 || field.Location != LocationNone) {
		base.Kind = tracepoint.ValueText
		base.Encoding = tracepoint.EncodingUTF8
		if nul := indexNUL(raw); nul >= 0 {
			raw = raw[:nul]
		}
		base.Text = string(raw)
		base.Width = 8
		base.Valid = true
		return base, nil
	}
	if field.ArrayLen >= 0 {
		count := field.ArrayLen
		if count == 0 {
			if field.Width <= 0 || len(raw)%field.Width != 0 {
				return base, fieldDiagnostic(field, fmt.Errorf("%w: flexible array size %d is not divisible by width %d", tracepoint.ErrInvalid, len(raw), field.Width))
			}
			count = len(raw) / field.Width
		}
		if count > maxArray {
			return base, fieldDiagnostic(field, fmt.Errorf("%w: array has %d elements, maximum is %d", tracepoint.ErrLimit, count, maxArray))
		}
		if field.Width <= 0 || count > math.MaxInt/field.Width || count*field.Width != len(raw) {
			return base, fieldDiagnostic(field, fmt.Errorf("%w: array declaration and size disagree", tracepoint.ErrInvalid))
		}
		base.Kind = tracepoint.ValueArray
		base.Encoding = tracepoint.EncodingArray
		base.Width = width32(len(raw))
		base.Array = make([]tracepoint.Value, count)
		element := field
		element.ArrayLen = -1
		element.Size = field.Width
		for i := 0; i < count; i++ {
			item, diagnostic := decodeScalar(element, raw[i*field.Width:(i+1)*field.Width], order)
			if diagnostic != nil {
				return base, diagnostic
			}
			base.Array[i] = item
		}
		base.Valid = true
		return base, nil
	}
	return decodeScalar(field, raw, order)
}

func decodeScalar(field FieldFormat, raw []byte, order tracepoint.ByteOrder) (tracepoint.Value, *tracepoint.Diagnostic) {
	value := tracepoint.Value{
		Raw:       raw,
		ByteOrder: order,
		Format:    field.Declaration,
		Width:     width32(len(raw)),
	}
	width := field.Width
	if width == 0 {
		width = len(raw)
	}
	if len(raw) != width {
		return value, fieldDiagnostic(field, fmt.Errorf("%w: %s field is %d bytes, declaration requires %d", tracepoint.ErrInvalid, field.Name, len(raw), width))
	}
	if width != 1 && width != 2 && width != 4 && width != 8 {
		return value, fieldDiagnostic(field, fmt.Errorf("%w: %d-byte scalar", tracepoint.ErrUnsupported, width))
	}
	kind := field.Kind
	if field.SignedSet && field.Kind != FieldFloat && field.Kind != FieldBool {
		if field.Signed {
			kind = FieldSigned
		} else {
			kind = FieldUnsigned
		}
	}
	switch kind {
	case FieldUnsigned:
		value.Kind = tracepoint.ValueUnsigned
		value.Unsigned = readUint(raw, order)
		value.Encoding = tracepoint.EncodingInteger
	case FieldSigned:
		value.Kind = tracepoint.ValueSigned
		value.Signed = signExtend(readUint(raw, order), width)
		value.Encoding = tracepoint.EncodingInteger
	case FieldChar:
		value.Kind = tracepoint.ValueSigned
		value.Signed = signExtend(readUint(raw, order), width)
		value.Encoding = tracepoint.EncodingInteger
	case FieldFloat:
		value.Kind = tracepoint.ValueFloat
		value.Encoding = tracepoint.EncodingFloat
		if width == 4 {
			value.Float = float64(math.Float32frombits(uint32(readUint(raw, order))))
		} else {
			value.Float = math.Float64frombits(readUint(raw, order))
		}
	case FieldBool:
		value.Kind = tracepoint.ValueBool
		value.Bool = readUint(raw, order) != 0
		value.Encoding = tracepoint.EncodingBoolean
	default:
		return value, fieldDiagnostic(field, fmt.Errorf("%w: scalar type", tracepoint.ErrUnsupported))
	}
	value.Valid = true
	return value, nil
}

func readUint(data []byte, order tracepoint.ByteOrder) uint64 {
	switch len(data) {
	case 1:
		return uint64(data[0])
	case 2:
		if order == tracepoint.ByteOrderLittle {
			return uint64(binary.LittleEndian.Uint16(data))
		}
		return uint64(binary.BigEndian.Uint16(data))
	case 4:
		if order == tracepoint.ByteOrderLittle {
			return uint64(binary.LittleEndian.Uint32(data))
		}
		return uint64(binary.BigEndian.Uint32(data))
	case 8:
		if order == tracepoint.ByteOrderLittle {
			return binary.LittleEndian.Uint64(data)
		}
		return binary.BigEndian.Uint64(data)
	default:
		return 0
	}
}

func signExtend(value uint64, width int) int64 {
	shift := uint(64 - width*8)
	return int64(value<<shift) >> shift
}

func indexNUL(data []byte) int {
	for i, b := range data {
		if b == 0 {
			return i
		}
	}
	return -1
}

func width32(bytes int) uint32 {
	if bytes <= 0 {
		return 0
	}
	if uint64(bytes) > math.MaxUint32/8 {
		return math.MaxUint32
	}
	return uint32(bytes * 8)
}

func fieldDiagnostic(field FieldFormat, err error) *tracepoint.Diagnostic {
	decodeErr := &tracepoint.DecodeError{Offset: field.Offset, Stage: "field " + field.Name, Err: err}
	return &tracepoint.Diagnostic{
		Severity: tracepoint.SeverityError,
		Offset:   field.Offset,
		Stage:    "field " + field.Name,
		Message:  "field could not be decoded",
		Err:      decodeErr,
	}
}
