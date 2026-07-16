package eventheader

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"unicode/utf8"
)

// Binding is the goroutine-local payload state for one immutable Schema. It is
// reusable after Reset and is not safe for concurrent mutation.
type Binding struct {
	schema  *Schema
	payload []byte
	index   int
}

// NewBinding creates an empty binding using storage as retained payload
// capacity.
func NewBinding(schema *Schema, storage []byte) Binding {
	return Binding{schema: schema, payload: storage[:0]}
}

// Bind creates an empty binding for this schema.
func (s *Schema) Bind(storage []byte) Binding {
	return NewBinding(s, storage)
}

// Reset removes bound values while retaining the schema and payload storage.
func (b *Binding) Reset() {
	if b == nil {
		return
	}
	b.payload = b.payload[:0]
	b.index = 0
}

// Complete verifies that every schema value has been supplied exactly once.
func (b *Binding) Complete() error {
	if b == nil || b.schema == nil {
		return fmt.Errorf("%w: binding has no schema", ErrState)
	}
	if b.index != len(b.schema.plan) {
		return fmt.Errorf("%w: binding has %d of %d values", ErrState, b.index, len(b.schema.plan))
	}
	return nil
}

func (b *Binding) begin(kind valueKind, array bool, count, dataSize int) ([]byte, error) {
	if err := b.check(kind, array, count); err != nil {
		return nil, err
	}
	plan := b.schema.plan[b.index]
	prefixSize := 0
	if plan.arrayKind == ArrayVariable {
		prefixSize = 2
	}
	if dataSize < 0 || dataSize > maxMetadataPayload-prefixSize-len(b.payload) ||
		len(b.schema.metadata)+len(b.payload)+prefixSize+dataSize > maxMetadataPayload {
		return nil, ErrEventTooLarge
	}

	oldLength := len(b.payload)
	newLength := oldLength + prefixSize + dataSize
	if newLength > cap(b.payload) {
		payload := make([]byte, newLength)
		copy(payload, b.payload)
		b.payload = payload
	} else {
		b.payload = b.payload[:newLength]
	}
	if prefixSize != 0 {
		nativeEndian.PutUint16(b.payload[oldLength:oldLength+2], uint16(count))
	}
	b.index++
	return b.payload[oldLength+prefixSize : newLength], nil
}

func (b *Binding) check(kind valueKind, array bool, count int) error {
	if b == nil || b.schema == nil {
		return fmt.Errorf("%w: binding has no schema", ErrState)
	}
	if b.index >= len(b.schema.plan) {
		return fmt.Errorf("%w: binding has too many values", ErrState)
	}
	plan := b.schema.plan[b.index]
	if plan.kind != kind {
		return fmt.Errorf("%w: value %d has the wrong type", ErrState, b.index)
	}
	if array != (plan.arrayKind != ArrayScalar) {
		return fmt.Errorf("%w: value %d has the wrong scalar/array shape", ErrState, b.index)
	}
	if !array {
		return nil
	}
	if count > maxCount {
		return ErrCountTooLarge
	}
	if plan.arrayKind == ArrayFixed && count != int(plan.arrayCount) {
		return fmt.Errorf("%w: fixed array has %d values; expected %d", ErrInvalidValue, count, plan.arrayCount)
	}
	return nil
}

func (b *Binding) Int8(value int8) error {
	data, err := b.begin(valueInt8, false, 1, 1)
	if err == nil {
		data[0] = byte(value)
	}
	return err
}

func (b *Binding) Uint8(value uint8) error {
	data, err := b.begin(valueUint8, false, 1, 1)
	if err == nil {
		data[0] = value
	}
	return err
}

func (b *Binding) Int16(value int16) error {
	data, err := b.begin(valueInt16, false, 1, 2)
	if err == nil {
		nativeEndian.PutUint16(data, uint16(value))
	}
	return err
}

func (b *Binding) Uint16(value uint16) error {
	data, err := b.begin(valueUint16, false, 1, 2)
	if err == nil {
		nativeEndian.PutUint16(data, value)
	}
	return err
}

func (b *Binding) Int32(value int32) error {
	data, err := b.begin(valueInt32, false, 1, 4)
	if err == nil {
		nativeEndian.PutUint32(data, uint32(value))
	}
	return err
}

func (b *Binding) Uint32(value uint32) error {
	data, err := b.begin(valueUint32, false, 1, 4)
	if err == nil {
		nativeEndian.PutUint32(data, value)
	}
	return err
}

func (b *Binding) Int64(value int64) error {
	data, err := b.begin(valueInt64, false, 1, 8)
	if err == nil {
		nativeEndian.PutUint64(data, uint64(value))
	}
	return err
}

func (b *Binding) Uint64(value uint64) error {
	data, err := b.begin(valueUint64, false, 1, 8)
	if err == nil {
		nativeEndian.PutUint64(data, value)
	}
	return err
}

func (b *Binding) Bool(value bool) error {
	data, err := b.begin(valueBool, false, 1, 1)
	if err == nil {
		data[0] = 0
		if value {
			data[0] = 1
		}
	}
	return err
}

func (b *Binding) Float32(value float32) error {
	data, err := b.begin(valueFloat32, false, 1, 4)
	if err == nil {
		nativeEndian.PutUint32(data, math.Float32bits(value))
	}
	return err
}

func (b *Binding) Float64(value float64) error {
	data, err := b.begin(valueFloat64, false, 1, 8)
	if err == nil {
		nativeEndian.PutUint64(data, math.Float64bits(value))
	}
	return err
}

func (b *Binding) Uintptr(value uintptr) error {
	size := strconv.IntSize / 8
	data, err := b.begin(valueUintptr, false, 1, size)
	if err == nil {
		if size == 8 {
			nativeEndian.PutUint64(data, uint64(value))
		} else {
			nativeEndian.PutUint32(data, uint32(value))
		}
	}
	return err
}

func (b *Binding) UUID(value [16]byte) error {
	data, err := b.begin(valueUUID, false, 1, len(value))
	if err == nil {
		copy(data, value[:])
	}
	return err
}

func (b *Binding) IPv4(value [4]byte) error {
	data, err := b.begin(valueIPv4, false, 1, len(value))
	if err == nil {
		copy(data, value[:])
	}
	return err
}

func (b *Binding) IPv6(value [16]byte) error {
	data, err := b.begin(valueIPv6, false, 1, len(value))
	if err == nil {
		copy(data, value[:])
	}
	return err
}

func (b *Binding) Port(value uint16) error {
	data, err := b.begin(valuePort, false, 1, 2)
	if err == nil {
		binary.BigEndian.PutUint16(data, value)
	}
	return err
}

func (b *Binding) String(value string) error {
	if err := b.check(valueString, false, 1); err != nil {
		return err
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: string is not valid UTF-8", ErrInvalidValue)
	}
	if len(value) > maxCount {
		return ErrCountTooLarge
	}
	data, err := b.begin(valueString, false, 1, 2+len(value))
	if err == nil {
		nativeEndian.PutUint16(data, uint16(len(value)))
		copy(data[2:], value)
	}
	return err
}

func (b *Binding) UTF16(value []uint16) error {
	if err := b.check(valueUTF16, false, 1); err != nil {
		return err
	}
	if len(value) > maxCount {
		return ErrCountTooLarge
	}
	data, err := b.begin(valueUTF16, false, 1, 2+len(value)*2)
	if err == nil {
		nativeEndian.PutUint16(data, uint16(len(value)))
		for i, unit := range value {
			nativeEndian.PutUint16(data[2+i*2:], unit)
		}
	}
	return err
}

func (b *Binding) Binary(value []byte) error {
	if err := b.check(valueBinary, false, 1); err != nil {
		return err
	}
	if len(value) > maxCount {
		return ErrCountTooLarge
	}
	data, err := b.begin(valueBinary, false, 1, 2+len(value))
	if err == nil {
		nativeEndian.PutUint16(data, uint16(len(value)))
		copy(data[2:], value)
	}
	return err
}

func (b *Binding) Int8Array(values []int8) error {
	data, err := b.begin(valueInt8, true, len(values), len(values))
	if err == nil {
		for i, value := range values {
			data[i] = byte(value)
		}
	}
	return err
}

func (b *Binding) Uint8Array(values []uint8) error {
	data, err := b.begin(valueUint8, true, len(values), len(values))
	if err == nil {
		copy(data, values)
	}
	return err
}

func (b *Binding) Int16Array(values []int16) error {
	data, err := b.begin(valueInt16, true, len(values), len(values)*2)
	if err == nil {
		for i, value := range values {
			nativeEndian.PutUint16(data[i*2:], uint16(value))
		}
	}
	return err
}

func (b *Binding) Uint16Array(values []uint16) error {
	data, err := b.begin(valueUint16, true, len(values), len(values)*2)
	if err == nil {
		for i, value := range values {
			nativeEndian.PutUint16(data[i*2:], value)
		}
	}
	return err
}

func (b *Binding) Int32Array(values []int32) error {
	data, err := b.begin(valueInt32, true, len(values), len(values)*4)
	if err == nil {
		for i, value := range values {
			nativeEndian.PutUint32(data[i*4:], uint32(value))
		}
	}
	return err
}

func (b *Binding) Uint32Array(values []uint32) error {
	data, err := b.begin(valueUint32, true, len(values), len(values)*4)
	if err == nil {
		for i, value := range values {
			nativeEndian.PutUint32(data[i*4:], value)
		}
	}
	return err
}

func (b *Binding) Int64Array(values []int64) error {
	data, err := b.begin(valueInt64, true, len(values), len(values)*8)
	if err == nil {
		for i, value := range values {
			nativeEndian.PutUint64(data[i*8:], uint64(value))
		}
	}
	return err
}

func (b *Binding) Uint64Array(values []uint64) error {
	data, err := b.begin(valueUint64, true, len(values), len(values)*8)
	if err == nil {
		for i, value := range values {
			nativeEndian.PutUint64(data[i*8:], value)
		}
	}
	return err
}

func (b *Binding) BoolArray(values []bool) error {
	data, err := b.begin(valueBool, true, len(values), len(values))
	if err == nil {
		for i, value := range values {
			data[i] = 0
			if value {
				data[i] = 1
			}
		}
	}
	return err
}

func (b *Binding) Float32Array(values []float32) error {
	data, err := b.begin(valueFloat32, true, len(values), len(values)*4)
	if err == nil {
		for i, value := range values {
			nativeEndian.PutUint32(data[i*4:], math.Float32bits(value))
		}
	}
	return err
}

func (b *Binding) Float64Array(values []float64) error {
	data, err := b.begin(valueFloat64, true, len(values), len(values)*8)
	if err == nil {
		for i, value := range values {
			nativeEndian.PutUint64(data[i*8:], math.Float64bits(value))
		}
	}
	return err
}

func (b *Binding) UintptrArray(values []uintptr) error {
	size := strconv.IntSize / 8
	data, err := b.begin(valueUintptr, true, len(values), len(values)*size)
	if err == nil {
		for i, value := range values {
			if size == 8 {
				nativeEndian.PutUint64(data[i*size:], uint64(value))
			} else {
				nativeEndian.PutUint32(data[i*size:], uint32(value))
			}
		}
	}
	return err
}

func (b *Binding) UUIDArray(values [][16]byte) error {
	data, err := b.begin(valueUUID, true, len(values), len(values)*16)
	if err == nil {
		for i := range values {
			copy(data[i*16:], values[i][:])
		}
	}
	return err
}

func (b *Binding) IPv4Array(values [][4]byte) error {
	data, err := b.begin(valueIPv4, true, len(values), len(values)*4)
	if err == nil {
		for i := range values {
			copy(data[i*4:], values[i][:])
		}
	}
	return err
}

func (b *Binding) IPv6Array(values [][16]byte) error {
	data, err := b.begin(valueIPv6, true, len(values), len(values)*16)
	if err == nil {
		for i := range values {
			copy(data[i*16:], values[i][:])
		}
	}
	return err
}

func (b *Binding) PortArray(values []uint16) error {
	data, err := b.begin(valuePort, true, len(values), len(values)*2)
	if err == nil {
		for i, value := range values {
			binary.BigEndian.PutUint16(data[i*2:], value)
		}
	}
	return err
}

func (b *Binding) StringArray(values []string) error {
	if err := b.check(valueString, true, len(values)); err != nil {
		return err
	}
	size := 0
	for _, value := range values {
		if !utf8.ValidString(value) {
			return fmt.Errorf("%w: string is not valid UTF-8", ErrInvalidValue)
		}
		if len(value) > maxCount {
			return ErrCountTooLarge
		}
		if len(value)+2 > maxMetadataPayload-size {
			return ErrEventTooLarge
		}
		size += len(value) + 2
	}
	data, err := b.begin(valueString, true, len(values), size)
	if err == nil {
		offset := 0
		for _, value := range values {
			nativeEndian.PutUint16(data[offset:], uint16(len(value)))
			offset += 2
			copy(data[offset:], value)
			offset += len(value)
		}
	}
	return err
}

func (b *Binding) UTF16Array(values [][]uint16) error {
	if err := b.check(valueUTF16, true, len(values)); err != nil {
		return err
	}
	size := 0
	for _, value := range values {
		if len(value) > maxCount {
			return ErrCountTooLarge
		}
		encodedSize := 2 + len(value)*2
		if encodedSize > maxMetadataPayload-size {
			return ErrEventTooLarge
		}
		size += encodedSize
	}
	data, err := b.begin(valueUTF16, true, len(values), size)
	if err == nil {
		offset := 0
		for _, value := range values {
			nativeEndian.PutUint16(data[offset:], uint16(len(value)))
			offset += 2
			for _, unit := range value {
				nativeEndian.PutUint16(data[offset:], unit)
				offset += 2
			}
		}
	}
	return err
}

func (b *Binding) BinaryArray(values [][]byte) error {
	if err := b.check(valueBinary, true, len(values)); err != nil {
		return err
	}
	size := 0
	for _, value := range values {
		if len(value) > maxCount {
			return ErrCountTooLarge
		}
		if len(value)+2 > maxMetadataPayload-size {
			return ErrEventTooLarge
		}
		size += len(value) + 2
	}
	data, err := b.begin(valueBinary, true, len(values), size)
	if err == nil {
		offset := 0
		for _, value := range values {
			nativeEndian.PutUint16(data[offset:], uint16(len(value)))
			offset += 2
			copy(data[offset:], value)
			offset += len(value)
		}
	}
	return err
}
