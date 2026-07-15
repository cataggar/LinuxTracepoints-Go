package eventheader

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"unicode/utf8"
)

const (
	maxCount             = math.MaxUint16
	maxMetadataPayload   = 65467
	maxStructDepth       = 8
	maxStructChildFields = 127
)

type structFrame struct {
	formatIndex int
	children    uint8
}

// Builder dynamically constructs one EventHeader event. A Builder is intended
// to be reused by one goroutine and is not safe for concurrent mutation.
//
// The zero value must be initialized with Reset.
type Builder struct {
	metadata []byte
	payload  []byte
	version  uint8
	id       uint16
	tag      EventTag
	opcode   Opcode
	activity ActivityID
	related  ActivityID
	hasAct   bool
	hasRel   bool
	active   bool
	structs  []structFrame
}

// NewBuilder creates a builder initialized with an event name.
func NewBuilder(name string) (*Builder, error) {
	builder := new(Builder)
	if err := builder.Reset(name); err != nil {
		return nil, err
	}
	return builder, nil
}

// Reset clears the previous event while retaining allocated storage.
func (b *Builder) Reset(name string) error {
	if b == nil {
		return ErrState
	}
	if err := validateMetadataName("event", name); err != nil {
		return err
	}
	b.metadata = append(b.metadata[:0], name...)
	b.metadata = append(b.metadata, 0)
	b.payload = b.payload[:0]
	b.version = 0
	b.id = 0
	b.tag = 0
	b.opcode = OpcodeInfo
	b.activity = ActivityID{}
	b.related = ActivityID{}
	b.hasAct = false
	b.hasRel = false
	b.active = true
	b.structs = b.structs[:0]
	return nil
}

// SetVersion sets the event schema version.
func (b *Builder) SetVersion(version uint8) error {
	if err := b.requireActive(); err != nil {
		return err
	}
	b.version = version
	return nil
}

// SetID sets the stable event identifier.
func (b *Builder) SetID(id uint16) error {
	if err := b.requireActive(); err != nil {
		return err
	}
	b.id = id
	return nil
}

// SetIDVersion sets the stable event identifier and schema version.
func (b *Builder) SetIDVersion(id uint16, version uint8) error {
	if err := b.requireActive(); err != nil {
		return err
	}
	b.id, b.version = id, version
	return nil
}

// SetTag sets the provider-defined event tag.
func (b *Builder) SetTag(tag EventTag) error {
	if err := b.requireActive(); err != nil {
		return err
	}
	b.tag = tag
	return nil
}

// SetOpcode sets the event opcode.
func (b *Builder) SetOpcode(opcode Opcode) error {
	if err := b.requireActive(); err != nil {
		return err
	}
	b.opcode = opcode
	return nil
}

// SetActivity sets optional activity and related IDs. A related ID requires an
// activity ID. Activity-start events conventionally use it for a parent ID,
// but the wire format permits related IDs with any opcode.
func (b *Builder) SetActivity(activity *ActivityID, related *ActivityID) error {
	if err := b.requireActive(); err != nil {
		return err
	}
	if related != nil && activity == nil {
		return fmt.Errorf("%w: related ID requires an activity ID", ErrInvalidValue)
	}
	b.hasAct, b.hasRel = activity != nil, related != nil
	b.activity, b.related = ActivityID{}, ActivityID{}
	if activity != nil {
		b.activity = *activity
	}
	if related != nil {
		b.related = *related
	}
	return nil
}

// BeginStruct starts a structure field. EndStruct determines and records its
// number of immediate children.
func (b *Builder) BeginStruct(name string, tag FieldTag) error {
	if err := b.requireActive(); err != nil {
		return err
	}
	if len(b.structs) >= maxStructDepth {
		return ErrNestingTooDeep
	}
	if err := b.canAddChild(); err != nil {
		return err
	}
	if err := validateMetadataName("field", name); err != nil {
		return err
	}

	b.metadata = append(b.metadata, name...)
	b.metadata = append(b.metadata, 0, byte(EncodingStruct|EncodingChainFlag))
	formatIndex := len(b.metadata)
	format := byte(0)
	if tag != 0 {
		format |= byte(FormatChainFlag)
	}
	b.metadata = append(b.metadata, format)
	if tag != 0 {
		b.metadata = appendNative16(b.metadata, uint16(tag))
	}
	b.noteChild()
	b.structs = append(b.structs, structFrame{formatIndex: formatIndex})
	return nil
}

// EndStruct completes the innermost structure.
func (b *Builder) EndStruct() error {
	if err := b.requireActive(); err != nil {
		return err
	}
	if len(b.structs) == 0 {
		return fmt.Errorf("%w: no open struct", ErrState)
	}
	index := len(b.structs) - 1
	frame := b.structs[index]
	if frame.children == 0 {
		return fmt.Errorf("%w: empty struct", ErrState)
	}
	b.metadata[frame.formatIndex] = b.metadata[frame.formatIndex]&byte(FormatChainFlag) | frame.children
	b.structs = b.structs[:index]
	return nil
}

// BeginStructArray reports the phase-2 limitation explicitly.
func (b *Builder) BeginStructArray(string, ArrayKind, FieldTag) error {
	if err := b.requireActive(); err != nil {
		return err
	}
	return ErrStructArrayUnsupported
}

func (b *Builder) Int8(name string, value int8, options ...FieldOptions) error {
	return b.addScalar(name, EncodingValue8, []byte{byte(value)}, FormatSignedInt, options)
}

func (b *Builder) Uint8(name string, value uint8, options ...FieldOptions) error {
	return b.addScalar(name, EncodingValue8, []byte{value}, FormatDefault, options)
}

func (b *Builder) Int16(name string, value int16, options ...FieldOptions) error {
	return b.addScalar(name, EncodingValue16, native16(uint16(value)), FormatSignedInt, options)
}

func (b *Builder) Uint16(name string, value uint16, options ...FieldOptions) error {
	return b.addScalar(name, EncodingValue16, native16(value), FormatDefault, options)
}

func (b *Builder) Int32(name string, value int32, options ...FieldOptions) error {
	return b.addScalar(name, EncodingValue32, native32(uint32(value)), FormatSignedInt, options)
}

func (b *Builder) Uint32(name string, value uint32, options ...FieldOptions) error {
	return b.addScalar(name, EncodingValue32, native32(value), FormatDefault, options)
}

func (b *Builder) Int64(name string, value int64, options ...FieldOptions) error {
	return b.addScalar(name, EncodingValue64, native64(uint64(value)), FormatSignedInt, options)
}

func (b *Builder) Uint64(name string, value uint64, options ...FieldOptions) error {
	return b.addScalar(name, EncodingValue64, native64(value), FormatDefault, options)
}

func (b *Builder) Bool(name string, value bool, options ...FieldOptions) error {
	byteValue := byte(0)
	if value {
		byteValue = 1
	}
	return b.addScalar(name, EncodingValue8, []byte{byteValue}, FormatBoolean, options)
}

func (b *Builder) Float32(name string, value float32, options ...FieldOptions) error {
	return b.addScalar(name, EncodingValue32, native32(math.Float32bits(value)), FormatFloat, options)
}

func (b *Builder) Float64(name string, value float64, options ...FieldOptions) error {
	return b.addScalar(name, EncodingValue64, native64(math.Float64bits(value)), FormatFloat, options)
}

func (b *Builder) Uintptr(name string, value uintptr, options ...FieldOptions) error {
	if strconv.IntSize == 64 {
		return b.addScalar(name, EncodingValue64, native64(uint64(value)), FormatDefault, options)
	}
	return b.addScalar(name, EncodingValue32, native32(uint32(value)), FormatDefault, options)
}

func (b *Builder) UintptrArray(name string, values []uintptr, kind ArrayKind, options ...FieldOptions) error {
	if strconv.IntSize == 64 {
		data := make([]byte, 0, len(values)*8)
		for _, value := range values {
			data = appendNative64(data, uint64(value))
		}
		return b.addArray(name, EncodingValue64, len(values), data, kind, FormatDefault, options)
	}
	data := make([]byte, 0, len(values)*4)
	for _, value := range values {
		data = appendNative32(data, uint32(value))
	}
	return b.addArray(name, EncodingValue32, len(values), data, kind, FormatDefault, options)
}

func (b *Builder) UUID(name string, value [16]byte, options ...FieldOptions) error {
	return b.addScalar(name, EncodingValue128, value[:], FormatUUID, options)
}

func (b *Builder) IPv4(name string, value [4]byte, options ...FieldOptions) error {
	return b.addScalar(name, EncodingValue32, value[:], FormatIPAddress, options)
}

func (b *Builder) IPv6(name string, value [16]byte, options ...FieldOptions) error {
	return b.addScalar(name, EncodingValue128, value[:], FormatIPAddress, options)
}

// Port emits a uint16 in network byte order.
func (b *Builder) Port(name string, value uint16, options ...FieldOptions) error {
	var data [2]byte
	binary.BigEndian.PutUint16(data[:], value)
	return b.addScalar(name, EncodingValue16, data[:], FormatPort, options)
}

// String emits a uint16 byte count followed by UTF-8 bytes.
func (b *Builder) String(name, value string, options ...FieldOptions) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: string is not valid UTF-8", ErrInvalidValue)
	}
	data, err := countedBytes([]byte(value))
	if err != nil {
		return err
	}
	return b.addScalar(name, EncodingStringLength16Char8, data, FormatDefault, options)
}

// UTF16 emits a uint16 code-unit count followed by native-endian UTF-16 units.
func (b *Builder) UTF16(name string, value []uint16, options ...FieldOptions) error {
	data, err := countedUint16(value)
	if err != nil {
		return err
	}
	return b.addScalar(name, EncodingStringLength16Char16, data, FormatDefault, options)
}

// Binary emits a uint16 byte count followed by uninterpreted bytes.
func (b *Builder) Binary(name string, value []byte, options ...FieldOptions) error {
	data, err := countedBytes(value)
	if err != nil {
		return err
	}
	return b.addScalar(name, EncodingBinaryLength16Char8, data, FormatDefault, options)
}

func (b *Builder) Int8Array(name string, values []int8, kind ArrayKind, options ...FieldOptions) error {
	data := make([]byte, len(values))
	for i, value := range values {
		data[i] = byte(value)
	}
	return b.addArray(name, EncodingValue8, len(values), data, kind, FormatSignedInt, options)
}

func (b *Builder) Uint8Array(name string, values []uint8, kind ArrayKind, options ...FieldOptions) error {
	return b.addArray(name, EncodingValue8, len(values), values, kind, FormatDefault, options)
}

func (b *Builder) Int16Array(name string, values []int16, kind ArrayKind, options ...FieldOptions) error {
	data := make([]byte, 0, len(values)*2)
	for _, value := range values {
		data = appendNative16(data, uint16(value))
	}
	return b.addArray(name, EncodingValue16, len(values), data, kind, FormatSignedInt, options)
}

func (b *Builder) Uint16Array(name string, values []uint16, kind ArrayKind, options ...FieldOptions) error {
	data := make([]byte, 0, len(values)*2)
	for _, value := range values {
		data = appendNative16(data, value)
	}
	return b.addArray(name, EncodingValue16, len(values), data, kind, FormatDefault, options)
}

func (b *Builder) Int32Array(name string, values []int32, kind ArrayKind, options ...FieldOptions) error {
	data := make([]byte, 0, len(values)*4)
	for _, value := range values {
		data = appendNative32(data, uint32(value))
	}
	return b.addArray(name, EncodingValue32, len(values), data, kind, FormatSignedInt, options)
}

func (b *Builder) Uint32Array(name string, values []uint32, kind ArrayKind, options ...FieldOptions) error {
	data := make([]byte, 0, len(values)*4)
	for _, value := range values {
		data = appendNative32(data, value)
	}
	return b.addArray(name, EncodingValue32, len(values), data, kind, FormatDefault, options)
}

func (b *Builder) Int64Array(name string, values []int64, kind ArrayKind, options ...FieldOptions) error {
	data := make([]byte, 0, len(values)*8)
	for _, value := range values {
		data = appendNative64(data, uint64(value))
	}
	return b.addArray(name, EncodingValue64, len(values), data, kind, FormatSignedInt, options)
}

func (b *Builder) Uint64Array(name string, values []uint64, kind ArrayKind, options ...FieldOptions) error {
	data := make([]byte, 0, len(values)*8)
	for _, value := range values {
		data = appendNative64(data, value)
	}
	return b.addArray(name, EncodingValue64, len(values), data, kind, FormatDefault, options)
}

func (b *Builder) BoolArray(name string, values []bool, kind ArrayKind, options ...FieldOptions) error {
	data := make([]byte, len(values))
	for i, value := range values {
		if value {
			data[i] = 1
		}
	}
	return b.addArray(name, EncodingValue8, len(values), data, kind, FormatBoolean, options)
}

func (b *Builder) Float32Array(name string, values []float32, kind ArrayKind, options ...FieldOptions) error {
	data := make([]byte, 0, len(values)*4)
	for _, value := range values {
		data = appendNative32(data, math.Float32bits(value))
	}
	return b.addArray(name, EncodingValue32, len(values), data, kind, FormatFloat, options)
}

func (b *Builder) Float64Array(name string, values []float64, kind ArrayKind, options ...FieldOptions) error {
	data := make([]byte, 0, len(values)*8)
	for _, value := range values {
		data = appendNative64(data, math.Float64bits(value))
	}
	return b.addArray(name, EncodingValue64, len(values), data, kind, FormatFloat, options)
}

func (b *Builder) UUIDArray(name string, values [][16]byte, kind ArrayKind, options ...FieldOptions) error {
	data := make([]byte, 0, len(values)*16)
	for _, value := range values {
		data = append(data, value[:]...)
	}
	return b.addArray(name, EncodingValue128, len(values), data, kind, FormatUUID, options)
}

func (b *Builder) IPv4Array(name string, values [][4]byte, kind ArrayKind, options ...FieldOptions) error {
	data := make([]byte, 0, len(values)*4)
	for _, value := range values {
		data = append(data, value[:]...)
	}
	return b.addArray(name, EncodingValue32, len(values), data, kind, FormatIPAddress, options)
}

func (b *Builder) IPv6Array(name string, values [][16]byte, kind ArrayKind, options ...FieldOptions) error {
	data := make([]byte, 0, len(values)*16)
	for _, value := range values {
		data = append(data, value[:]...)
	}
	return b.addArray(name, EncodingValue128, len(values), data, kind, FormatIPAddress, options)
}

func (b *Builder) PortArray(name string, values []uint16, kind ArrayKind, options ...FieldOptions) error {
	data := make([]byte, 0, len(values)*2)
	for _, value := range values {
		var encoded [2]byte
		binary.BigEndian.PutUint16(encoded[:], value)
		data = append(data, encoded[:]...)
	}
	return b.addArray(name, EncodingValue16, len(values), data, kind, FormatPort, options)
}

func (b *Builder) StringArray(name string, values []string, kind ArrayKind, options ...FieldOptions) error {
	data := make([]byte, 0)
	for _, value := range values {
		if !utf8.ValidString(value) {
			return fmt.Errorf("%w: string is not valid UTF-8", ErrInvalidValue)
		}
		encoded, err := countedBytes([]byte(value))
		if err != nil {
			return err
		}
		data = append(data, encoded...)
	}
	return b.addArray(name, EncodingStringLength16Char8, len(values), data, kind, FormatDefault, options)
}

func (b *Builder) UTF16Array(name string, values [][]uint16, kind ArrayKind, options ...FieldOptions) error {
	data := make([]byte, 0)
	for _, value := range values {
		encoded, err := countedUint16(value)
		if err != nil {
			return err
		}
		data = append(data, encoded...)
	}
	return b.addArray(name, EncodingStringLength16Char16, len(values), data, kind, FormatDefault, options)
}

func (b *Builder) BinaryArray(name string, values [][]byte, kind ArrayKind, options ...FieldOptions) error {
	data := make([]byte, 0)
	for _, value := range values {
		encoded, err := countedBytes(value)
		if err != nil {
			return err
		}
		data = append(data, encoded...)
	}
	return b.addArray(name, EncodingBinaryLength16Char8, len(values), data, kind, FormatDefault, options)
}

func (b *Builder) addScalar(name string, encoding FieldEncoding, data []byte, defaultFormat FieldFormat, options []FieldOptions) error {
	option, err := resolveOptions(defaultFormat, options)
	if err != nil {
		return err
	}
	return b.addField(name, encoding, ArrayScalar, 0, data, option)
}

func (b *Builder) addArray(name string, encoding FieldEncoding, count int, data []byte, kind ArrayKind, defaultFormat FieldFormat, options []FieldOptions) error {
	if kind != ArrayFixed && kind != ArrayVariable {
		return fmt.Errorf("%w: array method requires fixed or variable kind", ErrInvalidValue)
	}
	if count > maxCount {
		return ErrCountTooLarge
	}
	if kind == ArrayFixed && count == 0 {
		return fmt.Errorf("%w: fixed arrays must not be empty", ErrInvalidValue)
	}
	option, err := resolveOptions(defaultFormat, options)
	if err != nil {
		return err
	}
	return b.addField(name, encoding, kind, uint16(count), data, option)
}

func (b *Builder) addField(name string, encoding FieldEncoding, kind ArrayKind, count uint16, data []byte, option FieldOptions) error {
	if err := b.requireActive(); err != nil {
		return err
	}
	if err := b.canAddChild(); err != nil {
		return err
	}
	if err := validateMetadataName("field", name); err != nil {
		return err
	}
	if encoding == EncodingInvalid || encoding&^EncodingValueMask != 0 || encoding == EncodingStruct {
		return fmt.Errorf("%w: invalid field encoding %#x", ErrInvalidValue, encoding)
	}

	encoded := encoding
	switch kind {
	case ArrayScalar:
	case ArrayFixed:
		if count == 0 {
			return fmt.Errorf("%w: fixed arrays must not be empty", ErrInvalidValue)
		}
		encoded |= EncodingCArrayFlag
	case ArrayVariable:
		encoded |= EncodingVArrayFlag
	default:
		return fmt.Errorf("%w: invalid array kind %d", ErrInvalidValue, kind)
	}

	b.metadata = append(b.metadata, name...)
	b.metadata = append(b.metadata, 0)
	if option.Format != FormatDefault || option.Tag != 0 {
		b.metadata = append(b.metadata, byte(encoded|EncodingChainFlag))
		format := byte(option.Format)
		if option.Tag != 0 {
			format |= byte(FormatChainFlag)
		}
		b.metadata = append(b.metadata, format)
		if option.Tag != 0 {
			b.metadata = appendNative16(b.metadata, uint16(option.Tag))
		}
	} else {
		b.metadata = append(b.metadata, byte(encoded))
	}
	if kind == ArrayFixed {
		b.metadata = appendNative16(b.metadata, count)
	}
	if kind == ArrayVariable {
		b.payload = appendNative16(b.payload, count)
	}
	b.payload = append(b.payload, data...)
	b.noteChild()
	return nil
}

func resolveOptions(defaultFormat FieldFormat, options []FieldOptions) (FieldOptions, error) {
	if len(options) > 1 {
		return FieldOptions{}, fmt.Errorf("%w: at most one FieldOptions value is allowed", ErrInvalidValue)
	}
	option := FieldOptions{Format: defaultFormat}
	if len(options) == 1 {
		option.Tag = options[0].Tag
		if options[0].Format != FormatDefault || defaultFormat == FormatDefault {
			option.Format = options[0].Format
		}
	}
	if option.Format&^FormatValueMask != 0 {
		return FieldOptions{}, fmt.Errorf("%w: invalid field format %#x", ErrInvalidValue, option.Format)
	}
	return option, nil
}

func (b *Builder) canAddChild() error {
	if len(b.structs) != 0 && b.structs[len(b.structs)-1].children == maxStructChildFields {
		return ErrTooManyFields
	}
	return nil
}

func (b *Builder) noteChild() {
	if len(b.structs) != 0 {
		b.structs[len(b.structs)-1].children++
	}
}

func (b *Builder) requireActive() error {
	if b == nil || !b.active {
		return fmt.Errorf("%w: call Reset first", ErrState)
	}
	return nil
}

func validateMetadataName(kind, name string) error {
	if name == "" {
		return fmt.Errorf("%w: %s name is empty", ErrInvalidName, kind)
	}
	if !utf8.ValidString(name) {
		return fmt.Errorf("%w: %s name is not valid UTF-8", ErrInvalidName, kind)
	}
	for _, value := range []byte(name) {
		if value == 0 || value == ';' {
			return fmt.Errorf("%w: %s name contains NUL or semicolon", ErrInvalidName, kind)
		}
	}
	return nil
}

func countedBytes(value []byte) ([]byte, error) {
	if len(value) > maxCount {
		return nil, ErrCountTooLarge
	}
	result := make([]byte, 2, 2+len(value))
	nativeEndian.PutUint16(result, uint16(len(value)))
	return append(result, value...), nil
}

func countedUint16(value []uint16) ([]byte, error) {
	if len(value) > maxCount {
		return nil, ErrCountTooLarge
	}
	result := make([]byte, 0, 2+len(value)*2)
	result = appendNative16(result, uint16(len(value)))
	for _, unit := range value {
		result = appendNative16(result, unit)
	}
	return result, nil
}

func native16(value uint16) []byte {
	result := make([]byte, 2)
	nativeEndian.PutUint16(result, value)
	return result
}

func native32(value uint32) []byte {
	result := make([]byte, 4)
	nativeEndian.PutUint32(result, value)
	return result
}

func native64(value uint64) []byte {
	result := make([]byte, 8)
	nativeEndian.PutUint64(result, value)
	return result
}

func appendNative16(target []byte, value uint16) []byte {
	var encoded [2]byte
	nativeEndian.PutUint16(encoded[:], value)
	return append(target, encoded[:]...)
}

func appendNative32(target []byte, value uint32) []byte {
	var encoded [4]byte
	nativeEndian.PutUint32(encoded[:], value)
	return append(target, encoded[:]...)
}

func appendNative64(target []byte, value uint64) []byte {
	var encoded [8]byte
	nativeEndian.PutUint64(encoded[:], value)
	return append(target, encoded[:]...)
}

func (b *Builder) encodeSegments(level Level) ([]byte, []byte, []byte, error) {
	if err := b.requireActive(); err != nil {
		return nil, nil, nil, err
	}
	if level < LevelCritical || level > LevelVerbose {
		return nil, nil, nil, fmt.Errorf("%w: %d", ErrInvalidLevel, level)
	}
	if len(b.structs) != 0 {
		return nil, nil, nil, fmt.Errorf("%w: %d unclosed structs", ErrState, len(b.structs))
	}
	if b.hasRel && !b.hasAct {
		return nil, nil, nil, fmt.Errorf("%w: related ID requires activity ID", ErrInvalidValue)
	}
	if len(b.metadata) > maxCount {
		return nil, nil, nil, ErrMetadataTooLarge
	}
	if len(b.metadata)+len(b.payload) > maxMetadataPayload {
		return nil, nil, nil, ErrEventTooLarge
	}

	prefixCapacity := 12
	if b.hasAct {
		prefixCapacity += 20
		if b.hasRel {
			prefixCapacity += 16
		}
	}
	prefix := make([]byte, 0, prefixCapacity)
	prefix = append(prefix, byte(defaultHeaderFlags()), b.version)
	prefix = appendNative16(prefix, b.id)
	prefix = appendNative16(prefix, uint16(b.tag))
	prefix = append(prefix, byte(b.opcode), byte(level))
	if b.hasAct {
		size := uint16(16)
		if b.hasRel {
			size = 32
		}
		prefix = appendNative16(prefix, size)
		prefix = appendNative16(prefix, uint16(ExtensionActivityID|ExtensionKindChainFlag))
		prefix = append(prefix, b.activity[:]...)
		if b.hasRel {
			prefix = append(prefix, b.related[:]...)
		}
	}
	prefix = appendNative16(prefix, uint16(len(b.metadata)))
	prefix = appendNative16(prefix, uint16(ExtensionMetadata))
	return prefix, b.metadata, b.payload, nil
}

// Encode returns a complete wire-format event independent of the kernel.
func (b *Builder) Encode(level Level) ([]byte, error) {
	prefix, metadata, payload, err := b.encodeSegments(level)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, len(prefix)+len(metadata)+len(payload))
	result = append(result, prefix...)
	result = append(result, metadata...)
	result = append(result, payload...)
	return result, nil
}
