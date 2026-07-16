package eventheader

import (
	"fmt"
	"strconv"
)

type valueKind uint8

const (
	valueInvalid valueKind = iota
	valueInt8
	valueUint8
	valueInt16
	valueUint16
	valueInt32
	valueUint32
	valueInt64
	valueUint64
	valueBool
	valueFloat32
	valueFloat64
	valueUintptr
	valueUUID
	valueIPv4
	valueIPv6
	valuePort
	valueString
	valueUTF16
	valueBinary
	valueStruct
)

// SchemaOptions defines the immutable event header and metadata name.
type SchemaOptions struct {
	Name    string
	ID      uint16
	Version uint8
	Tag     EventTag
	Opcode  Opcode
}

// FieldDefinition is an immutable-schema input produced by the typed field
// constructors. NewSchema validates and copies its complete definition tree.
type FieldDefinition struct {
	name       string
	kind       valueKind
	encoding   FieldEncoding
	format     FieldFormat
	options    []FieldOptions
	arrayKind  ArrayKind
	arrayCount uint16
	countArgs  int
	arrayField bool
	children   []FieldDefinition
}

type valuePlan struct {
	kind       valueKind
	arrayKind  ArrayKind
	arrayCount uint16
}

// Schema contains pre-encoded immutable metadata and a flattened typed value
// plan. A Schema is safe for concurrent use.
type Schema struct {
	options  SchemaOptions
	metadata []byte
	plan     []valuePlan
}

func scalarField(name string, kind valueKind, encoding FieldEncoding, format FieldFormat, options []FieldOptions) FieldDefinition {
	return FieldDefinition{name: name, kind: kind, encoding: encoding, format: format, options: options}
}

func Int8Field(name string, options ...FieldOptions) FieldDefinition {
	return scalarField(name, valueInt8, EncodingValue8, FormatSignedInt, options)
}

func Uint8Field(name string, options ...FieldOptions) FieldDefinition {
	return scalarField(name, valueUint8, EncodingValue8, FormatDefault, options)
}

func Int16Field(name string, options ...FieldOptions) FieldDefinition {
	return scalarField(name, valueInt16, EncodingValue16, FormatSignedInt, options)
}

func Uint16Field(name string, options ...FieldOptions) FieldDefinition {
	return scalarField(name, valueUint16, EncodingValue16, FormatDefault, options)
}

func Int32Field(name string, options ...FieldOptions) FieldDefinition {
	return scalarField(name, valueInt32, EncodingValue32, FormatSignedInt, options)
}

func Uint32Field(name string, options ...FieldOptions) FieldDefinition {
	return scalarField(name, valueUint32, EncodingValue32, FormatDefault, options)
}

func Int64Field(name string, options ...FieldOptions) FieldDefinition {
	return scalarField(name, valueInt64, EncodingValue64, FormatSignedInt, options)
}

func Uint64Field(name string, options ...FieldOptions) FieldDefinition {
	return scalarField(name, valueUint64, EncodingValue64, FormatDefault, options)
}

func BoolField(name string, options ...FieldOptions) FieldDefinition {
	return scalarField(name, valueBool, EncodingValue8, FormatBoolean, options)
}

func Float32Field(name string, options ...FieldOptions) FieldDefinition {
	return scalarField(name, valueFloat32, EncodingValue32, FormatFloat, options)
}

func Float64Field(name string, options ...FieldOptions) FieldDefinition {
	return scalarField(name, valueFloat64, EncodingValue64, FormatFloat, options)
}

func UintptrField(name string, options ...FieldOptions) FieldDefinition {
	encoding := EncodingValue32
	if strconv.IntSize == 64 {
		encoding = EncodingValue64
	}
	return scalarField(name, valueUintptr, encoding, FormatDefault, options)
}

func UUIDField(name string, options ...FieldOptions) FieldDefinition {
	return scalarField(name, valueUUID, EncodingValue128, FormatUUID, options)
}

func IPv4Field(name string, options ...FieldOptions) FieldDefinition {
	return scalarField(name, valueIPv4, EncodingValue32, FormatIPAddress, options)
}

func IPv6Field(name string, options ...FieldOptions) FieldDefinition {
	return scalarField(name, valueIPv6, EncodingValue128, FormatIPAddress, options)
}

func PortField(name string, options ...FieldOptions) FieldDefinition {
	return scalarField(name, valuePort, EncodingValue16, FormatPort, options)
}

func StringField(name string, options ...FieldOptions) FieldDefinition {
	return scalarField(name, valueString, EncodingStringLength16Char8, FormatDefault, options)
}

func UTF16Field(name string, options ...FieldOptions) FieldDefinition {
	return scalarField(name, valueUTF16, EncodingStringLength16Char16, FormatDefault, options)
}

func BinaryField(name string, options ...FieldOptions) FieldDefinition {
	return scalarField(name, valueBinary, EncodingBinaryLength16Char8, FormatDefault, options)
}

// ArrayField converts a typed scalar definition into an array definition.
// Variable arrays take no count; fixed arrays take exactly one nonzero count.
func ArrayField(element FieldDefinition, kind ArrayKind, count ...uint16) FieldDefinition {
	alreadyArray := element.arrayField
	element.arrayKind = kind
	element.countArgs = len(count)
	element.arrayField = true
	if alreadyArray {
		element.countArgs = -1
	}
	if len(count) != 0 {
		element.arrayCount = count[0]
	}
	return element
}

// StructField defines a named nested structure. Its FieldOptions may specify a
// tag; Format must remain FormatDefault. Arrays of structures are unsupported.
func StructField(name string, fields []FieldDefinition, options ...FieldOptions) FieldDefinition {
	return FieldDefinition{
		name:     name,
		kind:     valueStruct,
		encoding: EncodingStruct,
		options:  options,
		children: fields,
	}
}

// NewSchema validates definitions, deep-copies their meaning, and pre-encodes
// all metadata.
func NewSchema(options SchemaOptions, fields ...FieldDefinition) (*Schema, error) {
	if err := validateMetadataName("event", options.Name); err != nil {
		return nil, err
	}
	metadata := make([]byte, 0, len(options.Name)+1+len(fields)*5)
	metadata = append(metadata, options.Name...)
	metadata = append(metadata, 0)
	plan := make([]valuePlan, 0, len(fields))
	minPayload := 0
	for i := range fields {
		var err error
		metadata, plan, minPayload, err = appendDefinition(metadata, plan, minPayload, fields[i], 0)
		if err != nil {
			return nil, fmt.Errorf("eventheader: field %d: %w", i, err)
		}
	}
	if len(metadata) > maxCount {
		return nil, ErrMetadataTooLarge
	}
	if len(metadata)+minPayload > maxMetadataPayload {
		return nil, ErrEventTooLarge
	}
	metadata = metadata[:len(metadata):len(metadata)]
	plan = plan[:len(plan):len(plan)]
	return &Schema{options: options, metadata: metadata, plan: plan}, nil
}

func appendDefinition(
	metadata []byte,
	plan []valuePlan,
	minPayload int,
	def FieldDefinition,
	depth int,
) ([]byte, []valuePlan, int, error) {
	if err := validateMetadataName("field", def.name); err != nil {
		return metadata, plan, minPayload, err
	}
	if def.kind == valueInvalid {
		return metadata, plan, minPayload, fmt.Errorf("%w: field definition was not produced by a typed constructor", ErrInvalidValue)
	}
	if len(def.options) > 1 {
		return metadata, plan, minPayload, fmt.Errorf("%w: at most one FieldOptions value is allowed", ErrInvalidValue)
	}

	if def.kind == valueStruct {
		if def.arrayField {
			return metadata, plan, minPayload, ErrStructArrayUnsupported
		}
		if depth >= maxStructDepth {
			return metadata, plan, minPayload, ErrNestingTooDeep
		}
		if len(def.children) == 0 {
			return metadata, plan, minPayload, fmt.Errorf("%w: empty struct", ErrInvalidValue)
		}
		if len(def.children) > maxStructChildFields {
			return metadata, plan, minPayload, ErrTooManyFields
		}
		option, err := resolveOptions(FormatDefault, def.options)
		if err != nil {
			return metadata, plan, minPayload, err
		}
		if option.Format != FormatDefault {
			return metadata, plan, minPayload, fmt.Errorf("%w: struct format must be default", ErrInvalidValue)
		}
		metadata = append(metadata, def.name...)
		metadata = append(metadata, 0, byte(EncodingStruct|EncodingChainFlag))
		format := byte(len(def.children))
		if option.Tag != 0 {
			format |= byte(FormatChainFlag)
		}
		metadata = append(metadata, format)
		if option.Tag != 0 {
			metadata = appendNative16(metadata, uint16(option.Tag))
		}
		for i := range def.children {
			metadata, plan, minPayload, err = appendDefinition(metadata, plan, minPayload, def.children[i], depth+1)
			if err != nil {
				return metadata, plan, minPayload, fmt.Errorf("struct %q field %d: %w", def.name, i, err)
			}
		}
		return metadata, plan, minPayload, nil
	}
	if len(def.children) != 0 {
		return metadata, plan, minPayload, fmt.Errorf("%w: scalar field has children", ErrInvalidValue)
	}
	if def.encoding == EncodingInvalid || def.encoding&^EncodingValueMask != 0 || def.encoding == EncodingStruct {
		return metadata, plan, minPayload, fmt.Errorf("%w: invalid field encoding", ErrInvalidValue)
	}

	switch def.arrayKind {
	case ArrayScalar:
		if def.arrayField || def.countArgs != 0 {
			return metadata, plan, minPayload, fmt.Errorf("%w: scalar field has an array count", ErrInvalidValue)
		}
	case ArrayFixed:
		if def.countArgs != 1 || def.arrayCount == 0 {
			return metadata, plan, minPayload, fmt.Errorf("%w: fixed arrays require one nonzero count", ErrInvalidValue)
		}
	case ArrayVariable:
		if def.countArgs != 0 {
			return metadata, plan, minPayload, fmt.Errorf("%w: variable arrays do not take a fixed count", ErrInvalidValue)
		}
	default:
		return metadata, plan, minPayload, fmt.Errorf("%w: invalid array kind %d", ErrInvalidValue, def.arrayKind)
	}
	option, err := resolveOptions(def.format, def.options)
	if err != nil {
		return metadata, plan, minPayload, err
	}
	encoded := def.encoding
	if def.arrayKind == ArrayFixed {
		encoded |= EncodingCArrayFlag
	} else if def.arrayKind == ArrayVariable {
		encoded |= EncodingVArrayFlag
	}
	metadata = append(metadata, def.name...)
	metadata = append(metadata, 0)
	if option.Format != FormatDefault || option.Tag != 0 {
		metadata = append(metadata, byte(encoded|EncodingChainFlag))
		format := byte(option.Format)
		if option.Tag != 0 {
			format |= byte(FormatChainFlag)
		}
		metadata = append(metadata, format)
		if option.Tag != 0 {
			metadata = appendNative16(metadata, uint16(option.Tag))
		}
	} else {
		metadata = append(metadata, byte(encoded))
	}
	if def.arrayKind == ArrayFixed {
		metadata = appendNative16(metadata, def.arrayCount)
	}

	elementSize := minimumValueSize(def.kind)
	count := 1
	if def.arrayKind == ArrayFixed {
		count = int(def.arrayCount)
	} else if def.arrayKind == ArrayVariable {
		minPayload += 2
		count = 0
	}
	if elementSize != 0 && count > (maxMetadataPayload-minPayload)/elementSize {
		return metadata, plan, minPayload, ErrEventTooLarge
	}
	minPayload += count * elementSize
	plan = append(plan, valuePlan{kind: def.kind, arrayKind: def.arrayKind, arrayCount: def.arrayCount})
	return metadata, plan, minPayload, nil
}

func minimumValueSize(kind valueKind) int {
	switch kind {
	case valueInt8, valueUint8, valueBool:
		return 1
	case valueInt16, valueUint16, valuePort:
		return 2
	case valueInt32, valueUint32, valueFloat32, valueIPv4:
		return 4
	case valueInt64, valueUint64, valueFloat64:
		return 8
	case valueUintptr:
		return strconv.IntSize / 8
	case valueUUID, valueIPv6:
		return 16
	case valueString, valueUTF16, valueBinary:
		return 2
	default:
		return 0
	}
}

// Name returns the schema's event name.
func (s *Schema) Name() string {
	if s == nil {
		return ""
	}
	return s.options.Name
}

// Options returns a copy of the schema options.
func (s *Schema) Options() SchemaOptions {
	if s == nil {
		return SchemaOptions{}
	}
	return s.options
}
