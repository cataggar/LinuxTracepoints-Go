// Package eventheader encodes the Microsoft EventHeader wire format and writes
// it through Linux user_events tracepoints.
package eventheader

import (
	"encoding/binary"
	"strconv"
)

// HeaderFlags describes pointer size, byte order, and header extensions.
type HeaderFlags uint8

const (
	HeaderFlagNone         HeaderFlags = 0
	HeaderFlagPointer64    HeaderFlags = 0x01
	HeaderFlagLittleEndian HeaderFlags = 0x02
	HeaderFlagExtension    HeaderFlags = 0x04
)

// Header is the logical form of the fixed eight-byte EventHeader prefix.
// Encode uses native byte order for ID and Tag.
type Header struct {
	Flags   HeaderFlags
	Version uint8
	ID      uint16
	Tag     EventTag
	Opcode  Opcode
	Level   Level
}

// ExtensionKind identifies a header extension.
type ExtensionKind uint16

const (
	ExtensionInvalid    ExtensionKind = 0
	ExtensionMetadata   ExtensionKind = 1
	ExtensionActivityID ExtensionKind = 2

	ExtensionKindMask      ExtensionKind = 0x7fff
	ExtensionKindChainFlag ExtensionKind = 0x8000
)

// ExtensionHeader is the logical form of the four-byte extension prefix.
type ExtensionHeader struct {
	Size uint16
	Kind ExtensionKind
}

// Level is the severity encoded in the tracepoint name and event header.
type Level uint8

const (
	LevelInvalid     Level = 0
	LevelCritical    Level = 1
	LevelError       Level = 2
	LevelWarning     Level = 3
	LevelInformation Level = 4
	LevelVerbose     Level = 5
)

// Opcode gives an event special correlation semantics.
type Opcode uint8

const (
	OpcodeInfo            Opcode = 0
	OpcodeActivityStart   Opcode = 1
	OpcodeActivityStop    Opcode = 2
	OpcodeCollectionStart Opcode = 3
	OpcodeCollectionStop  Opcode = 4
	OpcodeExtension       Opcode = 5
	OpcodeReply           Opcode = 6
	OpcodeResume          Opcode = 7
	OpcodeSuspend         Opcode = 8
	OpcodeSend            Opcode = 9
	OpcodeReceive         Opcode = 0xf0
)

// FieldEncoding describes the size and framing of a field value.
type FieldEncoding uint8

const (
	EncodingInvalid              FieldEncoding = 0
	EncodingStruct               FieldEncoding = 1
	EncodingValue8               FieldEncoding = 2
	EncodingValue16              FieldEncoding = 3
	EncodingValue32              FieldEncoding = 4
	EncodingValue64              FieldEncoding = 5
	EncodingValue128             FieldEncoding = 6
	EncodingZStringChar8         FieldEncoding = 7
	EncodingZStringChar16        FieldEncoding = 8
	EncodingZStringChar32        FieldEncoding = 9
	EncodingStringLength16Char8  FieldEncoding = 10
	EncodingStringLength16Char16 FieldEncoding = 11
	EncodingStringLength16Char32 FieldEncoding = 12
	EncodingBinaryLength16Char8  FieldEncoding = 13

	EncodingValueMask  FieldEncoding = 0x1f
	EncodingFlagMask   FieldEncoding = 0xe0
	EncodingCArrayFlag FieldEncoding = 0x20
	EncodingVArrayFlag FieldEncoding = 0x40
	EncodingChainFlag  FieldEncoding = 0x80
)

// FieldFormat describes how a decoder should display a field value.
type FieldFormat uint8

const (
	FormatDefault      FieldFormat = 0
	FormatUnsignedInt  FieldFormat = 1
	FormatSignedInt    FieldFormat = 2
	FormatHexInt       FieldFormat = 3
	FormatErrno        FieldFormat = 4
	FormatPID          FieldFormat = 5
	FormatTime         FieldFormat = 6
	FormatBoolean      FieldFormat = 7
	FormatFloat        FieldFormat = 8
	FormatHexBytes     FieldFormat = 9
	FormatString8      FieldFormat = 10
	FormatStringUTF    FieldFormat = 11
	FormatStringUTFBOM FieldFormat = 12
	FormatStringXML    FieldFormat = 13
	FormatStringJSON   FieldFormat = 14
	FormatUUID         FieldFormat = 15
	FormatPort         FieldFormat = 16
	FormatIPAddress    FieldFormat = 17
	// FormatIPAddressObsolete is accepted for compatibility but should not be
	// emitted by new code.
	FormatIPAddressObsolete FieldFormat = 18

	FormatValueMask FieldFormat = 0x7f
	FormatChainFlag FieldFormat = 0x80
)

const (
	// FormatIPv4 and FormatIPv6 preserve the historical Microsoft aliases.
	// New producers should use FormatIPAddress for both address widths;
	// FormatIPv6 maps to the obsolete decode-only value.
	FormatIPv4 = FormatIPAddress
	FormatIPv6 = FormatIPAddressObsolete
)

// ArrayKind selects scalar, fixed-length array, or variable-length array wire
// framing.
type ArrayKind uint8

const (
	ArrayScalar ArrayKind = iota
	ArrayFixed
	ArrayVariable
)

// Tag is a provider-defined 16-bit value.
type Tag uint16

// EventTag and FieldTag document where a Tag is used.
type EventTag = Tag
type FieldTag = Tag

// ActivityID is a 128-bit correlation identifier. Its bytes are emitted
// verbatim, in network/UUID order.
type ActivityID [16]byte

// FieldOptions controls optional metadata on a field.
type FieldOptions struct {
	Format FieldFormat
	Tag    FieldTag
}

var nativeEndian binary.ByteOrder = binary.NativeEndian

func defaultHeaderFlags() HeaderFlags {
	flags := HeaderFlagExtension
	if strconv.IntSize == 64 {
		flags |= HeaderFlagPointer64
	}
	var value [2]byte
	binary.NativeEndian.PutUint16(value[:], 1)
	if value[0] == 1 {
		flags |= HeaderFlagLittleEndian
	}
	return flags
}

// NativeHeaderFlags returns the pointer-size and byte-order flags for this
// process, with the mandatory extension bit set.
func NativeHeaderFlags() HeaderFlags {
	return defaultHeaderFlags()
}
