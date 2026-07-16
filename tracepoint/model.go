package tracepoint

import (
	"fmt"
	"math"
	"net/netip"
	"time"
)

// ByteOrder identifies the byte order used by a wire value.
type ByteOrder uint8

const (
	// ByteOrderUnknown means no byte order applies or it is unavailable.
	ByteOrderUnknown ByteOrder = iota
	// ByteOrderLittle is least-significant-byte first.
	ByteOrderLittle
	// ByteOrderBig is most-significant-byte first.
	ByteOrderBig
)

// String returns a human-readable byte-order name.
func (o ByteOrder) String() string {
	switch o {
	case ByteOrderLittle:
		return "little"
	case ByteOrderBig:
		return "big"
	default:
		return "unknown"
	}
}

// Encoding describes a value's wire representation.
type Encoding string

const (
	// EncodingNone means no particular wire encoding is known.
	EncodingNone Encoding = ""
	// EncodingInteger is a fixed-width integer.
	EncodingInteger Encoding = "integer"
	// EncodingFloat is an IEEE floating-point value.
	EncodingFloat Encoding = "float"
	// EncodingBoolean is a Boolean value.
	EncodingBoolean Encoding = "boolean"
	// EncodingUTF8 is UTF-8 text.
	EncodingUTF8 Encoding = "utf-8"
	// EncodingBinary is uninterpreted bytes.
	EncodingBinary Encoding = "binary"
	// EncodingUUID is a 16-byte UUID.
	EncodingUUID Encoding = "uuid"
	// EncodingIP is an IPv4 or IPv6 address.
	EncodingIP Encoding = "ip"
	// EncodingPort is a transport port.
	EncodingPort Encoding = "port"
	// EncodingTime is a timestamp or duration.
	EncodingTime Encoding = "time"
	// EncodingArray is a sequence of values.
	EncodingArray Encoding = "array"
	// EncodingStruct is a sequence of named fields.
	EncodingStruct Encoding = "struct"
	// EncodingDataLoc is a tracefs __data_loc reference.
	EncodingDataLoc Encoding = "data_loc"
	// EncodingRelLoc is a tracefs __rel_loc reference.
	EncodingRelLoc Encoding = "rel_loc"
)

// ValueKind identifies which member of Value is meaningful.
type ValueKind uint8

const (
	// ValueNull represents an explicit null or an unavailable value.
	ValueNull ValueKind = iota
	// ValueUnsigned selects Value.Unsigned.
	ValueUnsigned
	// ValueSigned selects Value.Signed.
	ValueSigned
	// ValueFloat selects Value.Float.
	ValueFloat
	// ValueBool selects Value.Bool.
	ValueBool
	// ValueText selects Value.Text.
	ValueText
	// ValueBinary selects Value.Binary.
	ValueBinary
	// ValueUUID selects Value.UUID.
	ValueUUID
	// ValueIP selects Value.IP.
	ValueIP
	// ValuePort selects Value.Port.
	ValuePort
	// ValueTime selects Value.Time.
	ValueTime
	// ValueArray selects Value.Array.
	ValueArray
	// ValueStruct selects Value.Struct.
	ValueStruct
)

// DiagnosticSeverity classifies a diagnostic.
type DiagnosticSeverity uint8

const (
	// SeverityInfo is informational.
	SeverityInfo DiagnosticSeverity = iota
	// SeverityWarning indicates a recoverable concern.
	SeverityWarning
	// SeverityError indicates invalid or unavailable decoded data.
	SeverityError
)

// Diagnostic describes a recoverable decoding issue.
type Diagnostic struct {
	// Severity classifies the issue.
	Severity DiagnosticSeverity
	// Offset is the byte offset associated with the issue.
	Offset int
	// Stage names the operation which reported the issue.
	Stage string
	// Message is a human-readable summary.
	Message string
	// Err is the machine-readable underlying error.
	Err error
}

// Error formats a diagnostic for logs.
func (d Diagnostic) Error() string {
	if d.Err == nil {
		return d.Message
	}
	if d.Message == "" {
		return d.Err.Error()
	}
	return fmt.Sprintf("%s: %v", d.Message, d.Err)
}

// Unwrap returns the diagnostic's underlying error.
func (d Diagnostic) Unwrap() error {
	return d.Err
}

// Optional is a value which may be absent.
type Optional[T any] struct {
	// Value is meaningful when Present is true.
	Value T
	// Present reports whether Value was supplied.
	Present bool
}

// Clock identifies a timestamp clock domain.
type Clock string

const (
	// ClockUnknown is an unspecified clock domain.
	ClockUnknown Clock = ""
	// ClockMonotonic is the monotonic clock.
	ClockMonotonic Clock = "monotonic"
	// ClockBoot is the boot-time clock, including suspend.
	ClockBoot Clock = "boottime"
	// ClockRealtime is the Unix wall clock.
	ClockRealtime Clock = "realtime"
	// ClockTAI is International Atomic Time.
	ClockTAI Clock = "tai"
)

// Timestamp stores nanoseconds in a clock domain. EpochOffset is the signed
// number of nanoseconds which converts Nanoseconds to Unix epoch nanoseconds
// when EpochOffsetKnown is true.
type Timestamp struct {
	// Nanoseconds is the value in Clock's domain.
	Nanoseconds uint64
	// Clock identifies the value's clock domain.
	Clock Clock
	// EpochOffset converts Nanoseconds to Unix nanoseconds when known.
	EpochOffset int64
	// EpochOffsetKnown reports whether EpochOffset is meaningful.
	EpochOffsetKnown bool
}

// UnixNano returns the Unix epoch value, if its offset is known and conversion
// does not overflow int64.
func (t Timestamp) UnixNano() (int64, bool) {
	if !t.EpochOffsetKnown {
		return 0, false
	}
	if t.EpochOffset >= 0 {
		offset := uint64(t.EpochOffset)
		if t.Nanoseconds > uint64(math.MaxInt64)-offset {
			return 0, false
		}
		return int64(t.Nanoseconds + offset), true
	}
	magnitude := uint64(-(t.EpochOffset + 1)) + 1
	if t.Nanoseconds >= magnitude {
		value := t.Nanoseconds - magnitude
		if value > uint64(math.MaxInt64) {
			return 0, false
		}
		return int64(value), true
	}
	negative := magnitude - t.Nanoseconds
	if negative > uint64(math.MaxInt64)+1 {
		return 0, false
	}
	if negative == uint64(math.MaxInt64)+1 {
		return math.MinInt64, true
	}
	return -int64(negative), true
}

// Time returns a time.Time when this timestamp has a known epoch offset.
func (t Timestamp) Time() (time.Time, bool) {
	n, ok := t.UnixNano()
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(0, n), true
}

// Compare compares two timestamps. Known, differing epoch offsets use Unix
// time even within one clock domain. Different clock domains are comparable
// only when both have known epoch offsets.
func (t Timestamp) Compare(other Timestamp) (int, error) {
	if t.Clock == other.Clock &&
		(!t.EpochOffsetKnown || !other.EpochOffsetKnown || t.EpochOffset == other.EpochOffset) {
		return compareUint64(t.Nanoseconds, other.Nanoseconds), nil
	}
	a, aok := t.UnixNano()
	b, bok := other.UnixNano()
	if !aok || !bok {
		return 0, ErrIncomparableClocks
	}
	if a < b {
		return -1, nil
	}
	if a > b {
		return 1, nil
	}
	return 0, nil
}

func compareUint64(a, b uint64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// Value is a tagged union. Kind selects the semantic member. Raw, ByteOrder,
// Encoding, Format, Width, Valid, and Diagnostics retain wire-level details.
// Raw may borrow decoder input; use CloneRecord when the input will be reused.
type Value struct {
	Kind      ValueKind
	Unsigned  uint64
	Signed    int64
	Float     float64
	Bool      bool
	Text      string
	Binary    []byte
	UUID      [16]byte
	IP        netip.Addr
	Port      uint16
	Time      Timestamp
	Array     []Value
	Struct    []Field
	Raw       []byte
	ByteOrder ByteOrder
	Encoding  Encoding
	Format    string
	// Width is the value's width in bits.
	Width       uint32
	Valid       bool
	Diagnostics []Diagnostic
}

// Field is a named structured value.
type Field struct {
	// Name is the source field name.
	Name string
	// Value is the decoded field value.
	Value Value
	// Offset is the field's source byte offset.
	Offset int
	// Diagnostics contains field-local decoding issues.
	Diagnostics []Diagnostic
}

// Identity identifies an event kind.
type Identity struct {
	// System is the event subsystem or provider.
	System string
	// Name is the event name.
	Name string
	// ID is the source event identifier.
	ID uint32
}

// EventHeaderExtension retains an unrecognized EventHeader extension.
type EventHeaderExtension struct {
	Kind   uint16
	Size   uint16
	Chain  bool
	Offset int
	Data   []byte
}

// EventHeaderInfo retains the EventHeader envelope for a materialized event.
// Raw slices may borrow decoder input.
type EventHeaderInfo struct {
	Provider          string
	Keyword           uint64
	Options           string
	Flags             uint8
	Version           uint8
	ID                uint16
	Tag               uint16
	Opcode            uint8
	Level             uint8
	ByteOrder         ByteOrder
	PointerWidth      uint8
	EventName         string
	EventNameRaw      []byte
	ActivityID        Optional[[16]byte]
	RelatedActivityID Optional[[16]byte]
	Extensions        []EventHeaderExtension
	Metadata          []byte
	Payload           []byte
}

// EventRecord is an ordinary decoded event. Common and Fields are kept
// separate so callers can apply event-specific schemas without losing common
// trace metadata from the record envelope.
type EventRecord struct {
	Common      []Field
	Fields      []Field
	EventHeader *EventHeaderInfo
}

// LostRecord reports records dropped by a source.
type LostRecord struct {
	// Count is the number of records reported lost.
	Count uint64
}

// CorruptRecord describes input which could not be represented as an event.
type CorruptRecord struct {
	// Reason summarizes why the source record is corrupt.
	Reason string
}

// RecordKind identifies the active record payload.
type RecordKind uint8

const (
	// RecordUnknown is an uninitialized record.
	RecordUnknown RecordKind = iota
	// RecordEvent selects Record.Event.
	RecordEvent
	// RecordLost selects Record.Lost.
	RecordLost
	// RecordCorrupt selects Record.Corrupt.
	RecordCorrupt
	// RecordRaw identifies an undecoded record represented only by Record.Raw.
	RecordRaw
)

// Record contains source metadata, one typed payload, and the original record
// bytes. Raw and all nested raw byte slices may borrow source storage.
// CloneRecord makes an independent deep copy.
type Record struct {
	// Kind selects Event, Lost, Corrupt, or a raw-only record.
	Kind RecordKind
	// Identity identifies the event or source record kind.
	Identity Identity
	// Timestamp is the source record timestamp.
	Timestamp Timestamp
	// CPU is the source CPU when known.
	CPU Optional[uint32]
	// PID is the source process ID when known.
	PID Optional[int32]
	// TID is the source thread ID when known.
	TID Optional[int32]
	// Event is present for RecordEvent.
	Event *EventRecord
	// Lost is present for RecordLost.
	Lost *LostRecord
	// Corrupt is present for RecordCorrupt.
	Corrupt *CorruptRecord
	// Raw is the complete borrowed source record.
	Raw []byte
	// Diagnostics contains record-level and field-local issues.
	Diagnostics []Diagnostic
}

// CloneRecord returns a deep copy of r, including every retained byte slice.
func CloneRecord(r Record) Record {
	out := r
	out.Raw = cloneBytes(r.Raw)
	out.Diagnostics = cloneDiagnostics(r.Diagnostics)
	if r.Event != nil {
		event := *r.Event
		event.Common = cloneFields(r.Event.Common)
		event.Fields = cloneFields(r.Event.Fields)
		if r.Event.EventHeader != nil {
			info := *r.Event.EventHeader
			info.EventNameRaw = cloneBytes(r.Event.EventHeader.EventNameRaw)
			info.Metadata = cloneBytes(r.Event.EventHeader.Metadata)
			info.Payload = cloneBytes(r.Event.EventHeader.Payload)
			if r.Event.EventHeader.Extensions != nil {
				info.Extensions = make([]EventHeaderExtension, len(r.Event.EventHeader.Extensions))
				copy(info.Extensions, r.Event.EventHeader.Extensions)
				for i := range info.Extensions {
					info.Extensions[i].Data = cloneBytes(r.Event.EventHeader.Extensions[i].Data)
				}
			}
			event.EventHeader = &info
		}
		out.Event = &event
	}
	if r.Lost != nil {
		lost := *r.Lost
		out.Lost = &lost
	}
	if r.Corrupt != nil {
		corrupt := *r.Corrupt
		out.Corrupt = &corrupt
	}
	return out
}

func cloneFields(fields []Field) []Field {
	if fields == nil {
		return nil
	}
	out := make([]Field, len(fields))
	for i := range fields {
		out[i] = fields[i]
		out[i].Value = cloneValue(fields[i].Value)
		out[i].Diagnostics = cloneDiagnostics(fields[i].Diagnostics)
	}
	return out
}

func cloneValue(v Value) Value {
	out := v
	out.Raw = cloneBytes(v.Raw)
	out.Binary = cloneBytes(v.Binary)
	out.Diagnostics = cloneDiagnostics(v.Diagnostics)
	if v.Array != nil {
		out.Array = make([]Value, len(v.Array))
		for i := range v.Array {
			out.Array[i] = cloneValue(v.Array[i])
		}
	}
	out.Struct = cloneFields(v.Struct)
	return out
}

func cloneDiagnostics(d []Diagnostic) []Diagnostic {
	if d == nil {
		return nil
	}
	return append([]Diagnostic(nil), d...)
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}
