package decode

import (
	"encoding/binary"

	"github.com/cataggar/LinuxTracepoints-Go/eventheader"
	"github.com/cataggar/LinuxTracepoints-Go/tracepoint"
)

// State is the current Enumerator state.
type State uint8

const (
	// BeforeFirst is the initial state.
	BeforeFirst State = iota
	// Value identifies one scalar value or array element.
	Value
	// ArrayBegin starts an array field.
	ArrayBegin
	// ArrayEnd ends an array field.
	ArrayEnd
	// StructBegin starts a structure field or structure array element.
	StructBegin
	// StructEnd ends a structure field or structure array element.
	StructEnd
	// Done means iteration completed successfully.
	Done
	// Error means iteration stopped with an error available from Err.
	Error
)

// String returns the state name.
func (s State) String() string {
	switch s {
	case BeforeFirst:
		return "BeforeFirst"
	case Value:
		return "Value"
	case ArrayBegin:
		return "ArrayBegin"
	case ArrayEnd:
		return "ArrayEnd"
	case StructBegin:
		return "StructBegin"
	case StructEnd:
		return "StructEnd"
	case Done:
		return "Done"
	case Error:
		return "Error"
	default:
		return "State(?)"
	}
}

// Limits bounds memory, nesting, and work performed on untrusted events.
// Zero fields select the documented defaults.
type Limits struct {
	MaxEventSize    int
	MaxMetadataSize int
	MaxPayloadSize  int
	MaxDepth        int
	MaxItems        int
	MaxTransitions  int
}

const (
	defaultMaxEventSize    = 16 << 20
	defaultMaxMetadataSize = 1 << 16
	defaultMaxPayloadSize  = 16 << 20
	defaultMaxDepth        = 8
	defaultMaxItems        = 4096
	defaultMaxTransitions  = 4096
)

// DefaultLimits returns the limits used for zero-valued Limits fields.
func DefaultLimits() Limits { return (Limits{}).normalized() }

func (l Limits) normalized() Limits {
	if l.MaxEventSize == 0 {
		l.MaxEventSize = defaultMaxEventSize
	}
	if l.MaxMetadataSize == 0 {
		l.MaxMetadataSize = defaultMaxMetadataSize
	}
	if l.MaxPayloadSize == 0 {
		l.MaxPayloadSize = defaultMaxPayloadSize
	}
	if l.MaxDepth == 0 {
		l.MaxDepth = defaultMaxDepth
	}
	if l.MaxItems == 0 {
		l.MaxItems = defaultMaxItems
	}
	if l.MaxTransitions == 0 {
		l.MaxTransitions = defaultMaxTransitions
	}
	return l
}

func (l Limits) valid() bool {
	return l.MaxEventSize > 0 && l.MaxMetadataSize > 0 &&
		l.MaxPayloadSize > 0 && l.MaxDepth > 0 &&
		l.MaxDepth <= 8 && l.MaxItems > 0 && l.MaxTransitions > 0
}

// Extension describes an unrecognized nonzero header extension. Data borrows
// the event input.
type Extension struct {
	Kind   eventheader.ExtensionKind
	Size   uint16
	Chain  bool
	Offset int
	Data   []byte
}

// EventInfo contains EventHeader information not represented by
// tracepoint.Record.
type EventInfo struct {
	Provider     string
	Keyword      uint64
	Options      string
	Header       eventheader.Header
	ByteOrder    tracepoint.ByteOrder
	Pointer64    bool
	EventName    string
	EventNameRaw []byte
	ActivityID   tracepoint.Optional[eventheader.ActivityID]
	RelatedID    tracepoint.Optional[eventheader.ActivityID]
	Extensions   []Extension
	Metadata     []byte
	Payload      []byte
	Diagnostics  []tracepoint.Diagnostic
}

// Item describes the current value or container transition. NameRaw and Raw
// borrow the event input. Format retains unknown numeric format values.
type Item struct {
	Name       string
	NameRaw    []byte
	Encoding   eventheader.FieldEncoding
	Format     eventheader.FieldFormat
	Tag        eventheader.FieldTag
	ArrayKind  eventheader.ArrayKind
	ArrayCount uint16
	ArrayIndex int
	Depth      int
	Offset     int
	Raw        []byte
	Value      tracepoint.Value
}

// Decoder decodes EventHeader events. It is safe for concurrent use after its
// Limits field is no longer modified.
type Decoder struct {
	Limits Limits
}

// New returns a decoder with default limits.
func New() *Decoder { return &Decoder{} }

type fieldDef struct {
	name      string
	nameRaw   []byte
	encoding  eventheader.FieldEncoding
	format    eventheader.FieldFormat
	tag       eventheader.FieldTag
	arrayKind eventheader.ArrayKind
	count     uint16
	depth     int
	offset    int
	children  []*fieldDef
}

type parsedEvent struct {
	info          EventInfo
	order         binary.ByteOrder
	payload       []byte
	payloadOffset int
	fields        []*fieldDef
	raw           []byte
}
