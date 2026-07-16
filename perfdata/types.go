package perfdata

import (
	"encoding/binary"
	"io"

	"github.com/cataggar/LinuxTracepoints-Go/tracefs"
	"github.com/cataggar/LinuxTracepoints-Go/tracepoint"
)

const (
	FeatureTracingData = 1
	FeatureEventDesc   = 12
	FeatureClockID     = 23
	FeatureCompressed  = 27
	FeatureClockData   = 29
)

const (
	RecordMmap          = 1
	RecordLost          = 2
	RecordComm          = 3
	RecordExit          = 4
	RecordThrottle      = 5
	RecordUnthrottle    = 6
	RecordFork          = 7
	RecordSample        = 9
	RecordMmap2         = 10
	RecordLostSamples   = 13
	RecordSwitch        = 14
	RecordSwitchCPUWide = 15
)

const (
	SampleIP         uint64 = 1 << 0
	SampleTID        uint64 = 1 << 1
	SampleTime       uint64 = 1 << 2
	SampleAddr       uint64 = 1 << 3
	SampleRead       uint64 = 1 << 4
	SampleCallchain  uint64 = 1 << 5
	SampleID         uint64 = 1 << 6
	SampleCPU        uint64 = 1 << 7
	SamplePeriod     uint64 = 1 << 8
	SampleStreamID   uint64 = 1 << 9
	SampleRaw        uint64 = 1 << 10
	SampleIdentifier uint64 = 1 << 16
)

// Limits bounds allocations and count-controlled work. Zero selects a
// conservative default.
type Limits struct {
	MaxFeatureBytes    int64
	MaxMetadataBytes   int64
	MaxAttrs           int
	MaxIDs             int
	MaxRecordBytes     int
	MaxReadValues      int
	MaxCallchain       int
	MaxFormatBytes     int
	MaxFormatFields    int
	MaxArrayElements   int
	MaxPostRecordBytes int64
}

// Options controls decoding.
type Options struct {
	Limits Limits
	// KeepMetadataRecords causes pipe metadata and round markers to be
	// returned as raw records. By default they are consumed internally.
	KeepMetadataRecords bool
}

// Attr is an owned portable view of perf_event_attr. Raw includes future
// fields not understood by this package.
type Attr struct {
	Type             uint32
	Size             uint32
	Config           uint64
	SamplePeriod     uint64
	SampleType       uint64
	ReadFormat       uint64
	Options          uint64
	WakeupEvents     uint32
	BreakpointType   uint32
	Config1          uint64
	Config2          uint64
	BranchSampleType uint64
	SampleIDAll      bool
	UseClockID       bool
	ClockID          int32
	SampleRegsUser   uint64
	SampleStackUser  uint32
	SampleRegsIntr   uint64
	AuxWatermark     uint32
	SampleMaxStack   uint16
	AuxSampleSize    uint32
	SigData          uint64
	Config3          uint64
	Raw              []byte
	UnknownTail      []byte
}

// EventDescriptor associates a perf attribute, display name, IDs, and an
// optional tracefs format.
type EventDescriptor struct {
	Attr   Attr
	Name   string
	IDs    []uint64
	Format *tracefs.Format
}

// Feature is an owned raw perf header feature.
type Feature struct {
	Index uint16
	Data  []byte
}

// TracingData retains the decoded tracing-data container and its opaque
// ancillary blocks.
type TracingData struct {
	Version      string
	ByteOrder    tracepoint.ByteOrder
	LongSize     int
	PageSize     uint32
	HeaderPage   []byte
	HeaderEvent  []byte
	Ftrace       [][]byte
	Kallsyms     []byte
	Printk       []byte
	SavedCmdline []byte
	Raw          []byte
	Trailing     []byte
}

// ClockInfo describes perf timestamp metadata.
type ClockInfo struct {
	ID               int32
	IDKnown          bool
	Clock            tracepoint.Clock
	ResolutionNS     uint64
	DataVersion      uint32
	WallClockNS      uint64
	ClockIDTimeNS    uint64
	EpochOffset      int64
	EpochOffsetKnown bool
}

// SampleDetails retains the perf sample envelope not represented directly by
// tracepoint.Record.
type SampleDetails struct {
	Identifier            tracepoint.Optional[uint64]
	IP                    tracepoint.Optional[uint64]
	Address               tracepoint.Optional[uint64]
	ID                    tracepoint.Optional[uint64]
	StreamID              tracepoint.Optional[uint64]
	Period                tracepoint.Optional[uint64]
	TimeEnabled           tracepoint.Optional[uint64]
	TimeRunning           tracepoint.Optional[uint64]
	Read                  []ReadValue
	Callchain             []uint64
	Raw                   []byte
	TrailingSampleData    []byte
	UnsupportedSampleBits uint64
}

// ReadValue is one counter in PERF_SAMPLE_READ.
type ReadValue struct {
	Value uint64
	ID    tracepoint.Optional[uint64]
	Lost  tracepoint.Optional[uint64]
}

// RecordDetails describes the most recently returned record.
type RecordDetails struct {
	Type         uint32
	Misc         uint16
	Size         uint16
	ID           tracepoint.Optional[uint64]
	StreamID     tracepoint.Optional[uint64]
	Sample       *SampleDetails
	Comm         *CommDetails
	Task         *TaskDetails
	Mmap         *MmapDetails
	Switch       *SwitchDetails
	PostDataSize uint64
}

type CommDetails struct {
	Name string
}

type TaskDetails struct {
	ParentPID int32
	ParentTID int32
}

type MmapDetails struct {
	Address    uint64
	Length     uint64
	PageOffset uint64
	Filename   string
	Major      uint32
	Minor      uint32
	Inode      uint64
	Generation uint64
	Protection uint32
	Flags      uint32
	BuildID    []byte
}

type SwitchDetails struct {
	Out         bool
	Preempt     bool
	NextPrevPID tracepoint.Optional[int32]
	NextPrevTID tracepoint.Optional[int32]
}

// Reader decodes one seek or pipe-mode stream.
type Reader struct {
	at        io.ReaderAt
	stream    io.Reader
	fileSize  int64
	pipe      bool
	order     binary.ByteOrder
	byteOrder tracepoint.ByteOrder
	offset    int64
	dataEnd   int64
	index     uint64
	limits    Limits
	opts      Options
	closed    bool
	terminal  error
	buf       []byte

	attrs         []*eventDesc
	byID          map[uint64]*eventDesc
	formats       map[uint32]*tracefs.Format
	features      map[uint16][]byte
	eventTypes    []byte
	tracing       TracingData
	clock         ClockInfo
	longSize      int
	pageSize      uint32
	metadataBytes int64

	layoutSet       bool
	sampleIDOffset  int
	suffixLayoutSet bool
	suffixMask      uint64
	suffixIDAll     bool
	sampleIDAll     bool
	noSampleIDAll   bool
	current         RecordDetails
}

type eventDesc struct {
	attr   Attr
	name   string
	ids    []uint64
	format *tracefs.Format
}

func defaultLimits(l Limits) (Limits, error) {
	if l.MaxFeatureBytes == 0 {
		l.MaxFeatureBytes = 64 << 20
	}
	if l.MaxMetadataBytes == 0 {
		l.MaxMetadataBytes = 128 << 20
	}
	if l.MaxAttrs == 0 {
		l.MaxAttrs = 65536
	}
	if l.MaxIDs == 0 {
		l.MaxIDs = 1000000
	}
	if l.MaxRecordBytes == 0 {
		l.MaxRecordBytes = 65535
	}
	if l.MaxReadValues == 0 {
		l.MaxReadValues = 4096
	}
	if l.MaxCallchain == 0 {
		l.MaxCallchain = 4096
	}
	if l.MaxFormatBytes == 0 {
		l.MaxFormatBytes = 1 << 20
	}
	if l.MaxFormatFields == 0 {
		l.MaxFormatFields = 4096
	}
	if l.MaxArrayElements == 0 {
		l.MaxArrayElements = 4096
	}
	if l.MaxPostRecordBytes == 0 {
		l.MaxPostRecordBytes = 64 << 20
	}
	if l.MaxFeatureBytes < 0 || l.MaxMetadataBytes < 0 || l.MaxAttrs < 0 ||
		l.MaxIDs < 0 || l.MaxRecordBytes < 8 || l.MaxRecordBytes > 65535 ||
		l.MaxReadValues < 0 || l.MaxCallchain < 0 || l.MaxFormatBytes < 0 ||
		l.MaxFormatFields < 0 || l.MaxArrayElements < 0 {
		return Limits{}, invalid("options", "negative or invalid limit")
	}
	if l.MaxPostRecordBytes < 0 {
		return Limits{}, invalid("options", "negative or invalid limit")
	}
	return l, nil
}
