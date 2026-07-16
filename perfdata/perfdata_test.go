package perfdata

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/cataggar/LinuxTracepoints-Go/tracepoint"
)

const testFormat = `name: test_event
ID: 123
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned int value;	offset:8;	size:4;	signed:0;
	field:__data_loc char[] text;	offset:12;	size:4;	signed:0;
print fmt: ""
`

func TestSeekAndPipeEquivalent(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		raw := testPayload(order)
		sample := sampleRecord(order, 77, 10, 11, 100, 3, raw)
		tracing := tracingBlob(order, 4, testFormat)
		seek := seekFixture(order, sample, tracing, 77)
		pipe := pipeFixture(order, sample, tracing, 77)

		sr, err := Open(bytes.NewReader(seek), int64(len(seek)), Options{})
		if err != nil {
			t.Fatalf("Open(%T): %v", order, err)
		}
		pr, err := OpenPipe(bytes.NewReader(pipe), Options{})
		if err != nil {
			t.Fatalf("OpenPipe(%T): %v", order, err)
		}
		for _, reader := range []*Reader{sr, pr} {
			record, err := reader.Next()
			if err != nil {
				t.Fatal(err)
			}
			if record.Kind != tracepoint.RecordEvent || record.Identity.Name != "test_event" {
				t.Fatalf("record = %#v", record)
			}
			if record.PID.Value != 10 || record.TID.Value != 11 || record.CPU.Value != 3 || record.Timestamp.Nanoseconds != 100 {
				t.Fatalf("envelope = %#v", record)
			}
			if got := record.Event.Fields[0].Value.Unsigned; got != 42 {
				t.Fatalf("value = %d", got)
			}
			if got := record.Event.Fields[1].Value.Text; got != "hi" {
				t.Fatalf("text = %q", got)
			}
			if _, err := reader.Next(); !errors.Is(err, io.EOF) {
				t.Fatalf("EOF = %v", err)
			}
		}
		if sr.LongSize() != 4 || sr.PageSize() != 4096 || sr.ByteOrder() == tracepoint.ByteOrderUnknown {
			t.Fatal("metadata accessors")
		}
	}
}

func TestHeterogeneousSampleAttrs(t *testing.T) {
	limits, err := defaultLimits(Limits{})
	if err != nil {
		t.Fatal(err)
	}
	r := newReader(Options{}, limits)
	r.order, r.byteOrder = binary.LittleEndian, tracepoint.ByteOrderLittle
	timeAttr := Attr{SampleType: SampleIdentifier | SampleTime}
	cpuAttr := Attr{SampleType: SampleIdentifier | SampleCPU}
	if err := r.addDescriptor(timeAttr, "time", []uint64{11}); err != nil {
		t.Fatal(err)
	}
	if err := r.addDescriptor(cpuAttr, "cpu", []uint64{22}); err != nil {
		t.Fatalf("heterogeneous attrs rejected: %v", err)
	}

	timeRaw := record(binary.LittleEndian, RecordSample, 0,
		append(u64(binary.LittleEndian, 11), u64(binary.LittleEndian, 123)...))
	timeRecord := r.decodeSample(timeRaw)
	if timeRecord.Kind != tracepoint.RecordRaw || timeRecord.Timestamp.Nanoseconds != 123 {
		t.Fatalf("time sample = %#v", timeRecord)
	}
	cpuBody := append(u64(binary.LittleEndian, 22), u32(binary.LittleEndian, 7)...)
	cpuBody = append(cpuBody, u32(binary.LittleEndian, 0)...)
	cpuRecord := r.decodeSample(record(binary.LittleEndian, RecordSample, 0, cpuBody))
	if cpuRecord.Kind != tracepoint.RecordRaw || !cpuRecord.CPU.Present || cpuRecord.CPU.Value != 7 {
		t.Fatalf("CPU sample = %#v", cpuRecord)
	}

	differentOffset := Attr{SampleType: SampleTID | SampleID}
	if err := r.addDescriptor(differentOffset, "", []uint64{33}); !errors.Is(err, tracepoint.ErrInvalid) {
		t.Fatalf("different lookup offset error = %v", err)
	}

	withSuffix := Attr{SampleType: SampleIdentifier | SampleTime, SampleIDAll: true}
	mixed := newReader(Options{}, limits)
	mixed.order = binary.LittleEndian
	if err := mixed.addDescriptor(timeAttr, "", []uint64{1}); err != nil {
		t.Fatal(err)
	}
	if err := mixed.addDescriptor(withSuffix, "", []uint64{2}); !errors.Is(err, tracepoint.ErrInvalid) {
		t.Fatalf("mixed sample_id_all error = %v", err)
	}

	suffixes := newReader(Options{}, limits)
	suffixes.order = binary.LittleEndian
	if err := suffixes.addDescriptor(withSuffix, "", []uint64{1}); err != nil {
		t.Fatal(err)
	}
	differentSuffix := Attr{SampleType: SampleIdentifier | SampleCPU, SampleIDAll: true}
	if err := suffixes.addDescriptor(differentSuffix, "", []uint64{2}); err != nil {
		t.Fatalf("identifier-dispatched suffixes rejected: %v", err)
	}

	commBody := append(append(u32(binary.LittleEndian, 3), u32(binary.LittleEndian, 4)...), []byte("cmd\x00\x00\x00\x00\x00")...)
	timeSuffix := append(u64(binary.LittleEndian, 123), u64(binary.LittleEndian, 1)...)
	timeSuffixRecord := suffixes.decodeKnown(RecordComm, 0,
		record(binary.LittleEndian, RecordComm, 0, append(append([]byte(nil), commBody...), timeSuffix...)))
	if timeSuffixRecord.Kind != tracepoint.RecordRaw || timeSuffixRecord.Timestamp.Nanoseconds != 123 ||
		timeSuffixRecord.CPU.Present || suffixes.current.ID.Value != 1 {
		t.Fatalf("time suffix = %#v, details %#v", timeSuffixRecord, suffixes.current)
	}
	suffixes.current = RecordDetails{}
	cpuSuffix := append(append(u32(binary.LittleEndian, 7), u32(binary.LittleEndian, 0)...), u64(binary.LittleEndian, 2)...)
	cpuSuffixRecord := suffixes.decodeKnown(RecordComm, 0,
		record(binary.LittleEndian, RecordComm, 0, append(append([]byte(nil), commBody...), cpuSuffix...)))
	if cpuSuffixRecord.Kind != tracepoint.RecordRaw || !cpuSuffixRecord.CPU.Present || cpuSuffixRecord.CPU.Value != 7 ||
		cpuSuffixRecord.Timestamp.Nanoseconds != 0 || suffixes.current.ID.Value != 2 {
		t.Fatalf("CPU suffix = %#v, details %#v", cpuSuffixRecord, suffixes.current)
	}

	unknownSuffix := append(u64(binary.LittleEndian, 999), u64(binary.LittleEndian, 999)...)
	unknownRecord := suffixes.decodeKnown(RecordComm, 0,
		record(binary.LittleEndian, RecordComm, 0, append(append([]byte(nil), commBody...), unknownSuffix...)))
	if unknownRecord.Kind != tracepoint.RecordCorrupt ||
		!errors.Is(unknownRecord.Diagnostics[0].Err, tracepoint.ErrUnknownID) {
		t.Fatalf("unknown terminal identifier = %#v", unknownRecord)
	}

	ambiguous := newReader(Options{}, limits)
	ambiguous.order = binary.LittleEndian
	if err := ambiguous.addDescriptor(Attr{SampleType: SampleID | SampleCPU, SampleIDAll: true}, "", []uint64{3}); err != nil {
		t.Fatal(err)
	}
	if err := ambiguous.addDescriptor(Attr{SampleType: SampleID | SampleStreamID, SampleIDAll: true}, "", []uint64{4}); !errors.Is(err, tracepoint.ErrInvalid) {
		t.Fatalf("ambiguous suffix error = %v", err)
	}
}

func TestLegacyClockIDFeatureIsResolution(t *testing.T) {
	limits, err := defaultLimits(Limits{})
	if err != nil {
		t.Fatal(err)
	}
	r := newReader(Options{}, limits)
	r.order = binary.LittleEndian
	if err := r.addDescriptor(Attr{UseClockID: true, ClockID: 7}, "", []uint64{1}); err != nil {
		t.Fatal(err)
	}
	feature := u64(binary.LittleEndian, 1)
	if err := r.applyFeature(FeatureClockID, feature); err != nil {
		t.Fatal(err)
	}
	feature[0] = 9
	info := r.ClockInfo()
	if !info.IDKnown || info.ID != 7 || info.ResolutionNS != 1 {
		t.Fatalf("clock info = %#v", info)
	}
	raw, ok := r.Feature(FeatureClockID)
	if !ok || binary.LittleEndian.Uint64(raw) != 1 {
		t.Fatalf("raw feature = %x, %v", raw, ok)
	}
}

func TestUnknownIDThenLostAndUnknown(t *testing.T) {
	order := binary.LittleEndian
	bad := sampleRecord(order, 999, 1, 2, 3, 4, testPayload(order))
	good := sampleRecord(order, 77, 1, 2, 4, 4, testPayload(order))
	lostBody := append(u64(order, 77), u64(order, 9)...)
	lost := record(order, RecordLost, 0, lostBody)
	unknown := record(order, 55, 0, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	records := append(append(append(bad, good...), lost...), unknown...)
	stream := pipeFixture(order, records, tracingBlob(order, 8, testFormat), 77)
	r, err := OpenPipe(bytes.NewReader(stream), Options{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := r.Next()
	if err != nil || first.Kind != tracepoint.RecordCorrupt || !errors.Is(first.Diagnostics[0].Err, tracepoint.ErrUnknownID) {
		t.Fatalf("unknown = %#v, %v", first, err)
	}
	second, err := r.Next()
	if err != nil || second.Kind != tracepoint.RecordEvent {
		t.Fatalf("valid sample after unknown = %#v, %v", second, err)
	}
	third, err := r.Next()
	if err != nil || third.Kind != tracepoint.RecordLost || third.Lost.Count != 9 {
		t.Fatalf("lost = %#v, %v", third, err)
	}
	fourth, err := r.Next()
	if err != nil || fourth.Kind != tracepoint.RecordRaw {
		t.Fatalf("raw = %#v, %v", fourth, err)
	}
}

func TestClockOffsetsAndMerge(t *testing.T) {
	order := binary.LittleEndian
	makeReader := func(tm uint64, wall, clock uint64) *Reader {
		sample := sampleRecord(order, 77, 1, 1, tm, 0, testPayload(order))
		stream := pipeFixture(order, sample, tracingBlob(order, 8, testFormat), 77)
		clockData := append(append(append(u32(order, 1), u32(order, 1)...), u64(order, wall)...), u64(order, clock)...)
		feature := featureRecord(order, FeatureClockData, clockData)
		stream = append(stream[:16], append(feature, stream[16:]...)...)
		r, err := OpenPipe(bytes.NewReader(stream), Options{})
		if err != nil {
			t.Fatal(err)
		}
		// Pipe clock metadata is consumed by Next, so Merge needs an explicit offset.
		return r
	}
	a, b := makeReader(10, 1000, 100), makeReader(5, 2000, 200)
	m, err := Merge([]*Reader{a, b}, MergeOptions{EpochOffsets: map[int]int64{0: 900, 1: 1800}})
	if err != nil {
		t.Fatal(err)
	}
	r1, err := m.Next()
	if err != nil {
		t.Fatal(err)
	}
	r2, err := m.Next()
	if err != nil {
		t.Fatal(err)
	}
	if r1.Timestamp.Nanoseconds != 10 || r2.Timestamp.Nanoseconds != 5 {
		t.Fatalf("merge order %d,%d", r1.Timestamp.Nanoseconds, r2.Timestamp.Nanoseconds)
	}
	if info := b.ClockInfo(); !info.EpochOffsetKnown || info.EpochOffset != 1800 {
		t.Fatalf("clock info = %#v", info)
	}

	negative := makeReader(1, 100, 200)
	if _, err := negative.Next(); err != nil {
		t.Fatal(err)
	}
	if info := negative.ClockInfo(); !info.EpochOffsetKnown || info.EpochOffset != -100 {
		t.Fatalf("negative clock info = %#v", info)
	}

	u, _ := OpenPipe(bytes.NewReader(pipeFixture(order, nil, tracingBlob(order, 8, testFormat), 77)), Options{})
	if _, err := Merge([]*Reader{u}, MergeOptions{}); !errors.Is(err, tracepoint.ErrIncomparableClocks) {
		t.Fatalf("incomparable = %v", err)
	}
	if off, ok := signedDifference(100, 200); !ok || off != -100 {
		t.Fatalf("negative offset %d,%v", off, ok)
	}

	makeTie := func(pid uint32) *Reader {
		r, err := OpenPipe(bytes.NewReader(pipeFixture(order, sampleRecord(order, 77, pid, pid, 7, 0, testPayload(order)), tracingBlob(order, 8, testFormat), 77)), Options{})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	tieA, tieB := makeTie(1), makeTie(2)
	tied, err := Merge([]*Reader{tieA, tieB}, MergeOptions{EpochOffsets: map[int]int64{0: 0, 1: 0}})
	if err != nil {
		t.Fatal(err)
	}
	firstTie, _ := tied.Next()
	if firstTie.PID.Value != 1 {
		t.Fatal("stable tie")
	}
	if _, err := Merge([]*Reader{tieA, tieA}, MergeOptions{
		EpochOffsets: map[int]int64{0: 0, 1: 0},
	}); !errors.Is(err, tracepoint.ErrInvalid) {
		t.Fatalf("duplicate merge reader error = %v", err)
	}
}

func TestMalformedCompressionLimitsCloseAndClone(t *testing.T) {
	order := binary.LittleEndian
	compressed := append(pipeHeader(order), record(order, recordCompressed, 0, nil)...)
	r, err := OpenPipe(bytes.NewReader(compressed), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Next(); !errors.Is(err, ErrUnsupportedCompression) {
		t.Fatalf("compression = %v", err)
	}

	truncated := append(pipeHeader(order), []byte{1, 2, 3}...)
	r, _ = OpenPipe(bytes.NewReader(truncated), Options{})
	if _, err = r.Next(); !errors.Is(err, tracepoint.ErrTruncated) {
		t.Fatalf("truncated = %v", err)
	}

	if _, err = OpenPipe(bytes.NewReader(pipeHeader(order)), Options{Limits: Limits{MaxAttrs: -1}}); !errors.Is(err, tracepoint.ErrInvalid) {
		t.Fatalf("limit = %v", err)
	}
	r, _ = OpenPipe(bytes.NewReader(pipeHeader(order)), Options{})
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Next(); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func TestEventDescSampleIDAllAndBorrowing(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		attr := testAttr(order)
		attr[42] = optionByte(order, 18%8)
		name := []byte("named-event\x00\x00\x00\x00\x00")
		eventDesc := append(append(u32(order, 1), u32(order, 64)...), attr...)
		eventDesc = append(eventDesc, u32(order, 1)...)
		eventDesc = append(eventDesc, u32(order, uint32(len(name)))...)
		eventDesc = append(eventDesc, name...)
		eventDesc = append(eventDesc, u64(order, 77)...)

		commBody := append(append(u32(order, 1), u32(order, 2)...), []byte("cmd\x00\x00\x00\x00\x00")...)
		commBody = append(commBody, u32(order, 3)...)
		commBody = append(commBody, u32(order, 4)...)
		commBody = append(commBody, u64(order, 55)...)
		commBody = append(commBody, u32(order, 6)...)
		commBody = append(commBody, u32(order, 0)...)
		commBody = append(commBody, u64(order, 77)...)

		stream := pipeHeader(order)
		stream = append(stream, record(order, recordHeaderAttr, 0, append(attr, u64(order, 77)...))...)
		stream = append(stream, featureRecord(order, FeatureEventDesc, eventDesc)...)
		stream = append(stream, record(order, RecordComm, 0, commBody)...)
		r, err := OpenPipe(bytes.NewReader(stream), Options{})
		if err != nil {
			t.Fatal(err)
		}
		got, err := r.Next()
		if err != nil {
			t.Fatal(err)
		}
		if len(r.EventDescriptors()) != 1 || r.EventDescriptors()[0].Name != "named-event" {
			t.Fatalf("descriptors = %#v", r.EventDescriptors())
		}
		if got.PID.Value != 3 || got.TID.Value != 4 || got.CPU.Value != 6 || got.Timestamp.Nanoseconds != 55 {
			t.Fatalf("sample_id_all = %#v", got)
		}
		if details := r.Details(); !details.ID.Present || details.ID.Value != 77 || details.Comm.Name != "cmd" {
			t.Fatalf("details = %#v", details)
		}
	}

	order := binary.LittleEndian
	one := sampleRecord(order, 77, 1, 2, 3, 4, testPayload(order))
	twoPayload := testPayload(order)
	order.PutUint32(twoPayload[8:], 99)
	two := sampleRecord(order, 77, 1, 2, 4, 4, twoPayload)
	r, _ := OpenPipe(bytes.NewReader(pipeFixture(order, append(one, two...), tracingBlob(order, 8, testFormat), 77)), Options{})
	first, _ := r.Next()
	clone := tracepoint.CloneRecord(first)
	_, _ = r.Next()
	if clone.Event.Fields[0].Value.Unsigned != 42 || clone.Raw[8] != one[8] {
		t.Fatal("CloneRecord did not preserve borrowed data")
	}
}

func TestEventHeaderDispatch(t *testing.T) {
	const format = `name: Provider_L4K2aGgroup
ID: 123
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned char eventheader_flags;	offset:8;	size:1;	signed:0;
print fmt: ""
`
	order := binary.LittleEndian
	metadata := []byte{'E', 'v', 't', 0, 'x', 0, 2}
	event := []byte{6, 0, 12, 0, 0, 0, 0, 4, byte(len(metadata)), 0, 1, 0}
	event = append(event, metadata...)
	event = append(event, 7)
	raw := make([]byte, 8, len(event)+8)
	order.PutUint16(raw, 123)
	order.PutUint32(raw[4:], 9)
	raw = append(raw, event...)
	r, err := OpenPipe(bytes.NewReader(pipeFixture(order, sampleRecord(order, 77, 9, 10, 11, 2, raw), tracingBlob(order, 8, format), 77)), Options{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != tracepoint.RecordEvent || got.Identity.System != "Provider" || got.Identity.Name != "Evt" || got.Event.Fields[0].Value.Unsigned != 7 || len(got.Event.Common) != 4 {
		t.Fatalf("EventHeader = %#v", got)
	}
}

func pipeFixture(order binary.ByteOrder, data, tracing []byte, id uint64) []byte {
	out := pipeHeader(order)
	attr := testAttr(order)
	out = append(out, record(order, recordHeaderAttr, 0, append(attr, u64(order, id)...))...)
	body := u32(order, uint32(len(tracing)))
	out = append(out, record(order, recordHeaderTracingData, 0, body)...)
	out = append(out, tracing...)
	out = append(out, data...)
	return out
}

func seekFixture(order binary.ByteOrder, data, tracing []byte, id uint64) []byte {
	const headerSize = 104
	featureDescOff := headerSize + len(data)
	featureOff := featureDescOff + 16
	attrOff := featureOff + len(tracing)
	idsOff := attrOff + 80
	out := make([]byte, idsOff+8)
	copy(out[:8], magic(order))
	order.PutUint64(out[8:], headerSize)
	order.PutUint64(out[16:], 80)
	putSection(order, out[24:], uint64(attrOff), 80)
	putSection(order, out[40:], headerSize, uint64(len(data)))
	order.PutUint64(out[72:], 1<<FeatureTracingData)
	copy(out[headerSize:], data)
	putSection(order, out[featureDescOff:], uint64(featureOff), uint64(len(tracing)))
	copy(out[featureOff:], tracing)
	copy(out[attrOff:], testAttr(order))
	putSection(order, out[attrOff+64:], uint64(idsOff), 8)
	order.PutUint64(out[idsOff:], id)
	return out
}

func testAttr(order binary.ByteOrder) []byte {
	b := make([]byte, 64)
	order.PutUint32(b, 2)
	order.PutUint32(b[4:], 64)
	order.PutUint64(b[8:], 123)
	order.PutUint64(b[24:], SampleIdentifier|SampleTID|SampleTime|SampleCPU|SampleRaw)
	return b
}

func tracingBlob(order binary.ByteOrder, longSize byte, format string) []byte {
	b := append([]byte(nil), tracingSignature...)
	b = append(b, []byte("0.6\x00")...)
	if order == binary.BigEndian {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	b = append(b, longSize)
	b = append(b, u32(order, 4096)...)
	b = append(b, []byte("header_page\x00")...)
	b = append(b, u64(order, 0)...)
	b = append(b, []byte("header_event\x00")...)
	b = append(b, u64(order, 0)...)
	b = append(b, u32(order, 0)...)
	b = append(b, u32(order, 1)...)
	b = append(b, []byte("testsys\x00")...)
	b = append(b, u32(order, 1)...)
	b = append(b, u64(order, uint64(len(format)))...)
	b = append(b, format...)
	b = append(b, u32(order, 0)...)
	b = append(b, u32(order, 0)...)
	b = append(b, u64(order, 0)...)
	return b
}

func testPayload(order binary.ByteOrder) []byte {
	b := make([]byte, 19)
	order.PutUint16(b, 123)
	order.PutUint32(b[4:], 10)
	order.PutUint32(b[8:], 42)
	order.PutUint32(b[12:], uint32(3<<16|16))
	copy(b[16:], []byte("hi\x00"))
	return b
}

func sampleRecord(order binary.ByteOrder, id uint64, pid, tid uint32, tm uint64, cpu uint32, raw []byte) []byte {
	body := u64(order, id)
	body = append(body, u32(order, pid)...)
	body = append(body, u32(order, tid)...)
	body = append(body, u64(order, tm)...)
	body = append(body, u32(order, cpu)...)
	body = append(body, u32(order, 0)...)
	body = append(body, u32(order, uint32(len(raw)))...)
	body = append(body, raw...)
	for (8+len(body))%8 != 0 {
		body = append(body, 0)
	}
	return record(order, RecordSample, 0, body)
}

func featureRecord(order binary.ByteOrder, index uint16, data []byte) []byte {
	return record(order, recordHeaderFeature, 0, append(u64(order, uint64(index)), data...))
}
func record(order binary.ByteOrder, typ uint32, misc uint16, body []byte) []byte {
	b := make([]byte, 8, len(body)+8)
	order.PutUint32(b, typ)
	order.PutUint16(b[4:], misc)
	order.PutUint16(b[6:], uint16(len(body)+8))
	return append(b, body...)
}
func pipeHeader(order binary.ByteOrder) []byte {
	b := make([]byte, 16)
	copy(b, magic(order))
	order.PutUint64(b[8:], 16)
	return b
}
func magic(order binary.ByteOrder) []byte {
	if order == binary.BigEndian {
		return magicBig[:]
	}
	return magicLittle[:]
}
func putSection(order binary.ByteOrder, b []byte, off, size uint64) {
	order.PutUint64(b, off)
	order.PutUint64(b[8:], size)
}
func u32(order binary.ByteOrder, v uint32) []byte {
	b := make([]byte, 4)
	order.PutUint32(b, v)
	return b
}
func u64(order binary.ByteOrder, v uint64) []byte {
	b := make([]byte, 8)
	order.PutUint64(b, v)
	return b
}

func optionByte(order binary.ByteOrder, bit int) byte {
	if order == binary.BigEndian {
		return 1 << (7 - bit)
	}
	return 1 << bit
}
