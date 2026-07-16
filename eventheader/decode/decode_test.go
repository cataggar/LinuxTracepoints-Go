package decode

import (
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"reflect"
	"testing"
	"unicode/utf8"

	"github.com/cataggar/LinuxTracepoints-Go/eventheader"
	"github.com/cataggar/LinuxTracepoints-Go/tracepoint"
)

func eventBytes(order binary.ByteOrder, extraFlags eventheader.HeaderFlags, metadata, payload []byte) []byte {
	flags := eventheader.HeaderFlagExtension | extraFlags
	if order == binary.LittleEndian {
		flags |= eventheader.HeaderFlagLittleEndian
	}
	data := []byte{byte(flags), 2, 0, 0, 0, 0, byte(eventheader.OpcodeReply), byte(eventheader.LevelInformation)}
	order.PutUint16(data[2:4], 0x1234)
	order.PutUint16(data[4:6], 0x5678)
	var extension [4]byte
	order.PutUint16(extension[:2], uint16(len(metadata)))
	order.PutUint16(extension[2:], uint16(eventheader.ExtensionMetadata))
	data = append(data, extension[:]...)
	data = append(data, metadata...)
	return append(data, payload...)
}

func addField(metadata []byte, name string, encoding eventheader.FieldEncoding, format eventheader.FieldFormat) []byte {
	metadata = append(metadata, name...)
	metadata = append(metadata, 0)
	if format == eventheader.FormatDefault {
		return append(metadata, byte(encoding))
	}
	return append(metadata, byte(encoding|eventheader.EncodingChainFlag), byte(format))
}

func TestDecodeAllEncodingsLittleAndBigEndian(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		metadata := []byte("All\x00")
		metadata = addField(metadata, "v8", eventheader.EncodingValue8, eventheader.FormatDefault)
		metadata = addField(metadata, "v16", eventheader.EncodingValue16, eventheader.FormatSignedInt)
		metadata = addField(metadata, "v32", eventheader.EncodingValue32, eventheader.FormatFloat)
		metadata = addField(metadata, "v64", eventheader.EncodingValue64, eventheader.FormatHexInt)
		metadata = addField(metadata, "v128", eventheader.EncodingValue128, eventheader.FormatUUID)
		metadata = addField(metadata, "z8", eventheader.EncodingZStringChar8, eventheader.FormatDefault)
		metadata = addField(metadata, "z16", eventheader.EncodingZStringChar16, eventheader.FormatDefault)
		metadata = addField(metadata, "z32", eventheader.EncodingZStringChar32, eventheader.FormatDefault)
		metadata = addField(metadata, "s8", eventheader.EncodingStringLength16Char8, eventheader.FormatDefault)
		metadata = addField(metadata, "s16", eventheader.EncodingStringLength16Char16, eventheader.FormatDefault)
		metadata = addField(metadata, "s32", eventheader.EncodingStringLength16Char32, eventheader.FormatDefault)
		metadata = addField(metadata, "bin", eventheader.EncodingBinaryLength16Char8, eventheader.FormatDefault)

		payload := []byte{7}
		payload = append16(payload, order, ^uint16(1))
		payload = append32(payload, order, math.Float32bits(1.5))
		payload = append64(payload, order, 0x1122334455667788)
		uuid := [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
		payload = append(payload, uuid[:]...)
		payload = append(payload, 'h', 'i', 0)
		payload = append16(payload, order, 'A')
		payload = append16(payload, order, 0)
		payload = append32(payload, order, 'B')
		payload = append32(payload, order, 0)
		payload = append16(payload, order, 2)
		payload = append(payload, "ok"...)
		payload = append16(payload, order, 1)
		payload = append16(payload, order, 'C')
		payload = append16(payload, order, 1)
		payload = append32(payload, order, 'D')
		payload = append16(payload, order, 3)
		payload = append(payload, 9, 8, 7)

		record, err := Decode("Provider_L4K2aGgroup", eventBytes(order, eventheader.HeaderFlagPointer64, metadata, payload))
		if err != nil {
			t.Fatal(err)
		}
		fields := record.Event.Fields
		if len(fields) != 12 || fields[0].Value.Unsigned != 7 || fields[1].Value.Signed != -2 ||
			fields[2].Value.Float != 1.5 || fields[3].Value.Unsigned != 0x1122334455667788 ||
			fields[4].Value.UUID != uuid || fields[5].Value.Text != "hi" ||
			fields[6].Value.Text != "A" || fields[7].Value.Text != "B" ||
			fields[8].Value.Text != "ok" || fields[9].Value.Text != "C" ||
			fields[10].Value.Text != "D" || !reflect.DeepEqual(fields[11].Value.Binary, []byte{9, 8, 7}) {
			t.Fatalf("incorrect decode for %T: %#v", order, fields)
		}
		if record.Identity.System != "Provider" || record.Identity.Name != "All" ||
			record.Identity.ID != 0x1234 || fields[0].Value.Raw[0] != 7 {
			t.Fatalf("identity or raw data not retained: %#v", record)
		}
	}
}

func TestFormats(t *testing.T) {
	order := binary.LittleEndian
	tests := []struct {
		format eventheader.FieldFormat
		raw    []byte
		kind   tracepoint.ValueKind
	}{
		{eventheader.FormatDefault, []byte{1}, tracepoint.ValueUnsigned},
		{eventheader.FormatUnsignedInt, []byte{1, 0}, tracepoint.ValueUnsigned},
		{eventheader.FormatSignedInt, []byte{0xff}, tracepoint.ValueSigned},
		{eventheader.FormatHexInt, []byte{1, 0, 0, 0}, tracepoint.ValueUnsigned},
		{eventheader.FormatErrno, []byte{2, 0, 0, 0}, tracepoint.ValueSigned},
		{eventheader.FormatPID, []byte{3, 0, 0, 0}, tracepoint.ValueSigned},
		{eventheader.FormatTime, []byte{1, 0, 0, 0}, tracepoint.ValueTime},
		{eventheader.FormatBoolean, []byte{1}, tracepoint.ValueBool},
		{eventheader.FormatFloat, []byte{0, 0, 0x80, 0x3f}, tracepoint.ValueFloat},
		{eventheader.FormatHexBytes, []byte{1}, tracepoint.ValueBinary},
		{eventheader.FormatString8, []byte{0xe9}, tracepoint.ValueText},
		{eventheader.FormatStringUTF, []byte("x"), tracepoint.ValueText},
		{eventheader.FormatStringUTFBOM, []byte{0xef, 0xbb, 0xbf, 'x'}, tracepoint.ValueText},
		{eventheader.FormatStringXML, []byte("<x/>"), tracepoint.ValueText},
		{eventheader.FormatStringJSON, []byte("{}"), tracepoint.ValueText},
		{eventheader.FormatUUID, make([]byte, 16), tracepoint.ValueUUID},
		{eventheader.FormatPort, []byte{0, 80}, tracepoint.ValuePort},
		{eventheader.FormatIPAddress, []byte{127, 0, 0, 1}, tracepoint.ValueIP},
		{eventheader.FormatIPAddressObsolete, make([]byte, 16), tracepoint.ValueIP},
	}
	for _, test := range tests {
		encoding := eventheader.EncodingBinaryLength16Char8
		if test.format == eventheader.FormatDefault {
			encoding = eventheader.EncodingValue8
		}
		value := decodeScalar(&fieldDef{encoding: encoding, format: test.format}, test.raw, 0, order, tracepoint.ByteOrderLittle)
		if value.Kind != test.kind || !value.Valid {
			t.Errorf("format %d = kind %d valid %v, want %d true", test.format, value.Kind, value.Valid, test.kind)
		}
	}
	unknown := decodeScalar(&fieldDef{encoding: eventheader.EncodingValue8, format: 42}, []byte{9}, 0, order, tracepoint.ByteOrderLittle)
	if unknown.Kind != tracepoint.ValueUnsigned || unknown.Format != "42" {
		t.Fatalf("unknown format was not retained with default interpretation: %#v", unknown)
	}
}

func TestTimeUsesSignedUnixSeconds(t *testing.T) {
	order := binary.LittleEndian
	tests := []struct {
		name     string
		encoding eventheader.FieldEncoding
		raw      []byte
		want     int64
	}{
		{"positive32", eventheader.EncodingValue32, append32(nil, order, 1_700_000_000), 1_700_000_000_000_000_000},
		{"negative32", eventheader.EncodingValue32, append32(nil, order, ^uint32(1_699_999_999)), -1_700_000_000_000_000_000},
		{"positive64", eventheader.EncodingValue64, append64(nil, order, 1_700_000_000), 1_700_000_000_000_000_000},
		{"negative64", eventheader.EncodingValue64, append64(nil, order, ^uint64(1_699_999_999)), -1_700_000_000_000_000_000},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := decodeScalar(&fieldDef{encoding: test.encoding, format: eventheader.FormatTime},
				test.raw, 4, order, tracepoint.ByteOrderLittle)
			got, ok := value.Time.UnixNano()
			if !value.Valid || value.Kind != tracepoint.ValueTime || !ok || got != test.want {
				t.Fatalf("time = %#v, UnixNano = %d,%v", value, got, ok)
			}
		})
	}

	raw := append64(nil, order, math.MaxInt64)
	value := decodeScalar(&fieldDef{encoding: eventheader.EncodingValue64, format: eventheader.FormatTime},
		raw, 9, order, tracepoint.ByteOrderLittle)
	if value.Valid || value.Kind != tracepoint.ValueTime || len(value.Diagnostics) != 1 ||
		!reflect.DeepEqual(value.Raw, raw) || !errors.Is(value.Diagnostics[0], tracepoint.ErrInvalid) {
		t.Fatalf("overflow time = %#v", value)
	}
}

func TestXMLAndJSONUseBOM(t *testing.T) {
	order := binary.LittleEndian
	for _, test := range []struct {
		format eventheader.FieldFormat
		text   string
	}{
		{eventheader.FormatStringXML, "<x/>"},
		{eventheader.FormatStringJSON, `{"x":1}`},
	} {
		raw := []byte{0xff, 0xfe}
		for _, r := range test.text {
			raw = append16(raw, order, uint16(r))
		}
		value := decodeScalar(&fieldDef{
			encoding: eventheader.EncodingStringLength16Char8,
			format:   test.format,
		}, raw, 0, order, tracepoint.ByteOrderLittle)
		if !value.Valid || value.Text != test.text {
			t.Errorf("format %d = %#v", test.format, value)
		}
	}
}

func TestInapplicableFormatsFallBackWithoutInvalidity(t *testing.T) {
	order := binary.LittleEndian
	fixed := decodeScalar(&fieldDef{
		encoding: eventheader.EncodingValue64,
		format:   eventheader.FormatUUID,
	}, append64(nil, order, 7), 0, order, tracepoint.ByteOrderLittle)
	if !fixed.Valid || fixed.Kind != tracepoint.ValueUnsigned || fixed.Unsigned != 7 {
		t.Fatalf("fixed fallback = %#v", fixed)
	}

	metadata := addField([]byte("Fallback\x00"), "text",
		eventheader.EncodingStringLength16Char8, eventheader.FormatUUID)
	record, err := Decode("P_L4K0", eventBytes(order, 0, metadata, append(append16(nil, order, 3), "abc"...)))
	if err != nil {
		t.Fatal(err)
	}
	counted := record.Event.Fields[0].Value
	if !counted.Valid || counted.Kind != tracepoint.ValueText || counted.Text != "abc" {
		t.Fatalf("counted fallback = %#v", counted)
	}

	metadata = addField([]byte("Counted\x00"), "utf16",
		eventheader.EncodingStringLength16Char16, eventheader.FormatUnsignedInt)
	metadata = addField(metadata, "unknown",
		eventheader.EncodingBinaryLength16Char8, eventheader.FieldFormat(42))
	payload := append16(nil, order, 1)
	payload = append16(payload, order, 'A')
	payload = append16(payload, order, 2)
	payload = append(payload, 9, 8)
	record, err = Decode("P_L4K0", eventBytes(order, 0, metadata, payload))
	if err != nil {
		t.Fatal(err)
	}
	if got := record.Event.Fields[0].Value; !got.Valid || got.Text != "A" {
		t.Fatalf("counted incompatible format fallback = %#v", got)
	}
	if got := record.Event.Fields[1].Value; !got.Valid ||
		!reflect.DeepEqual(got.Binary, []byte{9, 8}) || got.Format != "42" {
		t.Fatalf("counted unknown format fallback = %#v", got)
	}

	invalid := decodeScalar(&fieldDef{
		encoding: eventheader.EncodingValue8,
		format:   eventheader.FormatBoolean,
	}, []byte{2}, 0, order, tracepoint.ByteOrderLittle)
	if invalid.Valid || !errors.Is(invalid.Diagnostics[0], tracepoint.ErrInvalid) {
		t.Fatalf("invalid Boolean accepted: %#v", invalid)
	}
}

func TestValueWidthsAreBits(t *testing.T) {
	order := binary.LittleEndian
	metadata := addField([]byte("Widths\x00"), "scalar", eventheader.EncodingValue16, eventheader.FormatDefault)
	metadata = append(metadata, "array\x00"...)
	metadata = append(metadata, byte(eventheader.EncodingValue8|eventheader.EncodingVArrayFlag))
	metadata = append(metadata, "structure\x00"...)
	metadata = append(metadata, byte(eventheader.EncodingStruct|eventheader.EncodingChainFlag), 1)
	metadata = addField(metadata, "member", eventheader.EncodingValue8, eventheader.FormatDefault)
	payload := append16(nil, order, 1)
	payload = append16(payload, order, 2)
	payload = append(payload, 3, 4, 5)
	record, err := Decode("P_L4K0", eventBytes(order, 0, metadata, payload))
	if err != nil {
		t.Fatal(err)
	}
	fields := record.Event.Fields
	if fields[0].Value.Width != 16 || fields[1].Value.Width != 32 ||
		fields[1].Value.Array[0].Width != 8 || fields[2].Value.Width != 8 {
		t.Fatalf("widths = %d, %d/%d, %d", fields[0].Value.Width,
			fields[1].Value.Width, fields[1].Value.Array[0].Width, fields[2].Value.Width)
	}
	if got := bitWidth(math.MaxInt); got != math.MaxUint32 {
		t.Fatalf("saturated width = %d", got)
	}
}

func TestArraysStructArraysAndStates(t *testing.T) {
	order := binary.LittleEndian
	metadata := []byte("Arrays\x00")
	metadata = append(metadata, "fixed\x00"...)
	metadata = append(metadata, byte(eventheader.EncodingValue8|eventheader.EncodingCArrayFlag), 2, 0)
	metadata = append(metadata, "empty\x00"...)
	metadata = append(metadata, byte(eventheader.EncodingValue16|eventheader.EncodingVArrayFlag))
	metadata = append(metadata, "structs\x00"...)
	metadata = append(metadata, byte(eventheader.EncodingStruct|eventheader.EncodingCArrayFlag|eventheader.EncodingChainFlag), 1, 2, 0)
	metadata = addField(metadata, "member", eventheader.EncodingValue16, eventheader.FormatDefault)
	payload := []byte{4, 5, 0, 0, 10, 0, 20, 0}
	enumerator, err := Start("P_L4K0", eventBytes(order, 0, metadata, payload))
	if err != nil {
		t.Fatal(err)
	}
	var states []State
	for enumerator.Next() {
		states = append(states, enumerator.State())
	}
	if err := enumerator.Err(); err != nil {
		t.Fatal(err)
	}
	want := []State{
		ArrayBegin, Value, Value, ArrayEnd,
		ArrayBegin, ArrayEnd,
		ArrayBegin, StructBegin, Value, StructEnd, StructBegin, Value, StructEnd, ArrayEnd,
	}
	if !reflect.DeepEqual(states, want) {
		t.Fatalf("states = %v, want %v", states, want)
	}
	record, err := Decode("P_L4K0", eventBytes(order, 0, metadata, payload))
	if err != nil {
		t.Fatal(err)
	}
	fields := record.Event.Fields
	if len(fields) != 3 || len(fields[0].Value.Array) != 2 || len(fields[1].Value.Array) != 0 ||
		len(fields[2].Value.Array) != 2 || fields[2].Value.Array[1].Struct[0].Value.Unsigned != 20 {
		t.Fatalf("bad array tree: %#v", fields)
	}
}

func TestMaterializedStructFormatsIgnoreChildCount(t *testing.T) {
	order := binary.LittleEndian
	metadata := []byte("StructFormats\x00")
	metadata = append(metadata, "two\x00"...)
	metadata = append(metadata, byte(eventheader.EncodingStruct|eventheader.EncodingChainFlag), 2)
	for i := 0; i < 2; i++ {
		metadata = addField(metadata, string(rune('a'+i)), eventheader.EncodingValue8, eventheader.FormatUnsignedInt)
	}
	metadata = append(metadata, "six\x00"...)
	metadata = append(metadata, byte(eventheader.EncodingStruct|eventheader.EncodingChainFlag), 6)
	for i := 0; i < 6; i++ {
		metadata = addField(metadata, string(rune('c'+i)), eventheader.EncodingValue8, eventheader.FormatSignedInt)
	}
	metadata = append(metadata, "array\x00"...)
	metadata = append(metadata, byte(eventheader.EncodingStruct|eventheader.EncodingCArrayFlag|eventheader.EncodingChainFlag), 2, 2, 0)
	metadata = addField(metadata, "x", eventheader.EncodingValue8, eventheader.FormatTime)
	metadata = addField(metadata, "y", eventheader.EncodingValue8, eventheader.FormatBoolean)

	record, err := Decode("P_L4K0", eventBytes(order, 0, metadata, []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 10, 0,
	}))
	if err != nil {
		t.Fatal(err)
	}
	fields := record.Event.Fields
	if len(fields) != 3 || fields[0].Value.Format != "struct" || fields[1].Value.Format != "struct" ||
		fields[2].Value.Format != "struct" || len(fields[2].Value.Array) != 2 ||
		fields[2].Value.Array[0].Format != "struct" || fields[2].Value.Array[1].Format != "struct" {
		t.Fatalf("struct formats = %#v", fields)
	}
}

func TestExtensionsHeaderAndTrailingData(t *testing.T) {
	order := binary.BigEndian
	metadata := []byte("Event\x00v\x00\x02")
	header := []byte{byte(eventheader.HeaderFlagExtension | eventheader.HeaderFlagPointer64), 3, 0, 7, 0, 8, 9, 4}
	data := append([]byte(nil), header...)
	data = appendExtension(data, order, 99|eventheader.ExtensionKindChainFlag, []byte{1, 2})
	activity := make([]byte, 32)
	for i := range activity {
		activity[i] = byte(i)
	}
	data = appendExtension(data, order, eventheader.ExtensionActivityID|eventheader.ExtensionKindChainFlag, activity)
	data = appendExtension(data, order, eventheader.ExtensionMetadata, metadata)
	data = append(data, 5, 0, 0, 0)
	enumerator, err := Start("P_L4KffGg", data)
	if err != nil {
		t.Fatal(err)
	}
	info := enumerator.EventInfo()
	if !info.Pointer64 || info.Header.Version != 3 || info.Header.ID != 7 || info.Keyword != 0xff ||
		info.Options != "Gg" || len(info.Extensions) != 1 || !info.Extensions[0].Chain ||
		!info.ActivityID.Present || !info.RelatedID.Present {
		t.Fatalf("header information not retained: %#v", info)
	}
	for enumerator.Next() {
	}
	if enumerator.State() != Done || len(info.Diagnostics) != 1 ||
		info.Diagnostics[0].Severity != tracepoint.SeverityWarning {
		t.Fatalf("padding diagnostic missing: state=%d diagnostics=%#v", enumerator.State(), info.Diagnostics)
	}

	record, err := Decode("P_L4KffGg", data)
	if err != nil {
		t.Fatal(err)
	}
	materialized := record.Event.EventHeader
	if materialized == nil || materialized.Provider != "P" || materialized.Keyword != 0xff ||
		materialized.Flags != uint8(header[0]) || materialized.Version != 3 ||
		materialized.ID != 7 || materialized.Tag != 8 || materialized.Opcode != 9 ||
		materialized.Level != 4 || materialized.ByteOrder != tracepoint.ByteOrderBig ||
		materialized.PointerWidth != 64 || materialized.EventName != "Event" ||
		!materialized.ActivityID.Present || !materialized.RelatedActivityID.Present ||
		len(materialized.Extensions) != 1 || materialized.Extensions[0].Kind != 99 ||
		materialized.Extensions[0].Offset != 8 || !materialized.Extensions[0].Chain ||
		!reflect.DeepEqual(materialized.Metadata, metadata) ||
		!reflect.DeepEqual(materialized.Payload, []byte{5, 0, 0, 0}) {
		t.Fatalf("materialized EventHeader information = %#v", materialized)
	}
	clone := tracepoint.CloneRecord(record)
	data[12], data[len(data)-1] = 0xff, 0xff
	if clone.Event.EventHeader.Extensions[0].Data[0] != 1 ||
		clone.Event.EventHeader.EventNameRaw[0] != 'E' ||
		clone.Event.EventHeader.Metadata[0] != 'E' ||
		clone.Event.EventHeader.Payload[3] != 0 {
		t.Fatal("cloned EventHeader information shares input")
	}
}

func TestRecoverableInvalidValuesAndNames(t *testing.T) {
	metadata := append([]byte("E\x00"), 0xff, 0, byte(eventheader.EncodingStringLength16Char8))
	metadata = addField(metadata, "bool", eventheader.EncodingValue8, eventheader.FormatBoolean)
	data := eventBytes(binary.LittleEndian, 0, metadata, []byte{1, 0, 0xff, 2})
	record, err := Decode("P_L4K0", data)
	if err != nil {
		t.Fatal(err)
	}
	fields := record.Event.Fields
	if utf8.ValidString(fields[0].Name) == false || fields[0].Value.Valid ||
		fields[1].Value.Valid || len(record.Diagnostics) < 3 {
		t.Fatalf("invalid data diagnostics missing: %#v", record)
	}
}

func TestStructuralValidation(t *testing.T) {
	validMeta := []byte("E\x00v\x00\x02")
	valid := eventBytes(binary.LittleEndian, 0, validMeta, []byte{1})
	tests := []struct {
		name string
		data []byte
		err  error
	}{
		{"short header", valid[:7], tracepoint.ErrTruncated},
		{"bad flags", append([]byte{0x80}, valid[1:]...), tracepoint.ErrInvalid},
		{"short extension", valid[:10], tracepoint.ErrTruncated},
		{"zero encoding", eventBytes(binary.LittleEndian, 0, []byte("E\x00v\x00\x00"), nil), tracepoint.ErrInvalid},
		{"unknown encoding", eventBytes(binary.LittleEndian, 0, []byte("E\x00v\x00\x1f"), nil), tracepoint.ErrUnsupported},
		{"both arrays", eventBytes(binary.LittleEndian, 0, []byte("E\x00v\x00\x62"), nil), tracepoint.ErrInvalid},
		{"fixed zero", eventBytes(binary.LittleEndian, 0, []byte("E\x00v\x00\x22\x00\x00"), nil), tracepoint.ErrInvalid},
		{"missing event nul", eventBytes(binary.LittleEndian, 0, []byte("Event"), nil), tracepoint.ErrTruncated},
		{"empty field", eventBytes(binary.LittleEndian, 0, []byte("E\x00\x00\x02"), nil), tracepoint.ErrInvalid},
	}

	for _, test := range tests {
		_, err := Start("P_L4K0", test.data)
		if !errors.Is(err, test.err) {
			t.Errorf("%s error = %v, want %v", test.name, err, test.err)
		}
	}
	truncatedData := eventBytes(binary.LittleEndian, 0, []byte("E\x00v\x00\x05"), []byte{1})
	enumerator, err := Start("P_L4K0", truncatedData)
	if err != nil {
		t.Fatal(err)
	}
	if enumerator.Next() || !errors.Is(enumerator.Err(), tracepoint.ErrTruncated) || enumerator.State() != Error {
		t.Fatalf("payload truncation state/error = %d/%v", enumerator.State(), enumerator.Err())
	}
}

func TestInvalidAndDuplicateExtensions(t *testing.T) {
	order := binary.LittleEndian
	header := []byte{byte(eventheader.HeaderFlagExtension | eventheader.HeaderFlagLittleEndian), 0, 0, 0, 0, 0, 0, 4}
	meta := []byte("E\x00")
	makeData := func(extensions ...[]byte) []byte {
		data := append([]byte(nil), header...)
		for _, extension := range extensions {
			data = append(data, extension...)
		}
		return data
	}
	extension := func(kind eventheader.ExtensionKind, body []byte) []byte {
		return appendExtension(nil, order, kind, body)
	}
	tests := []struct {
		name string
		data []byte
		err  error
	}{
		{"no metadata", makeData(extension(3, nil)), tracepoint.ErrInvalid},
		{"zero kind", makeData(extension(0, nil)), tracepoint.ErrInvalid},
		{"bad activity size", makeData(extension(eventheader.ExtensionActivityID|eventheader.ExtensionKindChainFlag, make([]byte, 15)), extension(eventheader.ExtensionMetadata, meta)), tracepoint.ErrInvalid},
		{"duplicate activity", makeData(extension(eventheader.ExtensionActivityID|eventheader.ExtensionKindChainFlag, make([]byte, 16)), extension(eventheader.ExtensionActivityID|eventheader.ExtensionKindChainFlag, make([]byte, 16)), extension(eventheader.ExtensionMetadata, meta)), tracepoint.ErrInvalid},
		{"duplicate metadata", makeData(extension(eventheader.ExtensionMetadata|eventheader.ExtensionKindChainFlag, meta), extension(eventheader.ExtensionMetadata, meta)), tracepoint.ErrInvalid},
		{"truncated body", makeData([]byte{10, 0, 1, 0, 1}), tracepoint.ErrTruncated},
		{"truncated chained header", makeData(extension(eventheader.ExtensionMetadata|eventheader.ExtensionKindChainFlag, meta)), tracepoint.ErrTruncated},
	}
	for _, test := range tests {
		if _, err := Start("P_L4K0", test.data); !errors.Is(err, test.err) {
			t.Errorf("%s error = %v, want %v", test.name, err, test.err)
		}
	}
}

func TestMetadataCompatibilityAndLimits(t *testing.T) {
	// The advertised second child is absent. Microsoft decoders accept this.
	shortStruct := []byte("E\x00s\x00\x81\x02v\x00\x02")
	if _, err := Start("P_L4K0", eventBytes(binary.LittleEndian, 0, shortStruct, []byte{1})); err != nil {
		t.Fatalf("metadata ending before advertised child count rejected: %v", err)
	}
	arrayMeta := []byte("E\x00v\x00\x42")
	arrayPayload := []byte{3, 0, 1, 2, 3}
	enumerator, err := (&Decoder{Limits: Limits{MaxTransitions: 2}}).Start(
		"P_L4K0", eventBytes(binary.LittleEndian, 0, arrayMeta, arrayPayload))
	if err != nil {
		t.Fatal(err)
	}
	for enumerator.Next() {
	}
	if !errors.Is(enumerator.Err(), tracepoint.ErrLimit) || enumerator.State() != Error {
		t.Fatalf("transition limit not enforced: %v, %v", enumerator.State(), enumerator.Err())
	}
}

func TestTracepointNamesAndDepth(t *testing.T) {
	valid := eventBytes(binary.LittleEndian, 0, []byte("E\x00"), nil)
	for _, name := range []string{"P_L4K0", "_P2_L04K000aGgroupX"} {
		if _, err := Start(name, valid); err != nil {
			t.Errorf("%q rejected: %v", name, err)
		}
	}
	for _, name := range []string{"", "P_L4", "P_L4K", "P_L4KA", "P_L6K0", "2P_L4K0", "P_L4K0_bad"} {
		if _, err := Start(name, valid); !errors.Is(err, tracepoint.ErrInvalid) {
			t.Errorf("%q error = %v", name, err)
		}
	}
	for depth := 8; depth <= 9; depth++ {
		metadata := []byte("E\x00")
		for i := 0; i < depth; i++ {
			metadata = append(metadata, 's', byte('0'+i), 0, byte(eventheader.EncodingStruct|eventheader.EncodingChainFlag), 1)
		}
		metadata = addField(metadata, "v", eventheader.EncodingValue8, eventheader.FormatDefault)
		_, err := Start("P_L4K0", eventBytes(binary.LittleEndian, 0, metadata, []byte{1}))
		if depth == 8 && err != nil {
			t.Fatalf("depth 8 rejected: %v", err)
		}
		if depth == 9 && !errors.Is(err, tracepoint.ErrLimit) {
			t.Fatalf("depth 9 error = %v", err)
		}
	}
}

func append16(out []byte, order binary.ByteOrder, value uint16) []byte {
	var data [2]byte
	order.PutUint16(data[:], value)
	return append(out, data[:]...)
}

func append32(out []byte, order binary.ByteOrder, value uint32) []byte {
	var data [4]byte
	order.PutUint32(data[:], value)
	return append(out, data[:]...)
}

func append64(out []byte, order binary.ByteOrder, value uint64) []byte {
	var data [8]byte
	order.PutUint64(data[:], value)
	return append(out, data[:]...)
}

func appendExtension(out []byte, order binary.ByteOrder, kind eventheader.ExtensionKind, body []byte) []byte {
	out = append16(out, order, uint16(len(body)))
	out = append16(out, order, uint16(kind))
	return append(out, body...)
}

func TestNetworkFormats(t *testing.T) {
	port := decodeScalar(&fieldDef{encoding: eventheader.EncodingValue16, format: eventheader.FormatPort}, []byte{0x01, 0xbb}, 0, binary.LittleEndian, tracepoint.ByteOrderLittle)
	ip := decodeScalar(&fieldDef{encoding: eventheader.EncodingValue32, format: eventheader.FormatIPAddress}, []byte{192, 0, 2, 1}, 0, binary.LittleEndian, tracepoint.ByteOrderLittle)
	if port.Port != 443 || ip.IP != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("network-order decode failed: port=%d ip=%v", port.Port, ip.IP)
	}
}
