package tracefs

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cataggar/LinuxTracepoints-Go/tracepoint"
)

func mustFormat(t testing.TB, text string, longSize int) *Format {
	t.Helper()
	format, err := ParseFormat([]byte(text), ParseOptions{System: "tests", LongSize: longSize})
	if err != nil {
		t.Fatal(err)
	}
	return format
}

func TestDecodeScalarsArraysAndOpaque(t *testing.T) {
	format := mustFormat(t, `name: values
ID: 17
format:
 field:u16 common_type; offset:0; size:2; signed:0;

 field:unsigned int signed_override; offset:2; size:4; signed:1;
 field:u16 values[2]; offset:6; size:4;
 field:char text[5]; offset:10; size:5;
 field:struct unknown opaque; offset:15; size:2;
`, 8)
	data := []byte{
		0x34, 0x12,
		0xfe, 0xff, 0xff, 0xff,
		1, 0, 2, 0,
		'h', 'i', 0, 'x', 'x',
		0xaa, 0xbb,
	}
	record, err := format.Decode(data, DecodeOptions{ByteOrder: tracepoint.ByteOrderLittle, LongSize: 8})
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Event.Common) != 1 || record.Event.Common[0].Value.Unsigned != 0x1234 {
		t.Fatalf("common = %#v", record.Event.Common)
	}

	fields := record.Event.Fields
	if fields[0].Value.Kind != tracepoint.ValueSigned || fields[0].Value.Signed != -2 {
		t.Fatalf("signed override = %#v", fields[0].Value)
	}
	if got := fields[1].Value.Array; len(got) != 2 || got[0].Unsigned != 1 || got[1].Unsigned != 2 {
		t.Fatalf("array = %#v", got)
	}
	if fields[2].Value.Text != "hi" {
		t.Fatalf("text = %#v", fields[2].Value)
	}
	if fields[3].Value.Kind != tracepoint.ValueBinary || fields[3].Value.Binary[0] != 0xaa {
		t.Fatalf("opaque = %#v", fields[3].Value)
	}

	clone := tracepoint.CloneRecord(record)
	data[0], data[15] = 0, 0
	if clone.Raw[0] != 0x34 || clone.Event.Fields[3].Value.Binary[0] != 0xaa {
		t.Fatal("cloned decoded record shares input")
	}
}

func TestDecodeOpaqueScalarTypedefsAndEnums(t *testing.T) {
	format := mustFormat(t, `name: opaque
ID: 19
format:
 field:pid_t pid; offset:0; size:4; signed:1;
 field:dev_t device; offset:4; size:8; signed:0;
 field:enum state state; offset:12; size:4; signed:1;
 field:struct foo aggregate; offset:16; size:4; signed:1;
`, 8)
	data := make([]byte, 20)
	binary.LittleEndian.PutUint32(data, ^uint32(1))
	binary.LittleEndian.PutUint64(data[4:], 0x1122334455667788)
	binary.LittleEndian.PutUint32(data[12:], ^uint32(2))
	copy(data[16:], []byte{1, 2, 3, 4})
	record, err := Decode(format, data, DecodeOptions{ByteOrder: tracepoint.ByteOrderLittle, LongSize: 8})
	if err != nil {
		t.Fatal(err)
	}
	fields := record.Event.Fields
	if fields[0].Value.Signed != -2 || fields[1].Value.Unsigned != 0x1122334455667788 ||
		fields[2].Value.Signed != -3 || fields[3].Value.Kind != tracepoint.ValueBinary ||
		!fields[3].Value.Valid {
		t.Fatalf("opaque scalar decode = %#v", fields)
	}
}

func TestDecodeCharSignedOverrideAndMetadata(t *testing.T) {
	format := mustFormat(t, `name: chars
ID: 18
format:
 field:char unsigned_char; offset:0; size:1; signed:0;
 field:char signed_char; offset:1; size:1; signed:1;
`, 8)
	options := DecodeOptions{
		ByteOrder: tracepoint.ByteOrderLittle,
		LongSize:  8,
		Timestamp: tracepoint.Timestamp{Nanoseconds: 10, Clock: tracepoint.ClockMonotonic},
		CPU:       tracepoint.Optional[uint32]{Value: 2, Present: true},
		TID:       tracepoint.Optional[int32]{Value: 99, Present: true},
	}
	record, err := Decode(format, []byte{0xff, 0xff}, options)
	if err != nil {
		t.Fatal(err)
	}
	if record.Identity.System != "tests" || record.Identity.ID != 18 ||
		record.Timestamp.Nanoseconds != 10 || record.CPU.Value != 2 || record.TID.Value != 99 {
		t.Fatalf("metadata = %#v", record)
	}
	if got := record.Event.Fields[0].Value; got.Kind != tracepoint.ValueUnsigned || got.Unsigned != 255 {
		t.Fatalf("unsigned char = %#v", got)
	}
	if got := record.Event.Fields[1].Value; got.Kind != tracepoint.ValueSigned || got.Signed != -1 {
		t.Fatalf("signed char = %#v", got)
	}
}

func TestDecodeBigEndianAndLongSizes(t *testing.T) {
	for _, longSize := range []int{4, 8} {
		t.Run(string(rune('0'+longSize)), func(t *testing.T) {
			format := mustFormat(t, `name: long
ID: 1
format:
 field:unsigned long value; offset:0; size:`+string(rune('0'+longSize))+`;
`, longSize)
			data := make([]byte, longSize)
			if longSize == 4 {
				binary.BigEndian.PutUint32(data, 0x01020304)
			} else {
				binary.BigEndian.PutUint64(data, 0x0102030405060708)
			}
			record, err := Decode(format, data, DecodeOptions{ByteOrder: tracepoint.ByteOrderBig, LongSize: longSize})
			if err != nil {
				t.Fatal(err)
			}
			want := uint64(0x01020304)
			if longSize == 8 {
				want = 0x0102030405060708
			}
			if got := record.Event.Fields[0].Value.Unsigned; got != want {
				t.Fatalf("value = %#x, want %#x", got, want)
			}
		})
	}
}

func TestDecodeDynamicLocations(t *testing.T) {
	tests := []struct {
		name        string
		declaration string
		size        int
		descriptor  []byte
		padding     []byte
		text        []byte
	}{
		{"data2", "__data_loc", 2, []byte{4, 0}, []byte{0, 0}, []byte("two\x00")},
		{"rel2", "__rel_loc", 2, []byte{2, 0}, []byte{0, 0}, []byte("two\x00")},
		{"data4", "__data_loc", 4, []byte{4, 0, 4, 0}, nil, []byte("four")},
		{"rel4", "__rel_loc", 4, []byte{0, 0, 4, 0}, nil, []byte("four")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			format := mustFormat(t, "name: dynamic\nID: 2\nformat:\n field:"+test.declaration+
				" char[] value; offset:0; size:"+string(rune('0'+test.size))+";\n", 8)
			data := append(append(append([]byte(nil), test.descriptor...), test.padding...), test.text...)
			record, err := Decode(format, data, DecodeOptions{ByteOrder: tracepoint.ByteOrderLittle, LongSize: 8})
			if err != nil {
				t.Fatal(err)
			}
			value := record.Event.Fields[0].Value
			want := "two"
			if test.size == 4 {
				want = "four"
			}
			if !value.Valid || value.Text != want {
				t.Fatalf("value = %#v, want %q", value, want)
			}
			if test.declaration == "__data_loc" && value.Encoding != tracepoint.EncodingDataLoc {
				t.Fatalf("encoding = %q", value.Encoding)
			}
			if test.declaration == "__rel_loc" && value.Encoding != tracepoint.EncodingRelLoc {
				t.Fatalf("encoding = %q", value.Encoding)
			}
		})
	}
}

func TestDecodeFieldLocalErrors(t *testing.T) {
	format := mustFormat(t, `name: damaged
ID: 3
format:
 field:u32 bad; offset:20; size:4;
 field:u8 good; offset:0; size:1;
`, 8)
	record, err := Decode(format, []byte{9}, DecodeOptions{ByteOrder: tracepoint.ByteOrderLittle, LongSize: 8})
	if err != nil {
		t.Fatal(err)
	}

	if record.Event.Fields[0].Value.Valid || len(record.Event.Fields[0].Diagnostics) != 1 {
		t.Fatalf("bad field = %#v", record.Event.Fields[0])
	}
	if !errors.Is(record.Event.Fields[0].Diagnostics[0].Err, tracepoint.ErrTruncated) {
		t.Fatalf("diagnostic = %v", record.Event.Fields[0].Diagnostics[0].Err)
	}
	if got := record.Event.Fields[1].Value; !got.Valid || got.Unsigned != 9 {
		t.Fatalf("good field = %#v", got)
	}
}

func TestDecodeArrayLimitIsFieldLocal(t *testing.T) {
	format := mustFormat(t, `name: limit
ID: 7
format:
 field:u8 values[4]; offset:0; size:4;
 field:u8 good; offset:4; size:1;
`, 8)
	record, err := Decode(format, []byte{1, 2, 3, 4, 5}, DecodeOptions{
		ByteOrder:        tracepoint.ByteOrderLittle,
		LongSize:         8,
		MaxArrayElements: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(record.Event.Fields[0].Diagnostics[0], tracepoint.ErrLimit) {
		t.Fatalf("array diagnostic = %v", record.Event.Fields[0].Diagnostics[0])
	}
	if got := record.Event.Fields[1].Value.Unsigned; got != 5 {
		t.Fatalf("good field = %d", got)
	}
}

func TestDecodeDynamicErrorsAndRemainder(t *testing.T) {
	dynamic := mustFormat(t, `name: dynamic
ID: 4
format:
 field:__data_loc char[] value; offset:0; size:2;
`, 8)
	record, err := Decode(dynamic, []byte{2, 0, 'x'}, DecodeOptions{ByteOrder: tracepoint.ByteOrderLittle, LongSize: 8})
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Diagnostics) != 1 || !errors.Is(record.Diagnostics[0].Err, tracepoint.ErrTruncated) {
		t.Fatalf("diagnostics = %#v", record.Diagnostics)
	}

	remainder := mustFormat(t, `name: rest
ID: 5
format:
 field:struct bytes rest; offset:2; size:0;
`, 8)
	record, err = Decode(remainder, []byte{0, 0, 1, 2, 3}, DecodeOptions{ByteOrder: tracepoint.ByteOrderLittle, LongSize: 8})
	if err != nil {
		t.Fatal(err)
	}
	got := record.Event.Fields[0].Value.Binary
	if len(got) != 3 || got[0] != 1 || got[2] != 3 {
		t.Fatalf("remainder = %v", got)
	}
}

func TestDecodeRequiresExplicitOptions(t *testing.T) {
	format := mustFormat(t, "name:x\nID:1\nformat:\n", 8)
	for _, options := range []DecodeOptions{
		{LongSize: 8},
		{ByteOrder: tracepoint.ByteOrderLittle},
		{ByteOrder: tracepoint.ByteOrderLittle, LongSize: 4},
	} {
		_, err := Decode(format, nil, options)
		if !errors.Is(err, tracepoint.ErrInvalid) {
			t.Fatalf("Decode options %#v error = %v", options, err)
		}
	}
}

func FuzzDecode(f *testing.F) {
	format := mustFormat(f, `name: fuzz
ID: 6
format:
 field:__rel_loc char[] dynamic; offset:0; size:4;
 field:u16 values[2]; offset:4; size:4;
`, 8)
	f.Add([]byte{0, 0, 0, 0, 1, 0, 2, 0}, uint8(0))
	f.Add([]byte{4, 0, 2, 0, 'x', 0}, uint8(1))
	f.Fuzz(func(t *testing.T, data []byte, big uint8) {
		if len(data) > 4096 {
			return
		}
		order := tracepoint.ByteOrderLittle
		if big&1 != 0 {
			order = tracepoint.ByteOrderBig
		}
		_, _ = Decode(format, data, DecodeOptions{ByteOrder: order, LongSize: 8, MaxArrayElements: 64})
	})
}
