package eventheader

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
)

func requireLE64(t *testing.T) {
	t.Helper()
	var word [2]byte
	binary.NativeEndian.PutUint16(word[:], 1)
	if word[0] != 1 || strconv.IntSize != 64 {
		t.Skip("fixed golden is for little-endian 64-bit hosts")
	}
}

func TestGoldenUint32(t *testing.T) {
	requireLE64(t)
	builder, err := NewBuilder("E")
	if err != nil {
		t.Fatal(err)
	}
	if err := builder.Uint32("n", 0x12345678); err != nil {
		t.Fatal(err)
	}
	got, err := builder.Encode(LevelInformation)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
		0x05, 0x00, 0x01, 0x00,
		'E', 0, 'n', 0, 0x04,
		0x78, 0x56, 0x34, 0x12,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("wire = %x, want %x", got, want)
	}
}

func TestGoldenCountedStringAndBinary(t *testing.T) {
	requireLE64(t)
	builder, err := NewBuilder("S")
	if err != nil {
		t.Fatal(err)
	}
	if err := builder.String("s", "hi"); err != nil {
		t.Fatal(err)
	}
	if err := builder.Binary("b", []byte{1, 2}); err != nil {
		t.Fatal(err)
	}
	got, err := builder.Encode(LevelVerbose)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x07, 0, 0, 0, 0, 0, 0, 5,
		0x08, 0, 1, 0,
		'S', 0, 's', 0, 0x0a, 'b', 0, 0x0d,
		2, 0, 'h', 'i', 2, 0, 1, 2,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("wire = %x, want %x", got, want)
	}
}

func TestGoldenActivityAndRelated(t *testing.T) {
	requireLE64(t)
	builder, err := NewBuilder("E")
	if err != nil {
		t.Fatal(err)
	}
	if err := builder.SetOpcode(OpcodeActivityStart); err != nil {
		t.Fatal(err)
	}
	var activity, related ActivityID
	for i := range activity {
		activity[i] = byte(i)
		related[i] = byte(0xf0 + i)
	}
	if err := builder.SetActivity(&activity, &related); err != nil {
		t.Fatal(err)
	}
	got, err := builder.Encode(LevelVerbose)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x07, 0, 0, 0, 0, 0, 1, 5,
		0x20, 0, 0x02, 0x80,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
		2, 0, 1, 0, 'E', 0,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("wire = %x, want %x", got, want)
	}
}

func TestCoreFieldFamilies(t *testing.T) {
	builder, err := NewBuilder("Fields")
	if err != nil {
		t.Fatal(err)
	}
	var uuid [16]byte
	var ip4 [4]byte
	var ip6 [16]byte
	calls := []func() error{
		func() error { return builder.Int8("i8", -1) },
		func() error { return builder.Uint8("u8", 1) },
		func() error { return builder.Int16("i16", -2) },
		func() error { return builder.Uint16("u16", 2) },
		func() error { return builder.Int32("i32", -3) },
		func() error { return builder.Uint32("u32", 3) },
		func() error { return builder.Int64("i64", -4) },
		func() error { return builder.Uint64("u64", 4) },
		func() error { return builder.Bool("bool", true) },
		func() error { return builder.Float32("f32", 1.5) },
		func() error { return builder.Float64("f64", 2.5) },
		func() error { return builder.Uintptr("ptr", 5) },
		func() error { return builder.UUID("uuid", uuid) },
		func() error { return builder.IPv4("ip4", ip4) },
		func() error { return builder.IPv6("ip6", ip6) },
		func() error { return builder.Port("port", 443) },
		func() error { return builder.String("utf8", "héllo") },
		func() error { return builder.UTF16("utf16", []uint16{'h', 'i'}) },
		func() error { return builder.Binary("bin", []byte{1, 2, 3}) },
	}
	for i, call := range calls {
		if err := call(); err != nil {
			t.Fatalf("field %d: %v", i, err)
		}
	}

	wire, err := builder.Encode(LevelVerbose)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) == 0 {
		t.Fatal("empty encoding")
	}
	if !bytes.Contains(wire, []byte{0x01, 0xbb}) {
		t.Fatal("network-order port not present")
	}
}

func TestHeaderAndFieldOptions(t *testing.T) {
	builder, err := NewBuilder("T")
	if err != nil {
		t.Fatal(err)
	}
	if err := builder.SetIDVersion(0x1234, 2); err != nil {
		t.Fatal(err)
	}
	if err := builder.SetTag(0x5678); err != nil {
		t.Fatal(err)
	}
	if err := builder.SetOpcode(OpcodeReply); err != nil {
		t.Fatal(err)
	}
	if err := builder.Uint16("v", 1, FieldOptions{Format: FormatHexInt, Tag: 0x9abc}); err != nil {
		t.Fatal(err)
	}
	wire, err := builder.Encode(LevelError)
	if err != nil {
		t.Fatal(err)
	}
	if wire[1] != 2 || nativeEndian.Uint16(wire[2:4]) != 0x1234 ||
		nativeEndian.Uint16(wire[4:6]) != 0x5678 || wire[6] != byte(OpcodeReply) {
		t.Fatalf("header = %x", wire[:8])
	}
	wantMetadata := []byte{'T', 0, 'v', 0, 0x83, 0x83}
	wantMetadata = appendNative16(wantMetadata, 0x9abc)
	if !bytes.Contains(wire, wantMetadata) {
		t.Fatalf("field metadata %x not found in %x", wantMetadata, wire)
	}
}

func TestTagOnlyOptionsPreserveTypedFormat(t *testing.T) {
	tests := []struct {
		name     string
		encoding FieldEncoding
		format   FieldFormat
		add      func(*Builder) error
	}{
		{"signed", EncodingValue32, FormatSignedInt, func(b *Builder) error {
			return b.Int32("x", -1, FieldOptions{Tag: 1})
		}},
		{"bool", EncodingValue8, FormatBoolean, func(b *Builder) error {
			return b.Bool("x", true, FieldOptions{Tag: 1})
		}},
		{"float", EncodingValue32, FormatFloat, func(b *Builder) error {
			return b.Float32("x", 1, FieldOptions{Tag: 1})
		}},
		{"uuid", EncodingValue128, FormatUUID, func(b *Builder) error {
			return b.UUID("x", [16]byte{}, FieldOptions{Tag: 1})
		}},
		{"ip", EncodingValue32, FormatIPAddress, func(b *Builder) error {
			return b.IPv4("x", [4]byte{}, FieldOptions{Tag: 1})
		}},
		{"port", EncodingValue16, FormatPort, func(b *Builder) error {
			return b.Port("x", 80, FieldOptions{Tag: 1})
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			builder, err := NewBuilder("T")
			if err != nil {
				t.Fatal(err)
			}
			if err := test.add(builder); err != nil {
				t.Fatal(err)
			}
			wire, err := builder.Encode(LevelInformation)
			if err != nil {
				t.Fatal(err)
			}
			metadataSize := int(nativeEndian.Uint16(wire[8:10]))
			metadata := wire[12 : 12+metadataSize]
			want := []byte{
				'T', 0, 'x', 0,
				byte(test.encoding | EncodingChainFlag),
				byte(test.format | FieldFormat(FormatChainFlag)),
				1, 0,
			}
			if !bytes.Equal(metadata, want) {
				t.Fatalf("metadata = %x, want %x", metadata, want)
			}
		})
	}
}

func TestArraysAndNestedStructs(t *testing.T) {
	builder, err := NewBuilder("Arrays")
	if err != nil {
		t.Fatal(err)
	}
	if err := builder.BeginStruct("outer", 1); err != nil {
		t.Fatal(err)
	}
	if err := builder.Int32Array("fixed", []int32{1, 2}, ArrayFixed); err != nil {
		t.Fatal(err)
	}
	if err := builder.BeginStruct("inner", 0); err != nil {
		t.Fatal(err)
	}
	if err := builder.StringArray("strings", []string{"a", "bc"}, ArrayVariable); err != nil {
		t.Fatal(err)
	}
	if err := builder.BinaryArray("binary", [][]byte{{1}, {}}, ArrayFixed); err != nil {
		t.Fatal(err)
	}
	if err := builder.EndStruct(); err != nil {
		t.Fatal(err)
	}
	if err := builder.EndStruct(); err != nil {
		t.Fatal(err)
	}
	wire, err := builder.Encode(LevelInformation)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(wire, []byte{byte(EncodingValue32 | EncodingCArrayFlag | EncodingChainFlag), byte(FormatSignedInt), 2, 0}) {
		t.Fatal("fixed-array metadata not found")
	}
	if !bytes.Contains(wire, []byte{2, 0, 1, 0, 'a', 2, 0, 'b', 'c'}) {
		t.Fatal("variable string-array payload not found")
	}
}

func TestAllScalarArrayWidths(t *testing.T) {
	builder, err := NewBuilder("ScalarArrays")
	if err != nil {
		t.Fatal(err)
	}
	calls := []func() error{
		func() error { return builder.Int8Array("i8", []int8{-1}, ArrayFixed) },
		func() error { return builder.Uint8Array("u8", []uint8{1}, ArrayVariable) },
		func() error { return builder.Int16Array("i16", []int16{-1}, ArrayFixed) },
		func() error { return builder.Uint16Array("u16", []uint16{1}, ArrayVariable) },
		func() error { return builder.Int32Array("i32", []int32{-1}, ArrayFixed) },
		func() error { return builder.Uint32Array("u32", []uint32{1}, ArrayVariable) },
		func() error { return builder.Int64Array("i64", []int64{-1}, ArrayFixed) },
		func() error { return builder.Uint64Array("u64", []uint64{1}, ArrayVariable) },
		func() error { return builder.BoolArray("bool", []bool{true}, ArrayFixed) },
		func() error { return builder.Float32Array("f32", []float32{1}, ArrayVariable) },
		func() error { return builder.Float64Array("f64", []float64{1}, ArrayFixed) },
	}
	for i, call := range calls {
		if err := call(); err != nil {
			t.Fatalf("array %d: %v", i, err)
		}
	}
	if _, err := builder.Encode(LevelVerbose); err != nil {
		t.Fatal(err)
	}
}

func TestBuilderStateErrors(t *testing.T) {
	var zero Builder
	if _, err := zero.Encode(LevelInformation); !errors.Is(err, ErrState) {
		t.Fatalf("zero builder error = %v", err)
	}
	builder, err := NewBuilder("State")
	if err != nil {
		t.Fatal(err)
	}
	if err := builder.EndStruct(); !errors.Is(err, ErrState) {
		t.Fatalf("EndStruct error = %v", err)
	}
	if err := builder.BeginStruct("empty", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := builder.Encode(LevelInformation); !errors.Is(err, ErrState) {
		t.Fatalf("incomplete struct error = %v", err)
	}
	if err := builder.EndStruct(); !errors.Is(err, ErrState) {
		t.Fatalf("empty struct error = %v", err)
	}
	if err := builder.Reset("Again"); err != nil {
		t.Fatal(err)
	}
	if _, err := builder.Encode(LevelInformation); err != nil {
		t.Fatalf("builder not reusable after reset: %v", err)
	}
}

func TestBuilderLimits(t *testing.T) {
	builder, err := NewBuilder("Depth")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxStructDepth; i++ {
		if err := builder.BeginStruct("s", 0); err != nil {
			t.Fatalf("depth %d: %v", i, err)
		}
	}
	if err := builder.BeginStruct("tooDeep", 0); !errors.Is(err, ErrNestingTooDeep) {
		t.Fatalf("depth error = %v", err)
	}

	if err := builder.Reset("Children"); err != nil {
		t.Fatal(err)
	}
	if err := builder.BeginStruct("s", 0); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxStructChildFields; i++ {
		if err := builder.Uint8("v", 0); err != nil {
			t.Fatalf("child %d: %v", i, err)
		}
	}
	if err := builder.Uint8("tooMany", 0); !errors.Is(err, ErrTooManyFields) {
		t.Fatalf("field-count error = %v", err)
	}

	if err := builder.Reset("Counts"); err != nil {
		t.Fatal(err)
	}
	if err := builder.String("large", strings.Repeat("x", maxCount+1)); !errors.Is(err, ErrCountTooLarge) {
		t.Fatalf("string count error = %v", err)
	}
	if err := builder.Uint8Array("empty", nil, ArrayFixed); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("empty fixed-array error = %v", err)
	}
	if err := builder.Uint8Array("bad", nil, ArrayScalar); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("array-kind error = %v", err)
	}
	if err := builder.BeginStructArray("structs", ArrayFixed, 0); !errors.Is(err, ErrStructArrayUnsupported) {
		t.Fatalf("struct-array error = %v", err)
	}
}

func TestSizeBoundaries(t *testing.T) {
	builder, err := NewBuilder(strings.Repeat("e", maxMetadataPayload-1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := builder.Encode(LevelInformation); err != nil {
		t.Fatalf("exact metadata+payload limit: %v", err)
	}
	if err := builder.Reset(strings.Repeat("e", maxMetadataPayload)); err != nil {
		t.Fatal(err)
	}
	if _, err := builder.Encode(LevelInformation); !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("event-size error = %v", err)
	}
	if err := builder.Reset(strings.Repeat("e", maxCount)); err != nil {
		t.Fatal(err)
	}
	if _, err := builder.Encode(LevelInformation); !errors.Is(err, ErrMetadataTooLarge) {
		t.Fatalf("metadata-size error = %v", err)
	}

	if err := builder.Reset("ArrayCount"); err != nil {
		t.Fatal(err)
	}
	if err := builder.Uint8Array("values", make([]byte, maxCount), ArrayVariable); err != nil {
		t.Fatalf("maximum array count rejected: %v", err)
	}
	if err := builder.Uint8Array("tooMany", make([]byte, maxCount+1), ArrayVariable); !errors.Is(err, ErrCountTooLarge) {
		t.Fatalf("array count error = %v", err)
	}
}

func TestActivityValidationAndReuse(t *testing.T) {
	builder, err := NewBuilder("Activity")
	if err != nil {
		t.Fatal(err)
	}
	var activity, related ActivityID
	if err := builder.SetActivity(nil, &related); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("orphan related ID error = %v", err)
	}
	if err := builder.SetOpcode(OpcodeActivityStart); err != nil {
		t.Fatal(err)
	}
	if err := builder.SetActivity(&activity, &related); err != nil {
		t.Fatal(err)
	}
	first, err := builder.Encode(LevelInformation)
	if err != nil {
		t.Fatal(err)
	}
	second, err := builder.Encode(LevelInformation)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("successful encode mutated builder")
	}
	if err := builder.SetOpcode(OpcodeInfo); err != nil {
		t.Fatal(err)
	}
	info, err := builder.Encode(LevelInformation)
	if err != nil {
		t.Fatalf("related ID with info opcode: %v", err)
	}
	if info[6] != byte(OpcodeInfo) {
		t.Fatalf("opcode = %d, want %d", info[6], OpcodeInfo)
	}
}

func TestNativeIntegerPayload(t *testing.T) {
	builder, err := NewBuilder("Native")
	if err != nil {
		t.Fatal(err)
	}
	if err := builder.Uint64("value", math.MaxUint64); err != nil {
		t.Fatal(err)
	}
	wire, err := builder.Encode(LevelInformation)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire[len(wire)-8:], bytes.Repeat([]byte{0xff}, 8)) {
		t.Fatalf("payload = %x", wire[len(wire)-8:])
	}
}
