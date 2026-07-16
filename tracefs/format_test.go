package tracefs

import (
	"errors"
	"strings"
	"testing"

	"github.com/cataggar/LinuxTracepoints-Go/tracepoint"
)

const sampleFormat = `name: demo
ID: 42
unknown: retained
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;

	field special:const char comm[16] __attribute__((aligned(4))); offset:2; size:16; extra:value;
	field:__data_loc char[] filename; offset:18; size:4; signed:0;
print fmt: "comm=%s", REC->comm
`

func TestParseFormatLineEndings(t *testing.T) {
	for _, separator := range []string{"\n", "\r\n", "\r"} {
		t.Run(strings.ReplaceAll(separator, "\r", "CR"), func(t *testing.T) {
			input := strings.ReplaceAll(sampleFormat, "\n", separator)
			format, err := ParseFormat([]byte(input), ParseOptions{System: "test", LongSize: 8})
			if err != nil {
				t.Fatal(err)
			}
			if format.System != "test" || format.Name != "demo" || format.ID != 42 || format.LongSize != 8 {
				t.Fatalf("unexpected header: %#v", format)
			}
			if len(format.Common) != 1 || len(format.Fields) != 2 {
				t.Fatalf("field groups = %d common, %d ordinary", len(format.Common), len(format.Fields))
			}
			if got := format.Fields[0]; got.Name != "comm" || got.Kind != FieldChar || got.ArrayLen != 16 || len(got.Properties) != 1 {
				t.Fatalf("comm = %#v", got)
			}
			if got := format.Fields[1]; got.Name != "filename" || got.Location != LocationData || got.ArrayLen != 0 {
				t.Fatalf("filename = %#v", got)
			}
			if len(format.Properties) != 1 || format.Properties[0].Name != "unknown" {
				t.Fatalf("properties = %#v", format.Properties)
			}
			if format.PrintFormat != `"comm=%s", REC->comm` {
				t.Fatalf("print fmt = %q", format.PrintFormat)
			}
		})
	}
}

func TestParseCommonSeparatorAndDecimalID(t *testing.T) {
	format, err := ParseFormat([]byte(`name: groups
ID: 00123
format:
 field:u16 common_type; offset:0; size:2;

 field:u32 common_payload; offset:2; size:4;
 field:u8 common_late; offset:6; size:1;
`), ParseOptions{LongSize: 8})
	if err != nil {
		t.Fatal(err)
	}
	if format.ID != 123 || len(format.Common) != 1 || len(format.Fields) != 2 ||
		format.Fields[0].Name != "common_payload" || format.Fields[1].Name != "common_late" {
		t.Fatalf("format grouping/ID = %#v", format)
	}

	legacy, err := ParseFormat([]byte(`name: legacy
ID: 1
format:
 field:u16 common_type; offset:0; size:2;
 field:u32 payload; offset:2; size:4;
 field:u8 common_named_user; offset:6; size:1;
`), ParseOptions{LongSize: 8})
	if err != nil {
		t.Fatal(err)
	}
	if len(legacy.Common) != 1 || len(legacy.Fields) != 2 {
		t.Fatalf("legacy grouping = %#v", legacy)
	}
}

func TestParseDeclarations(t *testing.T) {
	input := `name: types
ID: 9
format:
 field:unsigned long word; offset:0; size:4;
 field:long long signed64; offset:4; size:8;
 field:u8 bytes[2]; offset:12; size:2;
 field:__s16 small; offset:14; size:2;
 field:uint32_t count; offset:16; size:4;
 field:const struct mystery opaque; offset:20; size:3;
 field:struct thing *ptr; offset:23; size:4;
 field:__rel_loc char[] relative; offset:27; size:2;
`
	format, err := ParseFormat([]byte(input), ParseOptions{LongSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name     string
		kind     FieldKind
		width    int
		arrayLen int
		location LocationKind
	}{
		{"word", FieldUnsigned, 4, -1, LocationNone},
		{"signed64", FieldSigned, 8, -1, LocationNone},
		{"bytes", FieldUnsigned, 1, 2, LocationNone},
		{"small", FieldSigned, 2, -1, LocationNone},
		{"count", FieldUnsigned, 4, -1, LocationNone},
		{"opaque", FieldOpaque, 0, -1, LocationNone},
		{"ptr", FieldUnsigned, 4, -1, LocationNone},
		{"relative", FieldChar, 1, 0, LocationRelative},
	}
	if len(format.Fields) != len(checks) {
		t.Fatalf("fields = %d, want %d", len(format.Fields), len(checks))
	}
	for i, want := range checks {
		got := format.Fields[i]
		if got.Name != want.name || got.Kind != want.kind || got.Width != want.width ||
			got.ArrayLen != want.arrayLen || got.Location != want.location {
			t.Errorf("field %d = %#v, want %+v", i, got, want)
		}
	}
}

func TestParseOpaqueScalarClassification(t *testing.T) {
	format, err := ParseFormat([]byte(`name: opaque
ID: 10
format:
 field:pid_t pid; offset:0; size:4; signed:1;
 field:dev_t device; offset:4; size:8; signed:0;
 field:enum state state; offset:12; size:4; signed:1;
 field:struct foo aggregate; offset:16; size:4; signed:1;
`), ParseOptions{LongSize: 8})
	if err != nil {
		t.Fatal(err)
	}
	want := []FieldKind{FieldSigned, FieldUnsigned, FieldSigned, FieldOpaque}
	for i := range want {
		if format.Fields[i].Kind != want[i] {
			t.Errorf("field %d kind = %v, want %v", i, format.Fields[i].Kind, want[i])
		}
	}
}

func TestParseFormatErrorsAndLimits(t *testing.T) {
	tests := []struct {
		name  string
		input string
		opts  ParseOptions
		want  error
	}{
		{"missing name", "ID: 1\nformat:\n", ParseOptions{LongSize: 8}, tracepoint.ErrInvalid},
		{"missing format", "name: x\nID: 1\n", ParseOptions{LongSize: 8}, tracepoint.ErrInvalid},
		{"duplicate format", "name: x\nID: 1\nformat:\nformat:\n", ParseOptions{LongSize: 8}, tracepoint.ErrInvalid},
		{"duplicate ID", "name: x\nID: 1\nID: 2\nformat:\n", ParseOptions{LongSize: 8}, tracepoint.ErrInvalid},
		{"missing offset", "name: x\nID: 1\nformat:\nfield:u8 x; size:1;\n", ParseOptions{LongSize: 8}, tracepoint.ErrInvalid},
		{"duplicate size", "name:x\nID:1\nformat:\nfield:u8 x;offset:0;size:1;size:2;\n", ParseOptions{LongSize: 8}, tracepoint.ErrInvalid},
		{"bad dynamic size", "name:x\nID:1\nformat:\nfield:__data_loc char[] x;offset:0;size:3;\n", ParseOptions{LongSize: 8}, tracepoint.ErrInvalid},
		{"impossible scalar size", "name:x\nID:1\nformat:\nfield:u32 x;offset:0;size:2;\n", ParseOptions{LongSize: 8}, tracepoint.ErrInvalid},
		{"impossible array size", "name:x\nID:1\nformat:\nfield:u16 x[2];offset:0;size:3;\n", ParseOptions{LongSize: 8}, tracepoint.ErrInvalid},
		{"byte limit", sampleFormat, ParseOptions{LongSize: 8, MaxFormatBytes: 10}, tracepoint.ErrLimit},
		{"field limit", sampleFormat, ParseOptions{LongSize: 8, MaxFields: 1}, tracepoint.ErrLimit},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseFormat([]byte(test.input), test.opts)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want errors.Is(_, %v)", err, test.want)
			}
			var positioned *ParseError
			if !errors.As(err, &positioned) || positioned.Line < 1 || positioned.Column < 1 {
				t.Fatalf("error is not positioned: %v", err)
			}
		})
	}
}

func TestParseComplexAttribute(t *testing.T) {
	format, err := ParseFormat([]byte(`name: attr
ID: 1
format:
 field:char text[4] __attribute__((section("a=b"), aligned(4))); offset:0; size:4;
`), ParseOptions{LongSize: 8})
	if err != nil {
		t.Fatal(err)
	}
	if got := format.Fields[0]; got.Name != "text" || got.Kind != FieldChar || got.ArrayLen != 4 {
		t.Fatalf("field = %#v", got)
	}
}

func FuzzParseFormat(f *testing.F) {
	f.Add([]byte(sampleFormat), uint8(8))
	f.Add([]byte("name:x\rID:1\rformat:\rfield:u8 x;offset:0;size:1;\r"), uint8(4))
	f.Add([]byte(""), uint8(0))
	f.Fuzz(func(t *testing.T, data []byte, longSize uint8) {
		if len(data) > 8192 {
			return
		}
		size := 4
		if longSize&1 != 0 {
			size = 8
		}
		_, _ = ParseFormat(data, ParseOptions{LongSize: size, MaxFormatBytes: 8192, MaxFields: 64})
	})
}
