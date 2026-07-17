package eventheaderfixture

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/cataggar/LinuxTracepoints-Go/eventheader"
	"github.com/cataggar/LinuxTracepoints-Go/userevents"
)

func fixtureValue() *RequestEvent {
	return &RequestEvent{
		RequestID:      [16]byte{1, 2, 3},
		NamedIPv4:      [4]Octet{192, 0, 2, 2},
		NamedIPv6:      [16]Octet{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		NamedUUID:      [16]Octet{4, 5, 6},
		NamedIPv4s:     [][4]Octet{{192, 0, 2, 3}, {192, 0, 2, 4}},
		NamedIPv6s:     [][16]Octet{{0x20, 1, 0xd, 0xb8, 1}, {0x20, 1, 0xd, 0xb8, 2}},
		NamedUUIDs:     [][16]Octet{{7, 8}, {9, 10}},
		FixedNamedIPv4: [2][4]Octet{{198, 51, 100, 1}, {198, 51, 100, 2}},
		FixedNamedIPv6: [2][16]Octet{{0x20, 1, 0xd, 0xb8, 3}, {0x20, 1, 0xd, 0xb8, 4}},
		FixedNamedUUID: [2][16]Octet{{11, 12}, {13, 14}},
		Client:         netip.MustParseAddr("192.0.2.1"),
		Status:         503,
		Enabled:        true,
		Label:          "fixture",
		Details: RequestDetails{
			Method:   "POST",
			Attempts: [2]uint32{1, 2},
		},
		Payload:    []Octet{0xaa, 0xbb},
		Raw:        [3]Octet{5, 6, 7},
		Bytes:      []byte{3, 4},
		Message:    []Word{'o', 'k'},
		Counts:     []Count{-1, 2},
		Pointers:   []PointerWord{1, 2},
		Blocks:     []OctetBlock{{8, 9}, {10, 11}},
		Words:      [][]Word{{'a'}, {'b', 'c'}},
		NamedBlobs: [][]Octet{{1, 2}, {3}},
	}
}

func TestGeneratedSchemaAndBindingParity(t *testing.T) {
	schema, err := RequestEventSchema()
	if err != nil {
		t.Fatal(err)
	}
	if again, err := RequestEventSchema(); err != nil || again != schema {
		t.Fatalf("second Schema call = %p, %v; want cached %p", again, err, schema)
	}

	expectedSchema, err := eventheader.NewSchema(
		eventheader.SchemaOptions{
			Name: "Request", ID: 12, Version: 2, Tag: 7, Opcode: eventheader.OpcodeInfo,
		},
		eventheader.UUIDField("request_id"),
		eventheader.IPv4Field("NamedIPv4"),
		eventheader.IPv6Field("NamedIPv6"),
		eventheader.UUIDField("NamedUUID"),
		eventheader.ArrayField(eventheader.IPv4Field("NamedIPv4s"), eventheader.ArrayVariable),
		eventheader.ArrayField(eventheader.IPv6Field("NamedIPv6s"), eventheader.ArrayVariable),
		eventheader.ArrayField(eventheader.UUIDField("NamedUUIDs"), eventheader.ArrayVariable),
		eventheader.ArrayField(eventheader.IPv4Field("FixedNamedIPv4"), eventheader.ArrayFixed, 2),
		eventheader.ArrayField(eventheader.IPv6Field("FixedNamedIPv6"), eventheader.ArrayFixed, 2),
		eventheader.ArrayField(eventheader.UUIDField("FixedNamedUUID"), eventheader.ArrayFixed, 2),
		eventheader.IPv4Field("client"),
		eventheader.Uint16Field("Status", eventheader.FieldOptions{
			Format: eventheader.FormatHexInt, Tag: 3,
		}),
		eventheader.BoolField("Enabled"),
		eventheader.StringField("Label"),
		eventheader.StructField("Details", []eventheader.FieldDefinition{
			eventheader.StringField("Method"),
			eventheader.ArrayField(
				eventheader.Uint32Field("Attempts", eventheader.FieldOptions{
					Format: eventheader.FormatUnsignedInt,
				}),
				eventheader.ArrayFixed, 2,
			),
		}),
		eventheader.BinaryField("Payload"),
		eventheader.BinaryField("Raw"),
		eventheader.ArrayField(eventheader.Uint8Field("Bytes"), eventheader.ArrayVariable),
		eventheader.UTF16Field("Message"),
		eventheader.ArrayField(eventheader.Int32Field("Counts"), eventheader.ArrayVariable),
		eventheader.ArrayField(eventheader.UintptrField("Pointers"), eventheader.ArrayVariable),
		eventheader.ArrayField(eventheader.BinaryField("Blocks"), eventheader.ArrayVariable),
		eventheader.ArrayField(eventheader.UTF16Field("Words"), eventheader.ArrayVariable),
		eventheader.ArrayField(eventheader.BinaryField("NamedBlobs"), eventheader.ArrayVariable),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(schema, expectedSchema) {
		t.Fatal("generated schema differs from the equivalent reusable schema")
	}

	value := fixtureValue()
	writer := &RequestEventWriter{binding: schema.Bind(nil)}
	if err := writer.bind(value); err != nil {
		t.Fatal(err)
	}
	expected := expectedSchema.Bind(nil)
	if err := expected.UUID(value.RequestID); err != nil {
		t.Fatal(err)
	}
	namedIPv4 := [4]byte{192, 0, 2, 2}
	if err := expected.IPv4(namedIPv4); err != nil {
		t.Fatal(err)
	}
	namedIPv6 := [16]byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if err := expected.IPv6(namedIPv6); err != nil {
		t.Fatal(err)
	}
	namedUUID := [16]byte{4, 5, 6}
	if err := expected.UUID(namedUUID); err != nil {
		t.Fatal(err)
	}
	namedIPv4s := [][4]byte{{192, 0, 2, 3}, {192, 0, 2, 4}}
	if err := expected.IPv4Array(namedIPv4s); err != nil {
		t.Fatal(err)
	}
	namedIPv6s := [][16]byte{{0x20, 1, 0xd, 0xb8, 1}, {0x20, 1, 0xd, 0xb8, 2}}
	if err := expected.IPv6Array(namedIPv6s); err != nil {
		t.Fatal(err)
	}
	namedUUIDs := [][16]byte{{7, 8}, {9, 10}}
	if err := expected.UUIDArray(namedUUIDs); err != nil {
		t.Fatal(err)
	}
	fixedNamedIPv4 := [][4]byte{{198, 51, 100, 1}, {198, 51, 100, 2}}
	if err := expected.IPv4Array(fixedNamedIPv4); err != nil {
		t.Fatal(err)
	}
	fixedNamedIPv6 := [][16]byte{{0x20, 1, 0xd, 0xb8, 3}, {0x20, 1, 0xd, 0xb8, 4}}
	if err := expected.IPv6Array(fixedNamedIPv6); err != nil {
		t.Fatal(err)
	}
	fixedNamedUUID := [][16]byte{{11, 12}, {13, 14}}
	if err := expected.UUIDArray(fixedNamedUUID); err != nil {
		t.Fatal(err)
	}
	address := value.Client.As4()
	if err := expected.IPv4(address); err != nil {
		t.Fatal(err)
	}
	if err := expected.Uint16(uint16(value.Status)); err != nil {
		t.Fatal(err)
	}
	if err := expected.Bool(bool(value.Enabled)); err != nil {
		t.Fatal(err)
	}
	if err := expected.String(string(value.Label)); err != nil {
		t.Fatal(err)
	}
	if err := expected.String(value.Details.Method); err != nil {
		t.Fatal(err)
	}
	if err := expected.Uint32Array(value.Details.Attempts[:]); err != nil {
		t.Fatal(err)
	}
	payload := []byte{byte(value.Payload[0]), byte(value.Payload[1])}
	if err := expected.Binary(payload); err != nil {
		t.Fatal(err)
	}
	raw := []byte{byte(value.Raw[0]), byte(value.Raw[1]), byte(value.Raw[2])}
	if err := expected.Binary(raw); err != nil {
		t.Fatal(err)
	}
	if err := expected.Uint8Array(value.Bytes); err != nil {
		t.Fatal(err)
	}
	message := []uint16{uint16(value.Message[0]), uint16(value.Message[1])}
	if err := expected.UTF16(message); err != nil {
		t.Fatal(err)
	}
	counts := []int32{int32(value.Counts[0]), int32(value.Counts[1])}
	if err := expected.Int32Array(counts); err != nil {
		t.Fatal(err)
	}
	pointers := []uintptr{1, 2}
	if err := expected.UintptrArray(pointers); err != nil {
		t.Fatal(err)
	}
	blocks := [][]byte{{8, 9}, {10, 11}}
	if err := expected.BinaryArray(blocks); err != nil {
		t.Fatal(err)
	}
	words := [][]uint16{{'a'}, {'b', 'c'}}
	if err := expected.UTF16Array(words); err != nil {
		t.Fatal(err)
	}
	namedBlobs := [][]byte{{1, 2}, {3}}
	if err := expected.BinaryArray(namedBlobs); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(writer.binding, expected) {
		t.Fatal("generated binding payload differs from direct Binding calls")
	}
	if err := writer.binding.Complete(); err != nil {
		t.Fatal(err)
	}
}

func TestClosedWriteChecksBeforeNilAndAllocatesNothing(t *testing.T) {
	writer := &RequestEventWriter{event: new(eventheader.Event)}
	var activity, related eventheader.ActivityID
	if err := writer.Write(nil, &activity, &related); !errors.Is(err, userevents.ErrClosed) {
		t.Fatalf("Write(nil) = %v, want ErrClosed", err)
	}
	allocations := testing.AllocsPerRun(1000, func() {
		_ = writer.Write(nil, nil, nil)
	})
	if allocations != 0 {
		t.Fatalf("closed Write allocations = %v, want 0", allocations)
	}
}

func TestClosedWriteFuncSkipsFactoryAndAllocatesNothing(t *testing.T) {
	writer := &RequestEventWriter{event: new(eventheader.Event)}
	factoryCalled := false
	factoryErr := errors.New("factory failure")
	factory := func() (*RequestEvent, error) {
		factoryCalled = true
		return nil, factoryErr
	}
	var activity, related eventheader.ActivityID
	if err := writer.WriteFunc(factory, &activity, &related); !errors.Is(err, userevents.ErrClosed) {
		t.Fatalf("WriteFunc(factory) = %v, want ErrClosed", err)
	}
	if factoryCalled {
		t.Fatal("closed WriteFunc invoked the factory")
	}
	allocations := testing.AllocsPerRun(1000, func() {
		_ = writer.WriteFunc(factory, nil, nil)
	})
	if allocations != 0 {
		t.Fatalf("closed WriteFunc allocations = %v, want 0", allocations)
	}
	if factoryCalled {
		t.Fatal("closed WriteFunc allocation runs invoked the factory")
	}
}

func TestGeneratedScratchIsRetained(t *testing.T) {
	schema, err := RequestEventSchema()
	if err != nil {
		t.Fatal(err)
	}
	value := fixtureValue()
	writer := &RequestEventWriter{binding: schema.Bind(make([]byte, 0, 128))}
	if err := writer.bind(value); err != nil {
		t.Fatal(err)
	}
	allocations := testing.AllocsPerRun(1000, func() {
		if err := writer.bind(value); err != nil {
			panic(err)
		}
	})
	if allocations != 0 {
		t.Fatalf("second enabled binding allocations = %v, want 0", allocations)
	}
}

func TestGeneratedFieldPathError(t *testing.T) {
	schema, err := RequestEventSchema()
	if err != nil {
		t.Fatal(err)
	}
	value := fixtureValue()
	value.Payload = make([]Octet, 65536)
	writer := &RequestEventWriter{binding: schema.Bind(nil)}
	err = writer.bind(value)
	if err == nil || !strings.Contains(err.Error(), "RequestEvent.Payload") ||
		!errors.Is(err, eventheader.ErrCountTooLarge) {
		t.Fatalf("bind error = %v", err)
	}
}

func TestGeneratedScratchRejectsHostileCountsBeforeAllocation(t *testing.T) {
	schema, err := RequestEventSchema()
	if err != nil {
		t.Fatal(err)
	}
	largeWords := make([]Word, 20000)
	tooManyWords := make([]Word, 65536)
	largeBytes := make([]Octet, 40000)
	tooManyBytes := make([]Octet, 65536)
	tests := []struct {
		name   string
		mutate func(*RequestEvent)
		path   string
		want   error
	}{
		{"binary count", func(v *RequestEvent) { v.Payload = tooManyBytes }, "RequestEvent.Payload", eventheader.ErrCountTooLarge},
		{"binary bytes", func(v *RequestEvent) { v.Payload = make([]Octet, 65535) }, "RequestEvent.Payload", eventheader.ErrEventTooLarge},
		{"ipv4 count", func(v *RequestEvent) { v.NamedIPv4s = make([][4]Octet, 65536) }, "RequestEvent.NamedIPv4s", eventheader.ErrCountTooLarge},
		{"ipv4 bytes", func(v *RequestEvent) { v.NamedIPv4s = make([][4]Octet, 16367) }, "RequestEvent.NamedIPv4s", eventheader.ErrEventTooLarge},
		{"ipv6 count", func(v *RequestEvent) { v.NamedIPv6s = make([][16]Octet, 65536) }, "RequestEvent.NamedIPv6s", eventheader.ErrCountTooLarge},
		{"ipv6 bytes", func(v *RequestEvent) { v.NamedIPv6s = make([][16]Octet, 4092) }, "RequestEvent.NamedIPv6s", eventheader.ErrEventTooLarge},
		{"uuid count", func(v *RequestEvent) { v.NamedUUIDs = make([][16]Octet, 65536) }, "RequestEvent.NamedUUIDs", eventheader.ErrCountTooLarge},
		{"uuid bytes", func(v *RequestEvent) { v.NamedUUIDs = make([][16]Octet, 4092) }, "RequestEvent.NamedUUIDs", eventheader.ErrEventTooLarge},
		{"numeric bytes", func(v *RequestEvent) { v.Counts = make([]Count, 20000) }, "RequestEvent.Counts", eventheader.ErrEventTooLarge},
		{"uintptr bytes", func(v *RequestEvent) { v.Pointers = make([]PointerWord, 20000) }, "RequestEvent.Pointers", eventheader.ErrEventTooLarge},
		{"utf16 repeated alias", func(v *RequestEvent) { v.Words = [][]Word{largeWords, largeWords} }, "RequestEvent.Words", eventheader.ErrEventTooLarge},
		{"utf16 inner count", func(v *RequestEvent) { v.Words = [][]Word{tooManyWords} }, "RequestEvent.Words", eventheader.ErrCountTooLarge},
		{"utf16 outer count", func(v *RequestEvent) { v.Words = make([][]Word, 65536) }, "RequestEvent.Words", eventheader.ErrCountTooLarge},
		{"binary repeated alias", func(v *RequestEvent) { v.NamedBlobs = [][]Octet{largeBytes, largeBytes} }, "RequestEvent.NamedBlobs", eventheader.ErrEventTooLarge},
		{"binary inner count", func(v *RequestEvent) { v.NamedBlobs = [][]Octet{tooManyBytes} }, "RequestEvent.NamedBlobs", eventheader.ErrCountTooLarge},
		{"binary outer count", func(v *RequestEvent) { v.NamedBlobs = make([][]Octet, 65536) }, "RequestEvent.NamedBlobs", eventheader.ErrCountTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := fixtureValue()
			test.mutate(value)
			writer := &RequestEventWriter{binding: schema.Bind(nil)}
			err := writer.bind(value)
			if !errors.Is(err, test.want) || !strings.Contains(err.Error(), test.path) {
				t.Fatalf("bind error = %v, want %v at %s", err, test.want, test.path)
			}
			scratch := reflect.ValueOf(writer).Elem()
			for i := 0; i < scratch.NumField(); i++ {
				field := scratch.Type().Field(i)
				if strings.HasPrefix(field.Name, "eventheaderGenScratch") &&
					scratch.Field(i).Cap() != 0 {
					t.Fatalf("%s allocated before validation", field.Name)
				}
			}
		})
	}
}
