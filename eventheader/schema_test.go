package eventheader

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/cataggar/LinuxTracepoints-Go/userevents"
)

func TestSchemaScalarMetadataAndPayloadParity(t *testing.T) {
	var uuid [16]byte
	var ipv4 [4]byte
	var ipv6 [16]byte
	for i := range uuid {
		uuid[i], ipv6[i] = byte(i), byte(0xf0+i)
	}
	copy(ipv4[:], []byte{127, 0, 0, 1})

	fields := []FieldDefinition{
		Int8Field("i8"), Uint8Field("u8"), Int16Field("i16"), Uint16Field("u16"),
		Int32Field("i32"), Uint32Field("u32", FieldOptions{Format: FormatHexInt, Tag: 1}),
		Int64Field("i64"), Uint64Field("u64"), BoolField("bool"), Float32Field("f32"),
		Float64Field("f64"), UintptrField("ptr"), UUIDField("uuid"), IPv4Field("ip4"),
		IPv6Field("ip6"), PortField("port"), StringField("string"), UTF16Field("utf16"),
		BinaryField("binary"),
	}
	schema, err := NewSchema(SchemaOptions{Name: "Fields"}, fields...)
	if err != nil {
		t.Fatal(err)
	}
	binding := schema.Bind(make([]byte, 0, 256))
	bindCalls := []func() error{
		func() error { return binding.Int8(-1) },
		func() error { return binding.Uint8(1) },
		func() error { return binding.Int16(-2) },
		func() error { return binding.Uint16(2) },
		func() error { return binding.Int32(-3) },
		func() error { return binding.Uint32(3) },
		func() error { return binding.Int64(-4) },
		func() error { return binding.Uint64(4) },
		func() error { return binding.Bool(true) },
		func() error { return binding.Float32(1.5) },
		func() error { return binding.Float64(2.5) },
		func() error { return binding.Uintptr(5) },
		func() error { return binding.UUID(uuid) },
		func() error { return binding.IPv4(ipv4) },
		func() error { return binding.IPv6(ipv6) },
		func() error { return binding.Port(443) },
		func() error { return binding.String("hello") },
		func() error { return binding.UTF16([]uint16{'h', 'i'}) },
		func() error { return binding.Binary([]byte{1, 2, 3}) },
	}
	for i, call := range bindCalls {
		if err := call(); err != nil {
			t.Fatalf("bind %d: %v", i, err)
		}
	}

	builder, err := NewBuilder("Fields")
	if err != nil {
		t.Fatal(err)
	}
	builderCalls := []func() error{
		func() error { return builder.Int8("i8", -1) },
		func() error { return builder.Uint8("u8", 1) },
		func() error { return builder.Int16("i16", -2) },
		func() error { return builder.Uint16("u16", 2) },
		func() error { return builder.Int32("i32", -3) },
		func() error {
			return builder.Uint32("u32", 3, FieldOptions{Format: FormatHexInt, Tag: 1})
		},
		func() error { return builder.Int64("i64", -4) },
		func() error { return builder.Uint64("u64", 4) },
		func() error { return builder.Bool("bool", true) },
		func() error { return builder.Float32("f32", 1.5) },
		func() error { return builder.Float64("f64", 2.5) },
		func() error { return builder.Uintptr("ptr", 5) },
		func() error { return builder.UUID("uuid", uuid) },
		func() error { return builder.IPv4("ip4", ipv4) },
		func() error { return builder.IPv6("ip6", ipv6) },
		func() error { return builder.Port("port", 443) },
		func() error { return builder.String("string", "hello") },
		func() error { return builder.UTF16("utf16", []uint16{'h', 'i'}) },
		func() error { return builder.Binary("binary", []byte{1, 2, 3}) },
	}
	for i, call := range builderCalls {
		if err := call(); err != nil {
			t.Fatalf("builder %d: %v", i, err)
		}
	}
	if !bytes.Equal(schema.metadata, builder.metadata) {
		t.Fatalf("metadata differs:\nschema %x\nbuilder %x", schema.metadata, builder.metadata)
	}
	if !bytes.Equal(binding.payload, builder.payload) {
		t.Fatalf("payload differs:\nbinding %x\nbuilder %x", binding.payload, builder.payload)
	}
}

func TestSchemaArrayAndNestedStructParity(t *testing.T) {
	fields := []FieldDefinition{
		StructField("outer", []FieldDefinition{
			ArrayField(Int32Field("fixed"), ArrayFixed, 2),
			StructField("inner", []FieldDefinition{
				ArrayField(StringField("strings"), ArrayVariable),
				ArrayField(BinaryField("binary"), ArrayFixed, 2),
			}),
		}, FieldOptions{Tag: 1}),
	}
	schema, err := NewSchema(SchemaOptions{Name: "Arrays"}, fields...)
	if err != nil {
		t.Fatal(err)
	}
	binding := schema.Bind(nil)
	if err := binding.Int32Array([]int32{1, 2}); err != nil {
		t.Fatal(err)
	}
	if err := binding.StringArray([]string{"a", "bc"}); err != nil {
		t.Fatal(err)
	}
	if err := binding.BinaryArray([][]byte{{1}, {}}); err != nil {
		t.Fatal(err)
	}

	builder, _ := NewBuilder("Arrays")
	_ = builder.BeginStruct("outer", 1)
	_ = builder.Int32Array("fixed", []int32{1, 2}, ArrayFixed)
	_ = builder.BeginStruct("inner", 0)
	_ = builder.StringArray("strings", []string{"a", "bc"}, ArrayVariable)
	_ = builder.BinaryArray("binary", [][]byte{{1}, {}}, ArrayFixed)
	_ = builder.EndStruct()
	_ = builder.EndStruct()
	if !bytes.Equal(schema.metadata, builder.metadata) || !bytes.Equal(binding.payload, builder.payload) {
		t.Fatalf("schema/builder mismatch: metadata %x/%x payload %x/%x",
			schema.metadata, builder.metadata, binding.payload, builder.payload)
	}
}

func TestSchemaAllArrayFamilies(t *testing.T) {
	definitions := []FieldDefinition{
		ArrayField(Int8Field("i8"), ArrayFixed, 1),
		ArrayField(Uint8Field("u8"), ArrayVariable),
		ArrayField(Int16Field("i16"), ArrayFixed, 1),
		ArrayField(Uint16Field("u16"), ArrayVariable),
		ArrayField(Int32Field("i32"), ArrayFixed, 1),
		ArrayField(Uint32Field("u32"), ArrayVariable),
		ArrayField(Int64Field("i64"), ArrayFixed, 1),
		ArrayField(Uint64Field("u64"), ArrayVariable),
		ArrayField(BoolField("bool"), ArrayFixed, 1),
		ArrayField(Float32Field("f32"), ArrayVariable),
		ArrayField(Float64Field("f64"), ArrayFixed, 1),
		ArrayField(UintptrField("ptr"), ArrayVariable),
		ArrayField(UUIDField("uuid"), ArrayFixed, 1),
		ArrayField(IPv4Field("ip4"), ArrayVariable),
		ArrayField(IPv6Field("ip6"), ArrayFixed, 1),
		ArrayField(PortField("port"), ArrayVariable),
		ArrayField(StringField("str"), ArrayFixed, 1),
		ArrayField(UTF16Field("utf16"), ArrayVariable),
		ArrayField(BinaryField("bin"), ArrayFixed, 1),
	}
	schema, err := NewSchema(SchemaOptions{Name: "AllArrays"}, definitions...)
	if err != nil {
		t.Fatal(err)
	}
	binding := schema.Bind(make([]byte, 0, 256))
	calls := []func() error{
		func() error { return binding.Int8Array([]int8{-1}) },
		func() error { return binding.Uint8Array([]byte{1}) },
		func() error { return binding.Int16Array([]int16{-2}) },
		func() error { return binding.Uint16Array([]uint16{2}) },
		func() error { return binding.Int32Array([]int32{-3}) },
		func() error { return binding.Uint32Array([]uint32{3}) },
		func() error { return binding.Int64Array([]int64{-4}) },
		func() error { return binding.Uint64Array([]uint64{4}) },
		func() error { return binding.BoolArray([]bool{true}) },
		func() error { return binding.Float32Array([]float32{1.5}) },
		func() error { return binding.Float64Array([]float64{2.5}) },
		func() error { return binding.UintptrArray([]uintptr{5}) },
		func() error { return binding.UUIDArray([][16]byte{{1}}) },
		func() error { return binding.IPv4Array([][4]byte{{127, 0, 0, 1}}) },
		func() error { return binding.IPv6Array([][16]byte{{1}}) },
		func() error { return binding.PortArray([]uint16{443}) },
		func() error { return binding.StringArray([]string{"s"}) },
		func() error { return binding.UTF16Array([][]uint16{{'s'}}) },
		func() error { return binding.BinaryArray([][]byte{{1}}) },
	}
	for i, call := range calls {
		if err := call(); err != nil {
			t.Fatalf("array %d: %v", i, err)
		}
	}
	if err := binding.Complete(); err != nil {
		t.Fatal(err)
	}

	builder, _ := NewBuilder("AllArrays")
	builderCalls := []func() error{
		func() error { return builder.Int8Array("i8", []int8{-1}, ArrayFixed) },
		func() error { return builder.Uint8Array("u8", []byte{1}, ArrayVariable) },
		func() error { return builder.Int16Array("i16", []int16{-2}, ArrayFixed) },
		func() error { return builder.Uint16Array("u16", []uint16{2}, ArrayVariable) },
		func() error { return builder.Int32Array("i32", []int32{-3}, ArrayFixed) },
		func() error { return builder.Uint32Array("u32", []uint32{3}, ArrayVariable) },
		func() error { return builder.Int64Array("i64", []int64{-4}, ArrayFixed) },
		func() error { return builder.Uint64Array("u64", []uint64{4}, ArrayVariable) },
		func() error { return builder.BoolArray("bool", []bool{true}, ArrayFixed) },
		func() error { return builder.Float32Array("f32", []float32{1.5}, ArrayVariable) },
		func() error { return builder.Float64Array("f64", []float64{2.5}, ArrayFixed) },
		func() error { return builder.UintptrArray("ptr", []uintptr{5}, ArrayVariable) },
		func() error { return builder.UUIDArray("uuid", [][16]byte{{1}}, ArrayFixed) },
		func() error { return builder.IPv4Array("ip4", [][4]byte{{127, 0, 0, 1}}, ArrayVariable) },
		func() error { return builder.IPv6Array("ip6", [][16]byte{{1}}, ArrayFixed) },
		func() error { return builder.PortArray("port", []uint16{443}, ArrayVariable) },
		func() error { return builder.StringArray("str", []string{"s"}, ArrayFixed) },
		func() error { return builder.UTF16Array("utf16", [][]uint16{{'s'}}, ArrayVariable) },
		func() error { return builder.BinaryArray("bin", [][]byte{{1}}, ArrayFixed) },
	}
	for i, call := range builderCalls {
		if err := call(); err != nil {
			t.Fatalf("builder array %d: %v", i, err)
		}
	}
	if !bytes.Equal(schema.metadata, builder.metadata) || !bytes.Equal(binding.payload, builder.payload) {
		t.Fatalf("array schema/builder mismatch: metadata %x/%x payload %x/%x",
			schema.metadata, builder.metadata, binding.payload, builder.payload)
	}
}

func TestSchemaDeepCopyNoFieldsAndValidation(t *testing.T) {
	options := []FieldOptions{{Tag: 7}}
	children := []FieldDefinition{Uint32Field("value", options...)}
	fields := []FieldDefinition{StructField("data", children)}
	schema, err := NewSchema(SchemaOptions{Name: "Immutable"}, fields...)
	if err != nil {
		t.Fatal(err)
	}
	metadata := append([]byte(nil), schema.metadata...)
	options[0].Tag = 99
	children[0] = StringField("changed")
	fields[0] = Uint8Field("other")
	if !bytes.Equal(schema.metadata, metadata) {
		t.Fatal("schema retained caller-mutable input")
	}
	if cap(schema.metadata) != len(schema.metadata) || cap(schema.plan) != len(schema.plan) {
		t.Fatal("schema retained appendable immutable slices")
	}
	empty, err := NewSchema(SchemaOptions{Name: "Empty"})
	if err != nil {
		t.Fatal(err)
	}
	binding := empty.Bind(nil)
	if err := binding.Complete(); err != nil {
		t.Fatal(err)
	}

	invalid := []FieldDefinition{
		{},
		ArrayField(Uint8Field("x"), ArrayFixed),
		ArrayField(Uint8Field("x"), ArrayFixed, 0),
		ArrayField(Uint8Field("x"), ArrayVariable, 1),
		ArrayField(StructField("x", []FieldDefinition{Uint8Field("y")}), ArrayFixed, 1),
		StructField("x", nil),
	}
	for i, field := range invalid {
		if _, err := NewSchema(SchemaOptions{Name: "Invalid"}, field); err == nil {
			t.Fatalf("invalid definition %d succeeded", i)
		}
	}
}

func TestSchemaDepthAndFieldLimits(t *testing.T) {
	field := Uint8Field("leaf")
	for range maxStructDepth {
		field = StructField("s", []FieldDefinition{field})
	}
	if _, err := NewSchema(SchemaOptions{Name: "Depth"}, field); err != nil {
		t.Fatalf("depth 8: %v", err)
	}
	field = StructField("tooDeep", []FieldDefinition{field})
	if _, err := NewSchema(SchemaOptions{Name: "Depth"}, field); !errors.Is(err, ErrNestingTooDeep) {
		t.Fatalf("depth error = %v", err)
	}
	children := make([]FieldDefinition, maxStructChildFields+1)
	for i := range children {
		children[i] = Uint8Field("x")
	}
	if _, err := NewSchema(SchemaOptions{Name: "Children"}, StructField("s", children)); !errors.Is(err, ErrTooManyFields) {
		t.Fatalf("children error = %v", err)
	}
}

func TestBindingOrderCountsBoundariesAndNonMutation(t *testing.T) {
	schema, err := NewSchema(SchemaOptions{Name: "Binding"},
		Uint32Field("value"),
		ArrayField(Uint16Field("fixed"), ArrayFixed, 2),
		StringField("text"),
		ArrayField(BinaryField("items"), ArrayVariable),
	)
	if err != nil {
		t.Fatal(err)
	}
	binding := schema.Bind(make([]byte, 0, 32))
	if err := binding.Complete(); !errors.Is(err, ErrState) {
		t.Fatalf("too-few error = %v", err)
	}
	if err := binding.String("wrong"); !errors.Is(err, ErrState) {
		t.Fatalf("wrong-type error = %v", err)
	}
	if binding.index != 0 || len(binding.payload) != 0 {
		t.Fatal("wrong type mutated binding")
	}
	if err := binding.Uint32(42); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), binding.payload...)
	if err := binding.Uint16Array([]uint16{1}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("fixed-count error = %v", err)
	}
	if binding.index != 1 || !bytes.Equal(binding.payload, before) {
		t.Fatal("rejected fixed count mutated binding")
	}
	if err := binding.Uint16Array([]uint16{1, 2}); err != nil {
		t.Fatal(err)
	}
	before = append(before[:0], binding.payload...)
	if err := binding.String(string([]byte{0xff})); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
	if binding.index != 2 || !bytes.Equal(binding.payload, before) {
		t.Fatal("rejected string mutated binding")
	}
	if err := binding.String("ok"); err != nil {
		t.Fatal(err)
	}
	if err := binding.BinaryArray([][]byte{{1}, {2, 3}}); err != nil {
		t.Fatal(err)
	}
	if err := binding.Uint32(1); !errors.Is(err, ErrState) {
		t.Fatalf("too-many error = %v", err)
	}
	if err := binding.Complete(); err != nil {
		t.Fatal(err)
	}

	largeSchema, _ := NewSchema(SchemaOptions{Name: "Large"}, ArrayField(Uint8Field("v"), ArrayVariable))
	largeBinding := largeSchema.Bind(nil)
	if err := largeBinding.Uint8Array(make([]byte, maxCount+1)); !errors.Is(err, ErrCountTooLarge) {
		t.Fatalf("count overflow = %v", err)
	}
	stringSchema, _ := NewSchema(SchemaOptions{Name: "Large"}, StringField("v"))
	stringBinding := stringSchema.Bind(nil)
	if err := stringBinding.String(strings.Repeat("x", maxCount)); !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("event boundary = %v", err)
	}
}

func TestEventGoldenActivityWrongSchemaAndDisabled(t *testing.T) {
	schema, err := NewSchema(SchemaOptions{
		Name: "Event", ID: 0x1234, Version: 2, Tag: 3, Opcode: OpcodeActivityStart,
	}, Uint32Field("value"))
	if err != nil {
		t.Fatal(err)
	}
	registration := new(fakeRegistration)
	registration.enabled.Store(true)
	set := fakeSet(LevelInformation, 1, "", registration)
	event := mustNewEvent(t, set, schema)
	binding := event.Bind(make([]byte, 0, 4))
	if err := binding.Uint32(0xabcdef01); err != nil {
		t.Fatal(err)
	}
	var activity, related ActivityID
	for i := range activity {
		activity[i], related[i] = byte(i), byte(0xf0+i)
	}
	if err := event.Write(&binding, &activity, &related); err != nil {
		t.Fatal(err)
	}
	builder, _ := NewBuilder("Event")
	_ = builder.SetIDVersion(0x1234, 2)
	_ = builder.SetTag(3)
	_ = builder.SetOpcode(OpcodeActivityStart)
	_ = builder.SetActivity(&activity, &related)
	_ = builder.Uint32("value", 0xabcdef01)
	want, err := builder.Encode(LevelInformation)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(registration.writes[0], want) {
		t.Fatalf("event wire = %x, want %x", registration.writes[0], want)
	}

	other, _ := NewSchema(SchemaOptions{Name: "Other"}, Uint32Field("value"))
	wrong := other.Bind(make([]byte, 0, 4))
	_ = wrong.Uint32(1)
	if err := event.Write(&wrong, nil, nil); !errors.Is(err, ErrState) {
		t.Fatalf("wrong-schema error = %v", err)
	}
	if err := event.Write(&binding, nil, &related); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("orphan-related error = %v", err)
	}

	registration.enabled.Store(false)
	if err := event.Write(nil, nil, &related); !errors.Is(err, userevents.ErrDisabled) {
		t.Fatalf("disabled error = %v, want ErrDisabled before validation", err)
	}
	if allocations := testing.AllocsPerRun(1000, func() {
		if err := event.Write(nil, nil, nil); !errors.Is(err, userevents.ErrDisabled) {
			panic(err)
		}
	}); allocations != 0 {
		t.Fatalf("disabled state-only Write allocations = %v, want 0", allocations)
	}
	registration.closedFlag.Store(true)
	if err := event.Write(&binding, nil, nil); !errors.Is(err, userevents.ErrClosed) {
		t.Fatalf("closed error = %v", err)
	}
	if allocations := testing.AllocsPerRun(1000, func() {
		if err := event.Write(nil, nil, nil); !errors.Is(err, userevents.ErrClosed) {
			panic(err)
		}
	}); allocations != 0 {
		t.Fatalf("closed state-only Write allocations = %v, want 0", allocations)
	}
}

func TestNewEventValidation(t *testing.T) {
	schema, err := NewSchema(SchemaOptions{Name: "Event"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewEvent(nil, schema); !errors.Is(err, userevents.ErrClosed) {
		t.Fatalf("nil set error = %v, want ErrClosed", err)
	}
	if _, err := NewEvent(fakeSet(LevelInformation, 0, "", new(fakeRegistration)), nil); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("nil schema error = %v, want ErrInvalidValue", err)
	}
	invalidLevel := fakeSet(LevelInformation, 0, "", new(fakeRegistration))
	invalidLevel.level = LevelInvalid
	if _, err := NewEvent(invalidLevel, schema); !errors.Is(err, ErrInvalidLevel) {
		t.Fatalf("invalid level error = %v, want ErrInvalidLevel", err)
	}
	closed := new(fakeRegistration)
	closed.closedFlag.Store(true)
	if _, err := NewEvent(fakeSet(LevelInformation, 0, "", closed), schema); !errors.Is(err, userevents.ErrClosed) {
		t.Fatalf("closed set error = %v, want ErrClosed", err)
	}
}

func TestConcurrentImmutableEventSeparateBindings(t *testing.T) {
	schema, _ := NewSchema(SchemaOptions{Name: "Concurrent"}, Uint64Field("value"))
	registration := new(fakeRegistration)
	registration.enabled.Store(true)
	event := mustNewEvent(t, fakeSet(LevelVerbose, math.MaxUint64, "", registration), schema)
	var wait sync.WaitGroup
	for worker := range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			binding := event.Bind(make([]byte, 0, 8))
			for value := range 100 {
				binding.Reset()
				if err := binding.Uint64(uint64(worker*100 + value)); err != nil {
					t.Errorf("bind: %v", err)
					return
				}
				if err := event.Write(&binding, nil, nil); err != nil {
					t.Errorf("write: %v", err)
					return
				}
			}
		}()
	}
	wait.Wait()
	if got := len(registration.writes); got != 3200 {
		t.Fatalf("writes = %d, want 3200", got)
	}
}

func TestReusableFixedBindingAndEventAllocations(t *testing.T) {
	schema, _ := NewSchema(SchemaOptions{Name: "Allocation"}, Uint32Field("value"))
	binding := schema.Bind(make([]byte, 0, 4))
	if got := testing.AllocsPerRun(1000, func() {
		binding.Reset()
		if err := binding.Uint32(42); err != nil {
			panic(err)
		}
	}); got != 0 {
		t.Fatalf("reused binding allocations = %v, want 0", got)
	}

	registration := new(fakeRegistration)
	event := mustNewEvent(t, fakeSet(LevelInformation, 1, "", registration), schema)
	binding.Reset()
	if err := binding.Uint32(42); err != nil {
		t.Fatal(err)
	}
	if got := testing.AllocsPerRun(1000, func() {
		_ = event.Enabled()
	}); got != 0 {
		t.Fatalf("Event.Enabled allocations = %v, want 0", got)
	}
	if got := testing.AllocsPerRun(1000, func() {
		_ = event.Write(&binding, nil, nil)
	}); got != 0 {
		t.Fatalf("disabled Event.Write allocations = %v, want 0", got)
	}
}

func BenchmarkReusableFixedBinding(b *testing.B) {
	schema, _ := NewSchema(SchemaOptions{Name: "Benchmark"}, Uint64Field("value"))
	binding := schema.Bind(make([]byte, 0, 8))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		binding.Reset()
		_ = binding.Uint64(42)
	}
}

func BenchmarkEventEnabledDisabled(b *testing.B) {
	schema, _ := NewSchema(SchemaOptions{Name: "Benchmark"})
	event := mustNewEvent(b, fakeSet(LevelInformation, 1, "", new(fakeRegistration)), schema)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = event.Enabled()
	}
}

func BenchmarkEventWriteDisabled(b *testing.B) {
	schema, _ := NewSchema(SchemaOptions{Name: "Benchmark"}, Uint32Field("value"))
	event := mustNewEvent(b, fakeSet(LevelInformation, 1, "", new(fakeRegistration)), schema)
	binding := event.Bind(make([]byte, 0, 4))
	_ = binding.Uint32(42)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = event.Write(&binding, nil, nil)
	}
}

func mustNewEvent(t testing.TB, set *EventSet, schema *Schema) *Event {
	t.Helper()
	event, err := NewEvent(set, schema)
	if err != nil {
		t.Fatalf("NewEvent: %v", err)
	}
	return event
}
