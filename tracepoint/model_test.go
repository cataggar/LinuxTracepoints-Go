package tracepoint

import (
	"errors"
	"math"
	"net/netip"
	"testing"
)

func TestCloneRecordIsIndependent(t *testing.T) {
	raw := []byte{1, 2, 3}
	binary := []byte{4, 5}
	nestedRaw := []byte{6}
	record := Record{
		Kind:     RecordEvent,
		Raw:      raw,
		Identity: Identity{System: "sched", Name: "switch", ID: 7},
		Event: &EventRecord{
			EventHeader: &EventHeaderInfo{
				EventNameRaw: raw[:1],
				Metadata:     raw,
				Payload:      binary,
				Extensions:   []EventHeaderExtension{{Kind: 3, Data: nestedRaw}},
			},
			Fields: []Field{{
				Name: "value",
				Value: Value{
					Kind:   ValueStruct,
					Raw:    raw[1:],
					Binary: binary,
					IP:     netip.MustParseAddr("192.0.2.1"),
					Array:  []Value{{Kind: ValueBinary, Raw: nestedRaw, Binary: nestedRaw}},
					Struct: []Field{{Name: "child", Value: Value{Kind: ValueText, Text: "x", Raw: nestedRaw}}},
					Valid:  true,
				},
				Diagnostics: []Diagnostic{{Message: "kept"}},
			}},
		},
		Diagnostics: []Diagnostic{{Message: "record"}},
	}

	clone := CloneRecord(record)
	raw[1] = 20
	binary[0] = 40
	nestedRaw[0] = 60
	record.Event.Fields[0].Value.Array[0].Kind = ValueNull
	record.Event.Fields[0].Diagnostics[0].Message = "changed"

	value := clone.Event.Fields[0].Value
	if clone.Raw[1] != 2 || value.Raw[0] != 2 || value.Binary[0] != 4 {
		t.Fatalf("clone shares byte storage: %#v", clone)
	}
	if value.Array[0].Kind != ValueBinary || value.Array[0].Raw[0] != 6 || value.Struct[0].Value.Raw[0] != 6 {
		t.Fatalf("clone shares nested storage: %#v", value)
	}
	if clone.Event.Fields[0].Diagnostics[0].Message != "kept" {
		t.Fatal("clone shares diagnostic slice")
	}
	if clone.Event.EventHeader.EventNameRaw[0] != 1 ||
		clone.Event.EventHeader.Metadata[1] != 2 ||
		clone.Event.EventHeader.Payload[0] != 4 ||
		clone.Event.EventHeader.Extensions[0].Data[0] != 6 {
		t.Fatal("clone shares EventHeader envelope storage")
	}
}

func TestTimestampCompare(t *testing.T) {
	a := Timestamp{Nanoseconds: 10, Clock: ClockMonotonic}
	b := Timestamp{Nanoseconds: 11, Clock: ClockMonotonic}
	if got, err := a.Compare(b); got != -1 || err != nil {
		t.Fatalf("Compare = %d, %v", got, err)
	}

	if _, err := a.Compare(Timestamp{Nanoseconds: 1, Clock: ClockBoot}); !errors.Is(err, ErrIncomparableClocks) {
		t.Fatalf("Compare error = %v", err)
	}
	realtime := Timestamp{Nanoseconds: 20, Clock: ClockMonotonic, EpochOffset: 100, EpochOffsetKnown: true}
	boot := Timestamp{Nanoseconds: 25, Clock: ClockBoot, EpochOffset: 100, EpochOffsetKnown: true}
	if got, err := realtime.Compare(boot); got != -1 || err != nil {
		t.Fatalf("epoch Compare = %d, %v", got, err)
	}

	negative := Timestamp{Clock: ClockRealtime, EpochOffset: -1, EpochOffsetKnown: true}
	epoch := Timestamp{Clock: ClockRealtime, EpochOffsetKnown: true}
	if got, err := negative.Compare(epoch); got != -1 || err != nil {
		t.Fatalf("negative/epoch Compare = %d, %v", got, err)
	}
	earlierNegative := Timestamp{Clock: ClockRealtime, EpochOffset: -2, EpochOffsetKnown: true}
	if got, err := earlierNegative.Compare(negative); got != -1 || err != nil {
		t.Fatalf("negative Compare = %d, %v", got, err)
	}

	overflow := Timestamp{
		Nanoseconds: math.MaxUint64, Clock: ClockRealtime, EpochOffsetKnown: true,
	}
	if _, err := overflow.Compare(Timestamp{
		Clock: ClockRealtime, EpochOffset: 1, EpochOffsetKnown: true,
	}); !errors.Is(err, ErrIncomparableClocks) {
		t.Fatalf("overflow Compare error = %v", err)
	}
	if got, err := overflow.Compare(Timestamp{
		Nanoseconds: math.MaxUint64 - 1, Clock: ClockRealtime, EpochOffsetKnown: true,
	}); got != 1 || err != nil {
		t.Fatalf("equivalent-offset overflow Compare = %d, %v", got, err)
	}
}

func TestTimestampUnixNanoBoundaries(t *testing.T) {
	tests := []struct {
		timestamp Timestamp
		want      int64
		ok        bool
	}{
		{Timestamp{Nanoseconds: uint64(math.MaxInt64), EpochOffsetKnown: true}, math.MaxInt64, true},
		{Timestamp{Nanoseconds: uint64(math.MaxInt64) + 1, EpochOffset: math.MinInt64, EpochOffsetKnown: true}, 0, true},
		{Timestamp{Nanoseconds: 0, EpochOffset: math.MinInt64, EpochOffsetKnown: true}, math.MinInt64, true},
		{Timestamp{Nanoseconds: math.MaxUint64, EpochOffset: -1, EpochOffsetKnown: true}, 0, false},
		{Timestamp{}, 0, false},
	}
	for _, test := range tests {
		got, ok := test.timestamp.UnixNano()
		if got != test.want || ok != test.ok {
			t.Errorf("UnixNano(%#v) = %d, %v; want %d, %v", test.timestamp, got, ok, test.want, test.ok)
		}
	}
}

func TestDecodeErrorUnwrap(t *testing.T) {
	err := &DecodeError{Offset: 3, Stage: "field", Err: ErrTruncated}
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("errors.Is(%v, ErrTruncated) is false", err)
	}
}
