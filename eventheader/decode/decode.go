package decode

import (
	"github.com/cataggar/LinuxTracepoints-Go/eventheader"
	"github.com/cataggar/LinuxTracepoints-Go/tracepoint"
)

type materialFrame struct {
	state  State
	item   Item
	values []tracepoint.Value
	fields []tracepoint.Field
}

// Decode validates and materializes one EventHeader event. The returned Raw
// slices borrow data.
func (d *Decoder) Decode(tracepointName string, data []byte) (tracepoint.Record, error) {
	enumerator, err := d.Start(tracepointName, data)
	if err != nil {
		return tracepoint.Record{}, err
	}
	var top []tracepoint.Field
	var stack []materialFrame
	appendValue := func(item Item, value tracepoint.Value) {
		if len(stack) == 0 {
			top = append(top, tracepoint.Field{Name: item.Name, Value: value, Offset: item.Offset})
			return
		}
		parent := &stack[len(stack)-1]
		if parent.state == ArrayBegin {
			parent.values = append(parent.values, value)
		} else {
			parent.fields = append(parent.fields, tracepoint.Field{Name: item.Name, Value: value, Offset: item.Offset})
		}
	}
	for enumerator.Next() {
		item := *enumerator.Item()
		switch enumerator.State() {
		case Value:
			appendValue(item, item.Value)
		case ArrayBegin, StructBegin:
			stack = append(stack, materialFrame{state: enumerator.State(), item: item})
		case ArrayEnd, StructEnd:
			frame := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			value := tracepoint.Value{
				Raw: item.Raw, ByteOrder: enumerator.event.info.ByteOrder,
				Format: containerFormat(frame.item), Width: bitWidth(len(item.Raw)), Valid: true,
			}
			if frame.state == ArrayBegin {
				value.Kind, value.Encoding, value.Array = tracepoint.ValueArray, tracepoint.EncodingArray, frame.values
			} else {
				value.Kind, value.Encoding, value.Struct = tracepoint.ValueStruct, tracepoint.EncodingStruct, frame.fields
			}
			appendValue(frame.item, value)
		}
	}
	if err := enumerator.Err(); err != nil {
		return tracepoint.Record{}, err
	}
	info := enumerator.EventInfo()
	diagnostics := append([]tracepoint.Diagnostic(nil), info.Diagnostics...)
	collectValueDiagnostics(top, &diagnostics)
	record := tracepoint.Record{
		Kind: tracepoint.RecordEvent,
		Identity: tracepoint.Identity{
			System: info.Provider, Name: info.EventName, ID: uint32(info.Header.ID),
		},
		Event: &tracepoint.EventRecord{
			Fields:      top,
			EventHeader: materializeEventHeaderInfo(info),
		},
		Raw:         data,
		Diagnostics: diagnostics,
	}
	return record, nil
}

func containerFormat(item Item) string {
	if item.Encoding == eventheader.EncodingStruct {
		return "struct"
	}
	return formatName(item.Format)
}

func materializeEventHeaderInfo(info *EventInfo) *tracepoint.EventHeaderInfo {
	pointerWidth := uint8(32)
	if info.Pointer64 {
		pointerWidth = 64
	}
	out := &tracepoint.EventHeaderInfo{
		Provider: info.Provider, Keyword: info.Keyword, Options: info.Options,
		Flags: uint8(info.Header.Flags), Version: info.Header.Version, ID: info.Header.ID,
		Tag: uint16(info.Header.Tag), Opcode: uint8(info.Header.Opcode), Level: uint8(info.Header.Level),
		ByteOrder: info.ByteOrder, PointerWidth: pointerWidth,
		EventName: info.EventName, EventNameRaw: info.EventNameRaw,
		Metadata: info.Metadata, Payload: info.Payload,
	}
	if info.ActivityID.Present {
		out.ActivityID.Present = true
		copy(out.ActivityID.Value[:], info.ActivityID.Value[:])
	}
	if info.RelatedID.Present {
		out.RelatedActivityID.Present = true
		copy(out.RelatedActivityID.Value[:], info.RelatedID.Value[:])
	}
	if info.Extensions != nil {
		out.Extensions = make([]tracepoint.EventHeaderExtension, len(info.Extensions))
		for i := range info.Extensions {
			extension := info.Extensions[i]
			out.Extensions[i] = tracepoint.EventHeaderExtension{
				Kind: uint16(extension.Kind), Size: extension.Size, Chain: extension.Chain,
				Offset: extension.Offset, Data: extension.Data,
			}
		}
	}
	return out
}

func collectValueDiagnostics(fields []tracepoint.Field, target *[]tracepoint.Diagnostic) {
	for i := range fields {
		value := &fields[i].Value
		*target = append(*target, fields[i].Diagnostics...)
		*target = append(*target, value.Diagnostics...)
		if value.Kind == tracepoint.ValueStruct {
			collectValueDiagnostics(value.Struct, target)
		}
		if value.Kind == tracepoint.ValueArray {
			for j := range value.Array {
				*target = append(*target, value.Array[j].Diagnostics...)
				if value.Array[j].Kind == tracepoint.ValueStruct {
					collectValueDiagnostics(value.Array[j].Struct, target)
				}
			}
		}
	}
}

// Decode is a convenience wrapper using default limits.
func Decode(tracepointName string, data []byte) (tracepoint.Record, error) {
	return new(Decoder).Decode(tracepointName, data)
}

// Start is a convenience wrapper using default limits.
func Start(tracepointName string, data []byte) (*Enumerator, error) {
	return new(Decoder).Start(tracepointName, data)
}
