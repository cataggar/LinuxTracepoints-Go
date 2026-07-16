package decode

import (
	"errors"
	"fmt"

	"github.com/cataggar/LinuxTracepoints-Go/eventheader"
	"github.com/cataggar/LinuxTracepoints-Go/tracepoint"
)

type taskKind uint8

const (
	taskFields taskKind = iota
	taskField
	taskArray
	taskArrayEnd
	taskStructEnd
)

type enumTask struct {
	kind       taskKind
	fields     []*fieldDef
	index      int
	def        *fieldDef
	count      int
	start      int
	arrayIndex int
}

// Enumerator is a bounded forward-only EventHeader iterator.
type Enumerator struct {
	event       *parsedEvent
	limits      Limits
	state       State
	item        *Item
	err         error
	pos         int
	transitions int
	stack       []enumTask
}

// Start validates the header, extensions, and metadata and returns an iterator
// positioned BeforeFirst. Payload errors are reported by Next.
func (d *Decoder) Start(tracepointName string, data []byte) (*Enumerator, error) {
	if d == nil {
		d = &Decoder{}
	}
	event, err := d.parse(tracepointName, data)
	if err != nil {
		return nil, err
	}
	e := &Enumerator{event: event, limits: d.Limits.normalized(), state: BeforeFirst}
	e.stack = append(e.stack, enumTask{kind: taskFields, fields: event.fields})
	return e, nil
}

// State returns the current state.
func (e *Enumerator) State() State {
	if e == nil {
		return Error
	}
	return e.state
}

// Item returns the current item. Each returned item remains valid for the
// Enumerator lifetime.
func (e *Enumerator) Item() *Item {
	if e == nil || e.state == BeforeFirst || e.state == Done || e.state == Error {
		return nil
	}
	return e.item
}

// EventInfo returns immutable event information. Borrowed slices remain valid
// under the same rules as the Enumerator input.
func (e *Enumerator) EventInfo() *EventInfo {
	if e == nil || e.event == nil {
		return nil
	}
	return &e.event.info
}

// Err returns the terminal iteration error, if any.
func (e *Enumerator) Err() error {
	if e == nil {
		return fmt.Errorf("%w: nil enumerator", tracepoint.ErrInvalid)
	}
	return e.err
}

// Next advances to the next value or container boundary. It returns false at
// Done or Error.
func (e *Enumerator) Next() bool {
	if e == nil || e.state == Done || e.state == Error {
		return false
	}
	for len(e.stack) != 0 {
		task := e.stack[len(e.stack)-1]
		e.stack = e.stack[:len(e.stack)-1]
		switch task.kind {
		case taskFields:
			if task.index == len(task.fields) {
				continue
			}
			def := task.fields[task.index]
			task.index++
			e.stack = append(e.stack, task, enumTask{kind: taskField, def: def, arrayIndex: -1})
		case taskField:
			if task.def.arrayKind != eventheader.ArrayScalar {
				count := int(task.def.count)
				start := e.pos
				if task.def.arrayKind == eventheader.ArrayVariable {
					if len(e.event.payload)-e.pos < 2 {
						return e.fail(truncated(e.event.payloadOffset+e.pos, "variable array count"))
					}
					count = int(e.event.order.Uint16(e.event.payload[e.pos : e.pos+2]))
					e.pos += 2
				}
				e.stack = append(e.stack,
					enumTask{kind: taskArrayEnd, def: task.def, count: count, start: start},
					enumTask{kind: taskArray, def: task.def, count: count, start: start},
				)
				return e.emit(ArrayBegin, task.def, start, nil, count, -1)
			}
			if task.def.encoding == eventheader.EncodingStruct {
				start := e.pos
				e.stack = append(e.stack,
					enumTask{kind: taskStructEnd, def: task.def, start: start, arrayIndex: task.arrayIndex},
					enumTask{kind: taskFields, fields: task.def.children},
				)
				return e.emit(StructBegin, task.def, start, nil, 0, task.arrayIndex)
			}
			raw, rawOffset, next, err := readWireValue(task.def, e.event.payload, e.pos, e.event.order)
			if err != nil {
				return e.fail(shiftDecodeError(err, e.event.payloadOffset))
			}
			e.pos = next
			value := decodeScalar(task.def, raw, e.event.payloadOffset+rawOffset, e.event.order, e.event.info.ByteOrder)
			return e.emit(Value, task.def, rawOffset, &value, 0, task.arrayIndex)
		case taskArray:
			if task.index == task.count {
				continue
			}
			index := task.index
			task.index++
			element := *task.def
			element.arrayKind = eventheader.ArrayScalar
			e.stack = append(e.stack, task, enumTask{kind: taskField, def: &element, arrayIndex: index})
		case taskArrayEnd:
			return e.emit(ArrayEnd, task.def, task.start, nil, task.count, -1)
		case taskStructEnd:
			return e.emit(StructEnd, task.def, task.start, nil, 0, task.arrayIndex)
		}
	}
	e.finish()
	return false
}

func (e *Enumerator) emit(state State, def *fieldDef, offset int, value *tracepoint.Value, count, arrayIndex int) bool {
	if e.transitions >= e.limits.MaxTransitions {
		return e.fail(decodeError(e.event.payloadOffset+offset, "iteration", tracepoint.ErrLimit))
	}
	e.transitions++
	raw := []byte(nil)
	if state == ArrayEnd || state == StructEnd {
		raw = e.event.payload[offset:e.pos]
	}
	item := &Item{
		Name: def.name, NameRaw: def.nameRaw, Encoding: def.encoding,
		Format: def.format, Tag: def.tag, ArrayKind: def.arrayKind,
		ArrayCount: uint16(count), ArrayIndex: arrayIndex, Depth: def.depth,
		Offset: e.event.payloadOffset + offset, Raw: raw,
	}
	if value != nil {
		item.Value = *value
		item.Raw = value.Raw
	}
	e.item = item
	e.state = state
	return true
}

func shiftDecodeError(err error, amount int) error {
	var de *tracepoint.DecodeError
	if !errors.As(err, &de) {
		return err
	}
	return &tracepoint.DecodeError{Offset: de.Offset + amount, Stage: de.Stage, Err: de.Err}
}

func (e *Enumerator) fail(err error) bool {
	e.err, e.state = err, Error
	return false
}

func (e *Enumerator) finish() {
	if trailing := len(e.event.payload) - e.pos; trailing != 0 {
		severity := tracepoint.SeverityError
		message := "unconsumed trailing payload"
		if trailing <= 7 {
			severity = tracepoint.SeverityWarning
			message = "possible perf padding remains after payload"
		}
		e.event.info.Diagnostics = append(e.event.info.Diagnostics, tracepoint.Diagnostic{
			Severity: severity, Offset: e.event.payloadOffset + e.pos, Stage: "payload", Message: message,
			Err: fmt.Errorf("%w: %d trailing bytes", tracepoint.ErrInvalid, trailing),
		})
	}
	e.state = Done
}
