package eventheader

import (
	"fmt"

	"github.com/cataggar/LinuxTracepoints-Go/userevents"
)

// Event binds one immutable Schema to one EventSet and precomputes the normal
// EventHeader prefix. It is safe for concurrent use with separate Bindings.
type Event struct {
	set    *EventSet
	schema *Schema
	prefix [12]byte
}

// NewEvent binds schema to set.
func NewEvent(set *EventSet, schema *Schema) (*Event, error) {
	if set == nil || set.registration == nil || set.closed() {
		return nil, userevents.ErrClosed
	}
	if set.level < LevelCritical || set.level > LevelVerbose {
		return nil, fmt.Errorf("%w: %d", ErrInvalidLevel, set.level)
	}
	if schema == nil || schema.options.Name == "" || len(schema.metadata) == 0 {
		return nil, fmt.Errorf("%w: unusable schema", ErrInvalidValue)
	}
	event := &Event{set: set, schema: schema}
	options := schema.options
	event.prefix[0] = byte(defaultHeaderFlags())
	event.prefix[1] = options.Version
	nativeEndian.PutUint16(event.prefix[2:4], options.ID)
	nativeEndian.PutUint16(event.prefix[4:6], uint16(options.Tag))
	event.prefix[6] = byte(options.Opcode)
	event.prefix[7] = byte(set.level)
	nativeEndian.PutUint16(event.prefix[8:10], uint16(len(schema.metadata)))
	nativeEndian.PutUint16(event.prefix[10:12], uint16(ExtensionMetadata))
	return event, nil
}

// Enabled reports whether this event's tracepoint is currently enabled.
func (e *Event) Enabled() bool {
	return e != nil && e.set != nil && e.set.Enabled()
}

// Bind creates an empty goroutine-local binding using storage as retained
// payload capacity.
func (e *Event) Bind(storage []byte) Binding {
	if e == nil {
		return Binding{payload: storage[:0]}
	}
	return NewBinding(e.schema, storage)
}

// WriteIfEnabled resets binding and invokes bind only when this event's
// tracepoint is enabled. It returns ErrDisabled without validating or mutating
// binding or invoking bind. A callback error may leave binding partially
// populated; the next enabled call resets it before reuse. Enablement is
// checked again by Write after the callback to handle collector races.
func (e *Event) WriteIfEnabled(
	binding *Binding,
	activity, related *ActivityID,
	bind func(*Binding) error,
) error {
	if e == nil || e.set == nil || e.set.registration == nil || e.set.closed() {
		return userevents.ErrClosed
	}
	if !e.set.Enabled() {
		if e.set.closed() {
			return userevents.ErrClosed
		}
		return userevents.ErrDisabled
	}
	if related != nil && activity == nil {
		return fmt.Errorf("%w: related ID requires an activity ID", ErrInvalidValue)
	}
	if binding == nil {
		return fmt.Errorf("%w: nil binding", ErrInvalidValue)
	}
	if binding.schema != e.schema {
		return fmt.Errorf("%w: binding belongs to a different schema", ErrState)
	}
	if bind == nil {
		return fmt.Errorf("%w: nil bind callback", ErrInvalidValue)
	}
	binding.Reset()
	if err := bind(binding); err != nil {
		return err
	}
	return e.Write(binding, activity, related)
}

// Write emits a complete binding with optional activity correlation IDs.
func (e *Event) Write(binding *Binding, activity, related *ActivityID) error {
	if e == nil || e.set == nil || e.set.registration == nil || e.set.closed() {
		return userevents.ErrClosed
	}
	if !e.set.Enabled() {
		if e.set.closed() {
			return userevents.ErrClosed
		}
		return userevents.ErrDisabled
	}
	if related != nil && activity == nil {
		return fmt.Errorf("%w: related ID requires an activity ID", ErrInvalidValue)
	}
	if binding == nil {
		return fmt.Errorf("%w: nil binding", ErrInvalidValue)
	}
	if binding.schema != e.schema {
		return fmt.Errorf("%w: binding belongs to a different schema", ErrState)
	}
	if err := binding.Complete(); err != nil {
		return err
	}
	if activity == nil {
		return e.set.writev(e.prefix[:], e.schema.metadata, binding.payload)
	}

	var prefix [48]byte
	copy(prefix[:8], e.prefix[:8])
	activitySize := 16
	if related != nil {
		activitySize = 32
	}
	nativeEndian.PutUint16(prefix[8:10], uint16(activitySize))
	nativeEndian.PutUint16(prefix[10:12], uint16(ExtensionActivityID|ExtensionKindChainFlag))
	copy(prefix[12:28], activity[:])
	offset := 28
	if related != nil {
		copy(prefix[offset:offset+16], related[:])
		offset += 16
	}
	copy(prefix[offset:offset+4], e.prefix[8:12])
	offset += 4
	return e.set.writev(prefix[:offset], e.schema.metadata, binding.payload)
}
