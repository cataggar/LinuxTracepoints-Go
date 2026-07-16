package eventheader

import (
	"fmt"
	"sync/atomic"

	"github.com/cataggar/LinuxTracepoints-Go/userevents"
)

type eventSetRegistration interface {
	Enabled() bool
	Closed() bool
	Writev(...[]byte) error
	Close() error
}

// EventSet owns one EventHeader tracepoint registration for a provider, level,
// keyword, and group. It does not own or close the underlying File.
type EventSet struct {
	registration eventSetRegistration
	name         string
	level        Level
	keyword      uint64
	closeDone    atomic.Bool
}

// NewEventSet validates and registers one EventHeader tracepoint.
func NewEventSet(file *userevents.File, provider string, level Level, keyword uint64, group string) (*EventSet, error) {
	if file == nil {
		return nil, fmt.Errorf("%w: nil user_events file", ErrInvalidValue)
	}
	name, err := TracepointName(provider, level, keyword, group)
	if err != nil {
		return nil, err
	}
	registration, err := file.Register(name, TracepointFields, userevents.RegisterOptions{})
	if err != nil {
		return nil, err
	}
	return &EventSet{
		registration: registration,
		name:         name,
		level:        level,
		keyword:      keyword,
	}, nil
}

// Name returns the canonical registered tracepoint name.
func (s *EventSet) Name() string {
	if s == nil {
		return ""
	}
	return s.name
}

// Level returns the event severity associated with the set.
func (s *EventSet) Level() Level {
	if s == nil {
		return LevelInvalid
	}
	return s.level
}

// Keyword returns the provider-defined category mask associated with the set.
func (s *EventSet) Keyword() uint64 {
	if s == nil {
		return 0
	}
	return s.keyword
}

// Enabled reports whether a collector currently enables this tracepoint.
func (s *EventSet) Enabled() bool {
	return s != nil && s.registration != nil && !s.closeDone.Load() && s.registration.Enabled()
}

func (s *EventSet) closed() bool {
	return s == nil || s.registration == nil || s.closeDone.Load() || s.registration.Closed()
}

func (s *EventSet) writev(payloads ...[]byte) error {
	if s == nil || s.registration == nil {
		return userevents.ErrClosed
	}
	return s.registration.Writev(payloads...)
}

// Write encodes and emits builder through Registration.Writev. The enabled
// state is checked before any encoding work.
func (s *EventSet) Write(builder *Builder) error {
	if s == nil || s.registration == nil {
		return userevents.ErrClosed
	}
	if s.closed() {
		return userevents.ErrClosed
	}
	if !s.Enabled() {
		if s.closed() {
			return userevents.ErrClosed
		}
		return userevents.ErrDisabled
	}
	if builder == nil {
		return fmt.Errorf("%w: nil builder", ErrInvalidValue)
	}
	prefix, metadata, payload, err := builder.encodeSegments(s.level)
	if err != nil {
		return err
	}
	return s.registration.Writev(prefix, metadata, payload)
}

// Close unregisters this event set. It does not close the underlying File.
func (s *EventSet) Close() error {
	if s == nil || s.registration == nil {
		return userevents.ErrClosed
	}
	err := s.registration.Close()
	if err == nil {
		s.closeDone.Store(true)
	}
	return err
}

// Write emits this builder through set.
func (b *Builder) Write(set *EventSet) error {
	if set == nil {
		return userevents.ErrClosed
	}
	return set.Write(b)
}
