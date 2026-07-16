package eventheader

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cataggar/LinuxTracepoints-Go/userevents"
)

type providerState uint8

const (
	providerZero providerState = iota
	providerOpen
	providerClosing
	providerClosed
)

type eventSetKey struct {
	level   Level
	keyword uint64
	group   string
}

type eventSetCreator func(Level, uint64, string) (*EventSet, error)

// Provider owns a concurrency-safe cache of EventHeader event sets.
type Provider struct {
	mu        sync.Mutex
	file      *userevents.File
	name      string
	sets      map[eventSetKey]*EventSet
	state     providerState
	ownFile   bool
	createSet eventSetCreator
	closeFile func() error
}

// NewProvider creates a provider that borrows file. Closing the provider does
// not close the file.
func NewProvider(file *userevents.File, name string) (*Provider, error) {
	if file == nil {
		return nil, fmt.Errorf("%w: nil user_events file", ErrInvalidValue)
	}
	return newProvider(name, false,
		func(level Level, keyword uint64, group string) (*EventSet, error) {
			return NewEventSet(file, name, level, keyword, group)
		},
		nil,
		file,
	)
}

// OpenProvider opens user_events_data and creates a provider that owns the
// resulting file.
func OpenProvider(name string) (*Provider, error) {
	if err := validateProviderName(name); err != nil {
		return nil, err
	}
	file, err := userevents.Open()
	if err != nil {
		return nil, err
	}
	provider, err := newProvider(name, true,
		func(level Level, keyword uint64, group string) (*EventSet, error) {
			return NewEventSet(file, name, level, keyword, group)
		},
		file.Close,
		file,
	)
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return provider, nil
}

func newProvider(
	name string,
	ownFile bool,
	create eventSetCreator,
	closeFile func() error,
	file *userevents.File,
) (*Provider, error) {
	if err := validateProviderName(name); err != nil {
		return nil, err
	}
	if create == nil {
		return nil, fmt.Errorf("%w: nil event-set creator", ErrInvalidValue)
	}
	if ownFile && closeFile == nil {
		return nil, fmt.Errorf("%w: owned provider has no file closer", ErrInvalidValue)
	}
	return &Provider{
		file:      file,
		name:      name,
		sets:      make(map[eventSetKey]*EventSet),
		state:     providerOpen,
		ownFile:   ownFile,
		createSet: create,
		closeFile: closeFile,
	}, nil
}

func validateProviderName(name string) error {
	if err := validateProvider(name); err != nil {
		return err
	}
	if len(name) > MaxProviderGroupLength {
		return fmt.Errorf("%w: provider is %d bytes; maximum is %d", ErrInvalidName, len(name), MaxProviderGroupLength)
	}
	return nil
}

// Name returns the provider name.
func (p *Provider) Name() string {
	if p == nil {
		return ""
	}
	return p.name
}

// EventSet returns the cached set for the exact level, keyword, and group.
func (p *Provider) EventSet(level Level, keyword uint64, group string) (*EventSet, error) {
	if p == nil {
		return nil, userevents.ErrClosed
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != providerOpen {
		return nil, userevents.ErrClosed
	}
	if level < LevelCritical || level > LevelVerbose {
		return nil, fmt.Errorf("%w: %d", ErrInvalidLevel, level)
	}
	if err := validateGroup(group); err != nil {
		return nil, err
	}
	if len(p.name)+len(group) > MaxProviderGroupLength {
		return nil, fmt.Errorf("%w: provider and group total %d bytes; maximum is %d", ErrInvalidName, len(p.name)+len(group), MaxProviderGroupLength)
	}

	key := eventSetKey{level: level, keyword: keyword, group: group}
	if set := p.sets[key]; set != nil {
		if !set.closed() {
			return set, nil
		}
		if err := set.Close(); err != nil {
			return nil, err
		}
		delete(p.sets, key)
	}
	set, err := p.createSet(level, keyword, group)
	if err != nil {
		return nil, err
	}
	if set == nil || set.registration == nil {
		if set != nil {
			_ = set.Close()
		}
		return nil, fmt.Errorf("%w: event-set creator returned an unusable set", ErrState)
	}
	p.sets[key] = set
	return set, nil
}

// Close unregisters all cached sets and closes the file only when the provider
// opened it. Failed set closes remain cached so a later Close can retry them.
func (p *Provider) Close() error {
	if p == nil {
		return userevents.ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state == providerZero {
		return userevents.ErrClosed
	}
	if p.state == providerClosed {
		return nil
	}
	p.state = providerClosing

	var closeErrors []error
	for key, set := range p.sets {
		if err := set.Close(); err != nil {
			closeErrors = append(closeErrors, err)
			continue
		}
		delete(p.sets, key)
	}
	if len(closeErrors) != 0 {
		return errors.Join(closeErrors...)
	}
	if p.ownFile {
		if err := p.closeFile(); err != nil {
			return err
		}
	}
	p.state = providerClosed
	return nil
}
