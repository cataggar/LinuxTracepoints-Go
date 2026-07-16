package eventheader

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cataggar/LinuxTracepoints-Go/userevents"
)

type fakeRegistration struct {
	enabled    atomic.Bool
	closedFlag atomic.Bool
	closeMu    sync.Mutex
	closeErrs  []error
	closeCalls int
	writeMu    sync.Mutex
	writes     [][]byte
}

func (r *fakeRegistration) Enabled() bool {
	return r != nil && !r.closedFlag.Load() && r.enabled.Load()
}

func (r *fakeRegistration) Closed() bool {
	return r == nil || r.closedFlag.Load()
}

func (r *fakeRegistration) Writev(parts ...[]byte) error {
	if r.Closed() {
		return userevents.ErrClosed
	}
	if !r.Enabled() {
		return userevents.ErrDisabled
	}
	size := 0
	for _, part := range parts {
		size += len(part)
	}
	wire := make([]byte, 0, size)
	for _, part := range parts {
		wire = append(wire, part...)
	}
	r.writeMu.Lock()
	r.writes = append(r.writes, wire)
	r.writeMu.Unlock()
	return nil
}

func (r *fakeRegistration) Close() error {
	r.closeMu.Lock()
	defer r.closeMu.Unlock()
	r.closeCalls++
	if len(r.closeErrs) != 0 {
		err := r.closeErrs[0]
		r.closeErrs = r.closeErrs[1:]
		if err != nil {
			return err
		}
	}
	r.closedFlag.Store(true)
	return nil
}

func fakeSet(level Level, keyword uint64, group string, registration *fakeRegistration) *EventSet {
	name, _ := TracepointName("TestProvider", level, keyword, group)
	return &EventSet{registration: registration, name: name, level: level, keyword: keyword}
}

func TestProviderCacheAndIndependentClose(t *testing.T) {
	var createCalls atomic.Int32
	var registrationsMu sync.Mutex
	var registrations []*fakeRegistration
	provider, err := newProvider("TestProvider", false,
		func(level Level, keyword uint64, group string) (*EventSet, error) {
			createCalls.Add(1)
			registration := new(fakeRegistration)
			registrationsMu.Lock()
			registrations = append(registrations, registration)
			registrationsMu.Unlock()
			return fakeSet(level, keyword, group, registration), nil
		}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	const workers = 100
	results := make(chan *EventSet, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			set, setErr := provider.EventSet(LevelInformation, 0x10, "group")
			if setErr != nil {
				t.Errorf("EventSet: %v", setErr)
				return
			}
			results <- set
		}()
	}
	wait.Wait()
	close(results)
	var first *EventSet
	for set := range results {
		if first == nil {
			first = set
		} else if set != first {
			t.Fatal("cache returned non-identical pointers")
		}
	}
	if got := createCalls.Load(); got != 1 {
		t.Fatalf("create calls = %d, want 1", got)
	}

	different, err := provider.EventSet(LevelInformation, 0x10, "other")
	if err != nil {
		t.Fatal(err)
	}
	if different == first {
		t.Fatal("different group reused the same set")
	}
	differentKeyword, err := provider.EventSet(LevelInformation, 0x11, "group")
	if err != nil {
		t.Fatal(err)
	}
	differentLevel, err := provider.EventSet(LevelVerbose, 0x10, "group")
	if err != nil {
		t.Fatal(err)
	}
	if differentKeyword == first || differentLevel == first || differentKeyword == differentLevel {
		t.Fatal("different level or keyword reused the same set")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, err := provider.EventSet(LevelInformation, 0x10, "group")
	if err != nil {
		t.Fatal(err)
	}
	if replacement == first {
		t.Fatal("independently closed set was not replaced")
	}
}

func TestProviderCloseOwnershipRetryAndJoinedErrors(t *testing.T) {
	errOne := errors.New("close one")
	errTwo := errors.New("close two")
	var created atomic.Int32
	var fileCloseCalls atomic.Int32
	provider, err := newProvider("TestProvider", true,
		func(level Level, keyword uint64, group string) (*EventSet, error) {
			registration := &fakeRegistration{}
			if created.Add(1) == 1 {
				registration.closeErrs = []error{errOne}
			} else {
				registration.closeErrs = []error{errTwo}
			}
			return fakeSet(level, keyword, group, registration), nil
		},
		func() error {
			fileCloseCalls.Add(1)
			return nil
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.EventSet(LevelError, 1, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.EventSet(LevelWarning, 2, ""); err != nil {
		t.Fatal(err)
	}
	err = provider.Close()
	if !errors.Is(err, errOne) || !errors.Is(err, errTwo) {
		t.Fatalf("Close error = %v, want both failures", err)
	}
	if fileCloseCalls.Load() != 0 {
		t.Fatal("owned file closed before all sets closed")
	}
	if _, err := provider.EventSet(LevelError, 3, ""); !errors.Is(err, userevents.ErrClosed) {
		t.Fatalf("EventSet while closing = %v, want ErrClosed", err)
	}
	if err := provider.Close(); err != nil {
		t.Fatalf("retry Close: %v", err)
	}
	if got := fileCloseCalls.Load(); got != 1 {
		t.Fatalf("owned file close calls = %d, want 1", got)
	}
	if err := provider.Close(); err != nil {
		t.Fatalf("idempotent Close: %v", err)
	}
	if got := fileCloseCalls.Load(); got != 1 {
		t.Fatalf("owned file close calls after idempotent Close = %d", got)
	}
}

func TestProviderBorrowedFileAndCreationCloseRace(t *testing.T) {
	createEntered := make(chan struct{})
	finishCreate := make(chan struct{})
	var fileCloseCalls atomic.Int32
	provider, err := newProvider("TestProvider", false,
		func(level Level, keyword uint64, group string) (*EventSet, error) {
			close(createEntered)
			<-finishCreate
			return fakeSet(level, keyword, group, new(fakeRegistration)), nil
		},
		func() error {
			fileCloseCalls.Add(1)
			return nil
		}, nil)
	if err != nil {
		t.Fatal(err)
	}

	setResult := make(chan error, 1)
	go func() {
		_, setErr := provider.EventSet(LevelVerbose, 1, "")
		setResult <- setErr
	}()
	<-createEntered
	closeResult := make(chan error, 1)
	go func() { closeResult <- provider.Close() }()
	close(finishCreate)
	if err := <-setResult; err != nil {
		t.Fatalf("creation: %v", err)
	}
	if err := <-closeResult; err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := fileCloseCalls.Load(); got != 0 {
		t.Fatalf("borrowed file close calls = %d, want 0", got)
	}
	if len(provider.sets) != 0 {
		t.Fatal("set remained cached after creation/close race")
	}
}

func TestProviderCreationAndOwnedFileCloseRetry(t *testing.T) {
	createErr := errors.New("register")
	var createCalls atomic.Int32
	var fileCloseCalls atomic.Int32
	fileCloseErr := errors.New("file close")
	provider, err := newProvider("TestProvider", true,
		func(level Level, keyword uint64, group string) (*EventSet, error) {
			if createCalls.Add(1) == 1 {
				return nil, createErr
			}
			return fakeSet(level, keyword, group, new(fakeRegistration)), nil
		},
		func() error {
			if fileCloseCalls.Add(1) == 1 {
				return fileCloseErr
			}
			return nil
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.EventSet(LevelInformation, 1, ""); !errors.Is(err, createErr) {
		t.Fatalf("creation error = %v", err)
	}
	if _, err := provider.EventSet(LevelInformation, 1, ""); err != nil {
		t.Fatalf("creation retry: %v", err)
	}
	if err := provider.Close(); !errors.Is(err, fileCloseErr) {
		t.Fatalf("file close error = %v", err)
	}
	if err := provider.Close(); err != nil {
		t.Fatalf("file close retry: %v", err)
	}
	if err := provider.Close(); err != nil {
		t.Fatalf("idempotent close: %v", err)
	}
	if got := fileCloseCalls.Load(); got != 2 {
		t.Fatalf("file close calls = %d, want 2", got)
	}
}

func TestProviderValidationAndZeroValue(t *testing.T) {
	if _, err := newProvider("bad-name", false, func(Level, uint64, string) (*EventSet, error) {
		return nil, nil
	}, nil, nil); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("invalid name error = %v", err)
	}
	var provider Provider
	if provider.Name() != "" {
		t.Fatal("zero provider has a name")
	}
	if _, err := provider.EventSet(LevelInformation, 0, ""); !errors.Is(err, userevents.ErrClosed) {
		t.Fatalf("zero EventSet error = %v", err)
	}
	if err := (*Provider)(nil).Close(); !errors.Is(err, userevents.ErrClosed) {
		t.Fatalf("nil Close error = %v", err)
	}
}
