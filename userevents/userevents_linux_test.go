//go:build linux

package userevents

import (
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestOpenPathAndClose(t *testing.T) {
	t.Parallel()

	path := createTemporaryFile(t)
	file, err := OpenPath(path)
	if err != nil {
		t.Fatalf("OpenPath returned an error: %v", err)
	}
	if got := file.Path(); got != path {
		t.Fatalf("Path() = %q, want %q", got, path)
	}

	_, err = file.Register("test_event", "u32 value", RegisterOptions{})
	if !errors.Is(err, unix.ENOTTY) {
		t.Fatalf("Register error = %v, want ENOTTY", err)
	}

	if err := file.Close(); err != nil {
		t.Fatalf("Close returned an error: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("second Close returned an error: %v", err)
	}
	if _, err := file.Register("test_event", "", RegisterOptions{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Register after Close error = %v, want ErrClosed", err)
	}
}

func TestWritevFraming(t *testing.T) {
	t.Parallel()

	var pipe [2]int
	if err := unix.Pipe(pipe[:]); err != nil {
		t.Fatalf("Pipe returned an error: %v", err)
	}
	t.Cleanup(func() {
		_ = unix.Close(pipe[0])
		_ = unix.Close(pipe[1])
	})

	enable, err := unix.Mmap(
		-1,
		0,
		4,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANON,
	)
	if err != nil {
		t.Fatalf("Mmap returned an error: %v", err)
	}
	t.Cleanup(func() {
		_ = unix.Munmap(enable)
	})
	atomic.StoreUint32((*uint32)(unsafe.Pointer(unsafe.SliceData(enable))), 1)

	registration := &Registration{
		ops:        &systemRegistrationOperations,
		fd:         pipe[1],
		writeIndex: 0x12345678,
		enable:     enable,
	}
	registration.closeCond.L = &registration.closeMu
	registration.lifecycle.Store(uint64(registrationOpen))
	if err := registration.Writev([]byte{1, 2}, []byte{3, 4}); err != nil {
		t.Fatalf("Writev returned an error: %v", err)
	}

	got := make([]byte, 8)
	if _, err := unix.Read(pipe[0], got); err != nil {
		t.Fatalf("Read returned an error: %v", err)
	}
	want := make([]byte, 8)
	binary.NativeEndian.PutUint32(want, registration.writeIndex)
	copy(want[4:], []byte{1, 2, 3, 4})
	if string(got) != string(want) {
		t.Fatalf("written bytes = %v, want %v", got, want)
	}

	atomic.StoreUint32((*uint32)(unsafe.Pointer(unsafe.SliceData(enable))), 0)
	if err := registration.Write(nil); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled Write error = %v, want ErrDisabled", err)
	}
}

func TestRegistrationAcquireBeforeClose(t *testing.T) {
	file := newTestFile(nil)
	writeEntered := make(chan struct{})
	finishWrite := make(chan struct{})
	closing := make(chan struct{})
	unregisterEntered := make(chan struct{}, 1)
	ops := testRegistrationOperations()
	ops.writev = func(_ int, vectors [][]byte) (int, error) {
		close(writeEntered)
		<-finishWrite
		return vectorSize(vectors), nil
	}
	ops.unregister = func(int, []byte) error {
		unregisterEntered <- struct{}{}
		return nil
	}
	registration := newTestRegistration(file, true, &ops)
	registration.onClosing = func() { close(closing) }

	writeResult := make(chan error, 1)
	go func() {
		writeResult <- registration.Write([]byte{1})
	}()
	<-writeEntered

	closeResult := make(chan error, 1)
	go func() {
		closeResult <- registration.Close()
	}()
	<-closing

	select {
	case <-unregisterEntered:
		t.Fatal("unregister started while a write was active")
	default:
	}

	close(finishWrite)
	if err := <-writeResult; err != nil {
		t.Fatalf("Write returned an error: %v", err)
	}
	<-unregisterEntered
	if err := <-closeResult; err != nil {
		t.Fatalf("Close returned an error: %v", err)
	}
}

func TestRegistrationCloseBeforeAcquire(t *testing.T) {
	file := newTestFile(nil)
	unregisterEntered := make(chan struct{})
	finishUnregister := make(chan struct{})
	var writes atomic.Int32
	ops := testRegistrationOperations()
	ops.writev = func(_ int, vectors [][]byte) (int, error) {
		writes.Add(1)
		return vectorSize(vectors), nil
	}
	ops.unregister = func(int, []byte) error {
		close(unregisterEntered)
		<-finishUnregister
		return nil
	}
	registration := newTestRegistration(file, true, &ops)

	closeResult := make(chan error, 1)
	go func() {
		closeResult <- registration.Close()
	}()
	<-unregisterEntered

	if registration.Enabled() {
		t.Fatal("Enabled returned true after close started")
	}
	if err := registration.Write(nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("Write error = %v, want ErrClosed", err)
	}
	if got := writes.Load(); got != 0 {
		t.Fatalf("writev calls = %d, want 0", got)
	}

	close(finishUnregister)
	if err := <-closeResult; err != nil {
		t.Fatalf("Close returned an error: %v", err)
	}
}

func TestRegistrationConcurrentEnabledWriteClose(t *testing.T) {
	file := newTestFile(nil)
	ops := testRegistrationOperations()
	registration := newTestRegistration(file, true, &ops)

	start := make(chan struct{})
	errs := make(chan error, 8)
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for range 1_000 {
				_ = registration.Enabled()
				err := registration.Write([]byte{1})
				if err != nil && !errors.Is(err, ErrClosed) {
					errs <- err
					return
				}
			}
		}()
	}
	close(start)
	if err := registration.Close(); err != nil {
		t.Fatalf("Close returned an error: %v", err)
	}
	workers.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent Write returned an error: %v", err)
	}
}

func TestRegistrationUnregisterFailureRetry(t *testing.T) {
	file := newTestFile(nil)
	var unregisterCalls atomic.Int32
	var munmapCalls atomic.Int32
	ops := testRegistrationOperations()
	ops.unregister = func(int, []byte) error {
		if unregisterCalls.Add(1) == 1 {
			return unix.EIO
		}
		return nil
	}
	ops.munmap = func([]byte) error {
		munmapCalls.Add(1)
		return nil
	}
	registration := newTestRegistration(file, true, &ops)

	if err := registration.Close(); !errors.Is(err, unix.EIO) {
		t.Fatalf("first Close error = %v, want EIO", err)
	}
	if registration.Closed() {
		t.Fatal("registration remained closed after unregister failure")
	}
	if !registration.Enabled() {
		t.Fatal("registration did not reopen after unregister failure")
	}
	if len(registration.enable) == 0 {
		t.Fatal("enable mapping was released after unregister failure")
	}
	if _, ok := file.regs[registration]; !ok {
		t.Fatal("registration was removed from its file after unregister failure")
	}
	if got := munmapCalls.Load(); got != 0 {
		t.Fatalf("munmap calls after unregister failure = %d, want 0", got)
	}

	if err := registration.Close(); err != nil {
		t.Fatalf("retry Close returned an error: %v", err)
	}
	if !registration.Closed() {
		t.Fatal("registration is open after successful retry")
	}
	if got := unregisterCalls.Load(); got != 2 {
		t.Fatalf("unregister calls = %d, want 2", got)
	}
	if got := munmapCalls.Load(); got != 1 {
		t.Fatalf("munmap calls = %d, want 1", got)
	}
	if _, ok := file.regs[registration]; ok {
		t.Fatal("closed registration remained in its file")
	}
}

func TestRegistrationMunmapFailureRetry(t *testing.T) {
	file := newTestFile(nil)
	var unregisterCalls atomic.Int32
	var munmapCalls atomic.Int32
	ops := testRegistrationOperations()
	ops.unregister = func(int, []byte) error {
		unregisterCalls.Add(1)
		return nil
	}
	ops.munmap = func([]byte) error {
		if munmapCalls.Add(1) == 1 {
			return unix.EIO
		}
		return nil
	}
	registration := newTestRegistration(file, true, &ops)

	if err := registration.Close(); !errors.Is(err, unix.EIO) {
		t.Fatalf("first Close error = %v, want EIO", err)
	}
	if !registration.Closed() {
		t.Fatal("registration accepted operations after unregister succeeded")
	}
	if _, ok := file.regs[registration]; !ok {
		t.Fatal("registration was removed before munmap succeeded")
	}

	if err := registration.Close(); err != nil {
		t.Fatalf("retry Close returned an error: %v", err)
	}
	if got := unregisterCalls.Load(); got != 1 {
		t.Fatalf("unregister calls = %d, want 1", got)
	}
	if got := munmapCalls.Load(); got != 2 {
		t.Fatalf("munmap calls = %d, want 2", got)
	}
}

func TestFileConcurrentCloseWaitsAndClosesFDOnce(t *testing.T) {
	var closeCalls atomic.Int32
	file := newTestFile(func(int) error {
		closeCalls.Add(1)
		return nil
	})
	unregisterEntered := make(chan struct{})
	finishUnregister := make(chan struct{})
	waitEntered := make(chan struct{})
	var waitOnce sync.Once
	file.onCloseWait = func() {
		waitOnce.Do(func() { close(waitEntered) })
	}
	ops := testRegistrationOperations()
	ops.unregister = func(int, []byte) error {
		close(unregisterEntered)
		<-finishUnregister
		return nil
	}
	newTestRegistration(file, false, &ops)

	firstResult := make(chan error, 1)
	go func() {
		firstResult <- file.Close()
	}()
	<-unregisterEntered

	if _, err := file.Register("during_close", "", RegisterOptions{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Register while closing error = %v, want ErrClosed", err)
	}

	secondResult := make(chan error, 1)
	go func() {
		secondResult <- file.Close()
	}()
	<-waitEntered
	close(finishUnregister)

	if err := <-firstResult; err != nil {
		t.Fatalf("first Close returned an error: %v", err)
	}
	if err := <-secondResult; err != nil {
		t.Fatalf("concurrent Close returned an error: %v", err)
	}
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("fd close calls = %d, want 1", got)
	}
}

func TestFileCloseRetriesAfterUnregisterFailure(t *testing.T) {
	var closeCalls atomic.Int32
	file := newTestFile(func(int) error {
		closeCalls.Add(1)
		return nil
	})
	var unregisterCalls atomic.Int32
	ops := testRegistrationOperations()
	ops.unregister = func(int, []byte) error {
		if unregisterCalls.Add(1) == 1 {
			return unix.EIO
		}
		return nil
	}
	newTestRegistration(file, false, &ops)

	if err := file.Close(); !errors.Is(err, unix.EIO) {
		t.Fatalf("first Close error = %v, want EIO", err)
	}
	if file.state != fileOpen {
		t.Fatalf("file state after failure = %d, want open", file.state)
	}
	if got := closeCalls.Load(); got != 0 {
		t.Fatalf("fd close calls after failure = %d, want 0", got)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("retry Close returned an error: %v", err)
	}
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("fd close calls = %d, want 1", got)
	}
}

func TestFileCloseErrorDoesNotRetryFD(t *testing.T) {
	var closeCalls atomic.Int32
	file := newTestFile(func(int) error {
		closeCalls.Add(1)
		return unix.EIO
	})

	if err := file.Close(); !errors.Is(err, unix.EIO) {
		t.Fatalf("first Close error = %v, want EIO", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("second Close returned an error: %v", err)
	}
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("fd close calls = %d, want 1", got)
	}
}

func TestRegistrationEnabledDisabledAllocations(t *testing.T) {
	file := newTestFile(nil)
	ops := testRegistrationOperations()
	registration := newTestRegistration(file, false, &ops)

	if got := testing.AllocsPerRun(1_000, func() {
		_ = registration.Enabled()
	}); got != 0 {
		t.Fatalf("Enabled allocations = %v, want 0", got)
	}
}

func TestZeroFileClose(t *testing.T) {
	t.Parallel()

	var file File
	if err := file.Close(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Close error = %v, want ErrClosed", err)
	}
}

func TestZeroRegistration(t *testing.T) {
	t.Parallel()

	var registration Registration
	if !registration.Closed() {
		t.Fatal("zero Registration is open")
	}
	if registration.Enabled() {
		t.Fatal("zero Registration is enabled")
	}
	if err := registration.Write(nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("Write error = %v, want ErrClosed", err)
	}
	if err := registration.Close(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Close error = %v, want ErrClosed", err)
	}
}

func BenchmarkRegistrationEnabledDisabled(b *testing.B) {
	file := newTestFile(nil)
	ops := testRegistrationOperations()
	registration := newTestRegistration(file, false, &ops)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = registration.Enabled()
	}
}

func BenchmarkRegistrationWriteDisabled(b *testing.B) {
	file := newTestFile(nil)
	ops := testRegistrationOperations()
	registration := newTestRegistration(file, false, &ops)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = registration.Write(nil)
	}
}

func newTestFile(closeFD func(int) error) *File {
	if closeFD == nil {
		closeFD = func(int) error { return nil }
	}
	file := &File{
		closeFD: closeFD,
		fd:      42,
		ready:   true,
		state:   fileOpen,
		regs:    make(map[*Registration]struct{}),
	}
	file.closeCond.L = &file.mu
	return file
}

func newTestRegistration(
	file *File,
	enabled bool,
	ops *registrationOperations,
) *Registration {
	enableWord := new(uint32)
	if enabled {
		atomic.StoreUint32(enableWord, 1)
	}
	registration := &Registration{
		file:   file,
		ops:    ops,
		fd:     file.fd,
		enable: unsafe.Slice((*byte)(unsafe.Pointer(enableWord)), 4),
	}
	registration.closeCond.L = &registration.closeMu
	registration.lifecycle.Store(uint64(registrationOpen))
	file.regs[registration] = struct{}{}
	return registration
}

func testRegistrationOperations() registrationOperations {
	return registrationOperations{
		writev: func(_ int, vectors [][]byte) (int, error) {
			return vectorSize(vectors), nil
		},
		unregister: func(int, []byte) error { return nil },
		munmap:     func([]byte) error { return nil },
	}
}

func vectorSize(vectors [][]byte) int {
	var size int
	for _, vector := range vectors {
		size += len(vector)
	}
	return size
}

func createTemporaryFile(t *testing.T) string {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), "user_events_data")
	if err != nil {
		t.Fatalf("CreateTemp returned an error: %v", err)
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		t.Fatalf("closing temporary file: %v", err)
	}
	return path
}
