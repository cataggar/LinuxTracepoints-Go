//go:build linux

package userevents

import (
	"encoding/binary"
	"errors"
	"os"
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
		fd:         pipe[1],
		writeIndex: 0x12345678,
		enable:     enable,
		ready:      true,
	}
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
