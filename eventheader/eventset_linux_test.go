//go:build linux

package eventheader

import (
	"errors"
	"os"
	"testing"

	"github.com/cataggar/LinuxTracepoints-Go/userevents"
	"golang.org/x/sys/unix"
)

func TestEventSetRegistrationOnRegularFile(t *testing.T) {
	data, err := os.CreateTemp(".", ".eventheader-data-*")
	if err != nil {
		t.Fatal(err)
	}
	path := data.Name()
	if err := data.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })

	file, err := userevents.OpenPath(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })

	set, err := NewEventSet(file, "Provider", LevelInformation, 1, "group")
	if set != nil {
		t.Fatal("NewEventSet returned a set after failed ioctl")
	}
	if !errors.Is(err, unix.ENOTTY) {
		t.Fatalf("NewEventSet error = %v, want ENOTTY", err)
	}
	if file.Path() != path {
		t.Fatalf("file path = %q, want %q", file.Path(), path)
	}
}

func TestClosedEventSetWrite(t *testing.T) {
	builder, err := NewBuilder("Event")
	if err != nil {
		t.Fatal(err)
	}
	set := &EventSet{registration: new(userevents.Registration)}
	if err := set.Write(builder); !errors.Is(err, userevents.ErrClosed) {
		t.Fatalf("Write error = %v, want ErrClosed", err)
	}
}
