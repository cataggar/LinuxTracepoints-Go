//go:build linux

package userevents

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestKernelRegistration(t *testing.T) {
	if os.Getenv("LINUXTRACEPOINTS_INTEGRATION") != "1" {
		t.Skip("set LINUXTRACEPOINTS_INTEGRATION=1 to test the kernel user_events ABI")
	}

	file, err := Open()
	if err != nil {
		t.Fatalf("Open returned an error: %v", err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Errorf("Close returned an error: %v", err)
		}
	})

	name := fmt.Sprintf("go_test_%d_%d", os.Getpid(), time.Now().UnixNano())
	registration, err := file.Register(name, "u32 value", RegisterOptions{})
	if err != nil {
		t.Fatalf("Register returned an error: %v", err)
	}
	if registration.Name() != name {
		t.Fatalf("Name() = %q, want %q", registration.Name(), name)
	}
	if err := registration.Write([]byte{1, 0, 0, 0}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("Write error = %v, want ErrDisabled", err)
	}
	if err := registration.Close(); err != nil {
		t.Fatalf("Registration.Close returned an error: %v", err)
	}
	if err := registration.Close(); err != nil {
		t.Fatalf("second Registration.Close returned an error: %v", err)
	}
}
