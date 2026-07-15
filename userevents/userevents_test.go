package userevents

import (
	"errors"
	"strings"
	"testing"
)

func TestMakeRegistrationCommand(t *testing.T) {
	t.Parallel()

	command, err := makeRegistrationCommand(
		"Provider_L4K1",
		"  u32 value; char name[16]  ",
		RegisterOptions{Flags: RegisterMultiFormat},
	)
	if err != nil {
		t.Fatalf("makeRegistrationCommand returned an error: %v", err)
	}
	if got, want := string(command), "Provider_L4K1 u32 value; char name[16]\x00"; got != want {
		t.Fatalf("command = %q, want %q", got, want)
	}
}

func TestMakeRegistrationCommandRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		event   string
		fields  string
		options RegisterOptions
	}{
		{name: "empty name"},
		{name: "invalid name", event: "provider:event"},
		{name: "non-ASCII name", event: "prøvider"},
		{name: "NUL", event: "provider", fields: "u32 value\x00"},
		{name: "newline", event: "provider", fields: "u32 value\nu32 injected"},
		{name: "invalid UTF-8", event: "provider", fields: string([]byte{0xff})},
		{name: "unknown flags", event: "provider", options: RegisterOptions{Flags: 4}},
		{
			name:   "too long",
			event:  "provider",
			fields: strings.Repeat("x", maxEventDescriptionSize),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := makeRegistrationCommand(test.event, test.fields, test.options)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("error = %v, want ErrInvalidArgument", err)
			}
		})
	}
}

func TestMakeDeleteCommand(t *testing.T) {
	t.Parallel()

	command, err := makeDeleteCommand("provider")
	if err != nil {
		t.Fatalf("makeDeleteCommand returned an error: %v", err)
	}
	if got, want := string(command), "provider\x00"; got != want {
		t.Fatalf("command = %q, want %q", got, want)
	}
}
