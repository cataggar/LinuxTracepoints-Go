package eventheader

import (
	"errors"
	"strings"
	"testing"
)

func TestTracepointName(t *testing.T) {
	tests := []struct {
		provider string
		level    Level
		keyword  uint64
		group    string
		want     string
	}{
		{"MyProvider", LevelWarning, 0x2a, "", "MyProvider_L3K2a"},
		{"_p2", LevelVerbose, ^uint64(0), "perf9", "_p2_L5KffffffffffffffffGperf9"},
	}
	for _, test := range tests {
		got, err := TracepointName(test.provider, test.level, test.keyword, test.group)
		if err != nil {
			t.Fatal(err)
		}
		if got != test.want {
			t.Fatalf("TracepointName = %q, want %q", got, test.want)
		}
	}
	if _, err := TracepointName(strings.Repeat("p", MaxProviderGroupLength), LevelVerbose, ^uint64(0), ""); err != nil {
		t.Fatalf("maximum provider/group length rejected: %v", err)
	}
}

func TestTracepointNameRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		provider string
		level    Level
		group    string
	}{
		{"", LevelInformation, ""},
		{"2provider", LevelInformation, ""},
		{"provider-name", LevelInformation, ""},
		{"prøvider", LevelInformation, ""},
		{"provider", LevelInvalid, ""},
		{"provider", 6, ""},
		{"provider", LevelInformation, "Upper"},
		{"provider", LevelInformation, "has_underscore"},
		{strings.Repeat("p", MaxProviderGroupLength), LevelInformation, "g"},
	}
	for _, test := range tests {
		if _, err := TracepointName(test.provider, test.level, 0, test.group); err == nil {
			t.Fatalf("TracepointName(%q, %d, %q) succeeded", test.provider, test.level, test.group)
		}
	}
}

func TestMetadataNames(t *testing.T) {
	for _, name := range []string{"", "a;b", "a\x00b", string([]byte{0xff})} {
		if _, err := NewBuilder(name); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("NewBuilder(%q) error = %v", name, err)
		}
	}
	builder, err := NewBuilder("valid_é")
	if err != nil {
		t.Fatal(err)
	}
	if err := builder.Uint8("bad;field", 1); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("field name error = %v", err)
	}
}
