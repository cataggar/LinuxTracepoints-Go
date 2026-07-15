//go:build linux

package userevents

import (
	"reflect"
	"strings"
	"testing"
)

func TestMountDataFileCandidates(t *testing.T) {
	t.Parallel()

	mountInfo := strings.NewReader(
		"20 1 0:20 / /sys/kernel/debug rw,nosuid - debugfs debugfs rw\n" +
			"21 1 0:21 / /custom\\040trace rw,nosuid - tracefs tracefs rw\n",
	)
	got, err := mountDataFileCandidates(mountInfo)
	if err != nil {
		t.Fatalf("mountDataFileCandidates returned an error: %v", err)
	}
	want := []string{
		"/custom trace/user_events_data",
		"/sys/kernel/debug/tracing/user_events_data",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates = %#v, want %#v", got, want)
	}
}

func TestUnescapeMountFieldRejectsInvalidEscape(t *testing.T) {
	t.Parallel()

	if _, err := unescapeMountField(`/bad\09x`); err == nil {
		t.Fatal("unescapeMountField accepted an invalid escape")
	}
}
