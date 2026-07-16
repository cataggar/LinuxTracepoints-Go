package main

import "testing"

func TestCLIExitCodes(t *testing.T) {
	if code := run([]string{"-version"}); code != 0 {
		t.Fatalf("-version exit code = %d", code)
	}
	if code := run([]string{"unexpected"}); code != 2 {
		t.Fatalf("positional argument exit code = %d", code)
	}
	if code := run([]string{"-type=A,A"}); code != 2 {
		t.Fatalf("duplicate type exit code = %d", code)
	}
	if code := run([]string{"-check", "-output=-"}); code != 2 {
		t.Fatalf("-check -output=- exit code = %d", code)
	}
	if code := run(nil); code != 1 {
		t.Fatalf("missing -type exit code = %d", code)
	}
}
