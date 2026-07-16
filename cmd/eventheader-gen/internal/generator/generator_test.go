package generator

import (
	"bytes"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGoldenAndDeterministic(t *testing.T) {
	dir := filepath.Join("testdata", "golden")
	config := Config{Dir: dir, Types: []string{"GoldenEvent"}, Output: "golden.go"}
	first, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("successive generations differ")
	}
	all, err := Generate(Config{Dir: dir, Output: "golden.go"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, all) {
		t.Fatal("generation without -type differs from explicit generation")
	}
	golden, err := os.ReadFile(filepath.Join(dir, "golden.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, golden) {
		t.Fatal("generated output differs from testdata/golden/golden.go")
	}
	for _, want := range []string{
		"clear(w.eventheaderGenScratch1)",
		"if len(w.eventheaderGenScratch1) > len(value.Messages) {",
		"clear(w.eventheaderGenScratch1[len(value.Messages):])",
		"clear(w.eventheaderGenScratch2[len(value.NamedBlobs):])",
		"clear(w.eventheaderGenScratch3[len(value.UTF16Text):])",
	} {
		if !bytes.Contains(first, []byte(want)) {
			t.Errorf("generated scratch resizing is missing %q", want)
		}
	}
}

func TestCheckCurrentAndStale(t *testing.T) {
	dir := filepath.Join("testdata", "golden")
	if err := Write(Config{
		Dir: dir, Types: []string{"GoldenEvent"}, Output: "golden.go", Check: true,
	}); err != nil {
		t.Fatalf("current check: %v", err)
	}
	err := Write(Config{
		Dir: filepath.Join("testdata", "stale"), Output: "eventheader_gen.go", Check: true,
	})
	if err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale check error = %v", err)
	}
	err = Write(Config{
		Dir: filepath.Join("testdata", "missing"), Types: []string{"MissingEvent"},
		Output: "eventheader_gen.go", Check: true,
	})
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing check error = %v", err)
	}
}

func TestOutputSafety(t *testing.T) {
	dir := filepath.Join("testdata", "missing")
	outside, err := filepath.Abs(filepath.Join(dir, "..", "eventheader_gen.go"))
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		output string
	}{
		{"parent traversal", "../eventheader_gen.go"},
		{"subdirectory", "nested/eventheader_gen.go"},
		{"absolute outside package", outside},
		{"non-Go extension", "eventheader_gen.txt"},
		{"dot-prefixed name", ".eventheader_gen.go"},
		{"underscore-prefixed name", "_eventheader_gen.go"},
		{"test file", "eventheader_gen_test.go"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := Config{Dir: dir, Types: []string{"MissingEvent"}, Output: test.output}
			if _, err := Generate(config); err == nil {
				t.Fatalf("Generate accepted unsafe output %q", test.output)
			}

			if err := Write(config); err == nil {
				t.Fatalf("Write accepted unsafe output %q", test.output)
			}
		})
	}

	inputPath := filepath.Join(dir, "input.go")
	before, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	config := Config{Dir: dir, Types: []string{"MissingEvent"}, Output: "input.go"}
	if _, err := Generate(config); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("arbitrary-source Generate error = %v", err)
	}
	if err := Write(config); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("arbitrary-source Write error = %v", err)
	}
	after, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("failed arbitrary-source overwrite changed input.go")
	}

	absolute, err := filepath.Abs(filepath.Join("testdata", "golden", "golden.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(Config{
		Dir: filepath.Join("testdata", "golden"), Types: []string{"GoldenEvent"},
		Output: absolute, Check: true,
	}); err != nil {
		t.Fatalf("valid absolute output: %v", err)
	}

	missing := Config{
		Dir: dir, Types: []string{"MissingEvent"}, Output: "eventheader_gen.go", Check: true,
	}
	if _, err := Generate(missing); err != nil {
		t.Fatalf("valid missing output: %v", err)
	}
	if err := Write(missing); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("valid missing -check error = %v", err)
	}
}

func TestConcurrentOutputGeneration(t *testing.T) {
	dir := newOutputTestPackage(t)
	config := Config{Dir: dir, Types: []string{"RaceEvent"}, Output: "eventheader_gen.go"}

	const writers = 8
	errors := make(chan error, writers)
	var wait sync.WaitGroup
	for range writers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errors <- Write(config)
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Errorf("concurrent Write: %v", err)
		}
	}
	config.Check = true
	if err := Write(config); err != nil {
		t.Fatalf("check concurrent output: %v", err)
	}
	assertNoOutputArtifacts(t, dir)
}

func TestConcurrentDifferentOutputGeneration(t *testing.T) {
	dir := newOutputTestPackage(t)
	output := "eventheader_gen.go"
	initialConfig := Config{
		Dir: dir, Types: []string{"RaceEvent", "OtherRaceEvent"}, Output: output,
	}
	if err := Write(initialConfig); err != nil {
		t.Fatal(err)
	}
	initial, err := validateOutputState(dir, output)
	if err != nil {
		t.Fatal(err)
	}
	first, err := Generate(Config{Dir: dir, Types: []string{"RaceEvent"}, Output: output})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(Config{Dir: dir, Types: []string{"OtherRaceEvent"}, Output: output})
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, desired := range [][]byte{first, second} {
		desired := desired
		go func() {
			<-start
			results <- writeOutput(dir, initial, desired, false)
		}()
	}
	close(start)
	var succeeded, rejected int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			succeeded++
		case strings.Contains(err.Error(), "concurrent modification"):
			rejected++
		default:
			t.Fatalf("concurrent write error = %v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("concurrent results: %d succeeded, %d rejected", succeeded, rejected)
	}
	current, err := os.ReadFile(initial.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current, first) && !bytes.Equal(current, second) {
		t.Fatal("losing invocation overwrote the newer generated output")
	}
	assertNoOutputArtifacts(t, dir)
}

func TestAbandonedOutputLock(t *testing.T) {
	dir := newOutputTestPackage(t)
	output := filepath.Join(dir, "eventheader_gen.go")
	lockPath := filepath.Join(dir, ".eventheader_gen.go.lock")
	if err := os.WriteFile(lockPath, []byte("stale owner metadata"), 0o600); err != nil {
		t.Fatal(err)
	}
	abandoned, err := os.OpenFile(lockPath, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	acquired, err := tryLockFile(abandoned)
	if err != nil || !acquired {
		t.Fatalf("acquire abandoned lock fixture: acquired=%t, err=%v", acquired, err)
	}
	if err := abandoned.Close(); err != nil {
		t.Fatal(err)
	}

	unlock, err := acquireOutputLockTimeout(output, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("acquire after abandoned owner: %v", err)
	}
	unlock()
}

func TestOutputLockContentionTimeout(t *testing.T) {
	dir := newOutputTestPackage(t)
	output := filepath.Join(dir, "eventheader_gen.go")
	unlock, err := acquireOutputLockTimeout(output, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	start := time.Now()
	_, err = acquireOutputLockTimeout(output, 40*time.Millisecond)
	if !errors.Is(err, errOutputLockTimeout) {
		t.Fatalf("contended lock error = %v, want timeout", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("lock timeout took too long: %s", elapsed)
	}
}

func TestAbsentOutputReplacementRace(t *testing.T) {
	dir := newOutputTestPackage(t)
	initial, err := validateOutputState(dir, "eventheader_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	data, err := Generate(Config{Dir: dir, Types: []string{"RaceEvent"}, Output: "eventheader_gen.go"})
	if err != nil {
		t.Fatal(err)
	}
	arbitrary := []byte("package fixture\n\nconst arbitrary = true\n")
	if err := os.WriteFile(initial.path, arbitrary, 0o644); err != nil {
		t.Fatal(err)
	}

	err = writeOutput(dir, initial, data, false)
	if err == nil || !strings.Contains(err.Error(), "concurrent modification") {
		t.Fatalf("replacement error = %v, want concurrent-modification refusal", err)
	}
	got, readErr := os.ReadFile(initial.path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(got, arbitrary) {
		t.Fatal("absent-target race overwrote concurrently created file")
	}
	assertNoOutputArtifacts(t, dir)
}

func TestGeneratedOutputReplacementRace(t *testing.T) {
	dir := newOutputTestPackage(t)
	config := Config{Dir: dir, Types: []string{"RaceEvent"}, Output: "eventheader_gen.go"}
	if err := Write(config); err != nil {
		t.Fatal(err)
	}
	initial, err := validateOutputState(dir, config.Output)
	if err != nil {
		t.Fatal(err)
	}
	arbitrary := []byte("package fixture\n\nconst arbitrary = true\n")
	if err := os.WriteFile(initial.path, arbitrary, 0o644); err != nil {
		t.Fatal(err)
	}

	err = writeOutput(dir, initial, append(initial.data, '\n'), false)
	if err == nil || !strings.Contains(err.Error(), "concurrent modification") {
		t.Fatalf("replacement error = %v, want concurrent-modification refusal", err)
	}
	got, readErr := os.ReadFile(initial.path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(got, arbitrary) {
		t.Fatal("generated-to-arbitrary race overwrote replacement file")
	}
	assertNoOutputArtifacts(t, dir)
}

func TestExistingOutputLastWindowChangeIsRestored(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires renameat2(RENAME_EXCHANGE)")
	}
	dir := newOutputTestPackage(t)
	config := Config{Dir: dir, Types: []string{"RaceEvent"}, Output: "eventheader_gen.go"}
	if err := Write(config); err != nil {
		t.Fatal(err)
	}
	initial, err := validateOutputState(dir, config.Output)
	if err != nil {
		t.Fatal(err)
	}
	changed := append(append([]byte(nil), initial.data...), '\n')
	desired := append(append([]byte(nil), initial.data...), []byte("\n\n")...)
	err = writeOutputWithHooks(dir, initial, desired, false, &replacementHooks{
		beforeCommit: func() {
			if writeErr := os.WriteFile(initial.path, changed, 0o644); writeErr != nil {
				t.Errorf("change output in replacement window: %v", writeErr)
			}
		},
	})
	if err == nil || !strings.Contains(err.Error(), "concurrent modification") {
		t.Fatalf("replacement error = %v, want concurrent-modification refusal", err)
	}
	got, readErr := os.ReadFile(initial.path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(got, changed) {
		t.Fatal("atomic rollback did not restore the last-window replacement")
	}
	assertNoOutputArtifacts(t, dir)
}

func TestExistingOutputRollbackDoesNotClobberNewerPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires renameat2(RENAME_EXCHANGE)")
	}
	dir := newOutputTestPackage(t)
	config := Config{Dir: dir, Types: []string{"RaceEvent"}, Output: "eventheader_gen.go"}
	if err := Write(config); err != nil {
		t.Fatal(err)
	}
	initial, err := validateOutputState(dir, config.Output)
	if err != nil {
		t.Fatal(err)
	}
	changed := append(append([]byte(nil), initial.data...), '\n')
	newer := append(append([]byte(nil), initial.data...), []byte("\n\n")...)
	desired := append(append([]byte(nil), initial.data...), []byte("\n\n\n")...)
	err = writeOutputWithHooks(dir, initial, desired, false, &replacementHooks{
		beforeCommit: func() {
			if writeErr := os.WriteFile(initial.path, changed, 0o644); writeErr != nil {
				t.Errorf("change output in replacement window: %v", writeErr)
			}
		},
		afterCommit: func() {
			replacement := filepath.Join(dir, ".newer-output")
			if writeErr := os.WriteFile(replacement, newer, 0o644); writeErr != nil {
				t.Errorf("write newer output: %v", writeErr)
				return
			}
			if renameErr := os.Rename(replacement, initial.path); renameErr != nil {
				t.Errorf("install newer output: %v", renameErr)
			}
		},
	})
	if err == nil || !strings.Contains(err.Error(), "concurrent modification") {
		t.Fatalf("replacement error = %v, want concurrent-modification refusal", err)
	}
	got, readErr := os.ReadFile(initial.path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(got, newer) {
		t.Fatal("rollback clobbered a newer output path")
	}
	assertNoOutputArtifacts(t, dir)
}

func newOutputTestPackage(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", ".output-race-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove test package: %v", err)
		}
	})
	source := `package fixture

//eventheader:event syntax=1 level=information
type RaceEvent struct {
	Value uint32
}

//eventheader:event syntax=1 level=warning
type OtherRaceEvent struct {
	Message string
}
`
	if err := os.WriteFile(filepath.Join(dir, "input.go"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func assertNoOutputArtifacts(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".eventheader_gen.go.*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, match := range matches {
		if filepath.Ext(match) != ".lock" {
			t.Fatalf("output left temporary artifact: %s", match)
		}
	}
}

func TestMalformedDiagnostics(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"UnknownOption", "unknown event option"},
		{"RepeatedTagOption", "repeated eventheader option"},
		{"PointerField", "pointers are not supported"},
		{"MachineInteger", "explicitly sized integer"},
		{"ImportedStruct", "imported structs are not supported"},
		{"StructArray", "array of structs"},
		{"AmbiguousAddress", "specify encoding=ipv4 or encoding=ipv6"},
		{"BadSyntax", "unsupported event directive syntax"},
		{"Generic", "must not be generic"},
		{"UnquotedName", "quoted Go string"},
		{"AddressCollection", "address collections require fixed byte-array elements"},
		{"UnknownSkipOption", "unknown eventheader option"},
		{"MalformedTag", "invalid struct tag"},
		{"RepeatedTagKey", "repeated eventheader struct-tag key"},
		{"MissingLevel", "requires a level"},
		{"BlankField", "blank field"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Generate(Config{
				Dir: filepath.Join("testdata", "malformed"), Types: []string{test.name},
			})
			var diagnostic *Diagnostic
			if !errors.As(err, &diagnostic) {
				t.Fatalf("error = %v, want positioned diagnostic", err)
			}
			if diagnostic.Position.Line == 0 || diagnostic.Position.Column == 0 {
				t.Fatalf("diagnostic has no source position: %v", diagnostic)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestBuildConstraintsAndCrossBuild(t *testing.T) {
	dir := filepath.Join("testdata", "constraints")
	for _, test := range []struct {
		types  []string
		output string
		tags   string
		want   string
		goos   string
		goarch string
	}{
		{[]string{"LinuxEvent"}, "linux_eventheader.go", "", "//go:build linux\n\n" + GeneratedMarker, "linux", ""},
		{[]string{"CustomEvent"}, "custom_eventheader.go", "custom", "//go:build custom\n\n" + GeneratedMarker, "", ""},
		{[]string{"FilenameLinuxEvent"}, "filename_linux_eventheader.go", "", "//go:build linux\n\n" + GeneratedMarker, "linux", ""},
		{[]string{"FilenameLinuxAMD64Event"}, "filename_linux_amd64_eventheader.go", "", "//go:build amd64 && linux\n\n" + GeneratedMarker, "linux", "amd64"},
		{[]string{"FilenameAMD64Event"}, "filename_amd64_eventheader.go", "", "//go:build amd64\n\n" + GeneratedMarker, "", "amd64"},
		{[]string{"CombinedLinuxAMD64Event"}, "combined_linux_amd64_eventheader.go", "custom", "//go:build amd64 && custom && linux\n\n" + GeneratedMarker, "linux", "amd64"},
	} {
		if (test.goos != "" && runtime.GOOS != test.goos) ||
			(test.goarch != "" && runtime.GOARCH != test.goarch) {
			continue
		}
		data, err := Generate(Config{Dir: dir, Types: test.types, Output: test.output, Tags: test.tags})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(string(data), test.want) {
			t.Fatalf("%s prefix = %q, want %q", test.output, data[:min(len(data), len(test.want))], test.want)
		}
		if err := Write(Config{
			Dir: dir, Types: test.types, Output: test.output, Tags: test.tags, Check: true,
		}); err != nil {
			t.Fatal(err)
		}
	}

	var diagnostic *Diagnostic
	if runtime.GOOS == "linux" {
		_, err := Generate(Config{
			Dir:    filepath.Join("testdata", "constraintmismatch"),
			Types:  []string{"LinuxEvent", "CustomEvent"},
			Output: "combined.go", Tags: "custom",
		})
		if !errors.As(err, &diagnostic) ||
			!strings.Contains(err.Error(), "separate outputs") {
			t.Fatalf("mixed constraint error = %v, want positioned separate-output diagnostic", err)
		}

		if _, err := Generate(Config{
			Dir:   filepath.Join("testdata", "constraintmismatch"),
			Types: []string{"LinuxEvent", "FilenameLinuxEvent"},
		}); err != nil {
			t.Fatalf("equivalent explicit and filename constraints: %v", err)
		}
	}
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		_, err := Generate(Config{
			Dir:   filepath.Join("testdata", "constraintmismatch"),
			Types: []string{"FilenameLinuxEvent", "FilenameLinuxAMD64Event"},
		})
		if !errors.As(err, &diagnostic) || !strings.Contains(err.Error(), "separate outputs") {
			t.Fatalf("filename constraint mismatch error = %v, want positioned diagnostic", err)
		}
	}

	for _, target := range []struct {
		goos, goarch string
	}{
		{"windows", "amd64"},
		{"linux", "amd64"},
		{"linux", "arm64"},
	} {
		command := exec.Command("go", "test", "-exec=true", "-tags=custom", "./testdata/constraints")
		command.Env = append(os.Environ(), "GOOS="+target.goos, "GOARCH="+target.goarch, "CGO_ENABLED=0")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("%s/%s custom-tag compile: %v\n%s", target.goos, target.goarch, err, output)
		}
	}
}

func TestDependencyBuildConstraints(t *testing.T) {
	dir := filepath.Join("testdata", "constraintdeps")
	for _, goarch := range []string{"amd64", "386"} {
		t.Run(goarch, func(t *testing.T) {
			t.Setenv("GOARCH", goarch)
			for _, event := range []string{
				"ArchConstantEvent", "ArchAliasEvent", "ArchNestedEvent", "TypedArchConstantEvent",
			} {
				_, err := Generate(Config{Dir: dir, Types: []string{event}})
				var diagnostic *Diagnostic
				if !errors.As(err, &diagnostic) {
					t.Fatalf("%s error = %v, want positioned diagnostic", event, err)
				}
				if filepath.Base(diagnostic.Position.Filename) != "base.go" ||
					!strings.Contains(err.Error(), "does not match event constraint") {
					t.Fatalf("%s error = %v, want dependency constraint mismatch in base.go", event, err)
				}
			}
			if _, err := Generate(Config{
				Dir: dir, Types: []string{"PortableDependencyEvent"},
			}); err != nil {
				t.Fatalf("portable dependencies: %v", err)
			}
		})
	}
	if runtime.GOOS == "linux" {
		for _, event := range []string{"SameConstraintEvent", "UnconstrainedDependencyEvent"} {
			if _, err := Generate(Config{Dir: dir, Types: []string{event}}); err != nil {
				t.Fatalf("%s: %v", event, err)
			}
		}
	}
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		_, err := Generate(Config{Dir: dir, Types: []string{"DifferentConstraintEvent"}})
		var diagnostic *Diagnostic
		if !errors.As(err, &diagnostic) ||
			!strings.Contains(err.Error(), "does not match event constraint") {
			t.Fatalf("different constrained dependency error = %v, want positioned mismatch", err)
		}
	}
}

func TestOutputFilenameBuildConstraints(t *testing.T) {
	dir := filepath.Join("testdata", "constraintmismatch")
	for _, test := range []struct {
		name, event, output, want string
	}{
		{"unconstrained narrowed", "UnconstrainedEvent", "result_linux.go", "not implied"},
		{"conflicting OS", "LinuxEvent", "result_windows.go", "not implied"},
		{"narrower architecture", "LinuxEvent", "result_linux_amd64.go", "not implied"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Generate(Config{Dir: dir, Types: []string{test.event}, Output: test.output})
			var diagnostic *Diagnostic
			if !errors.As(err, &diagnostic) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want positioned %q diagnostic", err, test.want)
			}
			err = Write(Config{
				Dir: dir, Types: []string{test.event}, Output: test.output, Check: true,
			})
			if !errors.As(err, &diagnostic) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("-check error = %v, want constraint diagnostic before stale check", err)
			}
		})
	}
	if runtime.GOOS == "linux" {
		if _, err := Generate(Config{
			Dir: dir, Types: []string{"LinuxEvent"}, Output: "result_linux.go",
		}); err != nil {
			t.Fatalf("implied Linux output constraint: %v", err)
		}
	}
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		if _, err := Generate(Config{
			Dir:   filepath.Join("testdata", "constraintmismatch"),
			Types: []string{"CombinedLinuxAMD64Event"}, Tags: "custom",
			Output: "result_linux.go",
		}); err != nil {
			t.Fatalf("combined explicit/filename event constraint: %v", err)
		}
	}
}

func TestFilenameBuildConstraints(t *testing.T) {
	knownOS := map[string]bool{"linux": true, "windows": true}
	knownArch := map[string]bool{"amd64": true, "arm64": true}
	for _, test := range []struct {
		name string
		want string
	}{
		{"event_linux.go", "linux"},
		{"event_linux_amd64.go", "amd64 && linux"},
		{"event_windows.go", "windows"},
		{"event_amd64.go", "amd64"},
		{"event_unrecognized.go", ""},
	} {
		expressions := filenameBuildConstraints(test.name, knownOS, knownArch)
		parts := make([]string, len(expressions))
		for i, expression := range expressions {
			parts[i] = expression.String()
		}
		sort.Strings(parts)
		if got := strings.Join(parts, " && "); got != test.want {
			t.Errorf("%s constraint = %q, want %q", test.name, got, test.want)
		}
	}
}

func TestCanonicalBuildConstraints(t *testing.T) {
	knownOS := map[string]bool{"linux": true, "windows": true}
	knownArch := map[string]bool{"amd64": true, "arm64": true}
	for _, test := range []struct {
		name     string
		filename string
		prefix   string
		want     string
	}{
		{"none", "event.go", "", ""},
		{"filename OS", "event_linux.go", "", "linux"},
		{"filename OS and architecture", "event_linux_amd64.go", "", "amd64 && linux"},
		{"explicit and filename", "event_linux_amd64.go", "//go:build custom\n\n", "amd64 && custom && linux"},
		{"legacy and filename", "event_arm64.go", "// +build custom\n\n", "arm64 && custom"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, test.filename, test.prefix+"package fixture\n", parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			got, err := canonicalBuildConstraint(file, test.filename, knownOS, knownArch)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("constraint = %q, want %q", got, test.want)
			}
		})
	}
}

func TestBuildConstraintOverlap(t *testing.T) {
	knownOS := map[string]bool{"linux": true, "windows": true}
	knownArch := map[string]bool{"386": true, "amd64": true, "arm64": true}
	targets := []buildTarget{
		{goos: "linux", goarch: "386"},
		{goos: "linux", goarch: "amd64"},
		{goos: "linux", goarch: "arm64"},
		{goos: "windows", goarch: "amd64"},
		{goos: "windows", goarch: "arm64"},
	}

	for _, test := range []struct {
		name, left, right string
		want              bool
	}{
		{"different operating systems", "linux", "windows", false},
		{"operating system union", "linux || windows", "windows", true},
		{"different architectures", "linux && amd64", "linux && arm64", false},
		{"feature excludes other architecture", "amd64.v2", "arm64", false},
		{"feature hierarchy overlaps", "amd64.v3", "amd64.v2", true},
		{"exclusive features", "386.387", "386.sse2", false},
		{"custom overlap", "linux && current", "linux && alternate", true},
		{"custom disjoint", "linux && current", "linux && !current", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := constraintsOverlap(test.left, test.right, targets, knownOS, knownArch); got != test.want {
				t.Fatalf("constraintsOverlap(%q, %q) = %t, want %t",
					test.left, test.right, got, test.want)
			}
		})
	}

	var manyTags []string
	for i := range 13 {
		manyTags = append(manyTags, fmt.Sprintf("tag%d", i))
	}
	left := strings.Join(manyTags, " && ")
	if !constraintsOverlap(left, "!tag0", targets, knownOS, knownArch) {
		t.Fatal("an expression beyond the custom-tag bound must conservatively overlap")
	}
}

func TestArchitectureFeatureBuildConstraints(t *testing.T) {
	knownOS := map[string]bool{"linux": true}
	knownArch := map[string]bool{
		"386": true, "amd64": true, "arm": true, "arm64": true,
		"mips": true, "ppc64": true, "riscv64": true, "wasm": true,
	}
	var targets []buildTarget
	for arch := range knownArch {
		targets = append(targets, buildTarget{goos: "linux", goarch: arch})
	}
	for _, test := range []struct {
		name, left, right string
		want              bool
	}{
		{"feature implies architecture", "amd64.v2", "amd64", true},
		{"feature excludes another architecture", "amd64.v2", "!arm64", true},
		{"amd64 hierarchy", "amd64.v4", "amd64.v2", true},
		{"amd64 hierarchy not reversed", "amd64.v2", "amd64.v3", false},
		{"arm hierarchy", "arm.7", "arm.5", true},
		{"arm64 hierarchy", "arm64.v9.5", "arm64.v8.9", true},
		{"ppc64 hierarchy", "ppc64.power10", "ppc64.power8", true},
		{"riscv64 hierarchy", "riscv64.rva23u64", "riscv64.rva22u64", true},
		{"386 feature implies architecture", "386.sse2", "386", true},
		{"unknown feature implies architecture", "amd64.future", "amd64", true},
		{"invalid feature and architecture", "amd64.v2 && !amd64", "custom", true},
		{"invalid exclusive features", "mips.hardfloat && mips.softfloat", "custom", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := constraintImplies(test.left, test.right, targets, knownOS, knownArch); got != test.want {
				t.Fatalf("constraintImplies(%q, %q) = %t, want %t",
					test.left, test.right, got, test.want)
			}
		})
	}
}

func TestWASMFeatureProfiles(t *testing.T) {
	knownOS := map[string]bool{"linux": true}
	knownArch := map[string]bool{"wasm": true}
	targets := []buildTarget{{goos: "linux", goarch: "wasm"}}
	profiles := []string{
		"wasm && !wasm.satconv && !wasm.signext",
		"wasm && wasm.satconv && !wasm.signext",
		"wasm && !wasm.satconv && wasm.signext",
		"wasm && wasm.satconv && wasm.signext",
	}
	for i, left := range profiles {
		for j, right := range profiles {
			want := i == j
			if got := constraintsOverlap(left, right, targets, knownOS, knownArch); got != want {
				t.Errorf("profile %d overlaps profile %d = %t, want %t", i, j, got, want)
			}
			if got := constraintImplies(left, right, targets, knownOS, knownArch); got != want {
				t.Errorf("profile %d implies profile %d = %t, want %t", i, j, got, want)
			}
		}
		if !constraintImplies(left, "wasm", targets, knownOS, knownArch) {
			t.Errorf("profile %d does not imply wasm", i)
		}
	}
	if constraintImplies("wasm.satconv", "wasm.signext", targets, knownOS, knownArch) {
		t.Error("wasm.satconv incorrectly implies wasm.signext")
	}
	if constraintImplies("wasm.signext", "wasm.satconv", targets, knownOS, knownArch) {
		t.Error("wasm.signext incorrectly implies wasm.satconv")
	}
}

func TestArchitectureFeatureOutputSuffix(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("requires an amd64 host toolchain")
	}
	dir, err := os.MkdirTemp(".", ".feature-output-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove feature package: %v", err)
		}
	})
	source := `//go:build amd64.v2

package fixture

//eventheader:event syntax=1 level=information
type FeatureEvent struct {
	Value uint32
}
`
	if err := os.WriteFile(filepath.Join(dir, "input.go"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOAMD64", "v2")
	data, err := Generate(Config{
		Dir: dir, Types: []string{"FeatureEvent"}, Output: "result_amd64.go",
	})
	if err != nil {
		t.Fatalf("feature-constrained amd64 output: %v", err)
	}
	if !bytes.HasPrefix(data, []byte("//go:build amd64.v2\n\n"+GeneratedMarker)) {
		t.Fatalf("generated feature constraint prefix = %q", data[:min(len(data), 80)])
	}
	_, err = Generate(Config{
		Dir: dir, Types: []string{"FeatureEvent"}, Output: "result_arm64.go",
	})
	if err == nil || !strings.Contains(err.Error(), "not implied") {
		t.Fatalf("cross-architecture output error = %v, want not implied", err)
	}
}

func TestBuildConstraintImplicationUsesValidTargets(t *testing.T) {
	knownOS := map[string]bool{
		"android": true, "darwin": true, "illumos": true, "ios": true,
		"linux": true, "solaris": true, "windows": true,
	}
	knownArch := map[string]bool{"amd64": true, "arm64": true}
	targets := []buildTarget{
		{goos: "android", goarch: "arm64"},
		{goos: "darwin", goarch: "amd64"},
		{goos: "illumos", goarch: "amd64"},
		{goos: "ios", goarch: "arm64"},
		{goos: "linux", goarch: "amd64"},
		{goos: "windows", goarch: "amd64"},
	}

	for _, test := range []struct {
		name, left, right string
		want              bool
	}{
		{"android implies linux", "android", "linux", true},
		{"android implies unix", "android", "unix", true},
		{"ios implies darwin", "ios", "darwin", true},
		{"illumos implies solaris", "illumos", "solaris", true},
		{"linux does not imply android", "linux", "android", false},
		{"cross OS antecedent is invalid", "linux && windows", "custom", true},
		{"cross architecture antecedent is invalid", "amd64 && arm64", "custom", true},
		{"valid target rejects other architecture", "linux && amd64", "arm64", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := constraintImplies(test.left, test.right, targets, knownOS, knownArch)
			if got != test.want {
				t.Fatalf("constraintImplies(%q, %q) = %t, want %t",
					test.left, test.right, got, test.want)
			}
		})
	}

	for _, test := range []struct {
		name, left, right string
	}{
		{"android linux", "android", "android && linux"},
		{"ios darwin", "ios", "ios && darwin"},
		{"illumos solaris", "illumos", "illumos && solaris"},
		{"android unix", "android", "android && unix"},
		{"invalid assignments", "linux && windows", "amd64 && arm64"},
	} {
		t.Run("equivalent "+test.name, func(t *testing.T) {
			if !constraintsEquivalent(test.left, test.right, targets, knownOS, knownArch) {
				t.Fatalf("constraintsEquivalent(%q, %q) = false", test.left, test.right)
			}
		})
	}
}

func TestEventheaderGeneratedHeader(t *testing.T) {
	for _, test := range []struct {
		name, header string
		want         bool
	}{
		{"exact", GeneratedMarker + "\n" + generatedSyntax + "\n\n", true},
		{"build constraint", "//go:build linux\n\n" + GeneratedMarker + "\n" + generatedSyntax + "\n\n", true},
		{"other generator", "// Code generated by another tool; DO NOT EDIT.\n" + generatedSyntax + "\n\n", false},
		{"missing syntax", GeneratedMarker + "\n\n", false},
		{"additional header line", GeneratedMarker + "\n" + generatedSyntax + "\n// extra\n\n", false},
		{"preceding license", "// license\n\n" + GeneratedMarker + "\n" + generatedSyntax + "\n\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go",
				test.header+"package fixture\n", parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			if got := isEventheaderGenerated(file); got != test.want {
				t.Fatalf("isEventheaderGenerated() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestRejectsArchitectureDependentArrayLengths(t *testing.T) {
	for _, event := range []string{
		"DirectSizeofEvent",
		"DerivedSizeofEvent",
		"DirectAlignofEvent",
		"DerivedOffsetofEvent",
		"MachineTypedConstantEvent",
		"UnprovenBuiltinEvent",
	} {
		t.Run(event, func(t *testing.T) {
			_, err := Generate(Config{
				Dir:   filepath.Join("testdata", "archsizes"),
				Types: []string{event},
			})
			var diagnostic *Diagnostic
			if !errors.As(err, &diagnostic) {
				t.Fatalf("error = %v, want positioned diagnostic", err)
			}
			if filepath.Base(diagnostic.Position.Filename) != "input.go" ||
				diagnostic.Position.Line == 0 || diagnostic.Position.Column == 0 {
				t.Fatalf("diagnostic has no source position: %v", diagnostic)
			}
			for _, want := range []string{
				"not provably architecture-independent",
				"explicit fixed count",
				"separate architecture-constrained source/output",
			} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error = %v, want substring %q", err, want)
				}
			}
		})
	}
}

func TestPortableArrayLengthsGenerateIdentically(t *testing.T) {
	config := Config{
		Dir:   filepath.Join("testdata", "archsizes"),
		Types: []string{"PortableArrayEvent"},
	}
	t.Setenv("GOARCH", "amd64")
	amd64, err := Generate(config)
	if err != nil {
		t.Fatalf("amd64: %v", err)
	}
	t.Setenv("GOARCH", "386")
	x86, err := Generate(config)
	if err != nil {
		t.Fatalf("386: %v", err)
	}
	if !bytes.Equal(amd64, x86) {
		t.Fatalf("generated output differs between amd64 and 386")
	}
	for _, want := range []string{"ArrayFixed, 3", "ArrayFixed, 4", "UintptrField"} {
		if !bytes.Contains(amd64, []byte(want)) {
			t.Fatalf("generated output does not contain %q:\n%s", want, amd64)
		}
	}
}

func TestGeneratedDependency(t *testing.T) {
	config := Config{
		Dir:   filepath.Join("testdata", "generateddep"),
		Types: []string{"GeneratedDependencyEvent"}, Output: "eventheader_gen.go", Check: true,
	}
	if _, err := Generate(config); err != nil {
		t.Fatalf("generate: %v", err)
	}
	config.Check = false
	if err := Write(config); err != nil {
		t.Fatalf("write: %v", err)
	}
	config.Check = true
	if err := Write(config); err != nil {
		t.Fatal(err)
	}
}

func TestStdoutWithExistingGeneratedOutput(t *testing.T) {
	dir := filepath.Join("testdata", "generateddep")
	fileConfig := Config{
		Dir: dir, Types: []string{"GeneratedDependencyEvent"}, Output: "eventheader_gen.go",
	}
	fileOutput, err := Generate(fileConfig)
	if err != nil {
		t.Fatalf("file generation: %v", err)
	}
	stdoutOutput, err := Generate(Config{
		Dir: dir, Types: []string{"GeneratedDependencyEvent"}, Output: "-",
	})
	if err != nil {
		t.Fatalf("stdout generation with existing generated API references: %v", err)
	}
	if !bytes.Equal(stdoutOutput, fileOutput) {
		t.Fatal("stdout generation differs from file generation")
	}
	current, err := os.ReadFile(filepath.Join(dir, "eventheader_gen.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stdoutOutput, current) {
		t.Fatal("stdout generation is not check-equivalent to existing output")
	}
	command := exec.Command("go", "run", "../../../../",
		"-type=GeneratedDependencyEvent", "-output=-")
	command.Dir = dir
	cliOutput, err := command.Output()
	if err != nil {
		t.Fatalf("stdout CLI generation: %v", err)
	}
	if !bytes.Equal(cliOutput, current) {
		t.Fatal("stdout CLI generation differs from existing output")
	}
	command = exec.Command("go", "run", "../../../../",
		"-type=GeneratedDependencyEvent", "-output=eventheader_gen.go", "-check")
	command.Dir = dir
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("equivalent file check: %v\n%s", err, output)
	}
}

func TestRegenerateWithMissingGeneratedAPIs(t *testing.T) {
	dir := filepath.Join("testdata", "generateddep")
	outputPath := filepath.Join(dir, "eventheader_gen.go")
	original, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.WriteFile(outputPath, original, 0o644); err != nil {
			t.Errorf("restore generated output: %v", err)
		}
	}()
	if err := os.Remove(outputPath); err != nil {
		t.Fatal(err)
	}

	config := Config{Dir: dir, Output: "eventheader_gen.go"}
	if _, err := Generate(config); err != nil {
		t.Fatalf("generate without output: %v", err)
	}
	if err := Write(config); err != nil {
		t.Fatalf("regenerate without output: %v", err)
	}
	config.Check = true
	if err := Write(config); err != nil {
		t.Fatalf("check regenerated output: %v", err)
	}
	command := exec.Command("go", "test", "-exec=true", "./testdata/generateddep")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile regenerated package: %v\n%s", err, output)
	}
}

func TestReplacementUsesOnlySelectedSyntheticAPIs(t *testing.T) {
	dir := filepath.Join("testdata", "generatedselection")
	outputPath := filepath.Join(dir, "eventheader_gen.go")
	original, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}

	selected := Config{Dir: dir, Types: []string{"SelectedA"}, Output: "eventheader_gen.go"}
	if _, err := Generate(selected); err != nil {
		t.Fatalf("selected API references with stale A+B output: %v", err)
	}

	withOmittedReference := selected
	withOmittedReference.Tags = "omittedref"
	if _, err := Generate(withOmittedReference); err == nil ||
		!strings.Contains(err.Error(), "OmittedBWriter") {
		t.Fatalf("omitted API reference error = %v, want OmittedBWriter", err)
	}
	if err := Write(withOmittedReference); err == nil ||
		!strings.Contains(err.Error(), "OmittedBWriter") {
		t.Fatalf("write omitted API reference error = %v, want OmittedBWriter", err)
	}
	unchanged, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unchanged, original) {
		t.Fatal("failed replacement modified existing output")
	}

	if _, err := Generate(Config{
		Dir: dir, Types: []string{"SelectedA"}, Output: "-", Tags: "omittedref",
	}); err != nil {
		t.Fatalf("stdout should retain existing generated declarations: %v", err)
	}

	if err := os.Remove(outputPath); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.WriteFile(outputPath, original, 0o644); err != nil {
			t.Errorf("restore generated output: %v", err)
		}
	}()
	if _, err := Generate(selected); err != nil {
		t.Fatalf("selected API references with missing output: %v", err)
	}
}

func TestStaleGeneratedAPIDependency(t *testing.T) {
	dir := filepath.Join("testdata", "stale")
	outputPath := filepath.Join(dir, "eventheader_gen.go")
	original, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.WriteFile(outputPath, original, 0o644); err != nil {
			t.Errorf("restore stale output: %v", err)
		}
	}()

	config := Config{Dir: dir, Output: "eventheader_gen.go"}
	if _, err := Generate(config); err != nil {
		t.Fatalf("generate with stale renamed output: %v", err)
	}
	if err := Write(config); err != nil {
		t.Fatalf("replace stale renamed output: %v", err)
	}
	config.Check = true
	if err := Write(config); err != nil {
		t.Fatalf("check replaced renamed output: %v", err)
	}
	command := exec.Command("go", "test", "-exec=true", "./testdata/stale")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile replaced renamed output: %v\n%s", err, output)
	}
}

func TestIgnoredSourceCollisions(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fixtures select events from Linux")
	}
	dir := filepath.Join("testdata", "ignoredcollisions")
	for _, test := range []struct {
		name, event, identifier string
	}{
		{"Windows top-level overlap", "CrossPlatformEvent", "CrossPlatformEventSchema"},
		{"Windows method overlap", "CrossPlatformMethodEvent", "Enabled"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Generate(Config{Dir: dir, Types: []string{test.event}})
			var diagnostic *Diagnostic
			if !errors.As(err, &diagnostic) ||
				filepath.Base(diagnostic.Position.Filename) != "collisions_windows.go" ||
				!strings.Contains(err.Error(), test.identifier) {
				t.Fatalf("error = %v, want positioned %s collision", err, test.identifier)
			}
		})
	}
	for _, event := range []string{"LinuxOnlyEvent", "LinuxMethodEvent"} {
		if _, err := Generate(Config{Dir: dir, Types: []string{event}}); err != nil {
			t.Fatalf("provably disjoint Windows collision for %s: %v", event, err)
		}
	}

	_, err := Generate(Config{
		Dir: dir, Types: []string{"CustomOverlapEvent"}, Tags: "current",
	})
	var diagnostic *Diagnostic
	if !errors.As(err, &diagnostic) ||
		filepath.Base(diagnostic.Position.Filename) != "collision_alternate_linux.go" {
		t.Fatalf("custom-tag overlap error = %v, want alternate collision", err)
	}
	if _, err := Generate(Config{
		Dir: dir, Types: []string{"CustomDisjointEvent"}, Tags: "current",
	}); err != nil {
		t.Fatalf("provably disjoint custom-tag collision: %v", err)
	}

	t.Setenv("CGO_ENABLED", "0")
	_, err = Generate(Config{Dir: dir, Types: []string{"CgoOverlapEvent"}})
	if !errors.As(err, &diagnostic) ||
		filepath.Base(diagnostic.Position.Filename) != "collision_cgo_linux.go" {
		t.Fatalf("implicit cgo overlap error = %v, want cgo collision", err)
	}
}

func TestGeneratedIdentifierCollisions(t *testing.T) {
	dir := filepath.Join("testdata", "collisions")
	_, err := Generate(Config{Dir: dir, Types: []string{"Foo", "NewFoo"}})
	var diagnostic *Diagnostic
	if !errors.As(err, &diagnostic) {
		t.Fatalf("collision error = %v, want positioned diagnostic", err)
	}
	if filepath.Base(diagnostic.Position.Filename) != "input.go" {
		t.Fatalf("collision position = %v, want input.go", diagnostic.Position)
	}
	for _, want := range []string{"NewFooWriter", "Foo", "NewFoo"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("collision error = %v, want %q", err, want)
		}
	}

	data, err := Generate(Config{Dir: dir, Types: []string{"FirstEvent", "SecondEvent"}})
	if err != nil {
		t.Fatalf("non-colliding events: %v", err)
	}
	for _, want := range []string{"FirstEventSchema", "SecondEventSchema"} {
		if !bytes.Contains(data, []byte(want)) {
			t.Fatalf("non-colliding output does not contain %s", want)
		}
	}
}

func TestGeneratedMethodCollisions(t *testing.T) {
	for _, test := range []struct {
		dir, output, method string
	}{
		{"methodcollisionmissing", "eventheader_gen.go", "Enabled"},
		{"methodcollisionstale", "eventheader_gen.go", "bind"},
	} {
		_, err := Generate(Config{
			Dir:   filepath.Join("testdata", test.dir),
			Types: []string{"CollisionEvent"}, Output: test.output,
		})
		var diagnostic *Diagnostic
		if !errors.As(err, &diagnostic) ||
			filepath.Base(diagnostic.Position.Filename) != "input.go" ||
			!strings.Contains(err.Error(), test.method) ||
			!strings.Contains(err.Error(), "generated method") {
			t.Fatalf("%s error = %v, want positioned %s collision", test.dir, err, test.method)
		}
	}

	data, err := Generate(Config{
		Dir:   filepath.Join("testdata", "methodextension"),
		Types: []string{"ExtensionEvent"}, Output: "eventheader_gen.go",
	})
	if err != nil {
		t.Fatalf("noncolliding extension method with missing output: %v", err)
	}
	if !bytes.Contains(data, []byte("func (w *ExtensionEventWriter) Enabled() bool")) {
		t.Fatal("generated output is missing generated writer methods")
	}
}

func TestActiveTestFileCollisions(t *testing.T) {
	dir := filepath.Join("testdata", "testcollisions")
	for _, test := range []struct {
		event, identifier string
	}{
		{"TopLevelTestEvent", "TopLevelTestEventSchema"},
		{"MethodTestEvent", "Write"},
	} {
		t.Run(test.event, func(t *testing.T) {
			_, err := Generate(Config{Dir: dir, Types: []string{test.event}})
			var diagnostic *Diagnostic
			if !errors.As(err, &diagnostic) ||
				filepath.Base(diagnostic.Position.Filename) != "collisions_linux_test.go" ||
				!strings.Contains(err.Error(), test.identifier) {
				t.Fatalf("error = %v, want positioned %s test collision", err, test.identifier)
			}
		})
	}

	if _, err := Generate(Config{Dir: dir, Types: []string{"NoncollidingTestEvent"}}); err != nil {
		t.Fatalf("noncolliding same-package test helpers: %v", err)
	}
	if _, err := Generate(Config{Dir: dir, Types: []string{"ExternalTestEvent"}}); err != nil {
		t.Fatalf("external-package test declaration must be ignored: %v", err)
	}
}

func TestRejectsPredeclaredIdentifierShadows(t *testing.T) {
	for _, name := range []string{"byte", "error", "len", "make", "clear"} {
		t.Run(name, func(t *testing.T) {
			_, err := Generate(Config{
				Dir: filepath.Join("testdata", "predeclared", name), Types: []string{"Event"},
			})
			var diagnostic *Diagnostic
			if !errors.As(err, &diagnostic) ||
				filepath.Base(diagnostic.Position.Filename) != "input.go" ||
				!strings.Contains(err.Error(), "package declaration "+name) ||
				!strings.Contains(err.Error(), "generated code cannot safely reference the predeclared identifier") {
				t.Fatalf("error = %v, want positioned %s predeclared-shadow diagnostic", err, name)
			}
		})
	}

	if _, err := Generate(Config{
		Dir: filepath.Join("testdata", "predeclared", "safe"), Types: []string{"Event"},
	}); err != nil {
		t.Fatalf("harmless non-predeclared package declaration: %v", err)
	}

	for _, test := range []struct {
		name, dir, file, identifier string
	}{
		{"active same-package test", "active", "active_shadow_test.go", "byte"},
		{"inactive overlapping same-package test", "inactive", "inactive_shadow_test.go", "error"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Generate(Config{
				Dir:   filepath.Join("testdata", "predeclaredtests", test.dir),
				Types: []string{"Event"},
			})
			var diagnostic *Diagnostic
			if !errors.As(err, &diagnostic) ||
				filepath.Base(diagnostic.Position.Filename) != test.file ||
				!strings.Contains(err.Error(), "package declaration "+test.identifier) {
				t.Fatalf("error = %v, want positioned %s test shadow", err, test.identifier)
			}
		})
	}

	if _, err := Generate(Config{
		Dir: filepath.Join("testdata", "predeclaredtests", "disjoint"), Types: []string{"Event"},
	}); err != nil {
		t.Fatalf("disjoint and external test shadows: %v", err)
	}
}

func TestRejectsUnverifiedImportedNamedPrimitives(t *testing.T) {
	for _, fixture := range []struct {
		dir, event string
	}{
		{"qualifier", "QualifiedEvent"},
		{"importedbytes", "ImportedByteEvent"},
	} {
		_, err := Generate(Config{
			Dir: filepath.Join("testdata", fixture.dir), Types: []string{fixture.event},
		})
		var diagnostic *Diagnostic
		if !errors.As(err, &diagnostic) ||
			!strings.Contains(err.Error(), "target parity is not established") {
			t.Fatalf("%s error = %v, want positioned target-parity diagnostic", fixture.dir, err)
		}
	}
}

func TestCgoEventBuildConstraint(t *testing.T) {
	output, err := exec.Command("go", "env", "CGO_ENABLED").Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(output)) != "1" {
		t.Skip("cgo is disabled")
	}
	dir := filepath.Join("testdata", "cgofixture")
	data, err := Generate(Config{
		Dir: dir, Types: []string{"CgoEvent"}, Output: "eventheader_gen.go",
	})
	if err != nil {
		t.Fatalf("generate cgo event: %v", err)
	}
	if !bytes.HasPrefix(data, []byte("//go:build cgo && linux\n\n"+GeneratedMarker)) {
		t.Fatalf("cgo output has wrong header:\n%s", data[:min(len(data), 100)])
	}
	if err := Write(Config{
		Dir: dir, Types: []string{"CgoEvent"}, Output: "eventheader_gen.go", Check: true,
	}); err != nil {
		t.Fatalf("check cgo output: %v", err)
	}
	command := exec.Command("go", "test", "-exec=true", "./testdata/cgofixture")
	command.Env = append(os.Environ(), "CGO_ENABLED=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile cgo-enabled fixture: %v\n%s", err, output)
	}
	command = exec.Command("go", "test", "-exec=true", "./testdata/cgofixture")
	command.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile cgo-disabled fixture: %v\n%s", err, output)
	}
}
