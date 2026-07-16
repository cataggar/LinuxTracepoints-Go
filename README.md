# LinuxTracepoints-Go

LinuxTracepoints-Go provides cgo-free Go support for Linux
[`user_events`](https://www.kernel.org/doc/html/latest/trace/user_events.html)
and the
[EventHeader](https://github.com/microsoft/LinuxTracepoints/blob/main/libeventheader-tracepoint/README.md)
wire format.

The project is under active development. The implementation roadmap is tracked
in [issue #1](https://github.com/cataggar/LinuxTracepoints-Go/issues/1).

## Scope

The producer packages create userspace tracepoints through the Linux
`user_events` ABI. They do not create in-kernel tracepoints declared with
`DECLARE_TRACE` or `DEFINE_TRACE`.

EventHeader supports provider-owned registration caches, immutable reusable
schemas, goroutine-local bindings, and dynamic runtime schemas.

The portable decoder packages parse ordinary tracefs formats, EventHeader
events, and seek- or pipe-mode `perf.data` without depending on the host byte
order or word size. Live perf-ring collection was evaluated for v0 and is
deferred; the library does not currently open `perf_event` rings.

## Decode perf.data

`perfdata.Reader` associates perf attributes, tracefs formats, event IDs, and
clock metadata before returning structured `tracepoint.Record` values:

```go
file, err := os.Open("perf.data")
if err != nil {
	log.Fatal(err)
}
defer file.Close()

info, err := file.Stat()
if err != nil {
	log.Fatal(err)
}
reader, err := perfdata.Open(file, info.Size(), perfdata.Options{})
if err != nil {
	log.Fatal(err)
}
defer reader.Close()

for {
	record, err := reader.Next()
	if errors.Is(err, io.EOF) {
		break
	}
	if err != nil {
		log.Fatal(err)
	}
	if record.Kind == tracepoint.RecordEvent {
		log.Printf("%s/%s: %d fields",
			record.Identity.System,
			record.Identity.Name,
			len(record.Event.Fields))
	}
}
```

Use `perfdata.OpenPipe` for a pipe-mode stream. Record and value byte slices
borrow the reader's reusable buffer until the next call to `Next`; call
`tracepoint.CloneRecord` to retain a record. Inner tracefs or EventHeader
damage is returned as `tracepoint.RecordCorrupt` when the enclosing perf record
boundary is still valid. Broken outer framing and unsupported compressed data
return errors.

For standalone payloads, use `tracefs.ParseFormat` and `tracefs.Decode` with an
explicit source byte order and `sizeof(long)`. Use
`eventheader/decode.Start` for bounded streaming iteration or
`eventheader/decode.Decode` for a materialized field tree.

## Generated typed writers

Annotate an event struct and run the generator from `go generate`:

```go
//go:generate go run github.com/cataggar/LinuxTracepoints-Go/cmd/eventheader-gen -type=RequestEvent -output=request_eventheader.go

//eventheader:event syntax=1 name="Request" level=information keyword=0x10 group="http" id=12 version=1
type RequestEvent struct {
	Status  uint16   `eventheader:"status,format=hex,tag=1"`
	Path    string
	Payload []byte
	Values  []byte   `eventheader:",encoding=u8"`
	ID      [16]byte `eventheader:",encoding=uuid"`
}
```

The directive also accepts `tag` and a named or numeric `opcode`. Field tags
can rename or skip fields and set `format`, `tag`, or a compatible semantic
`encoding` (`binary`, `u8`, `utf16`, `uuid`, `ipv4`, `ipv6`, or `port`).

Create one generated writer per goroutine. The disabled path checks enablement
before reading the event value and performs no allocation. Writers retain
scratch storage required to convert named collection element types:

```go
writer, err := NewRequestEventWriter(provider, make([]byte, 0, 256))
if err != nil {
	log.Fatal(err)
}
if writer.Enabled() {
	err = writer.Write(&RequestEvent{Status: 200, Path: "/health"}, nil, nil)
}
```

Use `-check` in CI to report missing or stale output without writing it.
`-tags` applies build tags while loading the package. Generated files preserve
the source event's explicit and filename-derived build constraints; events with
different effective constraints must use separate output files. An output
filename's `_GOOS.go`, `_GOARCH.go`, or `_GOOS_GOARCH.go` suffix must already
be implied by the event constraint. Events declared in cgo files have an
implicit `cgo` constraint, so their generated writers are excluded when cgo is
disabled. File output must be a normal non-test `.go` basename directly in the
source package directory. Existing output is replaced only when it has the
exact `eventheader-gen` generated header. Linux uses atomic path exchange and
Windows uses mandatory handle sharing/locking with `ReplaceFile`; platforms
without an atomic conditional replacement primitive refuse to replace stale
existing output, but still support creation, `-check`, and current-output
no-ops.

Fixed array lengths must be integer literals or local constant arithmetic based
only on architecture-independent integer constants. Expressions involving
`unsafe.Sizeof`, `unsafe.Alignof`, or `unsafe.Offsetof` are rejected; use an
explicit count or separate architecture-constrained source and output files.
Local constants and named or nested types used by an event must be
unconstrained or have the same effective constraint as the event. Imported
named primitives are rejected unless the generator explicitly supports their
stable standard-library semantics.

Writer method names `Enabled`, `Event`, `Write`, and `bind` are reserved.
Other methods may extend generated writer types. Collision checks include
same-package test files and inactive Go files whenever their effective build
constraints can overlap the generated file; external test packages are
ignored. The same overlap rules apply when rejecting package declarations that
shadow predeclared Go identifiers, because generated code needs to reference
those identifiers unambiguously.
Overlap analysis enumerates up to 12 distinct custom tags; larger expressions
are conservatively treated as overlapping.

## Reusable schemas

Use a `Provider`, `Schema`, and one `Binding` per goroutine when an event schema
is known in advance:

```go
provider, err := eventheader.OpenProvider("ExampleProvider")
if err != nil {
	log.Fatal(err)
}
defer provider.Close()

set, err := provider.EventSet(eventheader.LevelInformation, 0x1, "")
if err != nil {
	log.Fatal(err)
}

schema, err := eventheader.NewSchema(
	eventheader.SchemaOptions{Name: "Request"},
	eventheader.Uint32Field("status"),
	eventheader.StringField("path"),
)
if err != nil {
	log.Fatal(err)
}
event, err := eventheader.NewEvent(set, schema)
if err != nil {
	log.Fatal(err)
}
binding := event.Bind(make([]byte, 0, 128))

if event.Enabled() {
	binding.Reset()
	if err := binding.Uint32(200); err != nil {
		log.Fatal(err)
	}
	if err := binding.String("/health"); err != nil {
		log.Fatal(err)
	}
	if err := event.Write(&binding, nil, nil); err != nil &&
		!errors.Is(err, userevents.ErrDisabled) {
		log.Printf("write tracepoint: %v", err)
	}
}
```

`NewProvider` can instead borrow an existing `userevents.File`. Immutable
schemas and events may be shared; each goroutine uses its own reusable binding.
This reusable API and the dynamic API below remain available without code
generation.

## Dynamic schemas

`Builder` remains available when fields are selected at runtime:

```go
if set.Enabled() {
	builder, err := eventheader.NewBuilder("Request")
	if err != nil {
		log.Fatal(err)
	}
	if err := builder.Uint32("status", 200); err != nil {
		log.Fatal(err)
	}
	if err := builder.String("path", "/health"); err != nil {
		log.Fatal(err)
	}
	if err := set.Write(builder); err != nil &&
		!errors.Is(err, userevents.ErrDisabled) {
		log.Printf("write tracepoint: %v", err)
	}
}
```

The example requires imports for
`github.com/cataggar/LinuxTracepoints-Go/eventheader`,
`github.com/cataggar/LinuxTracepoints-Go/userevents`, `errors`, and `log`.

## Requirements

- Linux with `CONFIG_USER_EVENTS` for event registration and emission.
- Go 1.25 or later.

Non-Linux builds are supported so applications can compile portable code, but
attempts to register events return an unsupported-platform error. Decoding is
portable and available on non-Linux platforms.

## License

[MIT](LICENSE)
