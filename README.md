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

Phase 2 adds canonical EventHeader tracepoint naming, dynamic wire encoding,
activity IDs, fields, arrays, structures, and an `EventSet` bound to an existing
`userevents.File`. Provider caching, generated typed writers, decoding, and
collection are future work.

```go
file, err := userevents.Open()
if err != nil {
	log.Fatal(err)
}
defer file.Close()

set, err := eventheader.NewEventSet(
	file, "ExampleProvider", eventheader.LevelInformation, 0x1, "")
if err != nil {
	log.Fatal(err)
}
defer set.Close()

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
attempts to register events return an unsupported-platform error.

## License

[MIT](LICENSE)
