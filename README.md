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
attempts to register events return an unsupported-platform error.

## License

[MIT](LICENSE)
