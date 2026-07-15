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
`DECLARE_TRACE` or `DEFINE_TRACE`. Future decoder and collector packages may
consume both kernel tracepoints and userspace events.

## Requirements

- Linux with `CONFIG_USER_EVENTS` for event registration and emission.
- Go 1.25 or later.

Non-Linux builds are supported so applications can compile portable code, but
attempts to register events return an unsupported-platform error.

## License

[MIT](LICENSE)
