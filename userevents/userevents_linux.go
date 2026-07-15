//go:build linux

package userevents

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	defaultDataFilePath = "/sys/kernel/tracing/user_events_data"
	userRegSize         = 28
	userUnregSize       = 16
)

type userReg struct {
	Size       uint32
	EnableBit  uint8
	EnableSize uint8
	Flags      uint16
	EnableAddr uint64
	NameArgs   uint64
	WriteIndex uint32
}

type userUnreg struct {
	Size        uint32
	DisableBit  uint8
	Reserved    uint8
	Reserved2   uint16
	DisableAddr uint64
}

type fileState uint8

const (
	fileOpen fileState = iota
	fileClosing
	fileClosed
)

// File owns an open user_events_data descriptor and its registrations.
//
// The zero value is not usable. Create a File with Open or OpenPath.
type File struct {
	mu    sync.Mutex
	fd    int
	path  string
	ready bool
	state fileState
	regs  map[*Registration]struct{}
}

// Registration is a registered userspace tracepoint.
//
// A Registration supports concurrent Enabled, Write, Writev, and Close calls.
type Registration struct {
	mu         sync.RWMutex
	file       *File
	fd         int
	name       string
	options    RegisterOptions
	writeIndex uint32
	enable     []byte
	ready      bool
	closed     bool
}

// Open locates and opens the system user_events_data file.
func Open() (*File, error) {
	fd, path, err := openDataFile()
	if err != nil {
		return nil, err
	}
	return newFile(fd, path), nil
}

// OpenPath opens an explicit user_events_data path.
func OpenPath(path string) (*File, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: data file path is empty", ErrInvalidArgument)
	}
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return newFile(fd, path), nil
}

func newFile(fd int, path string) *File {
	return &File{
		fd:    fd,
		path:  path,
		ready: true,
		state: fileOpen,
		regs:  make(map[*Registration]struct{}),
	}
}

// Path returns the user_events_data path opened by the File.
func (f *File) Path() string {
	if f == nil {
		return ""
	}
	return f.path
}

// Register registers an event name and optional kernel field description.
func (f *File) Register(name, fields string, options RegisterOptions) (*Registration, error) {
	command, err := makeRegistrationCommand(name, fields, options)
	if err != nil {
		return nil, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.ready || f.state != fileOpen {
		return nil, ErrClosed
	}

	enable, err := unix.Mmap(
		-1,
		0,
		4,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANON,
	)
	if err != nil {
		return nil, os.NewSyscallError("mmap", err)
	}

	enableAddress := unsafe.Pointer(unsafe.SliceData(enable))
	reg := userReg{
		Size:       userRegSize,
		EnableBit:  0,
		EnableSize: 4,
		Flags:      uint16(options.Flags),
		EnableAddr: uint64(uintptr(enableAddress)),
		NameArgs:   uint64(uintptr(unsafe.Pointer(unsafe.SliceData(command)))),
	}
	if err := ioctl(f.fd, diagIOCSReg, unsafe.Pointer(&reg)); err != nil {
		_ = unix.Munmap(enable)
		runtime.KeepAlive(command)
		return nil, os.NewSyscallError("ioctl(DIAG_IOCSREG)", err)
	}
	runtime.KeepAlive(command)
	runtime.KeepAlive(enable)

	registration := &Registration{
		file:       f,
		fd:         f.fd,
		name:       name,
		options:    options,
		writeIndex: reg.WriteIndex,
		enable:     enable,
		ready:      true,
	}
	f.regs[registration] = struct{}{}
	return registration, nil
}

// Delete removes a persistent event. The operation normally requires
// CAP_PERFMON or CAP_SYS_ADMIN.
func (f *File) Delete(name string) error {
	command, err := makeDeleteCommand(name)
	if err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.ready || f.state != fileOpen {
		return ErrClosed
	}
	if err := ioctl(f.fd, diagIOCSDel, unsafe.Pointer(unsafe.SliceData(command))); err != nil {
		runtime.KeepAlive(command)
		return os.NewSyscallError("ioctl(DIAG_IOCSDEL)", err)
	}
	runtime.KeepAlive(command)
	return nil
}

// Close unregisters every event and then closes the data file.
//
// If an unregister operation fails, Close leaves the file open so cleanup can
// be retried without releasing memory that the kernel might still update.
func (f *File) Close() error {
	if f == nil {
		return ErrClosed
	}

	f.mu.Lock()
	if !f.ready {
		f.mu.Unlock()
		return ErrClosed
	}
	switch f.state {
	case fileClosed:
		f.mu.Unlock()
		return nil
	case fileClosing:
		f.mu.Unlock()
		return fmt.Errorf("%w: close already in progress", ErrClosed)
	}
	f.state = fileClosing
	registrations := make([]*Registration, 0, len(f.regs))
	for registration := range f.regs {
		registrations = append(registrations, registration)
	}
	f.mu.Unlock()

	var closeErrors []error
	for _, registration := range registrations {
		if err := registration.Close(); err != nil {
			closeErrors = append(closeErrors, err)
		}
	}
	if len(closeErrors) != 0 {
		f.mu.Lock()
		f.state = fileOpen
		f.mu.Unlock()
		return errors.Join(closeErrors...)
	}

	f.mu.Lock()
	fd := f.fd
	f.fd = -1
	f.state = fileClosed
	f.mu.Unlock()
	if err := unix.Close(fd); err != nil {
		return os.NewSyscallError("close", err)
	}
	return nil
}

// Name returns the registered event name.
func (r *Registration) Name() string {
	if r == nil {
		return ""
	}
	return r.name
}

// Options returns the options used to register the event.
func (r *Registration) Options() RegisterOptions {
	if r == nil {
		return RegisterOptions{}
	}
	return r.options
}

// WriteIndex returns the fd-specific index assigned by the kernel.
func (r *Registration) WriteIndex() uint32 {
	if r == nil {
		return 0
	}
	return r.writeIndex
}

// Closed reports whether the registration is unavailable for writes.
func (r *Registration) Closed() bool {
	if r == nil {
		return true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return !r.ready || r.closed
}

// Enabled reports whether a collector currently enables this tracepoint.
func (r *Registration) Enabled() bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ready && !r.closed && r.enabledLocked()
}

func (r *Registration) enabledLocked() bool {
	enableWord := (*uint32)(unsafe.Pointer(unsafe.SliceData(r.enable)))
	return atomic.LoadUint32(enableWord)&1 != 0
}

// Write emits one contiguous payload.
func (r *Registration) Write(payload []byte) error {
	return r.Writev(payload)
}

// Writev emits payload segments without first concatenating them.
func (r *Registration) Writev(payloads ...[]byte) error {
	if r == nil {
		return ErrClosed
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.ready || r.closed {
		return ErrClosed
	}
	if !r.enabledLocked() {
		return ErrDisabled
	}

	total := 4
	for _, payload := range payloads {
		if len(payload) > math.MaxInt-total {
			return fmt.Errorf("%w: payload size overflows int", ErrInvalidArgument)
		}
		total += len(payload)
	}

	var index [4]byte
	binary.NativeEndian.PutUint32(index[:], r.writeIndex)
	vectors := make([][]byte, 1, len(payloads)+1)
	vectors[0] = index[:]
	vectors = append(vectors, payloads...)

	written, err := unix.Writev(r.fd, vectors)
	runtime.KeepAlive(r.enable)
	runtime.KeepAlive(payloads)
	if err != nil {
		if errors.Is(err, unix.EBADF) {
			return ErrDisabled
		}
		return os.NewSyscallError("writev", err)
	}
	if written != total {
		return io.ErrShortWrite
	}
	return nil
}

// Close unregisters the tracepoint and releases its kernel-visible enable
// state. It is safe to call Close more than once.
func (r *Registration) Close() error {
	if r == nil {
		return ErrClosed
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.ready {
		return ErrClosed
	}
	if r.closed {
		return nil
	}

	enableAddress := unsafe.Pointer(unsafe.SliceData(r.enable))
	unreg := userUnreg{
		Size:        userUnregSize,
		DisableAddr: uint64(uintptr(enableAddress)),
	}
	if err := ioctl(r.fd, diagIOCSUnreg, unsafe.Pointer(&unreg)); err != nil {
		runtime.KeepAlive(r.enable)
		return os.NewSyscallError("ioctl(DIAG_IOCSUNREG)", err)
	}
	runtime.KeepAlive(r.enable)

	r.closed = true
	r.file.mu.Lock()
	delete(r.file.regs, r)
	r.file.mu.Unlock()

	enable := r.enable
	r.enable = nil
	if err := unix.Munmap(enable); err != nil {
		return os.NewSyscallError("munmap", err)
	}
	return nil
}

func ioctl(fd int, request uintptr, argument unsafe.Pointer) error {
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		request,
		uintptr(argument),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func openDataFile() (int, string, error) {
	fd, err := unix.Open(defaultDataFilePath, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err == nil {
		return fd, defaultDataFilePath, nil
	}

	openErrors := []error{
		&os.PathError{Op: "open", Path: defaultDataFilePath, Err: err},
	}
	notFoundOnly := errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR)

	mountInfo, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		openErrors = append(openErrors, &os.PathError{Op: "open", Path: "/proc/self/mountinfo", Err: err})
		notFoundOnly = false
	} else {
		candidates, parseErr := mountDataFileCandidates(mountInfo)
		closeErr := mountInfo.Close()
		if parseErr != nil {
			openErrors = append(openErrors, parseErr)
			notFoundOnly = false
		}
		if closeErr != nil {
			openErrors = append(openErrors, &os.PathError{Op: "close", Path: "/proc/self/mountinfo", Err: closeErr})
			notFoundOnly = false
		}

		seen := map[string]struct{}{defaultDataFilePath: {}}
		for _, candidate := range candidates {
			if _, exists := seen[candidate]; exists {
				continue
			}
			seen[candidate] = struct{}{}

			fd, openErr := unix.Open(candidate, unix.O_WRONLY|unix.O_CLOEXEC, 0)
			if openErr == nil {
				return fd, candidate, nil
			}
			openErrors = append(openErrors, &os.PathError{Op: "open", Path: candidate, Err: openErr})
			if !errors.Is(openErr, unix.ENOENT) && !errors.Is(openErr, unix.ENOTDIR) {
				notFoundOnly = false
			}
		}
	}

	joined := errors.Join(openErrors...)
	if notFoundOnly {
		return -1, "", fmt.Errorf("%w: %w", ErrUnsupported, joined)
	}
	return -1, "", fmt.Errorf("userevents: open data file: %w", joined)
}

func mountDataFileCandidates(reader io.Reader) ([]string, error) {
	var tracefsPaths []string
	var debugfsPaths []string
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if separator < 6 || separator+2 >= len(fields) {
			continue
		}

		mountPoint, err := unescapeMountField(fields[4])
		if err != nil {
			return nil, fmt.Errorf("userevents: parse mount point %q: %w", fields[4], err)
		}
		switch fields[separator+1] {
		case "tracefs":
			tracefsPaths = append(tracefsPaths, filepath.Join(mountPoint, "user_events_data"))
		case "debugfs":
			debugfsPaths = append(debugfsPaths, filepath.Join(mountPoint, "tracing", "user_events_data"))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("userevents: read mountinfo: %w", err)
	}
	return append(tracefsPaths, debugfsPaths...), nil
}

func unescapeMountField(value string) (string, error) {
	var result strings.Builder
	result.Grow(len(value))
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			result.WriteByte(value[index])
			continue
		}
		if index+3 >= len(value) {
			return "", fmt.Errorf("truncated escape")
		}
		var decoded byte
		for offset := 1; offset <= 3; offset++ {
			digit := value[index+offset]
			if digit < '0' || digit > '7' {
				return "", fmt.Errorf("invalid octal escape")
			}
			decoded = decoded*8 + digit - '0'
		}
		result.WriteByte(decoded)
		index += 3
	}
	return result.String(), nil
}
