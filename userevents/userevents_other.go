//go:build !linux

package userevents

// File is unavailable on non-Linux platforms.
type File struct{}

// Registration is unavailable on non-Linux platforms.
type Registration struct{}

// Open returns ErrUnsupported on non-Linux platforms.
func Open() (*File, error) {
	return nil, ErrUnsupported
}

// OpenPath returns ErrUnsupported on non-Linux platforms.
func OpenPath(string) (*File, error) {
	return nil, ErrUnsupported
}

// Path returns an empty path on non-Linux platforms.
func (*File) Path() string {
	return ""
}

// Register returns ErrUnsupported on non-Linux platforms.
func (*File) Register(string, string, RegisterOptions) (*Registration, error) {
	return nil, ErrUnsupported
}

// Delete returns ErrUnsupported on non-Linux platforms.
func (*File) Delete(string) error {
	return ErrUnsupported
}

// Close returns ErrUnsupported on non-Linux platforms.
func (*File) Close() error {
	return ErrUnsupported
}

// Name returns an empty name on non-Linux platforms.
func (*Registration) Name() string {
	return ""
}

// Options returns zero-valued options on non-Linux platforms.
func (*Registration) Options() RegisterOptions {
	return RegisterOptions{}
}

// WriteIndex returns zero on non-Linux platforms.
func (*Registration) WriteIndex() uint32 {
	return 0
}

// Enabled reports false on non-Linux platforms.
func (*Registration) Enabled() bool {
	return false
}

// Write returns ErrUnsupported on non-Linux platforms.
func (*Registration) Write([]byte) error {
	return ErrUnsupported
}

// Writev returns ErrUnsupported on non-Linux platforms.
func (*Registration) Writev(...[]byte) error {
	return ErrUnsupported
}

// Close returns ErrUnsupported on non-Linux platforms.
func (*Registration) Close() error {
	return ErrUnsupported
}
