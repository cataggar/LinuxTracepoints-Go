//go:build linux

package constraintdeps

const linuxCount = 3

type LinuxAlias = uint32

type LinuxNested struct {
	Value uint16
}
