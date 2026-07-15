//go:build linux

package userevents

import (
	"testing"
	"unsafe"
)

func TestUserRegLayout(t *testing.T) {
	t.Parallel()

	var value userReg
	offsets := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"Size", unsafe.Offsetof(value.Size), 0},
		{"EnableBit", unsafe.Offsetof(value.EnableBit), 4},
		{"EnableSize", unsafe.Offsetof(value.EnableSize), 5},
		{"Flags", unsafe.Offsetof(value.Flags), 6},
		{"EnableAddr", unsafe.Offsetof(value.EnableAddr), 8},
		{"NameArgs", unsafe.Offsetof(value.NameArgs), 16},
		{"WriteIndex", unsafe.Offsetof(value.WriteIndex), 24},
	}
	for _, offset := range offsets {
		if offset.got != offset.want {
			t.Errorf("%s offset = %d, want %d", offset.name, offset.got, offset.want)
		}
	}
	if userRegSize != 28 {
		t.Fatalf("userRegSize = %d, want 28", userRegSize)
	}
}

func TestUserUnregLayout(t *testing.T) {
	t.Parallel()

	var value userUnreg
	offsets := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"Size", unsafe.Offsetof(value.Size), 0},
		{"DisableBit", unsafe.Offsetof(value.DisableBit), 4},
		{"Reserved", unsafe.Offsetof(value.Reserved), 5},
		{"Reserved2", unsafe.Offsetof(value.Reserved2), 6},
		{"DisableAddr", unsafe.Offsetof(value.DisableAddr), 8},
	}
	for _, offset := range offsets {
		if offset.got != offset.want {
			t.Errorf("%s offset = %d, want %d", offset.name, offset.got, offset.want)
		}
	}
	if got := unsafe.Sizeof(value); got != userUnregSize {
		t.Fatalf("unsafe.Sizeof(userUnreg{}) = %d, want %d", got, userUnregSize)
	}
}

func TestIoctlRequests(t *testing.T) {
	t.Parallel()

	pointerSize := uintptr(unsafe.Sizeof(uintptr(0)))
	if pointerSize != 4 && pointerSize != 8 {
		t.Fatalf("pointer size = %d, want 4 or 8", pointerSize)
	}

	if pointerSize == 8 {
		if diagIOCSReg != 0xc0082a00 {
			t.Errorf("diagIOCSReg = %#x, want 0xc0082a00", diagIOCSReg)
		}
		if legacyIoctlEncoding {
			if diagIOCSUnreg != 0x80082a02 {
				t.Errorf("diagIOCSUnreg = %#x, want 0x80082a02", diagIOCSUnreg)
			}
		} else if diagIOCSUnreg != 0x40082a02 {
			t.Errorf("diagIOCSUnreg = %#x, want 0x40082a02", diagIOCSUnreg)
		}
	}
}
