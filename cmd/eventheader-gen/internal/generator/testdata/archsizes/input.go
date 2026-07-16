package archsizes

import "unsafe"

const (
	pointerSize        = unsafe.Sizeof(uintptr(0))
	derivedPointerSize = pointerSize * 2
	pointerOffset      = unsafe.Offsetof(struct {
		First byte
		Value uintptr
	}{}.Value)

	portableBase  = 1
	portableCount = (portableBase + 1) << 1

	machineTypedZero uint = 0
	machineCount          = (^machineTypedZero >> 62) + 1
	unprovenCount         = len("four")
)

//eventheader:event syntax=1 level=information keyword=1
type DirectSizeofEvent struct {
	Value [unsafe.Sizeof(uintptr(0))]byte
}

//eventheader:event syntax=1 level=information keyword=1
type DerivedSizeofEvent struct {
	Value [derivedPointerSize]byte
}

//eventheader:event syntax=1 level=information keyword=1
type DirectAlignofEvent struct {
	Value [unsafe.Alignof(uintptr(0))]byte
}

//eventheader:event syntax=1 level=information keyword=1
type DerivedOffsetofEvent struct {
	Value [pointerOffset]byte
}

//eventheader:event syntax=1 level=information keyword=1
type MachineTypedConstantEvent struct {
	Value [machineCount]byte
}

//eventheader:event syntax=1 level=information keyword=1
type UnprovenBuiltinEvent struct {
	Value [unprovenCount]byte
}

//eventheader:event syntax=1 level=information keyword=1
type PortableArrayEvent struct {
	Literal    [3]uint8
	Arithmetic [portableCount]uint16
	Pointer    uintptr
}
