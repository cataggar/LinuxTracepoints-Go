package malformed

import (
	"net/netip"
	"time"
)

//eventheader:event syntax=1 mystery=yes
type UnknownOption struct {
	Value uint32
}

//eventheader:event syntax=1 level=information
type RepeatedTagOption struct {
	Value uint32 `eventheader:",format=hex,format=pid"`
}

//eventheader:event syntax=1 level=information
type PointerField struct {
	Value *uint32
}

//eventheader:event syntax=1 level=information
type MachineInteger struct {
	Value int
}

//eventheader:event syntax=1 level=information
type ImportedStruct struct {
	Value time.Time
}

//eventheader:event syntax=1 level=information
type StructArray struct {
	Value []struct{ Count uint32 }
}

//eventheader:event syntax=1 level=information
type AmbiguousAddress struct {
	Value netip.Addr
}

//eventheader:event syntax=2
type BadSyntax struct {
	Value uint8
}

//eventheader:event syntax=1 level=information
type Generic[T any] struct {
	Value T
}

//eventheader:event name=Unquoted level=information
type UnquotedName struct {
	Value uint8
}

//eventheader:event level=information
type AddressCollection struct {
	Value []netip.Addr `eventheader:",encoding=ipv4"`
}

//eventheader:event level=information
type UnknownSkipOption struct {
	Value uint8 `eventheader:",skip"`
}

//eventheader:event level=information
type MalformedTag struct {
	Value uint8 `eventheader:"value`
}

//eventheader:event level=information
type RepeatedTagKey struct {
	Value uint8 `eventheader:"one" eventheader:"two"`
}

//eventheader:event
type MissingLevel struct {
	Value uint8
}

//eventheader:event level=information
type BlankField struct {
	_ uint32
}
