// Package eventheaderfixture is a generated-writer compile and runtime fixture.
package eventheaderfixture

import "net/netip"

//go:generate go run ../../cmd/eventheader-gen -type=RequestEvent -output=request_eventheader.go

type StatusCode uint16
type Octet uint8
type Word uint16
type Count int32
type Toggle bool
type Text string
type PointerWord uintptr
type OctetBlock [2]Octet

type RequestDetails struct {
	Method   string
	Attempts [2]uint32 `eventheader:",format=unsigned"`
}

//eventheader:event syntax=1 name="Request" level=information keyword=0x10 group="http" id=12 version=2 tag=7 opcode=info
type RequestEvent struct {
	RequestID      [16]byte     `eventheader:"request_id,encoding=uuid"`
	NamedIPv4      [4]Octet     `eventheader:",encoding=ipv4"`
	NamedIPv6      [16]Octet    `eventheader:",encoding=ipv6"`
	NamedUUID      [16]Octet    `eventheader:",encoding=uuid"`
	NamedIPv4s     [][4]Octet   `eventheader:",encoding=ipv4"`
	NamedIPv6s     [][16]Octet  `eventheader:",encoding=ipv6"`
	NamedUUIDs     [][16]Octet  `eventheader:",encoding=uuid"`
	FixedNamedIPv4 [2][4]Octet  `eventheader:",encoding=ipv4"`
	FixedNamedIPv6 [2][16]Octet `eventheader:",encoding=ipv6"`
	FixedNamedUUID [2][16]Octet `eventheader:",encoding=uuid"`
	Client         netip.Addr   `eventheader:"client,encoding=ipv4"`
	Status         StatusCode   `eventheader:",format=hex,tag=3"`
	Enabled        Toggle
	Label          Text
	Details        RequestDetails
	Payload        []Octet
	Raw            [3]Octet `eventheader:",encoding=binary"`
	Bytes          []byte   `eventheader:",encoding=u8"`
	Message        []Word   `eventheader:",encoding=utf16"`
	Counts         []Count
	Pointers       []PointerWord
	Blocks         []OctetBlock `eventheader:",encoding=binary"`
	Words          [][]Word     `eventheader:",encoding=utf16"`
	NamedBlobs     [][]Octet    `eventheader:",encoding=binary"`
	Ignored        int          `eventheader:"-"`
	_              uint64       `eventheader:"-"`
}
