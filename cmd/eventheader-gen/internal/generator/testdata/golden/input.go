package golden

import (
	"net"
	"time"
)

type Code uint32
type Enabled bool
type Message string
type Blob []byte
type UTF16 []uint16
type DurationAlias = time.Duration

const ValueCount = 1 << 1

type Detail struct {
	Count uint16 `eventheader:"count,encoding=port"`
	Text  string `eventheader:",format=json"`
}

//eventheader:event syntax=1 name="Golden" level=warning keyword=0x42 group="api" id=65535 version=255 tag=9 opcode=activity-start
type GoldenEvent struct {
	ID         [16]byte    `eventheader:"id,encoding=uuid,tag=1"`
	IDs        [2][16]byte `eventheader:"ids,encoding=uuid"`
	Code       Code        `eventheader:"code,format=hex"`
	Enabled    Enabled
	Message    Message
	Elapsed    DurationAlias
	Address    net.IP `eventheader:"address,encoding=ipv6"`
	Values     [ValueCount]int32
	Blobs      [][]byte
	Messages   []Message
	NamedBlobs []Blob
	UTF16Text  []UTF16 `eventheader:",encoding=utf16"`
	Raw        [3]byte `eventheader:"raw,encoding=binary"`
	Detail     Detail
	Data       []byte
	Skip       *int   `eventheader:"-"`
	_          uint64 `eventheader:"-"`
}
