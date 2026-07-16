package importedbytes

import "github.com/cataggar/LinuxTracepoints-Go/cmd/eventheader-gen/internal/generator/testdata/importedbytes/bytepkg"

//eventheader:event syntax=1 level=information
type ImportedByteEvent struct {
	UUID        [16]bytepkg.Octet   `eventheader:",encoding=uuid"`
	IPv4        [4]bytepkg.Octet    `eventheader:",encoding=ipv4"`
	IPv6        [16]bytepkg.Octet   `eventheader:",encoding=ipv6"`
	UUIDs       [][16]bytepkg.Octet `eventheader:",encoding=uuid"`
	FixedIPv4s  [2][4]bytepkg.Octet `eventheader:",encoding=ipv4"`
	IPv6s       [][16]bytepkg.Octet `eventheader:",encoding=ipv6"`
	Binary      []bytepkg.Octet
	FixedBinary [3]bytepkg.Octet `eventheader:",encoding=binary"`
}
