//go:build linux

package ignoredcollisions

//eventheader:event syntax=1 level=information
type LinuxOnlyEvent struct {
	Value uint32
}

//eventheader:event syntax=1 level=information
type LinuxMethodEvent struct {
	Value uint32
}

//eventheader:event syntax=1 level=information
type CgoOverlapEvent struct {
	Value uint32
}
