//go:build linux || windows

package ignoredcollisions

//eventheader:event syntax=1 level=information
type CrossPlatformEvent struct {
	Value uint32
}

//eventheader:event syntax=1 level=information
type CrossPlatformMethodEvent struct {
	Value uint32
}
