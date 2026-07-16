//go:build current

package ignoredcollisions

//eventheader:event syntax=1 level=information
type CustomOverlapEvent struct {
	Value uint32
}

//eventheader:event syntax=1 level=information
type CustomDisjointEvent struct {
	Value uint32
}
