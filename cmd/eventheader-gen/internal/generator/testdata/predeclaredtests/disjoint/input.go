//go:build !eventheader_disjoint

package disjoint

//eventheader:event syntax=1 level=information
type Event struct {
	Value uint32
}
