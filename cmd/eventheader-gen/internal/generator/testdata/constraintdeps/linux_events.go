//go:build linux

package constraintdeps

//eventheader:event syntax=1 level=information
type SameConstraintEvent struct {
	Values [linuxCount]byte
	Alias  LinuxAlias
	Nested LinuxNested
}

//eventheader:event syntax=1 level=information
type UnconstrainedDependencyEvent struct {
	Values [portableCount]byte
	Alias  PortableAlias
	Nested PortableNested
}
