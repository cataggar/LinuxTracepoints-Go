package constraintdeps

const portableCount = 2

type PortableAlias = uint32

type PortableNested struct {
	Value uint16
}

//eventheader:event syntax=1 level=information
type PortableDependencyEvent struct {
	Values [portableCount]byte
	Alias  PortableAlias
	Nested PortableNested
}

//eventheader:event syntax=1 level=information
type ArchConstantEvent struct {
	Values [archCount]byte
}

//eventheader:event syntax=1 level=information
type ArchAliasEvent struct {
	Value ArchAlias
}

//eventheader:event syntax=1 level=information
type ArchNestedEvent struct {
	Value ArchNested
}

const typedArchCount ArchAlias = 2

//eventheader:event syntax=1 level=information
type TypedArchConstantEvent struct {
	Values [typedArchCount]byte
}
