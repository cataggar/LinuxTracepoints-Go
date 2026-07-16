package constraintdeps

const (
	archBase  = 1
	archCount = archBase * 2
)

type ArchAlias = uint32

type ArchNested struct {
	Value uint32
}
