package constraintdeps

const (
	archBase  = 2
	archCount = archBase * 2
)

type ArchAlias = uint64

type ArchNested struct {
	Value uint64
}
