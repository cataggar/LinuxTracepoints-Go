package errorfixture

type error interface {
	Error() string
}

//eventheader:event syntax=1 level=information
type Event struct {
	Value uint32
}
