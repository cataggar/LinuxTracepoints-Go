package testcollisions

//eventheader:event syntax=1 level=information
type TopLevelTestEvent struct {
	Value uint32
}

//eventheader:event syntax=1 level=information
type MethodTestEvent struct {
	Value uint32
}

//eventheader:event syntax=1 level=information
type NoncollidingTestEvent struct {
	Value uint32
}

//eventheader:event syntax=1 level=information
type ExternalTestEvent struct {
	Value uint32
}
