package methodcollisionmissing

//eventheader:event syntax=1 level=information
type CollisionEvent struct {
	Value uint32
}

func (*CollisionEventWriter) Enabled() bool { return false }
