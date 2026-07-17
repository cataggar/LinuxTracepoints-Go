package methodcollisionwritefunc

//eventheader:event syntax=1 level=information
type CollisionEvent struct {
	Value uint32
}

func (*CollisionEventWriter) WriteFunc() {}
