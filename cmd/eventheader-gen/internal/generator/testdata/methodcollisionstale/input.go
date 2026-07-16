package methodcollisionstale

//eventheader:event syntax=1 level=information
type CollisionEvent struct {
	Value uint32
}

func (*CollisionEventWriter) bind(*CollisionEvent) error { return nil }
