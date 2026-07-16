package methodextension

//eventheader:event syntax=1 level=information
type ExtensionEvent struct {
	Value uint32
}

func (*ExtensionEventWriter) ResetForTest() {}
