package qualifier

import "github.com/cataggar/LinuxTracepoints-Go/cmd/eventheader-gen/internal/generator/testdata/qualifier/odd/v2"

//eventheader:event syntax=1 level=information
type QualifiedEvent struct {
	Value actualname.Value
}
