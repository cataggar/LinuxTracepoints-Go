package generateddep

import "github.com/cataggar/LinuxTracepoints-Go/eventheader"

var (
	PackageWriter        *GeneratedDependencyEventWriter
	PackageSchemaFactory = GeneratedDependencyEventSchema
)

func UseGeneratedAPIs(
	writer *GeneratedDependencyEventWriter,
	schemaFactory func() (*eventheader.Schema, error),
	provider *eventheader.Provider,
) {
	PackageWriter = writer
	PackageSchemaFactory = schemaFactory
	_, _ = NewGeneratedDependencyEventWriter(provider, nil)
	_ = writer.Enabled()
	_ = writer.Event()
	_ = writer.Write(nil, nil, nil)
}
