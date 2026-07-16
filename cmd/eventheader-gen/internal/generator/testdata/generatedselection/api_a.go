package generatedselection

import "github.com/cataggar/LinuxTracepoints-Go/eventheader"

var SelectedWriter *SelectedAWriter
var SelectedSchema = SelectedASchema

func useSelectedAPIs(writer *SelectedAWriter, provider *eventheader.Provider) {
	SelectedWriter = writer
	_, _ = NewSelectedAWriter(provider, nil)
	_ = writer.Enabled()
	_ = writer.Event()
	_ = writer.Write(nil, nil, nil)
	_ = writer.bind(nil)
	_ = writer.event
	_ = writer.binding
	eventheaderGenSelectedASchemaOnce.Do(func() {})
	_ = eventheaderGenSelectedASchemaValue
	_ = eventheaderGenSelectedASchemaErr
}
