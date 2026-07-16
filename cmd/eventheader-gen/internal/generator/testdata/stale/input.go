package stale

import "github.com/cataggar/LinuxTracepoints-Go/eventheader"

//eventheader:event syntax=1 level=information
type StaleEvent struct {
	Value uint32
}

var StaleWriter *StaleEventWriter
var StaleSchema = StaleEventSchema

func useStaleGeneratedAPI(writer *StaleEventWriter, provider *eventheader.Provider) {
	StaleWriter = writer
	_, _ = NewStaleEventWriter(provider, nil)
	_ = writer.Enabled()
	_ = writer.Event()
	_ = writer.Write(nil, nil, nil)
}
