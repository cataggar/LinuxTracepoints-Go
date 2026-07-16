package ignoredcollisions

var CrossPlatformEventSchema int
var LinuxOnlyEventSchema int

func (*CrossPlatformMethodEventWriter) Enabled() bool { return false }
func (*LinuxMethodEventWriter) Enabled() bool         { return false }
