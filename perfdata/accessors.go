package perfdata

import (
	"sort"

	"github.com/cataggar/LinuxTracepoints-Go/tracefs"
	"github.com/cataggar/LinuxTracepoints-Go/tracepoint"
)

func (r *Reader) ByteOrder() tracepoint.ByteOrder { return r.byteOrder }
func (r *Reader) LongSize() int                   { return r.longSize }
func (r *Reader) PageSize() uint32                { return r.pageSize }
func (r *Reader) ClockInfo() ClockInfo            { return r.clock }

func (r *Reader) Attrs() []Attr {
	out := make([]Attr, len(r.attrs))
	for i := range r.attrs {
		out[i] = cloneAttr(r.attrs[i].attr)
	}
	return out
}

func (r *Reader) EventDescriptors() []EventDescriptor {
	out := make([]EventDescriptor, len(r.attrs))
	for i, d := range r.attrs {
		out[i] = EventDescriptor{Attr: cloneAttr(d.attr), Name: d.name, IDs: append([]uint64(nil), d.ids...), Format: cloneFormat(d.format)}
	}
	return out
}

func (r *Reader) Formats() []*tracefs.Format {
	ids := make([]int, 0, len(r.formats))
	for id := range r.formats {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	out := make([]*tracefs.Format, len(ids))
	for i, id := range ids {
		out[i] = cloneFormat(r.formats[uint32(id)])
	}
	return out
}

func (r *Reader) Format(id uint32) (*tracefs.Format, bool) {
	f := r.formats[id]
	return cloneFormat(f), f != nil
}

func (r *Reader) Features() []Feature {
	ids := make([]int, 0, len(r.features))
	for id := range r.features {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	out := make([]Feature, len(ids))
	for i, id := range ids {
		out[i] = Feature{Index: uint16(id), Data: append([]byte(nil), r.features[uint16(id)]...)}
	}
	return out
}

func (r *Reader) Feature(index uint16) ([]byte, bool) {
	data, ok := r.features[index]
	return append([]byte(nil), data...), ok
}

// EventTypes returns the deprecated event-types section, if present.
func (r *Reader) EventTypes() []byte {
	return append([]byte(nil), r.eventTypes...)
}

func (r *Reader) TracingData() TracingData {
	t := r.tracing
	t.HeaderPage = append([]byte(nil), t.HeaderPage...)
	t.HeaderEvent = append([]byte(nil), t.HeaderEvent...)
	t.Kallsyms = append([]byte(nil), t.Kallsyms...)
	t.Printk = append([]byte(nil), t.Printk...)
	t.SavedCmdline = append([]byte(nil), t.SavedCmdline...)
	t.Raw = append([]byte(nil), t.Raw...)
	t.Trailing = append([]byte(nil), t.Trailing...)
	t.Ftrace = make([][]byte, len(r.tracing.Ftrace))
	for i := range t.Ftrace {
		t.Ftrace[i] = append([]byte(nil), r.tracing.Ftrace[i]...)
	}
	return t
}

func (r *Reader) Details() RecordDetails       { return cloneDetails(r.current) }
func (r *Reader) RecordDetails() RecordDetails { return cloneDetails(r.current) }

func cloneDetails(d RecordDetails) RecordDetails {
	if d.Sample != nil {
		s := *d.Sample
		s.Read = append([]ReadValue(nil), s.Read...)
		s.Callchain = append([]uint64(nil), s.Callchain...)
		s.Raw = append([]byte(nil), s.Raw...)
		s.TrailingSampleData = append([]byte(nil), s.TrailingSampleData...)
		d.Sample = &s
	}
	if d.Comm != nil {
		x := *d.Comm
		d.Comm = &x
	}
	if d.Task != nil {
		x := *d.Task
		d.Task = &x
	}
	if d.Mmap != nil {
		x := *d.Mmap
		x.BuildID = append([]byte(nil), d.Mmap.BuildID...)
		d.Mmap = &x
	}
	if d.Switch != nil {
		x := *d.Switch
		d.Switch = &x
	}
	return d
}

func cloneFormat(f *tracefs.Format) *tracefs.Format {
	if f == nil {
		return nil
	}
	out := *f
	out.Common = cloneFieldFormats(f.Common)
	out.Fields = cloneFieldFormats(f.Fields)
	out.Properties = append([]tracefs.Property(nil), f.Properties...)
	return &out
}

func cloneFieldFormats(in []tracefs.FieldFormat) []tracefs.FieldFormat {
	out := append([]tracefs.FieldFormat(nil), in...)
	for i := range out {
		out[i].Properties = append([]tracefs.Property(nil), in[i].Properties...)
	}
	return out
}

// Close releases reusable buffers. It is idempotent and does not close input.
func (r *Reader) Close() error {
	if r == nil || r.closed {
		return nil
	}
	r.closed = true
	r.buf = nil
	r.attrs = nil
	r.byID = nil
	r.formats = nil
	r.features = nil
	r.eventTypes = nil
	r.tracing = TracingData{}
	r.current = RecordDetails{}
	return nil
}
