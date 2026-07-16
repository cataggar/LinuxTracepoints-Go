// Package perfdata decodes portable Linux perf.data files and pipe streams.
//
// Reader returns records in file order. Byte slices in a returned record and
// in Details may be reused by the next call to Next. Use
// tracepoint.CloneRecord when a record must outlive that call.
package perfdata
