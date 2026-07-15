// Package userevents registers and writes Linux userspace tracepoints through
// the user_events ABI.
//
// Registrations are explicit resources. Callers must close each File, which
// unregisters its events before releasing their kernel-visible enable state.
package userevents
