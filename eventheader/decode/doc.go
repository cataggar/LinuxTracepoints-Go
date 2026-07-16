// Package decode decodes the portable Microsoft EventHeader wire format.
//
// Decoder.Start provides a bounded, forward-only view of an event. Returned
// byte slices borrow the caller's input and remain valid while that input is
// unchanged. Decoder.Decode materializes the same event as a tracepoint.Record;
// its Raw slices have the same borrowing rules.
package decode
