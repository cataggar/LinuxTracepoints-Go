package eventheader

import "errors"

var (
	// ErrInvalidName indicates an invalid provider, group, event, or field name.
	ErrInvalidName = errors.New("eventheader: invalid name")
	// ErrInvalidLevel indicates a level outside the supported range 1 through 5.
	ErrInvalidLevel = errors.New("eventheader: invalid level")
	// ErrInvalidValue indicates an invalid enum, count, activity, or field value.
	ErrInvalidValue = errors.New("eventheader: invalid value")
	// ErrState indicates an incomplete event or invalid builder/binding state.
	ErrState = errors.New("eventheader: invalid state")
	// ErrCountTooLarge indicates a count that cannot fit in the 16-bit wire field.
	ErrCountTooLarge = errors.New("eventheader: count exceeds 65535")
	// ErrMetadataTooLarge indicates metadata that cannot fit in its extension.
	ErrMetadataTooLarge = errors.New("eventheader: metadata exceeds 65535 bytes")
	// ErrEventTooLarge indicates metadata plus payload exceeding the conservative
	// user_events maximum.
	ErrEventTooLarge = errors.New("eventheader: metadata and payload exceed 65467 bytes")
	// ErrNestingTooDeep indicates more than eight nested structures.
	ErrNestingTooDeep = errors.New("eventheader: struct nesting exceeds 8")
	// ErrTooManyFields indicates more than 127 immediate struct children.
	ErrTooManyFields = errors.New("eventheader: struct has more than 127 fields")
	// ErrStructArrayUnsupported indicates an explicitly deferred array of structs.
	ErrStructArrayUnsupported = errors.New("eventheader: arrays of structs are not supported")
)
