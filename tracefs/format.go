package tracefs

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"

	"github.com/cataggar/LinuxTracepoints-Go/tracepoint"
)

const (
	defaultMaxFormatBytes = 1 << 20
	defaultMaxFields      = 4096
)

// ParseOptions controls format parsing. Zero limits select defaults of 1 MiB
// and 4096 fields. LongSize defaults to the deterministic value 8.
type ParseOptions struct {
	// System supplies the event subsystem, which is absent from format files.
	System string
	// LongSize is the source sizeof(long), either 4 or 8.
	LongSize int
	// MaxFormatBytes limits input size.
	MaxFormatBytes int
	// MaxFields limits the combined common and ordinary field count.
	MaxFields int
}

// Property retains a parsed property, including properties unknown to this
// implementation.
type Property struct {
	// Name is the property name without its colon.
	Name string
	// Value is the trimmed property value.
	Value string
	// Line is the one-based source line.
	Line int
	// Column is the one-based source column.
	Column int
}

// LocationKind identifies a tracefs dynamic-location descriptor.
type LocationKind uint8

const (
	// LocationNone identifies an ordinary fixed-location field.
	LocationNone LocationKind = iota
	// LocationData identifies an absolute __data_loc descriptor.
	LocationData
	// LocationRelative identifies a relative __rel_loc descriptor.
	LocationRelative
)

// FieldKind is the scalar interpretation of a field declaration.
type FieldKind uint8

const (
	// FieldOpaque is an unknown type decoded as binary.
	FieldOpaque FieldKind = iota
	// FieldUnsigned is an unsigned integer.
	FieldUnsigned
	// FieldSigned is a signed integer.
	FieldSigned
	// FieldFloat is an IEEE floating-point value.
	FieldFloat
	// FieldChar is a character or character array.
	FieldChar
	// FieldBool is a Boolean value.
	FieldBool
)

// FieldFormat describes one field in a tracefs format.
type FieldFormat struct {
	Declaration      string
	Name             string
	Kind             FieldKind
	Offset           int
	Size             int
	Signed           bool
	SignedSet        bool
	Width            int
	ArrayLen         int
	Pointer          bool
	Location         LocationKind
	Properties       []Property
	Line             int
	Column           int
	declarationClass declarationClass
}

// Format is parsed tracefs event metadata. Common and Fields preserve the two
// format groups.
type Format struct {
	System      string
	Name        string
	ID          uint32
	Common      []FieldFormat
	Fields      []FieldFormat
	PrintFormat string
	LongSize    int
	Properties  []Property
}

// ParseError identifies a source position in malformed format text.
type ParseError struct {
	Line   int
	Column int
	Err    error
}

// Error implements error.
func (e *ParseError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("tracefs format line %d, column %d: %v", e.Line, e.Column, e.Err)
}

// Unwrap returns the error category.
func (e *ParseError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// ParseFormat parses the contents of a tracefs event format file. It accepts
// LF, CRLF, and CR line endings.
func ParseFormat(data []byte, options ParseOptions) (*Format, error) {
	maxBytes := options.MaxFormatBytes
	if maxBytes == 0 {
		maxBytes = defaultMaxFormatBytes
	}
	maxFields := options.MaxFields
	if maxFields == 0 {
		maxFields = defaultMaxFields
	}
	if maxBytes < 0 || maxFields < 0 {
		return nil, parseError(1, 1, tracepoint.ErrInvalid, "negative limit")
	}
	if len(data) > maxBytes {
		return nil, parseError(1, 1, tracepoint.ErrLimit, "format exceeds %d bytes", maxBytes)
	}
	if options.LongSize != 0 && options.LongSize != 4 && options.LongSize != 8 {
		return nil, parseError(1, 1, tracepoint.ErrInvalid, "long size must be 4 or 8")
	}
	longSize := options.LongSize
	if longSize == 0 {
		longSize = 8
	}

	format := &Format{System: options.System, LongSize: longSize}
	var haveName, haveID, haveFormat, havePrint bool
	fieldCount := 0
	inFormat := false
	inUserFields := false
	haveFormatField := false
	for _, line := range splitLines(data) {
		text := strings.TrimSpace(line.text)
		if text == "" {
			if inFormat && haveFormatField {
				inUserFields = true
			}
			continue
		}
		column := firstNonSpace(line.text) + 1
		lower := strings.ToLower(text)
		switch {
		case lower == "format:":
			if haveFormat {
				return nil, parseError(line.number, column, tracepoint.ErrInvalid, "duplicate format section")
			}
			haveFormat = true
			inFormat = true
		case strings.HasPrefix(lower, "field:") || strings.HasPrefix(lower, "field special:"):
			if !inFormat {
				return nil, parseError(line.number, column, tracepoint.ErrInvalid, "field before format section")
			}
			field, err := parseFieldLine(text, line.number, column, longSize)
			if err != nil {
				return nil, err
			}
			fieldCount++
			if fieldCount > maxFields {
				return nil, parseError(line.number, column, tracepoint.ErrLimit, "more than %d fields", maxFields)
			}
			if !inUserFields && !strings.HasPrefix(field.Name, "common_") {
				inUserFields = true
			}
			haveFormatField = true
			if !inUserFields {
				format.Common = append(format.Common, field)
			} else {
				format.Fields = append(format.Fields, field)
			}
		case strings.HasPrefix(lower, "print fmt:"):
			if havePrint {
				return nil, parseError(line.number, column, tracepoint.ErrInvalid, "duplicate print fmt")
			}
			havePrint = true
			format.PrintFormat = strings.TrimSpace(text[len("print fmt:"):])
		default:
			name, value, ok := cutProperty(text)
			if !ok {
				return nil, parseError(line.number, column, tracepoint.ErrInvalid, "expected property")
			}
			prop := Property{Name: name, Value: value, Line: line.number, Column: column}
			switch strings.ToLower(name) {
			case "name":
				if haveName {
					return nil, parseError(line.number, column, tracepoint.ErrInvalid, "duplicate name")
				}
				if value == "" {
					return nil, parseError(line.number, column, tracepoint.ErrInvalid, "empty name")
				}
				haveName = true
				format.Name = value
			case "id":
				if haveID {
					return nil, parseError(line.number, column, tracepoint.ErrInvalid, "duplicate ID")
				}
				id, err := strconv.ParseUint(value, 10, 32)
				if err != nil {
					return nil, parseError(line.number, column, tracepoint.ErrInvalid, "invalid ID %q", value)
				}
				haveID = true
				format.ID = uint32(id)
			default:
				format.Properties = append(format.Properties, prop)
			}
		}
	}
	if !haveName {
		return nil, parseError(1, 1, tracepoint.ErrInvalid, "missing name")
	}
	if !haveID {
		return nil, parseError(1, 1, tracepoint.ErrInvalid, "missing ID")
	}
	if !haveFormat {
		return nil, parseError(1, 1, tracepoint.ErrInvalid, "missing format section")
	}
	return format, nil
}

type sourceLine struct {
	text   string
	number int
}

func splitLines(data []byte) []sourceLine {
	lines := make([]sourceLine, 0, 32)
	start, number := 0, 1
	for i := 0; i < len(data); i++ {
		if data[i] != '\r' && data[i] != '\n' {
			continue
		}
		lines = append(lines, sourceLine{string(data[start:i]), number})
		if data[i] == '\r' && i+1 < len(data) && data[i+1] == '\n' {
			i++
		}
		start = i + 1
		number++
	}
	if start < len(data) || len(data) == 0 {
		lines = append(lines, sourceLine{string(data[start:]), number})
	}
	return lines
}

func firstNonSpace(s string) int {
	for i, r := range s {
		if !unicode.IsSpace(r) {
			return i
		}
	}
	return 0
}

func cutProperty(s string) (string, string, bool) {
	at := strings.IndexByte(s, ':')
	if at < 1 {
		return "", "", false
	}
	return strings.TrimSpace(s[:at]), strings.TrimSpace(s[at+1:]), true
}

func parseError(line, column int, category error, format string, args ...any) error {
	return &ParseError{
		Line:   line,
		Column: column,
		Err:    fmt.Errorf("%w: %s", category, fmt.Sprintf(format, args...)),
	}
}

func parseFieldLine(text string, line, column, longSize int) (FieldFormat, error) {
	colon := strings.IndexByte(text, ':')
	if colon < 0 {
		return FieldFormat{}, parseError(line, column, tracepoint.ErrInvalid, "missing field declaration")
	}
	parts := splitSemicolons(text[colon+1:])
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return FieldFormat{}, parseError(line, column+colon+1, tracepoint.ErrInvalid, "missing field declaration")
	}
	declaration := strings.TrimSpace(parts[0])
	field, err := parseDeclaration(declaration, longSize)
	if err != nil {
		return FieldFormat{}, parseError(line, column+colon+1, tracepoint.ErrInvalid, "%v", err)
	}
	field.Declaration = declaration
	field.Line = line
	field.Column = column

	required := map[string]bool{}
	for _, part := range parts[1:] {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, ok := cutProperty(part)
		if !ok {
			return FieldFormat{}, parseError(line, column, tracepoint.ErrInvalid, "malformed field property %q", part)
		}
		key := strings.ToLower(name)
		prop := Property{Name: name, Value: value, Line: line, Column: column}
		switch key {
		case "offset", "size", "signed":
			if required[key] {
				return FieldFormat{}, parseError(line, column, tracepoint.ErrInvalid, "duplicate field property %s", name)
			}
			required[key] = true
			switch key {
			case "offset":
				n, parseErr := parseNonnegativeInt(value)
				if parseErr != nil {
					return FieldFormat{}, parseError(line, column, tracepoint.ErrInvalid, "invalid offset %q", value)
				}
				field.Offset = n
			case "size":
				n, parseErr := parseNonnegativeInt(value)
				if parseErr != nil {
					return FieldFormat{}, parseError(line, column, tracepoint.ErrInvalid, "invalid size %q", value)
				}
				field.Size = n
			case "signed":
				switch value {
				case "0":
					field.Signed = false
				case "1":
					field.Signed = true
				default:
					return FieldFormat{}, parseError(line, column, tracepoint.ErrInvalid, "signed must be 0 or 1")
				}
				field.SignedSet = true
			}
		default:
			field.Properties = append(field.Properties, prop)
		}
	}
	if !required["offset"] || !required["size"] {
		return FieldFormat{}, parseError(line, column, tracepoint.ErrInvalid, "field requires offset and size")
	}
	if field.Offset > math.MaxInt-field.Size {
		return FieldFormat{}, parseError(line, column, tracepoint.ErrInvalid, "field extent overflows")
	}
	if field.Location != LocationNone && field.Size != 2 && field.Size != 4 {
		return FieldFormat{}, parseError(line, column, tracepoint.ErrInvalid, "dynamic location size must be 2 or 4")
	}
	if field.Kind == FieldOpaque && field.Location == LocationNone &&
		field.declarationClass == declarationScalar &&
		(field.Size == 1 || field.Size == 2 || field.Size == 4 || field.Size == 8) {
		field.Width = field.Size
		if field.SignedSet && field.Signed {
			field.Kind = FieldSigned
		} else {
			field.Kind = FieldUnsigned
		}
	}
	if field.Location == LocationNone && field.Size != 0 && field.Kind != FieldOpaque {
		expected := field.Width
		if field.ArrayLen > 0 {
			if field.ArrayLen > math.MaxInt/field.Width {
				return FieldFormat{}, parseError(line, column, tracepoint.ErrInvalid, "array size overflows")
			}
			expected *= field.ArrayLen
		}
		if field.ArrayLen != 0 && expected != field.Size {
			return FieldFormat{}, parseError(line, column, tracepoint.ErrInvalid, "declared width %d disagrees with size %d", expected, field.Size)
		}
	}
	return field, nil
}

func parseNonnegativeInt(s string) (int, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 0, 63)
	if err != nil || n > uint64(math.MaxInt) {
		return 0, errors.New("out of range")
	}
	return int(n), nil
}

func splitSemicolons(s string) []string {
	var parts []string
	start, depth := 0, 0
	for i, r := range s {
		switch r {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ';':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	if start < len(s) {
		parts = append(parts, s[start:])
	}
	return parts
}
