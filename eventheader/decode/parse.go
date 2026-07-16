package decode

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cataggar/LinuxTracepoints-Go/eventheader"
	"github.com/cataggar/LinuxTracepoints-Go/tracepoint"
)

func decodeError(offset int, stage string, err error) error {
	return &tracepoint.DecodeError{Offset: offset, Stage: stage, Err: err}
}

func invalid(offset int, stage, message string) error {
	return decodeError(offset, stage, fmt.Errorf("%w: %s", tracepoint.ErrInvalid, message))
}

func truncated(offset int, stage string) error {
	return decodeError(offset, stage, tracepoint.ErrTruncated)
}

func parseTracepointName(name string) (string, eventheader.Level, uint64, string, error) {
	if len(name) > eventheader.MaxTracepointName {
		return "", 0, 0, "", invalid(0, "tracepoint name", "name is too long")
	}
	marker := strings.LastIndex(name, "_L")
	if marker <= 0 {
		return "", 0, 0, "", invalid(0, "tracepoint name", "missing _L suffix")
	}
	provider := name[:marker]
	if !identifier(provider) {
		return "", 0, 0, "", invalid(0, "tracepoint name", "invalid provider")
	}
	rest := name[marker+2:]
	k := strings.IndexByte(rest, 'K')
	if k <= 0 {
		return "", 0, 0, "", invalid(0, "tracepoint name", "missing keyword")
	}
	levelText := rest[:k]
	rest = rest[k+1:]
	i := 0
	for i < len(rest) && lowerHex(rest[i]) {
		i++
	}
	if i == 0 || !allLowerHex(levelText) {
		return "", 0, 0, "", invalid(0, "tracepoint name", "invalid lowercase hexadecimal level or keyword")
	}
	level64, err := strconv.ParseUint(levelText, 16, 8)
	if err != nil || level64 == 0 || level64 > 5 {
		return "", 0, 0, "", invalid(0, "tracepoint name", "level is out of range")
	}
	keyword, err := strconv.ParseUint(rest[:i], 16, 64)
	if err != nil {
		return "", 0, 0, "", invalid(0, "tracepoint name", "keyword is out of range")
	}
	options := rest[i:]
	for p := 0; p < len(options); {
		if options[p] < 'A' || options[p] > 'Z' {
			return "", 0, 0, "", invalid(0, "tracepoint name", "option must start with an uppercase letter")
		}
		p++
		for p < len(options) && ((options[p] >= 'a' && options[p] <= 'z') ||
			(options[p] >= '0' && options[p] <= '9')) {
			p++
		}
	}
	return provider, eventheader.Level(level64), keyword, options, nil
}

func identifier(s string) bool {
	if s == "" || !asciiLetter(s[0]) && s[0] != '_' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !asciiLetter(s[i]) && (s[i] < '0' || s[i] > '9') && s[i] != '_' {
			return false
		}
	}
	return true
}

func asciiLetter(b byte) bool { return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' }
func lowerHex(b byte) bool    { return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' }
func allLowerHex(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if !lowerHex(s[i]) {
			return false
		}
	}
	return true
}

func (d *Decoder) parse(tracepointName string, data []byte) (*parsedEvent, error) {
	limits := d.Limits.normalized()
	if !limits.valid() {
		return nil, decodeError(0, "limits", tracepoint.ErrLimit)
	}
	if len(data) > limits.MaxEventSize {
		return nil, decodeError(0, "event", tracepoint.ErrLimit)
	}
	provider, nameLevel, keyword, options, err := parseTracepointName(tracepointName)
	if err != nil {
		return nil, err
	}
	if len(data) < 8 {
		return nil, truncated(len(data), "header")
	}
	flags := eventheader.HeaderFlags(data[0])
	const accepted = eventheader.HeaderFlagPointer64 | eventheader.HeaderFlagLittleEndian | eventheader.HeaderFlagExtension
	if flags&^accepted != 0 {
		return nil, invalid(0, "header", "unsupported flag bits")
	}
	var order binary.ByteOrder = binary.BigEndian
	byteOrder := tracepoint.ByteOrderBig
	if flags&eventheader.HeaderFlagLittleEndian != 0 {
		order = binary.LittleEndian
		byteOrder = tracepoint.ByteOrderLittle
	}
	header := eventheader.Header{
		Flags: flags, Version: data[1], ID: order.Uint16(data[2:4]),
		Tag:    eventheader.EventTag(order.Uint16(data[4:6])),
		Opcode: eventheader.Opcode(data[6]), Level: eventheader.Level(data[7]),
	}
	if header.Level != nameLevel {
		return nil, invalid(7, "header", "level does not match tracepoint name")
	}
	info := EventInfo{
		Provider: provider, Keyword: keyword, Options: options, Header: header,
		ByteOrder: byteOrder, Pointer64: flags&eventheader.HeaderFlagPointer64 != 0,
	}
	offset := 8
	var metadata []byte
	metadataOffset := 0
	haveMetadata, haveActivity := false, false
	if flags&eventheader.HeaderFlagExtension != 0 {
		for {
			if len(data)-offset < 4 {
				return nil, truncated(offset, "extension header")
			}
			size := int(order.Uint16(data[offset : offset+2]))
			rawKind := eventheader.ExtensionKind(order.Uint16(data[offset+2 : offset+4]))
			kind := rawKind & eventheader.ExtensionKindMask
			extensionOffset := offset
			offset += 4
			if kind == eventheader.ExtensionInvalid {
				return nil, invalid(extensionOffset+2, "extension", "extension kind is zero")
			}
			if size > len(data)-offset {
				return nil, truncated(offset, "extension data")
			}
			body := data[offset : offset+size]
			offset += size
			switch kind {
			case eventheader.ExtensionMetadata:
				if haveMetadata {
					return nil, invalid(extensionOffset, "extension", "duplicate metadata extension")
				}
				haveMetadata = true
				metadata = body
				metadataOffset = extensionOffset + 4
			case eventheader.ExtensionActivityID:
				if haveActivity {
					return nil, invalid(extensionOffset, "extension", "duplicate activity extension")
				}
				if size != 16 && size != 32 {
					return nil, invalid(extensionOffset, "extension", "activity extension must contain 16 or 32 bytes")
				}
				haveActivity = true
				var activity eventheader.ActivityID
				copy(activity[:], body[:16])
				info.ActivityID = tracepoint.Optional[eventheader.ActivityID]{Value: activity, Present: true}
				if size == 32 {
					var related eventheader.ActivityID
					copy(related[:], body[16:])
					info.RelatedID = tracepoint.Optional[eventheader.ActivityID]{Value: related, Present: true}
				}
			default:
				info.Extensions = append(info.Extensions, Extension{
					Kind: kind, Size: uint16(size),
					Chain:  rawKind&eventheader.ExtensionKindChainFlag != 0,
					Offset: extensionOffset, Data: body,
				})
			}
			if rawKind&eventheader.ExtensionKindChainFlag == 0 {
				break
			}
		}
	}
	if !haveMetadata {
		return nil, invalid(offset, "extension", "exactly one metadata extension is required")
	}
	if len(metadata) > limits.MaxMetadataSize {
		return nil, decodeError(metadataOffset, "metadata", tracepoint.ErrLimit)
	}
	payload := data[offset:]
	if len(payload) > limits.MaxPayloadSize {
		return nil, decodeError(offset, "payload", tracepoint.ErrLimit)
	}
	nul := byteIndex(metadata, 0)
	if nul < 0 {
		return nil, truncated(metadataOffset, "event name")
	}
	if nul == 0 {
		return nil, invalid(metadataOffset, "event name", "event name is empty")
	}
	if containsSemicolon(metadata[:nul]) {
		return nil, invalid(metadataOffset, "event name", "event name contains a semicolon")
	}
	info.EventNameRaw = metadata[:nul]
	info.EventName = replacementString(info.EventNameRaw)
	info.Metadata = metadata
	info.Payload = payload
	if !utf8.Valid(info.EventNameRaw) {
		info.Diagnostics = append(info.Diagnostics, unicodeDiagnostic(metadataOffset, "event name"))
	}
	parser := metadataParser{data: metadata, pos: nul + 1, order: order, limits: limits}
	fields, err := parser.parseTop()
	if err != nil {
		var de *tracepoint.DecodeError
		if errors.As(err, &de) {
			de.Offset += metadataOffset
		}
		return nil, err
	}
	appendNameDiagnostics(&info.Diagnostics, fields, metadataOffset)
	return &parsedEvent{
		info: info, order: order, payload: payload, payloadOffset: offset,
		fields: fields, raw: data,
	}, nil
}

func appendNameDiagnostics(target *[]tracepoint.Diagnostic, fields []*fieldDef, base int) {
	for _, field := range fields {
		if !utf8.Valid(field.nameRaw) {
			*target = append(*target, unicodeDiagnostic(base+field.offset, "field name"))
		}
		appendNameDiagnostics(target, field.children, base)
	}
}

func byteIndex(data []byte, value byte) int {
	for i, b := range data {
		if b == value {
			return i
		}
	}
	return -1
}

func containsSemicolon(data []byte) bool {
	for _, b := range data {
		if b == ';' {
			return true
		}
	}
	return false
}

func replacementString(raw []byte) string { return strings.ToValidUTF8(string(raw), "\ufffd") }

func unicodeDiagnostic(offset int, stage string) tracepoint.Diagnostic {
	return tracepoint.Diagnostic{
		Severity: tracepoint.SeverityError, Offset: offset, Stage: stage,
		Message: "invalid Unicode replaced", Err: tracepoint.ErrInvalid,
	}
}

type metadataParser struct {
	data   []byte
	pos    int
	order  binary.ByteOrder
	limits Limits
	items  int
}

func (p *metadataParser) parseTop() ([]*fieldDef, error) {
	var fields []*fieldDef
	for p.pos < len(p.data) {
		field, err := p.parseField(0)
		if err != nil {
			return nil, err
		}
		fields = append(fields, field)
	}
	return fields, nil
}

func (p *metadataParser) parseField(depth int) (*fieldDef, error) {
	if p.items >= p.limits.MaxItems {
		return nil, decodeError(p.pos, "metadata", tracepoint.ErrLimit)
	}
	start := p.pos
	nul := byteIndex(p.data[p.pos:], 0)
	if nul < 0 {
		return nil, truncated(p.pos, "field name")
	}
	if nul == 0 {
		return nil, invalid(p.pos, "field name", "field name is empty")
	}
	nameRaw := p.data[p.pos : p.pos+nul]
	if containsSemicolon(nameRaw) {
		return nil, invalid(p.pos, "field name", "field name contains a semicolon")
	}
	p.pos += nul + 1
	if p.pos >= len(p.data) {
		return nil, truncated(p.pos, "field encoding")
	}
	encoded := eventheader.FieldEncoding(p.data[p.pos])
	p.pos++
	base := encoded & eventheader.EncodingValueMask
	if base == eventheader.EncodingInvalid {
		return nil, invalid(p.pos-1, "field encoding", "encoding is zero")
	}
	if encoded&eventheader.EncodingCArrayFlag != 0 && encoded&eventheader.EncodingVArrayFlag != 0 {
		return nil, invalid(p.pos-1, "field encoding", "fixed and variable array flags are both set")
	}
	if base > eventheader.EncodingBinaryLength16Char8 {
		return nil, decodeError(p.pos-1, "field encoding", fmt.Errorf("%w: encoding %d", tracepoint.ErrUnsupported, base))
	}
	format := eventheader.FormatDefault
	var tag eventheader.FieldTag
	if encoded&eventheader.EncodingChainFlag != 0 {
		if p.pos >= len(p.data) {
			return nil, truncated(p.pos, "field format")
		}
		format = eventheader.FieldFormat(p.data[p.pos] & byte(eventheader.FormatValueMask))
		formatByte := eventheader.FieldFormat(p.data[p.pos])
		p.pos++
		if formatByte&eventheader.FormatChainFlag != 0 {
			if len(p.data)-p.pos < 2 {
				return nil, truncated(p.pos, "field tag")
			}
			tag = eventheader.FieldTag(p.order.Uint16(p.data[p.pos : p.pos+2]))
			p.pos += 2
		}
	}
	arrayKind := eventheader.ArrayScalar
	var count uint16
	if encoded&eventheader.EncodingCArrayFlag != 0 {
		arrayKind = eventheader.ArrayFixed
		if len(p.data)-p.pos < 2 {
			return nil, truncated(p.pos, "fixed array count")
		}
		count = p.order.Uint16(p.data[p.pos : p.pos+2])
		p.pos += 2
		if count == 0 {
			return nil, invalid(p.pos-2, "fixed array count", "count is zero")
		}
	} else if encoded&eventheader.EncodingVArrayFlag != 0 {
		arrayKind = eventheader.ArrayVariable
	}
	field := &fieldDef{
		name: replacementString(nameRaw), nameRaw: nameRaw, encoding: base,
		format: format, tag: tag, arrayKind: arrayKind, count: count, depth: depth,
		offset: start,
	}
	p.items++
	if base == eventheader.EncodingStruct {
		if encoded&eventheader.EncodingChainFlag == 0 {
			return nil, invalid(start, "struct", "struct encoding has no child count")
		}
		childCount := int(format)
		if childCount == 0 || childCount > 127 {
			return nil, invalid(start, "struct", "child count is outside 1..127")
		}
		if depth+1 > p.limits.MaxDepth {
			return nil, decodeError(start, "struct", tracepoint.ErrLimit)
		}
		for range childCount {
			if p.pos == len(p.data) {
				break
			}
			child, err := p.parseField(depth + 1)
			if err != nil {
				return nil, err
			}
			field.children = append(field.children, child)
		}
	}
	return field, nil
}
