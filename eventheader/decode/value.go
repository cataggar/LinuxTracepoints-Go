package decode

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/cataggar/LinuxTracepoints-Go/eventheader"
	"github.com/cataggar/LinuxTracepoints-Go/tracepoint"
)

func fixedWidth(encoding eventheader.FieldEncoding) int {
	switch encoding {
	case eventheader.EncodingValue8:
		return 1
	case eventheader.EncodingValue16:
		return 2
	case eventheader.EncodingValue32:
		return 4
	case eventheader.EncodingValue64:
		return 8
	case eventheader.EncodingValue128:
		return 16
	default:
		return 0
	}
}

func textWidth(encoding eventheader.FieldEncoding) int {
	switch encoding {
	case eventheader.EncodingValue16, eventheader.EncodingZStringChar16,
		eventheader.EncodingStringLength16Char16:
		return 2
	case eventheader.EncodingValue32, eventheader.EncodingZStringChar32,
		eventheader.EncodingStringLength16Char32:
		return 4
	default:
		return 1
	}
}

func unitWidth(encoding eventheader.FieldEncoding) int {
	switch encoding {
	case eventheader.EncodingZStringChar16, eventheader.EncodingStringLength16Char16:
		return 2
	case eventheader.EncodingZStringChar32, eventheader.EncodingStringLength16Char32:
		return 4
	default:
		return 1
	}
}

func readWireValue(def *fieldDef, payload []byte, pos int, order binary.ByteOrder) ([]byte, int, int, error) {
	start := pos
	if width := fixedWidth(def.encoding); width != 0 {
		if len(payload)-pos < width {
			return nil, pos, pos, truncated(pos, "value")
		}
		return payload[pos : pos+width], pos, pos + width, nil
	}
	switch def.encoding {
	case eventheader.EncodingZStringChar8, eventheader.EncodingZStringChar16, eventheader.EncodingZStringChar32:
		width := unitWidth(def.encoding)
		for i := pos; i+width <= len(payload); i += width {
			zero := true
			for _, b := range payload[i : i+width] {
				zero = zero && b == 0
			}
			if zero {
				return payload[pos:i], pos, i + width, nil
			}
		}
		return payload[pos:], pos, len(payload), nil
	case eventheader.EncodingStringLength16Char8,
		eventheader.EncodingStringLength16Char16,
		eventheader.EncodingStringLength16Char32,
		eventheader.EncodingBinaryLength16Char8:
		if len(payload)-pos < 2 {
			return nil, pos, pos, truncated(pos, "value length")
		}
		count := int(order.Uint16(payload[pos : pos+2]))
		pos += 2
		width := 1
		if def.encoding != eventheader.EncodingBinaryLength16Char8 {
			width = unitWidth(def.encoding)
		}
		if count > (len(payload)-pos)/width {
			return nil, start, start, truncated(pos, "value data")
		}
		size := count * width
		return payload[pos : pos+size], pos, pos + size, nil
	default:
		return nil, start, start, decodeError(start, "value", tracepoint.ErrUnsupported)
	}
}

func valueEncoding(def *fieldDef) tracepoint.Encoding {
	switch def.encoding {
	case eventheader.EncodingValue8, eventheader.EncodingValue16,
		eventheader.EncodingValue32, eventheader.EncodingValue64:
		return tracepoint.EncodingInteger
	case eventheader.EncodingValue128, eventheader.EncodingBinaryLength16Char8:
		return tracepoint.EncodingBinary
	case eventheader.EncodingZStringChar8, eventheader.EncodingZStringChar16,
		eventheader.EncodingZStringChar32, eventheader.EncodingStringLength16Char8,
		eventheader.EncodingStringLength16Char16, eventheader.EncodingStringLength16Char32:
		return tracepoint.EncodingUTF8
	default:
		return tracepoint.EncodingNone
	}
}

func formatName(format eventheader.FieldFormat) string {
	names := [...]string{
		"default", "unsigned", "signed", "hex", "errno", "pid", "time",
		"boolean", "float", "hex-bytes", "string8", "string-utf",
		"string-utf-bom", "xml", "json", "uuid", "port", "ip", "ip-obsolete",
	}
	if int(format) < len(names) {
		return names[format]
	}
	return strconv.FormatUint(uint64(format), 10)
}

func decodeScalar(def *fieldDef, raw []byte, offset int, order binary.ByteOrder, byteOrder tracepoint.ByteOrder) tracepoint.Value {
	v := tracepoint.Value{
		Raw: raw, ByteOrder: byteOrder, Encoding: valueEncoding(def),
		Format: formatName(def.format), Width: bitWidth(len(raw)), Valid: true,
	}
	counted := def.encoding >= eventheader.EncodingZStringChar8
	if !formatApplicable(def.encoding, def.format) {
		defaultInterpretation(&v, def, raw, offset, order)
		return v
	}
	if isFixedSemantic(def.format) {
		if counted && len(raw) == 0 {
			v.Kind = tracepoint.ValueNull
			return v
		}
		if decodeSemantic(&v, def.format, raw, offset, order) {
			return v
		}
		defaultInterpretation(&v, def, raw, offset, order)
		return v
	}
	switch def.format {
	case eventheader.FormatUnsignedInt, eventheader.FormatHexInt:
		if u, ok := unsigned(raw, order); ok {
			v.Kind, v.Unsigned = tracepoint.ValueUnsigned, u
		} else {
			defaultInterpretation(&v, def, raw, offset, order)
		}
	case eventheader.FormatSignedInt, eventheader.FormatErrno, eventheader.FormatPID:
		if s, ok := signed(raw, order); ok {
			v.Kind, v.Signed = tracepoint.ValueSigned, s
		} else {
			defaultInterpretation(&v, def, raw, offset, order)
		}
	case eventheader.FormatHexBytes:
		v.Kind, v.Encoding, v.Binary = tracepoint.ValueBinary, tracepoint.EncodingBinary, raw
	case eventheader.FormatString8:
		v.Kind, v.Encoding, v.Text = tracepoint.ValueText, tracepoint.EncodingUTF8, decodeLatin1(raw)
	case eventheader.FormatStringUTF:
		decodeText(&v, raw, textWidth(def.encoding), order, false, offset)
	case eventheader.FormatStringUTFBOM, eventheader.FormatStringXML, eventheader.FormatStringJSON:
		decodeText(&v, raw, textWidth(def.encoding), order, true, offset)
	default:
		defaultInterpretation(&v, def, raw, offset, order)
	}
	return v
}

func formatApplicable(encoding eventheader.FieldEncoding, format eventheader.FieldFormat) bool {
	if format == eventheader.FormatDefault || format > eventheader.FormatIPAddressObsolete {
		return false
	}
	switch encoding {
	case eventheader.EncodingValue8:
		return format == eventheader.FormatUnsignedInt || format == eventheader.FormatSignedInt ||
			format == eventheader.FormatHexInt || format == eventheader.FormatBoolean ||
			format == eventheader.FormatHexBytes || format == eventheader.FormatString8
	case eventheader.EncodingValue16:
		return format == eventheader.FormatUnsignedInt || format == eventheader.FormatSignedInt ||
			format == eventheader.FormatHexInt || format == eventheader.FormatBoolean ||
			format == eventheader.FormatHexBytes || format == eventheader.FormatStringUTF ||
			format == eventheader.FormatPort
	case eventheader.EncodingValue32:
		return format == eventheader.FormatUnsignedInt || format == eventheader.FormatSignedInt ||
			format == eventheader.FormatHexInt || format == eventheader.FormatErrno ||
			format == eventheader.FormatPID || format == eventheader.FormatTime ||
			format == eventheader.FormatBoolean || format == eventheader.FormatFloat ||
			format == eventheader.FormatHexBytes || format == eventheader.FormatStringUTF ||
			format == eventheader.FormatIPAddress || format == eventheader.FormatIPAddressObsolete
	case eventheader.EncodingValue64:
		return format == eventheader.FormatUnsignedInt || format == eventheader.FormatSignedInt ||
			format == eventheader.FormatHexInt || format == eventheader.FormatTime ||
			format == eventheader.FormatFloat || format == eventheader.FormatHexBytes
	case eventheader.EncodingValue128:
		return format == eventheader.FormatHexBytes || format == eventheader.FormatUUID ||
			format == eventheader.FormatIPAddress || format == eventheader.FormatIPAddressObsolete
	case eventheader.EncodingZStringChar8:
		return format == eventheader.FormatHexBytes || format == eventheader.FormatString8 ||
			isUTFStringFormat(format)
	case eventheader.EncodingZStringChar16, eventheader.EncodingZStringChar32,
		eventheader.EncodingStringLength16Char16, eventheader.EncodingStringLength16Char32:
		return format == eventheader.FormatHexBytes || isUTFStringFormat(format)
	case eventheader.EncodingStringLength16Char8, eventheader.EncodingBinaryLength16Char8:
		return true
	default:
		return false
	}
}

func isUTFStringFormat(format eventheader.FieldFormat) bool {
	return format == eventheader.FormatStringUTF || format == eventheader.FormatStringUTFBOM ||
		format == eventheader.FormatStringXML || format == eventheader.FormatStringJSON
}

func isFixedSemantic(format eventheader.FieldFormat) bool {
	switch format {
	case eventheader.FormatUnsignedInt, eventheader.FormatSignedInt, eventheader.FormatHexInt,
		eventheader.FormatErrno, eventheader.FormatPID, eventheader.FormatTime,
		eventheader.FormatBoolean, eventheader.FormatFloat,
		eventheader.FormatUUID, eventheader.FormatPort, eventheader.FormatIPAddress,
		eventheader.FormatIPAddressObsolete:
		return true
	default:
		return false
	}
}

func decodeSemantic(v *tracepoint.Value, format eventheader.FieldFormat, raw []byte, offset int, order binary.ByteOrder) bool {
	switch format {
	case eventheader.FormatUnsignedInt, eventheader.FormatHexInt:
		u, ok := unsigned(raw, order)
		if !ok {
			return false
		}
		v.Kind, v.Encoding, v.Unsigned = tracepoint.ValueUnsigned, tracepoint.EncodingInteger, u
		return true
	case eventheader.FormatSignedInt:
		s, ok := signed(raw, order)
		if !ok {
			return false
		}
		v.Kind, v.Encoding, v.Signed = tracepoint.ValueSigned, tracepoint.EncodingInteger, s
		return true
	case eventheader.FormatErrno, eventheader.FormatPID:
		if len(raw) != 4 {
			return false
		}
		s, _ := signed(raw, order)
		v.Kind, v.Encoding, v.Signed = tracepoint.ValueSigned, tracepoint.EncodingInteger, s
		return true
	case eventheader.FormatBoolean:
		if len(raw) != 1 && len(raw) != 2 && len(raw) != 4 {
			return false
		}
		u, ok := unsigned(raw, order)
		if !ok {
			return false
		}
		v.Kind, v.Encoding = tracepoint.ValueBool, tracepoint.EncodingBoolean
		if u > 1 {
			markInvalid(v, offset, "Boolean value is not 0 or 1")
		} else {
			v.Bool = u != 0
		}
		return true
	case eventheader.FormatFloat:
		v.Kind, v.Encoding = tracepoint.ValueFloat, tracepoint.EncodingFloat
		switch len(raw) {
		case 4:
			v.Float = float64(math.Float32frombits(order.Uint32(raw)))
		case 8:
			v.Float = math.Float64frombits(order.Uint64(raw))
		default:
			return false
		}
		return true
	case eventheader.FormatUUID:
		if len(raw) != 16 {
			return false
		}
		v.Kind, v.Encoding = tracepoint.ValueUUID, tracepoint.EncodingUUID
		copy(v.UUID[:], raw)
		return true
	case eventheader.FormatPort:
		if len(raw) != 2 {
			return false
		}
		v.Kind, v.Encoding, v.Port = tracepoint.ValuePort, tracepoint.EncodingPort, binary.BigEndian.Uint16(raw)
		return true
	case eventheader.FormatIPAddress, eventheader.FormatIPAddressObsolete:
		v.Kind, v.Encoding = tracepoint.ValueIP, tracepoint.EncodingIP
		if len(raw) == 4 {
			var a [4]byte
			copy(a[:], raw)
			v.IP = netip.AddrFrom4(a)
		} else if len(raw) == 16 {
			var a [16]byte
			copy(a[:], raw)
			v.IP = netip.AddrFrom16(a)
		} else {
			return false
		}
		return true
	case eventheader.FormatTime:
		v.Kind, v.Encoding = tracepoint.ValueTime, tracepoint.EncodingTime
		var seconds int64
		switch len(raw) {
		case 4:
			seconds = int64(int32(order.Uint32(raw)))
		case 8:
			seconds = int64(order.Uint64(raw))
		default:
			return false
		}
		if seconds > math.MaxInt64/1_000_000_000 || seconds < math.MinInt64/1_000_000_000 {
			markInvalid(v, offset, "Unix seconds overflow nanosecond timestamp")
			return true
		}
		nanoseconds := seconds * 1_000_000_000
		v.Time = tracepoint.Timestamp{Clock: tracepoint.ClockRealtime, EpochOffsetKnown: true}
		if nanoseconds >= 0 {
			v.Time.Nanoseconds = uint64(nanoseconds)
		} else {
			v.Time.EpochOffset = nanoseconds
		}
		return true
	default:
		return false
	}
}

func bitWidth(bytes int) uint32 {
	if bytes <= 0 {
		return 0
	}
	if uint64(bytes) > math.MaxUint32/8 {
		return math.MaxUint32
	}
	return uint32(bytes * 8)
}

func defaultInterpretation(v *tracepoint.Value, def *fieldDef, raw []byte, offset int, order binary.ByteOrder) {
	switch def.encoding {
	case eventheader.EncodingValue8, eventheader.EncodingValue16,
		eventheader.EncodingValue32, eventheader.EncodingValue64:
		v.Kind, v.Encoding = tracepoint.ValueUnsigned, tracepoint.EncodingInteger
		v.Unsigned, _ = unsigned(raw, order)
	case eventheader.EncodingValue128, eventheader.EncodingBinaryLength16Char8:
		v.Kind, v.Encoding, v.Binary = tracepoint.ValueBinary, tracepoint.EncodingBinary, raw
	case eventheader.EncodingZStringChar8, eventheader.EncodingStringLength16Char8:
		decodeText(v, raw, 1, order, false, offset)
	case eventheader.EncodingZStringChar16, eventheader.EncodingStringLength16Char16:
		decodeText(v, raw, 2, order, false, offset)
	case eventheader.EncodingZStringChar32, eventheader.EncodingStringLength16Char32:
		decodeText(v, raw, 4, order, false, offset)
	default:
		v.Kind, v.Encoding, v.Binary = tracepoint.ValueBinary, tracepoint.EncodingBinary, raw
	}
}

func unsigned(raw []byte, order binary.ByteOrder) (uint64, bool) {
	switch len(raw) {
	case 1:
		return uint64(raw[0]), true
	case 2:
		return uint64(order.Uint16(raw)), true
	case 4:
		return uint64(order.Uint32(raw)), true
	case 8:
		return order.Uint64(raw), true
	default:
		return 0, false
	}
}

func signed(raw []byte, order binary.ByteOrder) (int64, bool) {
	u, ok := unsigned(raw, order)
	if !ok {
		return 0, false
	}
	switch len(raw) {
	case 1:
		return int64(int8(u)), true
	case 2:
		return int64(int16(u)), true
	case 4:
		return int64(int32(u)), true
	default:
		return int64(u), true
	}
}

func decodeLatin1(raw []byte) string {
	runes := make([]rune, len(raw))
	for i, b := range raw {
		runes[i] = rune(b)
	}
	return string(runes)
}

func decodeText(v *tracepoint.Value, raw []byte, width int, order binary.ByteOrder, bom bool, offset int) {
	v.Kind, v.Encoding = tracepoint.ValueText, tracepoint.EncodingUTF8
	if bom {
		switch {
		case len(raw) >= 3 && raw[0] == 0xef && raw[1] == 0xbb && raw[2] == 0xbf:
			raw, width = raw[3:], 1
		case len(raw) >= 4 && string(raw[:4]) == "\x00\x00\xfe\xff":
			raw, width, order = raw[4:], 4, binary.BigEndian
		case len(raw) >= 4 && string(raw[:4]) == "\xff\xfe\x00\x00":
			raw, width, order = raw[4:], 4, binary.LittleEndian
		case len(raw) >= 2 && string(raw[:2]) == "\xfe\xff":
			raw, width, order = raw[2:], 2, binary.BigEndian
		case len(raw) >= 2 && string(raw[:2]) == "\xff\xfe":
			raw, width, order = raw[2:], 2, binary.LittleEndian
		}
	}
	var valid bool
	switch width {
	case 1:
		valid = utf8.Valid(raw)
		v.Text = replacementString(raw)
	case 2:
		v.Text, valid = decodeUTF16(raw, order)
	case 4:
		v.Text, valid = decodeUTF32(raw, order)
	default:
		v.Text = replacementString(raw)
	}
	if !valid {
		markInvalid(v, offset, "invalid Unicode replaced")
	}
}

func decodeUTF16(raw []byte, order binary.ByteOrder) (string, bool) {
	if len(raw)%2 != 0 {
		return string(utf8.RuneError), false
	}
	units := make([]uint16, len(raw)/2)
	valid := true
	for i := range units {
		units[i] = order.Uint16(raw[i*2 : i*2+2])
	}
	for i := 0; i < len(units); i++ {
		if units[i] >= 0xd800 && units[i] <= 0xdbff {
			if i+1 == len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				valid = false
			} else {
				i++
			}
		} else if units[i] >= 0xdc00 && units[i] <= 0xdfff {
			valid = false
		}
	}
	return string(utf16.Decode(units)), valid
}

func decodeUTF32(raw []byte, order binary.ByteOrder) (string, bool) {
	if len(raw)%4 != 0 {
		return string(utf8.RuneError), false
	}
	runes := make([]rune, len(raw)/4)
	valid := true
	for i := range runes {
		r := rune(order.Uint32(raw[i*4 : i*4+4]))
		if !utf8.ValidRune(r) {
			r, valid = utf8.RuneError, false
		}
		runes[i] = r
	}
	return string(runes), valid
}

func markInvalid(v *tracepoint.Value, offset int, message string) {
	v.Valid = false
	v.Diagnostics = append(v.Diagnostics, tracepoint.Diagnostic{
		Severity: tracepoint.SeverityError, Offset: offset, Stage: "value",
		Message: message, Err: fmt.Errorf("%w: %s", tracepoint.ErrInvalid, message),
	})
}
