package tracefs

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

type declToken struct {
	text string
}

type declarationClass uint8

const (
	declarationScalar declarationClass = iota
	declarationAggregate
	declarationArray
)

func parseDeclaration(decl string, longSize int) (FieldFormat, error) {
	decl, err := removeDeclarationAttributes(decl)
	if err != nil {
		return FieldFormat{}, err
	}
	tokens, err := tokenizeDeclaration(decl)
	if err != nil {
		return FieldFormat{}, err
	}
	tokens = stripAttributes(tokens)
	if len(tokens) == 0 {
		return FieldFormat{}, fmt.Errorf("empty declaration")
	}
	field := FieldFormat{ArrayLen: -1}
	filtered := make([]declToken, 0, len(tokens))
	for _, token := range tokens {
		switch token.text {
		case "__data_loc":
			field.Location = LocationData
		case "__rel_loc":
			field.Location = LocationRelative
		default:
			filtered = append(filtered, token)
		}
	}
	tokens = filtered
	if len(tokens) < 2 {
		return FieldFormat{}, fmt.Errorf("declaration has no field name")
	}

	nameIndex := findNameToken(tokens)
	if nameIndex < 0 {
		return FieldFormat{}, fmt.Errorf("declaration has no field name")
	}
	field.Name = tokens[nameIndex].text
	field.Pointer = hasToken(tokens[:nameIndex], "*")

	arrayStart := -1
	if nameIndex+1 < len(tokens) && tokens[nameIndex+1].text == "[" {
		arrayStart = nameIndex + 1
	} else {
		for i := 0; i+1 < nameIndex; i++ {
			if tokens[i].text == "[" && tokens[i+1].text == "]" {
				arrayStart = i
				break
			}
		}
	}
	if arrayStart >= 0 {
		if arrayStart+1 >= len(tokens) {
			return FieldFormat{}, fmt.Errorf("unterminated array")
		}
		if tokens[arrayStart+1].text == "]" {
			field.ArrayLen = 0
		} else {
			if arrayStart+2 >= len(tokens) || tokens[arrayStart+2].text != "]" {
				return FieldFormat{}, fmt.Errorf("invalid array bound")
			}
			n, parseErr := strconv.ParseUint(tokens[arrayStart+1].text, 0, 31)
			if parseErr != nil || n == 0 {
				return FieldFormat{}, fmt.Errorf("invalid array bound %q", tokens[arrayStart+1].text)
			}
			field.ArrayLen = int(n)
		}
	}

	typeWords := make([]string, 0, nameIndex)
	for i, token := range tokens {
		if i == nameIndex || token.text == "*" || token.text == "[" || token.text == "]" || isNumber(token.text) {
			continue
		}
		if isQualifier(token.text) {
			continue
		}
		typeWords = append(typeWords, token.text)
	}
	field.declarationClass = declarationScalar
	for _, word := range typeWords {
		if word == "struct" || word == "union" {
			field.declarationClass = declarationAggregate
			break
		}
	}
	if field.ArrayLen >= 0 {
		field.declarationClass = declarationArray
	}
	classifyType(&field, typeWords, longSize)
	return field, nil
}

func removeDeclarationAttributes(s string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(s); {
		nameLen := attributeNameLength(s[i:])
		if nameLen == 0 || (i > 0 && isIdentContinue(rune(s[i-1]))) {
			out.WriteByte(s[i])
			i++
			continue
		}
		end := i + nameLen
		if end < len(s) && isIdentContinue(rune(s[end])) {
			out.WriteByte(s[i])
			i++
			continue
		}
		for end < len(s) && unicode.IsSpace(rune(s[end])) {
			end++
		}
		if end < len(s) && s[end] == '(' {
			depth := 0
			quote := byte(0)
			escaped := false
			for ; end < len(s); end++ {
				ch := s[end]
				if quote != 0 {
					if escaped {
						escaped = false
					} else if ch == '\\' {
						escaped = true
					} else if ch == quote {
						quote = 0
					}
					continue
				}
				if ch == '\'' || ch == '"' {
					quote = ch
				} else if ch == '(' {
					depth++
				} else if ch == ')' {
					depth--
					if depth == 0 {
						end++
						break
					}
				}
			}
			if depth != 0 || quote != 0 {
				return "", fmt.Errorf("unterminated attribute")
			}
		}
		out.WriteByte(' ')
		i = end
	}
	return out.String(), nil
}

func attributeNameLength(s string) int {
	for _, name := range []string{"__attribute__", "__attribute", "__aligned__", "__aligned", "__packed__", "__packed"} {
		if strings.HasPrefix(s, name) {
			return len(name)
		}
	}
	return 0
}

func tokenizeDeclaration(s string) ([]declToken, error) {
	var tokens []declToken
	for i := 0; i < len(s); {
		r := rune(s[i])
		if unicode.IsSpace(r) {
			i++
			continue
		}
		if isIdentStart(r) {
			start := i
			i++
			for i < len(s) && isIdentContinue(rune(s[i])) {
				i++
			}
			tokens = append(tokens, declToken{s[start:i]})
			continue
		}
		if r >= '0' && r <= '9' {
			start := i
			i++
			for i < len(s) && (isIdentContinue(rune(s[i])) || s[i] == 'x' || s[i] == 'X') {
				i++
			}
			tokens = append(tokens, declToken{s[start:i]})
			continue
		}
		switch s[i] {
		case '*', '[', ']', '(', ')', ',':
			tokens = append(tokens, declToken{s[i : i+1]})
			i++
		default:
			return nil, fmt.Errorf("unexpected character %q", s[i])
		}
	}
	return tokens, nil
}

func stripAttributes(tokens []declToken) []declToken {
	out := make([]declToken, 0, len(tokens))
	for i := 0; i < len(tokens); {
		text := tokens[i].text
		if text == "__attribute__" || text == "__attribute" || strings.HasPrefix(text, "__aligned") {
			i++
			if i < len(tokens) && tokens[i].text == "(" {
				depth := 0
				for i < len(tokens) {
					if tokens[i].text == "(" {
						depth++
					} else if tokens[i].text == ")" {
						depth--
					}
					i++
					if depth == 0 {
						break
					}
				}
			}
			continue
		}
		out = append(out, tokens[i])
		i++
	}
	return out
}

func findNameToken(tokens []declToken) int {
	// A flexible array before the name is tracefs's "__data_loc char[] name"
	// spelling. In all other supported forms, the declarator name is the last
	// identifier outside an attribute.
	for i := 0; i+2 < len(tokens); i++ {
		if tokens[i].text == "[" && tokens[i+1].text == "]" && isIdentifier(tokens[i+2].text) {
			return i + 2
		}
	}
	for i := len(tokens) - 1; i >= 0; i-- {
		if isIdentifier(tokens[i].text) && !isQualifier(tokens[i].text) {
			return i
		}
	}
	return -1
}

func classifyType(field *FieldFormat, words []string, longSize int) {
	lower := make([]string, len(words))
	for i := range words {
		lower[i] = strings.ToLower(words[i])
	}
	joined := strings.Join(lower, " ")
	if field.Pointer {
		field.Kind = FieldUnsigned
		field.Width = longSize
		return
	}
	if len(lower) == 1 {
		if kind, width, signed, ok := sizedAlias(lower[0]); ok {
			field.Kind, field.Width, field.Signed = kind, width, signed
			return
		}
	}
	switch {
	case joined == "char" || joined == "signed char":
		field.Kind, field.Width, field.Signed = FieldChar, 1, joined == "signed char"
	case joined == "unsigned char":
		field.Kind, field.Width = FieldUnsigned, 1
	case strings.Contains(joined, "long long"):
		field.Width = 8
		setIntegerKind(field, strings.Contains(joined, "unsigned"))
	case strings.Contains(joined, "long"):
		field.Width = longSize
		setIntegerKind(field, strings.Contains(joined, "unsigned"))
	case strings.Contains(joined, "short"):
		field.Width = 2
		setIntegerKind(field, strings.Contains(joined, "unsigned"))
	case joined == "int" || joined == "signed" || joined == "signed int":
		field.Kind, field.Width, field.Signed = FieldSigned, 4, true
	case joined == "unsigned" || joined == "unsigned int":
		field.Kind, field.Width = FieldUnsigned, 4
	case joined == "float":
		field.Kind, field.Width = FieldFloat, 4
	case joined == "double":
		field.Kind, field.Width = FieldFloat, 8
	case joined == "bool" || joined == "_bool":
		field.Kind, field.Width = FieldBool, 1
	default:
		field.Kind = FieldOpaque
	}
}

func sizedAlias(word string) (FieldKind, int, bool, bool) {
	aliases := []struct {
		prefix string
		signed bool
	}{
		{"u", false}, {"s", true}, {"__u", false}, {"__s", true},
		{"uint", false}, {"int", true},
	}
	for _, alias := range aliases {
		if !strings.HasPrefix(word, alias.prefix) {
			continue
		}
		suffix := strings.TrimPrefix(word, alias.prefix)
		suffix = strings.TrimSuffix(suffix, "_t")
		bits, err := strconv.Atoi(suffix)
		if err != nil || (bits != 8 && bits != 16 && bits != 32 && bits != 64) {
			continue
		}
		if alias.signed {
			return FieldSigned, bits / 8, true, true
		}
		return FieldUnsigned, bits / 8, false, true
	}
	return FieldOpaque, 0, false, false
}

func setIntegerKind(field *FieldFormat, unsigned bool) {
	if unsigned {
		field.Kind = FieldUnsigned
		field.Signed = false
	} else {
		field.Kind = FieldSigned
		field.Signed = true
	}
}

func hasToken(tokens []declToken, want string) bool {
	for _, token := range tokens {
		if token.text == want {
			return true
		}
	}
	return false
}

func isQualifier(s string) bool {
	switch s {
	case "const", "volatile", "restrict", "__restrict", "__restrict__",
		"static", "register", "__user", "__kernel", "__force", "__bitwise":
		return true
	default:
		return false
	}
}

func isIdentifier(s string) bool {
	if s == "" || !isIdentStart(rune(s[0])) {
		return false
	}
	for _, r := range s[1:] {
		if !isIdentContinue(r) {
			return false
		}
	}
	return true
}

func isIdentStart(r rune) bool {
	return r == '_' || unicode.IsLetter(r)
}

func isIdentContinue(r rune) bool {
	return isIdentStart(r) || unicode.IsDigit(r)
}

func isNumber(s string) bool {
	if s == "" {
		return false
	}
	_, err := strconv.ParseUint(s, 0, 64)
	return err == nil
}
