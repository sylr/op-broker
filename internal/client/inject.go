package client

import (
	"fmt"
	"strings"
)

// Template is a parsed inject template. The supported syntax is a subset of
// `op inject`: secret references enclosed in double braces, with optional
// whitespace inside the braces, e.g. "{{ op://vault/item/field }}".
// References may contain $VAR or ${VAR}, expanded from the client
// environment before the reference is sent to the server. Any other
// template syntax is rejected.
type Template struct {
	segments []segment
}

type segment struct {
	text  string // literal text, or the expanded reference if isRef
	isRef bool
}

// ParseTemplate parses src. lookupEnv resolves variables used in references.
func ParseTemplate(src string, lookupEnv func(string) (string, bool)) (*Template, error) {
	t := &Template{}
	pos := 0
	for {
		open := strings.Index(src[pos:], "{{")
		if open < 0 {
			if err := checkLiteral(src, pos, len(src)); err != nil {
				return nil, err
			}
			t.segments = append(t.segments, segment{text: src[pos:]})
			return t, nil
		}
		open += pos
		if err := checkLiteral(src, pos, open); err != nil {
			return nil, err
		}
		t.segments = append(t.segments, segment{text: src[pos:open]})

		end := strings.Index(src[open+2:], "}}")
		if end < 0 {
			return nil, fmt.Errorf("line %d: unclosed {{", lineOf(src, open))
		}
		end += open + 2
		inner := strings.TrimSpace(src[open+2 : end])
		if !strings.HasPrefix(inner, "op://") || strings.Contains(inner, "{{") {
			return nil, fmt.Errorf("line %d: unsupported template expression {{%s}} (only {{ op://... }} is supported)", lineOf(src, open), src[open+2:end])
		}
		expanded, err := expandVars(inner, lookupEnv)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineOf(src, open), err)
		}
		t.segments = append(t.segments, segment{text: expanded, isRef: true})
		pos = end + 2
	}
}

// Refs returns the distinct references used by the template.
func (t *Template) Refs() []string {
	var refs []string
	seen := make(map[string]bool)
	for _, s := range t.segments {
		if s.isRef && !seen[s.text] {
			seen[s.text] = true
			refs = append(refs, s.text)
		}
	}
	return refs
}

// Render substitutes values in a single pass: values are never interpreted
// as template syntax.
func (t *Template) Render(values map[string]string) ([]byte, error) {
	var b strings.Builder
	for _, s := range t.segments {
		if !s.isRef {
			b.WriteString(s.text)
			continue
		}
		v, ok := values[s.text]
		if !ok {
			return nil, fmt.Errorf("no value for %s", s.text)
		}
		b.WriteString(v)
	}
	return []byte(b.String()), nil
}

// checkLiteral rejects bare secret references, which `op inject` may resolve
// but this subset does not: leaving them unresolved would be silent.
func checkLiteral(src string, from, to int) error {
	if i := strings.Index(src[from:to], "op://"); i >= 0 {
		return fmt.Errorf("line %d: bare secret reference; enclose it in {{ }}", lineOf(src, from+i))
	}
	return nil
}

func lineOf(src string, pos int) int {
	return strings.Count(src[:pos], "\n") + 1
}

// expandVars expands $NAME and ${NAME}. Unset variables, defaults and any
// other use of '$' are errors.
func expandVars(s string, lookupEnv func(string) (string, bool)) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			b.WriteByte(s[i])
			continue
		}
		var name string
		switch {
		case i+1 < len(s) && s[i+1] == '{':
			end := strings.IndexByte(s[i+2:], '}')
			if end < 0 {
				return "", fmt.Errorf("unclosed ${ in %q", s)
			}
			name = s[i+2 : i+2+end]
			i += 2 + end
		default:
			j := i + 1
			for j < len(s) && isNameChar(s[j], j == i+1) {
				j++
			}
			name = s[i+1 : j]
			i = j - 1
		}
		if !validName(name) {
			return "", fmt.Errorf("unsupported variable syntax in %q", s)
		}
		v, ok := lookupEnv(name)
		if !ok {
			return "", fmt.Errorf("variable %s is not set", name)
		}
		b.WriteString(v)
	}
	return b.String(), nil
}

func isNameChar(c byte, first bool) bool {
	return c == '_' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || !first && '0' <= c && c <= '9'
}

func validName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if !isNameChar(name[i], i == 0) {
			return false
		}
	}
	return true
}
