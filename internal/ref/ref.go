// Package ref parses 1Password secret references (op://...) into a strict
// canonical form. The same parsed value is used for authorization and for
// invoking the op CLI, so what is checked is exactly what is executed.
package ref

import (
	"errors"
	"fmt"
	"strings"
)

const (
	scheme = "op://"

	// MaxRefLen bounds the length of a whole reference.
	MaxRefLen = 1024
	// MaxComponentLen bounds the length of a single path component.
	MaxComponentLen = 256
)

// Query keys and their accepted values. "attr" is an alias of "attribute".
var queryValues = map[string]map[string]bool{
	"attribute": {
		"type": true, "value": true, "id": true, "purpose": true, "label": true,
		"otp": true, "totp": true, "content": true, "size": true, "name": true,
	},
	"ssh-format": {"openssh": true},
}

// Ref is a parsed secret reference.
type Ref struct {
	Vault   string
	Item    string
	Section string // optional
	Field   string

	// QueryKey and QueryValue hold the optional single query parameter, with
	// QueryKey canonicalized ("attr" becomes "attribute").
	QueryKey   string
	QueryValue string
}

// Parse parses s strictly. It never decodes, cleans or normalizes the path:
// anything outside the supported grammar is rejected.
func Parse(s string) (Ref, error) {
	if len(s) > MaxRefLen {
		return Ref{}, errors.New("reference too long")
	}
	rest, ok := strings.CutPrefix(s, scheme)
	if !ok {
		return Ref{}, errors.New("reference must start with op://")
	}

	path, query, hasQuery := strings.Cut(rest, "?")
	segs := strings.Split(path, "/")
	if len(segs) != 3 && len(segs) != 4 {
		return Ref{}, errors.New("reference must be op://vault/item/[section/]field")
	}
	for _, seg := range segs {
		if err := ValidComponent(seg); err != nil {
			return Ref{}, err
		}
	}

	r := Ref{Vault: segs[0], Item: segs[1], Field: segs[len(segs)-1]}
	if len(segs) == 4 {
		r.Section = segs[2]
	}

	if hasQuery {
		key, value, ok := strings.Cut(query, "=")
		if !ok || strings.ContainsAny(value, "&=?#") {
			return Ref{}, errors.New("query must be a single key=value pair")
		}
		if key == "attr" {
			key = "attribute"
		}
		values, ok := queryValues[key]
		if !ok {
			return Ref{}, fmt.Errorf("unsupported query key %q", key)
		}
		if !values[value] {
			return Ref{}, fmt.Errorf("unsupported %s value %q", key, value)
		}
		r.QueryKey, r.QueryValue = key, value
	}
	return r, nil
}

// String returns the canonical form of the reference.
func (r Ref) String() string {
	var b strings.Builder
	b.WriteString(scheme)
	for i, seg := range r.Segments() {
		if i > 0 {
			b.WriteByte('/')
		}
		b.WriteString(seg)
	}
	if r.QueryKey != "" {
		b.WriteByte('?')
		b.WriteString(r.QueryKey)
		b.WriteByte('=')
		b.WriteString(r.QueryValue)
	}
	return b.String()
}

// Segments returns the path components: vault, item, [section,] field.
func (r Ref) Segments() []string {
	if r.Section != "" {
		return []string{r.Vault, r.Item, r.Section, r.Field}
	}
	return []string{r.Vault, r.Item, r.Field}
}

// ValidComponent reports whether s is a valid vault, item, section or field
// name. 1Password references only support ASCII letters, digits, '-', '_',
// '.' and spaces; anything else must be addressed by ID. Leading or trailing
// spaces and dot-only names are rejected to avoid ambiguity.
func ValidComponent(s string) error {
	if s == "" {
		return errors.New("empty reference component")
	}
	if len(s) > MaxComponentLen {
		return errors.New("reference component too long")
	}
	if s[0] == ' ' || s[len(s)-1] == ' ' {
		return fmt.Errorf("reference component %q has leading or trailing space", s)
	}
	if strings.Trim(s, ".") == "" {
		return fmt.Errorf("invalid reference component %q", s)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '-', c == '_', c == '.', c == ' ':
		default:
			return fmt.Errorf("unsupported character %q in reference component (use the ID instead)", c)
		}
	}
	return nil
}
