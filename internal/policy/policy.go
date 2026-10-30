// Package policy decides which tailnet callers may read which secrets.
//
// A rule grants its read and items patterns to any of its principals (the
// principals of a rule are ORed). Anything not granted by some rule is
// denied.
package policy

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/sylr/op-broker/internal/ref"
)

// Identity is a caller as identified by Tailscale WhoIs.
type Identity struct {
	LoginName string   // owner of the node; ignored for tagged nodes
	StableID  string   // Node.StableID
	NodeName  string   // Node.ComputedName, for logs only
	Tags      []string // ACL tags, e.g. "tag:ci"
}

// Tagged reports whether the node is tagged. A tagged node's identity is its
// tags: its UserProfile may still be the user who created it.
func (id Identity) Tagged() bool { return len(id.Tags) > 0 }

// Rule is a policy rule as written in the configuration file.
type Rule struct {
	Principals []string `yaml:"principals"`
	Read       []string `yaml:"read"`
	Items      []string `yaml:"items"`
}

// Policy is a compiled, validated set of rules.
type Policy struct {
	rules []rule
}

type principalKind int

const (
	principalUser principalKind = iota
	principalTag
	principalNode
)

type principal struct {
	kind  principalKind
	value string
}

type rule struct {
	principals []principal
	read       []pattern
	items      []pattern
}

// pattern is a list of segments. "*" matches exactly one segment and a final
// "**" matches one or more remaining segments.
type pattern []string

// Compile validates rules and returns the policy. Any invalid principal or
// pattern is an error.
func Compile(rules []Rule) (*Policy, error) {
	p := &Policy{}
	for i, r := range rules {
		var cr rule
		if len(r.Principals) == 0 {
			return nil, fmt.Errorf("rule %d: no principals", i)
		}
		if len(r.Read) == 0 && len(r.Items) == 0 {
			return nil, fmt.Errorf("rule %d: no read or items patterns", i)
		}
		for _, s := range r.Principals {
			pr, err := parsePrincipal(s)
			if err != nil {
				return nil, fmt.Errorf("rule %d: %w", i, err)
			}
			cr.principals = append(cr.principals, pr)
		}
		for _, s := range r.Read {
			pat, err := parseReadPattern(s)
			if err != nil {
				return nil, fmt.Errorf("rule %d: read pattern %q: %w", i, s, err)
			}
			cr.read = append(cr.read, pat)
		}
		for _, s := range r.Items {
			pat, err := parseItemPattern(s)
			if err != nil {
				return nil, fmt.Errorf("rule %d: items pattern %q: %w", i, s, err)
			}
			cr.items = append(cr.items, pat)
		}
		p.rules = append(p.rules, cr)
	}
	return p, nil
}

// AllowField reports whether id may read the field referenced by r. The query
// part of the reference is not considered: a grant covers every attribute of
// a field.
func (p *Policy) AllowField(id Identity, r ref.Ref) bool {
	segs := r.Segments()
	for _, cr := range p.rules {
		if cr.matchesIdentity(id) && slices.ContainsFunc(cr.read, func(pat pattern) bool { return pat.match(segs) }) {
			return true
		}
	}
	return false
}

// AllowItem reports whether id may read the whole item. Only items patterns
// are considered: field grants never imply item access.
func (p *Policy) AllowItem(id Identity, vault, item string) bool {
	segs := []string{vault, item}
	for _, cr := range p.rules {
		if cr.matchesIdentity(id) && slices.ContainsFunc(cr.items, func(pat pattern) bool { return pat.match(segs) }) {
			return true
		}
	}
	return false
}

func (r rule) matchesIdentity(id Identity) bool {
	for _, pr := range r.principals {
		switch pr.kind {
		case principalUser:
			if !id.Tagged() && id.LoginName != "" && strings.EqualFold(pr.value, id.LoginName) {
				return true
			}
		case principalTag:
			if slices.Contains(id.Tags, pr.value) {
				return true
			}
		case principalNode:
			if id.StableID != "" && pr.value == id.StableID {
				return true
			}
		}
	}
	return false
}

func parsePrincipal(s string) (principal, error) {
	kind, value, ok := strings.Cut(s, ":")
	if !ok || value == "" {
		return principal{}, fmt.Errorf("invalid principal %q: want user:<login>, tag:<name> or node:<stable-id>", s)
	}
	switch kind {
	case "user":
		return principal{principalUser, value}, nil
	case "tag":
		// Tailscale reports tags with their "tag:" prefix.
		return principal{principalTag, s}, nil
	case "node":
		return principal{principalNode, value}, nil
	default:
		return principal{}, fmt.Errorf("invalid principal %q: unknown kind %q", s, kind)
	}
}

func parseSegments(s string) (pattern, error) {
	rest, ok := strings.CutPrefix(s, "op://")
	if !ok {
		return nil, errors.New("must start with op://")
	}
	if strings.Contains(rest, "?") {
		return nil, errors.New("query parameters are not allowed in patterns")
	}
	pat := pattern(strings.Split(rest, "/"))
	for i, seg := range pat {
		switch seg {
		case "*":
		case "**":
			if i != len(pat)-1 {
				return nil, errors.New(`"**" is only allowed as the last segment`)
			}
		default:
			if err := ref.ValidComponent(seg); err != nil {
				return nil, err
			}
		}
	}
	return pat, nil
}

func parseReadPattern(s string) (pattern, error) {
	pat, err := parseSegments(s)
	if err != nil {
		return nil, err
	}
	if pat[len(pat)-1] == "**" {
		if len(pat) > 4 {
			return nil, errors.New("too many segments")
		}
		return pat, nil
	}
	if len(pat) != 3 && len(pat) != 4 {
		return nil, errors.New("must be op://vault/item/[section/]field (or end with **)")
	}
	return pat, nil
}

func parseItemPattern(s string) (pattern, error) {
	pat, err := parseSegments(s)
	if err != nil {
		return nil, err
	}
	if len(pat) != 2 || slices.Contains(pat, "**") {
		return nil, errors.New("must be op://vault/item (wildcard * allowed)")
	}
	return pat, nil
}

func (pat pattern) match(segs []string) bool {
	for i, p := range pat {
		if p == "**" {
			return len(segs) > i
		}
		if i >= len(segs) {
			return false
		}
		if p != "*" && !strings.EqualFold(p, segs[i]) {
			return false
		}
	}
	return len(segs) == len(pat)
}
