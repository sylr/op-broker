package ref

import (
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	tests := []struct {
		in   string
		want Ref
		str  string
	}{
		{
			in:   "op://Dev/postgres/password",
			want: Ref{Vault: "Dev", Item: "postgres", Field: "password"},
			str:  "op://Dev/postgres/password",
		},
		{
			in:   "op://Dev/My Item/db section/pass word",
			want: Ref{Vault: "Dev", Item: "My Item", Section: "db section", Field: "pass word"},
			str:  "op://Dev/My Item/db section/pass word",
		},
		{
			in:   "op://abc123def/x_y-z.1/one-time password?attr=otp",
			want: Ref{Vault: "abc123def", Item: "x_y-z.1", Field: "one-time password", QueryKey: "attribute", QueryValue: "otp"},
			str:  "op://abc123def/x_y-z.1/one-time password?attribute=otp",
		},
		{
			in:   "op://V/I/F?attribute=type",
			want: Ref{Vault: "V", Item: "I", Field: "F", QueryKey: "attribute", QueryValue: "type"},
			str:  "op://V/I/F?attribute=type",
		},
		{
			in:   "op://V/key/private key?ssh-format=openssh",
			want: Ref{Vault: "V", Item: "key", Field: "private key", QueryKey: "ssh-format", QueryValue: "openssh"},
			str:  "op://V/key/private key?ssh-format=openssh",
		},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := Parse(tt.in)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("Parse(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
			if s := got.String(); s != tt.str {
				t.Fatalf("String() = %q, want %q", s, tt.str)
			}
			again, err := Parse(got.String())
			if err != nil || again != got {
				t.Fatalf("canonical form does not round-trip: %+v, %v", again, err)
			}
		})
	}
}

func TestParseInvalid(t *testing.T) {
	tests := []string{
		"",
		"Dev/item/field",
		"OP://Dev/item/field",
		"op:/Dev/item/field",
		"op://Dev/item",
		"op://Dev/item/a/b/c",
		"op://Dev/item/field/",
		"op:///item/field",
		"op://Dev//field",
		"op://Dev/item/fi%20eld",
		"op://user@Dev/item/field",
		"op://Dev:443/item/field",
		"op://Dev/item/field#frag",
		`op://Dev/item\x/field`,
		"op://Dev/*/field",
		"op://Dev/**/field",
		"op://Dev/../field",
		"op://Dev/./field",
		"op://Dev/ item/field",
		"op://Dev/item /field",
		"op://Dev/item/field\n",
		"op://Dev/it\x00em/field",
		"op://Dév/item/field",
		"op://-/item/field?",
		"op://Dev/item/field?",
		"op://Dev/item/field?attribute",
		"op://Dev/item/field?attribute=",
		"op://Dev/item/field?attribute=bogus",
		"op://Dev/item/field?foo=bar",
		"op://Dev/item/field?attribute=otp&attribute=type",
		"op://Dev/item/field?attribute=otp?x",
		"op://Dev/item/field?ssh-format=pem",
		"op://Dev/item/field?ATTRIBUTE=otp",
		"op://Dev/" + strings.Repeat("a", MaxComponentLen+1) + "/field",
		"op://Dev/item/" + strings.Repeat("a/", MaxRefLen),
	}
	for _, in := range tests {
		t.Run(in, func(t *testing.T) {
			if r, err := Parse(in); err == nil {
				t.Fatalf("Parse(%q) = %+v, want error", in, r)
			}
		})
	}
}

func TestValidComponent(t *testing.T) {
	for _, ok := range []string{"a", "Dev", "a.b", "a b", "x-y_z", "...a"} {
		if err := ValidComponent(ok); err != nil {
			t.Errorf("ValidComponent(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "a/b", "..", ".", " a", "a ", "a\tb", "https:", "é"} {
		if err := ValidComponent(bad); err == nil {
			t.Errorf("ValidComponent(%q) = nil, want error", bad)
		}
	}
}
