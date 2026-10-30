package client

import (
	"slices"
	"testing"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func TestTemplate(t *testing.T) {
	src := "user: {{ op://Dev/db/user }}\npass: {{op://Dev/db/password}}\nagain: {{  op://Dev/db/user  }}\nenv: {{ op://$VAULT/${ITEM}/password }}\n"
	tpl, err := ParseTemplate(src, env(map[string]string{"VAULT": "Prod", "ITEM": "db"}))
	if err != nil {
		t.Fatal(err)
	}
	wantRefs := []string{"op://Dev/db/user", "op://Dev/db/password", "op://Prod/db/password"}
	if refs := tpl.Refs(); !slices.Equal(refs, wantRefs) {
		t.Fatalf("Refs = %v, want %v", refs, wantRefs)
	}
	out, err := tpl.Render(map[string]string{
		"op://Dev/db/user":      "admin",
		"op://Dev/db/password":  "{{ op://Dev/db/user }}", // must not be expanded again
		"op://Prod/db/password": "p$ROD",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "user: admin\npass: {{ op://Dev/db/user }}\nagain: admin\nenv: p$ROD\n"
	if string(out) != want {
		t.Fatalf("Render = %q, want %q", out, want)
	}
}

func TestTemplateNoRefs(t *testing.T) {
	tpl, err := ParseTemplate("plain text } { }}\n", env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(tpl.Refs()) != 0 {
		t.Fatalf("Refs = %v", tpl.Refs())
	}
	out, _ := tpl.Render(nil)
	if string(out) != "plain text } { }}\n" {
		t.Fatalf("Render = %q", out)
	}
}

func TestTemplateErrors(t *testing.T) {
	tests := map[string]string{
		"unclosed":          "a {{ op://Dev/db/user",
		"non-ref":           "{{ .Values.foo }}",
		"escape":            `{{ "{{" }}`,
		"nested":            "{{ op://Dev/{{x}} }}",
		"bare ref":          "url: op://Dev/db/user\n",
		"unset var":         "{{ op://$MISSING/db/user }}",
		"default":           "{{ op://${VAULT:-Dev}/db/user }}",
		"dollar alone":      "{{ op://Dev/db/user$ }}",
		"unclosed var":      "{{ op://${VAULT/db/user }}",
		"empty braces":      "{{ }}",
		"ref in empty name": "{{ op://${}/db/user }}",
	}
	for name, src := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseTemplate(src, env(map[string]string{"VAULT": "Dev"})); err == nil {
				t.Fatalf("ParseTemplate(%q) succeeded", src)
			}
		})
	}
}
