package policy

import (
	"testing"

	"github.com/sylr/op-broker/internal/ref"
)

var (
	sylvain    = Identity{LoginName: "sylvain@formance.com", StableID: "nLAPTOP", NodeName: "laptop"}
	ciByOwner  = Identity{LoginName: "sylvain@formance.com", StableID: "nCI", NodeName: "ci", Tags: []string{"tag:ci"}}
	otherUser  = Identity{LoginName: "eve@example.com", StableID: "nEVE", NodeName: "eve"}
	devbox     = Identity{LoginName: "eve@example.com", StableID: "nDEVBOX", NodeName: "devbox"}
	renamedEve = Identity{LoginName: "eve@example.com", StableID: "nEVE", NodeName: "devbox"}
)

// accounts are the account aliases the tests compile against; work is the
// default.
var accounts = []string{"work", "personal"}

func mustCompile(t *testing.T, rules []Rule) *Policy {
	t.Helper()
	p, err := Compile(rules, accounts, "work")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return p
}

func mustRef(t *testing.T, s string) ref.Ref {
	t.Helper()
	r, err := ref.Parse(s)
	if err != nil {
		t.Fatalf("ref.Parse(%q): %v", s, err)
	}
	return r
}

func TestAllowField(t *testing.T) {
	p := mustCompile(t, []Rule{
		{Principals: []string{"user:Sylvain@Formance.com"}, Read: []string{"op://Dev/**"}, Items: []string{"op://Dev/postgres"}},
		{Principals: []string{"tag:ci"}, Read: []string{"op://CI/deploy-key/private key"}},
		{Principals: []string{"node:nDEVBOX"}, Read: []string{"op://Infra/*/password"}},
		{Principals: []string{"user:eve@example.com", "tag:ops"}, Read: []string{"op://Shared/wifi/password"}},
	})

	tests := []struct {
		name string
		id   Identity
		ref  string
		want bool
	}{
		{"user glob", sylvain, "op://Dev/postgres/password", true},
		{"user glob with section", sylvain, "op://Dev/postgres/conn/host", true},
		{"case-insensitive match", sylvain, "op://dev/POSTGRES/password", true},
		{"query ignored", sylvain, "op://Dev/github/otp?attribute=otp", true},
		{"user outside grant", sylvain, "op://Prod/postgres/password", false},
		{"tagged node does not inherit creator", ciByOwner, "op://Dev/postgres/password", false},
		{"tagged node gets tag grant", ciByOwner, "op://CI/deploy-key/private key", true},
		{"tag grant is exact", ciByOwner, "op://CI/deploy-key/public key", false},
		{"node grant by stable id", devbox, "op://Infra/redis/password", true},
		{"node grant single-segment wildcard", devbox, "op://Infra/redis/section/password", false},
		{"node name is not an identity", renamedEve, "op://Infra/redis/password", false},
		{"principals are ORed", otherUser, "op://Shared/wifi/password", true},
		{"unknown user denied", Identity{LoginName: "mallory@example.com"}, "op://Shared/wifi/password", false},
		{"empty identity denied", Identity{}, "op://Dev/postgres/password", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.AllowField(tt.id, "work", mustRef(t, tt.ref)); got != tt.want {
				t.Fatalf("AllowField(%+v, %s) = %v, want %v", tt.id, tt.ref, got, tt.want)
			}
		})
	}
}

func TestAllowItem(t *testing.T) {
	p := mustCompile(t, []Rule{
		{Principals: []string{"user:sylvain@formance.com"}, Read: []string{"op://Dev/**"}, Items: []string{"op://Dev/postgres", "op://Ops/*"}},
		{Principals: []string{"tag:ci"}, Read: []string{"op://**"}},
	})
	tests := []struct {
		name        string
		id          Identity
		vault, item string
		want        bool
	}{
		{"explicit item", sylvain, "Dev", "postgres", true},
		{"case-insensitive", sylvain, "dev", "Postgres", true},
		{"wildcard item", sylvain, "Ops", "anything", true},
		{"read grant does not imply item", sylvain, "Dev", "github", false},
		{"read-everything does not imply item", ciByOwner, "Dev", "postgres", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.AllowItem(tt.id, "work", tt.vault, tt.item); got != tt.want {
				t.Fatalf("AllowItem(%s/%s) = %v, want %v", tt.vault, tt.item, got, tt.want)
			}
		})
	}
}

func TestDefaultDeny(t *testing.T) {
	p := mustCompile(t, nil)
	if p.AllowField(sylvain, "work", mustRef(t, "op://Dev/postgres/password")) {
		t.Fatal("empty policy allowed a field read")
	}
	if p.AllowItem(sylvain, "work", "Dev", "postgres") {
		t.Fatal("empty policy allowed an item read")
	}
}

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name string
		rule Rule
	}{
		{"no principals", Rule{Read: []string{"op://Dev/**"}}},
		{"no patterns", Rule{Principals: []string{"user:a@b"}}},
		{"bad principal kind", Rule{Principals: []string{"group:admins"}, Read: []string{"op://Dev/**"}}},
		{"empty principal", Rule{Principals: []string{"user:"}, Read: []string{"op://Dev/**"}}},
		{"bare principal", Rule{Principals: []string{"sylvain"}, Read: []string{"op://Dev/**"}}},
		{"missing scheme", Rule{Principals: []string{"user:a@b"}, Read: []string{"Dev/**"}}},
		{"query in pattern", Rule{Principals: []string{"user:a@b"}, Read: []string{"op://Dev/i/f?attribute=otp"}}},
		{"double star not last", Rule{Principals: []string{"user:a@b"}, Read: []string{"op://**/i/f"}}},
		{"too few segments", Rule{Principals: []string{"user:a@b"}, Read: []string{"op://Dev/item"}}},
		{"too many segments", Rule{Principals: []string{"user:a@b"}, Read: []string{"op://a/b/c/d/e"}}},
		{"bad component", Rule{Principals: []string{"user:a@b"}, Read: []string{"op://Dev/it%20em/f"}}},
		{"partial glob", Rule{Principals: []string{"user:a@b"}, Read: []string{"op://Dev/post*/f"}}},
		{"item pattern too long", Rule{Principals: []string{"user:a@b"}, Items: []string{"op://Dev/item/field"}}},
		{"item pattern double star", Rule{Principals: []string{"user:a@b"}, Items: []string{"op://Dev/**"}}},
		{"unknown account", Rule{Principals: []string{"user:a@b"}, Accounts: []string{"other"}, Read: []string{"op://Dev/**"}}},
		{"empty account", Rule{Principals: []string{"user:a@b"}, Accounts: []string{""}, Read: []string{"op://Dev/**"}}},
		{"account UUID instead of alias", Rule{Principals: []string{"user:a@b"}, Accounts: []string{"ABCDEFGHIJKLMNOPQRSTUVWXYZ"}, Read: []string{"op://Dev/**"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Compile([]Rule{tt.rule}, accounts, "work"); err == nil {
				t.Fatalf("Compile(%+v) succeeded, want error", tt.rule)
			}
		})
	}
}

func TestCompileUnknownDefaultAccount(t *testing.T) {
	if _, err := Compile(nil, accounts, "other"); err == nil {
		t.Fatal("Compile accepted an unknown default account")
	}
}

func TestAccounts(t *testing.T) {
	p := mustCompile(t, []Rule{
		// No accounts: the default account only, although the same vault
		// exists in every account.
		{Principals: []string{"user:sylvain@formance.com"}, Read: []string{"op://Private/**"}, Items: []string{"op://Private/*"}},
		{Principals: []string{"user:sylvain@formance.com"}, Accounts: []string{"personal"}, Read: []string{"op://Home/**"}, Items: []string{"op://Home/*"}},
		{Principals: []string{"tag:ci"}, Accounts: []string{"work", "personal"}, Read: []string{"op://CI/**"}},
	})
	tests := []struct {
		name    string
		id      Identity
		account string
		ref     string
		want    bool
	}{
		{"rule without accounts in default", sylvain, "work", "op://Private/a/b", true},
		{"rule without accounts not in other account", sylvain, "personal", "op://Private/a/b", false},
		{"rule with accounts in listed account", sylvain, "personal", "op://Home/a/b", true},
		{"rule with accounts not in default", sylvain, "work", "op://Home/a/b", false},
		{"rule with several accounts, first", ciByOwner, "work", "op://CI/a/b", true},
		{"rule with several accounts, second", ciByOwner, "personal", "op://CI/a/b", true},
		{"unknown account", sylvain, "other", "op://Private/a/b", false},
		{"empty account", sylvain, "", "op://Private/a/b", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.AllowField(tt.id, tt.account, mustRef(t, tt.ref)); got != tt.want {
				t.Fatalf("AllowField(%s, %s) = %v, want %v", tt.account, tt.ref, got, tt.want)
			}
		})
	}

	if !p.AllowItem(sylvain, "work", "Private", "x") || p.AllowItem(sylvain, "personal", "Private", "x") {
		t.Error("items: rule without accounts must cover the default account only")
	}
	if !p.AllowItem(sylvain, "personal", "Home", "x") || p.AllowItem(sylvain, "work", "Home", "x") {
		t.Error("items: rule with accounts must cover those accounts only")
	}
}
