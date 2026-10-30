package client

import (
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

func TestParseBroker(t *testing.T) {
	for in, want := range map[string]brokerIdentity{
		"user:sylvain@formance.com": {"user", "sylvain@formance.com"},
		"tag:op-broker":             {"tag", "tag:op-broker"},
		"node:nABC123CNTRL":         {"node", "nABC123CNTRL"},
	} {
		got, err := parseBroker(in)
		if err != nil || got != want {
			t.Errorf("parseBroker(%q) = %+v, %v, want %+v", in, got, err, want)
		}
		if got.String() != in {
			t.Errorf("String() = %q, want %q", got.String(), in)
		}
	}
	for _, bad := range []string{"", "op-broker", "tag:", "user:", "group:admins"} {
		if _, err := parseBroker(bad); err == nil {
			t.Errorf("parseBroker(%q) succeeded", bad)
		}
	}
	if _, err := TailscaleVerifier("bogus"); err == nil {
		t.Error("TailscaleVerifier accepted an invalid identity")
	}
	if _, err := TailscaleVerifier(""); err != nil {
		t.Errorf("TailscaleVerifier(\"\"): %v", err)
	}
}

func TestBrokerCheck(t *testing.T) {
	sylvain := &tailcfg.UserProfile{LoginName: "sylvain@formance.com"}
	eve := &tailcfg.UserProfile{LoginName: "eve@example.com"}
	userNode := &tailcfg.Node{StableID: "nBROKER", ComputedName: "op-broker"}
	taggedBySylvain := &tailcfg.Node{StableID: "nTAGGED", ComputedName: "op-broker", Tags: []string{"tag:op-broker"}}

	tests := []struct {
		name    string
		broker  string
		node    *tailcfg.Node
		profile *tailcfg.UserProfile
		ok      bool
	}{
		{"user owns untagged node", "user:sylvain@formance.com", userNode, sylvain, true},
		{"user match is case-insensitive", "user:Sylvain@Formance.com", userNode, sylvain, true},
		{"other user's node", "user:sylvain@formance.com", userNode, eve, false},
		{"tagged node created by the user", "user:sylvain@formance.com", taggedBySylvain, sylvain, false},
		{"missing profile", "user:sylvain@formance.com", userNode, nil, false},
		{"tag match", "tag:op-broker", taggedBySylvain, sylvain, true},
		{"untagged node for tag", "tag:op-broker", userNode, sylvain, false},
		{"pinned node", "node:nBROKER", userNode, eve, true},
		{"other node", "node:nBROKER", taggedBySylvain, sylvain, false},
		{"unknown peer", "user:sylvain@formance.com", nil, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := parseBroker(tt.broker)
			if err != nil {
				t.Fatal(err)
			}
			if err := b.check(tt.node, tt.profile); (err == nil) != tt.ok {
				t.Fatalf("check = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestDefaultBroker(t *testing.T) {
	users := map[tailcfg.UserID]tailcfg.UserProfile{42: {LoginName: "sylvain@formance.com"}}
	tags := views.SliceOf([]string{"tag:ci"})

	got, err := defaultBroker(&ipnstate.Status{Self: &ipnstate.PeerStatus{UserID: 42}, User: users})
	if err != nil || got != (brokerIdentity{"user", "sylvain@formance.com"}) {
		t.Fatalf("defaultBroker(untagged) = %+v, %v", got, err)
	}
	if _, err := defaultBroker(&ipnstate.Status{Self: &ipnstate.PeerStatus{UserID: 42, Tags: &tags}, User: users}); err == nil {
		t.Fatal("tagged machine derived a broker identity from its creator")
	}
	if _, err := defaultBroker(&ipnstate.Status{Self: &ipnstate.PeerStatus{UserID: 7}, User: users}); err == nil {
		t.Fatal("unknown owner accepted")
	}
	if _, err := defaultBroker(&ipnstate.Status{}); err == nil {
		t.Fatal("missing self accepted")
	}
}
