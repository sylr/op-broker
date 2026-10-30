package client

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// Verifier checks that the peer at remoteAddr is the broker. It is called on
// every new connection, with the address actually connected to, so a DNS
// answer cannot redirect the client after verification.
type Verifier func(ctx context.Context, remoteAddr string) error

// brokerIdentity is the tailnet identity the broker must have.
type brokerIdentity struct {
	kind  string // "user", "tag" or "node"
	value string // login, full tag ("tag:x") or stable node ID
}

func (b brokerIdentity) String() string {
	if b.kind == "tag" {
		return b.value
	}
	return b.kind + ":" + b.value
}

// parseBroker parses "user:<login>", "tag:<name>" or "node:<stable-id>".
func parseBroker(s string) (brokerIdentity, error) {
	kind, value, ok := strings.Cut(s, ":")
	if !ok || value == "" {
		return brokerIdentity{}, fmt.Errorf("invalid broker identity %q: want user:<login>, tag:<name> or node:<stable-id>", s)
	}
	switch kind {
	case "user", "node":
		return brokerIdentity{kind, value}, nil
	case "tag":
		return brokerIdentity{kind, s}, nil
	default:
		return brokerIdentity{}, fmt.Errorf("invalid broker identity %q: want user:<login>, tag:<name> or node:<stable-id>", s)
	}
}

// check reports whether a peer, as described by WhoIs, is the broker.
//
// A user identity only matches untagged nodes: only that user can register
// such nodes, whereas a tagged node's profile may merely be its creator.
func (b brokerIdentity) check(node *tailcfg.Node, profile *tailcfg.UserProfile) error {
	if node == nil {
		return errors.New("unknown peer")
	}
	ok := false
	switch b.kind {
	case "user":
		ok = !node.IsTagged() && profile != nil && strings.EqualFold(profile.LoginName, b.value)
	case "tag":
		ok = slices.Contains(node.Tags, b.value)
	case "node":
		ok = string(node.StableID) == b.value
	}
	if !ok {
		return fmt.Errorf("refusing to talk to %s: it is not %s", node.ComputedName, b)
	}
	return nil
}

// defaultBroker derives the broker identity from the local node: an untagged
// node expects a broker owned by the same user. A tagged node has no owner
// to derive from and must be configured explicitly.
func defaultBroker(st *ipnstate.Status) (brokerIdentity, error) {
	if st == nil || st.Self == nil {
		return brokerIdentity{}, errors.New("local Tailscale status unavailable")
	}
	if st.Self.Tags != nil && st.Self.Tags.Len() > 0 {
		return brokerIdentity{}, errors.New("this machine is a tagged node: set OPB_BROKER (or --broker) to the broker's identity, e.g. user:<login>")
	}
	profile, ok := st.User[st.Self.UserID]
	if !ok || profile.LoginName == "" {
		return brokerIdentity{}, errors.New("cannot determine the owner of this machine: set OPB_BROKER (or --broker)")
	}
	return brokerIdentity{"user", profile.LoginName}, nil
}

// TailscaleVerifier returns a Verifier that asks the local Tailscale daemon
// who owns the connected address and requires it to match expected
// ("user:<login>", "tag:<name>" or "node:<stable-id>"). If expected is
// empty, the broker must be an untagged node owned by the same user as this
// machine. It fails closed when the local daemon is unreachable.
func TailscaleVerifier(expected string) (Verifier, error) {
	var want *brokerIdentity
	if expected != "" {
		b, err := parseBroker(expected)
		if err != nil {
			return nil, err
		}
		want = &b
	}
	lc := &local.Client{}
	return func(ctx context.Context, remoteAddr string) error {
		b := want
		if b == nil {
			st, err := lc.StatusWithoutPeers(ctx)
			if err != nil {
				return fmt.Errorf("reading local Tailscale status: %w", err)
			}
			d, err := defaultBroker(st)
			if err != nil {
				return err
			}
			b = &d
		}
		res, err := lc.WhoIs(ctx, remoteAddr)
		if err != nil {
			return fmt.Errorf("verifying broker identity with the local Tailscale daemon: %w", err)
		}
		if err := b.check(res.Node, res.UserProfile); err != nil {
			return fmt.Errorf("%w (%s)", err, remoteAddr)
		}
		return nil
	}, nil
}
