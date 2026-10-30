package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/sylr/op-broker/internal/api"
	"github.com/sylr/op-broker/internal/client"
)

func TestFailExitCodes(t *testing.T) {
	tests := []struct {
		err  error
		want int
	}{
		{&client.Error{Code: api.CodeDenied}, exitDenied},
		{fmt.Errorf("wrapped: %w", &client.Error{Code: api.CodeDenied}), exitDenied},
		{&client.Error{Code: api.CodeOpLocked}, exitLocked},
		{&client.Error{Code: api.CodeTimeout}, exitLocked},
		{&client.Error{Code: api.CodeNotFound}, exitError},
		{&client.Error{Code: api.CodeOpFailed}, exitError},
		{&client.Error{Code: api.CodeBadRequest}, exitError},
		{errors.New("connection refused"), exitError},
		{errUsage{}, exitError},
		{flag.ErrHelp, exitOK},
	}
	for _, tt := range tests {
		if got := fail(tt.err); got != tt.want {
			t.Errorf("fail(%v) = %d, want %d", tt.err, got, tt.want)
		}
	}
}

func TestParseInterspersed(t *testing.T) {
	tests := []struct {
		args      []string
		wantPos   []string
		wantVault string
	}{
		{[]string{"get", "item", "--vault", "Dev"}, []string{"get", "item"}, "Dev"},
		{[]string{"--vault=Dev", "get", "item"}, []string{"get", "item"}, "Dev"},
		{[]string{"get", "--vault", "Dev", "item"}, []string{"get", "item"}, "Dev"},
		{[]string{"get", "--", "--vault"}, []string{"get", "--vault"}, ""},
		{[]string{"--vault", "Dev", "--", "get", "-x"}, []string{"get", "-x"}, "Dev"},
	}
	for _, tt := range tests {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		vault := fs.String("vault", "", "")
		pos, err := parseInterspersed(fs, tt.args)
		if err != nil {
			t.Errorf("%v: %v", tt.args, err)
			continue
		}
		if !slices.Equal(pos, tt.wantPos) || *vault != tt.wantVault {
			t.Errorf("%v: pos=%v vault=%q, want pos=%v vault=%q", tt.args, pos, *vault, tt.wantPos, tt.wantVault)
		}
	}
}

func TestParseInterspersedUnknownFlag(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if _, err := parseInterspersed(fs, []string{"get", "--bogus"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
}
