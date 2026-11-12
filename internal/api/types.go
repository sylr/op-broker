// Package api defines the wire types shared by the opbd server and the opb
// client.
package api

import (
	"net/http"
	"regexp"
)

// MaxRefs is the maximum number of refs accepted in one resolve request.
const MaxRefs = 100

// MaxBodyBytes is the maximum size of a request body.
const MaxBodyBytes = 1 << 20

// MaxValueBytes is the maximum total size of the values returned by one
// resolve request.
const MaxValueBytes = 8 << 20

// MaxResponseBytes is the maximum size of an encoded response body. Clients
// refuse larger responses; servers never send them.
const MaxResponseBytes = 16 << 20

// accountAlias is the syntax of account aliases.
var accountAlias = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ValidAccount reports whether s is a well-formed account alias. Aliases are
// names given to 1Password accounts in the opbd configuration; clients only
// ever send aliases, never account IDs.
func ValidAccount(s string) bool { return accountAlias.MatchString(s) }

// ResolveRequest is the body of POST /v1/resolve.
type ResolveRequest struct {
	Refs []string `json:"refs"`
	// Account is the alias of the account to read from. Empty means the
	// server's default account.
	Account string `json:"account,omitempty"`
}

// ResolveResponse maps each ref, as sent by the client, to its value.
type ResolveResponse struct {
	Values map[string]string `json:"values"`
}

// ItemRequest is the body of POST /v1/item.
type ItemRequest struct {
	Vault string `json:"vault"`
	Item  string `json:"item"`
	// Account is as in ResolveRequest.
	Account string `json:"account,omitempty"`
}

// ErrorBody is the body of every non-2xx response.
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail describes a failed request. Refs lists the offending refs when
// a batch was rejected because of some of its members.
type ErrorDetail struct {
	Code    Code     `json:"code"`
	Message string   `json:"message"`
	Refs    []string `json:"refs,omitempty"`
}

// Code is a stable, machine-readable error code.
type Code string

const (
	CodeBadRequest       Code = "bad_request"
	CodeDenied           Code = "denied"
	CodeNotFound         Code = "not_found"
	CodeUnsupportedValue Code = "unsupported_value"
	CodeTooLarge         Code = "too_large"
	CodeOpLocked         Code = "op_locked"
	CodeBusy             Code = "busy"
	CodeOpFailed         Code = "op_failed"
	CodeTimeout          Code = "timeout"
	CodeInternal         Code = "internal"
)

// Status returns the HTTP status associated with the code.
func (c Code) Status() int {
	switch c {
	case CodeBadRequest:
		return http.StatusBadRequest
	case CodeDenied:
		return http.StatusForbidden
	case CodeNotFound:
		return http.StatusNotFound
	case CodeUnsupportedValue, CodeTooLarge:
		return http.StatusUnprocessableEntity
	case CodeOpLocked, CodeBusy:
		return http.StatusServiceUnavailable
	case CodeOpFailed:
		return http.StatusBadGateway
	case CodeTimeout:
		return http.StatusGatewayTimeout
	default:
		return http.StatusInternalServerError
	}
}

// Message returns the generic, human-readable message for the code. Servers
// send this instead of any detail coming from the op CLI.
func (c Code) Message() string {
	switch c {
	case CodeBadRequest:
		return "invalid request"
	case CodeDenied:
		return "access denied"
	case CodeNotFound:
		return "secret reference not found"
	case CodeUnsupportedValue:
		return "value is not valid UTF-8 text"
	case CodeTooLarge:
		return "response would be too large, request fewer or smaller secrets"
	case CodeOpLocked:
		return "1Password is locked or approval is pending on the server"
	case CodeBusy:
		return "server is busy, try again"
	case CodeOpFailed:
		return "1Password CLI failed"
	case CodeTimeout:
		return "timed out waiting for 1Password"
	default:
		return "internal server error"
	}
}
