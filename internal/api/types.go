// Package api defines the wire types shared by the opbd server and the opb
// client.
package api

import "net/http"

// MaxRefs is the maximum number of refs accepted in one resolve request.
const MaxRefs = 100

// MaxBodyBytes is the maximum size of a request body.
const MaxBodyBytes = 1 << 20

// ResolveRequest is the body of POST /v1/resolve.
type ResolveRequest struct {
	Refs []string `json:"refs"`
}

// ResolveResponse maps each ref, as sent by the client, to its value.
type ResolveResponse struct {
	Values map[string]string `json:"values"`
}

// ItemRequest is the body of POST /v1/item.
type ItemRequest struct {
	Vault string `json:"vault"`
	Item  string `json:"item"`
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
	case CodeUnsupportedValue:
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
