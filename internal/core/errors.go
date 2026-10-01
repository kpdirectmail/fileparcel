package core

import (
	"errors"
	"fmt"
	"net/http"
)

// Error is the error type of every service. Code is the stable machine code
// (API "error.code"), Status the HTTP status, Message a human message safe to
// show to the user, Field the offending input field (for 422), Err an
// optional wrapped cause that is logged but never sent to clients.
//
// errors.Is(err, ErrX) matches by Code, so Invalid("name", "…") Is ErrInvalid
// and Wrap(ErrNotFound, "…", cause) Is ErrNotFound.
type Error struct {
	Code    string
	Status  int
	Message string
	Field   string
	Err     error
}

// Error implements error: "message" or "message: cause".
func (e *Error) Error() string {
	msg := e.Message
	if msg == "" {
		msg = e.Code
	}
	if e.Field != "" {
		msg = e.Field + ": " + msg
	}
	if e.Err != nil {
		return msg + ": " + e.Err.Error()
	}
	return msg
}

// Unwrap returns the wrapped cause.
func (e *Error) Unwrap() error { return e.Err }

// Is matches another *Error with the same Code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// HTTPStatus returns Status (500 when unset).
func (e *Error) HTTPStatus() int {
	if e.Status == 0 {
		return http.StatusInternalServerError
	}
	return e.Status
}

// Sentinel errors (DESIGN §5.1, §9.5). Never modify them; derive new values
// with Wrap, Errorf, Invalid or NotFoundf.
var (
	ErrNotFound          = &Error{Code: "not_found", Status: http.StatusNotFound, Message: "not found"}
	ErrForbidden         = &Error{Code: "forbidden", Status: http.StatusForbidden, Message: "forbidden"}
	ErrUnauthorized      = &Error{Code: "unauthorized", Status: http.StatusUnauthorized, Message: "authentication required"}
	ErrConflict          = &Error{Code: "conflict", Status: http.StatusConflict, Message: "conflict"}
	ErrInvalid           = &Error{Code: "invalid", Status: http.StatusUnprocessableEntity, Message: "invalid input"}
	ErrRateLimited       = &Error{Code: "rate_limited", Status: http.StatusTooManyRequests, Message: "too many requests, slow down"}
	ErrTooLarge          = &Error{Code: "too_large", Status: http.StatusRequestEntityTooLarge, Message: "request too large"}
	ErrQuota             = &Error{Code: "quota_exceeded", Status: http.StatusInsufficientStorage, Message: "storage quota exceeded"}
	ErrKeysLocked        = &Error{Code: "keys_locked", Status: http.StatusServiceUnavailable, Message: "the server is locked; unlock it first"}
	ErrMFARequired       = &Error{Code: "mfa_required", Status: http.StatusUnauthorized, Message: "second factor required"}
	ErrElevationRequired = &Error{Code: "elevation_required", Status: http.StatusForbidden, Message: "please confirm your identity to continue"}
	ErrEnrollRequired    = &Error{Code: "mfa_enroll_required", Status: http.StatusForbidden, Message: "two-factor authentication must be set up first"}
	ErrPrecondition      = &Error{Code: "precondition_failed", Status: http.StatusPreconditionFailed, Message: "precondition failed"}
	ErrNotImplemented    = &Error{Code: "not_implemented", Status: http.StatusNotImplemented, Message: "not implemented"}
	ErrUnavailable       = &Error{Code: "unavailable", Status: http.StatusServiceUnavailable, Message: "service unavailable"}
	// ErrPasswordChangeRequired refuses a session whose password was set by an
	// administrator or the installer until the user chooses their own
	// (Principal.MustChangePassword, DESIGN §9.3).
	ErrPasswordChangeRequired = &Error{Code: "password_change_required", Status: http.StatusForbidden, Message: "choose a new password first"}
	// ErrCSRF refuses an unsafe cookie-session request whose X-FP-CSRF token
	// is missing or belongs to another session — typically a tab still holding
	// the token of the session a sign-in in another tab replaced. Its own code
	// lets the web client re-read the token (GET /me) and retry once; a request
	// blocked as cross-origin stays plain ErrForbidden and is never retried.
	ErrCSRF = &Error{Code: "csrf_invalid", Status: http.StatusForbidden, Message: "missing or invalid CSRF token; reload the page"}
	// ErrCorrupt means stored data failed authentication (blob segment, wrapped
	// key, sealed field, backup archive). DESIGN §7.3: "any auth failure →
	// ErrCorrupt"; never return unauthenticated plaintext. Defined here so that
	// files, uploads, backup and the jobs can test for it without importing
	// blobstore/keys.
	ErrCorrupt = &Error{Code: "corrupt", Status: http.StatusInternalServerError, Message: "stored data failed its integrity check"}
	// ErrInternal is what clients see for unexpected errors (500 "internal").
	// Services should not return it; return the underlying error instead.
	ErrInternal = &Error{Code: "internal", Status: http.StatusInternalServerError, Message: "internal error"}
)

// Invalid returns a 422 "invalid" error for an input field.
func Invalid(field, msg string) error {
	return &Error{Code: ErrInvalid.Code, Status: ErrInvalid.Status, Message: msg, Field: field}
}

// NotFoundf returns a 404 "not_found" error with a formatted message
// (e.g. NotFoundf("folder not found")).
func NotFoundf(format string, a ...any) error {
	return &Error{Code: ErrNotFound.Code, Status: ErrNotFound.Status, Message: fmt.Sprintf(format, a...)}
}

// Wrap returns a copy of base with Message msg (base.Message when msg is "")
// wrapping err (may be nil).
func Wrap(base *Error, msg string, err error) error {
	if msg == "" {
		msg = base.Message
	}
	return &Error{Code: base.Code, Status: base.Status, Message: msg, Field: base.Field, Err: err}
}

// Errorf returns a copy of base with a formatted message.
// Example: core.Errorf(core.ErrConflict, "%q already exists", name).
func Errorf(base *Error, format string, a ...any) error {
	return &Error{Code: base.Code, Status: base.Status, Message: fmt.Sprintf(format, a...), Field: base.Field}
}

// AsError returns the *Error in err's chain, or nil.
func AsError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return nil
}
