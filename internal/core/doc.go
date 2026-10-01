// Package core is the FileParcel domain contract (DESIGN §5.1, §5.1b): the
// service interfaces every unit implements, the model structs whose json tags
// ARE the HTTP API schema, the Principal, the error type and pagination.
//
// Conventions (read before implementing a service or a handler):
//
//   - JSON field names are snake_case. Timestamps are time.Time (RFC 3339 in
//     JSON, INTEGER Unix ms UTC in the DB; use db.Ms/db.FromMs). Nullable
//     timestamps are *time.Time with omitempty. Secrets and hashes are never
//     serialized (json:"-"); input-only secrets (passwords in *Input types)
//     have json tags so they can be decoded, but they are never echoed.
//   - IDs are strings "<prefix>_<26 chars>" (package ids). Blob IDs are 32 hex.
//   - Every exported service method returns *Error values (or errors wrapping
//     them) for expected failures; handlers map them with httpx.Error. Any
//     other error becomes a 500 "internal".
//   - Request/response bodies that are not a single model (GET /me,
//     /auth/state, move/trash inputs, public share info, …) are in api.go.
//   - Lists are keyset-paginated: PageReq in, Page[T] out; cursors are opaque
//     (httpx.EncodeCursor/DecodeCursor); default limit 100, max 500.
//   - Services receive a *Principal ("by"/"p") for authorization and audit.
//     SystemPrincipal is used by the admin socket and the offline CLI.
//   - A service must not import another service's concrete package; it uses
//     the interfaces here, received via its constructor (DESIGN §5.2) or the
//     optional Binder hook (hooks.go).
//
// Import rule: core imports only the standard library and home, config, db,
// events, buildinfo.
package core
