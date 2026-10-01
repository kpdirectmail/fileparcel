package core

import (
	"encoding/json"
	"time"
)

// Shared HTTP request/response bodies for endpoints whose body is not a single
// model struct (DESIGN §9.4). Handlers decode/encode exactly these types, the
// CLI and the frontend read them as the schema. Paths are relative to
// /api/v1 unless noted. Input-only secrets have json tags (so they decode)
// but are never echoed back.

// ---------- authapi / meapi (unit B) ----------

// AuthState is GET /auth/state (public; drives the login/setup/unlock pages).
type AuthState struct {
	Instance     string   `json:"instance"`      // ui.instance_name
	SetupNeeded  bool     `json:"setup_needed"`  // no users yet → /setup
	Passkeys     bool     `json:"passkeys"`      // auth.passkeys
	RPID         string   `json:"rp_id"`         // WebAuthn RP ID
	KeysState    KeyState `json:"keys_state"`    // uninitialized | locked | unlocked
	LoginMessage string   `json:"login_message"` // ui.login_message ("" = none)
	PasswordMin  int64    `json:"password_min"`  // auth.password_min (the password forms' length rule)
}

// CodeInput is POST /auth/totp, /auth/recovery and /me/totp/confirm.
type CodeInput struct {
	Code string `json:"code"`
}

// PasskeyBeginInput is POST /auth/passkey/begin (username optional:
// discoverable credentials / conditional mediation).
type PasskeyBeginInput struct {
	Username string `json:"username,omitempty"`
}

// PasskeyBegin is the response of POST /auth/passkey/begin and
// /me/passkeys/begin: go-webauthn options ({"publicKey":{…}}) and the flow id
// to send back with the finish call.
type PasskeyBegin struct {
	Options json.RawMessage `json:"options"`
	FlowID  string          `json:"flow_id"`
}

// PasskeyFinishInput is POST /auth/passkey/finish and /me/passkeys/finish
// (Name only for registration; default "Passkey". Remember only for a
// passwordless sign-in: "keep me signed in", as LoginInput.Remember).
type PasskeyFinishInput struct {
	FlowID     string          `json:"flow_id"`
	Credential json.RawMessage `json:"credential"` // PublicKeyCredential JSON
	Name       string          `json:"name,omitempty"`
	Remember   bool            `json:"remember,omitempty"`
}

// ElevateResult is the response of POST /auth/elevate (body: ElevateInput).
// The session token is rotated on elevation, so the CSRF token may change.
type ElevateResult struct {
	ElevatedUntil time.Time `json:"elevated_until"`
	CSRF          string    `json:"csrf,omitempty"`
}

// Me is GET /me (A): everything the SPA needs about the current user. Also
// served while the second factor is pending (AuthLevel 1: MFA set,
// MFAPending true) so the login page can fetch the CSRF token; User is then
// reduced to what the login page uses (id, username, display name,
// must_change_password, mfa_enabled) and Prefs is empty.
type Me struct {
	User       *User           `json:"user"`
	CSRF       string          `json:"csrf,omitempty"` // "" for token/socket principals
	Prefs      json.RawMessage `json:"prefs,omitempty"`
	MFA        *MFAStatus      `json:"mfa,omitempty"`
	MFAPending bool            `json:"mfa_pending"` // AuthLevel 1
	// ElevatedUntil is the end of the step-up window (nil = not elevated).
	ElevatedUntil *time.Time      `json:"elevated_until,omitempty"`
	Features      map[string]bool `json:"features"` // passkeys, links, requests, …
	// SpaceID is the personal space ("" for guests); GroupSpaceIDs maps
	// group id → space id for the user's groups.
	SpaceID       string            `json:"space_id,omitempty"`
	GroupSpaceIDs map[string]string `json:"group_space_ids,omitempty"`
	Groups        []Group           `json:"groups"` // MyGroups (with my_role)
	Via           AuthVia           `json:"via"`
	// Staff reports whether the caller can use at least one server
	// permission on this channel (Principal.ServerAccess; false at AuthLevel 1).
	Staff bool `json:"staff"`
}

// PasswordChangeInput is POST /me/password (Auth.ChangePassword).
type PasswordChangeInput struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// RecoveryCodes is the response of POST /me/totp/confirm and
// POST /me/recovery-codes (shown once).
type RecoveryCodes struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

// TokenCreated is the response of POST /me/tokens: the token metadata and
// the secret "fpt_…" (shown once).
type TokenCreated struct {
	Token  *APIToken `json:"token"`
	Secret string    `json:"secret"`
}

// NameInput is POST /nodes/{id}/folders, PATCH /nodes/{id} (rename) and
// PATCH /me/passkeys/{id}.
type NameInput struct {
	Name string `json:"name"`
}

// ---------- usersapi (unit C) ----------

// UserCreated is the response of POST /admin/users; Password is set only when
// NewUser.GeneratePassword was requested (shown once).
type UserCreated struct {
	User     *User  `json:"user"`
	Password string `json:"password,omitempty"`
}

// PasswordResetInput is POST /admin/users/{id}/password (E). Exactly one of
// Password or Generate. The response is PasswordReset.
type PasswordResetInput struct {
	Password   string `json:"password,omitempty"`
	Generate   bool   `json:"generate,omitempty"`
	MustChange bool   `json:"must_change,omitempty"`
}

// PasswordReset is the response of POST /admin/users/{id}/password; Password
// is set only when generated (shown once).
type PasswordReset struct {
	Password string `json:"password,omitempty"`
}

// InviteCreated is the response of POST /admin/invites: URL is /invite/<token>
// (absolute when server.public_url is set; GET /admin/invites shows it again
// while the invite is active).
type InviteCreated struct {
	Invite *Invite `json:"invite"`
	URL    string  `json:"url"`
}

// RoleInput is PUT /admin/groups/{id}/members/{userId} (GroupRoleMember |
// GroupRoleManager).
type RoleInput struct {
	Role string `json:"role"`
}

// ---------- filesapi (unit D) ----------

// NodeIDsInput is POST /nodes/trash, /trash/restore and /trash/purge.
type NodeIDsInput struct {
	IDs []string `json:"ids"`
}

// MoveInput is POST /nodes/move and /nodes/copy. Conflict defaults to
// ConflictFail for move and ConflictRename for copy.
type MoveInput struct {
	IDs      []string       `json:"ids"`
	Dest     string         `json:"dest"` // destination folder id
	Conflict ConflictPolicy `json:"conflict,omitempty"`
}

// ArchiveTicketResponse is the response of POST /archives (body ArchiveInput)
// and POST /s/{token}/api/archive: a single-use, 60 s ticket and the URL to
// navigate to (/api/v1/archives/<ticket> or /s/<token>/zip/<ticket>).
type ArchiveTicketResponse struct {
	Ticket string `json:"ticket"`
	URL    string `json:"url"`
}

// ---------- uploadapi / sharesapi (unit E) ----------

// POST /upload-batches/{id}/files takes a bare JSON array of UploadFileInput
// (the same item shape as BatchInput.Files) and returns []UploadFileState.

// PasswordInput is POST /s/{token}/api/password.
type PasswordInput struct {
	Password string `json:"password"`
}

// PublicShare is the anonymous view of a share (no share or owner ids, no
// token, no counters that leak usage).
type PublicShare struct {
	Kind                string     `json:"kind"` // ShareLink | ShareRequest
	NodeID              string     `json:"node_id"`
	NodeName            string     `json:"node_name,omitempty"`
	NodeKind            string     `json:"node_kind,omitempty"`
	Title               string     `json:"title,omitempty"`
	Message             string     `json:"message,omitempty"`
	OwnerName           string     `json:"owner_name,omitempty"` // display name of the creator
	HasPassword         bool       `json:"has_password"`
	AllowDownload       bool       `json:"allow_download"`
	AllowPreview        bool       `json:"allow_preview"`
	AllowUpload         bool       `json:"allow_upload"`
	RequireUploaderName bool       `json:"require_uploader_name"`
	UploadMaxFileBytes  *int64     `json:"upload_max_file_bytes"`
	ExpiresAt           *time.Time `json:"expires_at"`
}

// PublicShareInfo is GET /s/{token}/api. When the share has a password and
// the access cookie is missing, the response is 200 with PasswordRequired
// true and only Share.Kind, Share.Title and Share.HasPassword filled — never
// Node, Items or the message. Otherwise
// Node is the shared node and, for folders, Items/NextCursor are the first
// page of its children (GET /s/{token}/api/list?node=&cursor= returns a
// Page[Node] for sub-folders). Nodes shown to anonymous visitors have
// CreatedBy/UpdatedBy/TrashedBy cleared (no user-id leak).
type PublicShareInfo struct {
	Share            PublicShare `json:"share"`
	PasswordRequired bool        `json:"password_required,omitempty"`
	Node             *Node       `json:"node,omitempty"`
	Items            []Node      `json:"items,omitempty"`
	NextCursor       string      `json:"next_cursor,omitempty"`
}

// ---------- securityapi (unit F) ----------

// SystemStatus is GET /system/status (public).
type SystemStatus struct {
	State       KeyState `json:"state"` // locked | unlocked | uninitialized
	SetupNeeded bool     `json:"setup_needed"`
	// WebUnlock (GET /system/status while locked): whether this client may
	// unlock over the web under keys.web_unlock — "allowed", "off" (web
	// unlock is disabled) or "network" (not from the client's network) — so
	// the unlock page does not ask for the passphrase only to refuse it.
	WebUnlock string `json:"web_unlock,omitempty"`
}

// PassphraseInput is POST /system/unlock and POST /admin/keys/{seal,unseal}.
// Unlock also accepts a recovery key ("FPRK-…") in Passphrase.
type PassphraseInput struct {
	Passphrase string `json:"passphrase"`
}

// PassphraseChangeInput is POST /admin/keys/passphrase.
type PassphraseChangeInput struct {
	CurrentPassphrase string `json:"current_passphrase"`
	NewPassphrase     string `json:"new_passphrase"`
}

// KeysRotateInput is POST /admin/keys/rotate: Target "kek" (Purpose blob|field),
// "master" or "data" (re-encryption job). Long operations return JobRef.
type KeysRotateInput struct {
	Target  string `json:"target"`
	Purpose string `json:"purpose,omitempty"`
}

// RecoveryKey is the response of POST /admin/keys/recovery (shown once).
type RecoveryKey struct {
	RecoveryKey string `json:"recovery_key"`
}

// CertRenewInput is POST /admin/certs/renew (all fields optional; the same
// value may be given as the ?force= query parameter).
type CertRenewInput struct {
	Force bool `json:"force,omitempty"`
}

// CARegenerateInput is POST /admin/certs/ca/regenerate (E). Unconstrained
// drops the CA's name constraints, so it can then sign for any name.
type CARegenerateInput struct {
	Unconstrained bool `json:"unconstrained,omitempty"`
}

// CustomCertInput is PUT /admin/certs/custom (E): the PEM chain (server
// certificate first) and its unencrypted PEM private key.
type CustomCertInput struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// ClientCertIssued is the response of POST /admin/client-certs (E) and
// POST /me/client-certs. P12 (standard base64) and Password (only when the
// server generated it) are shown once; DownloadURL is a single-use link to
// the same .p12 file, valid for 10 minutes and only for the issuing user.
type ClientCertIssued struct {
	ClientCert  *ClientCert `json:"client_cert"`
	P12         string      `json:"p12"`
	Password    string      `json:"password,omitempty"`
	Filename    string      `json:"filename"`
	DownloadURL string      `json:"download_url"`
}

// ---------- settingsapi (unit G) ----------

// NetworkOverview is GET /admin/network.
type NetworkOverview struct {
	Interfaces []NetInterface `json:"interfaces"`
	URLs       []AccessURL    `json:"urls"`
	Policy     AccessPolicy   `json:"policy"`
	Tailscale  *TailscaleInfo `json:"tailscale,omitempty"`
	ClientIP   string         `json:"client_ip"` // the requester's IP (for the lockout guard UI)
	// Ingress is the cached Tailscale Funnel/Serve status (nil when the
	// ingress service is not wired).
	Ingress   *IngressStatus `json:"ingress,omitempty"`
	VPNs      []VPNInfo      `json:"vpns"`      // detected VPNs (netinfo.BuildVPNs)
	Exposures []Exposure     `json:"exposures"` // ways the access policy may be bypassed
}

// PolicyInput is PUT /admin/network/policy (E). Force overrides the lockout
// guard (409 conflict when the requester would lose access).
type PolicyInput struct {
	Mode  string   `json:"mode"`
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
	Force bool     `json:"force,omitempty"`
}

// PolicyResult is the response of PUT /admin/network/policy.
type PolicyResult struct {
	Policy   AccessPolicy `json:"policy"`
	Warnings []string     `json:"warnings"`
}

// EmailTestInput is POST /admin/settings/email/test (Adm): send a test
// message to To with the configured SMTP settings.
type EmailTestInput struct {
	To string `json:"to"`
}

// ---------- opsapi (unit H) ----------

// JobRef is the response of endpoints that start a background job
// (POST /admin/backups, /admin/backups/{id}/verify, /admin/jobs/run, …).
type JobRef struct {
	JobID string `json:"job_id"`
}

// RunJobInput is POST /admin/jobs/run.
type RunJobInput struct {
	Kind   string          `json:"kind"`
	Params json.RawMessage `json:"params,omitempty"`
}

// BackupIdentity is the response of POST /admin/backups/identity (E): the
// new age recipient (public) and identity (secret, shown once).
type BackupIdentity struct {
	Recipient string `json:"recipient"`
	Identity  string `json:"identity"`
}

// SystemInfo is GET /admin/system.
type SystemInfo struct {
	Version       string    `json:"version"`
	Commit        string    `json:"commit,omitempty"`
	BuildDate     string    `json:"build_date,omitempty"`
	GoVersion     string    `json:"go_version"`
	OS            string    `json:"os"`
	Arch          string    `json:"arch"`
	Hostname      string    `json:"hostname"`
	Home          string    `json:"home"`
	PID           int       `json:"pid"`
	StartedAt     time.Time `json:"started_at"`
	UptimeSeconds int64     `json:"uptime_seconds"`
	KeysState     KeyState  `json:"keys_state"`
	KeyMode       string    `json:"key_mode,omitempty"` // KeyModePlain | KeyModeSealed
	SchemaVersion int       `json:"schema_version"`
	DBBytes       int64     `json:"db_bytes"`
	BlobsBytes    int64     `json:"blobs_bytes"`
	DiskFreeBytes int64     `json:"disk_free_bytes"`
	DiskSizeBytes int64     `json:"disk_size_bytes"`
	// RestartRequired lists settings changed since start that need a restart.
	RestartRequired []string `json:"restart_required"`
	Supervisor      string   `json:"supervisor,omitempty"` // systemd | launchd | docker | external (FILEPARCEL_SUPERVISED=1) | ""
}

// Dashboard is GET /admin/dashboard.
type Dashboard struct {
	Users         int            `json:"users"`
	Groups        int            `json:"groups"`
	Files         int64          `json:"files"`
	Folders       int64          `json:"folders"`
	StoredBytes   int64          `json:"stored_bytes"`
	DiskFreeBytes int64          `json:"disk_free_bytes"`
	DiskSizeBytes int64          `json:"disk_size_bytes"`
	ActiveShares  int            `json:"active_shares"`
	ActiveUploads int            `json:"active_uploads"`
	RunningJobs   int            `json:"running_jobs"`
	FailedJobs24h int            `json:"failed_jobs_24h"`
	KeysState     KeyState       `json:"keys_state"`
	Cert          *CertInfo      `json:"cert,omitempty"` // the default served certificate
	LastBackup    *Backup        `json:"last_backup,omitempty"`
	RecentAudit   []AuditRecord  `json:"recent_audit"`
	Warnings      []string       `json:"warnings"` // human-readable problems (cert expiring, no backup, …)
	Version       string         `json:"version"`
	Extra         map[string]any `json:"extra,omitempty"` // additive details without a core change
}
