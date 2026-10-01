package core

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"time"
)

// ---------- settings ----------

// Settings is the runtime settings store (DESIGN §11). Keys are registered by
// their owning packages with settings.Register. Typed getters return the zero
// value for unknown keys or type mismatches (and never block); use Raw to
// detect errors.
type Settings interface {
	// Raw returns the current value (or the default) as JSON. Unknown key -> ErrNotFound.
	// Secret settings return the sealed/masked form; use Secret for the plaintext.
	Raw(key string) (json.RawMessage, error)
	Int(key string) int64
	Bool(key string) bool
	String(key string) string
	Strings(key string) []string
	// Duration parses a TypeDuration setting ("15m").
	Duration(key string) time.Duration
	// Secret decrypts a secret setting ("" when unset).
	Secret(key string) (string, error)
	// Set validates every change (type, enum, range, custom Validate), applies
	// them atomically, writes one audit entry per key (secrets masked),
	// publishes events.TopicSettingsChanged and reports which keys need a restart.
	Set(ctx context.Context, by *Principal, changes map[string]json.RawMessage) (*SettingsResult, error)
	// Reset restores the default of key.
	Reset(ctx context.Context, by *Principal, key string) error
	// Catalog lists every registered setting with value/default; secrets are
	// masked (only is_set is reported).
	Catalog(ctx context.Context) ([]SettingView, error)
}

// ---------- keys ----------

// KeyState is the state of the master key.
type KeyState string

// Key states.
const (
	KeyStateUninitialized KeyState = "uninitialized" // no master key yet (before init)
	KeyStateLocked        KeyState = "locked"        // sealed mode, waiting for the passphrase
	KeyStateUnlocked      KeyState = "unlocked"      // keys available
)

// CipherID identifies the AEAD of a blob (stored in the blob header and blobs.cipher).
type CipherID uint8

// Ciphers (same values as crypt.CipherAES256GCM / crypt.CipherChaCha20Poly1305).
const (
	CipherAES256GCM        CipherID = 1
	CipherChaCha20Poly1305 CipherID = 2
)

// String returns "aes-256-gcm", "chacha20-poly1305" or "unknown".
func (c CipherID) String() string {
	switch c {
	case CipherAES256GCM:
		return "aes-256-gcm"
	case CipherChaCha20Poly1305:
		return "chacha20-poly1305"
	}
	return "unknown"
}

// Keys manages the master key, the keyring (KEKs), DEK wrapping, field
// encryption and MACs (DESIGN §7). All methods except State/Status/Unlock/Init
// return ErrKeysLocked while locked (and while uninitialized). MAC returns nil
// when the mac KEK is unavailable (callers such as audit must handle that).
type Keys interface {
	State() KeyState
	// Init creates the master key (keys/master.key, plain or sealed with
	// passphrase), the keyring (one active blob, field and mac KEK) and
	// meta.mk_id/mk_check, then leaves the service unlocked and publishes
	// keys.state. Used by `init`, `install` and `serve --init-if-missing`
	// (DESIGN §12, §14.2). recoveryKey is the one-time recovery key when one
	// was created (sealed mode; "" otherwise). Returns ErrConflict when a
	// master key already exists; sealed without a passphrase → ErrInvalid.
	// (Foundation addition: DESIGN §5.1 lists no initialisation method.)
	Init(ctx context.Context, sealed bool, passphrase []byte) (recoveryKey string, err error)
	Unlock(ctx context.Context, passphrase []byte) error // also accepts a recovery key string
	Lock(ctx context.Context) error                      // sealed mode only
	Status(ctx context.Context) (*KeyStatus, error)
	// NewDEK returns a fresh 32-byte DEK and its wrapping under the active blob
	// KEK (AAD "fp-dek|"+blobID).
	NewDEK(blobID []byte) (dek, wrapped []byte, kekID string, err error)
	UnwrapDEK(blobID []byte, kekID string, wrapped []byte) ([]byte, error)
	SealField(aad string, plaintext []byte) (string, error) // "v1:<kekid>:<b64url(nonce||ct)>"
	OpenField(aad string, sealed string) ([]byte, error)
	MAC(purpose string, data ...[]byte) []byte      // HMAC-SHA256 with HKDF(macKEK, "fp-mac|"+purpose)
	Seal(ctx context.Context, newPass []byte) error // plain → sealed
	Unseal(ctx context.Context, pass []byte) error  // sealed → plain
	ChangePassphrase(ctx context.Context, oldPass, newPass []byte) error
	RotateKEK(ctx context.Context, purpose string, progress func(done, total int64)) error // purpose: blob|field
	RotateMaster(ctx context.Context) error
	ExportRecovery(ctx context.Context) (string, error) // returns a new recovery key (shown once)
	Cipher() CipherID                                   // cipher for new blobs (auto-selected)
}

// ---------- blobs ----------

// BlobInfo describes a committed blob.
type BlobInfo struct {
	ID          string    `json:"id"`
	Size        int64     `json:"size"`
	StoredSize  int64     `json:"stored_size"`
	ContentHash string    `json:"content_hash"`
	Cipher      CipherID  `json:"cipher"`
	CreatedAt   time.Time `json:"created_at"`
}

// BlobStore stores encrypted, segmented blobs under data/blobs (DESIGN §7.3).
type BlobStore interface {
	Create(ctx context.Context) (BlobWriter, error)                    // streaming, unknown size
	CreateParted(ctx context.Context, size int64) (PartedBlob, error)  // part size is fixed: PartSize (8 MiB)
	OpenParted(ctx context.Context, blobID string) (PartedBlob, error) // resume
	Open(ctx context.Context, blobID string) (BlobReader, error)
	Stat(ctx context.Context, blobID string) (*BlobInfo, error)
	Delete(ctx context.Context, blobID string) error                                    // marks deleting + removes file + row
	Verify(ctx context.Context, blobID string) error                                    // decrypts every segment
	GC(ctx context.Context, minAge time.Duration) (removed int, freed int64, err error) // unreferenced + stale staging
	Reencrypt(ctx context.Context, blobID string) (newID string, err error)
}

// PartSize is the fixed upload part size: 8 MiB = 128 segments of 64 KiB.
const PartSize = 8 << 20

// BlobWriter streams a new blob of unknown size. Commit makes it ready; Abort
// deletes the staging data.
type BlobWriter interface {
	io.Writer
	Commit(ctx context.Context) (*BlobInfo, error)
	Abort() error
}

// PartedBlob is a blob of declared size written in PartSize parts, possibly
// out of order and in parallel, resumable across requests.
type PartedBlob interface {
	ID() string
	Size() int64
	PartCount() int
	WritePart(ctx context.Context, n int, r io.Reader, wantSHA256 []byte) (gotSHA256 []byte, err error) // idempotent per part
	Commit(ctx context.Context, partDigests [][]byte) (*BlobInfo, error)
	Abort() error
}

// BlobReader gives random access to a blob's plaintext (usable with http.ServeContent).
type BlobReader interface {
	io.ReadSeekCloser
	io.ReaderAt
	Size() int64
	ID() string
}

// ---------- users ----------

// Users manages accounts, groups, memberships, invites, roles and quotas.
//
// Authorization is by permission (DESIGN §6a): users.manage (create, admin
// fields, status, unlock, delete), users.credentials (passwords, 2FA,
// sessions of others; moving files on delete), invites.manage and
// groups.manage (group_ids on accounts and invites need it too), checked
// with Principal.Can, plus the escalation rules CheckManage (acting on
// another account) and CheckAssign (giving a role). The admin fields of
// UserUpdate are Role, RoleID, QuotaBytes and MustChangePassword; everyone
// may update their own DisplayName, Email and Prefs, but never their own
// role, quota or must_change_password. PATCH /me/profile decodes a
// ProfileUpdate (which cannot carry the admin fields) and converts it with
// ProfileUpdate.UserUpdate(). Creating, editing and deleting roles is for
// built-in owners and admins only (by.IsAdmin()). Members, MyGroups,
// GroupIDsOf and GroupsOf are effective: direct memberships plus those
// through a custom role (role_groups).
type Users interface {
	Get(ctx context.Context, id string) (*User, error)
	GetByUsername(ctx context.Context, username string) (*User, error)
	List(ctx context.Context, q UserQuery) (Page[User], error)
	Count(ctx context.Context) (int, error)
	Create(ctx context.Context, by *Principal, in NewUser) (*User, error) // + personal space (not for guests)
	Bootstrap(ctx context.Context, in NewUser) (*User, error)             // first owner; fails if any user exists
	Update(ctx context.Context, by *Principal, id string, in UserUpdate) (*User, error)
	SetPasswordHash(ctx context.Context, by *Principal, id, phc string, mustChange bool) error
	SetStatus(ctx context.Context, by *Principal, id, status string) error
	Delete(ctx context.Context, by *Principal, id, transferTo string) error
	RecordLoginFailure(ctx context.Context, id string) (lockedUntil *time.Time, err error)
	RecordLoginSuccess(ctx context.Context, id string, meta ReqMeta) error
	Unlock(ctx context.Context, by *Principal, id string) error
	Lookup(ctx context.Context, p *Principal, q string) ([]UserRef, error)
	ListGroups(ctx context.Context, q PageReq) (Page[Group], error)
	GetGroup(ctx context.Context, id string) (*Group, error)
	CreateGroup(ctx context.Context, by *Principal, in GroupInput) (*Group, error) // + group space ("Team folder")
	UpdateGroup(ctx context.Context, by *Principal, id string, in GroupInput) (*Group, error)
	DeleteGroup(ctx context.Context, by *Principal, id string) error
	Members(ctx context.Context, groupID string) ([]GroupMember, error)
	SetMember(ctx context.Context, by *Principal, groupID, userID, role string) error
	RemoveMember(ctx context.Context, by *Principal, groupID, userID string) error
	GroupIDsOf(ctx context.Context, userID string) ([]string, error)
	MyGroups(ctx context.Context, p *Principal) ([]Group, error)
	CreateInvite(ctx context.Context, by *Principal, in InviteInput) (*Invite, string, error) // returns token — URL is /invite/<token> (ListInvites shows it again while the invite is active)
	// ListInvites lists invitations; Invite.URL is filled only where the
	// caller (by) may see it (DESIGN §6a).
	ListInvites(ctx context.Context, by *Principal, q PageReq) (Page[Invite], error)
	RevokeInvite(ctx context.Context, by *Principal, id string) error
	LookupInvite(ctx context.Context, token string) (*Invite, error)
	AcceptInvite(ctx context.Context, token string, in AcceptInvite, phc string, meta ReqMeta) (*User, error)

	// ---- roles (DESIGN §6a) ----
	ListRoles(ctx context.Context, by *Principal) ([]RoleDef, error)         // built-ins (owner, admin, member, guest), then custom by name
	GetRole(ctx context.Context, by *Principal, id string) (*RoleDef, error) // built-in word or rol_…; by nil → no Editable/Assignable
	CreateRole(ctx context.Context, by *Principal, in RoleDefInput) (*RoleDef, error)
	UpdateRole(ctx context.Context, by *Principal, id string, in RoleDefUpdate) (*RoleDef, error)
	DeleteRole(ctx context.Context, by *Principal, id, reassignTo string) error
	LookupRoles(ctx context.Context, p *Principal) ([]RoleRef, error) // GET /roles (custom roles)
	RoleGroups(ctx context.Context, roleID string) ([]RoleGroup, error)
	SetRoleGroup(ctx context.Context, by *Principal, roleID, groupID, memberRole string) (*RoleGroup, error)
	RemoveRoleGroup(ctx context.Context, by *Principal, roleID, groupID string) error
	GroupsOf(ctx context.Context, userID string) ([]AccessGroup, error) // effective memberships with sources
}

// ---------- auth ----------

// Auth implements passwords, sessions, lockout, TOTP, recovery codes,
// passkeys, API tokens, CSRF and step-up (DESIGN §9.3).
type Auth interface {
	HashPassword(pw string) (string, error)
	VerifyPassword(phc, pw string) (ok bool, needsRehash bool)
	CheckPasswordPolicy(pw string, u *User) error
	Login(ctx context.Context, in LoginInput, meta ReqMeta) (*LoginResult, error)
	VerifyTOTP(ctx context.Context, p *Principal, code string) (*LoginResult, error)
	VerifyRecovery(ctx context.Context, p *Principal, code string) (*LoginResult, error)
	PasskeyLoginBegin(ctx context.Context, username string) (opts json.RawMessage, flowID string, err error)
	PasskeyLoginFinish(ctx context.Context, flowID string, resp []byte, remember bool, p *Principal, meta ReqMeta) (*LoginResult, error)
	Authenticate(r *http.Request) (*Principal, error) // cookie or Bearer; (nil,nil) = anonymous
	Logout(ctx context.Context, p *Principal) error
	Elevate(ctx context.Context, p *Principal, in ElevateInput) error
	CSRFToken(p *Principal) string
	CheckCSRF(p *Principal, token string) bool
	ChangePassword(ctx context.Context, p *Principal, current, next string) error // revokes other sessions
	AdminSetPassword(ctx context.Context, by *Principal, userID, pw string, mustChange bool) error
	ListSessions(ctx context.Context, userID string) ([]Session, error)
	RevokeSession(ctx context.Context, by *Principal, userID, sessionID string) error
	RevokeAllSessions(ctx context.Context, by *Principal, userID, exceptID string) error
	TOTPBegin(ctx context.Context, p *Principal) (*TOTPEnrollment, error) // secret, otpauth URI, QR SVG data URI
	TOTPConfirm(ctx context.Context, p *Principal, code string) (recovery []string, err error)
	TOTPDisable(ctx context.Context, by *Principal, userID string) error
	RegenerateRecovery(ctx context.Context, p *Principal) ([]string, error)
	PasskeyRegisterBegin(ctx context.Context, p *Principal) (json.RawMessage, string, error)
	PasskeyRegisterFinish(ctx context.Context, p *Principal, flowID string, resp []byte, name string) (*Passkey, error)
	ListPasskeys(ctx context.Context, userID string) ([]Passkey, error)
	RenamePasskey(ctx context.Context, p *Principal, id, name string) error
	DeletePasskey(ctx context.Context, p *Principal, id string) error
	CreateToken(ctx context.Context, p *Principal, in TokenInput) (*APIToken, string, error)
	ListTokens(ctx context.Context, userID string) ([]APIToken, error)
	RevokeToken(ctx context.Context, p *Principal, id string) error
	MFAStatus(ctx context.Context, userID string) (*MFAStatus, error)
	ResetMFA(ctx context.Context, by *Principal, userID string) error
	SessionCookie(token string, exp time.Time) *http.Cookie
	Setup(ctx context.Context, setupToken string, in NewUser, meta ReqMeta) (*LoginResult, error) // first-run web setup
	SetupToken(ctx context.Context) (string, error)                                               // creates/returns one-time setup token when no users exist (printed in logs)
	// RotateSession gives the caller's session a fresh token (same CSRF
	// token) and returns the new LoginResult, so handlers can re-set the
	// cookie after Elevate or ChangePassword. Returns (nil, nil) when p is
	// not a session principal.
	RotateSession(ctx context.Context, p *Principal) (*LoginResult, error)
	// RPID is the effective WebAuthn relying-party ID (auth.webauthn_rp_id
	// or the derived default); reported by GET /auth/state.
	RPID() string
}

// ---------- files ----------

// Perm is a permission level on a node. Levels are ordered:
// PermNone < PermView < PermEdit < PermManage < PermOwner.
type Perm int

// ConflictPolicy says what to do when a name already exists in the target folder.
type ConflictPolicy string

// Files implements the node tree, permissions, trash, versions, search,
// stars, grants and archives (DESIGN §6 permission model).
type Files interface {
	Spaces(ctx context.Context, p *Principal) ([]Space, error)
	Get(ctx context.Context, p *Principal, id string) (*Node, error)
	Authorize(ctx context.Context, p *Principal, id string, need Perm) (*Node, error)
	List(ctx context.Context, p *Principal, folderID string, q ListQuery) (Page[Node], error)
	Breadcrumbs(ctx context.Context, p *Principal, id string) ([]Node, error)
	Mkdir(ctx context.Context, p *Principal, parentID, name string) (*Node, error)
	MkdirAll(ctx context.Context, p *Principal, parentID, relPath string) (*Node, error)
	CommitFile(ctx context.Context, p *Principal, parentID, relPath string, b *BlobInfo, m FileMeta, c ConflictPolicy) (*Node, error)
	Rename(ctx context.Context, p *Principal, id, name string) (*Node, error)
	Move(ctx context.Context, p *Principal, ids []string, dest string, c ConflictPolicy) ([]Node, error)
	Copy(ctx context.Context, p *Principal, ids []string, dest string, c ConflictPolicy) ([]Node, error) // shares blobs, instant
	Trash(ctx context.Context, p *Principal, ids []string) error
	Restore(ctx context.Context, p *Principal, ids []string) ([]Node, error)
	Purge(ctx context.Context, p *Principal, ids []string) error
	ListTrash(ctx context.Context, p *Principal, q ListQuery) (Page[Node], error)
	EmptyTrash(ctx context.Context, p *Principal) error
	Open(ctx context.Context, p *Principal, id, versionID string) (*Node, BlobReader, error)
	Thumbnail(ctx context.Context, p *Principal, id string) (BlobReader, error)
	Walk(ctx context.Context, p *Principal, rootIDs []string, fn func(WalkEntry) error) error // keyset-paged DFS
	Search(ctx context.Context, p *Principal, q SearchQuery) (Page[Node], error)
	Recent(ctx context.Context, p *Principal, limit int) ([]Node, error)
	Star(ctx context.Context, p *Principal, id string, on bool) error
	Starred(ctx context.Context, p *Principal, q ListQuery) (Page[Node], error)
	Versions(ctx context.Context, p *Principal, id string) ([]FileVersion, error)
	RestoreVersion(ctx context.Context, p *Principal, id, versionID string) (*Node, error)
	Grants(ctx context.Context, p *Principal, id string) ([]Grant, error)
	SetGrant(ctx context.Context, p *Principal, id string, in GrantInput) (*Grant, error)
	RemoveGrant(ctx context.Context, p *Principal, id, grantID string) error
	SharedWithMe(ctx context.Context, p *Principal, q ListQuery) (Page[Node], error)
	Stats(ctx context.Context, p *Principal, id string) (*FolderStats, error)
	Usage(ctx context.Context, userID string) (*Usage, error)
	CreateArchiveTicket(ctx context.Context, p *Principal, shareID string, in ArchiveInput) (ticket string, err error)
	ConsumeArchiveTicket(ctx context.Context, ticket string) (*ArchiveTicket, error)
	WriteArchive(ctx context.Context, t *ArchiveTicket, w io.Writer) error // streams zip or tar
	// system-level (no principal) helpers used by shares/uploads/jobs:
	GetSys(ctx context.Context, id string) (*Node, error)
	IsWithin(ctx context.Context, ancestorID, id string) (bool, error)
	ListSys(ctx context.Context, folderID string, q ListQuery) (Page[Node], error)
	OpenSys(ctx context.Context, id string) (*Node, BlobReader, error)
	SysPrincipalFor(ctx context.Context, userID string) (*Principal, error) // acts as that user (public share ops)
	// SubjectGrants lists live grants to one subject (GET /admin/grants). The
	// route authorizes; names are filled only where the caller may see them,
	// the rest are counted in Hidden.
	SubjectGrants(ctx context.Context, p *Principal, q SubjectGrantQuery) (*SubjectGrants, error)
}

// ---------- uploads ----------

// UploadActor identifies who uploads: a principal (normal uploads) or a
// public file request (ShareID set, P = the share owner acting via
// Files.SysPrincipalFor, Uploader = the optional uploader name).
type UploadActor struct {
	P        *Principal
	ShareID  string
	Uploader string
}

// Uploads implements the parted upload protocol (DESIGN §8.1).
type Uploads interface {
	CreateBatch(ctx context.Context, a UploadActor, in BatchInput) (*UploadBatch, error)
	AddFiles(ctx context.Context, a UploadActor, batchID string, in []UploadFileInput) ([]UploadFileState, error)
	PutPart(ctx context.Context, a UploadActor, uploadID string, n int, body io.Reader, size int64, sha []byte) error
	PutSmall(ctx context.Context, a UploadActor, batchID, clientRef string, body io.Reader, size int64, sha []byte) (*UploadFileState, error)
	Status(ctx context.Context, a UploadActor, uploadID string) (*UploadFileState, error)
	CompleteFile(ctx context.Context, a UploadActor, uploadID string) (*UploadFileState, error)
	CompleteBatch(ctx context.Context, a UploadActor, batchID string) (*UploadBatch, error)
	GetBatch(ctx context.Context, a UploadActor, batchID string) (*UploadBatch, error)
	// ListBatches returns the user's own unfinished batches (open or
	// finalizing; not those of file requests), newest first, without files.
	ListBatches(ctx context.Context, a UploadActor) ([]UploadBatch, error)
	AbortBatch(ctx context.Context, a UploadActor, batchID string) error
	AbortFile(ctx context.Context, a UploadActor, uploadID string) error
	ExpireStale(ctx context.Context) (int, error)
}

// ---------- shares ----------

// Shares implements public links and file requests (DESIGN §9.4 sharesapi).
type Shares interface {
	Create(ctx context.Context, p *Principal, in ShareInput) (*Share, string, error) // token returned; URL = /s/<token>
	List(ctx context.Context, p *Principal, q ShareQuery) (Page[Share], error)
	ListAll(ctx context.Context, q ShareQuery) (Page[Share], error) // admin
	Get(ctx context.Context, p *Principal, id string) (*Share, error)
	Update(ctx context.Context, p *Principal, id string, in ShareUpdate) (*Share, error)
	Revoke(ctx context.Context, p *Principal, id string) error
	AccessLog(ctx context.Context, p *Principal, id string, q PageReq) (Page[ShareAccess], error)
	Resolve(ctx context.Context, token string) (*Share, *Node, error) // validates active/expiry/limits
	CheckPassword(ctx context.Context, s *Share, pw string, meta ReqMeta) error
	AccessCookie(s *Share) (*http.Cookie, error)
	HasAccess(r *http.Request, s *Share) bool          // password cookie valid (or no password)
	CountDownload(ctx context.Context, s *Share) error // atomic; ErrForbidden when exhausted
	RecordAccess(ctx context.Context, s *Share, a ShareAccess)
}

// ---------- audit ----------

// Audit is the HMAC-chained audit log (DESIGN §9.6).
//
// Key-state rule (binding for the implementation): Record and RecordTx must
// persist the row immediately whatever the key state — also while the keys
// are locked or uninitialized (system.start, failed keys.unlock, `init`
// before the master key exists). A row must never be dropped or deferred
// because MAC("audit", …) is unavailable. While the mac KEK is unavailable
// the row is chained with the unkeyed hash SHA-256(prev_hash || canonical(row))
// and meta "audit_unsealed_seq" records the first such seq (set in the same
// transaction). When the keys become unlocked (keys.state event, or lazily
// on the next Record), the service re-computes hash = MAC("audit",
// prev_hash || canonical(row)) for every row from that seq in one
// transaction and deletes the marker. Verify reports rows that are still
// unsealed instead of failing on them. An unsealed row proves nothing about
// its origin, so rows the sealing process did not write itself are sealed
// too but named by an appended audit.reseal entry (and in Verify).
type Audit interface {
	Record(ctx context.Context, e AuditEntry) // never fails the caller; fills actor/ip/request from ctx Principal
	RecordTx(ctx context.Context, tx *sql.Tx, e AuditEntry) error
	Query(ctx context.Context, q AuditQuery) (Page[AuditRecord], error)
	Verify(ctx context.Context) (*AuditVerify, error)
	Export(ctx context.Context, q AuditQuery, format string, w io.Writer) error // csv|jsonl
	Prune(ctx context.Context, before time.Time) (int, error)
}

// ---------- jobs ----------

// JobFunc runs one job. It should honour ctx cancellation (Cancel / Timeout /
// shutdown) and report progress through j.
type JobFunc func(ctx context.Context, j JobHandle) error

// JobHandle is the running job's view of itself.
type JobHandle interface {
	ID() string
	Params(v any) error // decodes the enqueue params (JSON) into v
	Progress(done, total int64, note string)
	SetResult(v any) // stored as JSON in jobs.result
}

// JobOptions configures a job kind. Exclusive names a lock: jobs sharing it
// never run concurrently. MaxConcurrent bounds parallel runs of this kind
// (0 = 1). Timeout 0 = none. Hidden jobs are omitted from user-facing lists.
type JobOptions struct {
	Exclusive     string
	MaxConcurrent int
	Timeout       time.Duration
	Hidden        bool
}

// Jobs is the persistent job queue, runner and cron-lite scheduler (DESIGN §9.7).
type Jobs interface {
	Register(kind string, fn JobFunc, o JobOptions)
	Enqueue(ctx context.Context, kind string, params any, by *Principal) (string, error)
	Get(ctx context.Context, id string) (*Job, error)
	List(ctx context.Context, q JobQuery) (Page[Job], error)
	Cancel(ctx context.Context, id string) error
	Schedule(name, cron, kind string, params any) error
	Unschedule(name string)
	Schedules(ctx context.Context) ([]JobSchedule, error)
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// ---------- backups ----------

// Backups creates, verifies, restores and prunes encrypted backups (tar → zstd → age).
//
// Online restore: ScheduleRestore prepares the restore, writes
// run/restore.json and requests a restart (events.TopicSystemRestart). The
// next `serve` applies it with backup.ApplyPendingRestore while holding the
// home lock and before wire.Build opens the database.
type Backups interface {
	Create(ctx context.Context, by *Principal, in BackupInput) (jobID string, err error)
	CreateSync(ctx context.Context, by *Principal, in BackupInput) (*Backup, error) // used by pre-upgrade/final backups & CLI offline
	List(ctx context.Context, q PageReq) (Page[Backup], error)
	Get(ctx context.Context, id string) (*Backup, error)
	Delete(ctx context.Context, by *Principal, id string) error
	Verify(ctx context.Context, by *Principal, id string, deep bool) (jobID string, err error)
	Download(ctx context.Context, id string) (io.ReadCloser, int64, string, error) // body, size, file name
	Import(ctx context.Context, by *Principal, r io.Reader) (*Backup, error)
	ScheduleRestore(ctx context.Context, by *Principal, id string, c RestoreCreds) error // writes run/restore.json, then restart
	RestoreOffline(ctx context.Context, file string, c RestoreCreds, o RestoreOpts) error
	Prune(ctx context.Context) (int, error)
	Config(ctx context.Context) (*BackupConfig, error)
	SetConfig(ctx context.Context, by *Principal, c BackupConfig) error
	GenerateIdentity(ctx context.Context, by *Principal) (recipient, identity string, err error)
}

// ---------- certs ----------

// Certs manages the local CA, leaf, client CA, ACME, Tailscale and custom
// certificates and the TLS configuration (DESIGN §10.4).
//
// Lifecycle contract: the constructor (certs.New) loads the existing CA,
// client CA, leaf, custom and cached ACME/Tailscale certificates from disk —
// no network access, no goroutines, missing files are not an error. It must
// work while the keys are locked (sealed CA keys are opened lazily, when
// issuing). In ModeOffline wire.Start never calls Start, so Status,
// Fingerprint, CAExport, TLSConfig and the client-cert methods must work
// right after New (`ca fingerprint`, `cert status`, `client-cert issue` run
// offline). Start only begins background work: renewal checks, the
// SAN-change watcher (network.changed, mdns.changed, settings.changed),
// ACME (certmagic) and Tailscale refresh.
type Certs interface {
	TLSConfig() *tls.Config
	Status(ctx context.Context) (*CertStatus, error)
	CAExport(format string) (data []byte, contentType, filename string, err error) // pem|der|mobileconfig
	Fingerprint() string                                                           // SHA-256 of CA cert DER, hex with colons
	RenewLocal(ctx context.Context, force bool) error
	RegenerateCA(ctx context.Context, by *Principal, constrained bool) error
	SetCustom(ctx context.Context, by *Principal, certPEM, keyPEM []byte) error
	ClearCustom(ctx context.Context, by *Principal) error
	ApplyACME(ctx context.Context) error
	FetchTailscale(ctx context.Context) error
	HTTPChallenge(next http.Handler) http.Handler
	PubliclyTrusted(serverName string) bool
	IssueClient(ctx context.Context, by *Principal, in ClientCertInput) (*ClientCert, []byte, error) // p12 bytes
	ListClient(ctx context.Context, q PageReq, userID string) (Page[ClientCert], error)
	RevokeClient(ctx context.Context, by *Principal, id, reason string) error
	CheckClient(ctx context.Context, cs *tls.ConnectionState) (*ClientCert, error)
	Init(ctx context.Context) error // create CA/client CA/leaf if missing (used by `init`)
	Start(ctx context.Context) error
}

// ---------- network / mdns / notify ----------

// Network enumerates interfaces, builds access URLs and enforces the access
// policy (DESIGN §10.1–10.3).
type Network interface {
	Interfaces(ctx context.Context) ([]NetInterface, error)
	URLs(ctx context.Context) ([]AccessURL, error)
	Allowed(ip netip.Addr) bool // lock-free hot path (atomic.Pointer)
	Policy() AccessPolicy
	SetPolicy(ctx context.Context, by *Principal, p AccessPolicy, current netip.Addr, force bool) ([]string, error) // warnings
	// CheckPolicy validates p and reports whether ip would be allowed under
	// it, without applying anything. It backs the lockout guard on the
	// settings routes that change network.access_mode/allow_cidrs/deny_cidrs.
	// An invalid policy returns ErrInvalid.
	CheckPolicy(p AccessPolicy, ip netip.Addr) (bool, error)
	Hostnames() []string // SAN names (mdns name.local, hostname, MagicDNS, extra)
	IPs() []netip.Addr   // SAN IPs
	Tailscale(ctx context.Context) (*TailscaleInfo, error)
	// IsLocal reports whether ip is an address of a local interface (any
	// interface; lock-free snapshot).
	IsLocal(ip netip.Addr) bool
	Start(ctx context.Context) error
}

// MDNS publishes <name>.local and the _https._tcp service (DESIGN §10.5).
type MDNS interface {
	Status() MDNSStatus
	Name() string // effective FQDN e.g. "fileparcel.local"
	Republish(ctx context.Context) error
	Start(ctx context.Context) error
	Stop() error
}

// Notify sends optional e-mail notifications (SMTP).
type Notify interface {
	Enabled() bool
	Send(ctx context.Context, to []string, tmpl string, data any) error
	Test(ctx context.Context, to string) error
}
