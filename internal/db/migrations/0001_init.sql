-- 0001_init: complete initial schema (DESIGN §6). Applied in one transaction by db.Migrate.
-- Conventions: *_at = INTEGER Unix ms UTC; IDs TEXT with prefixes; JSON columns TEXT;
-- sensitive columns field-encrypted (_enc, DESIGN §7.5).

CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
-- install_id, created_at, mk_id, mk_check, setup_token_hash, audit_anchor_seq, audit_anchor_hash

CREATE TABLE users (
  id TEXT PRIMARY KEY, username TEXT NOT NULL COLLATE NOCASE UNIQUE,
  display_name TEXT NOT NULL DEFAULT '', email TEXT COLLATE NOCASE UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('owner','admin','member','guest')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  password_hash TEXT, password_changed_at INTEGER, must_change_password INTEGER NOT NULL DEFAULT 0,
  webauthn_handle BLOB NOT NULL UNIQUE, quota_bytes INTEGER,
  failed_logins INTEGER NOT NULL DEFAULT 0, lock_level INTEGER NOT NULL DEFAULT 0, locked_until INTEGER,
  last_login_at INTEGER, last_login_ip TEXT, prefs TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, created_by TEXT);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY, token_hash BLOB NOT NULL UNIQUE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  auth_level INTEGER NOT NULL, mfa_method TEXT, csrf_secret BLOB NOT NULL, remember INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL, idle_expires_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, elevated_until INTEGER, ip TEXT, user_agent TEXT,
  client_cert_serial TEXT, revoked_at INTEGER);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE INDEX sessions_exp ON sessions(expires_at);

CREATE TABLE totp_secrets (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  secret_enc TEXT NOT NULL, confirmed_at INTEGER, last_step INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE recovery_codes (id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_mac BLOB NOT NULL, used_at INTEGER, created_at INTEGER NOT NULL);
CREATE INDEX recovery_user ON recovery_codes(user_id);
CREATE TABLE webauthn_credentials (id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id BLOB NOT NULL UNIQUE, name TEXT NOT NULL DEFAULT 'Passkey',
  credential_enc TEXT NOT NULL,                 -- webauthn.Credential JSON, field-encrypted
  aaguid BLOB, sign_count INTEGER NOT NULL DEFAULT 0,
  backup_eligible INTEGER NOT NULL DEFAULT 0, backup_state INTEGER NOT NULL DEFAULT 0,
  rp_id TEXT NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER);
CREATE INDEX webauthn_user ON webauthn_credentials(user_id);
CREATE TABLE api_tokens (id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL,
  token_hash BLOB NOT NULL UNIQUE, scopes TEXT NOT NULL, created_at INTEGER NOT NULL,
  expires_at INTEGER, last_used_at INTEGER, last_used_ip TEXT, revoked_at INTEGER);
CREATE TABLE client_certs (id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL,
  serial TEXT NOT NULL UNIQUE, fingerprint_sha256 TEXT NOT NULL UNIQUE,
  not_before INTEGER NOT NULL, not_after INTEGER NOT NULL, issued_by TEXT, issued_at INTEGER NOT NULL,
  revoked_at INTEGER, revoke_reason TEXT, last_seen_at INTEGER);

CREATE TABLE groups (id TEXT PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE UNIQUE,
  description TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, created_by TEXT);
CREATE TABLE group_members (
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('member','manager')), added_at INTEGER NOT NULL,
  PRIMARY KEY (group_id, user_id)) WITHOUT ROWID;
CREATE INDEX group_members_user ON group_members(user_id);
CREATE TABLE invites (id TEXT PRIMARY KEY, token_hash BLOB NOT NULL UNIQUE, token_enc TEXT NOT NULL,
  email TEXT, role TEXT NOT NULL CHECK (role IN ('admin','member','guest')),
  group_ids TEXT NOT NULL DEFAULT '[]', quota_bytes INTEGER,
  max_uses INTEGER NOT NULL DEFAULT 1, uses INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL,
  note TEXT, created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL, revoked_at INTEGER);

CREATE TABLE spaces (id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('user','group')),
  owner_user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  group_id TEXT REFERENCES groups(id) ON DELETE CASCADE,
  name TEXT NOT NULL, quota_bytes INTEGER, used_bytes INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
  CHECK ((kind='user' AND owner_user_id IS NOT NULL AND group_id IS NULL)
      OR (kind='group' AND group_id IS NOT NULL AND owner_user_id IS NULL)));
CREATE UNIQUE INDEX spaces_user ON spaces(owner_user_id) WHERE kind='user';
CREATE UNIQUE INDEX spaces_group ON spaces(group_id) WHERE kind='group';

CREATE TABLE keyring (id TEXT PRIMARY KEY,
  purpose TEXT NOT NULL CHECK (purpose IN ('blob','field','mac')),
  mk_id TEXT NOT NULL, wrapped BLOB NOT NULL,            -- nonce||ct, AES-256-GCM under MK, AAD "fp-kek|<id>|<purpose>"
  state TEXT NOT NULL CHECK (state IN ('active','retired')),
  created_at INTEGER NOT NULL, retired_at INTEGER);
CREATE UNIQUE INDEX keyring_active ON keyring(purpose) WHERE state='active';

CREATE TABLE blobs (id TEXT PRIMARY KEY,
  state TEXT NOT NULL CHECK (state IN ('staging','ready','deleting')),
  size INTEGER NOT NULL, stored_size INTEGER, cipher INTEGER NOT NULL, seg_log2 INTEGER NOT NULL DEFAULT 16,
  kek_id TEXT NOT NULL REFERENCES keyring(id), wrapped_dek BLOB NOT NULL,
  content_hash TEXT, parts_done INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, verified_at INTEGER);
CREATE INDEX blobs_kek ON blobs(kek_id);
CREATE INDEX blobs_state ON blobs(state, created_at);

-- nodes has an explicit INTEGER PRIMARY KEY (rid) so FTS5 external-content rowids survive VACUUM / VACUUM INTO.
CREATE TABLE nodes (rid INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE,
  space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
  parent_id TEXT REFERENCES nodes(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('folder','file')),
  name TEXT NOT NULL, name_key TEXT NOT NULL,           -- NFC; casefold(NFC)
  size INTEGER NOT NULL DEFAULT 0, mime TEXT, version_id TEXT,  -- no FK (cycle); code-maintained
  content_hash TEXT, client_mtime INTEGER,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  trashed_at INTEGER, trashed_by TEXT, trash_root INTEGER NOT NULL DEFAULT 0,
  thumb_blob_id TEXT REFERENCES blobs(id) ON DELETE SET NULL);
CREATE UNIQUE INDEX nodes_root ON nodes(space_id) WHERE parent_id IS NULL;
CREATE UNIQUE INDEX nodes_live_name ON nodes(parent_id, name_key) WHERE trashed_at IS NULL;
CREATE INDEX nodes_children ON nodes(parent_id, kind, name_key);
CREATE INDEX nodes_trash ON nodes(space_id, trash_root, trashed_at) WHERE trashed_at IS NOT NULL;
CREATE INDEX nodes_recent ON nodes(space_id, updated_at);
CREATE VIRTUAL TABLE nodes_fts USING fts5(name, content='nodes', content_rowid='rid', tokenize='trigram');
CREATE TRIGGER nodes_fts_ai AFTER INSERT ON nodes BEGIN
  INSERT INTO nodes_fts(rowid, name) VALUES (new.rid, new.name); END;
CREATE TRIGGER nodes_fts_ad AFTER DELETE ON nodes BEGIN
  INSERT INTO nodes_fts(nodes_fts, rowid, name) VALUES ('delete', old.rid, old.name); END;
CREATE TRIGGER nodes_fts_au AFTER UPDATE OF name ON nodes BEGIN
  INSERT INTO nodes_fts(nodes_fts, rowid, name) VALUES ('delete', old.rid, old.name);
  INSERT INTO nodes_fts(rowid, name) VALUES (new.rid, new.name); END;
-- search: trigram MATCH for queries >= 3 chars; LIKE on name_key for shorter queries.

CREATE TABLE file_versions (id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  blob_id TEXT NOT NULL REFERENCES blobs(id), size INTEGER NOT NULL, content_hash TEXT,
  created_at INTEGER NOT NULL, created_by TEXT REFERENCES users(id) ON DELETE SET NULL);
CREATE INDEX versions_node ON file_versions(node_id, created_at DESC);
CREATE INDEX versions_blob ON file_versions(blob_id);

CREATE TABLE node_grants (id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  subject_type TEXT NOT NULL CHECK (subject_type IN ('user','group')), subject_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('viewer','editor')), created_by TEXT,
  created_at INTEGER NOT NULL, expires_at INTEGER,
  UNIQUE (node_id, subject_type, subject_id));
CREATE INDEX grants_subject ON node_grants(subject_type, subject_id);
CREATE TABLE stars (user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE, created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, node_id)) WITHOUT ROWID;

CREATE TABLE shares (id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('link','request')),
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  created_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash BLOB NOT NULL UNIQUE, token_enc TEXT NOT NULL, title TEXT, message TEXT,
  password_hash TEXT, password_version INTEGER NOT NULL DEFAULT 0,
  allow_download INTEGER NOT NULL DEFAULT 1, allow_preview INTEGER NOT NULL DEFAULT 1,
  allow_upload INTEGER NOT NULL DEFAULT 0, require_uploader_name INTEGER NOT NULL DEFAULT 0,
  upload_max_file_bytes INTEGER, upload_quota_bytes INTEGER, upload_used_bytes INTEGER NOT NULL DEFAULT 0,
  max_downloads INTEGER, download_count INTEGER NOT NULL DEFAULT 0, expires_at INTEGER,
  notify_owner INTEGER NOT NULL DEFAULT 0, disabled_at INTEGER,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, last_access_at INTEGER);
CREATE INDEX shares_node ON shares(node_id);
CREATE INDEX shares_owner ON shares(created_by, created_at);
CREATE TABLE share_access_log (id INTEGER PRIMARY KEY,
  share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE, at INTEGER NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('view','preview','download','zip','upload','password_ok','password_fail','blocked')),
  node_id TEXT, bytes INTEGER, ip TEXT, user_agent TEXT, uploader TEXT);
CREATE INDEX share_access_share ON share_access_log(share_id, at);

CREATE TABLE upload_batches (id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,  -- quota owner (share owner for requests)
  share_id TEXT REFERENCES shares(id) ON DELETE CASCADE, uploader TEXT, actor_session TEXT,
  folder_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  mode TEXT NOT NULL CHECK (mode IN ('files','zip')), zip_name TEXT,
  conflict TEXT NOT NULL CHECK (conflict IN ('rename','replace','skip','fail')),
  declared_files INTEGER NOT NULL DEFAULT 0, declared_bytes INTEGER NOT NULL DEFAULT 0,
  reserved_bytes INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL CHECK (state IN ('open','finalizing','done','aborted','failed','expired')),
  job_id TEXT, result_node_id TEXT, error TEXT,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE INDEX upload_batches_state ON upload_batches(state, expires_at);
CREATE TABLE upload_files (id TEXT PRIMARY KEY,
  batch_id TEXT NOT NULL REFERENCES upload_batches(id) ON DELETE CASCADE,
  client_ref TEXT NOT NULL, rel_path TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'file' CHECK (kind IN ('file','dir')),
  size INTEGER NOT NULL, client_mtime INTEGER, mime TEXT,
  blob_id TEXT REFERENCES blobs(id) ON DELETE SET NULL,
  part_count INTEGER NOT NULL DEFAULT 0, parts_done INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL CHECK (state IN ('pending','uploading','uploaded','committed','skipped','failed','aborted')),
  node_id TEXT, error TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  UNIQUE (batch_id, client_ref));
CREATE TABLE upload_parts (upload_id TEXT NOT NULL REFERENCES upload_files(id) ON DELETE CASCADE,
  n INTEGER NOT NULL, size INTEGER NOT NULL, sha256 BLOB NOT NULL, received_at INTEGER NOT NULL,
  PRIMARY KEY (upload_id, n)) WITHOUT ROWID;

CREATE TABLE archive_tickets (id_hash BLOB PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE, share_id TEXT REFERENCES shares(id) ON DELETE CASCADE,
  node_ids TEXT NOT NULL, format TEXT NOT NULL CHECK (format IN ('zip','tar')), name TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER) WITHOUT ROWID;

CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL,   -- JSON value; secrets stored as JSON string "v1:…" (sealed)
  updated_at INTEGER NOT NULL, updated_by TEXT) WITHOUT ROWID;

CREATE TABLE audit_log (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, at INTEGER NOT NULL,
  actor_id TEXT, actor_name TEXT, actor_via TEXT, ip TEXT, user_agent TEXT, request_id TEXT,
  action TEXT NOT NULL, outcome TEXT NOT NULL CHECK (outcome IN ('success','failure','denied')),
  target_type TEXT, target_id TEXT, target_name TEXT, details TEXT NOT NULL DEFAULT '{}',
  prev_hash BLOB NOT NULL, hash BLOB NOT NULL);  -- hash = MAC("audit", prev_hash || canonical(row))
CREATE INDEX audit_at ON audit_log(at);
CREATE INDEX audit_actor ON audit_log(actor_id, at);
CREATE INDEX audit_action ON audit_log(action, at);
CREATE INDEX audit_target ON audit_log(target_type, target_id);

CREATE TABLE jobs (id TEXT PRIMARY KEY, kind TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('queued','running','succeeded','failed','canceled')),
  params TEXT NOT NULL DEFAULT '{}', result TEXT, error TEXT,
  progress_done INTEGER NOT NULL DEFAULT 0, progress_total INTEGER NOT NULL DEFAULT 0, note TEXT,
  created_by TEXT, schedule TEXT, attempts INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, started_at INTEGER, finished_at INTEGER);
CREATE INDEX jobs_state ON jobs(state, created_at);
CREATE INDEX jobs_kind ON jobs(kind, created_at);
CREATE TABLE schedules (name TEXT PRIMARY KEY, cron TEXT NOT NULL, kind TEXT NOT NULL,
  params TEXT NOT NULL DEFAULT '{}', enabled INTEGER NOT NULL DEFAULT 1,
  last_run_at INTEGER, next_run_at INTEGER, last_job_id TEXT) WITHOUT ROWID;

CREATE TABLE backups (id TEXT PRIMARY KEY,
  scope TEXT NOT NULL CHECK (scope IN ('full','metadata')),
  state TEXT NOT NULL CHECK (state IN ('running','ready','failed')),
  file_name TEXT NOT NULL, size INTEGER, sha256 TEXT,
  encryption TEXT NOT NULL CHECK (encryption IN ('x25519','passphrase')), recipients TEXT,
  blob_count INTEGER, blob_bytes INTEGER, db_size INTEGER, app_version TEXT, schema_version INTEGER,
  note TEXT, trigger TEXT NOT NULL CHECK (trigger IN ('manual','schedule','pre-upgrade','final','import')),
  job_id TEXT, created_by TEXT, created_at INTEGER NOT NULL, finished_at INTEGER,
  verified_at INTEGER, verify_ok INTEGER, error TEXT, copied_to TEXT);
CREATE INDEX backups_created ON backups(created_at);
