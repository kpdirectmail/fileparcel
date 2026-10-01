# FileParcel Encryption at Rest — Format Specification

This document specifies how FileParcel (format version 1) encrypts data at rest: the key hierarchy, the
master key file, the blob (file content) format, key wrapping, field encryption, MACs, rotation and backups.
It is written for auditors and for anyone who wants to verify or re-implement the formats. The user-facing
explanation is in [FILEPARCEL.md — Encryption at rest](FILEPARCEL.md#encryption-at-rest); the overall threat
model is in [SECURITY.md](SECURITY.md).

Notation: `||` is concatenation; `uint64be(x)` is the 8-byte big-endian encoding; strings are UTF-8 without a
terminator; `b64` is standard base64 with padding, `b64url` is URL-safe base64 without padding; *AEAD* is
AES-256-GCM (96-bit nonce, 128-bit tag) unless stated otherwise; a *box* is `nonce || ciphertext || tag`
with a fresh random 96-bit nonce for every encryption. All randomness comes from the operating system's
CSPRNG (`crypto/rand`).

## 1. Goals and non-goals

**Protected at rest:** file contents (all versions), thumbnails, zip-on-upload staging data, backup archives,
TOTP secrets, passkey credentials, share-link and invitation tokens (the recoverable copies), secret
settings (SMTP password, ACME DNS credentials, backup identity and passphrase), the private keys of the
local CA, the client CA and uploaded custom certificates, and the password of a password-protected zip upload
while its batch is in progress (§6.1).

**Not encrypted** (needed for queries or to serve the unlock page): file and folder names, sizes, MIME types
and timestamps; the folder structure; user names, display names and e-mail addresses; group names; share
settings and counters; which file versions are password-protected zips (`file_versions.zip_encryption`); the
audit log (integrity-protected, see §8); the TLS leaf key of the local CA
(`certs/server/leaf.key`, and `leaf.key.next` while it is being replaced) and the ACME/Tailscale certificate
keys; `fileparcel.toml`; logs. Full-disk
encryption is recommended to protect this metadata.

**Integrity:** every encrypted object is authenticated; truncation, extension, reordering and swapping of
encrypted data between objects are detected. Any authentication failure is reported as `corrupt` and no
unauthenticated plaintext is ever returned.

**Not a goal:** protection against an attacker who controls the running server process or the account it
runs as (they can read the keys from memory or the key file), and end-to-end encryption between clients
(the server sees plaintext while serving it).

## 2. Key hierarchy

```
passphrase ──argon2id──► KDF key ─┐                   (sealed mode only)
recovery key ──SHA-256──► RK key ─┤ AEAD-seal
                                   ▼
MK  master key, 32 random bytes          keys/master.key
 ├── KEK[blob]   32 bytes, keyring row, AEAD-wrapped by MK ──► wraps one DEK per blob
 ├── KEK[field]  32 bytes, keyring row, AEAD-wrapped by MK ──► seals DB fields and key files
 └── KEK[mac]    32 bytes, keyring row, AEAD-wrapped by MK ──► HKDF subkeys for HMACs
DEK  32 random bytes per blob, AEAD-wrapped by KEK[blob], stored only in the database
```

Deleting a blob's database row destroys its only wrapped DEK, which crypto-shreds the blob even if the
file on disk survives (e.g. on an SSD).

The MK is held in an `mmap`ed buffer that is excluded from core dumps (Linux `MADV_DONTDUMP`) and
`mlock`ed when the process is allowed to; it is zeroed on lock and shutdown and never logged. This is best
effort: short-lived copies (AES key schedules derived from it, the JSON of a plain key file being written)
pass through ordinary Go memory, and in plain mode the MK is on disk in `keys/master.key` anyway. CA private
keys are unsealed only for the duration of a signing operation.

## 3. Master key file (`keys/master.key`)

JSON, file mode 0600 in a 0700 directory, written atomically (write `master.key.tmp` with `O_EXCL`,
`fsync`, `rename`, `fsync` the directory).

**Plain mode**

```json
{"v":1,"mk_id":"mk_<26 base32>","mode":"plain","key":"<b64 32 bytes>",
 "recovery":{"nonce":"<b64 12 bytes>","ct":"<b64>"},
 "escrow":{"recovery":{"nonce":"<b64>","ct":"<b64>"}}}
```

**Sealed mode**

```json
{"v":1,"mk_id":"mk_…","mode":"sealed",
 "kdf":{"alg":"argon2id","t":3,"m_kib":131072,"p":4,"salt":"<b64 16 bytes>"},
 "nonce":"<b64 12 bytes>","ct":"<b64 AEAD(KDF key, MK, AAD)>",
 "recovery":{"nonce":"<b64>","ct":"<b64>"},
 "escrow":{"pass":{"nonce":"<b64>","ct":"<b64>"},"recovery":{"nonce":"<b64>","ct":"<b64>"}}}
```

| Item | Definition |
|---|---|
| KDF key | `argon2id(passphrase, salt, t, m_kib, p, 32)`. Defaults t=3, m=128 MiB, p=4. When reading a file the parameters are bounded (t ≤ 16, m ≤ 256 MiB — the whole process-wide argon2 budget — p ≤ 16, m ≥ 8·p) so a tampered file cannot exhaust memory; argon2 memory use is bounded process-wide by a semaphore. Passphrases are at least 8 characters and at most 1024 bytes. |
| `ct` | `AES-256-GCM(key = KDF key, nonce, plaintext = MK, AAD = "fp-mk\|" + mk_id)`, ciphertext and tag. |
| `recovery.ct` | `AES-256-GCM(key = SHA-256(RK), nonce, plaintext = MK, AAD = "fp-mk-recovery\|" + mk_id)`. Optional in both modes (created by a sealed initialisation and by making a new recovery key, `fileparcel keys recovery-key`; kept across seal/unseal/passphrase changes because the MK does not change). |
| RK (recovery key) | 32 random bytes, displayed once as `FPRK-` + 52 upper-case Crockford base32 characters in 13 groups of 4 (the last character carries one data bit and four zero bits). Parsing is case-insensitive, ignores dashes and white space and applies Crockford substitutions (O→0, I/L→1). |
| `escrow.pass.ct` | `AES-256-GCM(key = MK, nonce, plaintext = KDF key, AAD = "fp-mk-escrow\|pass\|" + mk_id)`. Sealed mode only. |
| `escrow.recovery.ct` | `AES-256-GCM(key = MK, nonce, plaintext = SHA-256(RK), AAD = "fp-mk-escrow\|recovery\|" + mk_id)`. Present whenever a `recovery` slot is. |

**Escrow.** The optional `escrow` object holds the *unlock secrets* — the argon2id-derived passphrase key and
the recovery hash — sealed **under the MK itself**. Opening them requires the MK, but they outlive it: anyone
who ever held an MK together with the key file that carried it (a copy of a plain key file, or of a sealed one
whose passphrase they learned) keeps the passphrase key and the recovery hash, and since a master rotation keeps
both, they open every later key file too — until the passphrase is changed (which writes a new salt) and a
new recovery key is made (§9). The escrow is what lets **master
rotation keep the passphrase and the recovery key unchanged** (§9) however the server was unlocked
(passphrase or recovery key, before or after a restart) — without it the server would have to ask for the
passphrase again at rotation time.

Key files written before escrow existed, or by hand, remain valid. A damaged entry (one that fails
authentication) or a stale one (a key that no longer opens the file) is ignored rather than blocking an
unlock. Seal, unseal, passphrase change and a new recovery key (`keys recovery-key`) rewrite a consistent set; `unseal` drops
`escrow.pass` and keeps `escrow.recovery`.

**Key check:** the database stores `meta.mk_id` and
`meta.mk_check = hex(HMAC-SHA256(MK, "fp-mk-check|" + mk_id))`. At start the server refuses to use a key file
whose MK does not match (wrong or foreign key file), with a clear error, instead of producing `corrupt`
errors later.

**Locked state:** in sealed mode the server starts *locked*: no KEK can be unwrapped, only the unlock page,
`/trust*`, `/healthz`, `/readyz`, static assets and `/api/v1/system/{status,unlock}` work; everything else
answers `503 keys_locked`. Unlock takes the passphrase or the recovery key (web: rate-limited and restricted
to the networks in `keys.web_unlock`; CLI: over the admin socket).

## 4. Keyring (table `keyring`)

| Column | Meaning |
|---|---|
| `id` | `kek_<26 base32>` |
| `purpose` | `blob`, `field` or `mac` |
| `mk_id` | the MK that wraps it |
| `wrapped` | `nonce \|\| AES-256-GCM(MK, KEK, AAD = "fp-kek\|" + id + "\|" + purpose)` |
| `state` | `active` (exactly one per purpose, enforced by a unique partial index) or `retired` |

Retired KEKs stay until nothing references them; `keys verify` reports those still referenced and
`keys rotate` deletes unreferenced retired KEKs.

## 5. Blobs (file contents and thumbnails)

Stored at `data/blobs/<id[0:2]>/<id[2:4]>/<id>`, where `id` is 32 lower-case hex characters (128 random
bits). Paths are derived only from validated ids and accessed through Go's `os.Root` (no traversal); user
supplied names never reach the file system. Database row: table `blobs` (`size` = plaintext size P, `cipher`,
`seg_log2`, `kek_id`, `wrapped_dek`, `content_hash`, `state`).

### 5.1 DEK wrapping

```
wrapped_dek = nonce || AES-256-GCM(KEK[blob], DEK, AAD = "fp-dek|" + id)     (id as 32 hex characters)
```

`blobs.kek_id` names the KEK. The AAD binds the DEK to its blob, so copying a wrapped DEK to another row fails.

### 5.2 File layout

```
Header, 32 bytes:
  0..3    magic "FPB1"
  4       format version = 1
  5       cipher id: 1 = AES-256-GCM, 2 = ChaCha20-Poly1305 (IETF, 96-bit nonce)
  6       seg_log2 = 16  → S = 65 536 plaintext bytes per segment
  7       flags = 0
  8..23   blob id, 16 raw bytes
  24..31  reserved, zero

Segments i = 0 … N-1, where N = max(1, ceil(P / S)):
  nonce_i (12 random bytes) || ciphertext_i (len_i bytes) || tag_i (16 bytes)          overhead O = 28
  len_i = S for i < N-1;  len_(N-1) = P - (N-1)·S   (0 for an empty blob: one empty final segment)
  ciphertext_i, tag_i = AEAD(DEK, nonce_i, plaintext segment i, AAD_i)
  AAD_i = header[0:32] || uint64be(i) || byte(1 if i = N-1 else 0)

Offset of segment i = 32 + i·(S + O);  stored size = 32 + P + N·O
```

Properties:

- The **final flag** in the AAD detects truncation and extension; the **index** detects reordering; the
  **header with the blob id** detects swapping segments or whole files between blobs; the header also
  authenticates the cipher id and segment size.
- **Random nonces per segment** (not counters) because an upload part may be rewritten on retry; with one DEK
  per blob the number of encryptions per key stays far below the AES-GCM random-nonce limit.
- **Random access:** plaintext offset `o` is in segment `o >> 16` at inner offset `o & 0xFFFF`. The reader
  implements `ReadAt`/`Seek` (HTTP ranges, video seeking) and caches the last decrypted segment. P comes from
  the database and is cross-checked against the file size on open.
- **Cipher selection:** `storage.cipher = auto` uses AES-256-GCM when the CPU has AES and carry-less
  multiplication instructions (amd64 AES+PCLMULQDQ, arm64 AES+PMULL) and ChaCha20-Poly1305 otherwise.
  Readers always honour the header's cipher id.

### 5.3 Writing

- **Streaming writer** (unknown size; zips, thumbnails): buffers one segment, writes segments as they fill,
  marks the last one final on commit, `fsync`s the file and its directory, then sets the row to `ready`.
- **Parted writer** (uploads): the size is declared up front and the file is preallocated. An upload part `n`
  (8 MiB = 128 segments) covers segments `[128n, 128n+127]` at fixed offsets and is written streaming while the
  SHA-256 of the part plaintext is computed; the part counts as done only if that digest equals the one the
  client sent. On commit all parts must be present.
- Staging blobs have `state = staging`; garbage collection removes staging blobs older than 48 hours and files
  without a row.

### 5.4 Content hash

`content_hash = "fp1:" + hex(SHA-256(SHA-256(chunk_0) || SHA-256(chunk_1) || …))` over 8 MiB plaintext chunks
(the empty blob hashes the empty concatenation). It is the same for parted and streamed blobs and is what the
upload client computes; it is not a secret and is not used as a key.

## 6. Field encryption (`KEK[field]`)

```
sealed = "v1:" + kek_id + ":" + b64url(nonce || AES-256-GCM(KEK[field], plaintext, AAD))
```

The AAD binds each value to its row, so values cannot be moved between rows or columns:

| Value | AAD |
|---|---|
| `totp_secrets.secret_enc` | `totp_secrets.secret_enc\|<user_id>` |
| `webauthn_credentials.credential_enc` | `webauthn_credentials.credential_enc\|<credential row id>` |
| `invites.token_enc` | `invites.token_enc\|<invite id>` |
| `shares.token_enc` | `shares.token_enc\|<share id>` |
| `upload_batches.zip_password_enc` | `upload_batches.zip_password_enc\|<batch id>` |
| `settings.value` of secret settings | `settings.value\|<setting key>` |
| `certs/ca/ca.key.enc` (PKCS#8 DER) | `file\|certs/ca/ca.key` |
| `certs/ca/client-ca.key.enc` | `file\|certs/ca/client-ca.key` |
| `certs/custom/key.pem.enc` | `file\|certs/custom/key.pem` |

### 6.1 Password-protected zip files

A zip-on-upload batch may be protected with a password (DESIGN §8.1). That password is a field like the
others of this section: sealed under `KEK[field]` with the AAD `upload_batches.zip_password_enc|<batch id>`
when the batch is created, opened by the `upload.zip` job, and set to NULL by the statement that ends the
batch (done, failed, aborted or expired; an hourly sweep clears any value left on an ended batch). KEK
rotation re-seals it like every other column of the table above.

The .zip itself then carries **two independent layers**:

- the **zip encryption** of its file entries under the uploader's password — WinZip AES-256 (AE-2:
  PBKDF2-HMAC-SHA1 × 1000 with a fresh 16-byte salt per entry → AES-256-CTR with the WinZip little-endian
  counter + HMAC-SHA1-80 over the ciphertext) or the weak legacy ZipCrypto — which recipients need after
  downloading and which FileParcel cannot remove or open once the batch has ended;
- the **at-rest encryption** of the blob that stores the .zip (§5), exactly as for any other file.

Neither depends on the other: rotating or re-encrypting FileParcel's keys leaves the zip encryption as it
is, and the zip password plays no part in FileParcel's key hierarchy. Which versions are protected is
recorded in plain text (`file_versions.zip_encryption` = `aes256`|`zipcrypto`) for the lock badges; the
names, sizes and times inside the .zip are readable to anyone who has the file (a limit of the zip format).
SECURITY.md discusses the strength of both zip methods.

## 7. MACs and token storage (`KEK[mac]`)

`MAC(purpose, parts…) = HMAC-SHA256(K_purpose, frame(part_1) || frame(part_2) || …)` with
`K_purpose = HKDF-SHA256(ikm = KEK[mac], salt = none, info = "fp-mac|" + purpose, 32 bytes)` and
`frame(p) = uint32be(len(p)) || p` (length framing makes the encoding unambiguous). Uses:

| Purpose | Input | Use |
|---|---|---|
| `recovery` | user id, normalised code | stored instead of 2FA recovery codes (low entropy, so not a plain hash) |
| `audit` | previous hash, canonical row | audit chain (§8) |
| `audit.anchor`, audit head | sequence, hash | checkpoints of the audit chain |
| `share` | share id, password version, expiry | share-link access cookie `__Host-fp_s_<last 8 of share id>` = `b64url(exp \|\| MAC)`, 12 h |

High-entropy tokens (session tokens, API tokens `fpt_…`, invitation, share, archive-ticket and setup tokens;
all ≥ 128 random bits) are stored as `SHA-256(token)` and looked up by that hash; comparisons are constant
time. Share and invitation tokens are additionally kept field-encrypted (§6) so owners can copy the link again.
The CSRF token is `b64url(HMAC-SHA256(session.csrf_secret, session.id))`.

Passwords are stored as argon2id PHC strings (`$argon2id$v=19$m=…,t=…,p=…$salt$hash`) and rehashed on login
when the parameters change.

## 8. Audit chain

Each `audit_log` row stores `prev_hash` (the previous row's hash, the prune anchor, or 32 zero bytes for the
first row) and

```
hash = MAC("audit", prev_hash, canonical(row))
canonical(row) = JSON array ["v1", id, at_ms, actor_id, actor_name, actor_via, ip, user_agent,
                             request_id, action, outcome, target_type, target_id, target_name, details]
```

While the keys are locked rows are chained with the unkeyed `SHA-256(prev_hash || canonical(row))` and
re-chained with the MAC ("resealed") as soon as the keys are unlocked. The unkeyed hash needs no key, so such
a row proves nothing about its origin: anyone who can write the database while the keys are unavailable can
append rows that the next unlock seals. The server process remembers the rows it wrote unsealed itself; when
a reseal also seals others (written by an earlier run, an offline command, or someone else), it appends a
sealed `audit.reseal` entry (outcome failure) naming them, and `audit verify` reports them while that entry
is kept. Two MAC-authenticated checkpoints in
the `meta` table — the head (last sealed row) and the prune anchor (last pruned row) — let `audit verify`
detect a truncated tail and verify a pruned log.

## 9. Rotation

- **KEK rotation** (`keys rotate --kek --purpose blob|field`): create a new active KEK, retire the old one, then
  re-wrap every DEK (blob) or re-seal every field and key file (field) in batches of 500 rows per transaction.
  Resumable, because every row names its KEK.
- The **mac KEK** is not rotated on its own (it would invalidate recovery codes, cookies and the audit chain); a
  master rotation re-wraps it unchanged.
- **Master rotation** (`keys rotate --master`): generate MK2, write `keys/master.key.next` (same mode; the
  passphrase and the recovery key stay as they are and are **not** asked for again — MK2 is re-sealed under
  the passphrase key and the recovery hash read from the key file's `escrow` object, §3, or from the unlock
  in progress), re-wrap all keyring rows under MK2 and update `meta.mk_id`/`mk_check` in one
  transaction, then atomically rename `.next` to `master.key`. Crash recovery at start: if `.next` exists,
  it is kept (renamed over `master.key`) when its `mk_id` equals `meta.mk_id`, i.e. when the keyring
  transaction committed; otherwise it is removed. `mk_check` cannot be used here, because computing it
  needs the MK, which a sealed `.next` file does not yield without the passphrase.
  Because the passphrase key and the recovery hash stay the same, a master rotation alone does not lock
  out someone who holds an older key file and its MK (§3): after a suspected leak also change the passphrase
  and make a new recovery key, and if the database may have been copied too, rotate the blob and field
  KEKs and re-encrypt the data (a master rotation re-wraps the KEKs without changing them).
- **Data re-encryption** (`keys rotate --data`, job `keys.reencrypt`): per blob, decrypt and re-encrypt with a
  fresh DEK into a new blob id, switch the references (`file_versions.blob_id`, `nodes.thumb_blob_id`) in one
  transaction, delete the old blob. It pauses while a full backup copies the blobs its database snapshot
  lists (the old blob it deletes would otherwise be missing from the archive) and continues afterwards.
  Metadata backups taken before it refer to the old blob ids: restoring one leaves its files without data
  (the restore reports them, and keeps hard links to the current blobs in `pre-restore-<ts>/` for an
  undo), so take a full backup after a data re-encryption.
  On a key file **without** `escrow` (hand-written or from an older build) the unlock secrets are not known:
  a master rotation after an unlock with the *recovery key* fails with a precondition error ("set a new
  passphrase first"), and an unknown recovery hash invalidates the old recovery key, so a new one must be
  made (`keys status` then reports no recovery key).
- **Seal / unseal / passphrase change** re-encrypt only the key file; the MK and all data stay unchanged.

## 10. Backups

A backup file (`*.fpbak`) is `age( zstd( tar ) )`:

- **age v1** (<https://age-encryption.org/v1>): X25519 recipients (`backup.recipients` plus the server's own
  backup recipient; decrypted with the identity stored as the secret setting `backup.identity`) or a scrypt
  passphrase recipient (`backup.passphrase`). The file starts with `age-encryption.org/v1`. Hybrid
  post-quantum recipients (`age1pq1…`) are accepted too, but age cannot encrypt to both kinds at once: the
  list must be all post-quantum or all classic, and a generated backup identity follows the list's kind.
  The server's own recipient is added to every X25519 backup even when the stored list leaves it out;
  when the list switches to the other kind, a new identity of that kind replaces it (the older ones stay
  in `backup.identity` for older backups, and the doctor asks for the new one to be exported).
- **tar members** (paths relative to the home): `fileparcel-backup.json` (header, first), `data/fileparcel.db`
  (a consistent `VACUUM INTO` snapshot), `fileparcel.toml`, `keys/master.key` (as on disk: plain or sealed),
  `certs/…`, for scope `full` every ready blob `data/blobs/ab/cd/<id>` (already encrypted as in §5, streamed),
  and `manifest.json` (last) with counts and the size and SHA-256 of every other member. Verification checks
  the manifest; deep verification also decrypts every blob with the restored keys (not possible when the
  backup's master key is sealed with a passphrase: the result then says the file contents were not
  decrypted).

Consequence: a backup plus its age identity (or passphrase) is equivalent to the data — plus, in sealed mode,
the master-key passphrase or recovery key. Protect the identity accordingly and keep it offline.

## 11. Algorithms and parameters (summary)

| Purpose | Algorithm |
|---|---|
| Blob segments | AES-256-GCM or ChaCha20-Poly1305, 64 KiB segments, random 96-bit nonces |
| Key wrapping, field sealing, master-key sealing | AES-256-GCM, random 96-bit nonces |
| Passphrase KDF | argon2id t=3, m=128 MiB, p=4, 16-byte salt |
| Password hashing | argon2id (PHC string), concurrency-bounded |
| Subkeys | HKDF-SHA256 |
| MACs | HMAC-SHA256 with length framing |
| Token lookup | SHA-256 |
| Backups | age (X25519 or scrypt) over zstd over tar |
| Password-protected zips (inside the .zip, §6.1) | WinZip AE-2: PBKDF2-HMAC-SHA1 × 1000, AES-256-CTR (little-endian counter), HMAC-SHA1-80; or legacy ZipCrypto |
| TLS (in transit) | TLS 1.2/1.3, AEAD suites only, X25519MLKEM768 hybrid key exchange preferred; ECDSA P-256 local CA and leaf |

Implementations: Go standard library (`crypto/aes`, `crypto/cipher`, `crypto/hkdf`, `crypto/hmac`,
`crypto/sha256`, `crypto/tls`, `crypto/ecdsa`; `crypto/pbkdf2` and `crypto/sha1` for the zip encryption,
written in `internal/ziputil`), `golang.org/x/crypto` (argon2, chacha20poly1305), `filippo.io/age`.
