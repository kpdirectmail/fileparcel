package users

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/ids"
)

// Invite limits.
const (
	inviteTokenBytes     = 24 // 192 bits (≥ 128 required, DESIGN §7.5)
	defaultInviteExpiry  = 7 * 24 * time.Hour
	maxInviteExpiry      = 365 * 24 * time.Hour
	maxInviteUses        = 1000
	maxInviteTokenLength = 128
)

// inviteAAD is the field-encryption AAD of invites.token_enc (DESIGN §7.5).
func inviteAAD(id string) string { return "invites.token_enc|" + id }

// InvitePath returns the root-relative URL of an invite token.
func InvitePath(token string) string { return "/invite/" + token }

// inviteCols selects an invites row plus the name of its custom role (NULL
// when it has none or the role was deleted).
const inviteCols = `id, token_enc, email, role, group_ids, quota_bytes, max_uses, uses, expires_at, note,
	created_by, created_at, revoked_at, role_id, (SELECT r.name FROM roles r WHERE r.id = invites.role_id)`

// inviteRow is a scanned invites row.
type inviteRow struct {
	inv      core.Invite
	tokenEnc string
}

// scanInvite reads an inviteCols row. RoleID is the custom role, else the
// base; RoleName the custom role's name ("Deleted role" when it is gone),
// else the built-in name.
func scanInvite(sc scanner) (*inviteRow, error) {
	var r inviteRow
	var email, note, createdBy, roleID, roleName sql.NullString
	var role, groups string
	var quota, revoked sql.NullInt64
	var expires, created int64
	if err := sc.Scan(&r.inv.ID, &r.tokenEnc, &email, &role, &groups, &quota, &r.inv.MaxUses, &r.inv.Uses,
		&expires, &note, &createdBy, &created, &revoked, &roleID, &roleName); err != nil {
		return nil, err
	}
	r.inv.Email = email.String
	r.inv.Role = core.Role(role)
	r.inv.RoleID = cmp.Or(roleID.String, role)
	switch {
	case roleName.Valid:
		r.inv.RoleName = roleName.String
	case roleID.Valid:
		r.inv.RoleName = deletedRoleName
	default:
		r.inv.RoleName = core.BuiltinRoleName(r.inv.Role)
	}
	if err := json.Unmarshal([]byte(groups), &r.inv.GroupIDs); err != nil || r.inv.GroupIDs == nil {
		r.inv.GroupIDs = []string{}
	}
	r.inv.QuotaBytes = db.FromNullInt64(quota)
	r.inv.ExpiresAt = db.FromMs(expires)
	r.inv.Note = note.String
	r.inv.CreatedBy = createdBy.String
	r.inv.CreatedAt = db.FromMs(created)
	r.inv.RevokedAt = db.FromNullMs(revoked)
	return &r, nil
}

// inviteStatus derives the status of an invite at now.
func inviteStatus(inv *core.Invite, now time.Time) string {
	switch {
	case inv.RevokedAt != nil:
		return core.InviteRevoked
	case inv.Uses >= inv.MaxUses:
		return core.InviteUsed
	case !now.Before(inv.ExpiresAt):
		return core.InviteExpired
	}
	return core.InviteActive
}

// inviteURL is the invite link: absolute when server.public_url is set.
func (s *Service) inviteURL(token string) string {
	return s.publicBase() + InvitePath(token)
}

// publicBase returns server.public_url without a trailing slash ("" when unset).
func (s *Service) publicBase() string {
	if s.env.Config == nil {
		return ""
	}
	return strings.TrimRight(strings.TrimSpace(s.env.Config.Server.PublicURL), "/")
}

// absoluteBase returns a base URL for links in e-mails: server.public_url, or
// the recommended (else first) access URL of the network service.
func (s *Service) absoluteBase(ctx context.Context) string {
	if b := s.publicBase(); b != "" {
		return b
	}
	s.mu.RLock()
	nw := s.network
	s.mu.RUnlock()
	if nw == nil {
		return ""
	}
	urls, err := nw.URLs(ctx)
	if err != nil || len(urls) == 0 {
		return ""
	}
	best := urls[0].URL
	for _, u := range urls {
		if u.Recommended {
			best = u.URL
			break
		}
	}
	return strings.TrimRight(best, "/")
}

// Limits of staff invitations (built-in admin, or a custom role with a
// server permission): single use, and valid for at most 7 days.
const maxStaffInviteExpiry = 7 * 24 * time.Hour

// CreateInvite creates an invitation (invites.manage) and returns it with the
// one-time token; the link is /invite/<token> (Invite.URL, absolute when
// server.public_url is set). The role is in.Role / in.RoleID (default
// member; owner invitations are not possible) and must pass
// core.CheckAssign: a delegate invites only for roles it may hand out,
// initial groups need groups.manage and a quota users.manage. Invitations
// for staff roles are single use and expire within 7 days. These rules are
// checked again when the invitation is accepted (inviteCheck). With in.Send
// the link is e-mailed to in.Email (needs SMTP). An invitation that names an
// e-mail address is single use (the account gets that address, and
// addresses are unique), so max_uses > 1 needs an invitation without one,
// and it is refused (409 on email) while an account already uses the
// address. A failed send does not undo the invitation: the returned
// Invite.EmailError says why no e-mail was queued. A refused escalation is
// audited as denied.
func (s *Service) CreateInvite(ctx context.Context, by *core.Principal, in core.InviteInput) (*core.Invite, string, error) {
	if err := requireCap(by, core.CapInvitesManage); err != nil {
		return nil, "", err
	}
	in.RoleID = strings.TrimSpace(in.RoleID)
	switch {
	case in.Role == core.RoleOwner || (in.Role == "" && in.RoleID == string(core.RoleOwner)):
		field := "role"
		if in.Role == "" {
			field = "role_id"
		}
		return nil, "", core.Invalid(field, "owners cannot be invited; invite an admin and change the role later")
	case in.Role != "" && in.Role != core.RoleAdmin && in.Role != core.RoleMember && in.Role != core.RoleGuest:
		return nil, "", core.Invalid("role", "role must be admin, member or guest")
	}
	email, err := cleanEmail(in.Email)
	if err != nil {
		return nil, "", err
	}
	groups, err := cleanGroupIDs(in.GroupIDs)
	if err != nil {
		return nil, "", err
	}
	if err := requireGroupsFor(by, groups); err != nil {
		return nil, "", err
	}
	quota, err := cleanQuota(in.QuotaBytes, "quota_bytes")
	if err != nil {
		return nil, "", err
	}
	if err := requireQuotaFor(by, quota); err != nil {
		return nil, "", err
	}
	maxUses := in.MaxUses
	if maxUses == 0 {
		maxUses = 1
	}
	if maxUses < 1 || maxUses > maxInviteUses {
		return nil, "", core.Invalid("max_uses", "max_uses must be between 1 and 1000")
	}
	// AcceptInvite gives the new account the invited address, and
	// users.email is UNIQUE: a second acceptance could only fail with a
	// conflict that blames the wrong person. Refuse the combination here
	// instead of handing out a link that stops working after one use. The
	// field is max_uses, not email: that is the one the form must change.
	if maxUses > 1 && email != "" {
		return nil, "", core.Invalid("max_uses",
			"an invitation addressed to an e-mail address creates a single account with that address; leave the e-mail empty for a link several people can use")
	}
	note, err := cleanLongText(in.Note, "note", maxNoteLen)
	if err != nil {
		return nil, "", err
	}
	now := s.now()
	expires := now.Add(defaultInviteExpiry)
	if in.ExpiresAt != nil {
		expires = in.ExpiresAt.UTC()
		if !expires.After(now) {
			return nil, "", core.Invalid("expires_at", "the expiry must be in the future")
		}
		if expires.After(now.Add(maxInviteExpiry)) {
			return nil, "", core.Invalid("expires_at", "invitations expire after at most 365 days")
		}
	}
	var notifier core.Notify
	if in.Send {
		if email == "" {
			return nil, "", core.Invalid("email", "an e-mail address is required to send the invitation")
		}
		if notifier = s.notifier(); notifier == nil {
			return nil, "", core.Invalid("send", "e-mail notifications are not configured")
		}
	}
	if s.env.Keys == nil {
		return nil, "", core.ErrKeysLocked
	}
	id := ids.New(ids.PrefixInvite)
	token := ids.Token(inviteTokenBytes)
	enc, err := s.env.Keys.SealField(inviteAAD(id), []byte(token))
	if err != nil {
		return nil, "", err
	}
	var to *core.RoleDef
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		var err error
		if to, err = resolveAssignment(ctx, tx, in.Role, in.RoleID); err != nil {
			return err
		}
		if to.Base == core.RoleOwner {
			return core.Invalid("role_id", "owners cannot be invited; invite an admin and change the role later")
		}
		if err := core.CheckAssign(by, core.AssignCheck{To: to}); err != nil {
			return err
		}
		if staffRole(to) {
			// A staff invitation creates an account with server permissions
			// and a password of the holder's choosing: keep the window small.
			if maxUses != 1 {
				return core.Invalid("max_uses", "invitations for roles with server permissions can be used once")
			}
			if expires.After(now.Add(maxStaffInviteExpiry)) {
				return core.Invalid("expires_at", "invitations for roles with server permissions expire within 7 days")
			}
		}
		for _, g := range groups {
			var x int
			if err := tx.QueryRowContext(ctx, `SELECT 1 FROM groups WHERE id = ?`, g).Scan(&x); db.IsNoRows(err) {
				return core.Invalid("group_ids", "group "+g+" does not exist")
			} else if err != nil {
				return err
			}
		}
		// AcceptInvite gives the account the invited address, so while an
		// account (active or disabled) holds it the link could only ever
		// fail for the invitee; tell the administrator now instead.
		if email != "" {
			var x int
			err := tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE email = ?`, email).Scan(&x)
			switch {
			case err == nil:
				return conflictField("email", "an account with this e-mail address already exists")
			case !db.IsNoRows(err):
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO invites (id, token_hash, token_enc, email, role, role_id, group_ids,
			quota_bytes, max_uses, uses, expires_at, note, created_by, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)`,
			id, ids.HashToken(token), enc, db.NullString(email), string(to.Base), db.NullString(customRoleID(to)),
			marshalGroupIDs(groups), db.NullInt64(quota), maxUses, db.Ms(expires), db.NullString(note),
			db.NullString(actorID(by)), db.Ms(now)); err != nil {
			return err
		}
		return s.auditByTx(ctx, tx, by, core.AuditEntry{
			Action: core.ActInviteCreate, TargetType: "invite", TargetID: id, TargetName: email,
			Details: map[string]any{"role": to.Base, "role_id": to.ID, "role_name": to.Name, "email": email,
				"groups": groups, "max_uses": maxUses, "expires_at": expires.Format(time.RFC3339), "send": in.Send},
		})
	})
	if err != nil {
		s.auditDenied(ctx, by, core.ActInviteCreate, "invite", "", email, err)
		return nil, "", err
	}
	inv := &core.Invite{
		ID: id, Email: email, Role: to.Base, RoleID: to.ID, RoleName: to.Name, GroupIDs: groups, QuotaBytes: quota,
		MaxUses: maxUses, ExpiresAt: db.FromMs(db.Ms(expires)), Note: note, CreatedBy: actorID(by),
		CreatedAt: db.FromMs(db.Ms(now)), Status: core.InviteActive, URL: s.inviteURL(token),
	}
	if notifier != nil {
		if err := s.sendInvite(ctx, notifier, by, inv, token); err != nil {
			// The invitation exists and its link works: report, don't fail.
			inv.EmailError = sendErrorText(err)
		}
	}
	return inv, token, nil
}

// sendInvite queues the invitation e-mail (delivered asynchronously by
// Notify). It returns why nothing was queued: no absolute base URL for the
// link, or Notify refused the message (queue full, shutting down, bad
// address); the failure is also logged.
func (s *Service) sendInvite(ctx context.Context, n core.Notify, by *core.Principal, inv *core.Invite, token string) error {
	base := s.absoluteBase(ctx)
	if base == "" {
		s.log.Warn("users: invite e-mail not sent: no absolute URL known (set server.public_url)", "invite", inv.ID)
		return core.Errorf(core.ErrUnavailable, "no absolute URL is known for the link; set server.public_url")
	}
	inviter := ""
	if by != nil && by.UserID != "" {
		if u, err := s.Get(ctx, by.UserID); err == nil {
			inviter = u.DisplayName
		}
	}
	data := map[string]any{
		"url": base + InvitePath(token), "inviter": inviter, "role": inv.RoleName,
		"expires_at": inv.ExpiresAt.Format(time.RFC3339), "note": inv.Note, "email": inv.Email,
	}
	if err := n.Send(ctx, []string{inv.Email}, "invite", data); err != nil {
		s.log.Warn("users: invite e-mail not sent", "invite", inv.ID, "err", err)
		return err
	}
	return nil
}

// sendErrorText is the administrator-facing reason of a failed send.
func sendErrorText(err error) string {
	if ce := core.AsError(err); ce != nil && ce.Message != "" {
		return ce.Message
	}
	return "the e-mail could not be queued"
}

// ListInvites lists invitations, newest first (keyset-paginated); by needs
// invites.manage. Active invites carry their link (decrypted from token_enc;
// omitted while the keys are locked) when by may see it (inviteURLVisible):
// everything else of the row is listed, so that any invitation can be
// revoked.
func (s *Service) ListInvites(ctx context.Context, by *core.Principal, q core.PageReq) (core.Page[core.Invite], error) {
	if err := requireCap(by, core.CapInvitesManage); err != nil {
		return core.Page[core.Invite]{}, err
	}
	where := ""
	var args []any
	if q.Cursor != "" {
		c, err := decodeCursor(q.Cursor)
		if err != nil {
			return core.Page[core.Invite]{}, err
		}
		where = ` WHERE (created_at < ? OR (created_at = ? AND id < ?))`
		args = append(args, c.N, c.N, c.I)
	}
	limit := q.EffectiveLimit()
	args = append(args, limit+1)
	rows, err := s.env.DB.Query(ctx, `SELECT `+inviteCols+` FROM invites`+where+` ORDER BY created_at DESC, id DESC LIMIT ?`, args...)
	if err != nil {
		return core.Page[core.Invite]{}, err
	}
	defer rows.Close()
	var list []*inviteRow
	for rows.Next() {
		r, err := scanInvite(rows)
		if err != nil {
			return core.Page[core.Invite]{}, err
		}
		list = append(list, r)
	}
	if err := rows.Err(); err != nil {
		return core.Page[core.Invite]{}, err
	}
	next := ""
	if len(list) > limit {
		list = list[:limit]
		last := list[len(list)-1]
		next = encodeCursor(cursor{N: db.Ms(last.inv.CreatedAt), I: last.inv.ID})
	}
	now := s.now()
	out := make([]core.Invite, 0, len(list))
	roles := map[string]*core.RoleDef{} // the custom roles of the listed invitations (nil: deleted)
	for _, r := range list {
		inv := r.inv
		inv.Status = inviteStatus(&inv, now)
		if inv.Status == core.InviteActive && s.env.Keys != nil && inviteURLVisible(by, &inv, s.inviteRole(ctx, roles, &inv)) {
			if tok, err := s.env.Keys.OpenField(inviteAAD(inv.ID), r.tokenEnc); err == nil {
				inv.URL = s.inviteURL(string(tok))
			} else if !errorsIsKeysLocked(err) {
				s.log.Warn("users: invite token cannot be decrypted", "invite", inv.ID, "err", err)
			}
		}
		out = append(out, inv)
	}
	return core.NewPage(out, next), nil
}

// inviteRole returns the role of inv for inviteURLVisible: the built-in
// role, or its custom role (cached in roles; nil when it was deleted or
// cannot be read, which hides the link from delegates).
func (s *Service) inviteRole(ctx context.Context, roles map[string]*core.RoleDef, inv *core.Invite) *core.RoleDef {
	if !core.IsCustomRoleID(inv.RoleID) {
		return builtinRole(inv.Role)
	}
	r, ok := roles[inv.RoleID]
	if !ok {
		var err error
		if r, err = getRole(ctx, s.env.DB.Reader(), inv.RoleID); err != nil {
			r = nil
		}
		roles[inv.RoleID] = r
	}
	return r
}

// inviteURLVisible reports whether by may see the link of inv, whose role
// is to (DESIGN §6a): an invitation link creates an account with a password
// of the holder's choosing, so it is shown only to built-in owners/admins
// (and the system principal), to the invitation's creator, and to a caller
// who could create the same invitation — core.CheckAssign passes for its
// role, and it adds no groups or the caller holds groups.manage.
func inviteURLVisible(by *core.Principal, inv *core.Invite, to *core.RoleDef) bool {
	switch {
	case by == nil:
		return false
	case by.IsAdmin():
		return true
	case by.UserID != "" && inv.CreatedBy == by.UserID:
		return true
	case len(inv.GroupIDs) > 0 && !by.Can(core.CapGroupsManage):
		return false
	}
	return to != nil && core.CheckAssign(by, core.AssignCheck{To: to}) == nil
}

// RevokeInvite revokes an invitation (invites.manage: revoking any
// invitation only reduces access; idempotent).
func (s *Service) RevokeInvite(ctx context.Context, by *core.Principal, id string) error {
	if err := requireCap(by, core.CapInvitesManage); err != nil {
		return err
	}
	return s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		r, err := scanInvite(tx.QueryRowContext(ctx, `SELECT `+inviteCols+` FROM invites WHERE id = ?`, id))
		if db.IsNoRows(err) {
			return core.NotFoundf("invitation not found")
		}
		if err != nil {
			return err
		}
		if r.inv.RevokedAt != nil {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE invites SET revoked_at = ? WHERE id = ?`, db.Ms(s.now()), id); err != nil {
			return err
		}
		return s.auditByTx(ctx, tx, by, core.AuditEntry{
			Action: core.ActInviteRevoke, TargetType: "invite", TargetID: id, TargetName: r.inv.Email,
			Details: map[string]any{"uses": r.inv.Uses, "status": inviteStatus(&r.inv, s.now())},
		})
	})
}

// Reasons recorded when an account's invitations are revoked because it lost
// the right to issue them (revokeInvitesOfTx).
const (
	revokeCreatorDemoted  = "creator_demoted"
	revokeCreatorDisabled = "creator_disabled"
	revokeCreatorDeleted  = "creator_deleted"
)

// revokeInvitesOfTx revokes the active invitations userID created, inside the
// transaction that takes away that account's right to issue them (a role
// without administrator rights or without invites.manage, disable, delete —
// before the row goes, since invites.created_by is ON DELETE SET NULL). A
// link that outlived its creator's rights would still create accounts on
// their behalf: administrators, holders of a role, or members of any group.
// Each revocation is audited as invite.revoke with the reason. Used, expired
// and already revoked invitations keep their status; the system principal's
// invitations (created_by NULL) are never affected. Re-enabling or promoting
// the account does not restore them.
func (s *Service) revokeInvitesOfTx(ctx context.Context, tx *sql.Tx, by *core.Principal, userID, reason string, now int64) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, COALESCE(email, ''), uses FROM invites
		WHERE created_by = ? AND revoked_at IS NULL AND uses < max_uses AND expires_at > ?`, userID, now)
	if err != nil {
		return err
	}
	type active struct {
		id, email string
		uses      int
	}
	var list []active
	for rows.Next() {
		var a active
		if err := rows.Scan(&a.id, &a.email, &a.uses); err != nil {
			rows.Close()
			return err
		}
		list = append(list, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, a := range list {
		if _, err := tx.ExecContext(ctx, `UPDATE invites SET revoked_at = ? WHERE id = ?`, now, a.id); err != nil {
			return err
		}
		if err := s.auditByTx(ctx, tx, by, core.AuditEntry{
			Action: core.ActInviteRevoke, TargetType: "invite", TargetID: a.id, TargetName: a.email,
			Details: map[string]any{"uses": a.uses, "status": core.InviteActive, "reason": reason, "created_by": userID},
		}); err != nil {
			return err
		}
	}
	return nil
}

// Reasons an open invitation stops being valid although nobody revoked it
// (inviteCheck); recorded on the invite.revoke entries of
// revokeInvalidInvitesTx.
const (
	// revokeStaffLimits: its custom role gained a server permission after
	// the invitation was created, and the invitation is not single use or
	// is valid for more than 7 days (the limits of staff invitations).
	revokeStaffLimits = "staff_limits"
	// revokeCreatorCannotGive: its creator, an account manager, could not
	// create it any more (the role is not delegable now, has server
	// permissions the creator lacks, or the creator lost invites.manage,
	// groups.manage for its groups or users.manage for its quota).
	revokeCreatorCannotGive = "creator_cannot_give"
	// revokeRoleGone: its custom role was deleted or has another base.
	revokeRoleGone = "role_deleted"
)

// inviteCheck decides whether the open invitation inv may still create an
// account, reading through q, and returns the role it gives (reason "") or
// why it may not (reason ≠ ""). The rules of CreateInvite apply to the role
// and the creator as they are now, so that no link creates an account its
// creator could not invite today (DESIGN §6a.4):
//   - a custom role must still exist with the invited base;
//   - a custom role that has a server permission needs a single-use
//     invitation valid for at most 7 days from its creation — an invitation
//     created before the role gained the permission does not become a
//     reusable staff link (built-in admin invitations were checked when they
//     were created; those from before v4 keep working, as the upgrade notes
//     promise);
//   - an invitation created by an account manager (not a built-in
//     owner/admin, not the system principal) needs its creator to be active
//     and to pass what CreateInvite demanded: invites.manage,
//     core.CheckAssign for the role (delegable, server permissions covered),
//     groups.manage for initial groups and users.manage for a quota.
//
// creators caches the creators' accounts by id (nil: deleted).
func inviteCheck(ctx context.Context, q queryer, inv *core.Invite, creators map[string]*core.User) (*core.RoleDef, string, error) {
	to := builtinRole(inv.Role)
	if core.IsCustomRoleID(inv.RoleID) {
		r, err := getRole(ctx, q, inv.RoleID)
		switch {
		case errors.Is(err, core.ErrNotFound):
			return nil, revokeRoleGone, nil
		case err != nil:
			return nil, "", err
		case r.Base != inv.Role:
			return nil, revokeRoleGone, nil
		}
		to = r
		if staffRole(to) && (inv.MaxUses != 1 || inv.ExpiresAt.Sub(inv.CreatedAt) > maxStaffInviteExpiry) {
			return nil, revokeStaffLimits, nil
		}
	}
	if to == nil {
		return nil, revokeRoleGone, nil
	}
	if inv.CreatedBy == "" { // the system principal (admin socket, offline CLI)
		return to, "", nil
	}
	u, ok := creators[inv.CreatedBy]
	if !ok {
		var err error
		if u, err = getUser(ctx, q, inv.CreatedBy); errors.Is(err, core.ErrNotFound) {
			u = nil
		} else if err != nil {
			return nil, "", err
		}
		creators[inv.CreatedBy] = u
	}
	if u == nil || u.Status != core.UserActive {
		return nil, revokeCreatorCannotGive, nil
	}
	by := creatorPrincipal(u)
	if by.IsAdmin() {
		return to, "", nil
	}
	if !by.Can(core.CapInvitesManage) || core.CheckAssign(by, core.AssignCheck{To: to}) != nil ||
		requireGroupsFor(by, inv.GroupIDs) != nil || requireQuotaFor(by, inv.QuotaBytes) != nil {
		return nil, revokeCreatorCannotGive, nil
	}
	return to, "", nil
}

// creatorPrincipal is the principal of the account u as auth would build it
// for a browser session now (role, custom role and its permissions), for
// re-checking what u may give (inviteCheck).
func creatorPrincipal(u *core.User) *core.Principal {
	p := &core.Principal{UserID: u.ID, Username: u.Username, Role: u.Role, RoleID: u.RoleID, RoleName: u.RoleName,
		Via: core.ViaSession, AuthLevel: core.AuthLevelFull}
	p.SetCaps(u.Permissions)
	return p
}

// revokeInvalidInvitesTx revokes the open invitations that inviteCheck no
// longer accepts, inside the transaction of a change that can invalidate
// them — a role edit (permissions, delegable), an account's role change, the
// deletion of a role whose holders move — after that change was written.
// Accepting such an invitation already fails; revoking it as well makes the
// list say so instead of showing a link that no longer works. Each
// revocation is audited as invite.revoke with the reason and the creator.
func (s *Service) revokeInvalidInvitesTx(ctx context.Context, tx *sql.Tx, by *core.Principal, now int64) error {
	rows, err := tx.QueryContext(ctx, `SELECT `+inviteCols+` FROM invites
		WHERE revoked_at IS NULL AND uses < max_uses AND expires_at > ?`, now)
	if err != nil {
		return err
	}
	var open []*inviteRow
	for rows.Next() {
		r, err := scanInvite(rows)
		if err != nil {
			rows.Close()
			return err
		}
		open = append(open, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	creators := map[string]*core.User{}
	for _, r := range open {
		inv := &r.inv
		_, reason, err := inviteCheck(ctx, tx, inv, creators)
		if err != nil {
			return err
		}
		if reason == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE invites SET revoked_at = ? WHERE id = ?`, now, inv.ID); err != nil {
			return err
		}
		details := map[string]any{"uses": inv.Uses, "status": core.InviteActive, "reason": reason,
			"role_id": inv.RoleID, "role_name": inv.RoleName}
		if inv.CreatedBy != "" {
			details["created_by"] = inv.CreatedBy
		}
		if err := s.auditByTx(ctx, tx, by, core.AuditEntry{
			Action: core.ActInviteRevoke, TargetType: "invite", TargetID: inv.ID, TargetName: inv.Email, Details: details,
		}); err != nil {
			return err
		}
	}
	return nil
}

// errInviteInvalid is the uniform answer for unknown, expired, used and
// revoked invitation tokens (no oracle).
func errInviteInvalid() error { return core.NotFoundf("this invitation is invalid or has expired") }

// findInvite looks up an active invite by token through q.
func (s *Service) findInvite(ctx context.Context, q queryer, token string) (*inviteRow, error) {
	if len(token) > maxInviteTokenLength || !ids.ValidToken(token) {
		return nil, errInviteInvalid()
	}
	r, err := scanInvite(q.QueryRowContext(ctx, `SELECT `+inviteCols+` FROM invites WHERE token_hash = ?`, ids.HashToken(token)))
	if db.IsNoRows(err) {
		return nil, errInviteInvalid()
	}
	if err != nil {
		return nil, err
	}
	r.inv.Status = inviteStatus(&r.inv, s.now())
	if r.inv.Status != core.InviteActive {
		return nil, errInviteInvalid()
	}
	return r, nil
}

// LookupInvite returns the active invitation for token (for the accept page:
// without URL or creator ID, but with the creator's display name as
// InvitedBy, as in the invite e-mail; the note is the administrator's message
// to the invitee). Unknown, expired, used and revoked tokens, and those
// AcceptInvite would refuse (inviteCheck), all return the same 404.
func (s *Service) LookupInvite(ctx context.Context, token string) (*core.Invite, error) {
	q := s.env.DB.Reader()
	r, err := s.findInvite(ctx, q, token)
	if err != nil {
		return nil, err
	}
	if _, reason, err := inviteCheck(ctx, q, &r.inv, map[string]*core.User{}); err != nil {
		return nil, err
	} else if reason != "" {
		return nil, errInviteInvalid()
	}
	inv := r.inv
	if inv.CreatedBy != "" {
		if u, err := s.Get(ctx, inv.CreatedBy); err == nil {
			inv.InvitedBy = u.DisplayName
		}
	}
	inv.CreatedBy = ""
	return &inv, nil
}

// AcceptInvite validates the invitation and creates the account atomically
// (role, quota and groups from the invite; groups deleted meanwhile are
// skipped). An invitation that inviteCheck refuses — its custom role was
// deleted, became a staff role the invitation is too wide for, or its
// creator could no longer create it — is invalid (the uniform 404). phc is
// the argon2id hash of in.Password computed by the caller. When the invite
// names an e-mail address, the account gets that address.
func (s *Service) AcceptInvite(ctx context.Context, token string, in core.AcceptInvite, phc string, meta core.ReqMeta) (*core.User, error) {
	if err := checkPHC(phc); err != nil {
		return nil, err
	}
	nu := core.NewUser{Username: in.Username, DisplayName: in.DisplayName, Email: in.Email, PasswordHash: phc}
	f, err := validateNewUser(nu)
	if err != nil {
		return nil, err
	}
	ip := ""
	if meta.IP.IsValid() {
		ip = meta.IP.String()
	}
	var id string
	err = s.env.DB.Tx(ctx, func(tx *sql.Tx) error {
		r, err := s.findInvite(ctx, tx, token)
		if err != nil {
			return err
		}
		inv := &r.inv
		uf := *f
		if inv.Email != "" {
			if uf.email != "" && !strings.EqualFold(uf.email, inv.Email) {
				return core.Invalid("email", "use the e-mail address the invitation was sent to")
			}
			uf.email = inv.Email
		}
		// The role and the creator's right to give it are checked again: an
		// invitation whose role is gone (or no longer has the invited base),
		// grew into a staff role, or that its creator could not create any
		// more is as invalid as a revoked one.
		to, reason, err := inviteCheck(ctx, tx, inv, map[string]*core.User{})
		if err != nil {
			return err
		}
		if reason != "" {
			return errInviteInvalid()
		}
		uf.role, uf.roleID = to.Base, customRoleID(to)
		uf.quota = inv.QuotaBytes
		uf.groupIDs = inv.GroupIDs
		now := s.now()
		res, err := tx.ExecContext(ctx, `UPDATE invites SET uses = uses + 1
			WHERE id = ? AND revoked_at IS NULL AND uses < max_uses AND expires_at > ?`, inv.ID, db.Ms(now))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return errInviteInvalid()
		}
		id = ids.New(ids.PrefixUser)
		if err := insertUser(ctx, tx, id, &uf, insertOpts{createdBy: inv.CreatedBy}, db.Ms(now)); err != nil {
			return err
		}
		actor := core.AuditEntry{ActorID: id, ActorName: uf.username, ActorVia: "invite", IP: ip,
			UserAgent: meta.UserAgent, RequestID: meta.RequestID}
		e := actor
		e.Action, e.TargetType, e.TargetID, e.TargetName = core.ActUserCreate, "user", id, uf.username
		e.Details = map[string]any{"role": uf.role, "role_id": to.ID, "role_name": to.Name, "email": uf.email,
			"groups": uf.groupIDs, "invite_id": inv.ID}
		if err := s.auditTx(ctx, tx, e); err != nil {
			return err
		}
		e = actor
		e.Action, e.TargetType, e.TargetID, e.TargetName = core.ActInviteAccept, "invite", inv.ID, inv.Email
		e.Details = map[string]any{"user_id": id, "username": uf.username, "role": uf.role, "role_id": to.ID,
			"role_name": to.Name, "uses": inv.Uses + 1}
		return s.auditTx(ctx, tx, e)
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

// errorsIsKeysLocked reports whether err means the keys are unavailable.
func errorsIsKeysLocked(err error) bool { return errors.Is(err, core.ErrKeysLocked) }
