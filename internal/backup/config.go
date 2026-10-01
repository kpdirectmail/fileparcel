package backup

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"filippo.io/age"

	"fileparcel/internal/core"
)

// Config implements core.Backups: the backup.* settings in one object
// (secrets reported only as HasIdentity/HasPassphrase).
func (s *Service) Config(ctx context.Context) (*core.BackupConfig, error) {
	st := s.env.Settings
	if st == nil {
		return nil, core.Errorf(core.ErrUnavailable, "settings unavailable")
	}
	c := &core.BackupConfig{
		Enabled:       st.Bool(SettingEnabled),
		ScheduleMeta:  st.String(SettingScheduleMeta),
		ScheduleFull:  st.String(SettingScheduleFull),
		KeepLast:      int(st.Int(SettingKeepLast)),
		KeepDaily:     int(st.Int(SettingKeepDaily)),
		KeepWeekly:    int(st.Int(SettingKeepWeekly)),
		KeepMonthly:   int(st.Int(SettingKeepMonthly)),
		Encryption:    st.String(SettingEncryption),
		Recipients:    st.Strings(SettingRecipients),
		CopyTo:        copyToDir(st.String(SettingCopyTo)),
		HasIdentity:   secretSet(st, SettingIdentity),
		HasPassphrase: secretSet(st, SettingPassphrase),
	}
	if c.Recipients == nil {
		c.Recipients = []string{}
	}
	// The server's own backup key is a recipient of every backup whatever
	// the list says (encryptionPlan): report it, so an empty list does not
	// read as "no recipient". Unknown while the keys are locked.
	if c.HasIdentity {
		if own, err := s.ownRecipient(); err == nil {
			c.IdentityRecipient = own
		}
	}
	return c, nil
}

// SetConfig implements core.Backups: validates and stores every field in
// one settings change (audited as settings.change; secrets masked). A nil
// Passphrase keeps the stored one; "" clears it.
func (s *Service) SetConfig(ctx context.Context, by *core.Principal, c core.BackupConfig) error {
	st := s.env.Settings
	if st == nil {
		return core.Errorf(core.ErrUnavailable, "settings unavailable")
	}
	if c.Encryption == "" {
		c.Encryption = core.BackupX25519
	}
	if c.Encryption != core.BackupX25519 && c.Encryption != core.BackupPassphrase {
		return core.Invalid("encryption", "encryption must be x25519 or passphrase")
	}
	for _, v := range []struct {
		field string
		n     int
	}{{"keep_last", c.KeepLast}, {"keep_daily", c.KeepDaily}, {"keep_weekly", c.KeepWeekly}, {"keep_monthly", c.KeepMonthly}} {
		if v.n < 0 {
			return core.Invalid(v.field, "must not be negative")
		}
	}
	recips := make([]string, 0, len(c.Recipients))
	for _, r := range c.Recipients {
		r = strings.TrimSpace(r)
		if r != "" && !slices.Contains(recips, r) {
			recips = append(recips, r)
		}
	}
	// The list replaces the stored one, but the server's own backup key
	// stays in it (encryptionPlan adds it to every backup anyway; this keeps
	// the list shown the one backups use, also while the keys are locked).
	// A list of the other kind (classic or post-quantum) cannot hold it: in
	// x25519 mode the identity then follows the list's kind, as a generated
	// one does, and a new one is made once the list is stored.
	own, err := s.ownRecipient()
	if err != nil && !errors.Is(err, core.ErrKeysLocked) {
		return err
	}
	regenerate := false
	if own != "" {
		if l, ok := withRecipient(recips, own); ok {
			recips = l
		} else {
			regenerate = c.Encryption == core.BackupX25519
		}
	}
	// A copy inside the FileParcel home is no second copy. Checked when the
	// value changes (a stored one from before the rule does not block the
	// other fields; the copy step refuses it).
	if dir := copyToDir(c.CopyTo); dir != copyToDir(st.String(SettingCopyTo)) {
		if err := validCopyTo(dir); err != nil {
			return core.Invalid("copy_to", err.Error())
		}
		if err := s.checkCopyTo(dir); err != nil {
			return err
		}
	}
	if c.Encryption == core.BackupPassphrase {
		willHave := secretSet(st, SettingPassphrase)
		if c.Passphrase != nil {
			willHave = *c.Passphrase != ""
		}
		if !willHave {
			return core.Invalid("passphrase", "set a backup passphrase to use passphrase encryption")
		}
	}
	changes := map[string]json.RawMessage{}
	put := func(key string, v any) {
		b, _ := json.Marshal(v)
		changes[key] = b
	}
	put(SettingEnabled, c.Enabled)
	put(SettingScheduleMeta, strings.TrimSpace(c.ScheduleMeta))
	put(SettingScheduleFull, strings.TrimSpace(c.ScheduleFull))
	put(SettingKeepLast, c.KeepLast)
	put(SettingKeepDaily, c.KeepDaily)
	put(SettingKeepWeekly, c.KeepWeekly)
	put(SettingKeepMonthly, c.KeepMonthly)
	put(SettingEncryption, c.Encryption)
	put(SettingRecipients, recips)
	put(SettingCopyTo, copyToDir(c.CopyTo))
	if c.Passphrase != nil {
		put(SettingPassphrase, *c.Passphrase)
	}
	if _, err := st.Set(ctx, by, changes); err != nil {
		return err
	}
	if regenerate {
		s.log.Warn("backup: the new backup recipients are of the other kind (classic or post-quantum) than the backup identity; generating a backup identity of their kind (export it from the Backups page and keep it safe)")
		if _, _, err := s.generateIdentity(ctx, by, false); err != nil {
			return err
		}
	}
	return nil
}

// ownRecipient returns the recipient of the stored backup identity ("" when
// none is stored). It fails with core.ErrKeysLocked while the keys are locked.
func (s *Service) ownRecipient() (string, error) {
	file, err := s.env.Settings.Secret(SettingIdentity)
	if err != nil {
		return "", err
	}
	return primaryRecipient(file), nil
}

// withRecipient returns list with recipient r (the server's own backup key)
// added at the end unless an entry already holds it. ok is false, and list
// is returned unchanged, when r is of the other kind (classic or
// post-quantum) than the recipients of list: age cannot encrypt to both.
func withRecipient(list []string, r string) (out []string, ok bool) {
	var all []age.Recipient
	for _, l := range list {
		if slices.Contains(strings.Fields(l), r) {
			return list, true
		}
		if rs, err := parseRecipients(l); err == nil {
			all = append(all, rs...)
		}
	}
	rs, err := parseRecipients(r)
	if err != nil {
		return list, true // not a recipient string; nothing to add
	}
	if checkRecipientMix(append(all, rs...)) != nil {
		return list, false
	}
	return append(slices.Clone(list), r), true
}

// GenerateIdentity implements core.Backups: creates a new X25519 identity (a
// hybrid post-quantum one when the other recipients are post-quantum, since
// age cannot mix the two kinds), stores it as backup.identity (previous identities are kept below it for
// decrypting older backups), replaces the previous identity's recipient in
// backup.recipients with the new one and returns the recipient and the
// identity file (shown once).
func (s *Service) GenerateIdentity(ctx context.Context, by *core.Principal) (string, string, error) {
	return s.generateIdentity(ctx, by, true)
}

func (s *Service) generateIdentity(ctx context.Context, by *core.Principal, exported bool) (string, string, error) {
	st := s.env.Settings
	if st == nil {
		return "", "", core.Errorf(core.ErrUnavailable, "settings unavailable")
	}
	old, err := st.Secret(SettingIdentity)
	if err != nil {
		return "", "", err
	}
	oldRecipient := primaryRecipient(old)
	recips := []string{}
	var kept []age.Recipient
	for _, r := range st.Strings(SettingRecipients) {
		if r != oldRecipient && !slices.Contains(recips, r) {
			recips = append(recips, r)
			if rs, err := parseRecipients(r); err == nil {
				kept = append(kept, rs...)
			}
		}
	}
	// age cannot encrypt to post-quantum and classic recipients together: the
	// new identity is of the kind the other recipients (or, without any, the
	// identity it replaces) already are.
	var identity, recipient string
	if hasHybrid(kept) || (len(kept) == 0 && strings.HasPrefix(oldRecipient, "age1pq1")) {
		id, err := age.GenerateHybridIdentity()
		if err != nil {
			return "", "", err
		}
		identity, recipient = id.String(), id.Recipient().String()
	} else {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			return "", "", err
		}
		identity, recipient = id.String(), id.Recipient().String()
	}
	recips = append(recips, recipient)
	file := newIdentityFile(identity, old, s.env.Now())
	fb, _ := json.Marshal(file)
	rb, _ := json.Marshal(recips)
	if _, err := st.Set(ctx, by, map[string]json.RawMessage{SettingIdentity: fb, SettingRecipients: rb}); err != nil {
		return "", "", err
	}
	if exported {
		s.markExported(ctx)
	} else {
		s.clearExported(ctx)
	}
	s.log.Info("backup identity generated", "recipient", recipient)
	return recipient, file, nil
}

// ExportIdentity returns the stored backup identity file and the recipient
// of its active identity (POST /admin/backups/identity/export, elevated).
// It is audited and recorded as exported for the doctor check.
func (s *Service) ExportIdentity(ctx context.Context, by *core.Principal) (string, string, error) {
	st := s.env.Settings
	if st == nil {
		return "", "", core.Errorf(core.ErrUnavailable, "settings unavailable")
	}
	file, err := st.Secret(SettingIdentity)
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(file) == "" {
		return "", "", core.NotFoundf("no backup identity is configured")
	}
	s.markExported(ctx)
	if by != nil {
		ctx = core.WithPrincipal(ctx, by)
	}
	s.audit(ctx, core.AuditEntry{Action: core.ActBackupDownload, TargetType: "backup_identity",
		TargetName: primaryRecipient(file), Details: map[string]any{"identity": true}})
	return primaryRecipient(file), file, nil
}

func (s *Service) markExported(ctx context.Context) {
	if err := s.setMeta(context.WithoutCancel(ctx), metaIdentityExported, s.env.Now().UTC().Format(time.RFC3339)); err != nil {
		s.log.Warn("backup: recording the identity export failed", "err", err)
	}
}

// clearExported forgets an earlier export when the server made an identity
// nobody has seen: that export was of another identity, which cannot decrypt
// the backups made from now on, so the doctor must warn again.
func (s *Service) clearExported(ctx context.Context) {
	if _, err := s.env.DB.Exec(context.WithoutCancel(ctx), `DELETE FROM meta WHERE key = ?`, metaIdentityExported); err != nil {
		s.log.Warn("backup: clearing the identity export record failed", "err", err)
	}
}

// configuredIdentities returns the identities that decrypt this server's
// backups: backup.identity and (when set) the backup passphrase. It needs
// the keys to be unlocked.
func (s *Service) configuredIdentities() ([]age.Identity, error) {
	c, err := s.configuredCreds()
	if err != nil {
		return nil, err
	}
	ids, err := credsIdentities(c)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, core.Invalid("identity", "no backup identity or passphrase is configured")
	}
	return ids, nil
}

// configuredCreds returns the stored secrets as RestoreCreds.
func (s *Service) configuredCreds() (core.RestoreCreds, error) {
	var c core.RestoreCreds
	st := s.env.Settings
	if st == nil {
		return c, core.Errorf(core.ErrUnavailable, "settings unavailable")
	}
	id, err := st.Secret(SettingIdentity)
	if err != nil {
		return c, err
	}
	pass, err := st.Secret(SettingPassphrase)
	if err != nil {
		return c, err
	}
	c.Identity, c.Passphrase = id, pass
	return c, nil
}

// resolveCreds returns c, or the configured secrets when c is empty.
func (s *Service) resolveCreds(c core.RestoreCreds) (core.RestoreCreds, error) {
	if strings.TrimSpace(c.Identity) != "" || c.Passphrase != "" {
		return c, nil
	}
	cc, err := s.configuredCreds()
	if err != nil {
		return c, err
	}
	if strings.TrimSpace(cc.Identity) == "" && cc.Passphrase == "" {
		return c, core.Invalid("identity", "provide the backup identity or passphrase")
	}
	return cc, nil
}
