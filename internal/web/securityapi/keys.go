package securityapi

import (
	"context"
	"net/http"
	"strings"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// Rotation targets of POST /admin/keys/rotate (core.KeysRotateInput.Target).
const (
	rotateKEK    = "kek"
	rotateMaster = "master"
	rotateData   = "data"
)

// keyWebUnlock is the keys unit's setting controlling POST /system/unlock.
const keyWebUnlock = "keys.web_unlock"

func (a *api) keys() (core.Keys, error) {
	if a.d == nil || a.d.Keys == nil {
		return nil, core.Wrap(core.ErrUnavailable, "the key service is unavailable", nil)
	}
	return a.d.Keys, nil
}

// audit records a keys.* action. The key service audits the operations it
// performs itself (unlock, lock, seal, unseal, passphrase, rotations,
// recovery export), so handlers only record what the service cannot see:
// the queuing of a rotation job by an administrator (the job then runs as
// the system principal).
func (a *api) audit(ctx context.Context, action string, err error, details map[string]any) {
	if a.d == nil || a.d.Audit == nil {
		return
	}
	e := core.AuditEntry{Action: action, TargetType: "keys"}
	if err != nil {
		e.Outcome = core.OutcomeFailure
		if ce := core.AsError(err); ce != nil {
			if details == nil {
				details = map[string]any{}
			}
			details["error"] = ce.Code
		}
	}
	if details != nil {
		e.Details = details
	}
	a.d.Audit.Record(ctx, e)
}

// webUnlockMode returns keys.web_unlock (lan | any | off; default lan).
func (a *api) webUnlockMode() string {
	if a.d != nil && a.d.Settings != nil {
		switch m := a.d.Settings.String(keyWebUnlock); m {
		case "any", "off", "lan":
			return m
		}
	}
	return "lan"
}

// writeKeyStatus answers with core.KeyStatus.
func (a *api) writeKeyStatus(w http.ResponseWriter, r *http.Request, status int) {
	k, err := a.keys()
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	st, err := k.Status(r.Context())
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if st.WebUnlock == "" {
		st.WebUnlock = a.webUnlockMode()
	}
	httpx.JSON(w, status, st)
}

// keysStatus is GET /admin/keys.
func (a *api) keysStatus(w http.ResponseWriter, r *http.Request) {
	a.writeKeyStatus(w, r, http.StatusOK)
}

// keysLock is POST /admin/keys/lock (E; sealed mode only).
func (a *api) keysLock(w http.ResponseWriter, r *http.Request) {
	k, err := a.keys()
	if err == nil {
		err = k.Lock(r.Context())
	}
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	a.writeKeyStatus(w, r, http.StatusOK)
}

// passphrase decodes core.PassphraseInput and requires a value.
func passphrase(r *http.Request) ([]byte, error) {
	in, err := httpx.Decode[core.PassphraseInput](r, maxSmallBody)
	if err != nil {
		return nil, err
	}
	if in.Passphrase == "" {
		return nil, core.Invalid("passphrase", "the passphrase is required")
	}
	return []byte(in.Passphrase), nil
}

// keysSeal is POST /admin/keys/seal (E): plain → sealed mode.
func (a *api) keysSeal(w http.ResponseWriter, r *http.Request) {
	pass, err := passphrase(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	defer clear(pass)
	k, err := a.keys()
	if err == nil {
		err = k.Seal(r.Context(), pass)
	}
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	a.writeKeyStatus(w, r, http.StatusOK)
}

// keysUnseal is POST /admin/keys/unseal (E): sealed → plain mode.
func (a *api) keysUnseal(w http.ResponseWriter, r *http.Request) {
	pass, err := passphrase(r)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	defer clear(pass)
	k, err := a.keys()
	if err == nil {
		err = k.Unseal(r.Context(), pass)
	}
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	a.writeKeyStatus(w, r, http.StatusOK)
}

// keysPassphrase is POST /admin/keys/passphrase (E).
func (a *api) keysPassphrase(w http.ResponseWriter, r *http.Request) {
	in, err := httpx.Decode[core.PassphraseChangeInput](r, maxSmallBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	switch {
	case in.CurrentPassphrase == "":
		httpx.Error(w, r, core.Invalid("current_passphrase", "the current passphrase is required"))
		return
	case in.NewPassphrase == "":
		httpx.Error(w, r, core.Invalid("new_passphrase", "the new passphrase is required"))
		return
	}
	oldPass, newPass := []byte(in.CurrentPassphrase), []byte(in.NewPassphrase)
	defer clear(oldPass)
	defer clear(newPass)
	k, err := a.keys()
	if err == nil {
		err = k.ChangePassphrase(r.Context(), oldPass, newPass)
	}
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	a.writeKeyStatus(w, r, http.StatusOK)
}

// keysRotate is POST /admin/keys/rotate (E). "kek" and "data" enqueue the
// keys.rotate_kek / keys.reencrypt jobs (202 + core.JobRef); "master"
// rotates synchronously (200 + core.KeyStatus). Offline (no job runner), a
// KEK rotation also runs synchronously.
func (a *api) keysRotate(w http.ResponseWriter, r *http.Request) {
	in, err := httpx.Decode[core.KeysRotateInput](r, maxSmallBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	k, err := a.keys()
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	target := strings.ToLower(strings.TrimSpace(in.Target))
	purpose := strings.ToLower(strings.TrimSpace(in.Purpose))
	ctx, p := r.Context(), mw.Principal(r)
	switch target {
	case rotateKEK:
		if purpose == "" {
			purpose = core.KEKBlob
		}
		if purpose != core.KEKBlob && purpose != core.KEKField {
			httpx.Error(w, r, core.Invalid("purpose", "purpose must be blob or field"))
			return
		}
		if a.d.Mode == app.ModeOffline || a.d.Jobs == nil {
			// No job runner (in-process CLI): rotate now; RotateKEK audits.
			if err := k.RotateKEK(ctx, purpose, nil); err != nil {
				httpx.Error(w, r, err)
				return
			}
			a.writeKeyStatus(w, r, http.StatusOK)
			return
		}
		a.enqueue(w, r, core.JobKeysRotateKEK, map[string]any{"purpose": purpose}, target, p)
	case rotateData:
		if a.d.Jobs == nil {
			httpx.Error(w, r, core.Wrap(core.ErrUnavailable, "the job service is unavailable", nil))
			return
		}
		a.enqueue(w, r, core.JobKeysReencrypt, map[string]any{}, target, p)
	case rotateMaster:
		if err := k.RotateMaster(ctx); err != nil {
			httpx.Error(w, r, err)
			return
		}
		a.writeKeyStatus(w, r, http.StatusOK)
	default:
		httpx.Error(w, r, core.Invalid("target", "target must be kek, master or data"))
	}
}

// enqueue starts a rotation job and answers 202 {job_id}. The request is
// audited (phase "queued", attributed to the administrator); the job audits
// the rotation itself when it finishes.
func (a *api) enqueue(w http.ResponseWriter, r *http.Request, kind string, params map[string]any, target string, p *core.Principal) {
	id, err := a.d.Jobs.Enqueue(r.Context(), kind, params, p)
	details := map[string]any{"target": target, "job_kind": kind, "phase": "queued"}
	for k, v := range params {
		details[k] = v
	}
	if id != "" {
		details["job_id"] = id
	}
	a.audit(r.Context(), core.ActKeysRotate, err, details)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusAccepted, core.JobRef{JobID: id})
}

// keysRecovery is POST /admin/keys/recovery (E): a new recovery key, shown once.
func (a *api) keysRecovery(w http.ResponseWriter, r *http.Request) {
	k, err := a.keys()
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	key, err := k.ExportRecovery(r.Context())
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, core.RecoveryKey{RecoveryKey: key})
}
