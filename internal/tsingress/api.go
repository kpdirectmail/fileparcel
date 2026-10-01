package tsingress

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/tslocal"
)

// ConfirmPublic is the typed confirmation FunnelInput.Confirm needs for
// every change that widens what the internet reaches.
const ConfirmPublic = "public"

// dnsDelay is how long after publishing Funnel the status mentions that
// public DNS may not know the name yet.
const dnsDelay = 10 * time.Minute

// SetFunnel turns Funnel on or off or changes its mode, port and sign-in
// rules (PUT /admin/network/funnel; the route requires network.manage and
// step-up). Enabling runs the checks, reconciles with the proposed state
// and stores the settings only when that succeeded; a failed store puts
// tailscaled back. Disabling stores mode off, then closes the listener and
// removes the entry (a failed removal answers the status with state
// error). While the server is stopped the settings and the marker are
// stored and the answer has state "stopped".
//
// Errors: 422 invalid (mode, port, allow_admin, confirm), 403 forbidden
// (weakening sign-in without being an owner or administrator), 412
// precondition_failed (field = the failing check), 409 conflict (field
// port: a foreign entry holds the port), 503 unavailable (tailscaled does
// not answer).
func (s *Service) SetFunnel(ctx context.Context, by *core.Principal, in core.FunnelInput) (*core.IngressStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done := s.opCtx(ctx)
	defer done()
	actx := withActor(ctx, by)
	cur := s.loadDesired()
	next := cur

	switch in.Mode {
	case core.FunnelOff, core.FunnelShares, core.FunnelApp:
		next.Mode = in.Mode
	default:
		return nil, core.Invalid("mode", "must be off, shares or app")
	}
	if in.Port != 0 {
		next.Port = in.Port
	}
	if in.AllowAdmin != nil {
		next.AllowAdmin = *in.AllowAdmin
	}
	if in.Require2FA != nil {
		next.Require2FA = *in.Require2FA
	}
	if in.Port != 0 || next.wants(core.IngressFunnel) {
		if !slices.Contains(tslocal.FunnelCandidatePorts, next.Port) {
			return nil, core.Invalid("port", "must be 443, 8443 or 10000 (the ports Tailscale Funnel supports)")
		}
	}
	if next.wants(core.IngressFunnel) {
		if slices.Contains(s.ownPorts(), next.Port) {
			return nil, core.Invalid("port", "FileParcel itself uses port "+strconv.Itoa(next.Port)+"; choose another port")
		}
		if next.Serve && next.ServePort == next.Port {
			return nil, core.Invalid("port", "Tailscale Serve uses port "+strconv.Itoa(next.Port)+"; choose another port")
		}
	}
	if in.AllowAdmin != nil && *in.AllowAdmin && next.Mode != core.FunnelApp {
		return nil, core.Invalid("allow_admin", "administration over Funnel needs the mode app")
	}
	if next.AllowAdmin && !next.Require2FA {
		return nil, core.Invalid("allow_admin", "administration over Funnel needs two-factor sign-in (require_2fa)")
	}
	// Weakening sign-in over the internet: switching allow_admin on or
	// require_2fa off, and entering app mode while the stored flags say so
	// (they stay stored while Funnel is off or in shares mode, where they
	// have no effect).
	weaken := !cur.AllowAdmin && next.AllowAdmin || cur.Require2FA && !next.Require2FA ||
		!cur.adminOverFunnel() && next.adminOverFunnel() || !cur.passwordOnlyOverFunnel() && next.passwordOnlyOverFunnel()
	widen := !cur.wants(core.IngressFunnel) && next.wants(core.IngressFunnel) ||
		cur.Mode == core.FunnelShares && next.Mode == core.FunnelApp || weaken
	if widen && in.Confirm != ConfirmPublic {
		return nil, core.Invalid("confirm", `type-confirmation required: send confirm="public"`)
	}
	// Weakening sign-in over the internet is an owner's or administrator's
	// decision (like the admin-only auth section), whatever network.manage
	// allows otherwise.
	if weaken && !by.IsAdmin() {
		s.auditFunnel(actx, core.OutcomeDenied, cur, next, map[string]any{"reason": "rbac"})
		msg := "only an owner or administrator can weaken sign-in over the public Funnel address"
		switch {
		case in.AllowAdmin == nil && next.adminOverFunnel():
			msg += " (administration over Funnel is allowed in its saved settings: turn that off to use the full app)"
		case in.Require2FA == nil && next.passwordOnlyOverFunnel():
			msg += " (two-factor sign-in is off in its saved settings: turn it on to use the full app)"
		}
		return nil, core.Errorf(core.ErrForbidden, "%s", msg)
	}

	if !next.wants(core.IngressFunnel) {
		return s.disable(actx, by, core.IngressFunnel, cur, next)
	}
	if err := s.precheck(actx, core.IngressFunnel, &next); err != nil {
		s.auditFunnel(actx, core.OutcomeDenied, cur, next, map[string]any{"reason": "check", "check": errField(err),
			"error": err.Error()})
		return nil, err
	}
	if err := s.applyAndStore(actx, by, core.IngressFunnel, cur, next); err != nil {
		s.auditFunnel(actx, core.OutcomeFailure, cur, next, map[string]any{"error": err.Error()})
		return nil, err
	}
	s.auditFunnel(actx, core.OutcomeSuccess, cur, next, nil)
	return s.statusLocked(actx), nil
}

// SetServe turns Serve on or off or changes its port (PUT
// /admin/network/serve; network.manage and step-up), with the same flow
// as SetFunnel (no typed confirmation: Serve reaches the tailnet only).
func (s *Service) SetServe(ctx context.Context, by *core.Principal, in core.ServeInput) (*core.IngressStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done := s.opCtx(ctx)
	defer done()
	actx := withActor(ctx, by)
	cur := s.loadDesired()
	next := cur
	next.Serve = in.Enabled
	if in.Port != 0 {
		if in.Port < 1 || in.Port > 65535 {
			return nil, core.Invalid("port", "must be between 1 and 65535")
		}
		next.ServePort = in.Port
	}
	if next.Serve {
		if slices.Contains(s.ownPorts(), next.ServePort) {
			return nil, core.Invalid("port", "FileParcel itself uses port "+strconv.Itoa(next.ServePort)+"; choose another port")
		}
		if next.wants(core.IngressFunnel) && next.Port == next.ServePort {
			return nil, core.Invalid("port", "Tailscale Funnel uses port "+strconv.Itoa(next.ServePort)+"; choose another port")
		}
	}
	if !next.Serve {
		return s.disable(actx, by, core.IngressServe, cur, next)
	}
	if err := s.precheck(actx, core.IngressServe, &next); err != nil {
		s.auditServe(actx, core.OutcomeDenied, cur, next, map[string]any{"reason": "check", "check": errField(err),
			"error": err.Error()})
		return nil, err
	}
	if err := s.applyAndStore(actx, by, core.IngressServe, cur, next); err != nil {
		s.auditServe(actx, core.OutcomeFailure, cur, next, map[string]any{"error": err.Error()})
		return nil, err
	}
	s.auditServe(actx, core.OutcomeSuccess, cur, next, nil)
	return s.statusLocked(actx), nil
}

// Reapply writes FileParcel's wanted entries again (POST
// /admin/network/tailscale/reapply): it fixes drift and retries a backend
// or permission problem the admin has solved meanwhile.
func (s *Service) Reapply(ctx context.Context, by *core.Principal) (*core.IngressStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done := s.opCtx(ctx)
	defer done()
	actx := withActor(ctx, by)
	s.stMu.Lock()
	s.unixRefused, s.configLocked = false, false
	s.stMu.Unlock()
	d := s.loadDesired()
	v := s.readView(actx, 0)
	if v.err != nil && !errors.Is(v.err, tslocal.ErrNotInstalled) {
		return nil, core.Wrap(core.ErrUnavailable, unavailableMessage(v), v.err)
	}
	out := s.reconcileLocked(actx, d, recOpts{reason: "reapply", add: [2]bool{true, true}})
	var firstErr error
	for i, k := range kinds {
		if !d.wants(k) {
			continue
		}
		err := userError(out, i, d)
		details := map[string]any{"reason": "reapply"}
		outcome := core.OutcomeSuccess
		if err != nil {
			outcome, details["error"] = core.OutcomeFailure, err.Error()
			if firstErr == nil {
				firstErr = err
			}
		}
		if k == core.IngressFunnel {
			s.auditFunnel(actx, outcome, d, d, details)
		} else {
			s.auditServe(actx, outcome, d, d, details)
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return s.statusLocked(actx), nil
}

// RemoveAll removes every entry FileParcel owns from tailscaled, closes the
// ingress listeners and deletes the marker (uninstall; the settings are
// kept). A failure names the commands that remove the entries by hand.
func (s *Service) RemoveAll(ctx context.Context, by *core.Principal, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done := s.opCtx(ctx)
	defer done()
	actx := withActor(ctx, by)
	for i := range kinds {
		s.policy[i].Store(&core.IngressPolicy{Mode: core.FunnelOff})
	}
	m, err := s.loadMarker()
	if err != nil {
		s.log.Warn("tsingress: ignoring an unreadable marker", "err", err)
		m = nil
	}
	own := s.ownership(m)
	removed, err := removeOwned(actx, s.ts, own)
	// The listeners close after the removal: a TCP port stays bound while
	// tailscaled may still route to it (the server stops after an
	// uninstall anyway).
	for _, k := range kinds {
		s.closeKind(k)
	}
	s.invalidateView()
	s.stMu.Lock()
	for i := range kinds {
		s.kst[i] = kindState{state: core.IngressStateOff}
	}
	s.stMu.Unlock()
	s.clearSnapshots()
	s.publish()
	if err != nil {
		// Nothing was removed: one failure entry per kind FileParcel had
		// published.
		for _, e := range m.entries() {
			s.audit(actx, e.Kind, core.OutcomeFailure, map[string]any{"reason": reason, "port": e.Port, "error": err.Error()})
		}
		return err
	}
	if werr := writeMarker(s.home(), nil); werr != nil {
		s.log.Warn("tsingress: could not remove the marker", "err", werr)
	}
	for _, e := range removed {
		s.audit(actx, e.kind, core.OutcomeSuccess, map[string]any{"reason": reason, "port": e.port})
	}
	return nil
}

// Status reports Funnel and Serve (GET /admin/network/tailscale). It reads
// tailscaled at most every 30 s unless refresh is set, which also asks
// tailscaled where Funnel can be enabled and re-runs the self-probe (it
// waits for the probe a few seconds; a slower one announces its result
// with ingress.changed).
func (s *Service) Status(ctx context.Context, refresh bool) (*core.IngressStatus, error) {
	maxAge := s.t.statusTTL
	if refresh {
		maxAge = 0
	}
	v := s.readView(ctx, maxAge)
	if refresh {
		if v.running() && !v.st.HasCap("funnel") {
			s.refreshFix(ctx)
		}
		s.probeNow(ctx)
	}
	return s.buildStatus(ctx, v, s.loadDesired()), nil
}

// statusLocked is the answer of the write routes (fresh when a write
// invalidated the cached read).
func (s *Service) statusLocked(ctx context.Context) *core.IngressStatus {
	return s.buildStatus(ctx, s.readView(ctx, s.t.statusTTL), s.loadDesired())
}

// disable stores kind off and reconciles (listener closed first, then the
// entry removed). A failed removal still answers the status (state error).
func (s *Service) disable(ctx context.Context, by *core.Principal, kind string, cur, next desired) (*core.IngressStatus, error) {
	if changes := settingsChanges(cur, next); len(changes) > 0 {
		if s.env.Settings == nil {
			return nil, core.Wrap(core.ErrUnavailable, "settings are not available", nil)
		}
		if _, err := s.env.Settings.Set(ctx, by, changes); err != nil {
			return nil, err
		}
	}
	i := kindIndex(kind)
	out := s.reconcileLocked(ctx, next, recOpts{reason: "user"})
	if cur.wants(kind) || out.k[i].state == core.IngressStateError {
		outcome := core.OutcomeSuccess
		var details map[string]any
		if out.k[i].state == core.IngressStateError {
			outcome, details = core.OutcomeFailure, map[string]any{"error": out.k[i].message}
		}
		if kind == core.IngressFunnel {
			s.auditFunnel(ctx, outcome, cur, next, details)
		} else {
			s.auditServe(ctx, outcome, cur, next, details)
		}
	} else if changes := settingsChanges(cur, next); len(changes) > 0 && kind == core.IngressFunnel {
		// Only the sign-in rules of a disabled Funnel changed.
		s.auditFunnel(ctx, core.OutcomeSuccess, cur, next, nil)
	}
	return s.statusLocked(ctx), nil
}

// precheck runs the checks of an enable on the proposed state (binding it
// to this node): 503 when tailscaled does not answer, 412 for the first
// failing check, 409 when a foreign entry holds the port. Nothing is
// changed.
func (s *Service) precheck(ctx context.Context, kind string, next *desired) error {
	v := s.readView(ctx, 0)
	if v.err != nil && !errors.Is(v.err, tslocal.ErrNotInstalled) {
		return core.Wrap(core.ErrUnavailable, unavailableMessage(v), v.err)
	}
	if v.running() {
		if kind == core.IngressServe && next.wants(core.IngressFunnel) && next.Node != "" && next.Node != v.st.NodeID() {
			c := nodeCheck(*next, v)
			c.Hint = "Turn Funnel on again here (or off) first."
			return checkError(&c)
		}
		next.Node = v.st.NodeID()
	}
	checks := s.prerequisites(kind, *next, v, s.ownPorts())
	f := firstFailure(checks)
	if f != nil && f.ID == checkFunnelAttr {
		s.refreshFix(ctx)
		f = firstFailure(s.prerequisites(kind, *next, v, s.ownPorts()))
	}
	if f != nil {
		return checkError(f)
	}
	if v.sc == nil {
		return core.Wrap(core.ErrUnavailable, "tailscaled's serve configuration could not be read", v.scErr)
	}
	m, _ := s.loadMarker()
	port := next.port(kind)
	if target, c := v.sc.Conflict(v.name()+":"+strconv.Itoa(port), port, s.ownership(m).owned); c {
		return conflictError(target, port)
	}
	return nil
}

// applyAndStore reconciles with next and, when that worked, stores next's
// settings; a failure of either puts tailscaled back to cur.
func (s *Service) applyAndStore(ctx context.Context, by *core.Principal, kind string, cur, next desired) error {
	if s.env.Settings == nil {
		return core.Wrap(core.ErrUnavailable, "settings are not available", nil)
	}
	var add [2]bool
	add[kindIndex(kind)] = true
	out := s.reconcileLocked(ctx, next, recOpts{reason: "user", add: add})
	if err := userError(out, kindIndex(kind), next); err != nil {
		s.reconcileLocked(ctx, cur, recOpts{reason: "revert", add: add})
		return err
	}
	if changes := settingsChanges(cur, next); len(changes) > 0 {
		if _, err := s.env.Settings.Set(ctx, by, changes); err != nil {
			s.reconcileLocked(ctx, cur, recOpts{reason: "revert", add: add})
			return err
		}
	}
	return nil
}

// userError maps the outcome of kind (index i) of a user's reconcile to
// the API error (nil when it is active, or stopped while the server is
// not running).
func userError(out *outcome, i int, d desired) error {
	o := out.k[i]
	port := d.port(kinds[i])
	switch o.state {
	case core.IngressStateActive, core.IngressStateStopped, core.IngressStateOff:
		return nil
	case core.IngressStateConflict:
		return conflictError(o.conflict, port)
	case core.IngressStateUnavailable, core.IngressStatePaused:
		if out.unreachable && o.check == nil {
			return core.Wrap(core.ErrUnavailable, o.message, nil)
		}
		if o.check != nil {
			return checkError(o.check)
		}
		return core.Wrap(core.ErrUnavailable, o.message, nil)
	case core.IngressStateDrift:
		return core.Errorf(core.ErrConflict, "%s", o.message)
	}
	err := o.err
	if err == nil {
		err = out.err
	}
	precondition := func(id, msg string) error {
		return &core.Error{Code: core.ErrPrecondition.Code, Status: core.ErrPrecondition.Status, Field: id, Message: msg, Err: err}
	}
	switch {
	case errors.Is(err, tslocal.ErrUnixForbidden):
		return precondition(checkBackend, tailscaleErrorMessage(err))
	case errors.Is(err, tslocal.ErrPermission):
		return precondition(checkOperator, tailscaleErrorMessage(err))
	case errors.Is(err, tslocal.ErrShieldsUp):
		return precondition(checkShieldsUp, "Shields-up is on, and Funnel does not work with it. sudo tailscale set --shields-up=false")
	case errors.Is(err, tslocal.ErrConfigLocked):
		return precondition(checkConfigLocked, "tailscaled runs from a configuration file, so its serve configuration is locked. "+
			"Add the entry to that file, or run tailscaled without --config.")
	case errors.Is(err, tslocal.ErrNotConnected):
		return precondition(checkRunning, "This device is not connected to its tailnet. Start Tailscale: sudo tailscale up")
	case errors.Is(err, tslocal.ErrPortInUse):
		return &core.Error{Code: core.ErrConflict.Code, Status: core.ErrConflict.Status, Field: "port", Err: err,
			Message: "another Tailscale Serve or Funnel listener uses port " + strconv.Itoa(port)}
	case err != nil && !isTailscaleError(err):
		// The ingress listener or the backend port.
		return precondition(checkBackend, o.message)
	case err != nil:
		return core.Wrap(core.ErrUnavailable, tailscaleErrorMessage(err), err)
	}
	return core.Wrap(core.ErrUnavailable, o.message, nil)
}

// isTailscaleError reports whether err came from tailscaled (rather than
// from opening a listener).
func isTailscaleError(err error) bool {
	var ae *tslocal.APIError
	return errors.As(err, &ae) || errors.Is(err, tslocal.ErrNoDaemon) || errors.Is(err, tslocal.ErrETagMismatch) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

// conflictError is the 409 answer of a port held by a foreign entry.
func conflictError(target string, port int) error {
	p := strconv.Itoa(port)
	return &core.Error{Code: core.ErrConflict.Code, Status: core.ErrConflict.Status, Field: "port",
		Message: target + " already uses port " + p + " on this device; remove it (" + tslocal.OffCommand(port, false) +
			") or choose another port"}
}

// errField returns the field of a core.Error ("" otherwise).
func errField(err error) string {
	if ce := core.AsError(err); ce != nil {
		return ce.Field
	}
	return ""
}

// settingsChanges returns the funnel.* settings that differ between cur and
// next.
func settingsChanges(cur, next desired) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	set := func(key string, a, b any) {
		if a != b {
			raw, _ := json.Marshal(b)
			out[key] = raw
		}
	}
	set(KeyMode, cur.Mode, next.Mode)
	set(KeyPort, cur.Port, next.Port)
	set(KeyAllowAdmin, cur.AllowAdmin, next.AllowAdmin)
	set(KeyRequire2FA, cur.Require2FA, next.Require2FA)
	set(KeyServe, cur.Serve, next.Serve)
	set(KeyServePort, cur.ServePort, next.ServePort)
	set(KeyNode, cur.Node, next.Node)
	return out
}

// ---------- audit ----------

// withActor puts by into ctx for the audit entries of a call.
func withActor(ctx context.Context, by *core.Principal) context.Context {
	if by != nil && core.PrincipalFrom(ctx) == nil {
		return core.WithPrincipal(ctx, by)
	}
	return ctx
}

func (s *Service) audit(ctx context.Context, kind, outcome string, details map[string]any) {
	if s.env.Audit == nil {
		return
	}
	action, name := core.ActNetworkFunnel, "Tailscale Funnel"
	if kind == core.IngressServe {
		action, name = core.ActNetworkServe, "Tailscale Serve"
	}
	s.env.Audit.Record(ctx, core.AuditEntry{Action: action, Outcome: outcome, TargetType: "network",
		TargetID: kind, TargetName: name, Details: details})
}

// auditFunnel records network.funnel with the before/after values.
func (s *Service) auditFunnel(ctx context.Context, outcome string, cur, next desired, extra map[string]any) {
	d := map[string]any{"mode": next.Mode, "previous_mode": cur.Mode, "port": next.Port, "previous_port": cur.Port,
		"allow_admin": next.AllowAdmin, "require_2fa": next.Require2FA}
	s.addApplied(d, core.IngressFunnel)
	for k, v := range extra {
		d[k] = v
	}
	s.audit(ctx, core.IngressFunnel, outcome, d)
}

// auditServe records network.serve with the before/after values.
func (s *Service) auditServe(ctx context.Context, outcome string, cur, next desired, extra map[string]any) {
	d := map[string]any{"enabled": next.Serve, "port": next.ServePort, "previous_port": cur.ServePort}
	s.addApplied(d, core.IngressServe)
	for k, v := range extra {
		d[k] = v
	}
	s.audit(ctx, core.IngressServe, outcome, d)
}

// addApplied adds the backend and URL of kind's current entry.
func (s *Service) addApplied(d map[string]any, kind string) {
	s.stMu.Lock()
	ks := s.kst[kindIndex(kind)]
	s.stMu.Unlock()
	if ks.backend != "" {
		d["backend"] = ks.backend
	}
	if ks.state == core.IngressStateActive && ks.hostPort != "" {
		if u := s.entryURL(ks); u != "" {
			d["url"] = u
		}
	}
}

// entryURL is https://name[:port]/ of an entry state.
func (s *Service) entryURL(ks kindState) string {
	name := ks.hostPort
	if i := strings.LastIndexByte(name, ':'); i > 0 {
		name = name[:i]
	}
	if name == "" {
		return ""
	}
	return hostURL(strings.ToLower(name), ks.port) + "/"
}
