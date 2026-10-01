package certs

import (
	"context"
	"errors"
	"strings"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/events"
)

// Background timing.
const (
	renewInterval   = 12 * time.Hour  // renewal check (DESIGN §9.7 certs.renew_check)
	renewSchedule   = "17 */12 * * *" // certs.renew_check schedule
	renewJobTimeout = 10 * time.Minute
)

// watchDebounce coalesces bursts of network/settings events (a variable for tests).
var watchDebounce = 5 * time.Second

// RegisterJobs implements core.JobRegistrar: the "certs.renew_check" job
// kind and its 12-hourly schedule. When the schedule is registered, Start
// does not run its own renewal ticker.
func (svc *Service) RegisterJobs(j core.Jobs) error {
	if j == nil {
		return nil
	}
	j.Register(core.JobCertsRenewCheck, func(ctx context.Context, h core.JobHandle) error {
		h.Progress(0, 1, "checking certificates")
		err := svc.renewCheck(ctx)
		h.Progress(1, 1, "")
		return err
	}, core.JobOptions{Exclusive: "certs", Timeout: renewJobTimeout, Hidden: true})
	if err := j.Schedule(core.JobCertsRenewCheck, renewSchedule, core.JobCertsRenewCheck, nil); err != nil {
		svc.log.Warn("cannot schedule the certificate renewal check; using an internal timer", "err", err)
		return nil
	}
	svc.jobsScheduled.Store(true)
	return nil
}

// renewCheck renews whatever needs it: the local leaf (missing, expiring,
// SAN change, CA change), the Tailscale certificate (< 14 days, or no longer
// covering the current MagicDNS name) and a failed or not yet applied ACME
// configuration. certmagic renews ACME certificates on its own.
func (svc *Service) renewCheck(ctx context.Context) error {
	var errs []error
	svc.ensureCustomLoaded()
	if svc.snapshot().ca != nil {
		if svc.keysUnlocked() {
			if err := svc.RenewLocal(ctx, false); err != nil {
				errs = append(errs, err)
			}
		} else if need, _ := svc.leafNeedsRenewal(svc.snapshot(), false); need {
			svc.pendingRenew.Store(true)
		}
	}
	if svc.settingBool(KeyTailscaleCert) && svc.tailscaleNeedsRefresh(ctx) {
		if err := svc.FetchTailscale(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if svc.started() && svc.settingBool(KeyACMEEnabled) && (svc.acme.Load() == nil || loadString(&svc.acmeErr) != "") {
		if err := svc.ApplyACME(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Start implements core.Certs: begins the background work — the SAN-change
// and settings watcher, the renewal timer (unless the certs.renew_check job
// is scheduled), ACME management and the Tailscale certificate. It returns
// quickly; problems are logged and reported by Status. Only called in
// network mode.
func (svc *Service) Start(ctx context.Context) error {
	svc.startOnce.Do(func() {
		bg, cancel := context.WithCancel(ctx)
		svc.mu.Lock()
		svc.bgCtx, svc.cancel = bg, cancel
		svc.mu.Unlock()

		if svc.snapshot().ca == nil {
			svc.log.Warn(`no local CA found; run "fileparcel init" (HTTPS will fail until certificates exist)`)
		}
		if wide := publicSuffixConstraints(svc.snapshot().ca); len(wide) > 0 {
			svc.log.Warn(`the local CA's name constraints include a public suffix (a whole top-level domain); `+
				`a leaked CA key could sign certificates for every name below it. Run "fileparcel ca regenerate" `+
				`(every device must then trust the new CA)`, "names", wide)
		}
		var ch <-chan events.Event
		unsub := func() {}
		if svc.env.Bus != nil {
			ch, unsub = svc.env.Bus.Subscribe(events.TopicNetworkChanged, events.TopicMDNSChanged,
				events.TopicSettingsChanged, events.TopicKeysState)
		}
		svc.wg.Add(1)
		go func() {
			defer svc.wg.Done()
			defer unsub()
			svc.loop(bg, ch)
		}()
	})
	return nil
}

// pending collects the work requested by events until the debounce fires.
type pending struct {
	leaf, acme, tailscale, unlock bool
}

func (p *pending) any() bool { return p.leaf || p.acme || p.tailscale || p.unlock }

// loop runs the initial check, reacts to events (debounced) and runs the
// fallback renewal timer.
func (svc *Service) loop(ctx context.Context, ch <-chan events.Event) {
	svc.runCheck(ctx, "start")

	var tick <-chan time.Time
	if !svc.jobsScheduled.Load() {
		t := time.NewTicker(renewInterval)
		defer t.Stop()
		tick = t.C
	}
	debounce := time.NewTimer(time.Hour)
	debounce.Stop()
	defer debounce.Stop()
	var p pending
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			svc.runCheck(ctx, "timer")
		case e, ok := <-ch:
			if !ok {
				ch = nil
				continue
			}
			svc.classify(e, &p)
			if p.any() {
				debounce.Reset(watchDebounce)
			}
		case <-debounce.C:
			work := p
			p = pending{}
			svc.apply(ctx, work)
		}
	}
}

// classify maps an event to pending work.
func (svc *Service) classify(e events.Event, p *pending) {
	switch e.Topic {
	case events.TopicNetworkChanged, events.TopicMDNSChanged:
		p.leaf = true
	case events.TopicKeysState:
		if ks, ok := e.Data.(core.KeysStateEvent); ok && ks.State == core.KeyStateUnlocked {
			p.unlock = true
		}
	case events.TopicSettingsChanged:
		ev, ok := e.Data.(core.SettingsChangedEvent)
		if !ok {
			if pe, ok2 := e.Data.(*core.SettingsChangedEvent); ok2 && pe != nil {
				ev, ok = *pe, true
			}
		}
		if !ok {
			return
		}
		for _, k := range ev.Keys {
			switch {
			case k == KeyExtraSANs || k == KeyLeafDays || k == "server.name" || k == "server.public_url" || k == "mdns.name":
				// KeyLeafDays too: the new validity only ever reached the
				// certificate through issueLeaf, so without this a change sat
				// unapplied until something else happened to reissue the leaf.
				p.leaf = true
			case strings.HasPrefix(k, "acme."):
				p.acme = true
			case strings.HasPrefix(k, "tailscale."):
				p.tailscale = true
			case strings.HasPrefix(k, "tls.") || strings.HasPrefix(k, "mtls."):
				svc.trust.reset() // HSTS/trust verdicts depend on these
			}
		}
	}
}

// apply performs debounced work.
func (svc *Service) apply(ctx context.Context, p pending) {
	if p.unlock {
		svc.ensureCustomLoaded()
		if svc.pendingRenew.Load() {
			p.leaf = true
		}
		// ACME and Tailscale need the keys too: readACMEConfig reads the
		// sealed acme.dns_credentials, so on a sealed server ApplyACME fails
		// at start and nothing retried it until the 12-hourly renew check.
		if svc.settingBool(KeyACMEEnabled) && (svc.acme.Load() == nil || loadString(&svc.acmeErr) != "") {
			p.acme = true
		}
		if svc.settingBool(KeyTailscaleCert) && svc.tailscaleNeedsRefresh(ctx) {
			p.tailscale = true
		}
	}
	if p.leaf && svc.snapshot().ca != nil {
		if svc.keysUnlocked() {
			if err := svc.RenewLocal(ctx, false); err != nil && ctx.Err() == nil {
				svc.log.Warn("local certificate renewal failed", "err", err)
			}
		} else if need, _ := svc.leafNeedsRenewal(svc.snapshot(), false); need {
			// Remembered for the unlock above: the change itself is not
			// announced again, and the next renew check is up to 12 h away.
			svc.pendingRenew.Store(true)
		}
	}
	// A renamed node or tailnet changes the MagicDNS name (network.changed):
	// the stored certificate no longer covers it, and only the leaf was
	// looked at, so the new ts.net name got the local leaf for weeks.
	if p.leaf && svc.settingBool(KeyTailscaleCert) && svc.tailscaleNameStale(ctx) {
		p.tailscale = true
	}
	if p.acme {
		if err := svc.ApplyACME(ctx); err != nil && ctx.Err() == nil {
			svc.log.Warn("ACME configuration failed", "err", err)
		}
	}
	if p.tailscale {
		if svc.settingBool(KeyTailscaleCert) {
			if err := svc.FetchTailscale(ctx); err != nil && ctx.Err() == nil {
				svc.log.Warn("Tailscale certificate fetch failed", "err", err)
			}
		} else if svc.tsErr.Swap(nil) != nil {
			// Turned off: a failure of the last attempt is no longer a
			// problem (Status hides it too), and must not reappear on re-enable.
			svc.publishChanged()
		}
	}
}

func (svc *Service) runCheck(ctx context.Context, why string) {
	if err := svc.renewCheck(ctx); err != nil && ctx.Err() == nil {
		svc.log.Warn("certificate check found problems", "trigger", why, "err", err)
	}
}
