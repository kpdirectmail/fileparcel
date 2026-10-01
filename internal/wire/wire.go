// Package wire constructs every concrete service in the fixed order of
// DESIGN §5.2 and starts the long-running ones. It is the only place (with
// cli, server, svc and cmd) that imports every service package.
//
// Frozen after foundation: units must not edit this file. Cross-service needs
// that the fixed constructors do not cover use the optional hooks in
// core/hooks.go (Binder, JobRegistrar, io.Closer).
package wire

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/audit"
	"fileparcel/internal/auth"
	"fileparcel/internal/backup"
	"fileparcel/internal/blobstore"
	"fileparcel/internal/buildinfo"
	"fileparcel/internal/certs"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/files"
	"fileparcel/internal/home"
	"fileparcel/internal/jobs"
	"fileparcel/internal/keys"
	"fileparcel/internal/logx"
	"fileparcel/internal/mdns"
	"fileparcel/internal/netinfo"
	"fileparcel/internal/notify"
	"fileparcel/internal/ratelimit"
	"fileparcel/internal/settings"
	"fileparcel/internal/shares"
	"fileparcel/internal/tsingress"
	"fileparcel/internal/uploads"
	"fileparcel/internal/users"
)

// StopTimeout bounds how long cleanup waits for jobs to stop.
const StopTimeout = 30 * time.Second

// Build loads the configuration of home h and constructs all services:
//
//	config.Load → h.EnsureLayout → logx (stderr + logs/fileparcel.log) →
//	db.Open + Migrate → events.New → env →
//	keys.Open → settings.New → audit.New → jobs.New, ratelimit.New →
//	blobstore.New → users.New, auth.New → files.New → uploads.New →
//	shares.New → netinfo.New, certs.New, mdns.New, tsingress.New →
//	backup.New, notify.New → Bind hooks → RegisterJobs hooks.
//
// In ModeOffline console logging is limited to warnings (the CLI owns stdout).
// The returned cleanup func (idempotent; never nil) stops jobs and mDNS,
// closes io.Closer services in reverse order, then the bus, the DB and the
// log file. Build does not take the home lock; callers (serve, offline CLI)
// hold h.Lock() around Build..cleanup.
func Build(ctx context.Context, h *home.Home, mode app.Mode) (*app.Deps, func(), error) {
	var closers []func() error
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			for i := len(closers) - 1; i >= 0; i-- {
				_ = closers[i]()
			}
		})
	}
	fail := func(step string, err error) (*app.Deps, func(), error) {
		cleanup()
		return nil, func() {}, fmt.Errorf("wire: %s: %w", step, err)
	}

	cfg, err := config.Load(h)
	if err != nil {
		return fail("config", err)
	}
	if err := h.EnsureLayout(); err != nil {
		return fail("layout", err)
	}
	log, logCloser, err := logx.New(logx.Options{
		Config:      cfg.Log,
		Dir:         h.LogsDir(),
		Stderr:      os.Stderr,
		StderrQuiet: mode == app.ModeOffline,
	})
	if err != nil {
		return fail("log", err)
	}
	closers = append(closers, logCloser.Close)
	slog.SetDefault(log)
	for _, w := range cfg.Warnings() {
		log.Warn("config: " + w)
	}

	database, err := db.Open(h.DB())
	if err != nil {
		return fail("db", err)
	}
	closers = append(closers, database.Close)
	applied, err := database.Migrate(ctx)
	if err != nil {
		return fail("migrate", err)
	}
	if len(applied) > 0 {
		log.Info("database migrated", "versions", applied)
	}

	bus := events.New()
	closers = append(closers, func() error { bus.Close(); return nil })

	env := &core.Env{
		Home:   h,
		Config: cfg,
		DB:     database,
		Log:    log,
		Clock:  core.SystemClock{},
		Bus:    bus,
		Build:  buildinfo.Get(),
	}

	var services []any
	add := func(s any) {
		services = append(services, s)
		if c, ok := s.(io.Closer); ok {
			closers = append(closers, c.Close)
		}
	}

	keysSvc, err := keys.Open(env)
	if err != nil {
		return fail("keys", err)
	}
	env.Keys = keysSvc
	add(keysSvc)

	settingsSvc, err := settings.New(env)
	if err != nil {
		return fail("settings", err)
	}
	env.Settings = settingsSvc
	add(settingsSvc)

	auditSvc, err := audit.New(env)
	if err != nil {
		return fail("audit", err)
	}
	env.Audit = auditSvc
	add(auditSvc)

	jobsSvc, err := jobs.New(env)
	if err != nil {
		return fail("jobs", err)
	}
	add(jobsSvc)
	limiter, err := ratelimit.New(env)
	if err != nil {
		return fail("ratelimit", err)
	}
	add(limiter)

	blobs, err := blobstore.New(env)
	if err != nil {
		return fail("blobstore", err)
	}
	add(blobs)

	usersSvc, err := users.New(env)
	if err != nil {
		return fail("users", err)
	}
	add(usersSvc)
	authSvc, err := auth.New(env, usersSvc, limiter)
	if err != nil {
		return fail("auth", err)
	}
	add(authSvc)

	filesSvc, err := files.New(env, blobs, jobsSvc)
	if err != nil {
		return fail("files", err)
	}
	add(filesSvc)

	uploadsSvc, err := uploads.New(env, filesSvc, blobs, jobsSvc)
	if err != nil {
		return fail("uploads", err)
	}
	add(uploadsSvc)

	sharesSvc, err := shares.New(env, filesSvc, limiter)
	if err != nil {
		return fail("shares", err)
	}
	add(sharesSvc)

	netSvc, err := netinfo.New(env)
	if err != nil {
		return fail("netinfo", err)
	}
	add(netSvc)
	certsSvc, err := certs.New(env, netSvc)
	if err != nil {
		return fail("certs", err)
	}
	add(certsSvc)
	mdnsSvc, err := mdns.New(env, netSvc)
	if err != nil {
		return fail("mdns", err)
	}
	add(mdnsSvc)
	// Tailscale Funnel/Serve: built in every mode (the offline CLI changes
	// and reports it), attached to listeners only by a running server.
	ingressSvc, err := tsingress.New(env, netSvc)
	if err != nil {
		return fail("tsingress", err)
	}
	add(ingressSvc)

	backupSvc, err := backup.New(env, blobs, jobsSvc)
	if err != nil {
		return fail("backup", err)
	}
	add(backupSvc)
	notifySvc, err := notify.New(env)
	if err != nil {
		return fail("notify", err)
	}
	add(notifySvc)

	// Stop long-running services first during cleanup (runs before the
	// closers registered above because cleanup walks in reverse).
	closers = append(closers, func() error {
		sctx, cancel := context.WithTimeout(context.Background(), StopTimeout)
		defer cancel()
		return errors.Join(jobsSvc.Stop(sctx), mdnsSvc.Stop())
	})

	reg := &core.Services{
		Keys: keysSvc, Settings: settingsSvc, Audit: auditSvc, Jobs: jobsSvc, Blobs: blobs,
		Users: usersSvc, Auth: authSvc, Files: filesSvc, Uploads: uploadsSvc, Shares: sharesSvc,
		Network: netSvc, Certs: certsSvc, MDNS: mdnsSvc, Backups: backupSvc, Notify: notifySvc,
		Ingress: ingressSvc,
	}
	for _, s := range services {
		if b, ok := s.(core.Binder); ok {
			if err := b.Bind(reg); err != nil {
				return fail(fmt.Sprintf("bind %T", s), err)
			}
		}
	}
	for _, s := range services {
		if r, ok := s.(core.JobRegistrar); ok {
			if err := r.RegisterJobs(jobsSvc); err != nil {
				return fail(fmt.Sprintf("register jobs %T", s), err)
			}
		}
	}

	d := &app.Deps{
		Env:     env,
		Mode:    mode,
		Auth:    authSvc,
		Users:   usersSvc,
		Files:   filesSvc,
		Uploads: uploadsSvc,
		Shares:  sharesSvc,
		Blobs:   blobs,
		Jobs:    jobsSvc,
		Backups: backupSvc,
		Certs:   certsSvc,
		Network: netSvc,
		MDNS:    mdnsSvc,
		Ingress: ingressSvc,
		Notify:  notifySvc,
		Limiter: limiter,
	}
	return d, cleanup, nil
}

// Start starts the long-running services in order: network → certs →
// ingress → mdns → jobs. In ModeOffline only the network service is started
// (certificates are just loaded by the constructor; the Tailscale ingress,
// mDNS and the jobs runner are skipped). Services must bind their goroutines
// to ctx and tolerate Stop without Start. The ingress service only
// subscribes to its events here; it changes tailscaled when server.Run
// attaches its listeners.
func Start(ctx context.Context, d *app.Deps) error {
	if err := d.Network.Start(ctx); err != nil {
		return fmt.Errorf("wire: start network: %w", err)
	}
	if d.Mode == app.ModeOffline {
		return nil
	}
	if err := d.Certs.Start(ctx); err != nil {
		return fmt.Errorf("wire: start certs: %w", err)
	}
	if d.Ingress != nil {
		if err := d.Ingress.Start(ctx); err != nil {
			// Funnel/Serve problems must not keep the server from starting.
			d.Log.Warn("tailscale ingress start failed", "err", err)
		}
	}
	if err := d.MDNS.Start(ctx); err != nil {
		// mDNS problems must not keep the server from starting.
		d.Log.Warn("mdns start failed", "err", err)
	}
	if err := d.Jobs.Start(ctx); err != nil {
		return fmt.Errorf("wire: start jobs: %w", err)
	}
	return nil
}
