package provision

import (
	"context"
	"errors"
	"fmt"
	"os"

	"fileparcel/internal/app"
	"fileparcel/internal/home"
)

// Builder constructs the services over a prepared home and returns a
// cleanup func (never nil on success). In production it is wire.Build in
// app.ModeOffline followed by wire.Start (only the network service starts);
// tests pass fakes.
type Builder func(ctx context.Context, h *home.Home) (*app.Deps, func(), error)

// Initialize creates and provisions a new home in dir: the checks of
// PrepareHome, the home lock, layout and fileparcel.toml, build, Provision,
// cleanup. It is the whole of `fileparcel init`, the fresh-install step of
// `fileparcel install` and `serve --init-if-missing` (DESIGN §12, §14.2 step
// 3, §14.7).
//
// Options and the directory are checked before anything is created. The
// layout, provisioning and any rollback all happen under the home lock, so
// of two concurrent initialisers of one directory (two containers starting
// on an empty volume) the second gets home.ErrLocked, or ErrExists once the
// first has finished, and never writes or removes anything. On any failure
// after the layout was created the home is removed again (Prepared.Remove:
// only what init created), so a failed init can simply be retried.
// ErrExists (wrapped) is returned when dir already is a home.
func Initialize(ctx context.Context, dir string, c ConfigOptions, o Options, build Builder) (*Result, error) {
	if build == nil {
		return nil, errors.New("provision: no service builder")
	}
	if err := o.Validate(); err != nil {
		return nil, err
	}
	h, err := home.New(dir)
	if err != nil {
		return nil, err
	}
	// Check first: the lock creates run/, which a refused directory must
	// not get. What existed before is recorded here, before the lock.
	p, err := inspectHome(h, c)
	if err != nil {
		if !errors.Is(err, ErrExists) && lockedByOther(h) {
			// Another initialiser is at work in dir: what failed the
			// check are its half-written files.
			return nil, home.ErrLocked
		}
		return nil, err
	}
	unlock, err := h.Lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	// Check again under the lock: another initialiser may have finished (or
	// left a damaged home behind) between the first check and the lock.
	if _, err := inspectHome(h, c); err != nil {
		return nil, err
	}
	if err := p.create(); err != nil {
		return nil, err
	}
	res, err := provisionPrepared(ctx, p, o, build)
	if err != nil {
		if rerr := p.Remove(); rerr != nil {
			err = fmt.Errorf("%w (and cleaning up %s failed: %v)", err, p.Home.Dir(), rerr)
		}
		return nil, err
	}
	return res, nil
}

// provisionPrepared builds the services and provisions the home (the caller
// holds the home lock).
func provisionPrepared(ctx context.Context, p *Prepared, o Options, build Builder) (*Result, error) {
	d, cleanup, err := build(ctx, p.Home)
	if err != nil {
		return nil, fmt.Errorf("build services: %w", err)
	}
	if cleanup != nil {
		defer cleanup()
	}
	if d == nil || d.Env == nil || d.Keys == nil || d.Certs == nil || d.Network == nil || d.Auth == nil || d.Users == nil {
		return nil, errors.New("provision: incomplete services")
	}
	res, err := Provision(ctx, d, o)
	if err != nil {
		return nil, err
	}
	res.Home = p.Home.Dir()
	return res, nil
}

// lockedByOther reports whether another process holds the lock of h, without
// creating run/ when there is no lock file.
func lockedByOther(h *home.Home) bool {
	if _, err := os.Lstat(h.LockFile()); err != nil {
		return false
	}
	unlock, err := h.Lock()
	if err != nil {
		return errors.Is(err, home.ErrLocked)
	}
	unlock()
	return false
}
