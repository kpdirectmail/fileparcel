package provision

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/home"
)

func TestInitialize(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "fp")
	var built *home.Home
	cleaned := 0
	w := newWorld(t)
	build := func(ctx context.Context, h *home.Home) (*app.Deps, func(), error) {
		built = h
		// The lock is held while the services exist.
		if _, err := h.Lock(); !errors.Is(err, home.ErrLocked) {
			t.Errorf("home not locked during build: %v", err)
		}
		return w.d, func() { cleaned++ }, nil
	}
	res, err := Initialize(ctx, dir, ConfigOptions{Name: "box", HTTPSPort: 9443}, Options{Admin: "admin"}, build)
	if err != nil {
		t.Fatal(err)
	}
	if built == nil || built.Dir() != dir || res.Home != dir || res.Owner != "admin" || cleaned != 1 {
		t.Fatalf("res %+v built %v cleaned %d", res, built, cleaned)
	}
	if !home.IsHome(dir) {
		t.Fatal("no fileparcel.toml")
	}
	unlock, err := built.Lock()
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	unlock()

	// Existing home.
	if _, err := Initialize(ctx, dir, ConfigOptions{}, Options{}, build); !errors.Is(err, ErrExists) {
		t.Fatalf("existing: %v", err)
	}
}

func TestInitializeRollsBack(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	w.certs.err = errors.New("ca failed")
	dir := filepath.Join(t.TempDir(), "fp")
	_, err := Initialize(ctx, dir, ConfigOptions{}, Options{Admin: "admin"},
		func(context.Context, *home.Home) (*app.Deps, func(), error) { return w.d, nil, nil })
	if err == nil || !strings.Contains(err.Error(), "ca failed") {
		t.Fatalf("err %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("failed init left the home behind")
	}

	// Build failures roll back too; invalid options fail before anything is created.
	_, err = Initialize(ctx, dir, ConfigOptions{}, Options{},
		func(context.Context, *home.Home) (*app.Deps, func(), error) { return nil, nil, errors.New("db broken") })
	if err == nil || !strings.Contains(err.Error(), "db broken") {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("left behind after build failure")
	}
	if _, err := Initialize(ctx, dir, ConfigOptions{}, Options{Access: "open"}, nil); err == nil {
		t.Fatal("nil builder accepted")
	}
	called := false
	if _, err := Initialize(ctx, dir, ConfigOptions{}, Options{Access: "open"},
		func(context.Context, *home.Home) (*app.Deps, func(), error) { called = true; return nil, nil, nil }); err == nil || called {
		t.Fatal("invalid options accepted")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("invalid options created the home")
	}
	// Incomplete services.
	if _, err := Initialize(ctx, dir, ConfigOptions{}, Options{},
		func(context.Context, *home.Home) (*app.Deps, func(), error) { return &app.Deps{}, nil, nil }); err == nil {
		t.Fatal("incomplete deps accepted")
	}
}

// Two initialisers of one directory (two containers on an empty volume): one
// wins, the other gets ErrExists or ErrLocked and never removes the winner's
// files.
func TestInitializeConcurrent(t *testing.T) {
	ctx := context.Background()
	for i := range 40 {
		dir := filepath.Join(t.TempDir(), "fp")
		if i%2 == 0 {
			if err := os.Mkdir(dir, 0o750); err != nil {
				t.Fatal(err)
			}
		}
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make([]error, 2)
		for g := range errs {
			w := newWorld(t)
			build := func(ctx context.Context, h *home.Home) (*app.Deps, func(), error) {
				if err := os.WriteFile(h.Path("data", "marker"), []byte("x"), 0o600); err != nil {
					return nil, nil, err
				}
				time.Sleep(2 * time.Millisecond)
				return w.d, nil, nil
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, errs[g] = Initialize(ctx, dir, ConfigOptions{}, Options{Admin: "admin"}, build)
			}()
		}
		close(start)
		wg.Wait()
		ok := 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrExists), errors.Is(err, home.ErrLocked):
			default:
				t.Fatalf("round %d: unexpected error %v", i, err)
			}
		}
		if ok != 1 {
			t.Fatalf("round %d: %d initialisers succeeded (%v)", i, ok, errs)
		}
		if !home.IsHome(dir) {
			t.Fatalf("round %d: fileparcel.toml removed", i)
		}
		if _, err := os.Stat(filepath.Join(dir, "data", "marker")); err != nil {
			t.Fatalf("round %d: the winner's data removed: %v", i, err)
		}
	}

	// A directory locked by someone else is left alone.
	dir := t.TempDir()
	h, err := home.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := h.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	w := newWorld(t)
	_, err = Initialize(ctx, dir, ConfigOptions{}, Options{Admin: "admin"},
		func(context.Context, *home.Home) (*app.Deps, func(), error) { return w.d, nil, nil })
	if !errors.Is(err, home.ErrLocked) {
		t.Fatalf("locked dir: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 || entries[0].Name() != "run" {
		t.Fatalf("locked dir changed: %v", entries)
	}
}

// A refused directory does not get a run/ from the lock.
func TestInitializeRefusalLeavesDirAlone(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	w := newWorld(t)
	_, err := Initialize(context.Background(), dir, ConfigOptions{}, Options{Admin: "admin"},
		func(context.Context, *home.Home) (*app.Deps, func(), error) { return w.d, nil, nil })
	if err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("err %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("refused dir changed: %v", entries)
	}
}
