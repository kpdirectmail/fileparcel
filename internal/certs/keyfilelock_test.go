package certs

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// lockingKeys is fakeKeys plus the key-file lock of *keys.Service
// (LockKeyFiles); it counts SealField calls made without holding it.
type lockingKeys struct {
	*fakeKeys
	fileMu   sync.Mutex
	held     atomic.Bool
	unlocked atomic.Int32 // SealField calls outside the lock
}

func (k *lockingKeys) LockKeyFiles() func() {
	k.fileMu.Lock()
	k.held.Store(true)
	var once sync.Once
	return func() {
		once.Do(func() {
			k.held.Store(false)
			k.fileMu.Unlock()
		})
	}
}

func (k *lockingKeys) SealField(aad string, pt []byte) (string, error) {
	if !k.held.Load() {
		k.unlocked.Add(1)
	}
	return k.fakeKeys.SealField(aad, pt)
}

// TestKeyFileWritesHoldTheKeysLock: sealing and writing a key file, and
// removing the custom key, run under the keys service's key-file lock, which
// a field KEK rotation takes around its changed-file check and rename —
// otherwise the rotation can rename the previous key back over a new one.
func TestKeyFileWritesHoldTheKeysLock(t *testing.T) {
	te := newTestEnv(t)
	lk := &lockingKeys{fakeKeys: te.keys}
	te.env.Keys = lk
	svc := te.initService(t) // creates the CA key files
	pub := newTestCA(t, "root")
	cp, kp, _ := pub.leaf(t, leafOpts{names: []string{"files.example.com"},
		notBefore: te.clock.Now().Add(-time.Hour), notAfter: te.clock.Now().Add(30 * 24 * time.Hour)})

	// While a rotation holds the lock, an upload waits for it.
	release := lk.LockKeyFiles()
	done := make(chan error, 1)
	go func() { done <- svc.SetCustom(context.Background(), nil, cp, kp) }()
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(svc.path(fileCustomKey)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the custom key was written while the key-file lock was held: %v", err)
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(svc.path(fileCustomKey)); err != nil {
		t.Fatalf("custom key not written: %v", err)
	}

	// Removing it waits as well.
	release = lk.LockKeyFiles()
	go func() { done <- svc.ClearCustom(context.Background(), nil) }()
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(svc.path(fileCustomKey)); err != nil {
		t.Fatalf("the custom key was removed while the key-file lock was held: %v", err)
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(svc.path(fileCustomKey)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("custom key not removed: %v", err)
	}
	if n := lk.unlocked.Load(); n != 0 {
		t.Fatalf("%d key files sealed without the key-file lock", n)
	}
}
