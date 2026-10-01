package crypt

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var cheap = Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

func TestAEADRoundTrip(t *testing.T) {
	key := RandomBytes(KeySize)
	for _, id := range []uint8{CipherAES256GCM, CipherChaCha20Poly1305} {
		a, err := NewAEAD(id, key)
		if err != nil {
			t.Fatal(err)
		}
		if a.NonceSize() != NonceSize || a.Overhead() != TagSize {
			t.Fatalf("cipher %d: nonce %d overhead %d", id, a.NonceSize(), a.Overhead())
		}
		pt := []byte("hello parcel")
		aad := []byte("fp-dek|abc")
		s1 := Seal(a, pt, aad)
		s2 := Seal(a, pt, aad)
		if bytes.Equal(s1, s2) {
			t.Fatal("nonces must be random")
		}
		if len(s1) != NonceSize+len(pt)+TagSize {
			t.Fatalf("sealed len %d", len(s1))
		}
		got, err := Open(a, s1, aad)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("open: %v %q", err, got)
		}
		if _, err := Open(a, s1, []byte("other")); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("wrong aad: %v", err)
		}
		bad := bytes.Clone(s1)
		bad[len(bad)-1] ^= 1
		if _, err := Open(a, bad, aad); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("tampered: %v", err)
		}
		if _, err := Open(a, s1[:5], aad); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("short: %v", err)
		}
		other, _ := NewAEAD(id, RandomBytes(KeySize))
		if _, err := Open(other, s1, aad); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("wrong key: %v", err)
		}
	}
	if _, err := NewAEAD(3, key); err == nil {
		t.Fatal("unknown cipher accepted")
	}
	if _, err := NewAEAD(CipherAES256GCM, key[:16]); err == nil {
		t.Fatal("short key accepted")
	}
	s, err := SealWithKey(CipherChaCha20Poly1305, key, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := OpenWithKey(CipherChaCha20Poly1305, key, s, nil); err != nil || string(pt) != "x" {
		t.Fatal(err)
	}
	if AutoCipher() != CipherAES256GCM && AutoCipher() != CipherChaCha20Poly1305 {
		t.Fatal("AutoCipher")
	}
}

func TestHKDFAndHMAC(t *testing.T) {
	k1, err := HKDF([]byte("secret"), nil, "fp-mac|audit", 32)
	if err != nil || len(k1) != 32 {
		t.Fatal(err)
	}
	k2, _ := HKDF([]byte("secret"), nil, "fp-mac|share", 32)
	if bytes.Equal(k1, k2) {
		t.Fatal("different info must give different keys")
	}
	if !bytes.Equal(HMAC(k1, []byte("a"), []byte("b")), HMAC(k1, []byte("a"), []byte("b"))) {
		t.Fatal("HMAC not deterministic")
	}
	if bytes.Equal(HMAC(k1, []byte("ab"), []byte("c")), HMAC(k1, []byte("a"), []byte("bc"))) {
		t.Fatal("HMAC framing ambiguous")
	}
	if !bytes.Equal(HMACRaw(k1, []byte("ab"), []byte("c")), HMACRaw(k1, []byte("a"), []byte("bc"))) {
		t.Fatal("HMACRaw must be plain concatenation")
	}
	b := []byte{1, 2, 3}
	Zero(b)
	if !bytes.Equal(b, []byte{0, 0, 0}) {
		t.Fatal("Zero")
	}
	if len(RandomBytes(7)) != 7 {
		t.Fatal("RandomBytes")
	}
}

func TestPasswordHash(t *testing.T) {
	phc, err := HashPasswordParams("correct horse", cheap)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(phc, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("phc %q", phc)
	}
	ok, rehash := VerifyPassword(phc, "correct horse")
	if !ok || !rehash {
		t.Fatalf("ok=%v rehash=%v (cheap params must ask for rehash)", ok, rehash)
	}
	if ok, _ := VerifyPassword(phc, "wrong"); ok {
		t.Fatal("wrong password accepted")
	}
	for _, bad := range []string{"", "$argon2i$v=19$m=64,t=1,p=1$AAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=64,t=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", "plain", "$argon2id$v=19$m=99999999,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"} {
		if ok, _ := VerifyPassword(bad, "x"); ok {
			t.Fatalf("malformed hash accepted: %q", bad)
		}
	}
	if _, err := HashPasswordParams("x", Argon2Params{MemoryKiB: 1, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}); err == nil {
		t.Fatal("weak params accepted")
	}
}

// No parameter this process mints or reads back may ask for more argon2
// memory than the whole budget: Argon2Key clamps its *reservation* but still
// allocates the m it is given, so the ceiling is what actually bounds a
// derivation.
func TestArgonMemoryCeiling(t *testing.T) {
	phc := func(m uint32) string {
		return "$argon2id$v=19$m=" + strconv.FormatUint(uint64(m), 10) + ",t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"
	}
	if _, err := ParsePHC(phc(Argon2BudgetKiB + 1)); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("ParsePHC above the budget: %v", err)
	}
	if _, err := ParsePHC(phc(Argon2BudgetKiB)); err != nil {
		t.Fatalf("ParsePHC at the budget: %v", err)
	}
	p := cheap
	p.MemoryKiB = Argon2BudgetKiB + 1
	if _, err := HashPasswordParams("x", p); err == nil {
		t.Fatal("minted a hash above the argon2 budget")
	}
}

func TestPasswordDefaultParams(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 64 MiB")
	}
	phc, err := HashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(phc, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("phc %q", phc)
	}
	ok, rehash := VerifyPassword(phc, "pw")
	if !ok || rehash {
		t.Fatalf("ok=%v rehash=%v", ok, rehash)
	}
	h, err := ParsePHC(phc)
	if err != nil || len(h.Salt) != 16 || len(h.Key) != 32 {
		t.Fatalf("parse: %v", err)
	}
}

// The budget bounds the argon2 memory in flight, not just the number of
// computations: a 128 MiB master-key derivation (keys/keyfile.go defaultKDF)
// takes twice the share of a 64 MiB password hash, so mixing them can never
// exceed Argon2BudgetKiB.
func TestArgonBudgetBoundsMemory(t *testing.T) {
	const big, small = 128 * 1024, 64 * 1024 // KiB, as keyfile and PasswordParams use
	var cur, peak atomic.Int64
	var wg sync.WaitGroup
	for i := range 3 * Argon2Slots {
		want := uint32(small)
		if i%4 == 0 { // a master-key derivation among the password hashes
			want = big
		}
		wg.Go(func() {
			got := argonBudget.acquire(want)
			if got != want {
				t.Errorf("acquire(%d) reserved %d", want, got)
			}
			n := cur.Add(int64(got))
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			cur.Add(-int64(got))
			argonBudget.release(got)
		})
	}
	wg.Wait()
	if peak.Load() > Argon2BudgetKiB {
		t.Fatalf("peak %d KiB in flight > budget %d KiB", peak.Load(), Argon2BudgetKiB)
	}
	if cur.Load() != 0 {
		t.Fatalf("budget not released: %d KiB still held", cur.Load())
	}
	argonBudget.mu.Lock()
	free := argonBudget.free
	argonBudget.mu.Unlock()
	if free != Argon2BudgetKiB {
		t.Fatalf("free %d, want %d", free, Argon2BudgetKiB)
	}
	if PasswordParams.MemoryKiB*Argon2Slots != Argon2BudgetKiB {
		t.Fatalf("budget %d KiB no longer matches %d x %d KiB (DESIGN §18.12)",
			Argon2BudgetKiB, Argon2Slots, PasswordParams.MemoryKiB)
	}
	_ = Argon2Key([]byte("p"), []byte("saltsalt"), 1, 64, 1, 32)
}

// A 128 MiB derivation and two 64 MiB ones fill the budget exactly; a third
// 64 MiB one waits, and no later request overtakes it.
func TestArgonBudgetBlocksAndIsFIFO(t *testing.T) {
	b := newArgonBudget(256 * 1024)
	n1 := b.acquire(128 * 1024)
	n2 := b.acquire(64 * 1024)
	n3 := b.acquire(64 * 1024)
	if b.free != 0 {
		t.Fatalf("free %d, want 0", b.free)
	}

	queued := make(chan uint32, 1) // needs 128 MiB: waits for two releases
	go func() { queued <- b.acquire(128 * 1024) }()
	behind := make(chan uint32, 1) // asks for less, but arrives later
	waitFor(t, b, 1)               // the 128 MiB request is at the head
	go func() { behind <- b.acquire(64 * 1024) }()
	waitFor(t, b, 2)

	b.release(n3) // 64 MiB free: not enough for the head of the queue
	select {
	case n := <-behind:
		t.Fatalf("a later 64 MiB request (%d KiB) overtook the queued 128 MiB one", n)
	case n := <-queued:
		t.Fatalf("the 128 MiB request ran with only 64 MiB free (%d KiB)", n)
	case <-time.After(50 * time.Millisecond):
	}
	b.release(n2) // 128 MiB free: the head runs, the later request still waits
	if n := <-queued; n != 128*1024 {
		t.Fatalf("queued reserved %d KiB", n)
	}
	b.release(n1)
	select {
	case n := <-behind:
		if n != 64*1024 {
			t.Fatalf("behind reserved %d KiB", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the queued 64 MiB request never ran")
	}
}

// waitFor blocks until n requests are queued behind the holders.
func waitFor(t *testing.T, b *argonBudgetSem, n uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		b.mu.Lock()
		queued := uint64(b.waiters.Len())
		b.mu.Unlock()
		if queued >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d requests queued, want %d", queued, n)
		}
		time.Sleep(time.Millisecond)
	}
}

// A request larger than the whole budget is clamped instead of deadlocking.
// Parameters that large are refused where they are minted and parsed, so the
// clamp is only a guard against a caller that bypasses those checks.
func TestArgonBudgetClampsOversizedRequest(t *testing.T) {
	b := newArgonBudget(64 * 1024)
	done := make(chan uint32, 1)
	go func() { done <- b.acquire(1024 * 1024) }()
	select {
	case n := <-done:
		if n != 64*1024 {
			t.Fatalf("reserved %d KiB, want the whole %d KiB budget", n, 64*1024)
		}
		b.release(n)
	case <-time.After(2 * time.Second):
		t.Fatal("an oversized request deadlocked")
	}
	if n := b.acquire(0); n != 1 { // a zero request must still take a ticket
		t.Fatalf("acquire(0) reserved %d", n)
	}
}

// A waiter whose context ends leaves the queue: at the head it lets the next
// one run, in the middle it blocks nobody, and it never keeps a reservation.
func TestArgonBudgetCancelledWaitersLeave(t *testing.T) {
	b := newArgonBudget(256 * 1024)
	n1 := b.acquire(128 * 1024)
	n2 := b.acquire(128 * 1024)

	type result struct {
		n   uint32
		err error
	}
	start := func(ctx context.Context, n uint32) chan result {
		ch := make(chan result, 1)
		go func() {
			got, err := b.acquireContext(ctx, n, true)
			ch <- result{got, err}
		}()
		return ch
	}
	headCtx, cancelHead := context.WithCancel(context.Background())
	head := start(headCtx, 256*1024) // needs everything: waits for both holders
	waitFor(t, b, 1)
	midCtx, cancelMid := context.WithCancel(context.Background())
	mid := start(midCtx, 64*1024)
	waitFor(t, b, 2)
	tail := start(context.Background(), 64*1024)
	waitFor(t, b, 3)

	cancelMid()
	select {
	case r := <-mid:
		if !errors.Is(r.err, context.Canceled) || r.n != 0 {
			t.Fatalf("cancelled middle waiter: %d KiB, %v", r.n, r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a cancelled waiter did not return")
	}
	b.release(n2) // 128 MiB free: still not enough for the head
	select {
	case r := <-tail:
		t.Fatalf("the tail overtook the head (%d KiB, %v)", r.n, r.err)
	case <-time.After(50 * time.Millisecond):
	}
	cancelHead() // the head leaves: the tail fits now and runs
	if r := <-head; !errors.Is(r.err, context.Canceled) || r.n != 0 {
		t.Fatalf("cancelled head: %d KiB, %v", r.n, r.err)
	}
	select {
	case r := <-tail:
		if r.err != nil || r.n != 64*1024 {
			t.Fatalf("tail: %d KiB, %v", r.n, r.err)
		}
		b.release(r.n)
	case <-time.After(2 * time.Second):
		t.Fatal("the waiter behind a cancelled head never ran")
	}
	b.release(n1)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.free != b.total || b.waiters.Len() != 0 {
		t.Fatalf("free %d of %d, %d waiting: a cancelled waiter kept memory or its place", b.free, b.total, b.waiters.Len())
	}
}

// Once maxWaiters requests are queued, a capped request (the request paths)
// fails at once instead of joining the queue; an uncapped one still waits.
func TestArgonBudgetBusyWhenQueueFull(t *testing.T) {
	b := newArgonBudget(64 * 1024)
	b.maxWaiters = 2
	held := b.acquire(64 * 1024)
	done := make(chan error, 3)
	for range 2 {
		go func() {
			n, err := b.acquireContext(context.Background(), 64*1024, true)
			if err == nil {
				b.release(n)
			}
			done <- err
		}()
	}
	waitFor(t, b, 2)
	began := time.Now()
	if _, err := b.acquireContext(context.Background(), 64*1024, true); !errors.Is(err, ErrArgonBusy) {
		t.Fatalf("capped request with a full queue: %v, want ErrArgonBusy", err)
	}
	if time.Since(began) > time.Second {
		t.Fatal("ErrArgonBusy must be immediate")
	}
	go func() { b.release(b.acquire(64 * 1024)); done <- nil }() // uncapped: queues anyway
	waitFor(t, b, 3)
	b.release(held)
	for range 3 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("queued request: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("queued requests never ran")
		}
	}
}

// The request-path variants report "not checked" (busy, or the client left)
// as an error, never as a wrong password.
func TestVerifyPasswordContext(t *testing.T) {
	phc, err := HashPasswordParams("correct horse", cheap)
	if err != nil {
		t.Fatal(err)
	}
	if ok, rehash, err := VerifyPasswordContext(context.Background(), phc, "correct horse"); !ok || !rehash || err != nil {
		t.Fatalf("ok=%v rehash=%v err=%v", ok, rehash, err)
	}
	if ok, _, err := VerifyPasswordContext(context.Background(), phc, "wrong"); ok || err != nil {
		t.Fatalf("wrong password: ok=%v err=%v", ok, err)
	}
	if ok, _, err := VerifyPasswordContext(context.Background(), "plain", "x"); ok || err != nil {
		t.Fatalf("malformed hash: ok=%v err=%v", ok, err)
	}
	_ = dummy() // mint the dummy hash while the budget is free

	// Exhaust the process-wide budget and fill its queue.
	held := argonBudget.acquire(Argon2BudgetKiB)
	argonBudget.mu.Lock()
	argonBudget.maxWaiters = 0
	argonBudget.mu.Unlock()
	defer func() {
		argonBudget.mu.Lock()
		argonBudget.maxWaiters = MaxArgonWaiters
		argonBudget.mu.Unlock()
	}()
	if ok, _, err := VerifyPasswordContext(context.Background(), phc, "correct horse"); ok || !errors.Is(err, ErrArgonBusy) {
		t.Fatalf("busy: ok=%v err=%v", ok, err)
	}
	if err := VerifyDummyContext(context.Background(), "x"); !errors.Is(err, ErrArgonBusy) {
		t.Fatalf("busy dummy: %v", err)
	}
	if _, err := Argon2KeyContext(context.Background(), []byte("p"), []byte("saltsalt"), 1, 64, 1, 32); !errors.Is(err, ErrArgonBusy) {
		t.Fatalf("busy key: %v", err)
	}
	argonBudget.mu.Lock()
	argonBudget.maxWaiters = MaxArgonWaiters
	argonBudget.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if ok, _, err := VerifyPasswordContext(ctx, phc, "correct horse"); ok || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("abandoned request: ok=%v err=%v", ok, err)
	}
	argonBudget.release(held)
	if err := VerifyDummyContext(context.Background(), "x"); err != nil {
		t.Fatalf("dummy after release: %v", err)
	}
	argonBudget.mu.Lock()
	defer argonBudget.mu.Unlock()
	if argonBudget.free != Argon2BudgetKiB || argonBudget.waiters.Len() != 0 {
		t.Fatalf("budget not restored: free %d, %d waiting", argonBudget.free, argonBudget.waiters.Len())
	}
}

// TestHasAESHardwareOnlyWhereGoHasAssembly pins DESIGN §7.7: "auto" may only
// choose AES-256-GCM where Go actually compiles AES and GHASH assembly.
// x/sys/cpu reports AES-NI on any modern x86, but a GOARCH=386 build gets the
// generic table-driven AES (a cache-timing risk and slower than ChaCha20),
// which is exactly what the setting exists to avoid.
func TestHasAESHardwareOnlyWhereGoHasAssembly(t *testing.T) {
	for _, arch := range []string{"386", "arm", "riscv64", "mips", "mips64", "mips64le", "loong64", "wasm"} {
		if hasAESHardware(arch) {
			t.Errorf("hasAESHardware(%q) = true; Go has no AES/GCM assembly for %s, so auto must pick ChaCha20-Poly1305", arch, arch)
		}
	}
	// The architectures Go does have assembly for still depend on the CPU;
	// on this host amd64/arm64 must at least be decided by the feature bits.
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		if HasAESHardware() != hasAESHardware(runtime.GOARCH) {
			t.Fatal("HasAESHardware does not use the running architecture")
		}
	}
}
