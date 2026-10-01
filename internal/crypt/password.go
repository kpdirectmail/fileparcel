package crypt

import (
	"container/list"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are argon2id cost parameters.
type Argon2Params struct {
	MemoryKiB uint32 // m
	Time      uint32 // t (iterations)
	Threads   uint8  // p
	SaltLen   int
	KeyLen    uint32
}

// PasswordParams are the parameters for new password hashes (DESIGN §18.12):
// m = 64 MiB, t = 3, p = 2, 16-byte salt, 32-byte key.
var PasswordParams = Argon2Params{MemoryKiB: 64 * 1024, Time: 3, Threads: 2, SaltLen: 16, KeyLen: 32}

// Argon2Slots is the nominal concurrency at PasswordParams cost; the real
// limit is Argon2BudgetKiB, the total argon2 memory in flight process-wide
// (DESIGN §18.12: 4 x 64 MiB). A derivation that asks for more memory (the
// sealed master-key KDF uses m = 128 MiB, keys/keyfile.go defaultKDF) takes a
// correspondingly larger share of the budget, so the ceiling holds on small
// machines however the derivations are mixed. That holds because no
// derivation may ask for more than the whole budget: every stored parameter
// is checked against Argon2BudgetKiB where it is minted (HashPasswordParams)
// and where it is read back (ParsePHC, keys.checkKDF).
const Argon2Slots = 4

// Argon2BudgetKiB is the total argon2 memory allowed in flight.
const Argon2BudgetKiB = Argon2Slots * 64 * 1024

// MaxArgonWaiters bounds the queue behind the budget for the request paths
// (the Context variants below): once that many derivations are waiting, the
// next one fails at once with ErrArgonBusy instead of queueing behind them,
// so a flood of password attempts cannot delay a sign-in without limit.
const MaxArgonWaiters = 8 * Argon2Slots

// ErrArgonBusy is returned by the Context variants when MaxArgonWaiters
// derivations are already queued. It says nothing about the password: the
// caller must answer "busy, try again", never "wrong password".
var ErrArgonBusy = errors.New("crypt: too many password checks are waiting; try again shortly")

var argonBudget = newArgonBudget(Argon2BudgetKiB)

// argonBudgetSem hands out argon2 memory FIFO: a request never overtakes an
// earlier one, so a large derivation cannot be starved by small ones. A
// waiter whose context ends leaves the queue (and wakes the next one when it
// was at the head).
type argonBudgetSem struct {
	mu         sync.Mutex
	total      uint32
	free       uint32
	waiters    list.List // *argonWaiter, oldest first
	maxWaiters int       // queue length at which capped requests fail (ErrArgonBusy)
}

type argonWaiter struct {
	n     uint32
	ready chan struct{} // closed once n KiB were reserved for this waiter
}

func newArgonBudget(total uint32) *argonBudgetSem {
	return &argonBudgetSem{total: total, free: total, maxWaiters: MaxArgonWaiters}
}

// acquire reserves n KiB, waiting as long as it takes, and returns the
// amount reserved (the path for callers without a context: the CLI, boot,
// password changes of signed-in users).
func (b *argonBudgetSem) acquire(n uint32) uint32 {
	n, _ = b.acquireContext(context.Background(), n, false)
	return n
}

// acquireContext reserves n KiB and returns the amount reserved. It gives up
// with ctx.Err() when ctx ends first, and a capped request fails at once
// with ErrArgonBusy when maxWaiters requests are already queued. The clamp
// to the whole budget is only a deadlock guard: a request larger than total
// could never be served. The real ceiling is enforced where parameters are
// minted and parsed, so n > total does not happen for a derivation this
// process agrees to run.
func (b *argonBudgetSem) acquireContext(ctx context.Context, n uint32, capped bool) (uint32, error) {
	if n == 0 {
		n = 1
	}
	if n > b.total {
		n = b.total
	}
	b.mu.Lock()
	if b.waiters.Len() == 0 && b.free >= n {
		b.free -= n
		b.mu.Unlock()
		return n, nil
	}
	if capped && b.waiters.Len() >= b.maxWaiters {
		b.mu.Unlock()
		return 0, ErrArgonBusy
	}
	w := &argonWaiter{n: n, ready: make(chan struct{})}
	e := b.waiters.PushBack(w)
	b.mu.Unlock()
	select {
	case <-w.ready:
		return n, nil
	case <-ctx.Done():
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	select {
	case <-w.ready:
		// Served while giving up: hand the reservation back.
		b.free += n
	default:
		b.waiters.Remove(e)
	}
	b.serveLocked() // the next waiter may fit now
	return 0, ctx.Err()
}

func (b *argonBudgetSem) release(n uint32) {
	b.mu.Lock()
	b.free += n
	b.serveLocked()
	b.mu.Unlock()
}

// serveLocked reserves memory for the waiters at the head of the queue, in
// order, as long as the head fits.
func (b *argonBudgetSem) serveLocked() {
	for e := b.waiters.Front(); e != nil; e = b.waiters.Front() {
		w := e.Value.(*argonWaiter)
		if b.free < w.n {
			return
		}
		b.free -= w.n
		b.waiters.Remove(e)
		close(w.ready)
	}
}

// Argon2Key derives keyLen bytes with argon2id while holding MemoryKiB of the
// process-wide argon2 budget, waiting for it as long as it takes. Use it (or
// Argon2KeyContext) for every argon2 computation in the process (passwords
// and the sealed master-key KDF).
func Argon2Key(password, salt []byte, t, mKiB uint32, p uint8, keyLen uint32) []byte {
	k, _ := argon2Key(context.Background(), false, password, salt, t, mKiB, p, keyLen)
	return k
}

// Argon2KeyContext is Argon2Key for request paths: it gives up (ctx.Err())
// when ctx ends while waiting for the budget, and fails at once with
// ErrArgonBusy when MaxArgonWaiters derivations are already queued.
func Argon2KeyContext(ctx context.Context, password, salt []byte, t, mKiB uint32, p uint8, keyLen uint32) ([]byte, error) {
	return argon2Key(ctx, true, password, salt, t, mKiB, p, keyLen)
}

func argon2Key(ctx context.Context, capped bool, password, salt []byte, t, mKiB uint32, p uint8, keyLen uint32) ([]byte, error) {
	n, err := argonBudget.acquireContext(ctx, mKiB, capped)
	if err != nil {
		return nil, err
	}
	defer argonBudget.release(n)
	return argon2.IDKey(password, salt, t, mKiB, p, keyLen), nil
}

// ErrInvalidHash is returned for strings that are not argon2id PHC hashes.
var ErrInvalidHash = errors.New("crypt: invalid argon2id PHC string")

var b64 = base64.RawStdEncoding

// HashPassword returns an argon2id PHC string with PasswordParams:
//
//	$argon2id$v=19$m=65536,t=3,p=2$<b64 salt>$<b64 key>   (unpadded std base64)
func HashPassword(pw string) (string, error) {
	return HashPasswordParams(pw, PasswordParams)
}

// HashPasswordParams is HashPassword with explicit parameters (tests use cheap ones).
func HashPasswordParams(pw string, p Argon2Params) (string, error) {
	if p.SaltLen < 8 || p.KeyLen < 16 || p.Time < 1 || p.Threads < 1 || p.MemoryKiB < 8*uint32(p.Threads) {
		return "", errors.New("crypt: argon2 parameters too weak")
	}
	// Never mint a hash this process would refuse to verify: m must fit in
	// the process-wide argon2 budget.
	if p.MemoryKiB > Argon2BudgetKiB {
		return "", errors.New("crypt: argon2 memory above the process budget")
	}
	salt := RandomBytes(p.SaltLen)
	key := Argon2Key([]byte(pw), salt, p.Time, p.MemoryKiB, p.Threads, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.MemoryKiB, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// PHC is a decoded argon2id PHC string.
type PHC struct {
	Version int
	Params  Argon2Params
	Salt    []byte
	Key     []byte
}

// ParsePHC decodes an argon2id PHC string.
func ParsePHC(s string) (*PHC, error) {
	parts := strings.Split(s, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, key
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, ErrInvalidHash
	}
	var h PHC
	v, ok := strings.CutPrefix(parts[2], "v=")
	if !ok {
		return nil, ErrInvalidHash
	}
	ver, err := strconv.Atoi(v)
	if err != nil {
		return nil, ErrInvalidHash
	}
	h.Version = ver
	for _, kv := range strings.Split(parts[3], ",") {
		k, val, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, ErrInvalidHash
		}
		n, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return nil, ErrInvalidHash
		}
		switch k {
		case "m":
			h.Params.MemoryKiB = uint32(n)
		case "t":
			h.Params.Time = uint32(n)
		case "p":
			if n > 255 {
				return nil, ErrInvalidHash
			}
			h.Params.Threads = uint8(n)
		default:
			return nil, ErrInvalidHash
		}
	}
	if h.Params.MemoryKiB == 0 || h.Params.Time == 0 || h.Params.Threads == 0 {
		return nil, ErrInvalidHash
	}
	// Refuse absurd costs from a tampered DB (DoS guard): no stored hash may
	// ask for more memory than the whole process-wide budget, t <= 64.
	if h.Params.MemoryKiB > Argon2BudgetKiB || h.Params.Time > 64 {
		return nil, ErrInvalidHash
	}
	if h.Salt, err = b64.DecodeString(parts[4]); err != nil || len(h.Salt) < 8 {
		return nil, ErrInvalidHash
	}
	if h.Key, err = b64.DecodeString(parts[5]); err != nil || len(h.Key) < 16 {
		return nil, ErrInvalidHash
	}
	h.Params.SaltLen = len(h.Salt)
	h.Params.KeyLen = uint32(len(h.Key))
	return &h, nil
}

// VerifyPassword checks pw against an argon2id PHC string in constant time.
// needsRehash is true (only when ok) if the hash was made with parameters
// other than PasswordParams, so the caller should store a fresh hash.
// Malformed hashes return (false, false).
func VerifyPassword(phc, pw string) (ok bool, needsRehash bool) {
	ok, needsRehash, _ = verifyPassword(context.Background(), phc, pw, false)
	return ok, needsRehash
}

// VerifyPasswordContext is VerifyPassword for request paths (sign-in, share
// passwords): it gives up when ctx ends while waiting for the argon2 budget
// and fails at once with ErrArgonBusy when too many checks are queued
// (Argon2KeyContext). A non-nil err means "not checked", never "wrong".
func VerifyPasswordContext(ctx context.Context, phc, pw string) (ok, needsRehash bool, err error) {
	return verifyPassword(ctx, phc, pw, true)
}

func verifyPassword(ctx context.Context, phc, pw string, capped bool) (ok, needsRehash bool, err error) {
	h, err := ParsePHC(phc)
	if err != nil || h.Version != argon2.Version {
		return false, false, nil
	}
	key, err := argon2Key(ctx, capped, []byte(pw), h.Salt, h.Params.Time, h.Params.MemoryKiB, h.Params.Threads, h.Params.KeyLen)
	if err != nil {
		return false, false, err
	}
	if subtle.ConstantTimeCompare(key, h.Key) != 1 {
		return false, false, nil
	}
	return true, h.Params != PasswordParams, nil
}

var (
	dummyOnce sync.Once
	dummyHash string
)

func dummy() string {
	dummyOnce.Do(func() {
		dummyHash, _ = HashPassword("fileparcel-dummy-password")
	})
	return dummyHash
}

// VerifyDummy performs a password verification against a fixed dummy hash and
// discards the result. Call it when the user does not exist so that login
// timing does not reveal account existence (DESIGN §9.3).
func VerifyDummy(pw string) {
	VerifyPassword(dummy(), pw)
}

// VerifyDummyContext is VerifyDummy with the queueing rules of
// VerifyPasswordContext; it returns their error (nil once the dummy check
// ran), so an unknown user is refused as "busy" exactly when a known one is.
func VerifyDummyContext(ctx context.Context, pw string) error {
	_, _, err := VerifyPasswordContext(ctx, dummy(), pw)
	return err
}
