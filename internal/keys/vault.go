package keys

import (
	"os"
	"sync"
)

// secretSize is the size of every secret held in the vault (MK, KEKs, MAC
// subkeys, the passphrase-derived key and the recovery-key hash).
const secretSize = 32

// secret is one 32-byte slot of key material in the vault. Bytes stays valid
// until the secret is released or the vault destroyed.
type secret struct {
	b    []byte
	page *vpage
	idx  int
}

// Bytes returns the key material.
func (s *secret) Bytes() []byte { return s.b }

// vpage is one page of vault memory, split into secretSize slots.
type vpage struct {
	mem     []byte
	used    []bool
	nfree   int
	mapped  bool // allocated with mmap (outside the Go heap)
	mlocked bool // mlock succeeded (never swapped out)
}

// vault keeps key material outside the Go heap in mlock'ed, non-dumpable
// pages when the platform allows it (best effort, DESIGN §7.2), and zeroes it
// on release. It is safe for concurrent use.
//
// Note: cipher.AEAD values built from these keys copy the key schedule onto
// the Go heap (crypto/aes and chacha20poly1305 offer no way around that);
// the vault protects the raw keys, which is what matters for the master key.
type vault struct {
	mu    sync.Mutex
	pages []*vpage
	dead  bool
}

func newVault() *vault { return &vault{} }

// put copies src (exactly secretSize bytes) into a new vault slot. The caller
// still owns src and should zero it.
func (v *vault) put(src []byte) *secret {
	if len(src) != secretSize {
		panic("keys: vault secret must be 32 bytes")
	}
	s := v.alloc()
	copy(s.b, src)
	return s
}

// alloc returns a zeroed slot.
func (v *vault) alloc() *secret {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dead {
		panic("keys: vault used after destroy")
	}
	for _, p := range v.pages {
		if p.nfree > 0 {
			return p.take()
		}
	}
	size := os.Getpagesize()
	if size < secretSize {
		size = 4096
	}
	mem, mapped, locked := sysAlloc(size)
	p := &vpage{mem: mem, used: make([]bool, len(mem)/secretSize), mapped: mapped, mlocked: locked}
	p.nfree = len(p.used)
	v.pages = append(v.pages, p)
	return p.take()
}

func (p *vpage) take() *secret {
	for i, u := range p.used {
		if !u {
			p.used[i] = true
			p.nfree--
			b := p.mem[i*secretSize : (i+1)*secretSize : (i+1)*secretSize]
			clear(b)
			return &secret{b: b, page: p, idx: i}
		}
	}
	panic("keys: vault page accounting")
}

// release zeroes s and returns its slot. Releasing nil or an already
// released secret is a no-op.
func (v *vault) release(s *secret) {
	if s == nil || s.page == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	clear(s.b)
	if !v.dead && s.page.used[s.idx] {
		s.page.used[s.idx] = false
		s.page.nfree++
	}
	s.page = nil
	s.b = nil
}

// destroy zeroes every page and returns the memory to the OS.
func (v *vault) destroy() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dead {
		return
	}
	v.dead = true
	for _, p := range v.pages {
		sysFree(p.mem, p.mapped, p.mlocked)
		p.mem = nil
	}
	v.pages = nil
}

// mlocked reports whether every page is locked in RAM (false when the vault
// is empty).
func (v *vault) mlocked() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.pages) == 0 {
		return false
	}
	for _, p := range v.pages {
		if !p.mlocked {
			return false
		}
	}
	return true
}
