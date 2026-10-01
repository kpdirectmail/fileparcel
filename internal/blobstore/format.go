package blobstore

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
)

// Blob file format (DESIGN §7.3):
//
//	Header (32 bytes): "FPB1" | version 1 | cipher id | seg_log2 16 | flags 0 |
//	                   blob id (16 raw bytes) | 8 reserved zero bytes
//	Segment i (i = 0 … N-1), N = max(1, ceil(P/S)), S = 64 KiB:
//	    nonce (12 random bytes) || ciphertext (len_i bytes) || tag (16 bytes)
//	    len_i = S for i < N-1; len_{N-1} = P - (N-1)·S (0 for an empty blob)
//	    AAD_i = header[0:32] || uint64be(i) || byte(final ? 1 : 0)
//	Stored offset of segment i = 32 + i·(S + 28); stored size = 32 + P + N·28
//
// Nonces are random per segment (never counters): a re-uploaded part is
// re-encrypted under the same DEK with fresh nonces. The DEK is unique per
// blob, so the number of encryptions per key stays far below GCM's
// random-nonce bound.
const (
	headerSize    = 32
	formatVersion = 1
	segLog2       = 16
	segSize       = 1 << segLog2
	nonceSize     = crypt.NonceSize
	tagSize       = crypt.TagSize
	segOverhead   = nonceSize + tagSize
	storedSegSize = segSize + segOverhead
	segsPerPart   = core.PartSize / segSize // 128
	aadSize       = headerSize + 8 + 1
	hashChunk     = core.PartSize // content_hash chunk size (8 MiB)
)

var magic = [4]byte{'F', 'P', 'B', '1'}

// numSegments returns N for a plaintext size p.
func numSegments(p int64) int64 {
	if p <= 0 {
		return 1
	}
	return (p + segSize - 1) >> segLog2
}

// StoredSize returns the on-disk size of a blob with plain bytes of
// plaintext: 32 + P + N·28.
func StoredSize(plain int64) int64 {
	return headerSize + plain + numSegments(plain)*segOverhead
}

// segOffset is the stored offset of segment i.
func segOffset(i int64) int64 { return headerSize + i*storedSegSize }

// segPlainLen is the plaintext length of segment i of a p-byte blob.
func segPlainLen(p, i int64) int64 {
	n := numSegments(p)
	if i < n-1 {
		return segSize
	}
	return p - (n-1)*segSize
}

// partCount is the number of PartSize parts of a p-byte blob (0 when empty).
func partCount(p int64) int {
	return int((p + core.PartSize - 1) / core.PartSize)
}

// header is the 32-byte blob header.
type header [headerSize]byte

func makeHeader(c core.CipherID, idRaw []byte) header {
	var h header
	copy(h[0:4], magic[:])
	h[4] = formatVersion
	h[5] = byte(c)
	h[6] = segLog2
	h[7] = 0
	copy(h[8:24], idRaw)
	return h
}

// checkHeader validates b against the expected id and cipher.
func checkHeader(b []byte, idRaw []byte, c core.CipherID) error {
	if len(b) != headerSize {
		return corrupt("short header")
	}
	want := makeHeader(c, idRaw)
	for i := range want {
		if b[i] != want[i] {
			return corrupt("header mismatch")
		}
	}
	return nil
}

// segCipher seals and opens the segments of one blob. It keeps the AAD
// (header prefix filled once) and the nonce in scratch space so that the
// per-segment work does not allocate. It is not safe for concurrent use;
// every writer, reader and WritePart call has its own.
type segCipher struct {
	a     cipher.AEAD
	aad   [aadSize]byte // header || uint64be(i) || final
	nonce [nonceSize]byte
}

func newSegCipher(a cipher.AEAD, h *header) *segCipher {
	c := &segCipher{a: a}
	copy(c.aad[:headerSize], h[:])
	return c
}

// setAAD fills the index and final flag of the AAD.
func (c *segCipher) setAAD(i int64, final bool) []byte {
	binary.BigEndian.PutUint64(c.aad[headerSize:], uint64(i))
	c.aad[aadSize-1] = 0
	if final {
		c.aad[aadSize-1] = 1
	}
	return c.aad[:]
}

// seal encrypts pt as segment i with a fresh random nonce into out (cap ≥
// storedSegSize) and returns the stored segment (nonce || ct || tag).
func (c *segCipher) seal(i int64, final bool, pt, out []byte) []byte {
	_, _ = rand.Read(c.nonce[:])
	out = append(out[:0], c.nonce[:]...)
	return c.a.Seal(out, c.nonce[:], pt, c.setAAD(i, final))
}

// open authenticates and decrypts stored segment i into dst[:0].
func (c *segCipher) open(i int64, final bool, stored, dst []byte) ([]byte, error) {
	if len(stored) < segOverhead {
		return nil, corrupt("truncated segment")
	}
	pt, err := c.a.Open(dst[:0], stored[:nonceSize], stored[nonceSize:], c.setAAD(i, final))
	if err != nil {
		return nil, corrupt("segment failed authentication")
	}
	return pt, nil
}

func corrupt(msg string) error { return core.Wrap(core.ErrCorrupt, "blob "+msg, nil) }

// contentHasher computes content_hash = "fp1:" + hex(SHA-256(concat(SHA-256
// of each 8 MiB plaintext chunk))). The empty blob hashes the empty
// concatenation.
type contentHasher struct {
	chunk hash.Hash
	outer hash.Hash
	n     int64 // bytes in the current chunk
}

func newContentHasher() *contentHasher {
	return &contentHasher{chunk: sha256.New(), outer: sha256.New()}
}

// Write feeds plaintext (never fails).
func (h *contentHasher) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		take := min(int64(len(p)), hashChunk-h.n)
		h.chunk.Write(p[:take])
		h.n += take
		p = p[take:]
		if h.n == hashChunk {
			h.outer.Write(h.chunk.Sum(nil))
			h.chunk.Reset()
			h.n = 0
		}
	}
	return total, nil
}

// Sum returns the content hash.
func (h *contentHasher) Sum() string {
	if h.n > 0 {
		h.outer.Write(h.chunk.Sum(nil))
		h.chunk.Reset()
		h.n = 0
	}
	return "fp1:" + hex.EncodeToString(h.outer.Sum(nil))
}

// HashOfDigests returns the content hash for the SHA-256 digests of the
// consecutive 8 MiB chunks (parts) of a blob: "fp1:" + hex(SHA-256(concat)).
// Upload clients compute the same per-part digests.
func HashOfDigests(digests [][]byte) string {
	h := sha256.New()
	for _, d := range digests {
		h.Write(d)
	}
	return "fp1:" + hex.EncodeToString(h.Sum(nil))
}
