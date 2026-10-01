package clikit

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"os"
	"strings"
)

// ChunkSize is the chunk size of the FileParcel content hash: the upload
// part size (core.PartSize, 8 MiB). Duplicated here so that clikit stays
// free of project imports; a test pins it to core.PartSize.
const ChunkSize = 8 << 20

// ContentHashPrefix prefixes content hashes of format version 1.
const ContentHashPrefix = "fp1:"

// ContentHasher computes the FileParcel content hash (DESIGN §7.3):
// "fp1:" + hex(SHA-256(concat(SHA-256(chunk_k)))) over consecutive chunks of
// ChunkSize plaintext bytes. An empty input hashes the empty concatenation.
// It is an io.Writer; call Sum when done.
type ContentHasher struct {
	chunk   hash.Hash // current chunk
	n       int64     // bytes in the current chunk
	outer   hash.Hash // SHA-256 over the chunk digests
	written int64
}

// NewContentHasher returns an empty hasher.
func NewContentHasher() *ContentHasher {
	return &ContentHasher{chunk: sha256.New(), outer: sha256.New()}
}

// Write implements io.Writer (never fails).
func (h *ContentHasher) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		room := ChunkSize - h.n
		take := int64(len(p))
		if take > room {
			take = room
		}
		h.chunk.Write(p[:take])
		h.n += take
		p = p[take:]
		if h.n == ChunkSize {
			h.flush()
		}
	}
	h.written += int64(total)
	return total, nil
}

func (h *ContentHasher) flush() {
	h.outer.Write(h.chunk.Sum(nil))
	h.chunk.Reset()
	h.n = 0
}

// Size returns the number of bytes hashed so far.
func (h *ContentHasher) Size() int64 { return h.written }

// Sum returns the content hash of everything written ("fp1:<64 hex>"). The
// hasher must not be written to afterwards.
func (h *ContentHasher) Sum() string {
	if h.n > 0 {
		h.flush()
	}
	return ContentHashPrefix + hex.EncodeToString(h.outer.Sum(nil))
}

// ContentHashFile computes the content hash of a local file.
func ContentHashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := NewContentHasher()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return h.Sum(), nil
}

// ComparableContentHash reports whether want is a content hash this package
// can verify (format fp1).
func ComparableContentHash(want string) bool {
	return strings.HasPrefix(want, ContentHashPrefix) && len(want) == len(ContentHashPrefix)+64
}
