package blobstore

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	"fileparcel/internal/core"
)

// Benchmarks report MB/s (b.SetBytes) and allocations. storage.fsync is
// off so that they measure the encryption pipeline rather than the disk:
//
//	go test -run '^$' -bench . -benchmem ./internal/blobstore/

const benchSize = 4 * core.PartSize // 32 MiB

var benchCiphers = []struct {
	name, setting string
}{{"aes-gcm", "aes-gcm"}, {"chacha20-poly1305", "chacha20-poly1305"}}

func benchStore(b *testing.B, cipher string) *testStore {
	b.Helper()
	ts := newStore(b)
	ts.settings.set("storage.fsync", false)
	ts.settings.set("storage.cipher", cipher)
	return ts
}

// BenchmarkWriteStream writes 32 MiB through the streaming writer in 1 MiB
// chunks.
func BenchmarkWriteStream(b *testing.B) {
	for _, c := range benchCiphers {
		b.Run(c.name, func(b *testing.B) {
			ts := benchStore(b, c.setting)
			data := randData(benchSize, 1)
			b.SetBytes(benchSize)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				w, err := ts.Create(ctx)
				if err != nil {
					b.Fatal(err)
				}
				for off := 0; off < len(data); off += 1 << 20 {
					if _, err := w.Write(data[off : off+1<<20]); err != nil {
						b.Fatal(err)
					}
				}
				info, err := w.Commit(ctx)
				if err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				_ = ts.Delete(ctx, info.ID)
				b.StartTimer()
			}
		})
	}
}

// BenchmarkWriteParted writes 32 MiB as four 8 MiB parts.
func BenchmarkWriteParted(b *testing.B) {
	for _, c := range benchCiphers {
		b.Run(c.name, func(b *testing.B) {
			ts := benchStore(b, c.setting)
			data := randData(benchSize, 2)
			digests := make([][]byte, 0, 4)
			for off := 0; off < len(data); off += core.PartSize {
				d := sha256.Sum256(data[off : off+core.PartSize])
				digests = append(digests, d[:])
			}
			b.SetBytes(benchSize)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				p, err := ts.CreateParted(ctx, benchSize)
				if err != nil {
					b.Fatal(err)
				}
				for n := range p.PartCount() {
					if _, err := p.WritePart(ctx, n, bytes.NewReader(data[n*core.PartSize:(n+1)*core.PartSize]), digests[n]); err != nil {
						b.Fatal(err)
					}
				}
				info, err := p.Commit(ctx, digests)
				if err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				_ = ts.Delete(ctx, info.ID)
				b.StartTimer()
			}
		})
	}
}

// BenchmarkRead reads a 32 MiB blob sequentially (as io.Copy does).
func BenchmarkRead(b *testing.B) {
	for _, c := range benchCiphers {
		b.Run(c.name, func(b *testing.B) {
			ts := benchStore(b, c.setting)
			info := ts.putStream(b, randData(benchSize, 3))
			buf := make([]byte, 32<<10)
			b.SetBytes(benchSize)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				r, err := ts.Open(ctx, info.ID)
				if err != nil {
					b.Fatal(err)
				}
				if n, err := io.CopyBuffer(io.Discard, r, buf); err != nil || n != benchSize {
					b.Fatal(n, err)
				}
				r.Close()
			}
		})
	}
}

// BenchmarkReadAtRandom reads 4 KiB at random offsets (Range requests,
// video seeking): each read decrypts one segment.
func BenchmarkReadAtRandom(b *testing.B) {
	ts := benchStore(b, "aes-gcm")
	info := ts.putStream(b, randData(benchSize, 4))
	r, err := ts.Open(ctx, info.ID)
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()
	buf := make([]byte, 4<<10)
	offs := randData(8*1024, 5)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		k := (i * 8) % len(offs)
		off := int64(uint32(offs[k])|uint32(offs[k+1])<<8|uint32(offs[k+2])<<16|uint32(offs[k+3])<<24) % (benchSize - int64(len(buf)))
		if _, err := r.ReadAt(buf, off); err != nil {
			b.Fatal(err)
		}
	}
}
