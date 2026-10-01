package blobstore

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
)

// serve runs http.ServeContent over a fresh BlobReader of id.
func (ts *testStore) serve(t testing.TB, id string, method string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	rd, err := ts.Open(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	req := httptest.NewRequest(method, "/content", nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	rec.Header().Set("ETag", `"ver_1"`)
	http.ServeContent(rec, req, "file.bin", time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), rd)
	return rec
}

// segmentBoundaries returns interesting offsets of a p-byte blob: every
// segment and part boundary ±1 plus the ends.
func segmentBoundaries(p int64) []int64 {
	var out []int64
	add := func(o int64) {
		if o >= 0 && o < p {
			out = append(out, o)
		}
	}
	for b := int64(0); b <= p; b += segSize {
		add(b - 1)
		add(b)
		add(b + 1)
	}
	add(p - 1)
	return out
}

// TestServeContentRanges drives the reader through http.ServeContent: full
// body, single ranges around every segment boundary, suffix and open
// ranges, multi-range (multipart/byteranges), If-Range and unsatisfiable
// ranges (DESIGN §7.3, §17).
func TestServeContentRanges(t *testing.T) {
	ts := newStore(t)
	const size = 4*segSize + 777
	data := randData(size, 5)
	info := ts.putParted(t, data)

	rec := ts.serve(t, info.ID, http.MethodGet, nil)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), data) || rec.Header().Get("Content-Length") != strconv.Itoa(size) ||
		rec.Header().Get("Accept-Ranges") != "bytes" {
		t.Fatalf("full: %d len %d headers %v", rec.Code, rec.Body.Len(), rec.Header())
	}
	head := ts.serve(t, info.ID, http.MethodHead, nil)
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Length") != strconv.Itoa(size) {
		t.Fatalf("HEAD: %d %d %v", head.Code, head.Body.Len(), head.Header())
	}

	single := func(spec string, start, end int64) {
		t.Helper()
		rec := ts.serve(t, info.ID, http.MethodGet, map[string]string{"Range": "bytes=" + spec})
		want := data[start : end+1]
		if rec.Code != http.StatusPartialContent || !bytes.Equal(rec.Body.Bytes(), want) ||
			rec.Header().Get("Content-Range") != fmt.Sprintf("bytes %d-%d/%d", start, end, size) {
			t.Fatalf("range %s: %d %q body %d bytes", spec, rec.Code, rec.Header().Get("Content-Range"), rec.Body.Len())
		}
	}
	for _, b := range segmentBoundaries(size) {
		single(fmt.Sprintf("%d-%d", b, b), b, b)
		single(fmt.Sprintf("%d-%d", b, min(b+segSize, size-1)), b, min(b+segSize, size-1))
		if b >= 5 {
			single(fmt.Sprintf("%d-%d", b-5, min(b+5, size-1)), b-5, min(b+5, size-1))
		}
		single(fmt.Sprintf("%d-", b), b, size-1)
	}
	single("-1", size-1, size-1)
	single("-70000", size-70000, size-1)
	single(fmt.Sprintf("0-%d", size+1000), 0, size-1) // clamped

	// multi-range across segment boundaries
	ranges := [][2]int64{{0, 10}, {segSize - 3, segSize + 3}, {2*segSize - 1, 3*segSize + 1}, {size - 5, size - 1}}
	var specs []string
	for _, r := range ranges {
		specs = append(specs, fmt.Sprintf("%d-%d", r[0], r[1]))
	}
	rec = ts.serve(t, info.ID, http.MethodGet, map[string]string{"Range": "bytes=" + strings.Join(specs, ",")})
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("multi-range status %d", rec.Code)
	}
	mt, params, err := mime.ParseMediaType(rec.Header().Get("Content-Type"))
	if err != nil || mt != "multipart/byteranges" {
		t.Fatalf("multi-range content type %q %v", rec.Header().Get("Content-Type"), err)
	}
	mr := multipart.NewReader(rec.Body, params["boundary"])
	for i, r := range ranges {
		p, err := mr.NextPart()
		if err != nil {
			t.Fatalf("part %d: %v", i, err)
		}
		if cr := p.Header.Get("Content-Range"); cr != fmt.Sprintf("bytes %d-%d/%d", r[0], r[1], size) {
			t.Fatalf("part %d: Content-Range %q", i, cr)
		}
		got, _ := io.ReadAll(p)
		if !bytes.Equal(got, data[r[0]:r[1]+1]) {
			t.Fatalf("part %d: body mismatch", i)
		}
	}
	if _, err := mr.NextPart(); !errors.Is(err, io.EOF) {
		t.Fatalf("extra part: %v", err)
	}

	// If-Range: matching ETag → 206, stale → full 200
	rec = ts.serve(t, info.ID, http.MethodGet, map[string]string{"Range": "bytes=100-199", "If-Range": `"ver_1"`})
	if rec.Code != http.StatusPartialContent || !bytes.Equal(rec.Body.Bytes(), data[100:200]) {
		t.Fatalf("If-Range match: %d", rec.Code)
	}
	rec = ts.serve(t, info.ID, http.MethodGet, map[string]string{"Range": "bytes=100-199", "If-Range": `"ver_0"`})
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), data) {
		t.Fatalf("If-Range mismatch: %d", rec.Code)
	}
	// If-None-Match → 304
	if rec := ts.serve(t, info.ID, http.MethodGet, map[string]string{"If-None-Match": `"ver_1"`}); rec.Code != http.StatusNotModified {
		t.Fatalf("If-None-Match: %d", rec.Code)
	}
	// unsatisfiable
	rec = ts.serve(t, info.ID, http.MethodGet, map[string]string{"Range": fmt.Sprintf("bytes=%d-", size)})
	if rec.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("unsatisfiable: %d", rec.Code)
	}

	// the empty blob
	empty := ts.putStream(t, nil)
	rec = ts.serve(t, empty.ID, http.MethodGet, nil)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 || rec.Header().Get("Content-Length") != "0" {
		t.Fatalf("empty: %d %v", rec.Code, rec.Header())
	}
}

// TestServeContentCorrupt: a tampered segment aborts the response body
// (the status is already sent), it never serves unauthenticated bytes.
func TestServeContentCorrupt(t *testing.T) {
	ts := newStore(t)
	data := randData(3*segSize, 6)
	info := ts.putStream(t, data)
	flipByte(t, ts, info.ID, segOffset(1)+100)
	rec := ts.serve(t, info.ID, http.MethodGet, nil)
	if rec.Body.Len() > segSize || !bytes.Equal(rec.Body.Bytes(), data[:rec.Body.Len()]) {
		t.Fatalf("served %d bytes past the damaged segment", rec.Body.Len())
	}
	rec = ts.serve(t, info.ID, http.MethodGet, map[string]string{"Range": "bytes=0-100"})
	if rec.Code != http.StatusPartialContent || !bytes.Equal(rec.Body.Bytes(), data[:101]) {
		t.Fatal("undamaged range must still be served")
	}
}

// fuzzBlobs are the blobs FuzzReadAt reads from (one store per process).
type fuzzBlob struct {
	id   string
	data []byte
}

// FuzzReadAt compares ReadAt/Seek+Read on blobs of the sizes of DESIGN §17
// with the plaintext.
func FuzzReadAt(f *testing.F) {
	ts := newStore(f)
	var blobs []fuzzBlob
	for i, size := range []int64{0, 1, segSize - 1, segSize, segSize + 1, 3*segSize + 5, core.PartSize + 1} {
		data := randData(size, uint64(100+i))
		var info *core.BlobInfo
		if i%2 == 0 {
			info = ts.putStream(f, data)
		} else {
			info = ts.putParted(f, data)
		}
		blobs = append(blobs, fuzzBlob{info.ID, data})
	}
	f.Add(uint8(0), int64(0), uint32(1))
	f.Add(uint8(3), int64(segSize-1), uint32(2))
	f.Add(uint8(5), int64(2*segSize-7), uint32(segSize+20))
	f.Add(uint8(6), int64(core.PartSize-3), uint32(10))
	f.Add(uint8(6), int64(-1), uint32(10))
	f.Add(uint8(4), int64(1<<40), uint32(10))
	f.Fuzz(func(t *testing.T, which uint8, off int64, n uint32) {
		b := blobs[int(which)%len(blobs)]
		size := int64(len(b.data))
		n %= 3 * segSize
		rd, err := ts.Open(ctx, b.id)
		if err != nil {
			t.Fatal(err)
		}
		defer rd.Close()
		buf := make([]byte, n)
		got, err := rd.ReadAt(buf, off)
		switch {
		case off < 0:
			if err == nil {
				t.Fatalf("negative offset accepted")
			}
			return
		case off >= size:
			if got != 0 || (n > 0 && err != io.EOF) {
				t.Fatalf("ReadAt(%d) past the end of %d: %d %v", off, size, got, err)
			}
			return
		}
		want := b.data[off:min(off+int64(n), size)]
		if got != len(want) || !bytes.Equal(buf[:got], want) {
			t.Fatalf("ReadAt(%d, %d) of %d: got %d bytes", off, n, size, got)
		}
		if (got < int(n)) != (err == io.EOF) || (err != nil && err != io.EOF) {
			t.Fatalf("ReadAt(%d, %d) of %d: err %v", off, n, size, err)
		}
		// Seek + Read gives the same bytes.
		if pos, err := rd.Seek(off, io.SeekStart); err != nil || pos != off {
			t.Fatalf("seek: %d %v", pos, err)
		}
		all, err := io.ReadAll(io.LimitReader(rd, int64(n)))
		if err != nil || !bytes.Equal(all, want) {
			t.Fatalf("Seek(%d)+Read(%d) of %d: %d bytes %v", off, n, size, len(all), err)
		}
	})
}
