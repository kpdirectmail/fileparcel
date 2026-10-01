package thumbs

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"testing"

	"golang.org/x/image/bmp"
)

func solid(w, h int, c color.Color) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, c)
		}
	}
	return img
}

func encode(t *testing.T, format string, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	var err error
	switch format {
	case "png":
		err = png.Encode(&buf, img)
	case "jpeg":
		err = jpeg.Encode(&buf, img, nil)
	case "gif":
		err = gif.Encode(&buf, img, nil)
	case "bmp":
		err = bmp.Encode(&buf, img)
	}
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// tinyWebP is a 1×1 lossless WebP.
var tinyWebP = []byte("RIFF\x1a\x00\x00\x00WEBPVP8L\x0d\x00\x00\x00\x2f\x00\x00\x00\x10\x07\x10\x11\x11\x88\x88\xfe\x07\x00")

func gen(t *testing.T, data []byte, o Options) (*Thumb, error) {
	t.Helper()
	return Generate(context.Background(), bytes.NewReader(data), int64(len(data)), o)
}

func decodeThumb(t *testing.T, th *Thumb) image.Image {
	t.Helper()
	img, format, err := image.Decode(bytes.NewReader(th.Data))
	if err != nil {
		t.Fatalf("thumbnail does not decode: %v", err)
	}
	if want := map[string]string{MIMEJPEG: "jpeg", MIMEPNG: "png"}[th.MIME]; format != want {
		t.Fatalf("format %s, MIME %s", format, th.MIME)
	}
	if b := img.Bounds(); b.Dx() != th.Width || b.Dy() != th.Height {
		t.Fatalf("bounds %v vs %dx%d", b, th.Width, th.Height)
	}
	return img
}

func TestGenerateFormats(t *testing.T) {
	red := color.NRGBA{200, 10, 10, 255}
	cases := []struct {
		name       string
		data       []byte
		mime       string
		wantW      int
		wantH      int
		wantFormat string
	}{
		{"jpeg landscape", encode(t, "jpeg", solid(1000, 500, red)), "image/jpeg", 320, 160, MIMEJPEG},
		{"png portrait opaque", encode(t, "png", solid(300, 900, red)), "image/png", 107, 320, MIMEJPEG},
		{"png alpha", encode(t, "png", solid(640, 640, color.NRGBA{0, 0, 255, 100})), "image/png", 320, 320, MIMEPNG},
		{"gif small (no upscale)", encode(t, "gif", solid(50, 40, red)), "image/gif", 50, 40, MIMEJPEG},
		{"bmp", encode(t, "bmp", solid(400, 100, red)), "image/bmp", 320, 80, MIMEJPEG},
		{"webp", tinyWebP, "image/webp", 1, 1, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !Supported(c.mime) {
				t.Fatalf("%s not supported", c.mime)
			}
			th, err := gen(t, c.data, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if th.Width != c.wantW || th.Height != c.wantH {
				t.Fatalf("size %dx%d, want %dx%d", th.Width, th.Height, c.wantW, c.wantH)
			}
			if c.wantFormat != "" && th.MIME != c.wantFormat {
				t.Fatalf("MIME %s, want %s", th.MIME, c.wantFormat)
			}
			decodeThumb(t, th)
		})
	}
}

func TestSupported(t *testing.T) {
	for m, want := range map[string]bool{
		"image/jpeg": true, "IMAGE/PNG": true, "image/gif; x=y": true, "image/webp": true, "image/bmp": true,
		"image/svg+xml": false, "image/avif": false, "image/tiff": false, "text/plain": false, "": false,
	} {
		if Supported(m) != want {
			t.Errorf("Supported(%q) != %v", m, want)
		}
	}
}

// pngHeader returns a PNG signature + IHDR chunk announcing w×h (no pixels).
func pngHeader(w, h uint32, depth, ctype byte) []byte {
	return pngIHDR(w, h, depth, ctype, false)
}

// pngIHDR is pngHeader with the interlace method: Adam7 when interlaced.
func pngIHDR(w, h uint32, depth, ctype byte, interlaced bool) []byte {
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], w)
	binary.BigEndian.PutUint32(ihdr[4:], h)
	ihdr[8], ihdr[9] = depth, ctype
	if interlaced {
		ihdr[12] = 1
	}
	return append([]byte("\x89PNG\r\n\x1a\n"), pngChunk("IHDR", ihdr)...)
}

// pngChunk returns a PNG chunk: length, type, data and CRC.
func pngChunk(typ string, data []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(data)))
	b = append(b, typ...)
	b = append(b, data...)
	return binary.BigEndian.AppendUint32(b, crc32.ChecksumIEEE(b[4:]))
}

func TestLimits(t *testing.T) {
	// A header announcing 100 MP is refused before any pixel is allocated.
	if _, err := gen(t, pngHeader(10000, 10000, 8, 2), Options{}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("100 MP: %v", err)
	}
	// 16-bit RGBA at 40 MP needs 320 MB decoded: over the memory budget.
	if _, err := gen(t, pngHeader(8000, 5000, 16, 6), Options{}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("16-bit 40 MP: %v", err)
	}
	// Custom pixel limit.
	if _, err := gen(t, encode(t, "png", solid(20, 20, color.White)), Options{MaxPixels: 100}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("custom limit: %v", err)
	}
	// Source size limit.
	if _, err := Generate(context.Background(), bytes.NewReader(nil), MaxSourceBytes+1, Options{}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("source size: %v", err)
	}
	for name, data := range map[string][]byte{
		"garbage":         []byte("definitely not an image"),
		"svg":             []byte("<svg xmlns='http://www.w3.org/2000/svg'/>"),
		"truncated png":   encode(t, "png", solid(64, 64, color.White))[:60],
		"zero dimensions": pngHeader(0, 10, 8, 2),
	} {
		if _, err := gen(t, data, Options{}); !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Generate(context.Background(), bytes.NewReader(nil), 0, Options{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("empty: %v", err)
	}
}

func TestCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	data := encode(t, "png", solid(10, 10, color.White))
	if _, err := Generate(ctx, bytes.NewReader(data), int64(len(data)), Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
}

// withOrientation inserts an EXIF APP1 segment with the given orientation
// right after the SOI marker of a JPEG.
func withOrientation(jpg []byte, o uint16, bigEndian bool) []byte {
	var tiff bytes.Buffer
	var bo binary.ByteOrder = binary.LittleEndian
	if bigEndian {
		bo = binary.BigEndian
		tiff.WriteString("MM")
	} else {
		tiff.WriteString("II")
	}
	w16 := func(v uint16) { var b [2]byte; bo.PutUint16(b[:], v); tiff.Write(b[:]) }
	w32 := func(v uint32) { var b [4]byte; bo.PutUint32(b[:], v); tiff.Write(b[:]) }
	w16(42)
	w32(8)
	w16(1)      // one entry
	w16(0x0112) // orientation
	w16(3)      // SHORT
	w32(1)      // count
	w16(o)
	w16(0)
	w32(0) // next IFD
	payload := append([]byte("Exif\x00\x00"), tiff.Bytes()...)
	seg := []byte{0xff, 0xe1, byte((len(payload) + 2) >> 8), byte(len(payload) + 2)}
	out := append([]byte{}, jpg[:2]...)
	out = append(out, seg...)
	out = append(out, payload...)
	return append(out, jpg[2:]...)
}

func TestEXIFOrientation(t *testing.T) {
	// Left half red, right half blue.
	src := image.NewNRGBA(image.Rect(0, 0, 80, 40))
	for y := 0; y < 40; y++ {
		for x := 0; x < 80; x++ {
			c := color.NRGBA{255, 0, 0, 255}
			if x >= 40 {
				c = color.NRGBA{0, 0, 255, 255}
			}
			src.Set(x, y, c)
		}
	}
	jpg := encode(t, "jpeg", src)
	for _, be := range []bool{false, true} {
		for o, want := range map[uint16][2]int{1: {80, 40}, 3: {80, 40}, 6: {40, 80}, 8: {40, 80}} {
			data := withOrientation(jpg, o, be)
			if got := exifOrientation(data); got != int(o) {
				t.Fatalf("parse orientation %d (be=%v): got %d", o, be, got)
			}
			th, err := gen(t, data, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if th.Width != want[0] || th.Height != want[1] {
				t.Fatalf("orientation %d: %dx%d", o, th.Width, th.Height)
			}
			img := decodeThumb(t, th)
			if o == 6 { // rotated 90° clockwise: red (left) ends up on top
				r, _, b, _ := img.At(20, 5).RGBA()
				if r < b {
					t.Fatalf("orientation 6: top is not red")
				}
			}
		}
	}
	if exifOrientation([]byte("not a jpeg")) != 1 || exifOrientation(jpg) != 1 {
		t.Fatal("default orientation")
	}
}

func TestFit(t *testing.T) {
	cases := [][4]int{{1000, 500, 320, 160}, {500, 1000, 160, 320}, {320, 320, 320, 320}, {10000, 1, 320, 1}, {100, 50, 100, 50}}
	for _, c := range cases {
		if w, h := fit(c[0], c[1], 320); w != c[2] || h != c[3] {
			t.Errorf("fit(%d,%d) = %d,%d want %d,%d", c[0], c[1], w, h, c[2], c[3])
		}
	}
}

// progJPEG16 is a 16×16 progressive JPEG (SOF2), written by libjpeg —
// image/jpeg only encodes baseline, so the sample is embedded.
var progJPEG16 = mustB64("/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDABALDA4MChAODQ4SERATGCgaGBYWGDEjJR0oOjM9PDkzODdASFxOQERXRTc4UG1R" +
	"V19iZ2hnPk1xeXBkeFxlZ2P/2wBDARESEhgVGC8aGi9jQjhCY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2Nj" +
	"Y2NjY2NjY2NjY2NjY2P/wgARCAAQABADASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAABAX/xAAUAQEAAAAAAAAAAAAA" +
	"AAAAAAAA/9oADAMBAAIQAxAAAAGatLD/xAAWEAADAAAAAAAAAAAAAAAAAAAAAgP/2gAIAQEAAQUCWYsxZizP/8QAFREBAQAA" +
	"AAAAAAAAAAAAAAAAAwD/2gAIAQMBAT8BB7//xAAVEQEBAAAAAAAAAAAAAAAAAAABAP/aAAgBAgEBPwEb/8QAFBABAAAAAAAA" +
	"AAAAAAAAAAAAIP/aAAgBAQAGPwIf/8QAFBABAAAAAAAAAAAAAAAAAAAAIP/aAAgBAQABPyEAH//aAAwDAQACAAMAAAAQY//E" +
	"ABYRAAMAAAAAAAAAAAAAAAAAAAAhMf/aAAgBAwEBPxCbP//EABQRAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQIBAT8Qf//EABYQ" +
	"AAMAAAAAAAAAAAAAAAAAAAAhMf/aAAgBAQABPxCSJIkiSP/Z")

func mustB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// withAPP1 returns data with a filler APP1 segment of n payload bytes
// spliced in right after the SOI, pushing the frame header past the 64 KiB
// head buffer (a large EXIF preview or ICC profile does the same).
func withAPP1(data []byte, n int) []byte {
	seg := make([]byte, 0, n+4)
	seg = append(seg, 0xff, 0xe1, byte((n+2)>>8), byte((n+2)&0xff))
	seg = append(seg, bytes.Repeat([]byte{'A'}, n)...)
	out := append([]byte{}, data[:2]...)
	out = append(out, seg...)
	return append(out, data[2:]...)
}

// TestProgressiveJPEGBudget pins that the memory guard charges a progressive
// JPEG what image/jpeg really needs for it (a whole-image coefficient array
// on top of the pixel buffer). Budgeting it at the 3 bytes/px of its color
// model let a ~1 MB upload allocate several hundred MiB.
func TestProgressiveJPEGBudget(t *testing.T) {
	px := int64(16 * 16) // both samples are one 16×16 MCU (4:2:0)
	baseline := encode(t, "jpeg", solid(16, 16, color.RGBA{R: 9, G: 40, B: 200, A: 255}))
	if f := readJPEGFrame(baseline, bytes.NewReader(baseline)); f.progressive {
		t.Fatal("a baseline JPEG was taken for a progressive one")
	}
	if f := readJPEGFrame(progJPEG16, bytes.NewReader(progJPEG16)); !f.progressive {
		t.Fatal("the progressive JPEG (SOF2) was not detected")
	}
	// Room for 4 bytes/px: the baseline image fits, the progressive one
	// needs five times its color model and does not.
	o := Options{MaxDecodedBytes: 4 * px}
	if _, err := gen(t, baseline, o); err != nil {
		t.Fatalf("baseline refused: %v", err)
	}
	if _, err := gen(t, progJPEG16, o); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("progressive JPEG accepted on a 4 bytes/px budget: %v", err)
	}
	// With room for the coefficients (3 planes + 3 × 4 bytes) it is decoded
	// as before.
	th, err := gen(t, progJPEG16, Options{MaxDecodedBytes: 15 * px})
	if err != nil {
		t.Fatalf("progressive JPEG with enough room: %v", err)
	}
	decodeThumb(t, th)

	// The frame header behind 80 KiB of metadata is still found (the head
	// buffer is 64 KiB, so this takes the second pass over the reader).
	padded := withAPP1(progJPEG16, 80<<10)
	if f := readJPEGFrame(padded[:64<<10], bytes.NewReader(padded)); !f.progressive {
		t.Fatal("progressive frame behind a large APP1 segment not detected")
	}
	if _, err := gen(t, padded, o); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("padded progressive JPEG accepted on a 4 bytes/px budget: %v", err)
	}
	// Truncated JPEG data: nothing is known, so it is charged the worst case.
	if f := readJPEGFrame(baseline[:4], bytes.NewReader(baseline[:4])); f != worstJPEGFrame {
		t.Fatal("a JPEG whose frame header cannot be found must be charged the worst case")
	}
}

// costOf runs the memory guard's estimate on data the way Generate does
// (64 KiB head, DecodeConfig, then decodeCost) and returns it with the
// announced pixel count.
func costOf(t *testing.T, data []byte, budget int64) (cost, px int64) {
	t.Helper()
	head := data[:min(len(data), 64<<10)]
	format := magic(head)
	dec, ok := decoders[format]
	if !ok {
		t.Fatalf("no decoder for % x", head[:min(len(head), 16)])
	}
	cfg, err := dec.config(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		t.Fatalf("%s DecodeConfig: %v", format, err)
	}
	return decodeCost(format, cfg, head, bytes.NewReader(data), budget), int64(cfg.Width) * int64(cfg.Height)
}

// pngFile returns a PNG w×h with the given chunks between IHDR and IDAT
// (paletted images need their PLTE there) and pixel data idat (nil: an
// empty IDAT, which DecodeConfig does not need).
func pngFile(w, h uint32, depth, ctype byte, interlaced bool, idat []byte, chunks ...[]byte) []byte {
	b := pngIHDR(w, h, depth, ctype, interlaced)
	for _, c := range chunks {
		b = append(b, c...)
	}
	b = append(b, pngChunk("IDAT", idat)...)
	return append(b, pngChunk("IEND", nil)...)
}

// pngZeroPixels returns the zlib stream of an all-zero w×h image of bpp
// bytes per pixel, in Adam7 passes when interlaced.
func pngZeroPixels(t *testing.T, w, h, bpp int, interlaced bool) []byte {
	t.Helper()
	passes := [][4]int{{0, 0, 1, 1}} // x0, y0, dx, dy
	if interlaced {
		passes = [][4]int{{0, 0, 8, 8}, {4, 0, 8, 8}, {0, 4, 4, 8}, {2, 0, 4, 4}, {0, 2, 2, 4}, {1, 0, 2, 2}, {0, 1, 1, 2}}
	}
	var raw []byte
	for _, p := range passes {
		pw, ph := (w-p[0]+p[2]-1)/p[2], (h-p[1]+p[3]-1)/p[3]
		if pw <= 0 || ph <= 0 {
			continue
		}
		raw = append(raw, make([]byte, ph*(1+pw*bpp))...) // filter byte 0 + zero samples per row
	}
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return z.Bytes()
}

// jpegSeg returns a JPEG marker segment.
func jpegSeg(marker byte, payload []byte) []byte {
	return append([]byte{0xff, marker, byte((len(payload) + 2) >> 8), byte(len(payload) + 2)}, payload...)
}

// jpegHeaders returns the headers of a w×h JPEG up to its first scan (no
// tables or entropy-coded data: DecodeConfig stops at the SOS marker): SOI,
// the segments before, a start-of-frame sof with one component per id
// (sampling factors hv) and the SOS header.
func jpegHeaders(sof byte, w, h int, ids, hv []byte, before ...[]byte) []byte {
	b := []byte{0xff, 0xd8}
	for _, s := range before {
		b = append(b, s...)
	}
	p := []byte{8, byte(h >> 8), byte(h), byte(w >> 8), byte(w), byte(len(ids))}
	for i, id := range ids {
		p = append(p, id, hv[i], 0)
	}
	b = append(b, jpegSeg(sof, p)...)
	sos := []byte{byte(len(ids))}
	for _, id := range ids {
		sos = append(sos, id, 0)
	}
	return append(b, jpegSeg(0xda, append(sos, 0, 63, 0))...)
}

// adobeAPP14 is an Adobe APP14 segment with the given color transform
// (0: RGB or CMYK, 1: YCbCr, 2: YCbCrK).
func adobeAPP14(transform byte) []byte {
	return jpegSeg(0xee, []byte{'A', 'd', 'o', 'b', 'e', 0, 100, 0, 0, 0, 0, transform})
}

// webpFile returns a RIFF WEBP container around the given chunks.
func webpFile(chunks ...[]byte) []byte {
	var body []byte
	for _, c := range chunks {
		body = append(body, c...)
	}
	b := append([]byte("RIFF"), binary.LittleEndian.AppendUint32(nil, uint32(4+len(body)))...)
	return append(append(b, "WEBP"...), body...)
}

// webpChunk returns a RIFF chunk (padded to an even length).
func webpChunk(fourCC string, data []byte) []byte {
	b := append([]byte(fourCC), binary.LittleEndian.AppendUint32(nil, uint32(len(data)))...)
	b = append(b, data...)
	if len(data)%2 == 1 {
		b = append(b, 0)
	}
	return b
}

// webpVP8 is a lossy key frame header announcing w×h.
func webpVP8(w, h int) []byte {
	return webpChunk("VP8 ", []byte{0x10, 0x02, 0x00, 0x9d, 0x01, 0x2a, byte(w), byte(w >> 8), byte(h), byte(h >> 8)})
}

// webpVP8L is a lossless image header announcing w×h.
func webpVP8L(w, h int) []byte {
	v := uint32(w-1) | uint32(h-1)<<14
	return webpChunk("VP8L", append([]byte{0x2f}, binary.LittleEndian.AppendUint32(nil, v)...))
}

// webpVP8X is an extended-format header announcing a w×h canvas.
func webpVP8X(w, h int, alpha bool) []byte {
	var flags byte
	if alpha {
		flags = 1 << 4
	}
	w, h = w-1, h-1
	return webpChunk("VP8X", []byte{flags, 0, 0, 0, byte(w), byte(w >> 8), byte(w >> 16), byte(h), byte(h >> 8), byte(h >> 16)})
}

// TestDecodeCost pins what the memory guard charges per pixel for each
// decoder and header (DESIGN §8.2): the color model DecodeConfig reports is
// not what several decoders allocate, and charging it let 95 KB uploads
// reach 750 MiB against the 256 MiB budget.
func TestDecodeCost(t *testing.T) {
	const big = 1 << 40 // no budget-dependent check
	gray, ycc, cmyk := []byte{1}, []byte{1, 2, 3}, []byte{1, 2, 3, 4}
	rgbIDs := []byte{'R', 'G', 'B'}
	s11, s111, s1111 := []byte{0x11}, []byte{0x11, 0x11, 0x11}, []byte{0x11, 0x11, 0x11, 0x11}
	trns := pngChunk("tRNS", []byte{0, 1}) // gray: the transparent sample value
	bigText := pngChunk("tEXt", append([]byte("Comment\x00"), bytes.Repeat([]byte{'x'}, 80<<10)...))
	plte := pngChunk("PLTE", []byte{0, 0, 0, 255, 255, 255})
	// junk between segments: image/jpeg skips it, the frame scan gives up.
	junkYCC := jpegHeaders(0xc0, 64, 64, ycc, s111, append(jpegSeg(0xe0, []byte("pad")), 0x00, 0x00))
	// a PNG whose chunk list breaks off after IHDR (absurd chunk length).
	brokenPNG := append(pngIHDR(64, 64, 16, 0, false), 0xff, 0xff, 0xff, 0xff, 't', 'E', 'X', 't')
	// an Adobe segment after the first scan still turns YCbCr into RGB.
	lateAdobe := append(append(jpegHeaders(0xc0, 64, 64, ycc, s111), 0x12, 0x34, 0x56), adobeAPP14(0)...)
	lateAdobe = append(lateAdobe, 0xff, 0xd9)

	for _, c := range []struct {
		name   string
		data   []byte
		budget int64
		per    int64 // bytes per pixel of area (×2: half bytes)
		area   int64 // 0: width × height
	}{
		// PNG: DecodeConfig stops at IHDR, tRNS turns gray into NRGBA(64).
		{"png gray8", pngFile(64, 64, 8, 0, false, nil), big, 2 * 1, 0},
		{"png gray8 tRNS", pngFile(64, 64, 8, 0, false, nil, trns), big, 2 * 4, 0},
		{"png gray1 tRNS", pngFile(64, 64, 1, 0, false, nil, trns), big, 2 * 4, 0},
		{"png gray16", pngFile(64, 64, 16, 0, false, nil), big, 2 * 2, 0},
		{"png gray16 tRNS", pngFile(64, 64, 16, 0, false, nil, trns), big, 2 * 8, 0},
		{"png rgb8 tRNS", pngFile(64, 64, 8, 2, false, nil, pngChunk("tRNS", []byte{0, 1, 0, 1, 0, 1})), big, 2 * 4, 0},
		{"png rgba8", pngFile(64, 64, 8, 6, false, nil), big, 2 * 4, 0},
		{"png rgba16", pngFile(64, 64, 16, 6, false, nil), big, 2 * 8, 0},
		{"png paletted", pngFile(64, 64, 8, 3, false, nil, plte, pngChunk("tRNS", []byte{0})), big, 2 * 1, 0},
		// Adam7: the passes are decoded next to the full image.
		{"png rgba8 interlaced", pngFile(64, 64, 8, 6, true, nil), big, 3 * 4, 0},
		{"png gray16 tRNS interlaced", pngFile(64, 64, 16, 0, true, nil, trns), big, 3 * 8, 0},
		// tRNS behind more than the 64 KiB head: found by re-reading.
		{"png tRNS behind 80 KiB tEXt", pngFile(64, 64, 16, 0, false, nil, bigText, trns), big, 2 * 8, 0},
		// No IDAT, or a chunk list that cannot be followed: worst case.
		{"png without IDAT", append(pngHeader(64, 64, 16, 0), pngChunk("IEND", nil)...), big, 3 * 8, 0},
		{"png broken chunk list", brokenPNG, big, 3 * 8, 0},

		// JPEG: planes (4:4:4 worst case) + RGBA/CMYK copy, + 4 per
		// component for a progressive frame, over the MCU-rounded area.
		{"jpeg gray", jpegHeaders(0xc0, 64, 64, gray, s11), big, 2 * 1, 0},
		{"jpeg ycbcr", jpegHeaders(0xc0, 64, 64, ycc, s111), big, 2 * 3, 0},
		{"jpeg rgb (ids)", jpegHeaders(0xc0, 64, 64, rgbIDs, s111), big, 2 * 7, 0},
		{"jpeg rgb (adobe)", jpegHeaders(0xc0, 64, 64, ycc, s111, adobeAPP14(0)), big, 2 * 7, 0},
		{"jpeg cmyk", jpegHeaders(0xc0, 64, 64, cmyk, s1111, adobeAPP14(0)), big, 2 * 8, 0},
		{"jpeg gray progressive", jpegHeaders(0xc2, 64, 64, gray, s11), big, 2 * 5, 0},
		{"jpeg ycbcr progressive", jpegHeaders(0xc2, 64, 64, ycc, s111), big, 2 * 15, 0},
		{"jpeg rgb progressive", jpegHeaders(0xc2, 64, 64, rgbIDs, s111), big, 2 * 19, 0},
		{"jpeg cmyk progressive", jpegHeaders(0xc2, 64, 64, cmyk, s1111), big, 2 * 24, 0},
		{"jpeg cmyk progressive behind 80 KiB APP1", withAPP1(jpegHeaders(0xc2, 64, 64, cmyk, s1111), 80<<10), big, 2 * 24, 0},
		// MCU rounding: 4:2:0 decodes whole 16×16 MCUs, gray 8×8 ones.
		{"jpeg ycbcr 4:2:0 rounded", jpegHeaders(0xc0, 100, 50, ycc, []byte{0x22, 0x11, 0x11}), big, 2 * 3, 112 * 64},
		{"jpeg gray rounded", jpegHeaders(0xc0, 10, 10, gray, []byte{0x22}), big, 2 * 1, 16 * 16},
		// An Adobe segment after the scan is looked for when it decides.
		{"jpeg late adobe, deciding", lateAdobe, 64 * 64 * 3, 2 * 7, 0},
		{"jpeg late adobe, not deciding", lateAdobe, big, 2 * 3, 0},
		{"jpeg no adobe, deciding", jpegHeaders(0xc0, 64, 64, ycc, s111), 64 * 64 * 3, 2 * 3, 0},
		// A frame header the scan cannot reach: progressive, 32×32 MCUs.
		{"jpeg junk before frame", junkYCC, big, 2 * 15, 0},

		// WebP: lossy 3, lossless (or VP8X, possibly lossless) 7, alpha 8.
		{"webp lossy", webpFile(webpVP8(64, 64)), big, 2 * 3, 0},
		{"webp lossless", webpFile(webpVP8L(64, 64)), big, 2 * 7, 0},
		{"webp vp8x", webpFile(webpVP8X(64, 64, false), webpVP8(64, 64)), big, 2 * 7, 0},
		{"webp vp8x alpha", webpFile(webpVP8X(64, 64, true)), big, 2 * 8, 0},

		// GIF and BMP: their color model.
		{"gif", encode(t, "gif", solid(64, 64, color.White)), big, 2 * 1, 0},
		{"bmp", encode(t, "bmp", solid(64, 64, color.White)), big, 2 * 4, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			cost, px := costOf(t, c.data, c.budget)
			area := c.area
			if area == 0 {
				area = px
			}
			if want := area * c.per / 2; cost != want {
				t.Fatalf("cost %d (%.1f bytes/px of %d px), want %d (%.1f)", cost, float64(cost)/float64(area), area, want, float64(c.per)/2)
			}
		})
	}
}

// TestDecodeCostRefusals pins the reported cases: 7000×7000 images whose
// color model alone fits the 256 MiB budget but whose decoder allocates
// 400–750 MiB are refused before anything is decoded, while an image that
// really fits is still accepted.
func TestDecodeCostRefusals(t *testing.T) {
	ycc, cmyk := []byte{1, 2, 3}, []byte{1, 2, 3, 4}
	s111, s1111 := []byte{0x11, 0x11, 0x11}, []byte{0x11, 0x11, 0x11, 0x11}
	trns := pngChunk("tRNS", []byte{0, 1})
	for name, data := range map[string][]byte{
		"png gray16 tRNS":            pngFile(7000, 7000, 16, 0, false, nil, trns),
		"png gray16 tRNS interlaced": pngFile(7000, 7000, 16, 0, true, nil, trns),
		"png rgba16 interlaced":      pngFile(5000, 5000, 16, 6, true, nil),
		"jpeg cmyk":                  jpegHeaders(0xc0, 7000, 7000, cmyk, s1111, adobeAPP14(2)),
		"jpeg adobe rgb":             jpegHeaders(0xc0, 7000, 7000, ycc, s111, adobeAPP14(0)),
		"webp alpha":                 webpFile(webpVP8X(7000, 7000, true)),
		"webp lossless":              webpFile(webpVP8L(7000, 7000)),
	} {
		if _, err := gen(t, data, Options{}); !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: %v, want ErrTooLarge", name, err)
		}
	}
	// Their plain counterparts fit (checked on the estimate alone: decoding
	// them would allocate the ~100–200 MB the budget allows).
	for name, data := range map[string][]byte{
		"png gray16":     pngFile(7000, 7000, 16, 0, false, nil),
		"png rgba16":     pngFile(5000, 5000, 16, 6, false, nil),
		"jpeg ycbcr":     jpegHeaders(0xc0, 7000, 7000, ycc, s111),
		"webp lossy":     webpFile(webpVP8(7000, 7000)),
		"webp alpha 25M": webpFile(webpVP8X(5000, 5000, true)),
	} {
		if cost, _ := costOf(t, data, MaxDecodedBytes); cost > MaxDecodedBytes {
			t.Errorf("%s: charged %d, over the %d budget", name, cost, MaxDecodedBytes)
		}
	}
}

// TestPNGTransparentGrayBudget decodes real gray PNGs with a tRNS chunk:
// image/png turns them into NRGBA64 (8 bytes/px), and Adam7 adds its passes
// on top, which is what the guard charges.
func TestPNGTransparentGrayBudget(t *testing.T) {
	px := int64(16 * 16)
	trns := pngChunk("tRNS", []byte{0, 0}) // the (all-zero) pixels are transparent
	flat := pngFile(16, 16, 16, 0, false, pngZeroPixels(t, 16, 16, 2, false), trns)
	adam7 := pngFile(16, 16, 16, 0, true, pngZeroPixels(t, 16, 16, 2, true), trns)

	// The premise: the decoder does not return the Gray16 DecodeConfig
	// announces.
	for name, data := range map[string][]byte{"flat": flat, "adam7": adam7} {
		img, err := png.Decode(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, ok := img.(*image.NRGBA64); !ok {
			t.Fatalf("%s: decoded as %T, the guard charges NRGBA64", name, img)
		}
	}

	for _, c := range []struct {
		name   string
		data   []byte
		budget int64
		ok     bool
	}{
		{"flat on Gray16's 2 bytes/px", flat, 2 * px, false},
		{"flat on 8 bytes/px", flat, 8 * px, true},
		{"adam7 on 8 bytes/px", adam7, 8 * px, false},
		{"adam7 on 12 bytes/px", adam7, 12 * px, true},
	} {
		th, err := gen(t, c.data, Options{MaxDecodedBytes: c.budget})
		if !c.ok {
			if !errors.Is(err, ErrTooLarge) {
				t.Errorf("%s: %v, want ErrTooLarge", c.name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if th.MIME != MIMEPNG { // transparent
			t.Errorf("%s: MIME %s", c.name, th.MIME)
		}
		decodeThumb(t, th)
	}
}
