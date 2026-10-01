// Package thumbs generates image thumbnails (DESIGN §8.2, §18.20): JPEG
// (quality 80), or PNG when the image has transparency, at most 320 px on the
// longest side, scaled with draw.CatmullRom.
//
// Decoding is bounded: the dimensions are read with image.DecodeConfig first
// and images above MaxPixels (50 MP), or for which their decoder would
// allocate more than MaxDecodedBytes (decodeCost), are refused before any
// pixel buffer is allocated.
// Supported inputs are JPEG, PNG, GIF (first frame), WebP and BMP. JPEG EXIF
// orientation is applied so phone photos are upright.
//
// The package is pure image processing: the caller (files, job
// thumbs.generate) reads the source blob, stores the returned bytes as an
// encrypted blob and records it in nodes.thumb_blob_id.
//
// Owned by unit D. Importable by files only.
package thumbs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"

	"golang.org/x/image/bmp"
	"golang.org/x/image/draw"
	"golang.org/x/image/webp"
)

// Limits and output parameters.
const (
	// MaxSize is the longest side of a thumbnail in pixels.
	MaxSize = 320
	// MaxPixels bounds the source image (width × height).
	MaxPixels = 50_000_000
	// MaxDecodedBytes bounds the memory the decoder allocates for the source
	// image: what decodeCost charges for its format, dimensions and headers,
	// not just width × height × its color model. Scaling adds a fixed
	// temporary on top that is not charged to the image: draw.CatmullRom
	// keeps 32 bytes per pixel of the image scaled in width only (thumbnail
	// width × source height), at most 320 × 7071 × 32 bytes (about 72 MB)
	// under MaxPixels.
	MaxDecodedBytes = 256 << 20
	// MaxSourceBytes bounds the encoded source file.
	MaxSourceBytes = 256 << 20
	// JPEGQuality is the JPEG encoder quality.
	JPEGQuality = 80
)

// Output types.
const (
	MIMEJPEG = "image/jpeg"
	MIMEPNG  = "image/png"
)

// Errors. Both mean "no thumbnail for this file" and are not worth retrying.
var (
	// ErrUnsupported: the type is not a supported image or the data is not decodable.
	ErrUnsupported = errors.New("thumbs: unsupported or undecodable image")
	// ErrTooLarge: the image exceeds MaxPixels, MaxDecodedBytes or MaxSourceBytes.
	ErrTooLarge = errors.New("thumbs: image too large")
)

// supported maps the stored MIME types to image.Decode format names.
var supported = map[string]string{
	"image/jpeg": "jpeg",
	"image/png":  "png",
	"image/gif":  "gif",
	"image/webp": "webp",
	"image/bmp":  "bmp",
}

// Supported reports whether a thumbnail can be generated for mime (a stored
// node MIME type, parameters ignored).
func Supported(mime string) bool {
	_, ok := supported[baseType(mime)]
	return ok
}

// Thumb is a generated thumbnail.
type Thumb struct {
	Data          []byte
	MIME          string // MIMEJPEG or MIMEPNG
	Width, Height int
}

// Options overrides the limits (zero values use the package constants).
type Options struct {
	MaxSize         int
	MaxPixels       int64
	MaxDecodedBytes int64
}

func (o Options) withDefaults() Options {
	if o.MaxSize <= 0 {
		o.MaxSize = MaxSize
	}
	if o.MaxPixels <= 0 {
		o.MaxPixels = MaxPixels
	}
	if o.MaxDecodedBytes <= 0 {
		o.MaxDecodedBytes = MaxDecodedBytes
	}
	return o
}

// decoders are called directly (not through image.Decode) so that only the
// formats listed here are ever parsed, whatever other packages register.
type decoder struct {
	config func(io.Reader) (image.Config, error)
	decode func(io.Reader) (image.Image, error)
}

var decoders = map[string]decoder{
	"jpeg": {jpeg.DecodeConfig, jpeg.Decode},
	"png":  {png.DecodeConfig, png.Decode},
	"gif":  {gif.DecodeConfig, gif.Decode},
	"webp": {webp.DecodeConfig, webp.Decode},
	"bmp":  {bmp.DecodeConfig, bmp.Decode},
}

// magic identifies the format from the leading bytes (the stored MIME type
// may be wrong; the content decides which decoder runs).
func magic(head []byte) string {
	switch {
	case bytes.HasPrefix(head, []byte("\xff\xd8\xff")):
		return "jpeg"
	case bytes.HasPrefix(head, []byte("\x89PNG\r\n\x1a\n")):
		return "png"
	case bytes.HasPrefix(head, []byte("GIF87a")), bytes.HasPrefix(head, []byte("GIF89a")):
		return "gif"
	case len(head) >= 12 && bytes.Equal(head[0:4], []byte("RIFF")) && bytes.Equal(head[8:12], []byte("WEBP")):
		return "webp"
	case bytes.HasPrefix(head, []byte("BM")):
		return "bmp"
	}
	return ""
}

// Generate decodes the image read from r (size bytes; the reader is rewound
// between the header check and the decode) and returns its thumbnail.
// Images already within MaxSize are re-encoded at their own size (never
// upscaled). ctx is checked between the steps (decoding itself cannot be
// interrupted, but it is bounded by the limits).
func Generate(ctx context.Context, r io.ReadSeeker, size int64, o Options) (*Thumb, error) {
	o = o.withDefaults()
	if size > MaxSourceBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, size)
	}
	if size <= 0 {
		return nil, ErrUnsupported
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	head := make([]byte, 64<<10)
	n, err := io.ReadFull(r, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	head = head[:n]
	format := magic(head)
	dec, ok := decoders[format]
	if !ok {
		return nil, ErrUnsupported
	}

	// Bounded header check.
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	cfg, err := dec.config(bufio.NewReader(r))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	if err := checkConfig(cfg, o); err != nil {
		return nil, err
	}
	if need := decodeCost(format, cfg, head, r, o.MaxDecodedBytes); need > o.MaxDecodedBytes {
		return nil, fmt.Errorf("%w: %dx%d pixels need too much memory", ErrTooLarge, cfg.Width, cfg.Height)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	img, err := dec.decode(bufio.NewReader(io.LimitReader(r, MaxSourceBytes)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	if b := img.Bounds(); b.Empty() || int64(b.Dx())*int64(b.Dy()) > int64(cfg.Width)*int64(cfg.Height) {
		return nil, ErrUnsupported // never trust more than DecodeConfig announced
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	orient := 1
	if format == "jpeg" {
		orient = exifOrientation(head)
	}
	return render(img, orient, o.MaxSize)
}

// checkConfig applies the pixel limits to the announced header (which also
// bounds the dimensions decodeCost multiplies).
func checkConfig(cfg image.Config, o Options) error {
	w, h := int64(cfg.Width), int64(cfg.Height)
	if w <= 0 || h <= 0 {
		return ErrUnsupported
	}
	if w*h > o.MaxPixels || w > 1<<20 || h > 1<<20 {
		return fmt.Errorf("%w: %dx%d pixels", ErrTooLarge, w, h)
	}
	return nil
}

// decodeCost returns how many bytes the decoder of format allocates for the
// image cfg announces (DESIGN §8.2, §18.20: the budget is per decoder). The
// color model DecodeConfig reports describes the finished image, not what
// the decoder builds on the way there, and some decoders choose the result
// from data DecodeConfig never reads — so the headers are consulted too.
// Where they cannot be read, the worst case is charged: the guard must not
// under-count what it cannot see. r is re-read from the start when the
// headers lie beyond head and left anywhere (every caller seeks before
// using it again); budget is the limit the caller applies and only decides
// whether a whole-file check is worth making.
func decodeCost(format string, cfg image.Config, head []byte, r io.ReadSeeker, budget int64) int64 {
	px := int64(cfg.Width) * int64(cfg.Height)
	switch format {
	case "jpeg":
		return jpegCost(cfg, head, r, budget)
	case "png":
		return pngCost(cfg, head, r)
	case "webp":
		return px * webpBytesPerPixel(cfg.ColorModel, head)
	}
	return px * bytesPerPixel(cfg.ColorModel) // GIF (paletted first frame), BMP
}

// jpegCost charges what image/jpeg allocates. It decodes whole MCUs (8 × the
// largest sampling factor, up to 32 × 32 px), so its planes cover the image
// rounded up to the MCU size; per pixel of that area it keeps:
//   - one byte per component (the Y/Cb/Cr planes, 4:4:4 as the worst case,
//     and the black plane of a 4-component image);
//   - a 4-byte RGBA (Adobe RGB) or CMYK copy when the frame is neither gray
//     nor YCbCr;
//   - for a progressive frame, the coefficients of the whole image — one
//     int32 per pixel and component — which are still held when the planes
//     and the copy are built.
//
// That makes gray 1, YCbCr 3, RGB 7 and CMYK 8 bytes/px, progressive 5, 15,
// 19 and 24. Budgeting a progressive frame at the 3 bytes/px of its color
// model let a 1.2 MB 7000×7000 progressive JPEG allocate 430 MiB.
func jpegCost(cfg image.Config, head []byte, r io.ReadSeeker, budget int64) int64 {
	f := readJPEGFrame(head, r)
	area := roundUp(int64(cfg.Width), f.mcuW) * roundUp(int64(cfg.Height), f.mcuH)
	comps, conv := int64(3), int64(0)
	switch cfg.ColorModel {
	case color.GrayModel:
		comps = 1
	case color.YCbCrModel:
	case color.RGBAModel: // Adobe RGB: converted to an RGBA copy
		conv = 4
	default: // CMYK or YCbCrK: three planes, the black plane and a 4-byte copy
		comps, conv = 4, 4
	}
	per := comps + conv
	if f.progressive {
		per += 4 * comps
	}
	// DecodeConfig stops at the first scan, but image/jpeg honours an Adobe
	// APP14 segment wherever it appears: one after the scan still turns a
	// YCbCr frame into RGB and adds the RGBA copy. Only looked for when that
	// copy decides the outcome.
	if cfg.ColorModel == color.YCbCrModel && area*per <= budget && area*(per+4) > budget && adobeSegment(r) {
		per += 4
	}
	return area * per
}

// jpegFrame is what the memory guard needs from a JPEG frame header.
type jpegFrame struct {
	progressive bool
	mcuW, mcuH  int64 // MCU size in pixels
}

// worstJPEGFrame is charged for a JPEG whose frame header cannot be read.
var worstJPEGFrame = jpegFrame{progressive: true, mcuW: 32, mcuH: 32}

// readJPEGFrame reads the start-of-frame header. head is the 64 KiB already
// read; r is used only when the frame header sits behind more metadata than
// that (a large ICC profile or EXIF preview), in which case it is re-read
// from the start and left where the scan stopped. A header that cannot be
// found at all yields worstJPEGFrame.
func readJPEGFrame(head []byte, r io.ReadSeeker) jpegFrame {
	if f, ok := scanJPEGFrame(bufio.NewReader(bytes.NewReader(head))); ok {
		return f
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return worstJPEGFrame
	}
	if f, ok := scanJPEGFrame(bufio.NewReader(io.LimitReader(r, MaxSourceBytes))); ok {
		return f
	}
	return worstJPEGFrame
}

// scanJPEGFrame walks the JPEG marker segments up to the start-of-frame
// marker and reads that frame's header: whether it is progressive
// (SOF2/SOF6/SOF10/SOF14) and its MCU size. ok is false when the data ends
// (or stops making sense) before the frame header.
func scanJPEGFrame(br *bufio.Reader) (f jpegFrame, ok bool) {
	var soi [2]byte
	if _, err := io.ReadFull(br, soi[:]); err != nil || soi[0] != 0xff || soi[1] != 0xd8 {
		return f, false
	}
	for {
		c, err := br.ReadByte()
		if err != nil || c != 0xff {
			return f, false
		}
		var m byte
		for { // any number of 0xff fill bytes may precede the marker
			if m, err = br.ReadByte(); err != nil {
				return f, false
			}
			if m != 0xff {
				break
			}
		}
		switch {
		case m == 0x01, m >= 0xd0 && m <= 0xd9:
			continue // standalone markers: no payload
		case m == 0xda, m == 0x00:
			return f, false // entropy-coded data before any frame header
		}
		var lb [2]byte
		if _, err := io.ReadFull(br, lb[:]); err != nil {
			return f, false
		}
		n := int(lb[0])<<8 | int(lb[1])
		if n < 2 {
			return f, false
		}
		if !isSOF(m) {
			if _, err := br.Discard(n - 2); err != nil {
				return f, false
			}
			continue
		}
		// Precision, height, width, component count, then an
		// (id, sampling factors, table) triple per component.
		p := make([]byte, n-2)
		if _, err := io.ReadFull(br, p); err != nil || len(p) < 6 {
			return f, false
		}
		nc := int(p[5])
		if nc < 1 || len(p) < 6+3*nc {
			return f, false
		}
		f = jpegFrame{progressive: m == 0xc2 || m == 0xc6 || m == 0xca || m == 0xce, mcuW: 8, mcuH: 8}
		if nc > 1 { // image/jpeg takes a single component as 1×1 whatever it says
			for i := range nc {
				hv := p[7+3*i]
				f.mcuW = max(f.mcuW, 8*int64(hv>>4))
				f.mcuH = max(f.mcuH, 8*int64(hv&0x0f))
			}
		}
		return f, true
	}
}

// adobeSegment reports whether the JPEG read from r (from the start, up to
// MaxSourceBytes) contains an Adobe APP14 segment anywhere: the bytes
// FF EE, two length bytes and "Adobe". A read error counts as a yes.
func adobeSegment(r io.ReadSeeker) bool {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return true
	}
	lr := io.LimitReader(r, MaxSourceBytes)
	buf := make([]byte, 64<<10)
	kept := 0
	for {
		n, err := io.ReadFull(lr, buf[kept:])
		b := buf[:kept+n]
		for i := 0; ; {
			j := bytes.Index(b[i:], []byte("Adobe"))
			if j < 0 {
				break
			}
			if k := i + j; k >= 4 && b[k-4] == 0xff && b[k-3] == 0xee {
				return true
			}
			i += j + 1
		}
		if err != nil {
			return !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF)
		}
		kept = copy(buf, b[len(b)-8:]) // a match may straddle two reads
	}
}

func roundUp(v, m int64) int64 { return (v + m - 1) / m * m }

// pngCost charges what image/png allocates. DecodeConfig stops at IHDR, so
// it reports a gray image as Gray or Gray16 even when a tRNS chunk makes the
// decoder build NRGBA (4 bytes/px) or NRGBA64 (8) instead; and an
// interlaced (Adam7) image is decoded pass by pass next to the full image,
// the largest pass being half of it: 1.5 times the full image.
func pngCost(cfg image.Config, head []byte, r io.ReadSeeker) int64 {
	per := bytesPerPixel(cfg.ColorModel)
	interlaced, trns := readPNGChunks(head, r)
	if trns {
		switch cfg.ColorModel {
		case color.GrayModel:
			per = 4
		case color.Gray16Model:
			per = 8
		}
	}
	need := int64(cfg.Width) * int64(cfg.Height) * per
	if interlaced {
		need += need / 2
	}
	return need
}

// readPNGChunks reports whether the PNG is interlaced and whether a tRNS
// chunk precedes its pixel data, from head or, when the first IDAT lies
// beyond it (large iCCP or text chunks), by re-reading r from the start.
// A chunk list that cannot be followed is charged the worst case (both).
func readPNGChunks(head []byte, r io.ReadSeeker) (interlaced, trns bool) {
	if il, t, ok := scanPNGChunks(bufio.NewReader(bytes.NewReader(head))); ok {
		return il, t
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return true, true
	}
	if il, t, ok := scanPNGChunks(bufio.NewReader(io.LimitReader(r, MaxSourceBytes))); ok {
		return il, t
	}
	return true, true
}

// scanPNGChunks walks the PNG chunks up to the first IDAT, the way
// image/png reads them (length, type, data, CRC). ok is false when the data
// ends (or stops making sense) before an IDAT that follows the IHDR.
func scanPNGChunks(br *bufio.Reader) (interlaced, trns, ok bool) {
	if _, err := br.Discard(8); err != nil { // signature
		return false, false, false
	}
	ihdr := false
	var hdr [8]byte
	for {
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return false, false, false
		}
		n := binary.BigEndian.Uint32(hdr[:4])
		if n > 0x7fffffff {
			return false, false, false
		}
		switch string(hdr[4:8]) {
		case "IDAT":
			return interlaced, trns, ihdr
		case "IHDR":
			var p [13]byte // width, height, depth, color type, compression, filter, interlace
			if n != uint32(len(p)) {
				return false, false, false
			}
			if _, err := io.ReadFull(br, p[:]); err != nil {
				return false, false, false
			}
			ihdr, interlaced, n = true, p[12] != 0, 0
		case "tRNS":
			trns = true
		}
		if _, err := br.Discard(int(n)); err != nil {
			return false, false, false
		}
		if _, err := br.Discard(4); err != nil { // CRC
			return false, false, false
		}
	}
}

// webpBytesPerPixel charges what x/image/webp allocates per pixel:
//   - a lossy frame (VP8) is 4:2:0 YCbCr, 1.5 bytes/px, charged as its
//     model's 3;
//   - a lossless one (VP8L) ends as NRGBA, but with a color-indexing
//     transform the packed image (up to 2 bytes/px) and the transform tiles
//     are still held when the 4-byte result is allocated: 7;
//   - an alpha channel is itself decoded as a lossless image (the 7 above),
//     reduced to a one-byte plane while that image is still held, and the
//     plane is kept while the frame is decoded: 8.
//
// An extended file (VP8X) without alpha is reported as YCbCr before its
// frame is seen, and that frame may be lossless: only a file that starts
// with its lossy frame is charged 3.
func webpBytesPerPixel(m color.Model, head []byte) int64 {
	switch {
	case m == color.NYCbCrAModel:
		return 8
	case m == color.YCbCrModel && len(head) >= 16 && string(head[12:16]) == "VP8 ":
		return 3
	}
	return 7
}

// isSOF reports whether m is a start-of-frame marker (0xc4 is DHT, 0xc8 is
// reserved and 0xcc is DAC).
func isSOF(m byte) bool { return m >= 0xc0 && m <= 0xcf && m != 0xc4 && m != 0xc8 && m != 0xcc }

// bytesPerPixel estimates the decoded size per pixel of a color model
// (worst case for YCbCr, whose subsampling is unknown before decoding).
func bytesPerPixel(m color.Model) int64 {
	if _, ok := m.(color.Palette); ok {
		return 1
	}
	switch m {
	case color.GrayModel, color.AlphaModel:
		return 1
	case color.Gray16Model, color.Alpha16Model:
		return 2
	case color.YCbCrModel:
		return 3
	case color.RGBA64Model, color.NRGBA64Model:
		return 8
	}
	return 4 // RGBA, NRGBA, CMYK, NYCbCrA and anything else
}

// render scales img to fit maxSize × maxSize, applies the EXIF orientation
// and encodes the result.
func render(img image.Image, orient, maxSize int) (*Thumb, error) {
	sb := img.Bounds()
	w, h := fit(sb.Dx(), sb.Dy(), maxSize)
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.CatmullRom.Scale(dst, dst.Bounds(), img, sb, draw.Src, nil)
	out := orientate(dst, orient)

	var buf bytes.Buffer
	t := &Thumb{Width: out.Bounds().Dx(), Height: out.Bounds().Dy()}
	if out.Opaque() {
		if err := jpeg.Encode(&buf, out, &jpeg.Options{Quality: JPEGQuality}); err != nil {
			return nil, err
		}
		t.MIME = MIMEJPEG
	} else {
		enc := png.Encoder{CompressionLevel: png.BestSpeed}
		if err := enc.Encode(&buf, out); err != nil {
			return nil, err
		}
		t.MIME = MIMEPNG
	}
	t.Data = buf.Bytes()
	return t, nil
}

// fit returns the size of a w × h image scaled to fit max × max (never
// upscaled; at least 1 × 1).
func fit(w, h, max int) (int, int) {
	if w <= max && h <= max {
		return w, h
	}
	if w >= h {
		nh := int((int64(h)*int64(max) + int64(w)/2) / int64(w))
		return max, clampMin1(nh)
	}
	nw := int((int64(w)*int64(max) + int64(h)/2) / int64(h))
	return clampMin1(nw), max
}

func clampMin1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// orientate applies EXIF orientation o (1–8) to src.
func orientate(src *image.RGBA, o int) *image.RGBA {
	if o < 2 || o > 8 {
		return src
	}
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	dw, dh := w, h
	if o >= 5 {
		dw, dh = h, w
	}
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var dx, dy int
			switch o {
			case 2: // mirror horizontal
				dx, dy = w-1-x, y
			case 3: // rotate 180
				dx, dy = w-1-x, h-1-y
			case 4: // mirror vertical
				dx, dy = x, h-1-y
			case 5: // transpose
				dx, dy = y, x
			case 6: // rotate 90 CW
				dx, dy = h-1-y, x
			case 7: // transverse
				dx, dy = h-1-y, w-1-x
			case 8: // rotate 270 CW
				dx, dy = y, w-1-x
			}
			si := src.PixOffset(x+b.Min.X, y+b.Min.Y)
			di := dst.PixOffset(dx, dy)
			copy(dst.Pix[di:di+4], src.Pix[si:si+4])
		}
	}
	return dst
}

// exifOrientation returns the EXIF orientation (1–8) found in the APP1
// segment of a JPEG's leading bytes, or 1.
func exifOrientation(b []byte) int {
	if len(b) < 4 || b[0] != 0xff || b[1] != 0xd8 {
		return 1
	}
	i := 2
	for i+4 <= len(b) {
		if b[i] != 0xff {
			return 1
		}
		marker := b[i+1]
		if marker == 0xd8 || (marker >= 0xd0 && marker <= 0xd7) || marker == 0x01 {
			i += 2
			continue
		}
		if marker == 0xda || marker == 0xd9 { // start of scan / end of image
			return 1
		}
		segLen := int(b[i+2])<<8 | int(b[i+3])
		if segLen < 2 || i+2+segLen > len(b) {
			return 1
		}
		seg := b[i+4 : i+2+segLen]
		if marker == 0xe1 && len(seg) >= 6 && string(seg[:6]) == "Exif\x00\x00" {
			return tiffOrientation(seg[6:])
		}
		i += 2 + segLen
	}
	return 1
}

// tiffOrientation reads tag 0x0112 of IFD0 of a TIFF structure.
func tiffOrientation(t []byte) int {
	if len(t) < 8 {
		return 1
	}
	var u16 func([]byte) int
	var u32 func([]byte) int
	switch string(t[:2]) {
	case "II":
		u16 = func(p []byte) int { return int(p[0]) | int(p[1])<<8 }
		u32 = func(p []byte) int { return int(p[0]) | int(p[1])<<8 | int(p[2])<<16 | int(p[3])<<24 }
	case "MM":
		u16 = func(p []byte) int { return int(p[0])<<8 | int(p[1]) }
		u32 = func(p []byte) int { return int(p[0])<<24 | int(p[1])<<16 | int(p[2])<<8 | int(p[3]) }
	default:
		return 1
	}
	if u16(t[2:4]) != 42 {
		return 1
	}
	off := u32(t[4:8])
	if off < 8 || off+2 > len(t) {
		return 1
	}
	count := u16(t[off : off+2])
	for k := 0; k < count; k++ {
		e := off + 2 + 12*k
		if e+12 > len(t) {
			return 1
		}
		if u16(t[e:e+2]) == 0x0112 {
			if typ := u16(t[e+2 : e+4]); typ != 3 { // SHORT
				return 1
			}
			if v := u16(t[e+8 : e+10]); v >= 1 && v <= 8 {
				return v
			}
			return 1
		}
	}
	return 1
}

func baseType(m string) string {
	for i := 0; i < len(m); i++ {
		if m[i] == ';' || m[i] == ' ' {
			m = m[:i]
			break
		}
	}
	b := []byte(m)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
