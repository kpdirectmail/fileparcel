// Package qr renders QR codes from a boombuler/barcode/qr matrix as SVG, as
// an SVG data URI (for <img src> and API responses such as
// TOTPEnrollment.QRDataURI) and as terminal half-block text for the CLI and
// installer (DESIGN §1). It is a leaf utility importable by any package.
//
// Owned by unit G. The API below is used by units B (TOTP QR), E (share QR),
// G (/qr.svg) and I (terminal QR); keep it stable.
package qr

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"strings"

	bqr "github.com/boombuler/barcode/qr"
)

// MaxLen is the longest input accepted (bytes), matching GET /qr.svg?data=<≤512 chars>.
const MaxLen = 512

// QuietZone is the white border in modules on every side (the spec minimum is 4).
const QuietZone = 4

// Errors.
var (
	ErrEmpty   = errors.New("qr: empty input")
	ErrTooLong = fmt.Errorf("qr: input longer than %d bytes", MaxLen)
)

// Options tunes SVG rendering.
type Options struct {
	// Title is an accessible <title> for the SVG (escaped; optional).
	Title string
}

// Code is an encoded QR matrix (error correction level M, automatic mode).
type Code struct {
	// Size is the number of modules per side (21 for version 1, +4 per version),
	// without the quiet zone.
	Size int
	dark []bool
}

// Encode encodes data (1..MaxLen bytes).
func Encode(data string) (*Code, error) {
	switch {
	case data == "":
		return nil, ErrEmpty
	case len(data) > MaxLen:
		return nil, ErrTooLong
	}
	bc, err := bqr.Encode(data, bqr.M, bqr.Auto)
	if err != nil {
		return nil, fmt.Errorf("qr: %w", err)
	}
	b := bc.Bounds()
	n := b.Dx()
	c := &Code{Size: n, dark: make([]bool, n*n)}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			r, _, _, _ := bc.At(b.Min.X+x, b.Min.Y+y).RGBA()
			c.dark[y*n+x] = r < 0x8000
		}
	}
	return c, nil
}

// Dark reports whether module (x, y) is dark; coordinates outside the matrix
// (including the quiet zone) are light.
func (c *Code) Dark(x, y int) bool {
	if c == nil || x < 0 || y < 0 || x >= c.Size || y >= c.Size {
		return false
	}
	return c.dark[y*c.Size+x]
}

// SVG renders the code as a standalone, scalable SVG (one <path>, quiet zone
// included, crisp edges). It contains no scripts or external references, so
// it is safe to serve as image/svg+xml under the app CSP.
func (c *Code) SVG(o Options) []byte {
	n := c.Size + 2*QuietZone
	var b bytes.Buffer
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" shape-rendering="crispEdges" role="img"`, n, n, n*8, n*8)
	if o.Title != "" {
		b.WriteString(` aria-label="` + html.EscapeString(o.Title) + `"`)
	}
	b.WriteString(">")
	if o.Title != "" {
		b.WriteString("<title>" + html.EscapeString(o.Title) + "</title>")
	}
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n)
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if !c.Dark(x, y) {
				continue
			}
			// merge horizontal runs into one rectangle
			run := 1
			for c.Dark(x+run, y) {
				run++
			}
			fmt.Fprintf(&b, "M%d %dh%dv1h-%dz", x+QuietZone, y+QuietZone, run, run)
			x += run - 1
		}
	}
	b.WriteString(`"/></svg>`)
	return b.Bytes()
}

// SVG encodes data and renders it as SVG.
func SVG(data string, o Options) ([]byte, error) {
	c, err := Encode(data)
	if err != nil {
		return nil, err
	}
	return c.SVG(o), nil
}

// DataURI encodes data as "data:image/svg+xml;base64,…" for <img src>.
func DataURI(data string) (string, error) {
	svg, err := SVG(data, Options{})
	if err != nil {
		return "", err
	}
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(svg), nil
}

// Terminal renders the code with Unicode half blocks (two module rows per
// text line), quiet zone included, each line ending in "\n". The default
// draws dark modules as spaces on a light block background, which scans on
// dark terminals; invert=true swaps them for light-background terminals.
func Terminal(data string, invert bool) (string, error) {
	c, err := Encode(data)
	if err != nil {
		return "", err
	}
	// light(x,y): module should be drawn as "ink" of the foreground glyph.
	light := func(x, y int) bool {
		d := c.Dark(x, y)
		if invert {
			return d
		}
		return !d
	}
	var b strings.Builder
	lo, hi := -QuietZone, c.Size+QuietZone
	for y := lo; y < hi; y += 2 {
		for x := lo; x < hi; x++ {
			top, bottom := light(x, y), y+1 < hi && light(x, y+1)
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteByte(' ')
			}
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}
