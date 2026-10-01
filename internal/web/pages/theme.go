package pages

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Theme generation for /theme.css (DESIGN §13.4): ui.accent_color is a
// validated "#rgb"/"#rrggbb" colour. The light-mode primary is the colour
// itself; the dark-mode variant keeps its hue in OKLCH and raises the
// lightness (reducing chroma until it fits sRGB) so it stays readable on the
// dark surfaces. The text colour on primary buttons is chosen per variant by
// WCAG contrast.

// RGB is an 8-bit sRGB colour.
type RGB struct{ R, G, B uint8 }

// ParseHexColor parses "#rgb" or "#rrggbb" (case-insensitive).
func ParseHexColor(s string) (RGB, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "#") {
		return RGB{}, fmt.Errorf("colour %q: must start with #", s)
	}
	h := s[1:]
	switch len(h) {
	case 3:
		h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
	case 6:
	default:
		return RGB{}, fmt.Errorf("colour %q: must be #rgb or #rrggbb", s)
	}
	v, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return RGB{}, fmt.Errorf("colour %q: not hexadecimal", s)
	}
	return RGB{uint8(v >> 16), uint8(v >> 8), uint8(v)}, nil
}

// Hex returns "#rrggbb".
func (c RGB) Hex() string { return fmt.Sprintf("#%02x%02x%02x", c.R, c.G, c.B) }

func srgbToLinear(c float64) float64 {
	if c <= 0.04045 {
		return c / 12.92
	}
	return math.Pow((c+0.055)/1.055, 2.4)
}

func linearToSRGB(c float64) float64 {
	if c <= 0.0031308 {
		return 12.92 * c
	}
	return 1.055*math.Pow(c, 1/2.4) - 0.055
}

// oklab converts sRGB to OKLab (L in 0..1).
func (c RGB) oklab() (L, a, b float64) {
	r := srgbToLinear(float64(c.R) / 255)
	g := srgbToLinear(float64(c.G) / 255)
	bl := srgbToLinear(float64(c.B) / 255)
	l := math.Cbrt(0.4122214708*r + 0.5363325363*g + 0.0514459929*bl)
	m := math.Cbrt(0.2119034982*r + 0.6806995451*g + 0.1073969566*bl)
	s := math.Cbrt(0.0883024619*r + 0.2817188376*g + 0.6299787005*bl)
	return 0.2104542553*l + 0.7936177850*m - 0.0040720468*s,
		1.9779984951*l - 2.4285922050*m + 0.4505937099*s,
		0.0259040371*l + 0.7827717662*m - 0.8086757660*s
}

// fromOKLab converts OKLab to linear-light sRGB components (may be out of gamut).
func fromOKLab(L, a, b float64) (r, g, bl float64) {
	l := L + 0.3963377774*a + 0.2158037573*b
	m := L - 0.1055613458*a - 0.0638541728*b
	s := L - 0.0894841775*a - 1.2914855480*b
	l, m, s = l*l*l, m*m*m, s*s*s
	return 4.0767416621*l - 3.3077115913*m + 0.2309699292*s,
		-1.2684380046*l + 2.6097574011*m - 0.3413193965*s,
		-0.0041960863*l - 0.7034186147*m + 1.7076147010*s
}

func inGamut(r, g, b float64) bool {
	const eps = 1e-4
	return r >= -eps && r <= 1+eps && g >= -eps && g <= 1+eps && b >= -eps && b <= 1+eps
}

func to8(c float64) uint8 {
	v := math.Round(linearToSRGB(math.Min(1, math.Max(0, c))) * 255)
	return uint8(math.Min(255, math.Max(0, v)))
}

// fromOKLCH converts OKLCH to sRGB, reducing chroma (binary search) until
// the colour is inside the sRGB gamut.
func fromOKLCH(L, C, h float64) RGB {
	L = math.Min(1, math.Max(0, L))
	conv := func(c float64) (float64, float64, float64) {
		return fromOKLab(L, c*math.Cos(h), c*math.Sin(h))
	}
	if r, g, b := conv(C); inGamut(r, g, b) {
		return RGB{to8(r), to8(g), to8(b)}
	}
	lo, hi := 0.0, C
	for range 24 {
		mid := (lo + hi) / 2
		if r, g, b := conv(mid); inGamut(r, g, b) {
			lo = mid
		} else {
			hi = mid
		}
	}
	r, g, b := conv(lo)
	return RGB{to8(r), to8(g), to8(b)}
}

// relLuminance is the WCAG relative luminance.
func (c RGB) relLuminance() float64 {
	return 0.2126*srgbToLinear(float64(c.R)/255) + 0.7152*srgbToLinear(float64(c.G)/255) +
		0.0722*srgbToLinear(float64(c.B)/255)
}

// Contrast returns the WCAG contrast ratio of two colours (1..21).
func Contrast(a, b RGB) float64 {
	la, lb := a.relLuminance(), b.relLuminance()
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// Text colours used on primary surfaces.
var (
	onLight = RGB{0xff, 0xff, 0xff} // white text
	onDark  = RGB{0x0b, 0x12, 0x20} // near-black text
)

// OnColor returns the text colour (white or near-black) with the higher
// contrast on bg.
func OnColor(bg RGB) RGB {
	if Contrast(bg, onLight) >= Contrast(bg, onDark) {
		return onLight
	}
	return onDark
}

// DarkVariant returns the dark-mode companion of c: same OKLCH hue,
// lightness raised to at least 0.72, gamut-mapped.
func DarkVariant(c RGB) RGB {
	L, a, b := c.oklab()
	C := math.Hypot(a, b)
	h := math.Atan2(b, a)
	if L < 0.72 {
		L = 0.72
	}
	return fromOKLCH(L, C, h)
}

// ThemeCSS returns the /theme.css body for accent (a valid #rgb/#rrggbb
// colour): the brand and primary custom properties for light and dark
// schemes (light-dark()) plus matching on-primary text colours.
//
// The sheet is unlayered, so it beats tokens.css (@layer tokens) —
// including its fallback for browsers without light-dark(). An unsupported
// light-dark() value in a custom property is still accepted and only turns
// invalid where it is used (a transparent primary button), so the plain
// light-scheme values come first and the light-dark() pair only behind
// @supports; those browsers also get plain hover / soft / text tints of the
// accent in place of the tokens.css fallback's default blue.
func ThemeCSS(accent RGB) string {
	dark := DarkVariant(accent)
	hover := mixBlack(accent, 0.14)
	var b strings.Builder
	b.WriteString("/* FileParcel theme: generated from ui.accent_color. */\n")
	b.WriteString(":root {\n")
	fmt.Fprintf(&b, "  --fp-brand: %s;\n", accent.Hex())
	fmt.Fprintf(&b, "  --fp-accent-light: %s;\n", accent.Hex())
	fmt.Fprintf(&b, "  --fp-accent-dark: %s;\n", dark.Hex())
	fmt.Fprintf(&b, "  --fp-primary: %s;\n", accent.Hex())
	fmt.Fprintf(&b, "  --fp-on-primary: %s;\n", OnColor(accent).Hex())
	b.WriteString("}\n")
	b.WriteString("@supports (color: light-dark(#000, #fff)) {\n  :root {\n")
	fmt.Fprintf(&b, "    --fp-primary: light-dark(%s, %s);\n", accent.Hex(), dark.Hex())
	fmt.Fprintf(&b, "    --fp-on-primary: light-dark(%s, %s);\n", OnColor(accent).Hex(), OnColor(dark).Hex())
	b.WriteString("  }\n}\n")
	b.WriteString("@supports not (color: light-dark(#000, #fff)) {\n  :root {\n")
	fmt.Fprintf(&b, "    --fp-primary-hover: %s;\n", hover.Hex())
	fmt.Fprintf(&b, "    --fp-primary-soft: %s;\n", accent.alpha(0.12))
	fmt.Fprintf(&b, "    --fp-primary-soft-2: %s;\n", accent.alpha(0.2))
	fmt.Fprintf(&b, "    --fp-primary-text: %s;\n", mixBlack(accent, 0.18).Hex())
	fmt.Fprintf(&b, "    --fp-focus-ring: %s;\n", hover.Hex())
	fmt.Fprintf(&b, "    --fp-selection: %s;\n", accent.alpha(0.25))
	b.WriteString("  }\n}\n")
	return b.String()
}

// mixBlack returns c mixed with black by p (0..1) in OKLCH, like CSS
// color-mix(in oklch, c, black p): lightness and chroma shrink, hue stays.
func mixBlack(c RGB, p float64) RGB {
	L, a, b := c.oklab()
	return fromOKLCH(L*(1-p), math.Hypot(a, b)*(1-p), math.Atan2(b, a))
}

// alpha returns c as "rgb(r g b / a)".
func (c RGB) alpha(a float64) string {
	return fmt.Sprintf("rgb(%d %d %d / %s)", c.R, c.G, c.B, strconv.FormatFloat(a, 'f', -1, 64))
}
