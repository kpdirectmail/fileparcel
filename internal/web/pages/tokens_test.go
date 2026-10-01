package pages

import (
	"math"
	"regexp"
	"strconv"
	"testing"

	"fileparcel/internal/web/static"
)

// TestTokensOnColorContrast: with the default accent /theme.css is only a
// comment, so tokens.css alone colours the primary and danger buttons. The
// dark scheme lightens both fills, so the text on them (--fp-on-primary,
// --fp-on-danger) must turn dark there and keep WCAG AA (4.5:1: the button
// labels are 13–14 px) on each fill and on its hover mix. The values are read
// from the stylesheets so a token change cannot silently regress. (Custom
// accents get their on-colour from ThemeCSS / OnColor.)
func TestTokensOnColorContrast(t *testing.T) {
	file := func(name string) string {
		t.Helper()
		b, ok := static.File(name)
		if !ok {
			t.Fatalf("no %s", name)
		}
		return string(b)
	}
	tokens, components := file("css/tokens.css"), file("css/components.css")
	const num = `([0-9.]+)`
	const lch = `oklch\(` + num + ` ` + num + ` ` + num + `\)`
	find := func(src, re string) []float64 {
		t.Helper()
		m := regexp.MustCompile(re).FindStringSubmatch(src)
		if m == nil {
			t.Fatalf("no declaration matching %s", re)
		}
		v := make([]float64, len(m)-1)
		for i, s := range m[1:] {
			f, err := strconv.ParseFloat(s, 64)
			if err != nil {
				t.Fatalf("%s: %v", re, err)
			}
			v[i] = f
		}
		return v
	}
	// color-mix(in oklch, c, white|black p): the achromatic end has no hue,
	// so lightness and chroma move towards it and the hue stays.
	mix := func(c []float64, towardL, p float64) []float64 {
		return []float64{c[0]*(1-p) + towardL*p, c[1] * (1 - p), c[2]}
	}
	rgb := func(c []float64) RGB { return fromOKLCH(c[0], c[1], c[2]*math.Pi/180) }

	brand := find(tokens, `--fp-brand: `+lch+`;`)
	floor := find(tokens, `--fp-primary: light-dark\(var\(--fp-brand\), oklch\(from var\(--fp-brand\) max\(l, `+num+`\) c h\)\);`)[0]
	primary := []float64{math.Max(brand[0], floor), brand[1], brand[2]}
	primaryHover := find(tokens, `--fp-primary-hover: light-dark\(color-mix\(in oklch, var\(--fp-primary\), black [0-9.]+%\), `+
		`color-mix\(in oklch, var\(--fp-primary\), white `+num+`%\)\);`)[0] / 100
	danger := find(tokens, `--fp-danger: light-dark\(`+lch+`, `+lch+`\);`)[3:]
	dangerHover := find(components, `--btn-bg-hover: color-mix\(in oklch, var\(--fp-danger\), black `+num+`%\);`)[0] / 100
	onPrimary := rgb(find(tokens, `--fp-on-primary: light-dark\(oklch\(1 0 0\), `+lch+`\);`))
	onDanger := rgb(find(tokens, `--fp-on-danger: light-dark\(oklch\(1 0 0\), `+lch+`\);`))

	for _, c := range []struct {
		name   string
		fill   []float64
		onFill RGB
	}{
		{"primary", primary, onPrimary},
		{"primary hover", mix(primary, 1, primaryHover), onPrimary},
		{"danger", danger, onDanger},
		{"danger hover", mix(danger, 0, dangerHover), onDanger},
	} {
		if r := Contrast(rgb(c.fill), c.onFill); r < 4.5 {
			t.Errorf("dark %s %s: text %s contrast %.2f < 4.5", c.name, rgb(c.fill).Hex(), c.onFill.Hex(), r)
		}
	}
}
