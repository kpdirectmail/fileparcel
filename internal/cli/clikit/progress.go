package clikit

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"golang.org/x/term"
	"golang.org/x/text/width"
)

// Progress renders a single, continuously rewritten status line for a
// transfer ("label [#####-----]  45%  1.2 GiB / 3.4 GiB  25.3 MiB/s  ETA 1m30s
// note") on a terminal. A disabled Progress (not a TTY, --json) counts but
// never writes. All methods are safe for concurrent use.
type Progress struct {
	w       io.Writer
	enabled bool
	label   string
	total   atomic.Int64
	done    atomic.Int64
	start   time.Time
	now     func() time.Time
	format  func(int64) string
	// cols returns the terminal width (0 = unknown: the line is not cut).
	cols func() int

	mu       sync.Mutex
	note     string
	stop     chan struct{}
	stopped  chan struct{}
	lastLen  int
	running  bool
	finished bool
}

// NewProgress returns a progress line writing to w when enabled is true.
// total may be 0 (unknown size: no percentage/ETA) and changed later with
// SetTotal.
func NewProgress(w io.Writer, enabled bool, label string, total int64) *Progress {
	p := &Progress{w: w, enabled: enabled && w != nil, label: label, start: time.Now(), now: time.Now, format: Bytes,
		cols: func() int { return 0 }}
	if f, ok := w.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fd := int(f.Fd())
		// Asked on every redraw (a cheap ioctl), so it follows resizes.
		p.cols = func() int {
			c, _, err := term.GetSize(fd)
			if err != nil {
				return 0
			}
			return c
		}
	}
	p.total.Store(total)
	return p
}

// SetFormat changes how amounts are rendered (default Bytes); use Count for
// item counts such as job progress. Call it before Start.
func (p *Progress) SetFormat(f func(int64) string) {
	if f != nil {
		p.format = f
	}
}

// Count formats n as a plain number (a SetFormat option).
func Count(n int64) string { return fmt.Sprintf("%d", n) }

// Enabled reports whether the line is drawn.
func (p *Progress) Enabled() bool { return p.enabled }

// Add records n more bytes done (n may be negative to undo a failed attempt).
func (p *Progress) Add(n int64) { p.done.Add(n) }

// Done returns the bytes done so far.
func (p *Progress) Done() int64 { return p.done.Load() }

// SetTotal changes the expected total.
func (p *Progress) SetTotal(n int64) { p.total.Store(n) }

// SetNote sets the trailing note (e.g. "12/40 files").
func (p *Progress) SetNote(s string) {
	p.mu.Lock()
	p.note = s
	p.mu.Unlock()
}

// Start redraws the line every interval until Finish. It is a no-op when
// disabled or already started.
func (p *Progress) Start(interval time.Duration) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	if p.running || p.finished {
		p.mu.Unlock()
		return
	}
	p.running = true
	p.stop = make(chan struct{})
	p.stopped = make(chan struct{})
	p.mu.Unlock()
	go func() {
		defer close(p.stopped)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			p.draw()
			select {
			case <-p.stop:
				return
			case <-t.C:
			}
		}
	}()
}

// Finish stops redrawing and clears the line (the caller prints a summary).
// Safe to call more than once and without Start.
func (p *Progress) Finish() {
	p.mu.Lock()
	if p.finished {
		p.mu.Unlock()
		return
	}
	p.finished = true
	running := p.running
	p.mu.Unlock()
	if running {
		close(p.stop)
		<-p.stopped
	}
	if p.enabled {
		p.mu.Lock()
		if p.lastLen > 0 {
			fmt.Fprint(p.w, "\r\x1b[K")
			p.lastLen = 0
		}
		p.mu.Unlock()
	}
}

func (p *Progress) draw() {
	// One row less than the terminal is wide: "\r" only returns to the start
	// of the last row, so a line that wraps leaves a stale row per redraw.
	line := p.fit(p.cols() - 1)
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprint(p.w, "\r"+line+"\x1b[K")
	p.lastLen = utf8.RuneCountInString(line)
}

// barWidth is the number of cells of the bar.
const barWidth = 24

// lineParts are the segments of the progress line, in order.
type lineParts struct {
	label, bar, amounts, rate, eta, note string
}

func (l lineParts) String() string {
	return l.label + l.bar + l.amounts + l.rate + l.eta + l.note
}

// Line renders the current state (without control characters).
func (p *Progress) Line() string { return p.parts().String() }

func (p *Progress) parts() lineParts {
	var l lineParts
	done, total := p.done.Load(), p.total.Load()
	elapsed := p.now().Sub(p.start)
	if p.label != "" {
		l.label = p.label + " "
	}
	if total > 0 {
		frac := float64(done) / float64(total)
		frac = min(max(frac, 0), 1)
		filled := int(frac * barWidth)
		l.bar = "[" + strings.Repeat("#", filled) + strings.Repeat("-", barWidth-filled) + "] "
		l.amounts = fmt.Sprintf("%3d%%  %s / %s", int(frac*100), p.format(done), p.format(total))
	} else {
		l.amounts = p.format(done)
	}
	rate := float64(0)
	if secs := elapsed.Seconds(); secs >= 0.5 {
		rate = float64(done) / secs
	}
	if rate > 0 {
		l.rate = fmt.Sprintf("  %s/s", p.format(int64(rate)))
		if total > done {
			eta := time.Duration(float64(total-done) / rate * float64(time.Second))
			l.eta = "  ETA " + shortDuration(eta)
		}
	}
	p.mu.Lock()
	note := p.note
	p.mu.Unlock()
	if note != "" {
		l.note = "  " + note
	}
	return l
}

// fit renders the line in at most maxCols terminal columns (maxCols <= 0:
// unlimited). The label and the amounts come first; the bar, the rate, the
// ETA and the note follow as far as they fit. Only when the label and the
// amounts alone are too wide is the label shortened, then the line cut.
func (p *Progress) fit(maxCols int) string {
	full := p.parts()
	if maxCols <= 0 || cols(full.String()) <= maxCols {
		return full.String()
	}
	l := lineParts{label: full.label, amounts: full.amounts}
	for _, opt := range []struct {
		dst *string
		v   string
	}{{&l.bar, full.bar}, {&l.rate, full.rate}, {&l.eta, full.eta}, {&l.note, full.note}} {
		if cols(l.String())+cols(opt.v) <= maxCols {
			*opt.dst = opt.v
		}
	}
	if over := cols(l.String()) - maxCols; over > 0 && l.label != "" {
		name := strings.TrimSuffix(l.label, " ")
		if keep := cols(name) - over; keep >= 4 {
			l.label = cutCols(name, keep) + " "
		} else {
			l.label = ""
		}
	}
	return cutCols(l.String(), maxCols)
}

// cols is the number of terminal columns s takes (East Asian wide and
// fullwidth characters take two).
func cols(s string) int {
	n := 0
	for _, r := range s {
		n += runeCols(r)
	}
	return n
}

func runeCols(r rune) int {
	switch width.LookupRune(r).Kind() {
	case width.EastAsianWide, width.EastAsianFullwidth:
		return 2
	}
	return 1
}

// cutCols shortens s to at most n columns, ending in "…" when cut.
func cutCols(s string, n int) string {
	if cols(s) <= n {
		return s
	}
	if n <= 0 {
		return ""
	}
	var b strings.Builder
	used := 0
	for _, r := range s {
		w := runeCols(r)
		if used+w > n-1 {
			break
		}
		b.WriteRune(r)
		used += w
	}
	return b.String() + "…"
}

// Bytes formats n with IEC units ("0 B", "1.5 KiB", "12.3 MiB").
func Bytes(n int64) string {
	if n < 0 {
		return "-" + Bytes(-n)
	}
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	v := float64(n)
	i := -1
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if v >= 100 {
		return fmt.Sprintf("%.0f %s", v, units[i])
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

func shortDuration(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

// CountingReader counts bytes read from R into a Progress and remembers how
// many bytes this reader contributed (so a failed attempt can be undone with
// Undo before retrying).
type CountingReader struct {
	R io.Reader
	P *Progress
	n int64
}

// Read implements io.Reader.
func (c *CountingReader) Read(b []byte) (int, error) {
	n, err := c.R.Read(b)
	if n > 0 {
		c.n += int64(n)
		if c.P != nil {
			c.P.Add(int64(n))
		}
	}
	return n, err
}

// Undo subtracts the bytes counted so far from the Progress and resets the
// counter.
func (c *CountingReader) Undo() {
	if c.P != nil && c.n != 0 {
		c.P.Add(-c.n)
	}
	c.n = 0
}

// CountingWriter counts bytes written to W into a Progress.
type CountingWriter struct {
	W io.Writer
	P *Progress
}

// Write implements io.Writer.
func (c *CountingWriter) Write(b []byte) (int, error) {
	n, err := c.W.Write(b)
	if n > 0 && c.P != nil {
		c.P.Add(int64(n))
	}
	return n, err
}
