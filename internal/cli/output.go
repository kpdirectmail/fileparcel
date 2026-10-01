package cli

// Output helpers shared by every command (STABLE API — see the package doc
// in root.go). Commands print human-readable tables by default and JSON with
// --json; prompts go to stderr so stdout stays machine-readable.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"fileparcel/internal/qr"
)

// ---------- structured output ----------

// Print writes v as indented JSON when --json is set, otherwise calls human
// with the command's stdout. human may be nil (then v is printed as JSON in
// both modes).
func Print(cmd *cobra.Command, v any, human func(w io.Writer) error) error {
	w := cmd.OutOrStdout()
	if G.JSON || human == nil {
		return PrintJSON(w, v)
	}
	return human(w)
}

// Table is a simple column-aligned text table. Cells are formatted with
// Cell; empty data cells print as "-" (a header is printed as given, so a
// column may be left unnamed).
//
//	t := cli.NewTable("ID", "NAME", "SIZE")
//	for _, n := range nodes { t.Add(n.ID, n.Name, cli.HumanBytes(n.Size)) }
//	return t.Render(w)
type Table struct {
	headers []string
	rows    [][]string
}

// NewTable returns a table with the given column headers.
func NewTable(headers ...string) *Table { return &Table{headers: headers} }

// Add appends one row (missing cells print as "-", extra cells are kept).
func (t *Table) Add(cells ...any) {
	row := make([]string, len(cells))
	for i, c := range cells {
		row[i] = Cell(c)
	}
	t.rows = append(t.rows, row)
}

// Len returns the number of rows.
func (t *Table) Len() int { return len(t.rows) }

// Render writes the table (header row first) aligned with two-space gutters.
// Header cells print as given — an empty header is a blank heading, not the
// "-" used for an empty data cell, which would read as a value. An empty
// table prints only the header line. The header is made bold after the
// alignment: tabwriter counts the invisible ANSI codes as characters, which
// shifted every heading after the first left of its column.
func (t *Table) Render(w io.Writer) error {
	var buf strings.Builder
	tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	cols := len(t.headers)
	for _, r := range t.rows {
		cols = max(cols, len(r))
	}
	line := func(cells []string, header bool) {
		out := make([]string, cols)
		for i := range out {
			v := ""
			if i < len(cells) {
				v = cells[i]
			}
			if v == "" && !header {
				v = "-"
			}
			out[i] = sanitizeCell(v)
		}
		fmt.Fprintln(tw, strings.Join(out, "\t"))
	}
	if len(t.headers) > 0 {
		line(t.headers, true)
	}
	for _, r := range t.rows {
		line(r, false)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	s := buf.String()
	if len(t.headers) > 0 {
		head, rest, _ := strings.Cut(s, "\n")
		s = Bold(head) + "\n" + rest
	}
	_, err := io.WriteString(w, s)
	return err
}

// sanitizeCell keeps table layout intact: tabs/newlines become spaces and
// control characters are dropped (user-controlled names must not be able to
// inject terminal escape sequences).
func sanitizeCell(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			return ' '
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			return -1
		}
		return r
	}, s)
}

// KV prints "key: value" pairs aligned (for "show"-style commands).
//
//	kv := cli.NewKV()
//	kv.Add("Username", u.Username)
//	kv.Add("Created", cli.HumanTime(u.CreatedAt))
//	return kv.Render(w)
type KV struct{ rows [][2]string }

// NewKV returns an empty key/value list.
func NewKV() *KV { return &KV{} }

// Add appends one pair; the value is formatted with Cell.
func (k *KV) Add(key string, value any) { k.rows = append(k.rows, [2]string{key, Cell(value)}) }

// Render writes the pairs, keys padded to the longest key. A pair with an
// empty key is a continuation row: it prints only the value, aligned under the
// value column (no stray colon).
func (k *KV) Render(w io.Writer) error {
	width := 0
	for _, r := range k.rows {
		width = max(width, utf8.RuneCountInString(r[0]))
	}
	for _, r := range k.rows {
		v := r[1]
		if v == "" {
			v = "-"
		}
		lead := r[0] + ":"
		if r[0] == "" {
			lead = " "
		}
		pad := strings.Repeat(" ", width-utf8.RuneCountInString(r[0]))
		if _, err := fmt.Fprintf(w, "%s%s %s\n", lead, pad, sanitizeCell(v)); err != nil {
			return err
		}
	}
	return nil
}

// Cell formats a value for tables and KV lists: nil pointers and zero times
// become "", *T is dereferenced, time.Time uses HumanTime, bool yes/no,
// []string is comma-joined, fmt.Stringer and errors use their text.
func Cell(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case *string:
		if x == nil {
			return ""
		}
		return *x
	case bool:
		return YesNo(x)
	case *bool:
		if x == nil {
			return ""
		}
		return YesNo(*x)
	case time.Time:
		return HumanTime(x)
	case *time.Time:
		return HumanTimePtr(x)
	case time.Duration:
		return HumanDuration(x)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case *int64:
		if x == nil {
			return ""
		}
		return strconv.FormatInt(*x, 10)
	case []string:
		return strings.Join(x, ",")
	case error:
		return x.Error()
	case fmt.Stringer:
		return x.String()
	}
	return fmt.Sprint(v)
}

// PrintJSONLine writes v as one compact JSON line (for streaming output such
// as `audit list --follow --json`).
func PrintJSONLine(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", b)
	return err
}

// ---------- human formatting ----------

// HumanBytes formats a byte count with IEC units: "0 B", "999 B", "1.5 KiB",
// "12.3 MiB", "4.0 GiB". Negative values keep their sign.
func HumanBytes(n int64) string {
	if n < 0 {
		return "-" + HumanBytes(-n)
	}
	if n < 1024 {
		return strconv.FormatInt(n, 10) + " B"
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

// HumanBytesPtr is HumanBytes for optional values (nil = "unlimited").
func HumanBytesPtr(n *int64) string {
	if n == nil {
		return "unlimited"
	}
	return HumanBytes(*n)
}

// ParseSize parses a size such as "1048576", "512K", "10M", "1.5G", "2T",
// "10GB", "10GiB" (binary multiples in every spelling; case-insensitive).
// "unlimited", "none" and "0" are NOT special here — callers decide what 0
// means; use ParseQuota for quota flags.
func ParseSize(s string) (int64, error) {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return 0, errors.New("empty size")
	}
	mult := float64(1)
	for _, u := range []struct {
		suffix string
		m      float64
	}{
		{"kib", 1 << 10}, {"mib", 1 << 20}, {"gib", 1 << 30}, {"tib", 1 << 40}, {"pib", 1 << 50},
		{"kb", 1 << 10}, {"mb", 1 << 20}, {"gb", 1 << 30}, {"tb", 1 << 40}, {"pb", 1 << 50},
		{"k", 1 << 10}, {"m", 1 << 20}, {"g", 1 << 30}, {"t", 1 << 40}, {"p", 1 << 50},
		{"b", 1},
	} {
		if strings.HasSuffix(t, u.suffix) {
			t = strings.TrimSpace(strings.TrimSuffix(t, u.suffix))
			mult = u.m
			break
		}
	}
	f, err := strconv.ParseFloat(t, 64)
	if err != nil || f < 0 || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, fmt.Errorf("invalid size %q (examples: 500M, 10G, 1.5T)", s)
	}
	v := f * mult
	// float64(math.MaxInt64) is exactly 2^63, the first value that does not
	// fit: int64(2^63) would wrap to a negative size.
	if v >= math.MaxInt64 {
		return 0, fmt.Errorf("size %q is too large", s)
	}
	return int64(v), nil
}

// ParseQuota parses a quota flag: "unlimited"/"none"/"" → nil, otherwise
// ParseSize.
func ParseQuota(s string) (*int64, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "unlimited", "none", "off":
		return nil, nil
	}
	n, err := ParseSize(s)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// HumanTime formats t in the local time zone as "2006-01-02 15:04"; the zero
// time is "".
func HumanTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format("2006-01-02 15:04")
}

// HumanTimePtr is HumanTime for optional timestamps (nil = "").
func HumanTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return HumanTime(*t)
}

// Ago formats t relative to now: "just now", "5 min ago", "3 h ago",
// "2 days ago", "in 4 days" (future), "" for the zero time.
func Ago(t time.Time) string { return agoFrom(t, time.Now()) }

func agoFrom(t, now time.Time) string {
	if t.IsZero() {
		return ""
	}
	// The direction comes from the times, not from the sign of the
	// difference: Sub saturates beyond ~292 years (a certificate valid
	// until 9999-12-31), and negating math.MinInt64 stays negative.
	future := t.After(now)
	d := now.Sub(t)
	if future {
		d = t.Sub(now)
	}
	saturated := d == math.MaxInt64
	var s string
	switch {
	case d < 45*time.Second:
		return "just now"
	case d < 90*time.Minute:
		s = fmt.Sprintf("%d min", int(math.Round(d.Minutes())))
	case d < 36*time.Hour:
		s = fmt.Sprintf("%d h", int(math.Round(d.Hours())))
	case d < 60*24*time.Hour:
		s = fmt.Sprintf("%d days", int(math.Round(d.Hours()/24)))
	case d < 2*365*24*time.Hour:
		s = fmt.Sprintf("%d months", int(math.Round(d.Hours()/24/30)))
	case saturated:
		// Too far apart for a Duration: count calendar years instead.
		fy := func(x time.Time) float64 { x = x.UTC(); return float64(x.Year()) + float64(x.YearDay()-1)/365.25 }
		s = fmt.Sprintf("%d years", int(math.Round(math.Abs(fy(t)-fy(now)))))
	default:
		s = fmt.Sprintf("%d years", int(math.Round(d.Hours()/24/365)))
	}
	if future {
		return "in " + s
	}
	return s + " ago"
}

// HumanDuration formats d compactly: "<1ms", "450ms", "12s", "3m20s", "2h5m",
// "3d4h". A non-zero duration never renders as "0ms".
func HumanDuration(d time.Duration) string {
	if d < 0 {
		return "-" + HumanDuration(-d)
	}
	switch {
	case d > 0 && d < time.Millisecond:
		return "<1ms"
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		m, s := int(d.Minutes()), int(d.Seconds())%60
		if s == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dm%ds", m, s)
	case d < 48*time.Hour:
		h, m := int(d.Hours()), int(d.Minutes())%60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh%dm", h, m)
	}
	days, h := int(d.Hours())/24, int(d.Hours())%24
	if h == 0 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dd%dh", days, h)
}

// ParseDuration extends time.ParseDuration with day and week units ("7d",
// "2w", "1d12h", "30d"). Plain integers are rejected (ambiguous).
func ParseDuration(s string) (time.Duration, error) {
	t := strings.TrimSpace(strings.ToLower(s))
	if t == "" {
		return 0, errors.New("empty duration")
	}
	var total time.Duration
	rest := t
	for _, unit := range []struct {
		suffix byte
		d      time.Duration
	}{{'w', 7 * 24 * time.Hour}, {'d', 24 * time.Hour}} {
		if i := strings.IndexByte(rest, unit.suffix); i > 0 {
			n, err := strconv.ParseFloat(rest[:i], 64)
			if err != nil || n < 0 {
				return 0, fmt.Errorf("invalid duration %q (examples: 30m, 12h, 7d, 2w)", s)
			}
			total += time.Duration(n * float64(unit.d))
			rest = rest[i+1:]
		}
	}
	if rest != "" {
		d, err := time.ParseDuration(rest)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q (examples: 30m, 12h, 7d, 2w)", s)
		}
		total += d
	}
	if total < 0 {
		return 0, fmt.Errorf("invalid duration %q: negative", s)
	}
	return total, nil
}

// YesNo returns "yes" or "no".
func YesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// Dash returns s, or "-" when s is empty.
func Dash(s string) string { return dash(s) }

// Truncate shortens s to at most n runes, ending in "…" when cut.
func Truncate(s string, n int) string {
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	if n == 1 {
		return "…"
	}
	return string(r[:n-1]) + "…"
}

// Plural returns "1 file" / "3 files". A word ending in a consonant + "y"
// takes "-ies" ("entry" → "entries"); everything else takes a plain "s".
func Plural(n int64, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.FormatInt(n, 10) + " " + pluralOf(word)
}

// pluralOf is the plural of word (see Plural).
func pluralOf(word string) string {
	if n := len(word); n >= 2 && word[n-1] == 'y' && !strings.ContainsRune("aeiou", rune(word[n-2])) {
		return word[:n-1] + "ies"
	}
	return word + "s"
}

// ---------- colours & messages ----------

// ColorEnabled reports whether ANSI colours are used on stdout: not with
// --no-color or --json, not when $NO_COLOR is set or TERM=dumb, and only when
// stdout is a terminal.
func ColorEnabled() bool {
	if G.NoColor || G.JSON || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// colorOn is ColorEnabled; tests (which never run on a terminal) replace it.
var colorOn = ColorEnabled

func ansi(code, s string) string {
	if !colorOn() || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// Bold, Dim, Green, Yellow, Red and Cyan wrap s in ANSI colours when
// ColorEnabled.
func Bold(s string) string   { return ansi("1", s) }
func Dim(s string) string    { return ansi("2", s) }
func Green(s string) string  { return ansi("32", s) }
func Yellow(s string) string { return ansi("33", s) }
func Red(s string) string    { return ansi("31", s) }
func Cyan(s string) string   { return ansi("36", s) }

// Infof prints an informational line to the command's stderr (never to
// stdout, which may carry JSON).
func Infof(cmd *cobra.Command, format string, a ...any) {
	fmt.Fprintf(cmd.ErrOrStderr(), format+"\n", a...)
}

// Warnf prints "warning: …" to the command's stderr.
func Warnf(cmd *cobra.Command, format string, a ...any) {
	fmt.Fprintln(cmd.ErrOrStderr(), Yellow("warning:")+" "+fmt.Sprintf(format, a...))
}

// Successf prints a success line to the command's stdout, unless --json is
// set (JSON output must stay a single document).
func Successf(cmd *cobra.Command, format string, a ...any) {
	if G.JSON {
		return
	}
	fmt.Fprintln(cmd.OutOrStdout(), Green("✓")+" "+fmt.Sprintf(format, a...))
}

// UsageError returns an error that makes the process exit with ExitUsage (2).
func UsageError(format string, a ...any) error {
	return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf(format, a...)}
}

// ---------- QR codes ----------

// PrintQR writes data as a terminal QR code (Unicode half blocks, quiet zone
// included). It is skipped (nil error) when --json is set.
func PrintQR(w io.Writer, data string) error {
	if G.JSON {
		return nil
	}
	s, err := qr.Terminal(data, false)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, s)
	return err
}

// ---------- prompts ----------

// ErrNotInteractive is returned by the prompt helpers when input is needed
// but stdin is not a terminal (and -y/--yes or a --…-stdin/--…-file flag was
// not given), so scripts fail fast instead of hanging.
var ErrNotInteractive = errors.New("input required but stdin is not a terminal (use -y/--yes or the --*-stdin / --*-file flags)")

// interactive reports whether r is usable for prompting: a terminal, or a
// non-file reader (tests use cmd.SetIn(strings.NewReader(…))).
func interactive(r io.Reader) (fd int, isTTY, ok bool) {
	if f, isFile := r.(*os.File); isFile {
		fd = int(f.Fd())
		if term.IsTerminal(fd) {
			return fd, true, true
		}
		return fd, false, false
	}
	return -1, false, r != nil
}

// lineReaders caches one bufio.Reader per input so consecutive prompts on a
// scripted (non-terminal) reader do not lose buffered bytes.
var (
	lineMu      sync.Mutex
	lineReaders = map[io.Reader]*bufio.Reader{}
)

func readLine(r io.Reader) (string, error) {
	lineMu.Lock()
	br, ok := lineReaders[r]
	if !ok {
		br = bufio.NewReaderSize(r, 4096)
		lineReaders[r] = br
	}
	lineMu.Unlock()
	s, err := br.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && s != "") {
		return "", err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

// Confirm asks a yes/no question on stderr. It returns true without asking
// when -y/--yes was given, def on an empty answer, and ErrNotInteractive when
// stdin is not a terminal.
func Confirm(cmd *cobra.Command, question string, def bool) (bool, error) {
	if G.Yes {
		return true, nil
	}
	in := cmd.InOrStdin()
	fd, tty, ok := interactive(in)
	if !ok {
		return false, ErrNotInteractive
	}
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	for {
		if err := ctxErr(cmd.Context()); err != nil {
			return false, err
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "%s %s ", question, hint)
		ans, err := promptRead(cmd, fd, tty, func() (string, error) { return readLine(in) })
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(ans)) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Fprintln(cmd.ErrOrStderr(), "Please answer yes or no.")
	}
}

// Prompt asks for a line of text on stderr, showing and returning def on an
// empty answer. With -y/--yes it returns def without asking.
func Prompt(cmd *cobra.Command, question, def string) (string, error) {
	if G.Yes {
		return def, nil
	}
	in := cmd.InOrStdin()
	fd, tty, ok := interactive(in)
	if !ok {
		return "", ErrNotInteractive
	}
	if err := ctxErr(cmd.Context()); err != nil {
		return "", err
	}
	if def != "" {
		fmt.Fprintf(cmd.ErrOrStderr(), "%s [%s]: ", question, def)
	} else {
		fmt.Fprintf(cmd.ErrOrStderr(), "%s: ", question)
	}
	ans, err := promptRead(cmd, fd, tty, func() (string, error) { return readLine(in) })
	if err != nil {
		return "", err
	}
	if ans = strings.TrimSpace(ans); ans == "" {
		return def, nil
	}
	return ans, nil
}

// PromptSecret reads a secret without echo (terminal) or one line (scripted
// reader in tests). It never honours --yes: a secret has no default.
func PromptSecret(cmd *cobra.Command, prompt string) (string, error) {
	in := cmd.InOrStdin()
	fd, tty, ok := interactive(in)
	if !ok {
		return "", ErrNotInteractive
	}
	if err := ctxErr(cmd.Context()); err != nil {
		return "", err
	}
	fmt.Fprint(cmd.ErrOrStderr(), prompt)
	if tty {
		b, err := ttyRead(cmd.Context(), fd, func() ([]byte, error) { return term.ReadPassword(fd) })
		fmt.Fprintln(cmd.ErrOrStderr())
		return string(b), err
	}
	s, err := readLine(in)
	fmt.Fprintln(cmd.ErrOrStderr())
	return s, err
}

// ctxErr is ctx.Err() for a possibly nil context (a command run without
// ExecuteContext): a prompt is not shown once the command is cancelled.
func ctxErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

// promptRead runs read for Confirm and Prompt: interruptible on a terminal
// (ttyRead; the aborted line then ends with a newline so the error message
// starts on its own line), synchronous on a scripted reader.
func promptRead(cmd *cobra.Command, fd int, tty bool, read func() (string, error)) (string, error) {
	if !tty {
		return read()
	}
	s, err := ttyRead(cmd.Context(), fd, read)
	if err != nil && ctxErr(cmd.Context()) != nil {
		fmt.Fprintln(cmd.ErrOrStderr())
	}
	return s, err
}

// ttyRead runs a blocking read of the terminal fd but returns ctx.Err() as
// soon as ctx is cancelled. Ctrl-C at a prompt does not end the read: the
// terminal keeps ISIG (term.ReadPassword too), the SIGINT goes to the
// signal handler that cancels the command context (Execute), and the read
// itself just restarts. The terminal mode (echo off during a password) is
// restored here, since the abandoned read, which stays blocked until the
// process exits, never gets to do it.
func ttyRead[T any](ctx context.Context, fd int, read func() (T, error)) (T, error) {
	if ctx == nil || ctx.Done() == nil {
		return read()
	}
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	st, _ := term.GetState(fd)
	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	go func() {
		v, err := read()
		done <- result{v, err}
	}()
	select {
	case r := <-done:
		return r.v, r.err
	case <-ctx.Done():
		if st != nil {
			_ = term.Restore(fd, st)
		}
		return zero, ctx.Err()
	}
}

// PromptNewSecret asks for a new secret twice and requires both entries to
// match and be non-empty (up to three attempts).
func PromptNewSecret(cmd *cobra.Command, prompt string) (string, error) {
	for range 3 {
		a, err := PromptSecret(cmd, prompt)
		if err != nil {
			return "", err
		}
		if a == "" {
			fmt.Fprintln(cmd.ErrOrStderr(), "Empty input, try again.")
			continue
		}
		b, err := PromptSecret(cmd, "Repeat: ")
		if err != nil {
			return "", err
		}
		if a == b {
			return a, nil
		}
		fmt.Fprintln(cmd.ErrOrStderr(), "The entries do not match, try again.")
	}
	return "", errors.New("too many attempts")
}

// maxSecret bounds secrets read from stdin or files.
const maxSecret = 64 << 10

// ReadSecret reads a secret from r: the first line, without the trailing
// newline (for --password-stdin / --passphrase-stdin). Empty input is an
// error.
func ReadSecret(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxSecret+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxSecret {
		return "", errors.New("secret input too long")
	}
	s, _, _ := strings.Cut(string(data), "\n")
	s = strings.TrimRight(s, "\r")
	if s == "" {
		return "", errors.New("empty secret input")
	}
	return s, nil
}

// ReadSecretStdin is ReadSecret on the command's stdin.
func ReadSecretStdin(cmd *cobra.Command) (string, error) { return ReadSecret(cmd.InOrStdin()) }

// ReadSecretFile reads a secret from a file (first line; for
// --password-file / --passphrase-file). It warns on stderr when the file is
// readable by other users and this process could chmod it: a secret
// bind-mounted into a container is owned by somebody else and has to stay
// readable (DESIGN §14.7), so telling the reader to chmod it would be wrong.
func ReadSecretFile(cmd *cobra.Command, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Mode().Perm()&0o004 != 0 && cmd != nil && canChangeMode(st) {
		Warnf(cmd, "%s is readable by other users; chmod 600 it", path)
	}
	s, err := ReadSecret(f)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// ---------- client helper ----------

// WithClient connects with the global flags (Connect(G.ConnectOptions())),
// runs fn and closes the client. Use it in RunE:
//
//	RunE: func(cmd *cobra.Command, args []string) error {
//	    return cli.WithClient(cmd, func(ctx context.Context, c *cli.Client) error {
//	        var page core.Page[core.User]
//	        if err := c.Do(ctx, "GET", "/api/v1/admin/users", nil, &page); err != nil { return err }
//	        …
//	    })
//	}
func WithClient(cmd *cobra.Command, fn func(ctx context.Context, c *Client) error) error {
	opts := G.ConnectOptions()
	pass, err := G.passphraseFunc(cmd)
	if err != nil {
		return err
	}
	opts.Passphrase = pass
	opts.Context = cmd.Context()
	c, err := Connect(opts)
	if err != nil {
		return err
	}
	defer c.Close()
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	return fn(ctx, c)
}
