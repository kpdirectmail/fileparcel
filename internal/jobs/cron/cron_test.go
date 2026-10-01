package cron

import (
	"strings"
	"testing"
	"time"
)

func TestParseErrors(t *testing.T) {
	bad := []string{
		"", "   ", "* * * *", "* * * * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * 32 * *",
		"* * * 13 *", "* * * 0 *", "* * * * 8", "*/0 * * * *", "*/61 * * * *", "5-1 * * * *",
		"a * * * *", "1,,2 * * * *", "1- * * * *", "-1 * * * *", "@reboot", "@every 5m", "* * * foo *",
		"1/x * * * *",
		// Parses field by field but can never match a real date: accepting
		// it would store a schedule that is enabled and never runs.
		"0 0 30 2 *", "0 3 30 2 *", "0 0 31 2 *", "0 0 31 4 *", "0 0 31 4,6,9,11 *", "0 0 30,31 2 *",
	}
	for _, s := range bad {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) succeeded", s)
		}
		if Valid(s) {
			t.Errorf("Valid(%q)", s)
		}
	}
	good := map[string]string{
		"@hourly":               "0 * * * *",
		"@DAILY":                "0 0 * * *",
		"@midnight":             "0 0 * * *",
		"@weekly":               "0 0 * * 0",
		"@monthly":              "0 0 1 * *",
		"@yearly":               "0 0 1 1 *",
		"  0   3 * *   * ":      "0 3 * * *",
		"0 9 * JAN-mar Mon-FRI": "0 9 * JAN-mar Mon-FRI",
		"*/15 0-6/2 1,15 * 7":   "*/15 0-6/2 1,15 * 7",
	}
	for in, want := range good {
		s, err := Parse(in)
		if err != nil {
			t.Errorf("Parse(%q): %v", in, err)
			continue
		}
		if s.String() != want {
			t.Errorf("Parse(%q).String() = %q, want %q", in, s.String(), want)
		}
	}
}

func TestMustParsePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	MustParse("nope")
}

func TestNext(t *testing.T) {
	utc := time.UTC
	at := func(y int, mo time.Month, d, h, mi int) time.Time { return time.Date(y, mo, d, h, mi, 0, 0, utc) }
	tests := []struct {
		spec string
		from time.Time
		want time.Time
	}{
		{"*/15 * * * *", at(2026, 9, 19, 10, 7), at(2026, 9, 19, 10, 15)},
		{"*/15 * * * *", at(2026, 9, 19, 10, 45), at(2026, 9, 19, 11, 0)},
		{"* * * * *", at(2026, 9, 19, 10, 7).Add(30 * time.Second), at(2026, 9, 19, 10, 8)},
		{"0 3 * * *", at(2026, 9, 19, 3, 0), at(2026, 9, 20, 3, 0)}, // strictly after
		{"0 3 * * *", at(2026, 9, 19, 2, 59), at(2026, 9, 19, 3, 0)},
		{"0 0 1 * *", at(2026, 1, 31, 12, 0), at(2026, 2, 1, 0, 0)},
		{"0 0 1 * *", at(2026, 12, 15, 0, 0), at(2027, 1, 1, 0, 0)},   // year rollover
		{"0 4 * * 0", at(2026, 9, 16, 12, 0), at(2026, 9, 20, 4, 0)},  // Wed → Sun
		{"0 4 * * 7", at(2026, 9, 16, 12, 0), at(2026, 9, 20, 4, 0)},  // 7 = Sunday
		{"0 4 * * sun", at(2026, 9, 20, 4, 0), at(2026, 9, 27, 4, 0)}, // strictly after
		{"30 2 29 2 *", at(2026, 1, 1, 0, 0), at(2028, 2, 29, 2, 30)}, // leap day
		{"0 0 13 * 5", at(2026, 2, 1, 0, 0), at(2026, 2, 6, 0, 0)},    // DOM or DOW (Friday Feb 6)
		{"0 0 13 * 5", at(2026, 2, 7, 0, 0), at(2026, 2, 13, 0, 0)},   // 13th (also a Friday)
		{"0 0 13 * *", at(2026, 2, 7, 0, 0), at(2026, 2, 13, 0, 0)},
		{"0 0 * * 1", at(2026, 2, 7, 0, 0), at(2026, 2, 9, 0, 0)},
		{"0 0 */10 * *", at(2026, 2, 12, 0, 0), at(2026, 2, 21, 0, 0)}, // 1,11,21,31
		{"15 10-12/2 * * *", at(2026, 2, 12, 10, 16), at(2026, 2, 12, 12, 15)},
		{"0 9 * jan-mar mon-fri", at(2026, 3, 31, 9, 0), at(2027, 1, 1, 9, 0)}, // Fri Jan 1 2027
		{"@hourly", at(2026, 9, 19, 23, 30), at(2026, 9, 20, 0, 0)},
	}
	for _, tt := range tests {
		s := MustParse(tt.spec)
		got := s.Next(tt.from)
		if !got.Equal(tt.want) {
			t.Errorf("%q from %v: got %v, want %v", tt.spec, tt.from, got, tt.want)
		}
	}
	var nilSched *Schedule
	if !nilSched.Next(time.Now()).IsZero() {
		t.Fatal("nil schedule")
	}
	if !(&Schedule{}).Next(time.Now()).IsZero() {
		t.Fatal("zero schedule")
	}
}

// A spec that parses field by field but can never match a real date must be
// refused: jobs.Schedule would otherwise store an enabled schedule whose
// next_run_at is NULL, and the scheduler never selects such a row again — a
// permanently dead schedule with no error anywhere.
func TestUnreachableSpecsRejected(t *testing.T) {
	for _, spec := range []string{"0 0 30 2 *", "0 3 30 2 *", "0 0 31 2 *", "0 0 31 4 *", "0 0 31 4,6,9,11 *"} {
		sc, err := Parse(spec)
		if err == nil {
			t.Errorf("Parse(%q) accepted a spec that never runs (next = %v)", spec, sc.Next(time.Now()))
			continue
		}
		if !strings.Contains(err.Error(), "never matches") {
			t.Errorf("Parse(%q) error = %v", spec, err)
		}
		if Valid(spec) {
			t.Errorf("Valid(%q) = true", spec)
		}
	}
	// Rare but reachable specs stay accepted.
	for _, spec := range []string{"30 2 29 2 *", "0 0 31 1,3 *", "0 0 30 4 *", "0 0 31 2 1", "@yearly"} {
		sc, err := Parse(spec)
		if err != nil {
			t.Errorf("Parse(%q): %v", spec, err)
			continue
		}
		if !sc.Reachable() {
			t.Errorf("Reachable(%q) = false", spec)
		}
	}
	// Next keeps its guard for a Schedule not built by Parse.
	impossible := &Schedule{minute: 1, hour: 1, dom: 1 << 30, month: 1 << 2, dowStar: true, dow: 0x7f}
	if n := impossible.Next(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); !n.IsZero() {
		t.Errorf("Next on an impossible schedule = %v, want zero", n)
	}
	if impossible.Reachable() {
		t.Error("Reachable on an impossible schedule = true")
	}
}

func TestNextDST(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip("no tzdata:", err)
	}
	// Spring forward: 2026-03-29 02:00 → 03:00. 02:30 does not exist; the run
	// happens right after the gap (03:30 CEST = 01:30 UTC).
	s := MustParse("30 2 * * *")
	got := s.Next(time.Date(2026, 3, 29, 1, 0, 0, 0, loc))
	if want := time.Date(2026, 3, 29, 1, 30, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("spring forward: got %v, want %v", got.UTC(), want)
	}
	// Fall back: 2026-10-25 03:00 CEST → 02:00 CET; 02:30 occurs twice. It runs once.
	// (Which of the two instants Go picks for the ambiguous wall time is unspecified.)
	first := s.Next(time.Date(2026, 10, 25, 1, 0, 0, 0, loc))
	if a, b := time.Date(2026, 10, 25, 0, 30, 0, 0, time.UTC), time.Date(2026, 10, 25, 1, 30, 0, 0, time.UTC); !first.Equal(a) && !first.Equal(b) {
		t.Fatalf("fall back first: got %v", first.UTC())
	}
	second := s.Next(first)
	if want := time.Date(2026, 10, 26, 2, 30, 0, 0, loc); !second.Equal(want) {
		t.Fatalf("fall back runs twice: got %v, want %v", second, want)
	}
	// Hourly schedules keep firing every wall-clock hour across the change.
	h := MustParse("0 * * * *")
	n := h.Next(time.Date(2026, 3, 29, 1, 30, 0, 0, loc))
	if want := time.Date(2026, 3, 29, 3, 0, 0, 0, loc); !n.Equal(want) {
		t.Fatalf("hourly over gap: %v want %v", n, want)
	}
	// Local-time schedule: 03:00 Berlin is 01:00 UTC in summer.
	d := MustParse("0 3 * * *").Next(time.Date(2026, 7, 1, 12, 0, 0, 0, loc))
	if want := time.Date(2026, 7, 2, 1, 0, 0, 0, time.UTC); !d.Equal(want) {
		t.Fatalf("local time: %v", d.UTC())
	}
}

// Which side of a spring-forward gap a missing wall-clock time resolves to is
// decided by time.Date and differs per zone: Berlin puts 02:30 after the gap,
// New York before it. The package comment says exactly that; this pins the
// part that must hold everywhere — the run happens once, within an hour of
// the gap, and the schedule is back on time the next day.
func TestNextDSTGapResolvesOncePerZone(t *testing.T) {
	s := MustParse("30 2 * * *")
	for _, tc := range []struct {
		zone       string
		day        time.Time // local noon the day before the transition
		gapStart   time.Time // UTC instant the gap opens
		gapSeconds int
	}{
		{"Europe/Berlin", time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC), time.Date(2026, 3, 29, 1, 0, 0, 0, time.UTC), 3600},
		{"America/New_York", time.Date(2026, 3, 7, 12, 0, 0, 0, time.UTC), time.Date(2026, 3, 8, 7, 0, 0, 0, time.UTC), 3600},
	} {
		loc, err := time.LoadLocation(tc.zone)
		if err != nil {
			t.Skip("no tzdata:", err)
		}
		from := tc.day.In(loc)
		first := s.Next(from)
		gapEnd := tc.gapStart.Add(time.Duration(tc.gapSeconds) * time.Second)
		if first.Before(tc.gapStart.Add(-time.Hour)) || first.After(gapEnd.Add(time.Hour)) {
			t.Errorf("%s: transition-day run %v is not within an hour of the gap %v..%v",
				tc.zone, first.UTC(), tc.gapStart, gapEnd)
		}
		// Exactly one run on the transition day, and the next one is the
		// normal 02:30 local the day after.
		second := s.Next(first)
		wantDay := first.In(loc).AddDate(0, 0, 1)
		want := time.Date(wantDay.Year(), wantDay.Month(), wantDay.Day(), 2, 30, 0, 0, loc)
		if !second.Equal(want) {
			t.Errorf("%s: run after the gap = %v, want %v", tc.zone, second, want)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"* * * * *", "*/5 1-3 1,2 jan mon", "@daily", "0 0 30 2 *"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, spec string) {
		s, err := Parse(spec)
		if err != nil {
			return
		}
		from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		n := s.Next(from)
		if !n.IsZero() && !n.After(from) {
			t.Fatalf("%q: next %v not after %v", spec, n, from)
		}
		// Re-parsing the normalized form gives the same schedule.
		s2, err := Parse(s.String())
		if err != nil || !s2.Next(from).Equal(n) {
			t.Fatalf("%q: normalized form differs", spec)
		}
	})
}
