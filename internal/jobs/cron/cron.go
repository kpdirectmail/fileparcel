// Package cron is the "cron-lite" schedule parser used by the job scheduler
// (DESIGN §9.7) and by packages that validate cron settings.
//
// A spec has five whitespace-separated fields:
//
//	minute (0-59)  hour (0-23)  day-of-month (1-31)  month (1-12 or jan-dec)  day-of-week (0-7 or sun-sat; 0 and 7 = Sunday)
//
// Each field is "*", a value, a range "a-b", a list "a,b,c-d" and any of
// those with a step: "*/15", "0-30/5", "10/20" (= 10-max/20). Descriptors are
// accepted as well: @hourly, @daily (@midnight), @weekly, @monthly and
// @yearly (@annually).
//
// Day matching follows Vixie cron: when both day-of-month and day-of-week are
// restricted (neither field starts with "*"), a day matches if EITHER field
// matches; otherwise both must match.
//
// Parse rejects a spec that parses but can never match a real date
// ("0 0 30 2 *"), so a schedule built from it can never be silently dead;
// Reachable answers the same question for a Schedule.
//
// Next computes run times on the wall clock of the location of its argument,
// so schedules follow local time across DST changes. A wall-clock time that
// occurs twice (fall back) runs once. A wall-clock time that does not exist
// (spring forward) runs once, at the instant the platform resolves the
// missing time to: time.Date may map it to either side of the gap depending
// on the zone, so such a run can land in the hour just before the gap
// (America/New_York resolves 02:30 to 01:30 EST) or just after it
// (Europe/Berlin resolves 02:30 to 03:30 CEST). Only schedules that name an
// hour inside a zone's gap are affected, and only on the transition day.
//
// The package is a leaf utility (stdlib only) so any package may import it.
package cron

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule is a parsed cron spec. The zero value matches nothing.
type Schedule struct {
	spec                     string
	minute, hour, dom, month uint64 // bit i set = value i allowed
	dow                      uint64 // bits 0..6 (7 folded onto 0)
	domStar, dowStar         bool
}

// String returns the normalized spec (descriptors expanded).
func (s *Schedule) String() string { return s.spec }

var descriptors = map[string]string{
	"@hourly":   "0 * * * *",
	"@daily":    "0 0 * * *",
	"@midnight": "0 0 * * *",
	"@weekly":   "0 0 * * 0",
	"@monthly":  "0 0 1 * *",
	"@yearly":   "0 0 1 1 *",
	"@annually": "0 0 1 1 *",
}

var monthNames = map[string]int{
	"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
	"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

var dowNames = map[string]int{"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}

type fieldDef struct {
	name     string
	min, max int
	names    map[string]int
}

var fields = [5]fieldDef{
	{"minute", 0, 59, nil},
	{"hour", 0, 23, nil},
	{"day of month", 1, 31, nil},
	{"month", 1, 12, monthNames},
	{"day of week", 0, 7, dowNames},
}

// Parse parses a 5-field spec or a descriptor. Errors name the offending field.
func Parse(spec string) (*Schedule, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return nil, fmt.Errorf("cron: empty schedule")
	}
	if strings.HasPrefix(s, "@") {
		exp, ok := descriptors[strings.ToLower(s)]
		if !ok {
			return nil, fmt.Errorf("cron: unknown descriptor %q (use @hourly, @daily, @weekly, @monthly or @yearly)", s)
		}
		s = exp
	}
	parts := strings.Fields(s)
	if len(parts) != 5 {
		return nil, fmt.Errorf("cron: expected 5 fields (minute hour day-of-month month day-of-week), got %d", len(parts))
	}
	sc := &Schedule{spec: strings.Join(parts, " ")}
	var bits [5]uint64
	for i, p := range parts {
		b, err := parseField(p, fields[i])
		if err != nil {
			return nil, err
		}
		bits[i] = b
	}
	sc.minute, sc.hour, sc.dom, sc.month = bits[0], bits[1], bits[2], bits[3]
	sc.dow = bits[4]
	if sc.dow&(1<<7) != 0 { // 7 = Sunday
		sc.dow = (sc.dow | 1) &^ (1 << 7)
	}
	sc.domStar = strings.HasPrefix(parts[2], "*")
	sc.dowStar = strings.HasPrefix(parts[4], "*")
	if !sc.Reachable() {
		return nil, fmt.Errorf("cron: %q never matches a date (e.g. February 30): it would never run", sc.spec)
	}
	return sc, nil
}

// reachRef is the reference instant of Reachable. It is fixed so that
// Reachable (and therefore Parse) never depends on the current date; any
// window of searchYears contains a leap year, so February 29 is reachable.
var reachRef = time.Date(2001, time.January, 1, 0, 0, 0, 0, time.UTC)

// Reachable reports whether the schedule matches any date at all. A spec
// like "0 0 31 2 *" parses field by field but names a day that never exists,
// which would leave the schedule permanently idle with no error.
func (s *Schedule) Reachable() bool { return !s.Next(reachRef).IsZero() }

// MustParse is Parse that panics on error (for constant specs).
func MustParse(spec string) *Schedule {
	s, err := Parse(spec)
	if err != nil {
		panic(err)
	}
	return s
}

// Valid reports whether spec parses.
func Valid(spec string) bool {
	_, err := Parse(spec)
	return err == nil
}

func parseField(p string, f fieldDef) (uint64, error) {
	var bits uint64
	for _, item := range strings.Split(p, ",") {
		if item == "" {
			return 0, fmt.Errorf("cron: %s: empty list element in %q", f.name, p)
		}
		rng, stepStr, hasStep := strings.Cut(item, "/")
		step := 1
		if hasStep {
			n, err := strconv.Atoi(stepStr)
			if err != nil || n <= 0 || n > f.max {
				return 0, fmt.Errorf("cron: %s: invalid step %q", f.name, stepStr)
			}
			step = n
		}
		var lo, hi int
		switch {
		case rng == "*":
			lo, hi = f.min, f.max
			if f.name == "day of week" {
				hi = 6 // "*" = every day once; 7 would duplicate Sunday
			}
		case strings.Contains(rng, "-"):
			a, b, _ := strings.Cut(rng, "-")
			var err error
			if lo, err = parseValue(a, f); err != nil {
				return 0, err
			}
			if hi, err = parseValue(b, f); err != nil {
				return 0, err
			}
			if lo > hi {
				return 0, fmt.Errorf("cron: %s: range %q is reversed", f.name, rng)
			}
		default:
			v, err := parseValue(rng, f)
			if err != nil {
				return 0, err
			}
			lo, hi = v, v
			if hasStep { // "a/n" = a-max/n
				hi = f.max
			}
		}
		for v := lo; v <= hi; v += step {
			bits |= 1 << uint(v)
		}
	}
	return bits, nil
}

func parseValue(s string, f fieldDef) (int, error) {
	if f.names != nil {
		if v, ok := f.names[strings.ToLower(s)]; ok {
			return v, nil
		}
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("cron: %s: invalid value %q", f.name, s)
	}
	if v < f.min || v > f.max {
		return 0, fmt.Errorf("cron: %s: value %d out of range %d-%d", f.name, v, f.min, f.max)
	}
	return v, nil
}

// searchYears bounds Next: specs that never match (e.g. "0 0 31 2 *") give
// the zero time instead of looping forever.
const searchYears = 8

// Next returns the first activation strictly after t, computed on the wall
// clock of t's location. It returns the zero time when the schedule never
// matches within searchYears (impossible dates such as February 30 — Parse
// rejects those, so only a hand-built Schedule can still hit this).
func (s *Schedule) Next(t time.Time) time.Time {
	if s == nil || s.minute == 0 || s.hour == 0 || s.dom == 0 || s.month == 0 || s.dow == 0 {
		return time.Time{}
	}
	loc := t.Location()
	// Start at the next whole wall-clock minute after t.
	y, mo, d := t.Date()
	h, mi := t.Hour(), t.Minute()+1
	limit := y + searchYears
	for {
		// Normalize the civil fields (pure calendar arithmetic, no zones).
		if mi > 59 {
			mi = 0
			h++
		}
		if h > 23 {
			h = 0
			d++
		}
		if d > daysIn(y, mo) {
			d = 1
			mo++
		}
		if mo > 12 {
			mo = 1
			y++
		}
		if y > limit {
			return time.Time{}
		}
		switch {
		case s.month&(1<<uint(mo)) == 0:
			mo++
			d, h, mi = 1, 0, 0
			continue
		case !s.dayMatches(y, mo, d):
			d++
			h, mi = 0, 0
			continue
		case s.hour&(1<<uint(h)) == 0:
			h++
			mi = 0
			continue
		case s.minute&(1<<uint(mi)) == 0:
			mi++
			continue
		}
		inst := time.Date(y, mo, d, h, mi, 0, 0, loc)
		if inst.After(t) {
			return inst
		}
		// An ambiguous wall-clock time resolved to an instant at or before t
		// (DST fall-back): keep searching from the next minute.
		mi++
	}
}

func (s *Schedule) dayMatches(y int, mo time.Month, d int) bool {
	domOK := s.dom&(1<<uint(d)) != 0
	wd := time.Date(y, mo, d, 12, 0, 0, 0, time.UTC).Weekday()
	dowOK := s.dow&(1<<uint(wd)) != 0
	if s.domStar || s.dowStar {
		return domOK && dowOK
	}
	return domOK || dowOK
}

func daysIn(y int, mo time.Month) int {
	return time.Date(y, mo+1, 0, 12, 0, 0, 0, time.UTC).Day()
}
