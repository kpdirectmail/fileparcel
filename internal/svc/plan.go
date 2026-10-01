package svc

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// Plan is an ordered list of install/upgrade/uninstall steps. The same plan
// is printed by --dry-run and executed otherwise, so the dry-run output is
// exactly what would happen.
type Plan struct {
	Title string
	Facts [][2]string // key/value summary lines printed before the steps
	Steps []Step
	Notes []string // printed after the steps (warnings, hints)
}

// Step is one plan entry. Run may be nil for informational steps.
type Step struct {
	Title  string
	Detail []string // extra lines (commands, paths) shown in dry runs
	Run    func(ctx context.Context) error
}

// Fact adds a summary line.
func (p *Plan) Fact(key, value string) { p.Facts = append(p.Facts, [2]string{key, value}) }

// Add appends a step.
func (p *Plan) Add(title string, run func(ctx context.Context) error, detail ...string) {
	p.Steps = append(p.Steps, Step{Title: title, Run: run, Detail: detail})
}

// Note appends a closing note.
func (p *Plan) Note(format string, a ...any) { p.Notes = append(p.Notes, fmt.Sprintf(format, a...)) }

// Print writes the plan (dry run).
func (p *Plan) Print(w io.Writer) error {
	var b strings.Builder
	if p.Title != "" {
		b.WriteString(p.Title + "\n\n")
	}
	width := 0
	for _, f := range p.Facts {
		width = max(width, len(f[0]))
	}
	for _, f := range p.Facts {
		fmt.Fprintf(&b, "  %-*s  %s\n", width+1, f[0]+":", f[1])
	}
	if len(p.Facts) > 0 {
		b.WriteString("\n")
	}
	b.WriteString("Steps:\n")
	for i, s := range p.Steps {
		fmt.Fprintf(&b, "  %2d. %s\n", i+1, s.Title)
		for _, d := range s.Detail {
			fmt.Fprintf(&b, "        %s\n", d)
		}
	}
	for _, n := range p.Notes {
		b.WriteString("\n" + n + "\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// Execute runs the steps in order, printing "[i/n] title" to w before
// each; it stops at the first error (wrapped with the step title).
func (p *Plan) Execute(ctx context.Context, w io.Writer) error {
	n := len(p.Steps)
	for i, s := range p.Steps {
		if err := ctx.Err(); err != nil {
			return err
		}
		if w != nil {
			fmt.Fprintf(w, "[%d/%d] %s\n", i+1, n, s.Title)
		}
		if s.Run == nil {
			continue
		}
		if err := s.Run(ctx); err != nil {
			return fmt.Errorf("%s: %w", s.Title, err)
		}
	}
	return nil
}
