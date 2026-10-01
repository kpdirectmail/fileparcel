package clikit

import (
	"context"
	"time"
)

// Backoff configures Retry: the first retry waits Initial, every further one
// doubles up to Max; at most Attempts calls are made (>= 1).
type Backoff struct {
	Initial  time.Duration
	Max      time.Duration
	Attempts int
}

// TransferBackoff is the policy of the upload protocol (DESIGN §8.1):
// exponential backoff 1s → 30s, 6 tries.
var TransferBackoff = Backoff{Initial: time.Second, Max: 30 * time.Second, Attempts: 6}

// Retry calls fn until it succeeds, returns an error for which retryable is
// false, the attempts are exhausted, or ctx is done (then ctx's error is
// returned only if fn never produced one). attempt starts at 1.
func Retry(ctx context.Context, b Backoff, retryable func(error) bool, fn func(attempt int) error) error {
	if b.Attempts < 1 {
		b.Attempts = 1
	}
	delay := b.Initial
	var err error
	for attempt := 1; ; attempt++ {
		if cerr := ctx.Err(); cerr != nil {
			if err != nil {
				return err
			}
			return cerr
		}
		err = fn(attempt)
		if err == nil || attempt >= b.Attempts || (retryable != nil && !retryable(err)) {
			return err
		}
		if ctx.Err() != nil {
			return err
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return err
		case <-t.C:
		}
		delay *= 2
		if b.Max > 0 && delay > b.Max {
			delay = b.Max
		}
	}
}
