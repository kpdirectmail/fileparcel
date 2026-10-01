package mw

import (
	"testing"

	"fileparcel/internal/ratelimit"
)

// TestLoginStartBucketNames: the login_start bucket and its /64 aggregate
// are the ratelimit package's (TestBucketNames checks that the registry
// configures every aggregate of netBuckets).
func TestLoginStartBucketNames(t *testing.T) {
	if BucketLoginStart != ratelimit.BucketLoginStart || BucketLoginStartNet != ratelimit.BucketLoginStartNet {
		t.Fatal("mw.BucketLoginStart* constants drifted from ratelimit.BucketLoginStart*")
	}
	if netBuckets[BucketLoginStart] != BucketLoginStartNet {
		t.Fatal("login_start has no per-/64 aggregate")
	}
}
