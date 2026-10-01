package cli

import (
	"crypto/x509"
	"testing"
	"time"
)

// The leaf is reported once its automatic renewal is overdue (half of
// min(30 days, a third of its lifetime), like certs.renewBefore, at most 14
// days): a healthy short-lived leaf (tls.leaf_days = 7) is not "expiring"
// all the time. The thresholds are the server doctor's (the CA: 90 days),
// whose cert checks the local ones replace.
func TestCertWarnBeforeFollowsLeafLifetime(t *testing.T) {
	day := 24 * time.Hour
	nb := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	cert := func(span time.Duration) *x509.Certificate {
		return &x509.Certificate{NotBefore: nb, NotAfter: nb.Add(span)}
	}
	tests := []struct {
		id   string
		c    *x509.Certificate
		want time.Duration
	}{
		{"cert.leaf", cert(397 * day), 14 * day},
		{"cert.leaf", cert(7 * day), 7 * day / 6},
		{"cert.leaf", cert(60 * day), 10 * day},
		{"cert.leaf", &x509.Certificate{NotAfter: nb}, 14 * day}, // no lifetime known
		{"cert.ca", cert(7 * day), 90 * day},
		{"cert.ca", cert(10 * 365 * day), 90 * day},
	}
	for _, tt := range tests {
		if got := certWarnBefore(tt.id, tt.c); got != tt.want {
			t.Errorf("%s over %v: %v, want %v", tt.id, tt.c.NotAfter.Sub(tt.c.NotBefore), got, tt.want)
		}
	}
}
