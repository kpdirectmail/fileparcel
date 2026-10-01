package opsapi

import (
	"time"

	"fileparcel/internal/core"
)

// CertWarnBefore is how close to its expiry the doctor calls the local CA
// (ca) or the local server certificate expiring: caWarn, or leafWarn for a
// leaf valid from notBefore to notAfter. `fileparcel doctor` uses it for its
// on-disk certificate checks, which replace this package's cert.ca and
// cert.leaf checks in its report, so both doctors apply the same thresholds.
func CertWarnBefore(ca bool, notBefore, notAfter time.Time) time.Duration {
	if ca {
		return caWarn
	}
	return leafWarn(&core.CertInfo{NotBefore: notBefore, NotAfter: notAfter})
}
