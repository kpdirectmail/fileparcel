package keys

import (
	"errors"
	"strings"
)

// Recovery keys (DESIGN §7.2): 256 random bits written as "FPRK-" followed by
// 52 uppercase Crockford base32 characters in 13 groups of 4, e.g.
//
//	FPRK-7K3M-Q2ZD-…-W8A0
//
// The last character carries 1 data bit and 4 zero padding bits. Parsing is
// case-insensitive, ignores dashes and white space and applies the Crockford
// substitutions (O→0, I/L→1).

const (
	recoveryPrefix  = "FPRK"
	recoveryChars   = 52 // ceil(256/5)
	recoveryGroup   = 4
	recoveryRawSize = 32
	crockfordUpper  = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

var errNotRecoveryKey = errors.New("not a recovery key")

// formatRecoveryKey encodes 32 raw bytes.
func formatRecoveryKey(raw []byte) string {
	if len(raw) != recoveryRawSize {
		panic("keys: recovery key must be 32 bytes")
	}
	var chars [recoveryChars]byte
	var acc uint32
	bits := 0
	n := 0
	for _, b := range raw {
		acc = acc<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			chars[n] = crockfordUpper[(acc>>(bits-5))&31]
			n++
			bits -= 5
		}
	}
	if bits > 0 { // 256 = 51*5 + 1 → one bit left, padded with zeros
		chars[n] = crockfordUpper[(acc<<(5-bits))&31]
		n++
	}
	var sb strings.Builder
	sb.Grow(len(recoveryPrefix) + recoveryChars + recoveryChars/recoveryGroup)
	sb.WriteString(recoveryPrefix)
	for i := 0; i < n; i += recoveryGroup {
		sb.WriteByte('-')
		sb.Write(chars[i:min(i+recoveryGroup, n)])
	}
	return sb.String()
}

// parseRecoveryKey decodes a recovery key string into its 32 raw bytes
// (caller zeroes the result). It returns errNotRecoveryKey for anything that
// is not a well-formed recovery key.
func parseRecoveryKey(s []byte) ([]byte, error) {
	var clean []byte
	for _, c := range s {
		switch {
		case c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n':
			continue
		case c >= 'a' && c <= 'z':
			c -= 'a' - 'A'
		}
		clean = append(clean, c)
	}
	defer clear(clean)
	if len(clean) != len(recoveryPrefix)+recoveryChars || string(clean[:len(recoveryPrefix)]) != recoveryPrefix {
		return nil, errNotRecoveryKey
	}
	out := make([]byte, 0, recoveryRawSize)
	var acc uint32
	bits := 0
	for i, c := range clean[len(recoveryPrefix):] {
		switch c {
		case 'O':
			c = '0'
		case 'I', 'L':
			c = '1'
		}
		v := strings.IndexByte(crockfordUpper, c)
		if v < 0 {
			clear(out)
			return nil, errNotRecoveryKey
		}
		acc = acc<<5 | uint32(v)
		bits += 5
		if bits >= 8 {
			out = append(out, byte(acc>>(bits-8)))
			bits -= 8
		}
		if i == recoveryChars-1 && acc&((1<<bits)-1) != 0 { // padding bits must be zero
			clear(out)
			return nil, errNotRecoveryKey
		}
	}
	if len(out) != recoveryRawSize {
		clear(out)
		return nil, errNotRecoveryKey
	}
	return out, nil
}
