package authtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

var b64 = base64.RawURLEncoding

// Authenticator is a software WebAuthn authenticator (ES256, "none"
// attestation, discoverable credentials) that answers the options produced
// by go-webauthn the way a browser would (PublicKeyCredential JSON).
type Authenticator struct {
	// Origin is put into clientDataJSON (e.g. "https://fileparcel.local:8443").
	Origin string
	// UV sets the user-verified flag in the authenticator data.
	UV bool
	// FreezeCounter keeps the signature counter at its current value
	// (simulates a cloned authenticator when it is non-zero).
	FreezeCounter bool

	mu    sync.Mutex
	creds []*swCredential
}

type swCredential struct {
	id         []byte
	key        *ecdsa.PrivateKey
	rpID       string
	userHandle []byte
	counter    uint32
}

// Credentials returns the number of credentials held.
func (a *Authenticator) Credentials() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.creds)
}

type creationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Exclude []struct {
			ID string `json:"id"`
		} `json:"excludeCredentials"`
	} `json:"publicKey"`
}

type requestOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
		Allow     []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	} `json:"publicKey"`
}

func (a *Authenticator) flags(extra protocol.AuthenticatorFlags) byte {
	f := protocol.FlagUserPresent | extra
	if a.UV {
		f |= protocol.FlagUserVerified
	}
	return byte(f)
}

func authData(rpID string, flags byte, counter uint32, attested []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, h[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, counter)
	return append(out, attested...)
}

func (a *Authenticator) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.Origin, "crossOrigin": false})
	return b
}

// Create answers navigator.credentials.create() options ({"publicKey":…})
// with a registration response.
func (a *Authenticator) Create(options []byte) ([]byte, error) {
	var o creationOptions
	if err := json.Unmarshal(options, &o); err != nil {
		return nil, err
	}
	userHandle, err := b64.DecodeString(o.PublicKey.User.ID)
	if err != nil {
		return nil, fmt.Errorf("user.id: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, ex := range o.PublicKey.Exclude {
		for _, c := range a.creds {
			if b64.EncodeToString(c.id) == ex.ID {
				return nil, fmt.Errorf("authtest: credential already registered (excluded)")
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pub, err := key.PublicKey.ECDH()
	if err != nil {
		return nil, err
	}
	pt := pub.Bytes() // 0x04 || X || Y
	cose, err := webauthncbor.Marshal(map[int64]any{
		1:  int64(webauthncose.EllipticKey),
		3:  int64(webauthncose.AlgES256),
		-1: int64(webauthncose.P256),
		-2: pt[1:33],
		-3: pt[33:65],
	})
	if err != nil {
		return nil, err
	}
	c := &swCredential{id: make([]byte, 32), key: key, rpID: o.PublicKey.RP.ID, userHandle: userHandle}
	_, _ = rand.Read(c.id)
	attested := make([]byte, 16) // zero AAGUID
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(c.id)))
	attested = append(attested, c.id...)
	attested = append(attested, cose...)
	ad := authData(c.rpID, a.flags(protocol.FlagAttestedCredentialData), 0, attested)
	att, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": ad})
	if err != nil {
		return nil, err
	}
	a.creds = append(a.creds, c)
	id := b64.EncodeToString(c.id)
	return json.Marshal(map[string]any{
		"id": id, "rawId": id, "type": "public-key", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"attestationObject": b64.EncodeToString(att),
			"clientDataJSON":    b64.EncodeToString(a.clientData("webauthn.create", o.PublicKey.Challenge)),
			"transports":        []string{"internal"},
		},
	})
}

// Get answers navigator.credentials.get() options with an assertion from
// the first matching credential (allowCredentials, else any credential of
// the RP — discoverable).
func (a *Authenticator) Get(options []byte) ([]byte, error) {
	var o requestOptions
	if err := json.Unmarshal(options, &o); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var c *swCredential
	for _, cand := range a.creds {
		if cand.rpID != o.PublicKey.RPID {
			continue
		}
		if len(o.PublicKey.Allow) == 0 {
			c = cand
			break
		}
		for _, al := range o.PublicKey.Allow {
			if al.ID == b64.EncodeToString(cand.id) {
				c = cand
			}
		}
		if c != nil {
			break
		}
	}
	if c == nil {
		return nil, ErrNoCredential
	}
	if !a.FreezeCounter {
		c.counter++
	}
	ad := authData(c.rpID, a.flags(0), c.counter, nil)
	cd := a.clientData("webauthn.get", o.PublicKey.Challenge)
	cdh := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, c.key, digest[:])
	if err != nil {
		return nil, err
	}
	id := b64.EncodeToString(c.id)
	return json.Marshal(map[string]any{
		"id": id, "rawId": id, "type": "public-key", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"authenticatorData": b64.EncodeToString(ad),
			"clientDataJSON":    b64.EncodeToString(cd),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(c.userHandle),
		},
	})
}
