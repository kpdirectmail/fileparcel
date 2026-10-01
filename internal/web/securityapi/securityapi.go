// Package securityapi owns certificates, client certificates, keys, system
// unlock/status and the trust downloads (DESIGN §9.4, unit F).
//
// Mount (under /api/v1). Cap(certs.manage) = mw.RequireCap(core.CapCertsManage)
// (owners and admins hold it; API tokens need the admin scope); Adm =
// mw.RequireAdmin (built-in owners/admins only: uploading a custom
// certificate means knowing the private key of the served certificate, and
// the key routes are the master key); E = elevated:
//
//	GET    /admin/certs                      Cap(certs.manage) → core.CertStatus + uncovered_names
//	POST   /admin/certs/renew {force}        Cap(certs.manage) → core.CertStatus + uncovered_names
//	POST   /admin/certs/ca/regenerate {unconstrained}  Cap(certs.manage), E → core.CertStatus
//	PUT    /admin/certs/custom {cert_pem,key_pem}      (Adm, E) → core.CertStatus
//	DELETE /admin/certs/custom               (Adm, E) → core.CertStatus
//	POST   /admin/certs/acme/apply           Cap(certs.manage), E → core.CertStatus
//	POST   /admin/certs/tailscale/fetch      Cap(certs.manage) → core.CertStatus
//	GET    /admin/client-certs?user_id=      Cap(certs.manage) → core.Page[core.ClientCert]
//	POST   /admin/client-certs               Cap(certs.manage), E; core.ClientCertInput → ClientCertIssued, p12 once
//	GET    /admin/client-certs/download?ticket=  Cap(certs.manage); one-time .p12 download
//	DELETE /admin/client-certs/{id}?reason=  Cap(certs.manage)
//	GET    /admin/keys                       (Adm) → core.KeyStatus
//	POST   /admin/keys/lock                  (Adm, E)
//	POST   /admin/keys/seal|unseal           (Adm, E; core.PassphraseInput)
//	POST   /admin/keys/passphrase            (Adm, E; core.PassphraseChangeInput)
//	POST   /admin/keys/rotate                (Adm, E; core.KeysRotateInput → core.JobRef | core.KeyStatus)
//	POST   /admin/keys/recovery              (Adm, E) → core.RecoveryKey (shown once)
//	GET    /me/client-certs                  (F) → core.Page[core.ClientCert] (own)
//	POST   /me/client-certs                  (F, no API tokens; only if mtls.self_service) → ClientCertIssued
//	GET    /me/client-certs/download?ticket= (F; one-time .p12 download)
//	DELETE /me/client-certs/{id}             (F; own certificates)
//	GET    /system/status                    public → core.SystemStatus
//	POST   /system/unlock {passphrase}       public, only when locked; rate limit "unlock" per IP;
//	                                         network per keys.web_unlock (lan = private ranges and the
//	                                         global IPv6 subnets of the server's own interfaces)
//
// Every certificate route answers with core.CertStatus plus "uncovered_names":
// the names that are wanted in the local leaf but the local CA may not sign
// (its name constraints) — they are dropped from the certificate without a
// reissue or an error, while the access URLs and the strict Host check still
// advertise them.
//
// MountRoot:
//
//	GET /trust/ca.crt   GET /trust/ca.pem   GET /trust/ca.mobileconfig
//
// Key rotation: target "kek" enqueues the keys.rotate_kek job and "data" the
// keys.reencrypt job (both registered by the keys unit) and answer 202 with
// core.JobRef; "master" runs synchronously (and so does "kek" in the
// in-process CLI, which has no job runner).
//
// Audit: the key and certificate services record their own actions (keys.*,
// cert.*, ca.regenerate, client_cert.*). Handlers add only what the services
// cannot see: the queuing of a rotation job (keys.rotate, phase "queued",
// attributed to the administrator — the job runs as the system principal)
// and unlock attempts refused by keys.web_unlock (keys.unlock, outcome
// denied). Anonymous unlock attempts reach the key service with a
// rights-less context principal that carries the client address, user
// agent and request id for the audit log.
package securityapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// Body limits.
const (
	maxCustomBody = 128 << 10 // PEM chain + key
	maxSmallBody  = 16 << 10
)

// api bundles the handlers and their state.
type api struct {
	d   *app.Deps
	p12 *p12Store
}

// Mount registers this package's routes on the /api/v1 router.
func Mount(r chi.Router, d *app.Deps) {
	a := &api{d: d, p12: newP12Store()}

	r.Group(func(r chi.Router) {
		r.Use(mw.RequireCap(core.CapCertsManage), mw.NoStore)
		r.Get("/admin/certs", a.certStatus)
		r.With(mw.MaxBody(maxSmallBody)).Post("/admin/certs/renew", a.certRenew)
		r.Post("/admin/certs/tailscale/fetch", a.certTailscale)
		r.Get("/admin/client-certs", a.adminClientList)
		r.Get("/admin/client-certs/download", a.clientDownload)
		r.Delete("/admin/client-certs/{id}", a.adminClientRevoke)

		r.Group(func(r chi.Router) {
			r.Use(mw.RequireElevated)
			r.With(mw.MaxBody(maxSmallBody)).Post("/admin/certs/ca/regenerate", a.caRegenerate)
			r.Post("/admin/certs/acme/apply", a.acmeApply)
			r.With(mw.MaxBody(maxSmallBody)).Post("/admin/client-certs", a.adminClientIssue)
		})
	})

	r.Group(func(r chi.Router) {
		r.Use(mw.RequireAdmin, mw.NoStore)
		r.Get("/admin/keys", a.keysStatus)

		r.Group(func(r chi.Router) {
			r.Use(mw.RequireElevated)
			r.With(mw.MaxBody(maxCustomBody)).Put("/admin/certs/custom", a.customSet)
			r.Delete("/admin/certs/custom", a.customClear)
			r.Post("/admin/keys/lock", a.keysLock)
			r.With(mw.MaxBody(maxSmallBody)).Post("/admin/keys/seal", a.keysSeal)
			r.With(mw.MaxBody(maxSmallBody)).Post("/admin/keys/unseal", a.keysUnseal)
			r.With(mw.MaxBody(maxSmallBody)).Post("/admin/keys/passphrase", a.keysPassphrase)
			r.With(mw.MaxBody(maxSmallBody)).Post("/admin/keys/rotate", a.keysRotate)
			r.Post("/admin/keys/recovery", a.keysRecovery)
		})
	})

	r.Group(func(r chi.Router) {
		r.Use(mw.RequireFull, mw.NoStore)
		r.Get("/me/client-certs", a.meClientList)
		r.With(noTokens, mw.MaxBody(maxSmallBody)).Post("/me/client-certs", a.meClientIssue)
		r.Get("/me/client-certs/download", a.clientDownload)
		r.Delete("/me/client-certs/{id}", a.meClientRevoke)
	})

	r.Group(func(r chi.Router) {
		r.Use(mw.NoStore)
		r.Get("/system/status", a.systemStatus)
		r.With(mw.RateLimit(mw.BucketUnlock, mw.PerIP), mw.MaxBody(maxSmallBody)).Post("/system/unlock", a.systemUnlock)
	})
}

// MountRoot registers this package's routes on the root router.
func MountRoot(r chi.Router, d *app.Deps) {
	a := &api{d: d}
	r.Group(func(r chi.Router) {
		r.Get("/trust/ca.crt", a.trustDownload("der"))
		r.Get("/trust/ca.pem", a.trustDownload("pem"))
		r.Get("/trust/ca.mobileconfig", a.trustDownload("mobileconfig"))
	})
}

// noTokens refuses API-token principals, like the credential-management
// routes of meapi: a client certificate is a network-layer credential that
// outlives and outranks the token's scopes, so issuing one needs a browser
// session or the admin socket (DESIGN §9.4).
func noTokens(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := mw.Principal(r); p != nil && p.Via == core.ViaToken {
			httpx.Error(w, r, core.Errorf(core.ErrForbidden, "not available with API tokens; use the web interface or the admin socket"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handlerFunc is the shape of every handler here.
type handlerFunc = func(http.ResponseWriter, *http.Request)
