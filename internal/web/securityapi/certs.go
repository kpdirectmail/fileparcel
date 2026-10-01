package securityapi

import (
	"net/http"
	"strconv"

	"fileparcel/internal/core"
	"fileparcel/internal/web/httpx"
	"fileparcel/internal/web/mw"
)

// Request shapes of the certificate routes. They live in core (the API
// contract) and are aliased here so the handlers keep their short names.
type (
	// RenewInput is POST /admin/certs/renew (all fields optional).
	RenewInput = core.CertRenewInput
	// RegenerateCAInput is POST /admin/certs/ca/regenerate. Unconstrained
	// drops the CA's name constraints (it can then sign for any name; warned).
	RegenerateCAInput = core.CARegenerateInput
	// CustomCertInput is PUT /admin/certs/custom: the PEM chain (server
	// certificate first) and its unencrypted PEM private key.
	CustomCertInput = core.CustomCertInput
)

func (a *api) certs() (core.Certs, error) {
	if a.d == nil || a.d.Certs == nil {
		return nil, core.Wrap(core.ErrUnavailable, "the certificate service is unavailable", nil)
	}
	return a.d.Certs, nil
}

// uncoveredNamer is implemented by the certificate service: the names that
// are wanted in the local leaf but the local CA may not sign (its name
// constraints) or that exceed the SAN limit.
type uncoveredNamer interface{ UncoveredNames() []string }

// certStatusView is the GET /admin/certs body: core.CertStatus plus the names
// the local certificate does not cover. Without it, a name added to
// tls.extra_sans or network.extra_hosts that the CA may not sign disappears
// without a trace — no reissue, no error, nothing in the status — while the
// access URLs and the strict-Host allowlist still advertise it.
type certStatusView struct {
	*core.CertStatus
	UncoveredNames []string `json:"uncovered_names,omitempty"`
}

// writeStatus answers with the current certificate status.
func (a *api) writeStatus(w http.ResponseWriter, r *http.Request, status int) {
	c, err := a.certs()
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	st, err := c.Status(r.Context())
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	view := certStatusView{CertStatus: st}
	if u, ok := c.(uncoveredNamer); ok {
		view.UncoveredNames = u.UncoveredNames()
	}
	httpx.JSON(w, status, view)
}

// certStatus is GET /admin/certs.
func (a *api) certStatus(w http.ResponseWriter, r *http.Request) {
	a.writeStatus(w, r, http.StatusOK)
}

// certRenew is POST /admin/certs/renew: reissues the local leaf (when needed,
// or always with force — from the body or the ?force= query parameter).
func (a *api) certRenew(w http.ResponseWriter, r *http.Request) {
	in, err := httpx.Decode[RenewInput](r, maxSmallBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	if q := r.URL.Query().Get("force"); q != "" {
		f, perr := strconv.ParseBool(q)
		if perr != nil {
			httpx.Error(w, r, core.Invalid("force", "force must be true or false"))
			return
		}
		in.Force = in.Force || f
	}
	c, err := a.certs()
	if err == nil {
		err = c.RenewLocal(r.Context(), in.Force)
	}
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	a.writeStatus(w, r, http.StatusOK)
}

// caRegenerate is POST /admin/certs/ca/regenerate (E).
func (a *api) caRegenerate(w http.ResponseWriter, r *http.Request) {
	in, err := httpx.Decode[RegenerateCAInput](r, maxSmallBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	c, err := a.certs()
	if err == nil {
		err = c.RegenerateCA(r.Context(), mw.Principal(r), !in.Unconstrained)
	}
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	a.writeStatus(w, r, http.StatusOK)
}

// customSet is PUT /admin/certs/custom (E).
func (a *api) customSet(w http.ResponseWriter, r *http.Request) {
	in, err := httpx.Decode[CustomCertInput](r, maxCustomBody)
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	c, err := a.certs()
	if err == nil {
		err = c.SetCustom(r.Context(), mw.Principal(r), []byte(in.CertPEM), []byte(in.KeyPEM))
	}
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	a.writeStatus(w, r, http.StatusOK)
}

// customClear is DELETE /admin/certs/custom (E).
func (a *api) customClear(w http.ResponseWriter, r *http.Request) {
	c, err := a.certs()
	if err == nil {
		err = c.ClearCustom(r.Context(), mw.Principal(r))
	}
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	a.writeStatus(w, r, http.StatusOK)
}

// acmeApply is POST /admin/certs/acme/apply (E): (re)applies the acme.*
// settings; obtaining runs in the background (see acme_error in the status).
func (a *api) acmeApply(w http.ResponseWriter, r *http.Request) {
	c, err := a.certs()
	if err == nil {
		err = c.ApplyACME(r.Context())
	}
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	a.writeStatus(w, r, http.StatusAccepted)
}

// certTailscale is POST /admin/certs/tailscale/fetch.
func (a *api) certTailscale(w http.ResponseWriter, r *http.Request) {
	c, err := a.certs()
	if err == nil {
		err = c.FetchTailscale(r.Context())
	}
	if err != nil {
		httpx.Error(w, r, err)
		return
	}
	a.writeStatus(w, r, http.StatusOK)
}
