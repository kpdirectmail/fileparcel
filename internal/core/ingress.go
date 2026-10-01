package core

import (
	"context"
	"net/netip"
	"time"
)

// Tailscale Funnel and Serve (DESIGN §10.6). tailscaled terminates TLS for
// <node>.<tailnet>.ts.net and proxies to a dedicated FileParcel ingress
// listener: Funnel from the internet, Serve from the tailnet. The Ingress
// service (package tsingress) configures tailscaled; the server's ingress
// listeners (IngressListeners) mark every request they accept with an
// IngressInfo in its context (WithIngress), which the middleware uses to
// apply the ingress policy (IngressPolicy).

// Ingress kinds (IngressInfo.Kind, IngressEntry.Kind, ReqMeta.Ingress).
const (
	IngressFunnel = "funnel"
	IngressServe  = "serve"
)

// Funnel modes (funnel.mode; IngressEntry.Mode and IngressPolicy.Mode, where
// Serve uses FunnelOff and FunnelApp).
const (
	FunnelOff    = "off"
	FunnelShares = "shares" // share links and file requests only
	FunnelApp    = "app"    // the whole app (sign-in over the internet)
)

// Ingress entry states (IngressEntry.State).
const (
	IngressStateOff         = "off"
	IngressStateActive      = "active"
	IngressStateStopped     = "stopped"     // enabled, the server is not running
	IngressStateDrift       = "drift"       // tailscaled no longer carries the owned entry
	IngressStateConflict    = "conflict"    // a foreign Serve/Funnel entry holds the port
	IngressStatePaused      = "paused"      // enabled on another node (funnel.node)
	IngressStateUnavailable = "unavailable" // tailscaled unreachable or not capable
	IngressStateError       = "error"
)

// IngressCheck is one prerequisite check of an ingress entry.
type IngressCheck struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Status  string `json:"status"` // ok|warn|fail|skip
	Message string `json:"message,omitempty"`
	Hint    string `json:"hint,omitempty"`
	FixURL  string `json:"fix_url,omitempty"`
}

// IngressEntry is the state of Funnel or Serve.
type IngressEntry struct {
	Kind                string         `json:"kind"` // funnel|serve
	Mode                string         `json:"mode"` // funnel: off|shares|app; serve: off|app
	Port                int            `json:"port"` // public (Funnel) or tailnet (Serve) HTTPS port
	HostPort            string         `json:"host_port,omitempty"`
	URL                 string         `json:"url,omitempty"`     // https://name[:port]/
	Backend             string         `json:"backend,omitempty"` // unix:/…/run/ts-funnel.sock | http://127.0.0.1:18443
	State               string         `json:"state"`             // IngressState* constants
	Message             string         `json:"message,omitempty"`
	AppliedAt           *time.Time     `json:"applied_at,omitempty"`
	LastRequestAt       *time.Time     `json:"last_request_at,omitempty"`
	LastPublicRequestAt *time.Time     `json:"last_public_request_at,omitempty"` // Tailscale-Funnel-Request seen
	ProbedAt            *time.Time     `json:"probed_at,omitempty"`
	Checks              []IngressCheck `json:"checks"`
}

// ForeignServe is a Serve/Funnel entry of tailscaled that FileParcel did not create.
type ForeignServe struct {
	HostPort   string `json:"host_port"`
	Mount      string `json:"mount,omitempty"`
	Target     string `json:"target"`
	Funnel     bool   `json:"funnel"`
	Foreground bool   `json:"foreground"`
	Service    string `json:"service,omitempty"`
	Bypass     bool   `json:"bypass"` // targets FileParcel's main port or admin socket
}

// IngressStatus is GET /admin/network/tailscale and the answer of the
// Funnel/Serve write routes.
type IngressStatus struct {
	Available   bool           `json:"available"`
	Reason      string         `json:"reason,omitempty"`
	Transport   string         `json:"transport"` // localapi|cli|none
	Funnel      IngressEntry   `json:"funnel"`
	Serve       IngressEntry   `json:"serve"`
	FunnelPorts []int          `json:"funnel_ports"` // usable: cap ∩ {443,8443,10000} − own ports
	AllowAdmin  bool           `json:"allow_admin"`
	Require2FA  bool           `json:"require_2fa"`
	Foreign     []ForeignServe `json:"foreign"`
	Tailscale   *TailscaleInfo `json:"tailscale,omitempty"`
}

// FunnelInput is PUT /admin/network/funnel (E).
type FunnelInput struct {
	Mode       string `json:"mode"`           // off|shares|app
	Port       int    `json:"port,omitempty"` // 0 = keep current
	AllowAdmin *bool  `json:"allow_admin,omitempty"`
	Require2FA *bool  `json:"require_2fa,omitempty"`
	// Confirm must be "public" for: off→shares|app, shares→app, allow_admin
	// false→true, require_2fa true→false.
	Confirm string `json:"confirm,omitempty"`
}

// ServeInput is PUT /admin/network/serve (E).
type ServeInput struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port,omitempty"` // 0 = keep current
}

// IngressInfo describes a request that arrived through a Tailscale ingress
// listener (set by the listener's handler, read with IngressFrom).
type IngressInfo struct {
	Kind     string     // IngressFunnel | IngressServe
	ClientIP netip.Addr // validated X-Forwarded-For
	Public   bool       // Tailscale-Funnel-Request: ?1 seen
	Host     string     // canonical host[:port]
	TSUser   string     // serve only; log field
}

type ingressKey struct{}

// WithIngress stores in in ctx.
func WithIngress(ctx context.Context, in *IngressInfo) context.Context {
	return context.WithValue(ctx, ingressKey{}, in)
}

// IngressFrom returns the ingress of the request whose context is ctx, or
// nil for a direct connection.
func IngressFrom(ctx context.Context) *IngressInfo {
	in, _ := ctx.Value(ingressKey{}).(*IngressInfo)
	return in
}

// IPLimitKey is the rate-limit key of a client address: for an IPv6 address
// of an internet client (internet: the request came over Funnel) the /64
// prefix ("2001:db8:1:2::/64"), since one client controls a whole /64;
// otherwise the address itself (IPv4-mapped IPv6 unmapped, zone dropped), as
// LAN and tailnet devices may share a /64.
func IPLimitKey(ip netip.Addr, internet bool) string {
	ip = ip.Unmap().WithZone("")
	if internet && ip.Is6() {
		return netip.PrefixFrom(ip, 64).Masked().String()
	}
	return ip.String()
}

// IngressPolicy is what an open ingress listener enforces (Ingress.Policy;
// read on every request, lock-free).
type IngressPolicy struct {
	Mode       string // funnel: off|shares|app; serve: off|app — what the open listener enforces
	DNSName    string
	Port       int
	AllowAdmin bool
	Require2FA bool
}

// Ingress configures Tailscale Funnel and Serve (package tsingress, DESIGN
// §10.6). Deps.Ingress is nil until that package is wired; every user
// nil-checks it.
type Ingress interface {
	Status(ctx context.Context, refresh bool) (*IngressStatus, error)
	SetFunnel(ctx context.Context, by *Principal, in FunnelInput) (*IngressStatus, error)
	SetServe(ctx context.Context, by *Principal, in ServeInput) (*IngressStatus, error)
	Reapply(ctx context.Context, by *Principal) (*IngressStatus, error)
	RemoveAll(ctx context.Context, by *Principal, reason string) error
	Start(ctx context.Context) error // subscribe + load; no writes
	Attach(l IngressListeners)       // server.Run, after listen: first reconcile (async)
	Detach(ctx context.Context)      // server shutdown: suspend TCP-backend entries
	// lock-free hot path
	Policy(kind string) IngressPolicy
	CheckProbe(kind, nonce string) bool
	Note(kind string, public, conflict bool)
	PublicBaseURL() string // "" unless Funnel shares|app is active
	InternetLinks() bool
	AccessURLs() []AccessURL
}

// IngressListeners opens and closes the ingress listeners tailscaled
// connects to (implemented by package server).
type IngressListeners interface {
	Open(kind, network, address string, peerUIDs []int) error
	Close(kind string)
}
