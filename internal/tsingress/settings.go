package tsingress

import (
	"errors"
	"slices"

	"fileparcel/internal/core"
	"fileparcel/internal/settings"
	"fileparcel/internal/tslocal"
)

// Setting keys of the section "funnel" (DESIGN §11.2).
const (
	KeyMode        = "funnel.mode"
	KeyPort        = "funnel.port"
	KeyAllowAdmin  = "funnel.allow_admin"
	KeyRequire2FA  = "funnel.require_2fa"
	KeyServe       = "funnel.serve"
	KeyServePort   = "funnel.serve_port"
	KeyNode        = "funnel.node"
	KeyBackend     = "funnel.backend"
	KeyBackendPort = "funnel.backend_port"
)

// Routes that own the managed keys (settings.Def.Managed): PATCH and DELETE
// /admin/settings refuse those keys with 409; the service stores them.
const (
	ManagedFunnel = "PUT /api/v1/admin/network/funnel"
	ManagedServe  = "PUT /api/v1/admin/network/serve"
)

// Backends: how tailscaled reaches FileParcel (funnel.backend).
const (
	BackendAuto = "auto"
	BackendUnix = "unix" // <HOME>/run/ts-{funnel,serve}.sock
	BackendTCP  = "tcp"  // 127.0.0.1:<funnel.backend_port> (+1 for Serve)
)

// Settings of other packages the checks read (tsingress imports no other
// service).
const (
	keyHTTPSPort    = "server.https_port"
	keyHTTPPort     = "server.http_port"
	keyMTLSMode     = "mtls.mode"
	keyMTLSExempt   = "mtls.exempt_shares"
	mtlsRequired    = "required"
	defaultMainPort = 8443
)

// Defaults of the section (the registered ones).
const (
	defaultPort = 443
)

func init() {
	settings.Register(settings.Def{Key: KeyMode, Section: "funnel", Order: 10, Type: settings.TypeEnum,
		Default: core.FunnelOff, Enum: []string{core.FunnelOff, core.FunnelShares, core.FunnelApp}, Managed: ManagedFunnel,
		Label: "Tailscale Funnel",
		Description: "Publish FileParcel on the internet through Tailscale Funnel. shares: only share links and file " +
			"requests; app: the whole app with sign-in (two-factor accounts only). Changed on the Network page or " +
			"with \"fileparcel network funnel\"."})
	settings.Register(settings.Def{Key: KeyPort, Section: "funnel", Order: 20, Type: settings.TypeInt,
		Default: defaultPort, Min: 1, Max: 65535, Validate: validFunnelPort, Managed: ManagedFunnel,
		Label:       "Funnel port",
		Description: "Public HTTPS port of the Funnel address: 443, 8443 or 10000 (as far as the tailnet policy allows it)."})
	settings.Register(settings.Def{Key: KeyAllowAdmin, Section: "funnel", Order: 30, Type: settings.TypeBool,
		Default: false, Managed: ManagedFunnel,
		Label:       "Administration over Funnel",
		Description: "Allow the admin pages over the public Funnel address (mode app only; needs two-factor sign-in)."})
	settings.Register(settings.Def{Key: KeyRequire2FA, Section: "funnel", Order: 40, Type: settings.TypeBool,
		Default: true, Managed: ManagedFunnel,
		Label:       "Two-factor sign-in over Funnel",
		Description: "Over the public Funnel address only accounts with two-factor authentication can sign in."})
	settings.Register(settings.Def{Key: KeyServe, Section: "funnel", Order: 50, Type: settings.TypeBool,
		Default: false, Managed: ManagedServe,
		Label: "Tailscale Serve",
		Description: "Publish FileParcel on the tailnet with Tailscale's HTTPS certificate and without a port " +
			"(https://<device>.<tailnet>.ts.net/). Changed on the Network page or with \"fileparcel network tailscale-serve\"."})
	settings.Register(settings.Def{Key: KeyServePort, Section: "funnel", Order: 60, Type: settings.TypeInt,
		Default: defaultPort, Min: 1, Max: 65535, Managed: ManagedServe,
		Label:       "Serve port",
		Description: "Tailnet HTTPS port of Tailscale Serve."})
	settings.Register(settings.Def{Key: KeyNode, Section: "funnel", Order: 70, Type: settings.TypeString,
		Default: "", Validate: validNode, Managed: ManagedFunnel,
		Label: "Tailscale device",
		Description: "The Tailscale device (stable node ID) Funnel and Serve were turned on for. A restored backup or " +
			"a copied home publishes nothing on another device."})
	settings.Register(settings.Def{Key: KeyBackend, Section: "funnel", Order: 80, Type: settings.TypeEnum,
		Default: BackendAuto, Enum: []string{BackendAuto, BackendUnix, BackendTCP},
		Label: "Connection from Tailscale",
		Description: "How tailscaled reaches FileParcel. unix: a private socket in the run directory; tcp: " +
			"127.0.0.1 on funnel.backend_port; auto: the socket where tailscaled allows it (Linux), otherwise tcp."})
	settings.Register(settings.Def{Key: KeyBackendPort, Section: "funnel", Order: 90, Type: settings.TypeInt,
		Default: 0, Min: 0, Max: 65534, Validate: validBackendPort,
		Label:       "Local port for Tailscale",
		Description: "First of the two 127.0.0.1 ports of the tcp connection (Funnel, then Serve); 0 = chosen at first use."})
}

func validFunnelPort(v any) error {
	n, _ := v.(int64)
	if !slices.Contains(tslocal.FunnelCandidatePorts, int(n)) {
		return errors.New("must be 443, 8443 or 10000 (the ports Tailscale Funnel supports)")
	}
	return nil
}

func validBackendPort(v any) error {
	if n, _ := v.(int64); n != 0 && n < 1024 {
		return errors.New("must be 0 (automatic) or between 1024 and 65534")
	}
	return nil
}

// validNode accepts a Tailscale StableNodeID (letters and digits) or "".
func validNode(v any) error {
	s, _ := v.(string)
	if len(s) > 64 {
		return errors.New("must be a Tailscale node ID")
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return errors.New("must be a Tailscale node ID")
		}
	}
	return nil
}

// desired is the wanted Funnel/Serve configuration: the settings, or the
// proposal of a SetFunnel/SetServe call.
type desired struct {
	Mode        string // funnel: off|shares|app
	Port        int
	AllowAdmin  bool
	Require2FA  bool
	Serve       bool
	ServePort   int
	Node        string // StableNodeID ("" = not bound)
	Backend     string // auto|unix|tcp
	BackendPort int    // 0 = not chosen yet
}

// wants reports whether kind is wanted on.
func (d desired) wants(kind string) bool {
	if kind == core.IngressFunnel {
		return d.Mode == core.FunnelShares || d.Mode == core.FunnelApp
	}
	return d.Serve
}

// adminOverFunnel reports whether the admin pages are reachable over the
// Funnel address (app mode with allow_admin).
func (d desired) adminOverFunnel() bool { return d.Mode == core.FunnelApp && d.AllowAdmin }

// passwordOnlyOverFunnel reports whether accounts without a second factor
// can sign in over the Funnel address (app mode without require_2fa).
func (d desired) passwordOnlyOverFunnel() bool { return d.Mode == core.FunnelApp && !d.Require2FA }

// anyWanted reports whether Funnel or Serve is wanted.
func (d desired) anyWanted() bool { return d.wants(core.IngressFunnel) || d.wants(core.IngressServe) }

// port returns kind's HTTPS port on the Tailscale side.
func (d desired) port(kind string) int {
	if kind == core.IngressFunnel {
		return d.Port
	}
	return d.ServePort
}

// mode is IngressEntry.Mode and IngressPolicy.Mode of kind: the Funnel mode,
// or app/off for Serve.
func (d desired) mode(kind string) string {
	switch {
	case kind == core.IngressFunnel:
		return d.Mode
	case d.Serve:
		return core.FunnelApp
	}
	return core.FunnelOff
}

// loadDesired reads the desired state from the settings (the registered
// defaults without a settings store).
func (s *Service) loadDesired() desired {
	st := s.env.Settings
	if st == nil {
		return desired{Mode: core.FunnelOff, Port: defaultPort, Require2FA: true, ServePort: defaultPort, Backend: BackendAuto}
	}
	return desired{
		Mode: st.String(KeyMode), Port: int(st.Int(KeyPort)), AllowAdmin: st.Bool(KeyAllowAdmin),
		Require2FA: st.Bool(KeyRequire2FA), Serve: st.Bool(KeyServe), ServePort: int(st.Int(KeyServePort)),
		Node: st.String(KeyNode), Backend: st.String(KeyBackend), BackendPort: int(st.Int(KeyBackendPort)),
	}
}

// ownPorts returns FileParcel's own listening ports: server.https_port and
// server.http_port as configured (a change waiting for a restart included)
// and as the running server uses them. A Funnel/Serve entry on one of them
// would take it over on the Tailscale addresses.
func (s *Service) ownPorts() []int {
	var out []int
	add := func(p int) {
		if p > 0 && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	if st := s.env.Settings; st != nil {
		add(int(st.Int(keyHTTPSPort)))
		add(int(st.Int(keyHTTPPort)))
	}
	if c := s.env.Config; c != nil {
		add(c.Server.HTTPSPort)
		add(c.Server.HTTPPort)
	}
	if len(out) == 0 {
		add(defaultMainPort)
	}
	return out
}

// mainPort is the port of FileParcel's own TLS listener (the target a
// hand-made Tailscale proxy would bypass the access policy with).
func (s *Service) mainPorts() []int {
	var out []int
	if st := s.env.Settings; st != nil {
		if p := int(st.Int(keyHTTPSPort)); p > 0 {
			out = append(out, p)
		}
	}
	if c := s.env.Config; c != nil && c.Server.HTTPSPort > 0 && !slices.Contains(out, c.Server.HTTPSPort) {
		out = append(out, c.Server.HTTPSPort)
	}
	if len(out) == 0 {
		out = append(out, defaultMainPort)
	}
	return out
}
