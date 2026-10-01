package tsingress

import (
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/tslocal"
)

// Check IDs (core.IngressCheck.ID, the field of a 412 answer; DESIGN §10.6).
const (
	checkContainer      = "container"
	checkRunning        = "tailscale.running"
	checkControl        = "tailscale.control"
	checkMagicDNS       = "tailscale.magicdns"
	checkHTTPS          = "tailscale.https"
	checkFunnelAttr     = "tailscale.funnel_attr"
	checkFunnelPort     = "tailscale.funnel_port"
	checkCLIPort        = "tailscale.cli_port"
	checkShieldsUp      = "tailscale.shields_up"
	checkOperator       = "tailscale.operator"
	checkConfigLocked   = "tailscale.config_locked"
	checkKeyExpiry      = "tailscale.key_expiry"
	checkPortFileParcel = "port.fileparcel"
	checkPortFree       = "port.free"
	checkPortShadow     = "port.shadow"
	checkBackend        = "backend"
	checkBackendTCP     = "backend.tcp"
	checkMTLS           = "mtls"
	checkNode           = "node"
	checkReachable      = "reachable"
	checkPasskeys       = "passkeys"
)

// Settings of package auth the passkey check reads (tsingress imports no
// other service; unregistered they read as empty).
const (
	keyWebAuthnRPID    = "auth.webauthn_rp_id"
	keyWebAuthnOrigins = "auth.webauthn_origins"
)

// Check results.
const (
	statusOK   = "ok"
	statusWarn = "warn"
	statusFail = "fail"
	statusSkip = "skip"
)

// keyExpiryWarn is how early an expiring node key is reported.
const keyExpiryWarn = 14 * 24 * time.Hour

// Texts shared by several checks.
const (
	adminDNSURL      = "https://login.tailscale.com/admin/dns"
	noFunnelURL      = "https://tailscale.com/s/no-funnel"
	headscaleHint    = "This device uses a self-hosted control server: Headscale has no ts.net certificates or Funnel relays (juanfont/headscale#1921)."
	funnelAttrPolicy = `Allow Funnel for this device in the tailnet policy: "nodeAttrs": [{"target": ["autogroup:member"], "attr": ["funnel"]}]`
	tcpSquatNote     = "While FileParcel is stopped another local program could take that port; FileParcel removes its entry on every clean stop."
)

type checkList []core.IngressCheck

func (l *checkList) add(id, label, status, msg, hint, fix string) {
	*l = append(*l, core.IngressCheck{ID: id, Label: label, Status: status, Message: msg, Hint: hint, FixURL: fix})
}

// firstFailure returns the first failing check (nil when none fails).
func firstFailure(cs []core.IngressCheck) *core.IngressCheck {
	for i := range cs {
		if cs[i].Status == statusFail {
			c := cs[i]
			return &c
		}
	}
	return nil
}

// checkError is the 412 answer of a failing check (field = check ID).
func checkError(c *core.IngressCheck) error {
	msg := c.Message
	if c.Hint != "" {
		msg = strings.TrimSuffix(msg, ".") + ". " + c.Hint
	}
	return &core.Error{Code: core.ErrPrecondition.Code, Status: core.ErrPrecondition.Status, Message: msg, Field: c.ID}
}

// prerequisites evaluates the checks that decide whether kind can be
// published (in the order a 412 reports the first failure): the machine,
// tailscaled and the node's capabilities, the port and the mTLS policy.
func (s *Service) prerequisites(kind string, d desired, v *tsView, own []int) []core.IngressCheck {
	funnel := kind == core.IngressFunnel
	port := d.port(kind)
	transport := s.ts.Transport()
	var out checkList

	if s.inContainer() {
		out.add(checkContainer, "Not in a container", statusFail,
			"FileParcel runs in a container, which Tailscale's connection cannot reach",
			"Run the Tailscale client in the same container or network namespace (not supported in this version).", "")
	} else {
		out.add(checkContainer, "Not in a container", statusOK, "", "", "")
	}

	running := v.running()
	switch {
	case transport == "":
		out.add(checkRunning, "Tailscale is running", statusFail, "Tailscale is not installed on this machine",
			"Install Tailscale and sign in: https://tailscale.com/download", "")
	case !running:
		out.add(checkRunning, "Tailscale is running", statusFail, unavailableMessage(v), "Start Tailscale: sudo tailscale up", "")
	default:
		out.add(checkRunning, "Tailscale is running", statusOK, "Connected as "+v.dnsName(), "", "")
	}

	if running {
		s.tailscaleChecks(&out, kind, d, v, transport)
	} else {
		for _, c := range [][2]string{{checkControl, "Control server"}, {checkMagicDNS, "MagicDNS"},
			{checkHTTPS, "HTTPS certificates"}} {
			out.add(c[0], c[1], statusSkip, "Needs a running Tailscale", "", "")
		}
		if funnel {
			out.add(checkFunnelAttr, "Funnel allowed for this device", statusSkip, "Needs a running Tailscale", "", "")
			out.add(checkFunnelPort, "Funnel port allowed", statusSkip, "Needs a running Tailscale", "", "")
		}
	}

	if slices.Contains(own, port) {
		out.add(checkPortFileParcel, "Port not used by FileParcel", statusFail,
			"FileParcel itself uses port "+strconv.Itoa(port)+"; Tailscale would take it over on the tailnet address",
			"Choose another port.", "")
	} else {
		out.add(checkPortFileParcel, "Port not used by FileParcel", statusOK, "", "", "")
	}

	mtlsMode := ""
	exempt := false
	if st := s.env.Settings; st != nil {
		mtlsMode, exempt = st.String(keyMTLSMode), st.Bool(keyMTLSExempt)
	}
	switch {
	case mtlsMode != mtlsRequired:
		out.add(checkMTLS, "Client certificates", statusOK, "", "", "")
	case funnel && d.Mode == core.FunnelShares && exempt:
		out.add(checkMTLS, "Client certificates", statusOK,
			"Share links are exempt from client certificates (mtls.exempt_shares)", "", "")
	default:
		hint := "Set mtls.mode to optional or off"
		if funnel {
			hint += ", or publish share links only with mtls.exempt_shares on"
		}
		out.add(checkMTLS, "Client certificates", statusFail,
			"Client certificates are required (mtls.mode), which cannot work through Tailscale's TLS", hint+".", "")
	}
	return out
}

// tailscaleChecks adds the checks of a running tailscaled.
func (s *Service) tailscaleChecks(out *checkList, kind string, d desired, v *tsView, transport string) {
	funnel := kind == core.IngressFunnel
	port := d.port(kind)
	st := v.st
	hs := v.selfHosted()
	capHint := func(hint string) string {
		if hs {
			return strings.TrimSpace(hint + " " + headscaleHint)
		}
		return hint
	}
	consoleURL := func(u string) string {
		if hs {
			return ""
		}
		return u
	}

	switch {
	case v.prefs == nil:
		out.add(checkControl, "Control server", statusSkip, "tailscaled's preferences could not be read", "", "")
	case hs:
		host := v.prefs.ControlURL
		if u, err := url.Parse(host); err == nil && u.Hostname() != "" {
			host = u.Hostname()
		}
		out.add(checkControl, "Control server", statusOK, "Self-hosted control server "+host, "", "")
	default:
		out.add(checkControl, "Control server", statusOK, "Tailscale's control server", "", "")
	}

	if st.Self != nil && st.Self.DNSName != "" && (st.CurrentTailnet == nil || st.CurrentTailnet.MagicDNSEnabled) {
		out.add(checkMagicDNS, "MagicDNS", statusOK, v.dnsName(), "", "")
	} else {
		out.add(checkMagicDNS, "MagicDNS", statusFail, "MagicDNS is off for this tailnet",
			capHint("Turn on MagicDNS in the admin console."), consoleURL(adminDNSURL))
	}

	if st.HasCap("https") && len(st.CertDomains) > 0 {
		out.add(checkHTTPS, "HTTPS certificates", statusOK, "", "", "")
	} else {
		out.add(checkHTTPS, "HTTPS certificates", statusFail, "HTTPS certificates are not enabled for this tailnet",
			capHint("Enable HTTPS certificates in the admin console (DNS page)."), consoleURL(adminDNSURL))
	}

	ports := st.FunnelPorts()
	if funnel {
		if st.HasCap("funnel") {
			out.add(checkFunnelAttr, "Funnel allowed for this device", statusOK, "", "", "")
		} else {
			fix := noFunnelURL
			s.stMu.Lock()
			if f := s.fix; f != nil && !f.complete && f.url != "" {
				fix = f.url
			}
			s.stMu.Unlock()
			out.add(checkFunnelAttr, "Funnel allowed for this device", statusFail,
				"The tailnet policy does not allow Funnel for this device", capHint(funnelAttrPolicy), consoleURL(fix))
		}
		if slices.Contains(ports, port) {
			out.add(checkFunnelPort, "Funnel port allowed", statusOK, "", "", "")
		} else {
			out.add(checkFunnelPort, "Funnel port allowed", statusFail,
				"Port "+strconv.Itoa(port)+" is not allowed for Funnel on this device",
				capHint("Allowed here: "+portList(ports)+"."), "")
		}
		if transport == "cli" && port != 443 {
			if slices.Contains(ports, 443) {
				out.add(checkCLIPort, "Port 443 allowed (tailscale command)", statusOK, "", "", "")
			} else {
				out.add(checkCLIPort, "Port 443 allowed (tailscale command)", statusFail,
					"The tailscale command can only turn on Funnel when port 443 is allowed for this device",
					"Allow port 443 for Funnel in the tailnet policy, or use port 443.", "")
			}
		}
	}

	switch {
	case v.prefs == nil:
		out.add(checkShieldsUp, "Shields-up off", statusSkip, "tailscaled's preferences could not be read", "", "")
	case !v.prefs.ShieldsUp:
		out.add(checkShieldsUp, "Shields-up off", statusOK, "", "", "")
	case funnel:
		out.add(checkShieldsUp, "Shields-up off", statusFail, "Shields-up is on, and Funnel does not work with it",
			"sudo tailscale set --shields-up=false", "")
	default:
		out.add(checkShieldsUp, "Shields-up off", statusWarn, "Tailnet devices cannot connect while shields-up is on",
			"sudo tailscale set --shields-up=false", "")
	}

	switch {
	case s.goos == "darwin" || s.goos == "windows" || transport == "cli":
		out.add(checkOperator, "Permission to configure Tailscale", statusSkip,
			"tailscaled decides when FileParcel changes its configuration", "", "")
	case s.mayConfigure(v.prefs):
		out.add(checkOperator, "Permission to configure Tailscale", statusOK, "", "", "")
	default:
		u := s.serviceUser()
		hint := "Allow FileParcel's user to configure Tailscale: sudo tailscale set --operator=" + u
		if v.prefs != nil && v.prefs.OperatorUser != "" {
			hint += " (tailscaled has one operator per machine; it is " + v.prefs.OperatorUser + " now)"
		}
		out.add(checkOperator, "Permission to configure Tailscale", statusFail,
			"FileParcel's user ("+u+") may not change tailscaled's configuration", hint, "")
	}

	s.stMu.Lock()
	locked := s.configLocked
	s.stMu.Unlock()
	if locked {
		out.add(checkConfigLocked, "Serve configuration editable", statusFail,
			"tailscaled runs from a configuration file, so its serve configuration is locked",
			"Add the entry to that file, or run tailscaled without --config.", "")
	}

	if st.Self != nil {
		switch exp := st.Self.KeyExpiry; {
		case exp == nil:
			out.add(checkKeyExpiry, "Device key expiry", statusOK, "Key expiry is disabled for this device", "", "")
		case exp.Before(s.now().Add(keyExpiryWarn)):
			out.add(checkKeyExpiry, "Device key expiry", statusWarn,
				"The key of this device expires on "+exp.UTC().Format("2006-01-02"),
				"Disable key expiry for this machine in the admin console.", "")
		default:
			out.add(checkKeyExpiry, "Device key expiry", statusOK,
				"The key of this device expires on "+exp.UTC().Format("2006-01-02"), "", "")
		}
	}
}

// portChecks adds port.free (a foreign entry on the port, from the serve
// configuration read with v) and port.shadow (another local program
// listening on the port). applied: FileParcel's entry is on the port (its
// tailscaled listener then is not another program).
func (s *Service) portChecks(kind string, d desired, v *tsView, own ownership, applied bool) []core.IngressCheck {
	port := d.port(kind)
	p := strconv.Itoa(port)
	var out checkList
	switch {
	case v == nil || v.sc == nil || v.name() == "":
		out.add(checkPortFree, "Port free in Tailscale", statusSkip, "tailscaled's serve configuration could not be read", "", "")
	default:
		if target, c := v.sc.Conflict(v.name()+":"+p, port, own.owned); c {
			out.add(checkPortFree, "Port free in Tailscale", statusFail, target+" already uses port "+p+" on this device",
				"Remove it (on this machine: "+tslocal.OffCommand(port, false)+") or choose another port.", "")
		} else {
			out.add(checkPortFree, "Port free in Tailscale", statusOK, "", "", "")
		}
	}

	addrs, known := s.listening(port)
	if !known {
		out.add(checkPortShadow, "No other program on the port", statusSkip, "Not checked on this system", "", "")
		return out
	}
	var tsIPs []netip.Addr
	if v != nil && v.st != nil {
		tsIPs = v.st.IPs()
	}
	var hits []string
	for _, a := range addrs {
		ip := a.Addr().Unmap()
		if ip.IsUnspecified() || (!applied && slices.Contains(tsIPs, ip)) {
			hits = append(hits, a.String())
		}
	}
	if len(hits) > 0 {
		out.add(checkPortShadow, "No other program on the port", statusWarn,
			strings.Join(hits, ", ")+" listens on port "+p+"; Tailscale takes that port over on the tailnet address",
			"Choose another port if that program must stay reachable over the tailnet.", "")
	} else {
		out.add(checkPortShadow, "No other program on the port", statusOK, "", "", "")
	}
	return out
}

// nodeCheck reports whether the configuration belongs to this node.
func nodeCheck(d desired, v *tsView) core.IngressCheck {
	c := core.IngressCheck{ID: checkNode, Label: "This Tailscale device", Status: statusOK}
	switch {
	case d.Node == "":
	case v == nil || v.st == nil || v.st.NodeID() == "":
		c.Status, c.Message = statusSkip, "The Tailscale device is unknown"
	case d.Node != v.st.NodeID():
		c.Status = statusFail
		c.Message = "Funnel and Serve were turned on for another Tailscale device (" + d.Node + ")"
		c.Hint = "Turn them on again here to publish from this device."
	}
	return c
}

// runtimeChecks are the checks of the running entry: the backend listener
// and the self-probe.
func runtimeChecks(ks kindState, wanted bool) []core.IngressCheck {
	var out checkList
	switch {
	case !wanted && ks.state == core.IngressStateError && ks.backend == BackendTCP && ks.proxy != "":
		// The entry could not be removed: its port stays bound.
		addr := strings.TrimPrefix(ks.proxy, "http://")
		out.add(checkBackendTCP, "Local TCP connection", statusWarn,
			"Tailscale still forwards to "+addr+", so FileParcel keeps that port bound (answering \"not found\") "+
				"and retries removing the entry. "+tcpSquatNote,
			"Remove the entry with the command above if FileParcel cannot.", "")
		return out
	case !wanted:
		return nil
	case ks.backendErr:
		out.add(checkBackend, "Connection from Tailscale", statusFail, ks.message, "", "")
	case ks.proxy == "":
		out.add(checkBackend, "Connection from Tailscale", statusSkip, "Set up when FileParcel publishes it", "", "")
	default:
		out.add(checkBackend, "Connection from Tailscale", statusOK, ks.proxy, "", "")
	}
	if ks.backend == BackendTCP && ks.proxy != "" {
		addr := strings.TrimPrefix(ks.proxy, "http://")
		msg := "FileParcel uses " + addr + ". " + tcpSquatNote
		if ks.tcpWarn {
			msg = "tailscaled only allows Unix-socket targets for root or an operator with sudo rights, so FileParcel uses " +
				addr + ". " + tcpSquatNote
		}
		out.add(checkBackendTCP, "Local TCP connection", statusWarn, msg,
			"Allow FileParcel's user to run sudo tailscale, or keep the TCP connection.", "")
	}
	if ks.reachable != nil {
		out = append(out, *ks.reachable)
	} else {
		out.add(checkReachable, "Reachable over the tailnet", statusSkip, "Not tested yet", "", "")
	}
	return out
}

// passkeyCheck tells whether passkeys work on kind's address (Funnel in
// app mode, Serve; nil otherwise). A browser offers a passkey only on the
// domain it was registered for — the WebAuthn RP ID, by default the
// server's .local name — and FileParcel accepts only its allowed origins,
// so on https://<device>.<tailnet>.ts.net an account whose only second
// factor is a passkey cannot sign in (Funnel requires two-factor sign-in)
// or finish a two-factor sign-in, unless auth.webauthn_rp_id covers the
// MagicDNS name and the address is an allowed origin.
func (s *Service) passkeyCheck(kind string, d desired, v *tsView) *core.IngressCheck {
	dns := v.dnsName()
	if !d.wants(kind) || kind == core.IngressFunnel && d.Mode != core.FunnelApp || dns == "" {
		return nil
	}
	c := &core.IngressCheck{ID: checkPasskeys, Label: "Passkeys on this address", Status: statusOK}
	var rp string
	var origins []string
	if st := s.env.Settings; st != nil {
		rp = strings.ToLower(strings.TrimSuffix(st.String(keyWebAuthnRPID), "."))
		for _, o := range st.Strings(keyWebAuthnOrigins) {
			origins = append(origins, strings.TrimSuffix(strings.ToLower(strings.TrimSpace(o)), "/"))
		}
	}
	port := d.port(kind)
	origin := hostURL(dns, port)
	covered := rp != "" && (dns == rp || strings.HasSuffix(dns, "."+rp))
	allowed := dns == rp && port == 443 || slices.Contains(origins, origin) ||
		port == 443 && slices.Contains(origins, origin+":443")
	if covered && allowed {
		return c
	}
	domain := "the server's .local name"
	if rp != "" {
		domain = rp
	}
	c.Status = statusWarn
	c.Message = "Passkeys belong to " + domain + ", so browsers do not use them at " + origin + "/: accounts whose only " +
		"second factor is a passkey cannot sign in there"
	if kind == core.IngressFunnel {
		c.Message += " (accounts with an authenticator app can)"
	}
	c.Hint = "To use passkeys there, set auth.webauthn_rp_id to " + dns
	if !(dns == rp && port == 443) {
		c.Hint += " and add " + origin + " to auth.webauthn_origins"
	}
	c.Hint += "; passkeys registered for the old domain then stop working and have to be added again."
	return c
}

// portList renders ports for messages ("443, 8443" or "none").
func portList(ports []int) string {
	if len(ports) == 0 {
		return "none"
	}
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ", ")
}
