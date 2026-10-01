package cli

// "fileparcel network vpn|funnel|tailscale-serve" (DESIGN §10.1, §10.6,
// §12): the VPNs on this machine and whether their devices may connect (GET
// /admin/network → vpns; allow and remove edit the access policy, role
// edits network.iface_roles), Tailscale Funnel (FileParcel on the internet)
// and Tailscale Serve (a tailnet address without a port): GET
// /admin/network/tailscale, PUT /admin/network/funnel and
// /admin/network/serve, POST /admin/network/tailscale/reapply. Changes need
// network.manage and, remotely, step-up. With the server stopped they are
// stored and published when it starts (state "stopped").

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/core"
)

// ---------- VPNs ----------

func newNetworkVPNCmd() *cobra.Command {
	cmd := groupCmd("vpn", "Show the VPNs on this machine and let their devices connect",
		`FileParcel recognises the VPNs on this machine and whether other devices can
reach this server through them:

  mesh VPNs (their devices can connect): Tailscale and Headscale, ZeroTier,
    NetBird, Nebula, Netmaker, innernet, Husarnet, NordVPN Meshnet, and
    WireGuard, OpenVPN, IPsec, tinc or SoftEther tunnels
  outgoing-only VPNs (nobody comes in through them): Mullvad, NordVPN,
    Proton VPN, Cloudflare WARP, Twingate, Firezone, and any tunnel that
    carries this machine's internet traffic
  public overlays (anyone on them could connect): Yggdrasil

"list" shows each one with its interfaces, address ranges and whether the
access policy lets its devices in; "allow" adds a VPN's ranges to the allow
list and "remove" takes them out again.`,
		`  fileparcel network vpn
  fileparcel network vpn allow tailscale
  fileparcel network vpn remove wg0`)
	// "fileparcel network vpn" alone lists them, like "network vpn list".
	cmd.Annotations = map[string]string{annBare: "list"}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return unknownCommandError(cmd, args[0])
		}
		return runVPNList(cmd)
	}
	cmd.AddCommand(newNetworkVPNListCmd(), newNetworkVPNChangeCmd(true), newNetworkVPNChangeCmd(false), newNetworkVPNRoleCmd())
	setListHint(cmd, "fileparcel network vpn list")
	return cmd
}

func newNetworkVPNListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List the VPNs found and whether they may connect",
		Long: `List the VPNs found on this machine: their interfaces, the address ranges
"network vpn allow" adds, their role (mesh: its devices can connect; egress or
access: outgoing only; overlay: public; "override" when set with "network vpn
role") and whether the access policy lets their devices in (yes, partly, no).`,
		Example: `  fileparcel network vpn list
  fileparcel network vpn list --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { return runVPNList(cmd) },
	}
}

func runVPNList(cmd *cobra.Command) error {
	return WithClient(cmd, func(ctx context.Context, c *Client) error {
		ov, err := getNetwork(ctx, c)
		if err != nil {
			return err
		}
		vpns := ov.VPNs
		if vpns == nil {
			vpns = []core.VPNInfo{}
		}
		return Print(cmd, vpns, func(w io.Writer) error {
			if len(vpns) == 0 {
				Infof(cmd, "no VPN found on this machine")
				return nil
			}
			return renderVPNs(w, vpns)
		})
	})
}

// renderVPNs prints the VPN table.
func renderVPNs(w io.Writer, vpns []core.VPNInfo) error {
	t := NewTable("VPN", "INTERFACES", "RANGES", "ROLE", "ALLOWED", "NOTE", "ID")
	for _, v := range vpns {
		note := v.Note
		if v.Warning != "" {
			note = strings.TrimPrefix(note+"; warning: "+v.Warning, "; ")
		}
		t.Add(v.Label, strings.Join(v.Interfaces, ", "), strings.Join(v.Ranges, ", "), roleText(v.Role, v.RoleSource),
			v.Allowed, Truncate(note, 70), v.ID)
	}
	return t.Render(w)
}

// roleText is an interface or VPN role, marked when network.iface_roles
// sets it.
func roleText(role, source string) string {
	if source == core.VPNRoleSourceOverride {
		return role + " (override)"
	}
	return role
}

// findVPN finds a VPN by id ("tailscale"), label or interface name ("wg0").
func findVPN(vpns []core.VPNInfo, ref string) (*core.VPNInfo, error) {
	for i := range vpns {
		v := &vpns[i]
		if strings.EqualFold(v.ID, ref) || strings.EqualFold(v.Label, ref) || slices.Contains(v.Interfaces, ref) {
			return v, nil
		}
	}
	if len(vpns) == 0 {
		return nil, UsageError("no VPN %q: no VPN was found on this machine", ref)
	}
	known := make([]string, len(vpns))
	for i, v := range vpns {
		known[i] = v.ID
	}
	return nil, UsageError("no VPN %q on this machine (known: %s; see \"fileparcel network vpn list\")", ref, strings.Join(known, ", "))
}

// vpnIface is the interface a "network vpn role" hint names.
func vpnIface(v *core.VPNInfo) string {
	if len(v.Interfaces) > 0 {
		return v.Interfaces[0]
	}
	return "<interface>"
}

// newNetworkVPNChangeCmd is "network vpn allow" (allow) or "network vpn
// remove".
func newNetworkVPNChangeCmd(allow bool) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "allow <vpn|interface>",
		Short: "Let the devices of a VPN connect (adds its ranges)",
		Long: `Add the address ranges of a VPN to the allow list (network.allow_cidrs), so its
devices may connect in allowlist mode. Name the VPN by its id or an interface
("network vpn list"). Outgoing-only VPNs are refused: nobody comes in through
them. A public overlay (Yggdrasil) asks first, since anyone on it could then
connect. A change that would lock out your own connection is refused unless
--force.

` + elevationNote,
		Example: `  fileparcel network vpn allow tailscale
  fileparcel network vpn allow wg0`,
		Args: cobra.ExactArgs(1),
	}
	if !allow {
		cmd.Use = "remove <vpn|interface>"
		cmd.Aliases = []string{"rm"}
		cmd.Short = "Stop allowing a VPN's networks"
		cmd.Long = `Take the address ranges of a VPN out of the allow list again. Its devices may
then connect only when other entries or the access mode let them in. A change
that would lock out your own connection is refused unless --force.

` + elevationNote
		cmd.Example = `  fileparcel network vpn remove zerotier
  fileparcel network vpn remove wg0 --force`
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return WithClient(cmd, func(ctx context.Context, c *Client) error {
			ov, err := getNetwork(ctx, c)
			if err != nil {
				return err
			}
			v, err := findVPN(ov.VPNs, args[0])
			if err != nil {
				return err
			}
			if allow {
				return allowVPN(ctx, cmd, c, ov.Policy, v, force)
			}
			return removeVPN(ctx, cmd, c, ov.Policy, v, force)
		})
	}
	cmd.Flags().BoolVar(&force, "force", false, "apply even if it locks out the client making the change")
	return cmd
}

func allowVPN(ctx context.Context, cmd *cobra.Command, c *Client, p core.AccessPolicy, v *core.VPNInfo, force bool) error {
	if !v.CanAllow {
		switch {
		case v.Role == core.VPNRoleEgress || v.Role == core.VPNRoleAccess:
			return &usageHintError{
				msg:   fmt.Sprintf("devices cannot reach this server through %s (it only carries this machine's outgoing traffic)", v.Label),
				hints: []string{fmt.Sprintf("if that is wrong: fileparcel network vpn role %s mesh", shellArg(vpnIface(v)))},
			}
		case len(v.Ranges) == 0 && v.Note != "":
			return UsageError("%s: %s", v.Label, v.Note)
		}
		return UsageError("devices cannot reach this server through %s", v.Label)
	}
	if v.NeedsForce {
		if err := confirmOrAbort(cmd, fmt.Sprintf("Anyone on %s could then connect to this server. Continue?", v.Label)); err != nil {
			return err
		}
	}
	if v.Warning != "" {
		Warnf(cmd, "%s: %s", v.Label, v.Warning)
	}
	allowList := slices.Clone(p.Allow)
	var added []string
	for _, r := range v.Ranges {
		if !slices.ContainsFunc(allowList, func(x string) bool { return samePrefix(x, r) }) {
			allowList, added = append(allowList, r), append(added, r)
		}
	}
	if len(added) == 0 {
		return done(cmd, &core.PolicyResult{Policy: p}, "the ranges of %s are in the allow list already (%s)", v.Label, strings.Join(v.Ranges, ", "))
	}
	p.Allow = allowList
	res, err := setPolicy(ctx, cmd, c, p, force)
	if err != nil {
		return err
	}
	if p.Mode == core.AccessAny {
		Infof(cmd, "Note: the allow list is not used in mode %q (every address may connect).", p.Mode)
	}
	return done(cmd, res, "devices on %s may connect now (allowed %s)", v.Label, strings.Join(added, ", "))
}

func removeVPN(ctx context.Context, cmd *cobra.Command, c *Client, p core.AccessPolicy, v *core.VPNInfo, force bool) error {
	if len(v.Ranges) == 0 {
		msg := fmt.Sprintf("FileParcel knows no address ranges of %s; remove its networks with \"fileparcel network allow remove CIDR\"", v.Label)
		if v.Note != "" {
			msg += " (" + v.Note + ")"
		}
		return UsageError("%s", msg)
	}
	var removed []string
	allowList := slices.DeleteFunc(slices.Clone(p.Allow), func(x string) bool {
		for _, r := range v.Ranges {
			if samePrefix(x, r) {
				removed = append(removed, x)
				return true
			}
		}
		return false
	})
	if len(removed) == 0 {
		Warnf(cmd, "the ranges of %s (%s) are not in the allow list", v.Label, strings.Join(v.Ranges, ", "))
		return done(cmd, &core.PolicyResult{Policy: p}, "nothing to remove")
	}
	p.Allow = allowList
	res, err := setPolicy(ctx, cmd, c, p, force)
	if err != nil {
		return err
	}
	return done(cmd, res, "removed %s from the allow list (%s)", strings.Join(removed, ", "), v.Label)
}

// vpnRoles are the words of "network vpn role" with what they mean.
var vpnRoles = []struct{ Role, Means string }{
	{core.VPNRoleMesh, "devices can reach this server through it"},
	{core.VPNRoleUnknown, "a tunnel treated like a mesh VPN"},
	{core.VPNRoleAccess, "outgoing only: nobody comes in through it"},
	{core.VPNRoleEgress, "outgoing only: nobody comes in through it"},
	{core.VPNRoleOverlay, "a public overlay: anyone on it could connect"},
	{core.VPNRoleLocal, "LAN or Wi-Fi, also for the .local name"},
	{core.VPNRoleNone, "not used by FileParcel"},
	{"auto", "automatic detection"},
}

// ifaceRolesKey is the setting "network vpn role" edits.
const ifaceRolesKey = "network.iface_roles"

func newNetworkVPNRoleCmd() *cobra.Command {
	var words []string
	for _, r := range vpnRoles {
		words = append(words, r.Role)
	}
	return &cobra.Command{
		Use:   "role <interface> <mesh|unknown|access|egress|overlay|local|none|auto>",
		Short: "Correct how FileParcel treats a network interface",
		Long: `Correct how FileParcel treats a network interface when the automatic
detection is wrong (network.iface_roles): mesh (devices of that VPN can
connect), unknown (a tunnel treated like mesh), access or egress (outgoing
only: nobody comes in through it), overlay (a public overlay), local (LAN or
Wi-Fi; also gets the .local name) or none (not used). auto removes the
correction. The role decides which addresses are offered, the names in the
certificate and the VPN list.

` + elevationNote,
		Example: `  fileparcel network vpn role wg0 mesh
  fileparcel network vpn role wg0 auto`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			iface, role := strings.TrimSpace(args[0]), strings.ToLower(strings.TrimSpace(args[1]))
			if iface == "" || iface == "." || iface == ".." || len(iface) > 64 ||
				strings.ContainsFunc(iface, func(r rune) bool { return r <= ' ' || r == '/' || r == '=' || r == 0x7f }) {
				return UsageError("%q is not a network interface name", args[0])
			}
			i := slices.IndexFunc(vpnRoles, func(r struct{ Role, Means string }) bool { return r.Role == role })
			if i < 0 {
				return UsageError("invalid role %q (%s)", args[1], joinOr(words))
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				s, err := getSetting(ctx, c, ifaceRolesKey)
				if err != nil {
					if apiStatus(err) == http.StatusNotFound {
						return &hintError{err, "this server cannot set interface roles (upgrade it)"}
					}
					return err
				}
				if ov, err := getNetwork(ctx, c); err == nil &&
					!slices.ContainsFunc(ov.Interfaces, func(n core.NetInterface) bool { return n.Name == iface }) {
					Warnf(cmd, "there is no interface %q on this machine now; the role applies when it appears", iface)
				}
				// The server trims the name of an entry ("wg0 = egress"
				// is wg0's), and so does this match.
				entries := slices.DeleteFunc(settingStrings(s), func(e string) bool {
					name, _, _ := strings.Cut(e, "=")
					return strings.TrimSpace(name) == iface
				})
				if role != "auto" {
					entries = append(entries, iface+"="+role)
				}
				if entries == nil {
					entries = []string{}
				}
				res, err := patchSettings(ctx, cmd, c, map[string]any{ifaceRolesKey: entries})
				if err != nil {
					return err
				}
				if role == "auto" {
					return done(cmd, res, "%s: back to automatic detection", iface)
				}
				return done(cmd, res, "%s is %s now (%s)", iface, role, vpnRoles[i].Means)
			})
		},
	}
}

// ---------- Funnel and Serve ----------

// getIngress reads the Funnel/Serve status (refresh: read Tailscale anew).
func getIngress(ctx context.Context, c *Client, refresh bool) (*core.IngressStatus, error) {
	var st core.IngressStatus
	path := api("/admin/network/tailscale")
	if refresh {
		path = api("/admin/network/tailscale", "refresh", "1")
	}
	if err := c.Do(ctx, http.MethodGet, path, nil, &st); err != nil {
		return nil, noIngressHint(err)
	}
	return &st, nil
}

// noIngressHint explains a 404 of the Funnel/Serve routes: a server from
// before them.
func noIngressHint(err error) error {
	if apiStatus(err) == http.StatusNotFound {
		return &hintError{err, "this server has no Tailscale Funnel or Serve support (upgrade it)"}
	}
	return err
}

// modeText names a Funnel mode.
func modeText(mode string) string {
	switch mode {
	case core.FunnelShares:
		return "share links"
	case core.FunnelApp:
		return "the whole app"
	}
	return mode
}

// ingressLine is the one-line state of Funnel or Serve ("on (share links):
// https://…/", "off", "needs attention: …").
func ingressLine(e core.IngressEntry) string {
	on := "on"
	if e.Kind == core.IngressFunnel && e.Mode != core.FunnelOff {
		on += " (" + modeText(e.Mode) + ")"
	}
	withMsg := func(s string) string {
		if e.Message != "" {
			return s + ": " + e.Message
		}
		return s
	}
	switch e.State {
	case core.IngressStateOff, "":
		return "off"
	case core.IngressStateActive:
		return strings.TrimSuffix(on+": "+e.URL, ": ")
	case core.IngressStateStopped:
		return on + ", published when the server starts"
	case core.IngressStateDrift:
		return withMsg("needs attention (FileParcel's entry is missing in Tailscale; fileparcel network funnel reapply)")
	case core.IngressStateConflict:
		return withMsg("needs attention (another Tailscale entry uses port " + fmt.Sprint(e.Port) + ")")
	case core.IngressStatePaused:
		return withMsg("paused (it was turned on on another device)")
	case core.IngressStateUnavailable:
		return withMsg("unavailable")
	}
	return withMsg(e.State)
}

// checkMark is the mark of a check status.
func checkMark(status string) string {
	switch status {
	case "ok":
		return Green("✓")
	case "warn":
		return Yellow("!")
	case "fail":
		return Red("✗")
	}
	return "-"
}

// renderChecks prints the prerequisite checks, one per line: mark, id and
// what it found, then how to fix a check that is not ok (hint and fix URL)
// on a line of its own. The result is the last column, so a long message
// does not widen every line past the terminal as a table's column would.
func renderChecks(w io.Writer, checks []core.IngressCheck) error {
	if len(checks) == 0 {
		return nil
	}
	width := 0
	for _, ch := range checks {
		width = max(width, len([]rune(ch.ID)))
	}
	indent := strings.Repeat(" ", width+4)
	if _, err := fmt.Fprintln(w, Bold("Checks")); err != nil {
		return err
	}
	for _, ch := range checks {
		what := sanitizeCell(cmp.Or(ch.Message, ch.Label))
		if _, err := fmt.Fprintf(w, "%s %-*s  %s\n", checkMark(ch.Status), width, sanitizeCell(ch.ID), what); err != nil {
			return err
		}
		if fix := strings.TrimSpace(ch.Hint + " " + ch.FixURL); fix != "" && ch.Status != "ok" {
			if _, err := fmt.Fprintf(w, "%s→ %s\n", indent, sanitizeCell(fix)); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkResult is the one-line result of a check in a key-value list: the
// mark (uncoloured: KV values are sanitized) and what it found; a skipped
// check only says why.
func checkResult(ch core.IngressCheck) string {
	what := cmp.Or(ch.Message, ch.Label)
	switch ch.Status {
	case "ok":
		return "✓ " + what
	case "warn":
		return "! " + what
	case "fail":
		return "✗ " + what
	}
	return what
}

// tailscaleDevice describes this machine on the tailnet.
func tailscaleDevice(ts *core.TailscaleInfo) string {
	switch {
	case ts == nil:
		return ""
	case !ts.Running:
		return cmp.Or(ts.Error, "Tailscale is not running")
	}
	s := cmp.Or(ts.DNSName, "(no MagicDNS name)")
	if ts.Kind != "" {
		s += " (" + ts.Kind + ")"
	}
	return s
}

// renderIngress prints the status of Funnel (kind IngressFunnel) or Serve.
func renderIngress(w io.Writer, st *core.IngressStatus, kind string) error {
	e := st.Funnel
	if kind == core.IngressServe {
		e = st.Serve
	}
	kv := NewKV()
	kv.Add("State", ingressLine(e))
	if kind == core.IngressFunnel {
		kv.Add("Mode", modeText(cmp.Or(e.Mode, core.FunnelOff)))
	}
	kv.Add("URL", e.URL)
	if e.Port > 0 {
		kv.Add("Port", e.Port)
	}
	kv.Add("Backend", e.Backend)
	if kind == core.IngressFunnel {
		last := "none yet"
		if e.LastPublicRequestAt != nil {
			last = Ago(*e.LastPublicRequestAt)
		}
		kv.Add("Last public request", last)
		if e.Mode == core.FunnelApp {
			twoFA, admin := "not required (anyone who guesses a password can sign in)", "blocked over Funnel"
			if st.Require2FA {
				twoFA = "required over Funnel"
			}
			if st.AllowAdmin {
				admin = "reachable over Funnel"
			}
			kv.Add("Two-factor sign-in", twoFA)
			kv.Add("Admin pages", admin)
		}
	}
	if i := slices.IndexFunc(e.Checks, func(ch core.IngressCheck) bool { return ch.ID == "reachable" }); i >= 0 {
		kv.Add("Reachable", checkResult(e.Checks[i]))
	}
	kv.Add("Tailscale device", tailscaleDevice(st.Tailscale))
	if !st.Available && st.Reason != "" {
		kv.Add("Unavailable", st.Reason)
	}
	if err := kv.Render(w); err != nil {
		return err
	}
	if len(e.Checks) > 0 {
		fmt.Fprintln(w)
		if err := renderChecks(w, e.Checks); err != nil {
			return err
		}
	}
	if alt := funnelAlternative(st, kind); alt != "" {
		fmt.Fprintln(w)
		fmt.Fprintln(w, alt)
	}
	for _, f := range st.Foreign {
		if !f.Bypass {
			continue
		}
		_, port, err := net.SplitHostPort(f.HostPort)
		if err != nil {
			port = "PORT"
		}
		fmt.Fprintf(w, "%s Tailscale forwards %s to FileParcel directly (%s).\n"+
			"  Every visitor would appear as one address, so FileParcel refuses these requests.\n"+
			"  Remove it on the machine running it: tailscale serve --yes --https=%s off\n", Red("✗"), f.HostPort, f.Target, port)
	}
	return nil
}

// funnelAlternative is what to use instead of Funnel when it cannot work
// here ("" otherwise), as the web UI shows it: only on the Funnel page and
// while Funnel is off. A self-hosted control server (Headscale) has no
// Funnel at all; without a usable Tailscale the reason says how to get one,
// and a reverse proxy is the other way.
func funnelAlternative(st *core.IngressStatus, kind string) string {
	if kind != core.IngressFunnel || cmp.Or(st.Funnel.Mode, core.FunnelOff) != core.FunnelOff {
		return ""
	}
	proxy := "use a reverse proxy with a public certificate and set\nserver.trusted_proxies."
	switch {
	case st.Tailscale != nil && st.Tailscale.Kind == core.IfHeadscale && (!st.Available || !st.Tailscale.FunnelCapable):
		return "Instead: sign this machine in to Tailscale's own control server (Headscale has\nno Funnel), or " + proxy
	case !st.Available:
		return "Without Tailscale Funnel: " + proxy
	}
	return ""
}

// ingressError explains a refused Funnel/Serve change: a failed check (412)
// prints the checks table and exits 1; a port another Tailscale entry uses
// (409) says how to see it.
func ingressError(ctx context.Context, cmd *cobra.Command, c *Client, err error, kind string) error {
	ce := core.AsError(err)
	switch {
	case ce == nil:
		return err
	case ce.Code == core.ErrPrecondition.Code:
		if !G.JSON {
			if st, gerr := getIngress(ctx, c, false); gerr == nil {
				e := st.Funnel
				if kind == core.IngressServe {
					e = st.Serve
				}
				_ = renderChecks(cmd.ErrOrStderr(), e.Checks)
			}
		}
		return &ExitCodeError{Code: ExitFailure, Err: err}
	case ce.Code == core.ErrConflict.Code && ce.Field == "port":
		return &hintError{err, `another Tailscale Serve or Funnel entry uses that port (see "tailscale serve status"); pick another --port`}
	}
	return noIngressHint(err)
}

// publicHost is "<name>" or "<name>:<port>" of the Funnel address.
func publicHost(st *core.IngressStatus, port int) string {
	name := ""
	if st.Tailscale != nil {
		name = st.Tailscale.DNSName
	}
	if name == "" {
		name = "<machine>.<tailnet>.ts.net"
	}
	if port != 0 && port != 443 {
		name += fmt.Sprintf(":%d", port)
	}
	return name
}

// ingressDone prints the answer of a Funnel/Serve change: the status with
// --json; offline, that it applies when the server starts; else the state.
func ingressDone(cmd *cobra.Command, st *core.IngressStatus, kind string) error {
	if G.JSON {
		return PrintJSON(cmd.OutOrStdout(), st)
	}
	e, name := st.Funnel, "Funnel"
	if kind == core.IngressServe {
		e, name = st.Serve, "Tailscale Serve"
	}
	switch e.State {
	case core.IngressStateStopped:
		Successf(cmd, "Saved. FileParcel publishes it on Tailscale when the server starts.")
	case core.IngressStateOff:
		Successf(cmd, "%s is off", name)
	case core.IngressStateActive:
		Successf(cmd, "%s is %s", name, ingressLine(e))
		if kind == core.IngressFunnel && (e.AppliedAt == nil || time.Since(*e.AppliedAt) < 10*time.Minute) {
			Infof(cmd, "It can take up to 10 minutes until the name works on the internet.")
		}
	default:
		Warnf(cmd, "%s: %s", name, ingressLine(e))
		_ = renderChecks(cmd.OutOrStdout(), e.Checks)
	}
	return nil
}

func newNetworkFunnelCmd() *cobra.Command {
	cmd := groupCmd("funnel", "Publish FileParcel on the internet with Tailscale Funnel",
		`Tailscale Funnel makes FileParcel reachable from the whole internet at
https://<machine>.<tailnet>.ts.net, without opening ports on your router.
Tailscale handles HTTPS and passes the requests to FileParcel over a private
local connection.

Two modes:
  shares  only share links and file requests work from the internet;
          everything else answers "not found" (the default)
  app     the whole web app; anyone can reach the sign-in page, two-factor
          sign-in is required over Funnel and admin pages stay blocked
          unless --allow-admin

It needs Tailscale signed in to tailscale.com (Headscale has no Funnel),
HTTPS certificates and Funnel allowed for this machine in the tailnet
policy; "fileparcel network funnel status" checks each of these and says how
to fix them. Public port: 443 (the first time), 8443 or 10000, never the port
FileParcel itself uses; a later "enable" keeps the port unless --port is
given. The public name can take up to 10 minutes to work.

`+confirmNote+"\n"+elevationNote,
		`  fileparcel network funnel
  fileparcel network funnel enable
  fileparcel network funnel enable --mode app --port 8443
  fileparcel network funnel disable`)
	cmd.Annotations = map[string]string{annBare: "status"}
	status := newIngressStatusCmd(core.IngressFunnel)
	cmd.RunE = func(c *cobra.Command, args []string) error {
		if len(args) > 0 {
			return unknownCommandError(c, args[0])
		}
		return runIngressStatus(c, core.IngressFunnel, false)
	}
	cmd.AddCommand(status, newFunnelEnableCmd(), newFunnelDisableCmd(), newIngressReapplyCmd("funnel"))
	return cmd
}

// newIngressStatusCmd is "network funnel status" or "network
// tailscale-serve status".
func newIngressStatusCmd(kind string) *cobra.Command {
	var refresh bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show whether Funnel is on, its address and what is missing",
		Long: `Show the state of Tailscale Funnel: whether it is on and in which mode, the
public address and port, how Tailscale reaches FileParcel, the last request
from the internet, and every check it needs (Tailscale running, HTTPS
certificates, Funnel allowed for this device, …) with how to fix a failing
one. --refresh reads Tailscale again instead of using what the server read
up to 30 seconds ago.`,
		Example: `  fileparcel network funnel status
  fileparcel network funnel status --refresh --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { return runIngressStatus(cmd, kind, refresh) },
	}
	if kind == core.IngressServe {
		cmd.Short = "Show whether Serve is on, its address and what is missing"
		cmd.Long = `Show the state of Tailscale Serve: whether it is on, the tailnet address and
port, how Tailscale reaches FileParcel and every check it needs, with how to
fix a failing one. --refresh reads Tailscale again instead of using what the
server read up to 30 seconds ago.`
		cmd.Example = `  fileparcel network tailscale-serve status
  fileparcel network tailscale-serve status --refresh --json`
	}
	cmd.Flags().BoolVar(&refresh, "refresh", false, "read the state of Tailscale again now")
	return cmd
}

func runIngressStatus(cmd *cobra.Command, kind string, refresh bool) error {
	return WithClient(cmd, func(ctx context.Context, c *Client) error {
		st, err := getIngress(ctx, c, refresh)
		if err != nil {
			return err
		}
		return Print(cmd, st, func(w io.Writer) error { return renderIngress(w, st, kind) })
	})
}

// funnelEffective returns what admin pages and two-factor sign-in will be
// over Funnel after the change in: the flags where given, else the stored
// settings (they are kept while Funnel is off or in shares mode, so turning
// app mode on brings them back).
func funnelEffective(st *core.IngressStatus, in core.FunnelInput) (allowAdmin, require2FA bool) {
	allowAdmin, require2FA = st.AllowAdmin, st.Require2FA
	if in.AllowAdmin != nil {
		allowAdmin = *in.AllowAdmin
	}
	if in.Require2FA != nil {
		require2FA = *in.Require2FA
	}
	return allowAdmin, require2FA
}

// funnelWidens reports what a Funnel change opens up in app mode: admin
// pages and sign-in without a second factor, each when it becomes true now
// (the flags change it, or app mode starts with it stored).
func funnelWidens(st *core.IngressStatus, in core.FunnelInput) (admin, no2FA bool) {
	if in.Mode != core.FunnelApp {
		return false, false
	}
	toApp := cmp.Or(st.Funnel.Mode, core.FunnelOff) != core.FunnelApp
	allowAdmin, require2FA := funnelEffective(st, in)
	admin = allowAdmin && (toApp || !st.AllowAdmin)
	no2FA = !require2FA && (toApp || st.Require2FA)
	return admin, no2FA
}

// widenQuestions are the questions a Funnel change asks before it is sent
// with confirm "public": what becomes reachable from the internet,
// including admin pages or sign-in without two-factor that switching to app
// mode brings back from the stored settings.
func widenQuestions(st *core.IngressStatus, in core.FunnelInput) []string {
	port := cmp.Or(in.Port, st.Funnel.Port)
	host := publicHost(st, port)
	cur := cmp.Or(st.Funnel.Mode, core.FunnelOff)
	var qs []string
	switch {
	case in.Mode == core.FunnelApp && cur != core.FunnelApp:
		qs = append(qs, fmt.Sprintf("FileParcel's sign-in page will be reachable from the whole internet at https://%s/. Continue?", host))
	case in.Mode == core.FunnelShares && cur == core.FunnelOff:
		qs = append(qs, fmt.Sprintf("Share links and file requests will be reachable from the whole internet at https://%s/s/…. Continue?", host))
	}
	admin, no2FA := funnelWidens(st, in)
	if admin {
		qs = append(qs, "Admin pages will be reachable over Funnel. Continue?")
	}
	if no2FA {
		qs = append(qs, "Accounts without two-factor sign-in will be able to sign in over Funnel. Continue?")
	}
	return qs
}

// funnelPorts are the public ports Tailscale Funnel supports.
var funnelPorts = []int{443, 8443, 10000}

func newFunnelEnableCmd() *cobra.Command {
	var mode string
	var port int
	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Publish share links (or the whole app) on the internet",
		Long: `Turn Tailscale Funnel on, or change its mode or port. --mode shares (the
default when Funnel is off) publishes only share links and file requests;
--mode app the whole web app with its sign-in page. In app mode two-factor
sign-in is required over Funnel (--no-require-2fa lifts that) and admin pages
stay blocked (--allow-admin opens them); only an owner or administrator may
weaken these. Both are kept while Funnel is off or shares only, and come back
with --mode app. Whatever becomes reachable from the internet is asked about
first. The port stays as it is unless --port. With the server stopped the
change is saved and published when it starts.

` + confirmNote + "\n" + elevationNote,
		Example: `  fileparcel network funnel enable
  fileparcel network funnel enable --mode app -y`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			f := cmd.Flags()
			mode = strings.ToLower(strings.TrimSpace(mode))
			if f.Changed("mode") && mode != core.FunnelShares && mode != core.FunnelApp {
				return UsageError("--mode must be shares or app (got %q; \"fileparcel network funnel disable\" turns it off)", mode)
			}
			if f.Changed("port") && !slices.Contains(funnelPorts, port) {
				return UsageError("--port must be 443, 8443 or 10000 (the ports Tailscale Funnel supports)")
			}
			appFlag := ""
			for _, n := range []string{"allow-admin", "no-allow-admin", "require-2fa", "no-require-2fa"} {
				if f.Changed(n) && appFlag == "" {
					appFlag = n
				}
			}
			if mode == core.FunnelShares && appFlag != "" {
				return UsageError("--%s only applies to --mode app", appFlag)
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				st, err := getIngress(ctx, c, false)
				if err != nil {
					return err
				}
				in := core.FunnelInput{Mode: mode}
				if in.Mode == "" {
					in.Mode = cmp.Or(st.Funnel.Mode, core.FunnelOff)
					if in.Mode == core.FunnelOff {
						in.Mode = core.FunnelShares
					}
				}
				if in.Mode == core.FunnelShares && appFlag != "" {
					return UsageError("--%s only applies to --mode app (Funnel is in mode shares; add --mode app)", appFlag)
				}
				if f.Changed("port") {
					in.Port = port
				}
				// --allow-admin=false blocks admin pages like --no-allow-admin.
				in.AllowAdmin, in.Require2FA = onOff(f, "allow-admin"), onOff(f, "require-2fa")
				qs := widenQuestions(st, in)
				for _, q := range qs {
					if err := confirmOrAbort(cmd, q); err != nil {
						return err
					}
				}
				if len(qs) > 0 {
					in.Confirm = "public"
				}
				admin, no2FA := funnelWidens(st, in)
				if no2FA {
					Warnf(cmd, "anyone who guesses a password can sign in over Funnel")
				}
				if admin {
					Warnf(cmd, "admin pages are reachable from the internet")
				}
				var out core.IngressStatus
				if err := c.Do(ctx, http.MethodPut, api("/admin/network/funnel"), in, &out); err != nil {
					return ingressError(ctx, cmd, c, err, core.IngressFunnel)
				}
				return ingressDone(cmd, &out, core.IngressFunnel)
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&mode, "mode", "", "shares (share links and file requests only) or app (the whole web app); default: shares when Funnel is off, else the current mode")
	f.IntVar(&port, "port", 0, "public port: 443, 8443 or 10000 (default: the current port, 443 the first time)")
	f.Bool("allow-admin", false, "app mode: let admin pages be reached over Funnel (needs two-factor sign-in)")
	f.Bool("no-allow-admin", false, "app mode: block admin pages over Funnel (the default)")
	f.Bool("require-2fa", false, "app mode: only accounts with two-factor sign-in may sign in over Funnel (the default)")
	f.Bool("no-require-2fa", false, "app mode: let accounts without two-factor sign-in sign in over Funnel")
	cmd.MarkFlagsMutuallyExclusive("allow-admin", "no-allow-admin")
	cmd.MarkFlagsMutuallyExclusive("require-2fa", "no-require-2fa")
	return cmd
}

func newFunnelDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable",
		Short: "Stop publishing FileParcel on the internet",
		Long: `Turn Tailscale Funnel off: FileParcel's Funnel entry is removed from Tailscale
and nothing is reachable from the internet through it any more. Share links
keep working on your other addresses.

` + elevationNote,
		Example: `  fileparcel network funnel disable
  fileparcel network funnel disable --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				var out core.IngressStatus
				if err := c.Do(ctx, http.MethodPut, api("/admin/network/funnel"), core.FunnelInput{Mode: core.FunnelOff}, &out); err != nil {
					return ingressError(ctx, cmd, c, err, core.IngressFunnel)
				}
				return ingressDone(cmd, &out, core.IngressFunnel)
			})
		},
	}
}

// newIngressReapplyCmd is "reapply" of network funnel or network
// tailscale-serve (parent: "funnel" or "tailscale-serve").
func newIngressReapplyCmd(parent string) *cobra.Command {
	kind := core.IngressFunnel
	if parent != "funnel" {
		kind = core.IngressServe
	}
	return &cobra.Command{
		Use:   "reapply",
		Short: "Write FileParcel's Funnel and Serve entries to Tailscale again",
		Long: `Write FileParcel's Funnel and Serve entries to Tailscale again, for example
after "needs attention" (the entry was removed or changed in Tailscale), and
check them anew.

` + elevationNote,
		Example: fmt.Sprintf(`  fileparcel network %[1]s reapply
  fileparcel network %[1]s reapply --json`, parent),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				var out core.IngressStatus
				if err := c.Do(ctx, http.MethodPost, api("/admin/network/tailscale/reapply"), nil, &out); err != nil {
					return ingressError(ctx, cmd, c, err, kind)
				}
				if G.JSON {
					return PrintJSON(cmd.OutOrStdout(), &out)
				}
				switch {
				case out.Funnel.State == core.IngressStateStopped || out.Serve.State == core.IngressStateStopped:
					// The server is stopped: nothing was written.
					Successf(cmd, "Saved. FileParcel publishes it on Tailscale when the server starts.")
				case out.Funnel.State == core.IngressStateOff && out.Serve.State == core.IngressStateOff:
					Successf(cmd, "Funnel and Serve are off; FileParcel has no entries in Tailscale")
				default:
					Successf(cmd, "wrote FileParcel's entries to Tailscale again")
				}
				return renderIngressLines(cmd.OutOrStdout(), &out)
			})
		},
	}
}

// renderIngressLines prints the one-line states of Funnel and Serve.
func renderIngressLines(w io.Writer, st *core.IngressStatus) error {
	kv := NewKV()
	kv.Add("Funnel", ingressLine(st.Funnel))
	kv.Add("Serve", ingressLine(st.Serve))
	return kv.Render(w)
}

func newNetworkTailscaleServeCmd() *cobra.Command {
	cmd := groupCmd("tailscale-serve", "Tailnet HTTPS address without a port (Tailscale Serve)",
		`Tailscale Serve gives the devices on your tailnet the address
https://<machine>.<tailnet>.ts.net/ (no port number, a certificate every
browser trusts) for the whole web app. Only tailnet devices can use it, and
the access policy still applies. It cannot share port 443 with Funnel: use
Funnel on 8443 or 10000 when both are on.

`+elevationNote,
		`  fileparcel network tailscale-serve
  fileparcel network tailscale-serve enable
  fileparcel network tailscale-serve disable`, "ts-serve")
	// "network serve" is not "fileparcel serve" (which runs the server).
	cmd.SuggestFor = []string{"serve"}
	cmd.Annotations = map[string]string{annBare: "status"}
	cmd.RunE = func(c *cobra.Command, args []string) error {
		if len(args) > 0 {
			return unknownCommandError(c, args[0])
		}
		return runIngressStatus(c, core.IngressServe, false)
	}
	cmd.AddCommand(newIngressStatusCmd(core.IngressServe), newServeToggleCmd(true), newServeToggleCmd(false),
		newIngressReapplyCmd("tailscale-serve"))
	return cmd
}

// newServeToggleCmd is "network tailscale-serve enable" (on) or "disable".
func newServeToggleCmd(on bool) *cobra.Command {
	var port int
	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Give the tailnet an HTTPS address without a port",
		Long: `Turn Tailscale Serve on: the devices on your tailnet reach FileParcel at
https://<machine>.<tailnet>.ts.net/ (or :PORT with --port). It asks nothing
first: only tailnet devices can use it. With the server stopped the change is
saved and published when it starts.

` + elevationNote,
		Example: `  fileparcel network tailscale-serve enable
  fileparcel network tailscale-serve enable --port 8443`,
		Args: cobra.NoArgs,
	}
	if !on {
		cmd.Use = "disable"
		cmd.Short = "Remove the tailnet address without a port"
		cmd.Long = `Turn Tailscale Serve off: FileParcel's Serve entry is removed from Tailscale.
The tailnet devices keep the other addresses ("fileparcel network urls").

` + elevationNote
		cmd.Example = `  fileparcel network tailscale-serve disable
  fileparcel network tailscale-serve disable --json`
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if on && cmd.Flags().Changed("port") && (port < 1 || port > 65535) {
			return UsageError("--port must be between 1 and 65535")
		}
		return WithClient(cmd, func(ctx context.Context, c *Client) error {
			in := core.ServeInput{Enabled: on}
			if on && cmd.Flags().Changed("port") {
				in.Port = port
			}
			var out core.IngressStatus
			if err := c.Do(ctx, http.MethodPut, api("/admin/network/serve"), in, &out); err != nil {
				// A port Funnel uses: say how to move Funnel (409, or 422
				// "different from the other kind's port").
				if ce := core.AsError(err); on && ce != nil && ce.Field == "port" {
					if st, gerr := getIngress(ctx, c, false); gerr == nil && st.Funnel.State != core.IngressStateOff &&
						st.Funnel.Port == cmp.Or(in.Port, st.Serve.Port, 443) {
						return &hintError{err, fmt.Sprintf(`Funnel uses port %d: run "fileparcel network funnel enable --port 10000" first, or pick --port`,
							st.Funnel.Port)}
					}
				}
				return ingressError(ctx, cmd, c, err, core.IngressServe)
			}
			return ingressDone(cmd, &out, core.IngressServe)
		})
	}
	if on {
		cmd.Flags().IntVar(&port, "port", 0, "tailnet HTTPS port, 1-65535 (default: the current port, 443 the first time)")
	}
	return cmd
}
