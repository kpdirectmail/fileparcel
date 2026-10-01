package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"fileparcel/internal/config"
	"fileparcel/internal/core"
)

func init() { Register(newNetworkCmd) }

func newNetworkCmd() *cobra.Command {
	cmd := groupCmd("network", "Show addresses and control who may connect",
		`Shows how the server can be reached (addresses per network, with QR codes for
phones), the VPNs on this machine, whether Tailscale Funnel publishes it on
the internet, and the access policy that decides which addresses may connect
at all:

  private    this machine, home networks and VPNs (private address ranges)
  allowlist  this machine plus the networks you allow (the default)
  any        every address (only behind a firewall, with 2FA for everyone)

The deny list always wins; this machine (loopback) is always allowed. A change
that would lock out your own connection is refused unless --force.
"fileparcel network" alone shows everything at a glance.`,
		`  fileparcel network
  fileparcel network urls --qr
  fileparcel network allow add 192.168.1.0/24
  fileparcel network funnel enable`, "net")
	// "fileparcel network" alone shows the overview, like "network status".
	cmd.Annotations = map[string]string{annBare: "status"}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return unknownCommandError(cmd, args[0])
		}
		return runNetworkOverview(cmd)
	}
	cmd.AddCommand(newNetworkStatusCmd(), newNetworkURLsCmd(), newNetworkInterfacesCmd(), newNetworkPolicyCmd(),
		newNetworkListCmd("allow"), newNetworkListCmd("deny"), newNetworkModeCmd(), newNetworkVPNCmd(), newNetworkFunnelCmd(),
		newNetworkTailscaleServeCmd(), newMDNSCmd())
	return cmd
}

// newNetworkStatusCmd is "network status", the overview that "fileparcel
// network" alone prints too.
func newNetworkStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "status",
		Aliases: []string{"show"},
		Short:   "Show addresses, policy, VPNs and Funnel at a glance",
		Long: `Show how the server can be reached and who may connect: the addresses, the
access policy with your own address, remote access (Tailscale Funnel and
Serve, the VPNs on this machine), the Tailscale state and ways around the
access policy that need attention. "fileparcel network" alone prints the
same. --json prints the whole overview.`,
		Example: `  fileparcel network status
  fileparcel network status --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { return runNetworkOverview(cmd) },
	}
}

func getNetwork(ctx context.Context, c *Client) (*core.NetworkOverview, error) {
	var ov core.NetworkOverview
	if err := c.Do(ctx, http.MethodGet, api("/admin/network"), nil, &ov); err != nil {
		return nil, err
	}
	return &ov, nil
}

func runNetworkOverview(cmd *cobra.Command) error {
	return WithClient(cmd, func(ctx context.Context, c *Client) error {
		ov, err := getNetwork(ctx, c)
		if err != nil {
			return err
		}
		return Print(cmd, ov, func(w io.Writer) error {
			fmt.Fprintln(w, Bold("Access URLs"))
			if err := renderURLs(w, ov.URLs); err != nil {
				return err
			}
			fmt.Fprintln(w)
			fmt.Fprintln(w, Bold("Access policy"))
			if err := renderPolicy(w, ov.Policy, ov.ClientIP); err != nil {
				return err
			}
			if err := renderRemoteAccess(w, ov); err != nil {
				return err
			}
			if ov.Tailscale != nil && ov.Tailscale.Running {
				fmt.Fprintln(w)
				fmt.Fprintln(w, Bold("Tailscale"))
				kv := NewKV()
				kv.Add("Name", ov.Tailscale.DNSName)
				kv.Add("Tailnet", ov.Tailscale.Tailnet)
				kv.Add("Certificates possible", ov.Tailscale.CertCapable)
				if err := kv.Render(w); err != nil {
					return err
				}
			}
			return renderExposures(w, ov.Exposures)
		})
	})
}

// renderRemoteAccess prints the "Remote access" block of the overview:
// Funnel and Serve in one line each and the VPN table. Servers from before
// Funnel and VPN detection send neither (the block is left out).
func renderRemoteAccess(w io.Writer, ov *core.NetworkOverview) error {
	if ov.Ingress == nil && ov.VPNs == nil {
		return nil
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, Bold("Remote access"))
	kv := NewKV()
	if st := ov.Ingress; st != nil {
		funnel := ingressLine(st.Funnel)
		if funnel == "off" {
			funnel += " (fileparcel network funnel enable)"
		}
		kv.Add("Funnel", funnel)
		kv.Add("Serve", ingressLine(st.Serve))
	}
	if ov.VPNs != nil && len(ov.VPNs) == 0 {
		kv.Add("VPNs", "none found")
	}
	if err := kv.Render(w); err != nil {
		return err
	}
	if len(ov.VPNs) == 0 {
		return nil
	}
	fmt.Fprintln(w)
	return renderVPNs(w, ov.VPNs)
}

// renderExposures prints the ways around the access policy the server
// found (a proxy, Tailscale without a TUN device, …), the worst first.
func renderExposures(w io.Writer, exps []core.Exposure) error {
	if len(exps) == 0 {
		return nil
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, Bold("Needs attention"))
	for _, sev := range []string{"fail", "warn", "info"} {
		mark := map[string]string{"fail": Red("✗"), "warn": Yellow("!"), "info": "i"}[sev]
		for _, e := range exps {
			if e.Severity != sev {
				continue
			}
			fmt.Fprintf(w, "%s %s\n", mark, sanitizeCell(e.Message))
			if e.Hint != "" {
				fmt.Fprintf(w, "  %s\n", sanitizeCell(e.Hint))
			}
		}
	}
	return nil
}

func renderURLs(w io.Writer, urls []core.AccessURL) error {
	t := NewTable("URL", "VIA", "TRUSTED", "NOTE")
	for _, u := range urls {
		via := u.Label
		if u.Interface != "" && !strings.Contains(via, u.Interface) {
			via = strings.TrimSpace(via + " (" + u.Interface + ")")
		}
		rec := ""
		if u.Recommended {
			rec = "recommended"
		}
		t.Add(u.URL, via, u.Trusted, rec)
	}
	return t.Render(w)
}

func renderPolicy(w io.Writer, p core.AccessPolicy, clientIP string) error {
	kv := NewKV()
	kv.Add("Mode", p.Mode)
	kv.Add("Allow", strings.Join(p.Allow, ", "))
	kv.Add("Deny", strings.Join(p.Deny, ", "))
	if clientIP != "" {
		kv.Add("Your address", clientIP)
	}
	return kv.Render(w)
}

func newNetworkURLsCmd() *cobra.Command {
	var qr, recommended bool
	cmd := &cobra.Command{
		Use:   "urls",
		Short: "List the addresses the server can be reached at",
		Long: `List the HTTPS addresses of the server: one per network address, the .local
name, the Tailscale MagicDNS name and configured public names. --qr adds a QR
code per address for phones.`,
		Example: `  fileparcel network urls
  fileparcel network urls --recommended --qr`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				urls, err := doList[core.AccessURL](ctx, c, http.MethodGet, api("/network/urls"), nil)
				if err != nil {
					return err
				}
				if recommended {
					urls = slices.DeleteFunc(urls, func(u core.AccessURL) bool { return !u.Recommended })
				}
				return Print(cmd, urls, func(w io.Writer) error {
					if len(urls) == 0 {
						Infof(cmd, "no access URLs")
						return nil
					}
					if !qr {
						return renderURLs(w, urls)
					}
					for _, u := range urls {
						fmt.Fprintf(w, "%s  %s\n", Bold(u.URL), Dim(u.Label))
						if err := PrintQR(w, u.URL); err != nil {
							return err
						}
					}
					return nil
				})
			})
		},
	}
	cmd.Flags().BoolVar(&qr, "qr", false, "print a QR code for each URL")
	cmd.Flags().BoolVar(&recommended, "recommended", false, "only the recommended URLs")
	return cmd
}

func newNetworkInterfacesCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "interfaces",
		Aliases: []string{"if", "ifaces"},
		Short:   "List network interfaces (LAN, Wi-Fi, VPNs)",
		Long: `List the network interfaces of this machine with their kind (LAN, Wi-Fi,
Tailscale, WireGuard, ZeroTier, …), their role, state and addresses. The role
says what FileParcel uses an interface for: mesh or unknown (a VPN whose
devices can connect), local (LAN, Wi-Fi), egress or access (outgoing only),
overlay (a public overlay) or none; "fileparcel network vpn role" corrects it.`,
		Example: `  fileparcel network interfaces
  fileparcel network interfaces --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				ov, err := getNetwork(ctx, c)
				if err != nil {
					return err
				}
				return Print(cmd, ov.Interfaces, func(w io.Writer) error {
					t := NewTable("NAME", "KIND", "ROLE", "UP", "MTU", "ADDRESSES")
					for _, i := range ov.Interfaces {
						addrs := make([]string, len(i.Addrs))
						for k, a := range i.Addrs {
							addrs[k] = a.String()
						}
						role := roleText(i.Role, i.RoleSource)
						if i.Role == "" && i.IsVPN { // a server from before interface roles
							role = "vpn"
						}
						t.Add(i.Name, i.Label, role, i.Up, i.MTU, strings.Join(addrs, ", "))
					}
					return t.Render(w)
				})
			})
		},
	}
}

func newNetworkPolicyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "policy",
		Short: "Show who may connect (mode, allow and deny lists)",
		Long:  "Show the access mode, the allow and deny lists and the address you connect from.",
		Example: `  fileparcel network policy
  fileparcel network policy --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				ov, err := getNetwork(ctx, c)
				if err != nil {
					return err
				}
				return Print(cmd, ov.Policy, func(w io.Writer) error { return renderPolicy(w, ov.Policy, ov.ClientIP) })
			})
		},
	}
}

// normalizeCIDR validates a CIDR or single IP and returns its canonical form.
func normalizeCIDR(s string) (string, error) {
	p, err := config.ParsePrefixOrAddr(strings.TrimSpace(s))
	if err != nil {
		return "", UsageError("%q is not an IP address or CIDR (e.g. 192.168.1.0/24, fd7a:115c:a1e0::/48)", s)
	}
	if p.IsSingleIP() {
		return p.Addr().String(), nil
	}
	return p.Masked().String(), nil
}

func samePrefix(a, b string) bool {
	pa, err1 := config.ParsePrefixOrAddr(a)
	pb, err2 := config.ParsePrefixOrAddr(b)
	if err1 != nil || err2 != nil {
		return strings.EqualFold(a, b)
	}
	return pa.Masked() == pb.Masked()
}

// setPolicy sends PUT /admin/network/policy and prints the warnings.
func setPolicy(ctx context.Context, cmd *cobra.Command, c *Client, p core.AccessPolicy, force bool) (*core.PolicyResult, error) {
	in := core.PolicyInput{Mode: p.Mode, Allow: p.Allow, Deny: p.Deny, Force: force}
	if in.Allow == nil {
		in.Allow = []string{}
	}
	if in.Deny == nil {
		in.Deny = []string{}
	}
	var res core.PolicyResult
	if err := c.Do(ctx, http.MethodPut, api("/admin/network/policy"), in, &res); err != nil {
		if ce := core.AsError(err); ce != nil && ce.Code == core.ErrConflict.Code && !force {
			return nil, &hintError{err, "the change would lock out the client making it; re-run with --force if that is intended"}
		}
		return nil, err
	}
	for _, w := range res.Warnings {
		Warnf(cmd, "%s", w)
	}
	return &res, nil
}

// networkListTexts are the help texts of "network allow" and "network deny";
// examples: two argument lists for "add", then two for "remove".
var networkListTexts = map[string]struct {
	group, long, list, add, remove string
	examples                       [4]string
}{
	"allow": {
		group: "Manage the networks allowed to connect",
		long: `The addresses and address ranges that may connect in allowlist mode, and in
private mode in addition to the private ranges (network.allow_cidrs). This
machine (loopback) is always allowed.`,
		list: "Show the allowed networks", add: "Allow networks or addresses to connect",
		remove:   "Stop allowing networks or addresses",
		examples: [4]string{"192.168.1.0/24", "10.8.0.0/24 192.168.1.20", "192.168.1.0/24", "10.8.0.0/24 --force"},
	},
	"deny": {
		group: "Manage the networks that may never connect",
		long: `The addresses and address ranges that may never connect, in every mode
(network.deny_cidrs); the deny list wins over the allow list.`,
		list: "Show the blocked networks", add: "Block networks or addresses",
		remove:   "Unblock networks or addresses",
		examples: [4]string{"192.168.1.66", "203.0.113.0/24 198.51.100.7", "192.168.1.66", "203.0.113.0/24"},
	},
}

func newNetworkListCmd(which string) *cobra.Command {
	t := networkListTexts[which]
	cmd := groupCmd(which, t.group, t.long,
		fmt.Sprintf(`  fileparcel network %[1]s list
  fileparcel network %[1]s add %[2]s
  fileparcel network %[1]s remove %[2]s`, which, t.examples[0]))
	get := func(p core.AccessPolicy) []string {
		if which == "allow" {
			return p.Allow
		}
		return p.Deny
	}
	put := func(p *core.AccessPolicy, l []string) {
		if which == "allow" {
			p.Allow = l
		} else {
			p.Deny = l
		}
	}
	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   t.list,
		Long:    fmt.Sprintf("Show the addresses and address ranges of the %s list (network.%s_cidrs).", which, which),
		Example: fmt.Sprintf(`  fileparcel network %[1]s list
  fileparcel network %[1]s list --json`, which),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				ov, err := getNetwork(ctx, c)
				if err != nil {
					return err
				}
				l := get(ov.Policy)
				if l == nil {
					l = []string{}
				}
				return Print(cmd, l, func(w io.Writer) error {
					if len(l) == 0 {
						Infof(cmd, "the %s list is empty", which)
					}
					for _, e := range l {
						fmt.Fprintln(w, e)
					}
					return nil
				})
			})
		},
	}
	var force bool
	change := func(add bool) *cobra.Command {
		verb, short, examples, aliases := "remove", t.remove, t.examples[2:], []string{"rm"}
		what := "Remove addresses or address ranges (192.168.1.0/24) from the " + which + " list."
		if add {
			verb, short, examples, aliases = "add", t.add, t.examples[:2], nil
			what = "Add addresses or address ranges (192.168.1.0/24) to the " + which + " list."
		}
		cmd := &cobra.Command{
			Use:     verb + " <cidr|ip>...",
			Aliases: aliases,
			Short:   short,
			Long: what + `
A change that would lock out your own connection is refused unless --force.

` + elevationNote,
			Example: fmt.Sprintf(`  fileparcel network %[1]s %[2]s %[3]s
  fileparcel network %[1]s %[2]s %[4]s`, which, verb, examples[0], examples[1]),
			Args: cobra.MinimumNArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				var entries []string
				for _, a := range args {
					n, err := normalizeCIDR(a)
					if err != nil {
						return err
					}
					entries = append(entries, n)
				}
				return WithClient(cmd, func(ctx context.Context, c *Client) error {
					ov, err := getNetwork(ctx, c)
					if err != nil {
						return err
					}
					p := ov.Policy
					l := slices.Clone(get(p))
					for _, e := range entries {
						has := slices.ContainsFunc(l, func(x string) bool { return samePrefix(x, e) })
						switch {
						case add && !has:
							l = append(l, e)
						case !add && has:
							l = slices.DeleteFunc(l, func(x string) bool { return samePrefix(x, e) })
						case !add:
							Warnf(cmd, "%s is not in the %s list", e, which)
						}
					}
					put(&p, l)
					res, err := setPolicy(ctx, cmd, c, p, force)
					if err != nil {
						return err
					}
					// Allowlist and private mode both admit the allow list
					// (private: in addition to the private ranges); only "any"
					// ignores it.
					if which == "allow" && add && p.Mode == core.AccessAny {
						Infof(cmd, "Note: the allow list is not used in mode %q (every address may connect).", p.Mode)
					}
					return done(cmd, res, "%s list: %s", which, Dash(strings.Join(get(res.Policy), ", ")))
				})
			},
		}
		cmd.Flags().BoolVar(&force, "force", false, "apply even if it locks out the client making the change")
		return cmd
	}
	cmd.AddCommand(list, change(true), change(false))
	return cmd
}

func newNetworkModeCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "mode <private|allowlist|any>",
		Short: "Choose who may connect",
		Long: `Choose who may connect (network.access_mode): private (this machine, home
networks and VPNs), allowlist (this machine plus the allow list) or any. "any"
lets every address that can reach the server connect: use it only behind a
firewall or with a public certificate and two-factor sign-in for everyone. A
change that would lock out your own connection is refused unless --force.

` + elevationNote,
		Example: `  fileparcel network mode allowlist
  fileparcel network mode private
  fileparcel network mode any --force`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{core.AccessPrivate, core.AccessAllowlist, core.AccessAny},
		RunE: func(cmd *cobra.Command, args []string) error {
			mode := strings.ToLower(args[0])
			if !slices.Contains([]string{core.AccessPrivate, core.AccessAllowlist, core.AccessAny}, mode) {
				return UsageError("invalid mode %q (private, allowlist or any)", args[0])
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				ov, err := getNetwork(ctx, c)
				if err != nil {
					return err
				}
				p := ov.Policy
				p.Mode = mode
				if mode == core.AccessAllowlist && len(p.Allow) == 0 {
					Warnf(cmd, "the allow list is empty: only loopback will be able to connect (add ranges with \"network allow add\")")
				}
				if mode == core.AccessAny {
					Warnf(cmd, "mode \"any\" accepts connections from every address that can reach this machine")
				}
				res, err := setPolicy(ctx, cmd, c, p, force)
				if err != nil {
					return err
				}
				return done(cmd, res, "access mode is now %s", res.Policy.Mode)
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "apply even if it locks out the client making the change")
	return cmd
}

// ---------- mdns ----------

// mdnsStatusOut is the --json shape of "network mdns status": the
// responder's live state plus the settings it is converging on. The two
// differ for a few seconds after a write, because the responder re-publishes
// asynchronously.
type mdnsStatusOut struct {
	core.MDNSStatus
	SettingMode string `json:"setting_mode,omitempty"`
	SettingName string `json:"setting_name,omitempty"`
}

// withSetting renders a running value, naming the configured one while the
// responder has not caught up yet.
func withSetting(running, setting string) string {
	if setting == "" || strings.EqualFold(running, setting) {
		return running
	}
	return fmt.Sprintf("%s (running; %q configured, republishing)", running, setting)
}

// mdnsNameLine renders the published name. It differs from st.Configured
// (the <name>.local built from mdns.name / server.name) while a collision
// rename is in effect (§10.5), a lasting state rather than a pending
// republish; only a setting that differs from st.Configured means the
// responder has not caught up with a settings change yet. Older servers omit
// Configured, so the running name stands in for it then.
func mdnsNameLine(st core.MDNSStatus, settingName string) string {
	line := st.Name
	if st.Name != "" && st.Configured != "" && !strings.EqualFold(st.Name, st.Configured) {
		line += fmt.Sprintf(" (renamed after a name collision; configured: %s)", st.Configured)
	}
	ref := st.Configured
	if ref == "" {
		ref = st.Name
	}
	if want := mdnsFQDN(settingName); want != "" && !strings.EqualFold(want, ref) {
		line += fmt.Sprintf(" (running; %q configured, republishing)", want)
	}
	return line
}

// mdnsFQDN turns the mdns.name label into the name it is published as
// ("" = derived from server.name, which cannot be compared here).
func mdnsFQDN(label string) string {
	if label == "" {
		return ""
	}
	return label + ".local"
}

func newMDNSCmd() *cobra.Command {
	cmd := groupCmd("mdns", "Manage the .local name (mDNS / Bonjour)",
		`FileParcel announces <name>.local and an _https._tcp service on the local
network through Avahi (Linux), dns-sd (macOS) or a built-in responder, so
phones and computers find it by name. The name does not reach through VPNs
such as Tailscale or WireGuard; use MagicDNS or the IP address there.`,
		`  fileparcel network mdns status
  fileparcel network mdns name files
  fileparcel network mdns mode builtin
  fileparcel network mdns disable`, "bonjour")
	status := &cobra.Command{
		Use:   "status",
		Short: "Show how the .local name is published",
		Long: `Show the configured and effective backend, the published name, the state and
the interfaces. The responder re-publishes asynchronously, so right after
"network mdns mode"/"name"/"disable" the running values still lag the
settings; both are shown until they agree. A name already taken by another
device on the LAN is published as <name>-2.local instead; the configured name
is then shown next to it.`,
		Example: `  fileparcel network mdns status
  fileparcel network mdns status --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				var st core.MDNSStatus
				if err := c.Do(ctx, http.MethodGet, api("/admin/mdns"), nil, &st); err != nil {
					return err
				}
				out := mdnsStatusOut{MDNSStatus: st}
				if list, err := settingsCatalog(ctx, c); err == nil {
					out.SettingMode = settingText(findSetting(list, "mdns.mode"))
					out.SettingName = settingText(findSetting(list, "mdns.name"))
				}
				return Print(cmd, &out, func(w io.Writer) error {
					kv := NewKV()
					kv.Add("Name", mdnsNameLine(st, out.SettingName))
					kv.Add("State", st.State)
					kv.Add("Mode", withSetting(st.Mode, out.SettingMode))
					kv.Add("Backend", st.Backend)
					kv.Add("Interfaces", strings.Join(st.Interfaces, ", "))
					kv.Add("Error", st.Error)
					return kv.Render(w)
				})
			})
		},
	}
	setMode := func(use, short, long, mode string) *cobra.Command {
		return &cobra.Command{
			Use:   use,
			Short: short,
			Long:  long + "\n\n" + elevationNote,
			Example: fmt.Sprintf(`  fileparcel network mdns %[1]s
  fileparcel network mdns %[1]s --json`, use),
			Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				return WithClient(cmd, func(ctx context.Context, c *Client) error {
					if _, err := patchSettings(ctx, cmd, c, map[string]any{"mdns.mode": mode}); err != nil {
						return err
					}
					return done(cmd, nil, "mDNS mode: %s", mode)
				})
			},
		}
	}
	modes := []string{"auto", "avahi", "dnssd", "builtin", "off"}
	mode := &cobra.Command{
		Use:   "mode <auto|avahi|dnssd|builtin|off>",
		Short: "Choose how the .local name is published",
		Long: `Choose how the .local name is published: auto (Avahi on Linux when available,
dns-sd on macOS, else built-in), avahi, dnssd, builtin (own responder on UDP
5353) or off.

` + elevationNote,
		Example: `  fileparcel network mdns mode auto
  fileparcel network mdns mode builtin`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: modes,
		RunE: func(cmd *cobra.Command, args []string) error {
			m := strings.ToLower(args[0])
			if !slices.Contains(modes, m) {
				return UsageError("invalid mode %q (%s)", args[0], strings.Join(modes, ", "))
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				if _, err := patchSettings(ctx, cmd, c, map[string]any{"mdns.mode": m}); err != nil {
					return err
				}
				return done(cmd, nil, "mDNS mode: %s", m)
			})
		},
	}
	var forceName bool
	name := &cobra.Command{
		Use:   "name <label>",
		Short: "Change the .local name",
		Long: `Set the label published as <label>.local (mdns.name; "" = server.name). The
server certificate is reissued for the new name. Changing it breaks passkeys
that use the .local name as their relying party (unless auth.webauthn_rp_id
pins it); while accounts have no second factor other than a passkey, the
change is refused unless --force.

` + elevationNote,
		Example: `  fileparcel network mdns name files
  fileparcel network mdns name ""`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			label := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(args[0])), ".local")
			if label != "" && !config.ValidDNSLabel(label) {
				return UsageError("%q is not a valid DNS label (a-z, 0-9 and '-', at most 63 characters)", args[0])
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				if _, err := patchSettingsForce(ctx, cmd, c, map[string]any{"mdns.name": label}, forceName); err != nil {
					return guardHint(err, forceName)
				}
				if label == "" {
					return done(cmd, nil, "mDNS name reset to the server name")
				}
				return done(cmd, nil, "mDNS name: %s.local", label)
			})
		},
	}
	name.Flags().BoolVar(&forceName, "force", false, "rename even though accounts that rely on a passkey alone lose it")
	republish := &cobra.Command{
		Use:   "republish",
		Short: "Announce the name again",
		Long: `Withdraw and announce the .local name again, for example after network
changes or a name collision. Needs the running server.`,
		Example: `  fileparcel network mdns republish
  fileparcel network mdns republish --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				if err := requireServer(c, "network mdns republish"); err != nil {
					return err
				}
				if err := c.Do(ctx, http.MethodPost, api("/admin/mdns/republish"), nil, nil); err != nil {
					return err
				}
				return done(cmd, nil, "mDNS records republished")
			})
		},
	}
	cmd.AddCommand(status,
		setMode("enable", "Publish the .local name", `Publish the .local name with the best way this machine offers (mdns.mode=auto;
"fileparcel network mdns mode" picks one).`, "auto"),
		setMode("disable", "Stop publishing the .local name", `Stop publishing the .local name (mdns.mode=off). Devices then reach the server
by IP address or another name.`, "off"),
		mode, name, republish)
	return cmd
}
