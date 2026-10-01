package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/cli/clikit"
	"fileparcel/internal/core"
)

func init() { Register(newCertCmd) }

// ---------- settings helpers (shared by cert, config, network, mdns, maintenance) ----------

// settingsCatalog fetches GET /admin/settings.
func settingsCatalog(ctx context.Context, c *Client) ([]core.SettingView, error) {
	return listAll[core.SettingView](ctx, c, api("/admin/settings"), 0)
}

// findSetting returns the catalog entry of key.
func findSetting(list []core.SettingView, key string) *core.SettingView {
	for i := range list {
		if list[i].Key == key {
			return &list[i]
		}
	}
	return nil
}

// getSetting fetches one setting from the catalog.
func getSetting(ctx context.Context, c *Client, key string) (*core.SettingView, error) {
	list, err := settingsCatalog(ctx, c)
	if err != nil {
		return nil, err
	}
	if s := findSetting(list, key); s != nil {
		return s, nil
	}
	return nil, core.Errorf(core.ErrNotFound, "unknown setting %q (see \"fileparcel config list --all\")", key)
}

// patchSettings applies changes with PATCH /admin/settings and reports keys
// that need a restart and the server's warnings (values applied that will
// not take full effect) on stderr.
func patchSettings(ctx context.Context, cmd *cobra.Command, c *Client, changes map[string]any) (*core.SettingsResult, error) {
	return patchSettingsForce(ctx, cmd, c, changes, false)
}

// patchSettingsForce is patchSettings with ?force=1 when force: it confirms
// a change a server guard refuses with 409 conflict (see guardHint).
func patchSettingsForce(ctx context.Context, cmd *cobra.Command, c *Client, changes map[string]any, force bool) (*core.SettingsResult, error) {
	body := make(map[string]json.RawMessage, len(changes))
	for k, v := range changes {
		switch x := v.(type) {
		case json.RawMessage:
			body[k] = x
		default:
			b, err := json.Marshal(v)
			if err != nil {
				return nil, err
			}
			body[k] = b
		}
	}
	var res core.SettingsResult
	if err := c.Do(ctx, http.MethodPatch, api("/admin/settings", "force", boolParam(force)), body, &res); err != nil {
		return nil, err
	}
	noteRestart(cmd, c, res.RestartRequired)
	for _, w := range res.Warnings {
		Warnf(cmd, "%s", w)
	}
	return &res, nil
}

// guardHint points a command with --force at it when the server refused an
// unconfirmed settings change with 409 conflict: an access policy that would
// lock out the client making it, or turning passkeys off or moving the
// passkey domain while accounts have no other second factor.
func guardHint(err error, force bool) error {
	if e, ok := envOverrideError(err); ok {
		return e
	}
	if ce := core.AsError(err); ce != nil && ce.Code == core.ErrConflict.Code && !force {
		return &hintError{err, "re-run with --force if that is intended"}
	}
	return err
}

// envOverrideError rewrites the server's refusal to change a setting that
// an environment variable of the server process sets (409 conflict, which
// --force does not change): the key once, not "log.level: log.level is set
// by …", and where to change it instead.
func envOverrideError(err error) (error, bool) {
	ce := core.AsError(err)
	if ce == nil || ce.Code != core.ErrConflict.Code || !strings.Contains(ce.Message, "environment variable") {
		return err, false
	}
	msg := ce.Message
	if ce.Field != "" && !strings.HasPrefix(msg, ce.Field+" ") {
		msg = ce.Field + ": " + msg
	}
	return &hintError{&core.Error{Code: ce.Code, Status: ce.Status, Message: msg},
		"the server's environment (for example its service unit) overrides fileparcel.toml for this setting; " +
			"unset the variable there and restart the server to change it here (--force does not help)"}, true
}

// noteRestart tells the user which changed settings need a restart.
func noteRestart(cmd *cobra.Command, c *Client, keys []string) {
	if len(keys) == 0 {
		return
	}
	if c.Mode() == ModeOffline {
		Infof(cmd, "Takes effect when the server starts: %s", strings.Join(keys, ", "))
		return
	}
	Warnf(cmd, "restart the server to apply %s (fileparcel service restart)", strings.Join(keys, ", "))
}

// settingText decodes a string-typed setting value ("" when unset or of
// another type).
func settingText(s *core.SettingView) string {
	var out string
	if s == nil || len(s.Value) == 0 {
		return ""
	}
	_ = json.Unmarshal(s.Value, &out)
	return out
}

// settingStrings decodes a strings-typed setting value.
func settingStrings(s *core.SettingView) []string {
	var out []string
	if s == nil || len(s.Value) == 0 {
		return nil
	}
	_ = json.Unmarshal(s.Value, &out)
	return out
}

// ---------- cert ----------

func newCertCmd() *cobra.Command {
	cmd := groupCmd("cert", "Manage HTTPS certificates (local CA, Tailscale, Let's Encrypt)",
		`FileParcel serves HTTPS with a certificate from its own local certificate
authority (CA) by default; devices trust it once ("fileparcel ca"). It can also
use a Tailscale certificate for its ts.net name, one from Let's Encrypt or
another ACME CA, or a certificate you upload. "fileparcel cert status" shows
which one is used for which name.`,
		`  fileparcel cert status
  fileparcel cert sans add files.example.lan
  fileparcel cert tailscale enable
  fileparcel cert acme enable --email me@example.com --domain files.example.com --challenge dns --dns-provider cloudflare --credentials-stdin`,
		"certs", "tls")
	cmd.AddCommand(newCertStatusCmd(), newCertRenewCmd(), newCertSansCmd(), newCertUploadCmd(), newCertClearCustomCmd(),
		newCertACMECmd(), newCertTailscaleCmd())
	return cmd
}

func renderCertInfo(kv *KV, prefix string, ci *core.CertInfo) {
	if ci == nil {
		kv.Add(prefix, "none")
		return
	}
	kv.Add(prefix, ci.Subject)
	kv.Add("  Issuer", ci.Issuer)
	var names []string
	names = append(names, ci.DNSNames...)
	names = append(names, ci.IPs...)
	if len(names) > 0 {
		kv.Add("  Names", strings.Join(names, ", "))
	}
	kv.Add("  Valid", fmt.Sprintf("%s → %s (%s)", HumanTime(ci.NotBefore), HumanTime(ci.NotAfter), Ago(ci.NotAfter)))
	kv.Add("  Fingerprint", ci.Fingerprint)
}

func newCertStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "status",
		Aliases: []string{"show"},
		Short:   "Show the certificates in use",
		Long: `Show the local CA, the server certificate it issued and any Tailscale, ACME or
uploaded certificate, with their names, validity and fingerprints.`,
		Example: `  fileparcel cert status
  fileparcel cert status --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				// GET /admin/certs answers core.CertStatus plus the names the
				// local CA may not sign, which the leaf therefore does not carry.
				var body struct {
					core.CertStatus
					UncoveredNames []string `json:"uncovered_names,omitempty"`
				}
				if err := c.Do(ctx, http.MethodGet, api("/admin/certs"), nil, &body); err != nil {
					return err
				}
				st := body.CertStatus
				return Print(cmd, &body, func(w io.Writer) error {
					kv := NewKV()
					renderCertInfo(kv, "Local CA", st.CA)
					if st.CA != nil {
						constraint := "unconstrained"
						if st.CAConstrained {
							constraint = "name-constrained: " + strings.Join(append(slices.Clone(st.PermittedDNS), st.PermittedIPs...), ", ")
						}
						kv.Add("  Constraints", constraint)
					}
					renderCertInfo(kv, "Leaf", st.Leaf)
					if len(body.UncoveredNames) > 0 {
						kv.Add("  Not covered", strings.Join(body.UncoveredNames, ", ")+
							` (outside the local CA's name constraints; run "fileparcel ca regenerate" to include them)`)
					}
					if st.Tailscale != nil || st.TailscaleError != "" {
						renderCertInfo(kv, "Tailscale", st.Tailscale)
						kv.Add("  Error", st.TailscaleError)
					}
					kv.Add("ACME", YesNo(st.ACMEEnabled))
					for i := range st.ACME {
						renderCertInfo(kv, "  ACME cert", &st.ACME[i])
					}
					if st.ACMEError != "" {
						kv.Add("  ACME error", st.ACMEError)
					}
					if st.Custom != nil {
						renderCertInfo(kv, "Custom", st.Custom)
					}
					renderCertInfo(kv, "Client CA (mTLS)", st.ClientCA)
					kv.Add("mTLS mode", st.MTLSMode)
					kv.Add("HSTS", st.HSTS)
					kv.Add("Publicly trusted", st.PubliclyTrusted)
					return kv.Render(w)
				})
			})
		},
	}
}

func newCertRenewCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Reissue the certificate from the local CA",
		Long: `Reissue the server certificate from the local CA if it expires within 30 days
or its names changed (--force: always). The server switches to it without a
restart. This happens automatically too.`,
		Example: `  fileparcel cert renew
  fileparcel cert renew --force`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				var body any
				if force {
					body = map[string]bool{"force": true}
				}
				if err := c.Do(ctx, http.MethodPost, api("/admin/certs/renew", "force", boolParam(force)), body, nil); err != nil {
					return err
				}
				if force {
					return done(cmd, nil, "leaf certificate reissued")
				}
				return done(cmd, nil, "leaf certificate checked (renewed if needed)")
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "reissue even if the current certificate is still fine")
	return cmd
}

// boolParam renders "true" for true and "" (omitted) for false.
func boolParam(b bool) string {
	if b {
		return "true"
	}
	return ""
}

// validSAN accepts DNS names (optionally "*." wildcards) and IP addresses.
func validSAN(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	name := strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(s), "."), "*.")
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// caPermitsName reports whether a CA with the constraints in st could issue a
// leaf carrying name (a DNS name or an IP address). It mirrors dnsPermitted
// and ipPermitted in internal/certs; an unparsable constraint is treated as
// permitting, so this never claims a working name is forbidden.
func caPermitsName(st *core.CertStatus, name string) bool {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if ip, err := netip.ParseAddr(n); err == nil {
		if len(st.PermittedIPs) == 0 {
			return true
		}
		for _, c := range st.PermittedIPs {
			pre, err := netip.ParsePrefix(strings.TrimSpace(c))
			if err != nil || pre.Masked().Contains(ip.Unmap().WithZone("")) {
				return true
			}
		}
		return false
	}
	if len(st.PermittedDNS) == 0 {
		return true
	}
	n = strings.TrimPrefix(n, "*.")
	for _, c := range st.PermittedDNS {
		c = strings.ToLower(strings.TrimSpace(c))
		if strings.HasPrefix(c, ".") {
			if strings.HasSuffix(n, c) && len(n) > len(c) {
				return true
			}
			continue
		}
		if n == c || strings.HasSuffix(n, "."+c) {
			return true
		}
	}
	return false
}

// newCertSansCmd is "cert sans": alone it lists the names; "add" and
// "remove" change tls.extra_sans. The hidden --add/--remove flags of "cert
// sans" keep the old form working (legacy.go).
func newCertSansCmd() *cobra.Command {
	var add, remove []string
	cmd := &cobra.Command{
		Use:     "sans",
		Aliases: []string{"names"},
		Short:   "Show or change the extra names in the certificate",
		Long: `Show the names the server certificate covers, or add and remove extra DNS
names and IP addresses (setting tls.extra_sans). Interface addresses, the
.local name, the host name and the Tailscale MagicDNS name are included
automatically. The certificate is reissued when the list changes.

A name the local CA's name constraints do not cover cannot go into the
certificate. It is still stored, but the certificate keeps its current names
until the CA is rebuilt for it with "fileparcel ca regenerate".`,
		Example: `  fileparcel cert sans
  fileparcel cert sans add files.home.arpa 10.8.0.1
  fileparcel cert sans remove old.example.lan`,
		Annotations: map[string]string{annBare: "list"},
		Args:        cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return unknownCommandError(cmd, args[0])
			}
			return runSANs(cmd, add, remove)
		},
	}
	// Legacy: "cert sans --add X --remove Y" (legacy.go).
	cmd.Flags().StringArrayVar(&add, "add", nil, "add a DNS name or IP address (repeatable)")
	cmd.Flags().StringArrayVar(&remove, "remove", nil, "remove a name (repeatable)")
	_ = cmd.Flags().MarkHidden("add")
	_ = cmd.Flags().MarkHidden("remove")
	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List the names the certificate covers",
		Long: `List the DNS names and IP addresses of the server certificate and the extra
names you added (tls.extra_sans). "fileparcel cert sans" alone does the same.`,
		Example: `  fileparcel cert sans list
  fileparcel cert sans list --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { return runSANs(cmd, nil, nil) },
	}
	addCmd := &cobra.Command{
		Use:   "add <name|ip>...",
		Short: "Add DNS names or IP addresses to the certificate",
		Long: `Add extra DNS names or IP addresses to the server certificate
(tls.extra_sans); the certificate is reissued. A name the local CA's name
constraints do not cover is stored but stays out of the certificate until
"fileparcel ca regenerate".`,
		Example: `  fileparcel cert sans add files.home.arpa
  fileparcel cert sans add files.home.arpa 10.8.0.1`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error { return runSANs(cmd, args, nil) },
	}
	removeCmd := &cobra.Command{
		Use:     "remove <name|ip>...",
		Aliases: []string{"rm"},
		Short:   "Remove extra names from the certificate",
		Long: `Remove extra DNS names or IP addresses (tls.extra_sans); the certificate is
reissued. Names added automatically cannot be removed.`,
		Example: `  fileparcel cert sans remove old.example.lan
  fileparcel cert sans remove 10.8.0.1 old.example.lan`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error { return runSANs(cmd, nil, args) },
	}
	cmd.AddCommand(list, addCmd, removeCmd)
	return cmd
}

// runSANs shows the certificate names (no add and no remove) or changes
// tls.extra_sans.
func runSANs(cmd *cobra.Command, add, remove []string) error {
	for _, s := range append(slices.Clone(add), remove...) {
		if !validSAN(s) {
			return UsageError("%q is not a DNS name or IP address", s)
		}
	}
	return WithClient(cmd, func(ctx context.Context, c *Client) error {
		set, err := getSetting(ctx, c, "tls.extra_sans")
		if err != nil {
			return err
		}
		extra := settingStrings(set)
		var st core.CertStatus
		stErr := c.Do(ctx, http.MethodGet, api("/admin/certs"), nil, &st)
		if len(add) == 0 && len(remove) == 0 {
			if stErr != nil {
				return stErr
			}
			out := map[string]any{"extra_sans": extra}
			if st.Leaf != nil {
				out["dns_names"], out["ips"] = st.Leaf.DNSNames, st.Leaf.IPs
			}
			return Print(cmd, out, func(w io.Writer) error {
				kv := NewKV()
				if st.Leaf != nil {
					kv.Add("Leaf DNS names", strings.Join(st.Leaf.DNSNames, ", "))
					kv.Add("Leaf IP addresses", strings.Join(st.Leaf.IPs, ", "))
				}
				kv.Add("Extra names (tls.extra_sans)", strings.Join(extra, ", "))
				return kv.Render(w)
			})
		}
		next := slices.Clone(extra)
		for _, a := range add {
			if !slices.ContainsFunc(next, func(s string) bool { return strings.EqualFold(s, a) }) {
				next = append(next, a)
			}
		}
		for _, r := range remove {
			next = slices.DeleteFunc(next, func(s string) bool { return strings.EqualFold(s, r) })
		}
		if next == nil {
			next = []string{}
		}
		// Names the CA's constraints forbid never reach the leaf:
		// desiredSANs drops them, so no reissue happens and nothing is
		// reported. Say so here instead of printing a bare success.
		var refused []string
		if stErr == nil {
			for _, a := range add {
				if !caPermitsName(&st, a) {
					refused = append(refused, a)
				}
			}
		}
		res, err := patchSettings(ctx, cmd, c, map[string]any{"tls.extra_sans": next})
		if err != nil {
			return err
		}
		out := struct {
			ExtraSANs []string `json:"extra_sans"`
			NotInLeaf []string `json:"not_in_leaf,omitempty"`
		}{next, refused}
		if err := done(cmd, out, "extra certificate names: %s", Dash(strings.Join(next, ", "))); err != nil {
			return err
		}
		if len(refused) > 0 && len(res.Warnings) == 0 { // the server's warning says the same
			Warnf(cmd, "the local CA cannot issue %s: its name constraints permit only %s",
				strings.Join(refused, ", "), Dash(strings.Join(append(slices.Clone(st.PermittedDNS), st.PermittedIPs...), ", ")))
			Infof(cmd, "the name is stored but stays out of the certificate; run \"fileparcel ca regenerate\" to rebuild the CA for it (every client has to trust the new CA again)")
		}
		return nil
	})
}

// readPEMFile reads a PEM file up to max bytes.
func readPEMFile(cmd *cobra.Command, path string, max int64, secret bool) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && secret && st.Mode().Perm()&0o044 != 0 && canChangeMode(st) {
		Warnf(cmd, "%s is readable by other users; chmod 600 it", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > max {
		return "", fmt.Errorf("%s is larger than %s", path, HumanBytes(max))
	}
	if !strings.Contains(string(data), "-----BEGIN ") {
		return "", fmt.Errorf("%s is not a PEM file", path)
	}
	return string(data), nil
}

// customCertInput is the body of PUT /admin/certs/custom.
type customCertInput struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

func newCertUploadCmd() *cobra.Command {
	var certFile, keyFile string
	cmd := &cobra.Command{
		Use:   "upload --cert FILE --key FILE",
		Short: "Use your own certificate",
		Long: `Upload a certificate chain (PEM, server certificate first) and its private key
(PEM). The server checks that they match, are valid now and are usable for
HTTPS, then serves the certificate for the names it contains. The key is
stored encrypted. "fileparcel cert clear-custom" stops using it.

` + elevationNote,
		Example: `  fileparcel cert upload --cert fullchain.pem --key privkey.pem
  fileparcel cert upload --cert fullchain.pem --key privkey.pem --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if certFile == "" || keyFile == "" {
				return UsageError("both --cert and --key are required")
			}
			certPEM, err := readPEMFile(cmd, certFile, 64<<10, false)
			if err != nil {
				return err
			}
			keyPEM, err := readPEMFile(cmd, keyFile, 16<<10, true)
			if err != nil {
				return err
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				if err := c.Do(ctx, http.MethodPut, api("/admin/certs/custom"), customCertInput{CertPEM: certPEM, KeyPEM: keyPEM}, nil); err != nil {
					return err
				}
				return done(cmd, nil, "custom certificate installed")
			})
		},
	}
	cmd.Flags().StringVar(&certFile, "cert", "", "certificate chain (PEM)")
	cmd.Flags().StringVar(&keyFile, "key", "", "private key (PEM)")
	return cmd
}

func newCertClearCustomCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clear-custom",
		Short: "Stop using the uploaded certificate",
		Long: `Remove the uploaded certificate and its key; the server falls back to the
other certificates.

` + elevationNote,
		Example: `  fileparcel cert clear-custom
  fileparcel cert clear-custom --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				if err := c.Do(ctx, http.MethodDelete, api("/admin/certs/custom"), nil, nil); err != nil {
					return err
				}
				return done(cmd, nil, "custom certificate removed")
			})
		},
	}
}

// ---------- acme ----------

func newCertACMECmd() *cobra.Command {
	cmd := groupCmd("acme", "Get certificates from Let's Encrypt (or another ACME CA)",
		`Get certificates every browser trusts with ACME (Let's Encrypt by default).
Home servers are rarely reachable from the internet, so the DNS challenge
(Cloudflare API token or RFC 2136 dynamic DNS) is the default; "http" and
"tls-alpn" need the server reachable from the internet on ports 80/443. The
Let's Encrypt test CA (staging) is used unless --production.`,
		`  echo '{"api_token":"…"}' | fileparcel cert acme enable --email me@example.com --domain files.example.com --credentials-stdin --production
  fileparcel cert acme disable`)
	var email, challenge, provider, caURL string
	var domains []string
	var credsStdin, production bool
	var credsFile string
	var wait *waitFlags
	enable := &cobra.Command{
		Use:   "enable",
		Short: "Get certificates from an ACME CA now and keep them renewed",
		Long: `Store the ACME settings (acme.*) and request the certificates now; they are
renewed automatically. The command waits up to 3 minutes for the first
certificate and fails when the CA refuses it (--no-wait returns at once; the
request then runs in the background: see "fileparcel cert status"). A request
still running after 3 minutes goes on in the background. With the server
stopped the settings are checked and used when it starts.

DNS credentials are JSON, read from standard input with --credentials-stdin or
from a file with --credentials-file FILE:
  cloudflare: {"api_token":"…"}  (optionally "zone_token")
  rfc2136:    {"server":"ns1.example.com:53","key_name":"fileparcel.","key_alg":"hmac-sha256.","key":"<base64>"}
              ("key_alg" is optional; the default is hmac-sha256.)
They are checked for the provider's required keys before anything is saved,
and stored encrypted (acme.dns_credentials).

` + elevationNote,
		Example: `  echo '{"api_token":"…"}' | fileparcel cert acme enable --email me@example.com --domain files.example.com --credentials-stdin
  fileparcel cert acme enable --email me@example.com --domain files.example.com --challenge http --production`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if email == "" || len(domains) == 0 {
				return UsageError("--email and at least one --domain are required")
			}
			for _, d := range domains {
				if !validSAN(d) || net.ParseIP(d) != nil {
					return UsageError("%q is not a DNS name", d)
				}
			}
			switch challenge {
			case "dns", "http", "tls-alpn":
			default:
				return UsageError("invalid --challenge %q (dns, http or tls-alpn)", challenge)
			}
			switch provider {
			case "cloudflare", "rfc2136":
			default:
				return UsageError("invalid --dns-provider %q (cloudflare or rfc2136)", provider)
			}
			changes := map[string]any{
				"acme.enabled": true, "acme.email": email, "acme.domains": domains,
				"acme.challenge": challenge, "acme.dns_provider": provider,
			}
			switch {
			case caURL != "":
				changes["acme.ca"] = caURL
			case production:
				changes["acme.ca"] = "production"
			default:
				changes["acme.ca"] = "staging"
			}
			if credsStdin || credsFile != "" {
				var data []byte
				var err error
				flag := "--credentials-stdin"
				if credsFile != "" {
					flag = "--credentials-file"
					data, err = readCredentialsFile(cmd, credsFile)
				} else {
					data, err = io.ReadAll(io.LimitReader(cmd.InOrStdin(), maxSecret))
				}
				if err != nil {
					return err
				}
				var obj map[string]any
				if err := json.Unmarshal(data, &obj); err != nil || len(obj) == 0 {
					return UsageError("%s expects a JSON object (e.g. {\"api_token\":\"…\"})", flag)
				}
				if err := checkDNSCredentials(provider, obj); err != nil {
					return err
				}
				changes["acme.dns_credentials"] = strings.TrimSpace(string(data))
			} else if challenge == "dns" {
				Warnf(cmd, "no --credentials-stdin or --credentials-file given; using the stored acme.dns_credentials")
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				if _, err := patchSettings(ctx, cmd, c, changes); err != nil {
					return err
				}
				if err := c.Do(ctx, http.MethodPost, api("/admin/certs/acme/apply"), nil, nil); err != nil {
					return fmt.Errorf("settings saved, but requesting the certificate failed: %w", err)
				}
				if !production && caURL == "" {
					Infof(cmd, "Using the Let's Encrypt STAGING CA (untrusted test certificates); re-run with --production when it works.")
				}
				if c.Mode() == ModeOffline || !wait.Wait() {
					return done(cmd, nil, "ACME enabled for %s; the certificate is requested in the background (see \"fileparcel cert status\")",
						strings.Join(domains, ", "))
				}
				st, err := waitACME(ctx, cmd, c, domains, acmeWaitTimeout)
				if err != nil {
					return err
				}
				if st == nil {
					Warnf(cmd, "no certificate yet after %s; the request goes on in the background (see \"fileparcel cert status\")",
						HumanDuration(acmeWaitTimeout))
					return done(cmd, nil, "ACME enabled for %s", strings.Join(domains, ", "))
				}
				return done(cmd, nil, "ACME enabled for %s: certificate issued", strings.Join(domains, ", "))
			})
		},
	}
	wait = addWaitFlags(enable, true, "the first certificate is issued (up to 3 minutes)")
	f := enable.Flags()
	f.StringVar(&email, "email", "", "ACME account e-mail (expiry notices)")
	f.StringArrayVar(&domains, "domain", nil, "domain name to obtain a certificate for (repeatable)")
	f.StringVar(&challenge, "challenge", "dns", "challenge type: dns, http or tls-alpn")
	f.StringVar(&provider, "dns-provider", "cloudflare", "DNS provider for the dns challenge: cloudflare or rfc2136")
	f.BoolVar(&credsStdin, "credentials-stdin", false, "read the DNS provider credentials (JSON) from stdin")
	f.StringVar(&credsFile, "credentials-file", "", "read the DNS provider credentials (JSON) from `FILE`")
	enable.MarkFlagsMutuallyExclusive("credentials-stdin", "credentials-file")
	f.BoolVar(&production, "production", false, "use the Let's Encrypt production CA (default: staging)")
	f.StringVar(&caURL, "ca", "", "custom ACME directory URL (overrides --production)")
	disable := &cobra.Command{
		Use:   "disable",
		Short: "Stop using ACME certificates",
		Long: `Turn ACME off (acme.enabled=false). Certificates it got are no longer served
or renewed; the local CA's certificate takes over.

` + elevationNote,
		Example: `  fileparcel cert acme disable
  fileparcel cert acme disable --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				if _, err := patchSettings(ctx, cmd, c, map[string]any{"acme.enabled": false}); err != nil {
					return err
				}
				if err := c.Do(ctx, http.MethodPost, api("/admin/certs/acme/apply"), nil, nil); err != nil && !errors.Is(err, core.ErrNotFound) {
					Warnf(cmd, "applying the change failed (it takes effect at the next restart): %v", err)
				}
				return done(cmd, nil, "ACME disabled")
			})
		},
	}
	cmd.AddCommand(enable, disable)
	return cmd
}

// acmeWaitTimeout is how long "cert acme enable" waits for the first
// certificate (a DNS challenge waits for the record to propagate).
var acmeWaitTimeout = 3 * time.Minute

// acmePoll is the interval between two looks at the certificate status.
var acmePoll = 2 * time.Second

// waitACME follows the background ACME request (GET /admin/certs) until
// every domain has a certificate (returns the status), the request failed
// (returns an error with the CA's answer) or timeout passed (nil, nil). An
// error left from before this change counts once it outlives a short grace
// period (the unchanged configuration is retried and may still succeed).
func waitACME(ctx context.Context, cmd *cobra.Command, c *Client, domains []string, timeout time.Duration) (*core.CertStatus, error) {
	prog := clikit.NewProgress(cmd.ErrOrStderr(), stderrIsTerminal(cmd) && !G.JSON, "requesting the certificate", 0)
	prog.SetFormat(clikit.Count)
	prog.Start(250 * time.Millisecond)
	defer prog.Finish()
	start := time.Now()
	stale := ""
	for first := true; ; first = false {
		var st core.CertStatus
		if err := c.Do(ctx, http.MethodGet, api("/admin/certs"), nil, &st); err != nil {
			return nil, err
		}
		if acmeCovers(&st, domains) {
			return &st, nil
		}
		if first {
			stale = st.ACMEError
		}
		if st.ACMEError != "" && (st.ACMEError != stale || time.Since(start) > 30*time.Second) {
			return nil, &hintError{fmt.Errorf("ACME is enabled, but the certificate request failed: %s", st.ACMEError),
				`check the domain, the DNS credentials and the CA (--ca); it is retried automatically ("fileparcel cert status" shows the state)`}
		}
		if time.Since(start) >= timeout {
			return nil, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(acmePoll):
		}
	}
}

// acmeCovers reports whether the ACME certificates in st name every domain.
func acmeCovers(st *core.CertStatus, domains []string) bool {
	for _, d := range domains {
		if !slices.ContainsFunc(st.ACME, func(ci core.CertInfo) bool {
			return slices.ContainsFunc(ci.DNSNames, func(n string) bool { return strings.EqualFold(n, d) })
		}) {
			return false
		}
	}
	return len(domains) > 0
}

// readCredentialsFile reads the JSON of --credentials-file. Like
// ReadSecretFile it warns about a file other users can read, but it keeps
// every line (the JSON may span several).
func readCredentialsFile(cmd *cobra.Command, path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Mode().Perm()&0o004 != 0 && canChangeMode(st) {
		Warnf(cmd, "%s is readable by other users; chmod 600 it", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSecret+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSecret {
		return nil, fmt.Errorf("%s: too long for credentials", path)
	}
	return data, nil
}

// dnsCredentialKeys are the keys each DNS provider requires in
// acme.dns_credentials (certs.dnsProvider). The setting itself accepts any
// JSON object, so wrong keys would otherwise be stored together with
// acme.enabled=true and only fail at the apply step, stopping a working
// ACME setup.
var dnsCredentialKeys = map[string][]string{
	"cloudflare": {"api_token"},
	"rfc2136":    {"server", "key_name", "key"},
}

// checkDNSCredentials refuses credentials that lack a required key of the
// provider (or have it empty or not a string).
func checkDNSCredentials(provider string, obj map[string]any) error {
	var missing []string
	for _, k := range dnsCredentialKeys[provider] {
		if s, _ := obj[k].(string); strings.TrimSpace(s) == "" {
			missing = append(missing, strconv.Quote(k))
		}
	}
	if len(missing) > 0 {
		return UsageError("%s credentials need %s (see \"fileparcel cert acme enable --help\")", provider, strings.Join(missing, ", "))
	}
	return nil
}

// ---------- tailscale ----------

func newCertTailscaleCmd() *cobra.Command {
	cmd := groupCmd("tailscale", "Use a Tailscale (ts.net) certificate",
		`Serve a certificate every browser trusts for this machine's Tailscale
MagicDNS name (<machine>.<tailnet>.ts.net), fetched from the local tailscaled.
Needs HTTPS certificates turned on for the tailnet and operator permission for
this user ("sudo tailscale set --operator=$USER"). Headscale cannot issue
ts.net certificates.

For Funnel and Serve see "fileparcel network funnel" and "fileparcel network
tailscale-serve".`,
		`  fileparcel cert tailscale enable
  fileparcel cert tailscale fetch
  fileparcel cert tailscale disable`)
	var domain string
	enable := &cobra.Command{
		Use:   "enable",
		Short: "Use the Tailscale certificate",
		Long: `Turn tailscale.cert_enabled on and fetch the certificate now. It is renewed
automatically when less than 14 days remain.

` + elevationNote,
		Example: `  fileparcel cert tailscale enable
  fileparcel cert tailscale enable --domain box.tail1234.ts.net`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			changes := map[string]any{"tailscale.cert_enabled": true}
			if cmd.Flags().Changed("domain") {
				changes["tailscale.domain"] = domain
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				if _, err := patchSettings(ctx, cmd, c, changes); err != nil {
					return err
				}
				if err := c.Do(ctx, http.MethodPost, api("/admin/certs/tailscale/fetch"), nil, nil); err != nil {
					return &hintError{fmt.Errorf("enabled, but fetching the certificate failed: %w", err),
						"check \"tailscale status\", enable HTTPS certificates for the tailnet and run \"sudo tailscale set --operator=$USER\""}
				}
				return done(cmd, nil, "Tailscale certificate enabled")
			})
		},
	}
	enable.Flags().StringVar(&domain, "domain", "", "MagicDNS name to use (default: detected)")
	disable := &cobra.Command{
		Use:   "disable",
		Short: "Stop using the Tailscale certificate",
		Long: `Turn tailscale.cert_enabled off; the local CA's certificate then covers the
ts.net name.

` + elevationNote,
		Example: `  fileparcel cert tailscale disable
  fileparcel cert tailscale disable --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				if _, err := patchSettings(ctx, cmd, c, map[string]any{"tailscale.cert_enabled": false}); err != nil {
					return err
				}
				return done(cmd, nil, "Tailscale certificate disabled")
			})
		},
	}
	fetch := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch or renew the Tailscale certificate now",
		Long: `Fetch the Tailscale certificate from tailscaled now; this normally happens
automatically.`,
		Example: `  fileparcel cert tailscale fetch
  fileparcel cert tailscale fetch --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				if err := c.Do(ctx, http.MethodPost, api("/admin/certs/tailscale/fetch"), nil, nil); err != nil {
					return err
				}
				return done(cmd, nil, "Tailscale certificate fetched")
			})
		},
	}
	cmd.AddCommand(enable, disable, fetch)
	return cmd
}
