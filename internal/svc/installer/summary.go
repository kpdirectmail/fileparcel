package installer

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"fileparcel/internal/core"
	"fileparcel/internal/netinfo"
	"fileparcel/internal/qr"
	"fileparcel/internal/svc"
	"fileparcel/internal/svc/provision"
)

// FirewallAdvice is one detected firewall and the commands to run.
type FirewallAdvice struct {
	Kind     string   `json:"kind"`
	Active   bool     `json:"active"`
	Commands []string `json:"commands"`
}

// Summary is the result of an install, upgrade or uninstall (printed once:
// it may contain credentials).
type Summary struct {
	Action          string           `json:"action"` // init | install | upgrade | uninstall
	Home            string           `json:"home"`
	Version         string           `json:"version,omitempty"`
	PreviousVersion string           `json:"previous_version,omitempty"`
	Service         svc.Kind         `json:"service"`
	Boot            bool             `json:"boot"`
	Started         bool             `json:"started"`
	Healthy         bool             `json:"healthy"`
	URLs            []core.AccessURL `json:"urls,omitempty"`
	TrustURL        string           `json:"trust_url,omitempty"`
	CAFingerprint   string           `json:"ca_fingerprint,omitempty"`
	Admin           string           `json:"admin,omitempty"`
	Password        string           `json:"password,omitempty"` // generated (shown once)
	SetupToken      string           `json:"setup_token,omitempty"`
	RecoveryKey     string           `json:"recovery_key,omitempty"`
	BackupRecipient string           `json:"backup_recipient,omitempty"`
	BackupIdentity  string           `json:"backup_identity,omitempty"`
	Backup          string           `json:"backup,omitempty"` // pre-upgrade / final backup
	Symlink         string           `json:"symlink,omitempty"`
	Firewall        []FirewallAdvice `json:"firewall,omitempty"`
	// FirewallAnywhere: the firewall commands open the ports to every
	// address (network access "any").
	FirewallAnywhere bool     `json:"firewall_anywhere,omitempty"`
	Tailscale        []string `json:"tailscale,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
	NextSteps        []string `json:"next_steps,omitempty"`
	// Incomplete: an install failed after the home was initialised (the
	// summary still carries the credentials shown only once).
	Incomplete bool `json:"incomplete,omitempty"`
	// Unchanged: an upgrade (or install on an installed home) found this
	// binary already installed and did nothing; Started and Healthy were
	// not checked.
	Unchanged bool `json:"unchanged,omitempty"`
}

// maxQR bounds the QR codes printed (one per recommended URL).
const maxQR = 3

// maxURLColumn is the widest URL column of the summary.
const maxURLColumn = 44

// Print writes the summary: JSON when asJSON, else human text with terminal
// QR codes for the recommended URLs.
func (s *Summary) Print(w io.Writer, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(s)
	}
	if s.Unchanged {
		_, err := fmt.Fprintf(w, "FileParcel %s is already installed in %s; nothing to upgrade.\n", dashIfEmpty(s.Version), s.Home)
		return err
	}
	var b strings.Builder
	switch s.Action {
	case "init":
		fmt.Fprintf(&b, "\nFileParcel %s home initialised in %s\n", s.Version, s.Home)
	case "install":
		if s.Incomplete {
			fmt.Fprintf(&b, "\nFileParcel %s was initialised in %s, but the installation did not finish\n", s.Version, s.Home)
		} else {
			fmt.Fprintf(&b, "\nFileParcel %s is installed in %s\n", s.Version, s.Home)
		}
	case "upgrade":
		fmt.Fprintf(&b, "\nFileParcel in %s was upgraded from %s to %s\n", s.Home, dashIfEmpty(s.PreviousVersion), s.Version)
	case "uninstall":
		fmt.Fprintf(&b, "\nFileParcel was uninstalled from %s\n", s.Home)
	}
	if s.Service != "" && s.Action != "uninstall" && s.Action != "init" {
		state := "registered"
		if s.Started {
			state = "running"
			if !s.Healthy {
				state = "started, but the health check failed"
			}
		}
		boot := ""
		if s.Service != svc.KindNone {
			boot = " (start at boot: " + yesNo(s.Boot) + ")"
		}
		if s.Service == svc.KindNone {
			state = "not registered"
		}
		fmt.Fprintf(&b, "Service: %s, %s%s\n", s.Service.Describe(), state, boot)
	}
	if len(s.URLs) > 0 {
		b.WriteString("\nOpen FileParcel at:\n")
		qrs := 0
		// The URL column fits the longest URL up to maxURLColumn; a longer
		// one (IPv6) gets its label on the next line.
		width := 0
		for _, u := range s.URLs {
			if n := len(u.URL); n <= maxURLColumn && n > width {
				width = n
			}
		}
		for _, u := range s.URLs {
			label := u.Label
			if u.Interface != "" && !strings.Contains(label, u.Interface) {
				label += " " + u.Interface
			}
			mark := ""
			if u.Recommended {
				mark = "  (recommended)"
			}
			if len(u.URL) > width {
				fmt.Fprintf(&b, "  %s\n  %-*s %s%s\n", u.URL, width, "", strings.TrimSpace(label), mark)
				continue
			}
			fmt.Fprintf(&b, "  %-*s %s%s\n", width, u.URL, strings.TrimSpace(label), mark)
		}
		for _, u := range s.URLs {
			if !u.Recommended || qrs >= maxQR {
				continue
			}
			if code, err := qr.Terminal(u.URL, false); err == nil {
				fmt.Fprintf(&b, "\n  %s\n", u.URL)
				for _, line := range strings.SplitAfter(code, "\n") {
					if line != "" {
						b.WriteString("  " + line)
					}
				}
				qrs++
			}
		}
	}
	if s.TrustURL != "" || s.CAFingerprint != "" {
		b.WriteString("\nTrust the certificate on each device (once):\n")
		if s.TrustURL != "" {
			fmt.Fprintf(&b, "  %s\n", s.TrustURL)
		}
		if s.CAFingerprint != "" {
			fmt.Fprintf(&b, "  CA fingerprint (SHA-256): %s\n", s.CAFingerprint)
		}
	}
	if s.Admin != "" || s.SetupToken != "" {
		b.WriteString("\n")
		if s.Admin != "" {
			if s.Password != "" {
				b.WriteString("Admin account (shown only once - store it in your password manager):\n")
				fmt.Fprintf(&b, "  username: %s\n  password: %s\n", s.Admin, s.Password)
				b.WriteString("  You must choose a new password at the first sign-in.\n")
			} else {
				fmt.Fprintf(&b, "Admin account: %s (with the password you chose)\n", s.Admin)
			}
		}
		if s.SetupToken != "" {
			fmt.Fprintf(&b, "Create the first account at /setup with this one-time setup token:\n  %s\n", s.SetupToken)
			b.WriteString("  (Every server start replaces it with a new token, printed in the log.)\n")
		}
	}
	if s.RecoveryKey != "" {
		b.WriteString("\nMaster-key recovery key (shown only once - store it offline; it unlocks the server if the passphrase is lost):\n")
		b.WriteString(indent(s.RecoveryKey, "  "))
	}
	if s.BackupIdentity != "" {
		b.WriteString("\nBackup identity (shown only once - keep it outside this machine; backups cannot be restored elsewhere without it):\n")
		b.WriteString(indent(s.BackupIdentity, "  "))
	}
	if s.Backup != "" {
		fmt.Fprintf(&b, "\nBackup: %s\n", s.Backup)
	}
	if s.Symlink != "" && s.Action != "uninstall" {
		fmt.Fprintf(&b, "\nCommand: %s\n", s.Symlink)
	}
	for _, fw := range s.Firewall {
		if len(fw.Commands) == 0 {
			continue
		}
		state := "is installed"
		if fw.Active {
			state = "is active"
		}
		switch {
		case s.Action == "uninstall":
			fmt.Fprintf(&b, "\nFirewall: %s %s; remove the FileParcel rules you added:\n", fw.Kind, state)
		case s.FirewallAnywhere:
			fmt.Fprintf(&b, "\nFirewall: %s %s; to allow access from anywhere (network access \"any\") run:\n", fw.Kind, state)
		default:
			fmt.Fprintf(&b, "\nFirewall: %s %s; to allow access from your networks run:\n", fw.Kind, state)
		}
		for _, c := range fw.Commands {
			fmt.Fprintf(&b, "  %s\n", c)
		}
	}
	if len(s.Tailscale) > 0 {
		b.WriteString("\nTailscale:\n")
		for _, t := range s.Tailscale {
			fmt.Fprintf(&b, "  %s\n", t)
		}
	}
	if len(s.Warnings) > 0 {
		b.WriteString("\nWarnings:\n")
		for _, x := range s.Warnings {
			fmt.Fprintf(&b, "  - %s\n", x)
		}
	}
	if len(s.NextSteps) > 0 {
		b.WriteString("\nNext steps:\n")
		for _, x := range s.NextSteps {
			fmt.Fprintf(&b, "  - %s\n", x)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// indent prefixes every non-empty line of s with prefix and ends it with a newline.
func indent(s, prefix string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			b.WriteString(prefix)
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// ResultSummary builds the summary of a freshly provisioned home (`init`,
// and the credentials/URL part of `install`): URLs, /trust URL, CA
// fingerprint, the credentials shown once and the Tailscale hint. user is
// the login name used in the Tailscale operator hint.
func ResultSummary(action, version string, res *provision.Result, user string) *Summary {
	s := &Summary{Action: action, Version: version}
	if res == nil {
		return s
	}
	s.Home = res.Home
	s.URLs, s.TrustURL, s.CAFingerprint = res.URLs, trustURL(res.URLs), res.CAFingerprint
	s.Admin, s.Password, s.SetupToken = res.Owner, res.Password, res.SetupToken
	s.RecoveryKey, s.BackupIdentity, s.BackupRecipient = res.RecoveryKey, res.BackupIdentity, res.BackupRecipient
	s.Tailscale = tailscaleHints(res.Tailscale, user)
	s.Warnings = append(s.Warnings, res.Warnings...)
	return s
}

// trustURL returns <recommended URL>/trust ("" without URLs).
func trustURL(urls []core.AccessURL) string {
	pick := ""
	for _, u := range urls {
		if u.Recommended && u.Kind != core.URLKindIP {
			pick = u.URL
			break
		}
	}
	if pick == "" {
		for _, u := range urls {
			if u.Recommended {
				pick = u.URL
				break
			}
		}
	}
	if pick == "" && len(urls) > 0 {
		pick = urls[0].URL
	}
	if pick == "" {
		return ""
	}
	u, err := url.Parse(pick)
	if err != nil || u.Host == "" {
		return ""
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/trust"}).String()
}

// firewallInput derives the hint input from the provisioned network: the
// allowed networks (LAN and Wi-Fi subnets, extra CIDRs) by source, and the
// VPNs devices come in through (roles mesh and unknown: Tailscale,
// Headscale, WireGuard, …) by their real interface names. Exit, corporate
// and overlay VPNs get no rule (DESIGN §10.1).
func firewallInput(res *provision.Result, httpsPort, httpPort int, bin string) svc.HintInput {
	in := svc.HintInput{HTTPSPort: httpsPort, HTTPPort: httpPort, Binary: bin, Anywhere: res.AccessMode == core.AccessAny}
	// Networks opened by interface: no source rule for them.
	vpnRanges := map[string]bool{}
	for _, i := range res.Interfaces {
		if r := netinfo.RoleOf(i); !i.Up || (r != core.VPNRoleMesh && r != core.VPNRoleUnknown) {
			continue
		}
		if !slices.Contains(in.VPNIfaces, i.Name) {
			in.VPNIfaces = append(in.VPNIfaces, i.Name)
		}
		for _, a := range i.Addrs {
			vpnRanges[a.Masked().String()] = true
		}
	}
	for _, v := range netinfo.BuildVPNs(res.Interfaces, res.Tailscale, core.AccessPolicy{}) {
		if v.Role == core.VPNRoleMesh || v.Role == core.VPNRoleUnknown {
			for _, r := range v.Ranges {
				vpnRanges[r] = true
			}
		}
	}
	for _, c := range res.AllowCIDRs {
		if vpnRanges[c] {
			continue
		}
		if p, err := netip.ParsePrefix(c); err == nil {
			in.Subnets = append(in.Subnets, p)
		}
	}
	return in
}

// firewallAdvice detects the firewalls and computes their commands.
func firewallAdvice(fws []svc.Firewall, in svc.HintInput, removal bool) []FirewallAdvice {
	var out []FirewallAdvice
	for _, fw := range fws {
		cmds := svc.Hints(fw.Kind, in)
		if removal {
			cmds = svc.RemovalHints(fw.Kind, in)
		}
		if len(cmds) == 0 || (!fw.Active && !removal) {
			continue
		}
		out = append(out, FirewallAdvice{Kind: fw.Kind, Active: fw.Active, Commands: cmds})
	}
	return out
}

// funnelHint is the installer's pointer to Tailscale Funnel (share links on
// the internet, DESIGN §10.6).
const funnelHint = "Share links on the internet: fileparcel network funnel enable"

// tailscaleHints explains trusted ts.net certificates (DESIGN §10.4, §19)
// and points at Tailscale Funnel. Headscale has neither ts.net certificates
// nor Funnel relays, so it gets no hint.
func tailscaleHints(ts *core.TailscaleInfo, user string) []string {
	if ts == nil || !ts.Running || ts.DNSName == "" || ts.Kind == core.IfHeadscale {
		return nil
	}
	if ts.CertCapable {
		return []string{"for a publicly trusted certificate on " + ts.DNSName + " run: fileparcel cert tailscale enable", funnelHint}
	}
	if user == "" {
		user = "$USER"
	}
	return []string{
		"for a publicly trusted certificate on " + ts.DNSName + ", allow FileParcel to use `tailscale cert`:",
		"  sudo tailscale set --operator=" + user + "   (and enable HTTPS certificates in the tailnet admin console)",
		"  then: fileparcel cert tailscale enable",
		funnelHint,
	}
}
