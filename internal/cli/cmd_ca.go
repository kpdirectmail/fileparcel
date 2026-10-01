package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"fileparcel/internal/core"
)

func init() { Register(newCACmd) }

// CA export formats and their public download paths (securityapi MountRoot).
var caFormats = map[string]string{
	"pem":          "/trust/ca.pem",
	"der":          "/trust/ca.crt",
	"mobileconfig": "/trust/ca.mobileconfig",
}

// trustOSes lists the supported --os values of ca trust-help in print order.
var trustOSes = []string{"ios", "android", "macos", "windows", "linux", "firefox"}

func newCACmd() *cobra.Command {
	cmd := groupCmd("ca", "Export and trust the local certificate authority",
		`FileParcel creates its own certificate authority (CA) when it is set up and
issues the server's certificate from it. Devices trust the server after
installing the CA certificate once ("fileparcel ca trust-help" explains how on
each device). By default the CA may only sign local names and private
addresses, so it cannot be abused to impersonate public web sites.`,
		`  fileparcel ca fingerprint
  fileparcel ca export --format mobileconfig -o fileparcel.mobileconfig
  fileparcel ca trust-help --os android`)
	cmd.AddCommand(newCAShowCmd(), newCAFingerprintCmd(), newCAExportCmd(), newCARegenerateCmd(), newCATrustHelpCmd())
	return cmd
}

// fetchCA downloads the public CA certificate in format (pem|der|mobileconfig)
// and returns the data and the server's suggested file name.
func fetchCA(ctx context.Context, c *Client, format string) ([]byte, string, error) {
	p, ok := caFormats[format]
	if !ok {
		return nil, "", UsageError("invalid --format %q (pem, der or mobileconfig)", format)
	}
	resp, err := c.Stream(ctx, http.MethodGet, p, nil, nil)
	if err != nil {
		return nil, "", err
	}
	name := ""
	if _, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition")); err == nil {
		name = filepath.Base(params["filename"])
	}
	data, err := readStreamBody(resp, 1<<20)
	if err != nil {
		return nil, "", err
	}
	if name == "" || name == "." || name == string(filepath.Separator) {
		name = "fileparcel-ca." + map[string]string{"pem": "pem", "der": "crt", "mobileconfig": "mobileconfig"}[format]
	}
	return data, name, nil
}

// caFingerprint computes the SHA-256 fingerprint of the CA certificate (from
// its PEM) in the "AB:CD:…" form shown on the /trust page.
func caFingerprint(pemData []byte) (string, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("the server did not return a PEM certificate")
	}
	sum := sha256.Sum256(block.Bytes)
	return colonHex(sum[:]), nil
}

// colonHex renders bytes as upper-case hex pairs separated by colons.
func colonHex(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	parts := make([]string, 0, len(h)/2)
	for i := 0; i+1 < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func newCAShowCmd() *cobra.Command {
	var asPEM bool
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the local CA certificate",
		Long: `Show the local CA's subject, validity, fingerprint and the names it may sign;
--pem prints the certificate itself.`,
		Example: `  fileparcel ca show
  fileparcel ca show --pem > fileparcel-ca.pem`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				if asPEM {
					data, _, err := fetchCA(ctx, c, "pem")
					if err != nil {
						return err
					}
					_, err = cmd.OutOrStdout().Write(data)
					return err
				}
				var st core.CertStatus
				if err := c.Do(ctx, http.MethodGet, api("/admin/certs"), nil, &st); err != nil {
					return err
				}
				if st.CA == nil {
					return core.Errorf(core.ErrNotFound, "no local CA yet (run \"fileparcel init\")")
				}
				out := map[string]any{"ca": st.CA, "constrained": st.CAConstrained, "permitted_dns": st.PermittedDNS, "permitted_ips": st.PermittedIPs}
				return Print(cmd, out, func(w io.Writer) error {
					kv := NewKV()
					renderCertInfo(kv, "Subject", st.CA)
					kv.Add("Name-constrained", st.CAConstrained)
					if st.CAConstrained {
						kv.Add("Permitted names", strings.Join(st.PermittedDNS, ", "))
						kv.Add("Permitted IPs", strings.Join(st.PermittedIPs, ", "))
					}
					return kv.Render(w)
				})
			})
		},
	}
	cmd.Flags().BoolVar(&asPEM, "pem", false, "print the CA certificate in PEM format")
	return cmd
}

func newCAFingerprintCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fingerprint",
		Short: "Print the CA's SHA-256 fingerprint",
		Long: `Print the SHA-256 fingerprint of the local CA certificate. Compare it with the
fingerprint shown on a device (or on the /trust page) before trusting the CA,
and use it with "--fingerprint" for remote CLI access.`,
		Example: `  fileparcel ca fingerprint
  fileparcel ca fingerprint --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				data, _, err := fetchCA(ctx, c, "pem")
				if err != nil {
					return err
				}
				fp, err := caFingerprint(data)
				if err != nil {
					return err
				}
				return Print(cmd, map[string]string{"sha256": fp}, func(w io.Writer) error {
					_, err := fmt.Fprintln(w, fp)
					return err
				})
			})
		},
	}
}

func newCAExportCmd() *cobra.Command {
	var format, out string
	var force bool
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Save the CA certificate for phones and computers",
		Long: `Write the CA certificate as PEM (Linux, Firefox, Android), DER .crt (Windows,
Android) or an Apple configuration profile (.mobileconfig for iOS/macOS).
Without -o, PEM goes to standard output and the other formats to a file in the
current directory. Devices on the network can also download it from
https://<server>/trust.`,
		Example: `  fileparcel ca export > fileparcel-ca.pem
  fileparcel ca export --format der -o fileparcel-ca.crt
  fileparcel ca export --format mobileconfig`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			format = strings.ToLower(format)
			if format == "crt" {
				format = "der"
			}
			if _, ok := caFormats[format]; !ok {
				return UsageError("invalid --format %q (pem, der or mobileconfig)", format)
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				data, name, err := fetchCA(ctx, c, format)
				if err != nil {
					return err
				}
				dest := out
				if dest == "" && format != "pem" {
					dest = name
				}
				if dest == "" || dest == "-" {
					_, err := cmd.OutOrStdout().Write(data)
					return err
				}
				if fi, err := os.Stat(dest); err == nil && fi.IsDir() {
					dest = filepath.Join(dest, name)
				}
				if !force && fileExists(dest) {
					return fmt.Errorf("%s already exists (use --force to overwrite)", dest)
				}
				if err := os.WriteFile(dest, data, 0o644); err != nil {
					return err
				}
				return done(cmd, map[string]string{"path": dest, "format": format}, "wrote %s", dest)
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&format, "format", "pem", "pem, der or mobileconfig")
	addOutputFlag(cmd, &out, `output file or directory ("-" = stdout)`)
	addForceFlag(cmd, &force, "overwrite an existing file")
	return cmd
}

// caRegenerateInput is the body of POST /admin/certs/ca/regenerate
// (securityapi.RegenerateCAInput).
type caRegenerateInput struct {
	Unconstrained bool `json:"unconstrained,omitempty"`
}

func newCARegenerateCmd() *cobra.Command {
	var unconstrained bool
	cmd := &cobra.Command{
		Use:   "regenerate",
		Short: "Replace the local CA (every device must trust it again)",
		Long: `Create a new local CA and reissue the server certificate from it. Every
device that trusted the old CA shows certificate warnings until the new CA is
installed; passkeys keep working once it is trusted. --unconstrained lets the
CA sign any name (only needed for unusual host names; a leaked unconstrained
CA key could impersonate any web site for devices that trust it).

` + confirmNote + "\n" + elevationNote,
		Example: `  fileparcel ca regenerate
  fileparcel ca regenerate --unconstrained -y`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			q := "Replace the local CA? Every device must install the new CA certificate."
			if unconstrained {
				Warnf(cmd, "an unconstrained CA can sign certificates for ANY domain; devices that trust it trust all of them")
			}
			if err := confirmOrAbort(cmd, q); err != nil {
				return err
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				in := caRegenerateInput{Unconstrained: unconstrained}
				if err := c.Do(ctx, http.MethodPost, api("/admin/certs/ca/regenerate"), in, nil); err != nil {
					return err
				}
				fp := ""
				if data, _, err := fetchCA(ctx, c, "pem"); err == nil {
					fp, _ = caFingerprint(data)
				}
				return done(cmd, map[string]any{"fingerprint": fp, "constrained": !unconstrained},
					"new local CA created (fingerprint %s); install it on your devices (\"fileparcel ca trust-help\")", Dash(fp))
			})
		},
	}
	cmd.Flags().BoolVar(&unconstrained, "unconstrained", false, "create the CA without name constraints (not recommended)")
	return cmd
}

// trustContext is what trust-help can tell about this server.
type trustContext struct {
	Origin      string // https://host:port or ""
	Fingerprint string
	CRTName     string // file name of the /trust/ca.crt download (<server.name>-ca.crt) or ""
}

func newCATrustHelpCmd() *cobra.Command {
	var osName string
	cmd := &cobra.Command{
		Use:     "trust-help",
		Aliases: []string{"trust"},
		Short:   "Explain how to trust the CA on each device",
		Long: `Print step-by-step instructions for installing and trusting the FileParcel CA
certificate on iOS, Android, macOS, Windows, Linux and Firefox, with the
download address and the fingerprint to compare. Works without a running
server (then with placeholders).`,
		Example: `  fileparcel ca trust-help
  fileparcel ca trust-help --os ios`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			osName = strings.ToLower(strings.TrimSpace(osName))
			if osName == "mac" || osName == "osx" || osName == "darwin" {
				osName = "macos"
			}
			if osName != "" && !slices.Contains(trustOSes, osName) {
				return UsageError("invalid --os %q (%s)", osName, strings.Join(trustOSes, ", "))
			}
			tc := trustContext{}
			opts := G.ConnectOptions()
			// A help text never prompts for the master key passphrase.
			opts.Passphrase = func() ([]byte, error) { return nil, errors.New("not unlocking for trust-help") }
			if c, err := Connect(opts); err == nil {
				ctx := cmd.Context()
				if ctx == nil {
					ctx = context.Background()
				}
				tc.Origin = newURLResolver(c).abs(ctx, "/")
				tc.Origin = strings.TrimSuffix(tc.Origin, "/")
				if data, name, err := fetchCA(ctx, c, "pem"); err == nil {
					tc.Fingerprint, _ = caFingerprint(data)
					// The .crt download has the same base name as the .pem.
					tc.CRTName = strings.TrimSuffix(name, ".pem") + ".crt"
				}
				c.Close()
			}
			list := trustOSes
			if osName != "" {
				list = []string{osName}
			}
			if G.JSON {
				out := map[string]any{"origin": tc.Origin, "fingerprint": tc.Fingerprint, "instructions": map[string]string{}}
				for _, o := range list {
					out["instructions"].(map[string]string)[o] = trustInstructions(o, tc)
				}
				return PrintJSON(cmd.OutOrStdout(), out)
			}
			w := cmd.OutOrStdout()
			fp := tc.Fingerprint
			if fp == "" {
				fp = `(run "fileparcel ca fingerprint" on the server)`
			}
			fmt.Fprintf(w, "CA fingerprint (SHA-256): %s\n", fp)
			fmt.Fprintf(w, "Compare it with the fingerprint your device shows before trusting the certificate.\n")
			for _, o := range list {
				fmt.Fprintf(w, "\n%s\n%s\n", Bold(trustTitle(o)), trustInstructions(o, tc))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&osName, "os", "", "only this platform: "+strings.Join(trustOSes, ", "))
	return cmd
}

func trustTitle(o string) string {
	return map[string]string{"ios": "iOS / iPadOS", "android": "Android", "macos": "macOS", "windows": "Windows",
		"linux": "Linux", "firefox": "Firefox (all platforms)"}[o]
}

// trustInstructions returns the per-platform steps (DESIGN §10.4).
func trustInstructions(o string, tc trustContext) string {
	origin := tc.Origin
	if origin == "" {
		origin = "https://<server>:8443"
	}
	trust := origin + "/trust"
	pemURL, crtURL, mcURL := origin+"/trust/ca.pem", origin+"/trust/ca.crt", origin+"/trust/ca.mobileconfig"
	// The downloads are named after server.name (a DNS label, so no quoting
	// is needed), and so is the iOS profile ("FileParcel CA (<name>)").
	crt := tc.CRTName
	if crt == "" {
		crt = "fileparcel-ca.crt"
	}
	profile := "FileParcel CA (<server name>)"
	if n, ok := strings.CutSuffix(tc.CRTName, "-ca.crt"); ok && n != "" {
		profile = "FileParcel CA (" + n + ")"
	}
	var s string
	switch o {
	case "ios":
		s = fmt.Sprintf(`  1. Open %s in Safari (other browsers cannot install profiles) and tap
     "Download profile" (%s). Tap "Allow".
  2. Settings → General → VPN & Device Management → "%s" → Install.
  3. Settings → General → About → Certificate Trust Settings → enable full trust
     for "FileParcel Local CA (…)". Without this step the certificate is NOT trusted.`, trust, mcURL, profile)
	case "android":
		s = fmt.Sprintf(`  1. Download %s (or scan the QR code on %s).
  2. Settings → Security & privacy → More security settings → Encryption &
     credentials → Install a certificate → CA certificate → "Install anyway",
     and pick the downloaded file. (The menu names vary by vendor; search
     Settings for "CA certificate".)
  3. Chrome uses the system store; Firefox for Android needs Settings → About
     Firefox → tap the logo 5× → Secret settings → "Use third party CA certificates".`, crtURL, trust)
	case "macos":
		s = fmt.Sprintf(`  1. Download %s (or %s).
  2. Double-click it; Keychain Access opens. Add it to the "System" keychain.
  3. Double-click "FileParcel Local CA" → Trust → "When using this certificate:"
     Always Trust. Close the window and confirm with your password.
  Terminal alternative, in the folder of the downloaded file:
     sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s`, crtURL, mcURL, crt)
	case "windows":
		s = fmt.Sprintf(`  1. Download %s.
  2. Double-click it → Install Certificate → Local Machine → "Place all
     certificates in the following store" → Trusted Root Certification
     Authorities → Finish.
  Command prompt (as Administrator) alternative, in the folder of the downloaded file:
     certutil -addstore -f Root %s`, crtURL, crt)
	case "linux":
		s = fmt.Sprintf(`  Download the certificate in PEM format and compare its fingerprint:
     curl -fsSLk %s -o fileparcel-ca.crt
     openssl x509 -noout -fingerprint -sha256 -in fileparcel-ca.crt
  Debian/Ubuntu:
     sudo cp fileparcel-ca.crt /usr/local/share/ca-certificates/fileparcel-ca.crt
     sudo update-ca-certificates
  Fedora/RHEL:
     sudo cp fileparcel-ca.crt /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust
  Arch and others with p11-kit:
     sudo trust anchor --store fileparcel-ca.crt
  Chrome/Chromium on Linux use their own NSS store:
     certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "FileParcel Local CA" -i fileparcel-ca.crt`, pemURL)
	case "firefox":
		s = fmt.Sprintf(`  Firefox keeps its own certificate list:
  1. Download %s.
  2. Settings → Privacy & Security → Certificates → View Certificates →
     Authorities → Import… → select the file → tick "Trust this CA to identify
     websites" → OK.
  Or, on Windows/macOS, set security.enterprise_roots.enabled = true in
  about:config to use the system store.`, pemURL)
	}
	return s
}
