package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/core"
)

func init() { Register(newOpenCmd) }

func newOpenCmd() *cobra.Command {
	var showQR, noBrowser bool
	cmd := &cobra.Command{
		Use:   "open",
		Short: "Open the web app in your browser (or show QR codes for phones)",
		Long: `Open the recommended address of the server in your default browser. Without
a graphical session, and with --qr or --no-browser, the addresses are printed
instead; --qr adds a QR code per recommended address that phones can scan.`,
		Example: `  fileparcel open
  fileparcel open --qr
  fileparcel open --no-browser`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				urls, err := lcAccessURLs(ctx, c)
				if err != nil {
					return err
				}
				if len(urls) == 0 {
					return errors.New("the server reports no access URLs")
				}
				if c.Mode() == ModeOffline {
					Warnf(cmd, "the server is not running (start it with \"fileparcel service start\" or \"fileparcel serve\")")
				}
				target := lcPreferredURL(urls)
				if !showQR && !noBrowser && !G.JSON && c.Mode() != ModeOffline && lcCanOpenBrowser() {
					if err := lcOpenBrowser(ctx, target); err == nil {
						Successf(cmd, "opened %s", target)
						return nil
					} else {
						Warnf(cmd, "could not start a browser: %v", err)
					}
				}
				return Print(cmd, urls, func(w io.Writer) error {
					for _, u := range urls {
						mark := ""
						if u.Recommended {
							mark = "  " + Dim("(recommended)")
						}
						label := u.Label
						if label == "" {
							label = u.Kind
						}
						if _, err := fmt.Fprintf(w, "%s  %s%s\n", Bold(u.URL), sanitizeCell(label), mark); err != nil {
							return err
						}
					}
					if !showQR {
						return nil
					}
					n := 0
					for _, u := range urls {
						if !u.Recommended && u.URL != target {
							continue
						}
						if n == 3 {
							break
						}
						n++
						fmt.Fprintf(w, "\n%s\n", u.URL)
						if err := PrintQR(w, u.URL); err != nil {
							return err
						}
					}
					return nil
				})
			})
		},
	}
	cmd.Flags().BoolVar(&showQR, "qr", false, "print the URLs with terminal QR codes instead of opening a browser")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "only print the URLs")
	return cmd
}

// lcAccessURLs returns the server's access URLs (GET /network/urls; in
// offline mode the in-process network service answers directly when the API
// cannot).
func lcAccessURLs(ctx context.Context, c *Client) ([]core.AccessURL, error) {
	var urls []core.AccessURL
	err := c.Do(ctx, http.MethodGet, "/api/v1/network/urls", nil, &urls)
	if err == nil {
		return urls, nil
	}
	if d := c.Deps(); d != nil && d.Network != nil {
		return d.Network.URLs(ctx)
	}
	return nil, err
}

// lcPreferredURL picks the URL to open: the first recommended name-based
// URL, else the first recommended one, else the first.
func lcPreferredURL(urls []core.AccessURL) string {
	if i := slices.IndexFunc(urls, func(u core.AccessURL) bool { return u.Recommended && u.Kind != core.URLKindIP }); i >= 0 {
		return urls[i].URL
	}
	if i := slices.IndexFunc(urls, func(u core.AccessURL) bool { return u.Recommended }); i >= 0 {
		return urls[i].URL
	}
	return urls[0].URL
}

// lcCanOpenBrowser reports a graphical session (macOS always; Linux with
// DISPLAY or WAYLAND_DISPLAY and xdg-open).
func lcCanOpenBrowser() bool {
	switch runtime.GOOS {
	case "darwin":
		return true
	case "linux", "freebsd", "openbsd", "netbsd":
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return false
		}
		_, err := exec.LookPath("xdg-open")
		return err == nil
	}
	return false
}

// lcOpenBrowser starts the default browser on an https URL.
func lcOpenBrowser(ctx context.Context, target string) error {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("refusing to open %q", target)
	}
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, u.String())
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	return cmd.Run()
}
