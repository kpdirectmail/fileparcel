package cli

import (
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/home"
	"fileparcel/internal/svc"
)

func init() { Register(newHealthcheckCmd) }

func newHealthcheckCmd() *cobra.Command {
	var port int
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "healthcheck",
		Short: "Exit 0 when the local server answers (for scripts)",
		Long: `Ask the server on this machine whether it answers: GET
https://127.0.0.1:<port>/healthz (and [::1]), with the certificate checked
against this installation's local CA only. Exit status 0 when the server
answers 200, 1 otherwise. Used by the installer, upgrades and the Docker
HEALTHCHECK.`,
		Example: `  fileparcel healthcheck
  fileparcel healthcheck --port 9443 --timeout 2s`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			h, err := home.Resolve(G.Home)
			if err != nil {
				return err
			}
			if !h.Exists() {
				return notAHomeError(h.Dir())
			}
			herr := svc.HealthCheck(lcCtx(cmd), h, port, timeout)
			out := struct {
				Healthy bool   `json:"healthy"`
				Error   string `json:"error,omitempty"`
			}{Healthy: herr == nil}
			if herr != nil {
				out.Error = herr.Error()
			}
			if err := Print(cmd, out, func(w io.Writer) error {
				if herr != nil {
					return nil // printed as the error below
				}
				_, err := fmt.Fprintln(w, "ok")
				return err
			}); err != nil {
				return err
			}
			if herr != nil {
				if G.JSON {
					return &ExitCodeError{Code: ExitFailure}
				}
				return &ExitCodeError{Code: ExitFailure, Err: fmt.Errorf("unhealthy: %w", herr)}
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&port, "port", 0, "HTTPS port (default: server.https_port from fileparcel.toml)")
	durationVar(cmd.Flags(), &timeout, "timeout", 5*time.Second, "timeout per address")
	return cmd
}
