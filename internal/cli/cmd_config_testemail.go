package cli

import (
	"context"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"fileparcel/internal/core"
)

// newConfigTestEmailCmd is "config test-email": POST
// /admin/settings/email/test, the check behind Settings → Email → *Send test
// e-mail…* in the web app.
func newConfigTestEmailCmd() *cobra.Command {
	var to string
	cmd := &cobra.Command{
		Use:   "test-email --to ADDRESS",
		Short: "Send a test e-mail with the saved SMTP settings",
		Long: `Send a test e-mail to an address with the SMTP settings that are saved now
(smtp.*), to check them before a real notification depends on them. When the
message cannot be sent, the answer of the mail server is shown.`,
		Example: `  fileparcel config test-email --to admin@example.org
  fileparcel --json config test-email --to admin@example.org`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			to = strings.TrimSpace(to)
			if to == "" {
				return UsageError("--to is required: the address to send the test e-mail to")
			}
			return WithClient(cmd, func(ctx context.Context, c *Client) error {
				if err := c.Do(ctx, http.MethodPost, api("/admin/settings/email/test"), core.EmailTestInput{To: to}, nil); err != nil {
					return err
				}
				return done(cmd, map[string]any{"sent": true, "to": to},
					"test e-mail sent to %s (if it does not arrive, check the spam folder and the server log)", to)
			})
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "the address to send the test e-mail to")
	return cmd
}
