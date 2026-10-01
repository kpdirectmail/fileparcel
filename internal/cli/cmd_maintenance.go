package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"fileparcel/internal/core"
)

func init() { Register(newMaintenanceCmd) }

// Settings behind maintenance mode (registered by the platform unit; see the
// unit report). While enabled, the server answers page and API requests for
// files, shares and uploads with 503 and shows maintenanceMessageKey;
// administrators, sign-in, users' own account settings and the admin socket
// keep working (web/mw.Maintenance).
const (
	maintenanceKey        = "maintenance.enabled"
	maintenanceMessageKey = "maintenance.message"
)

// maintenanceState is the --json output of maintenance status.
type maintenanceState struct {
	Enabled bool   `json:"enabled"`
	Message string `json:"message,omitempty"`
	// messageSupported: the server registers maintenanceMessageKey.
	messageSupported bool
}

func readMaintenance(ctx context.Context, c *Client) (*maintenanceState, error) {
	list, err := settingsCatalog(ctx, c)
	if err != nil {
		return nil, err
	}
	s := findSetting(list, maintenanceKey)
	if s == nil {
		return nil, errMaintenanceUnsupported
	}
	st := &maintenanceState{}
	_ = json.Unmarshal(s.Value, &st.Enabled)
	if m := findSetting(list, maintenanceMessageKey); m != nil {
		st.messageSupported = true
		_ = json.Unmarshal(m.Value, &st.Message)
	}
	return st, nil
}

var errMaintenanceUnsupported = core.Errorf(core.ErrNotImplemented,
	"this server has no maintenance mode (setting %s is not registered)", maintenanceKey)

// Maintenance actions (the subcommands of "maintenance").
const (
	maintStatus = "status"
	maintOn     = "on"
	maintOff    = "off"
)

// newMaintenanceCmd is "maintenance": alone it shows the state; "on",
// "off" and "status" are subcommands. --message is a flag of the parent, so
// both "maintenance --message M on" and "maintenance on --message M" work.
// A word cobra does not match (the old positional forms "ON", "Enable")
// runs the subcommand it names, case-insensitively.
func newMaintenanceCmd() *cobra.Command {
	var message string
	cmd := &cobra.Command{
		Use:   "maintenance",
		Short: "Keep users out while you work on the server",
		Long: `Maintenance mode keeps users out while you work on the server: the web app
shows a maintenance notice and requests for files, shares and uploads are
answered with "503 unavailable". Administrators and the admin socket (this
command on the server) keep working, and so do signing in and every user's
own account settings (profile, password, two-factor, sessions, tokens);
invitations cannot be accepted until it is off again.

The state is the setting maintenance.enabled; --message sets the notice.
"fileparcel maintenance" alone shows the current state.`,
		Example: `  fileparcel maintenance
  fileparcel maintenance on --message "Upgrading, back at 14:00"
  fileparcel maintenance off`,
		Annotations: map[string]string{annBare: maintStatus},
		Args:        cobra.ArbitraryArgs,
	}
	run := func(c *cobra.Command, action string) error {
		return runMaintenance(c, action, message, cmd.PersistentFlags().Changed("message"))
	}
	cmd.RunE = func(c *cobra.Command, args []string) error {
		switch len(args) {
		case 0:
			return run(c, maintStatus)
		case 1:
			for _, sub := range c.Commands() {
				if strings.EqualFold(args[0], sub.Name()) || slices.ContainsFunc(sub.Aliases, func(a string) bool {
					return strings.EqualFold(args[0], a)
				}) {
					return run(c, sub.Name())
				}
			}
			return unknownCommandError(c, args[0])
		}
		return UsageError("%q takes one word (on, off or status), got %d", c.CommandPath(), len(args))
	}
	cmd.PersistentFlags().StringVar(&message, "message", "", `notice shown to users while maintenance mode is on (with "on" only)`)
	sub := func(use, short, long, example string, aliases ...string) *cobra.Command {
		return &cobra.Command{
			Use:     use,
			Aliases: aliases,
			Short:   short,
			Long:    long,
			Example: example,
			Args:    cobra.NoArgs,
			RunE:    func(c *cobra.Command, args []string) error { return run(c, use) },
		}
	}
	cmd.AddCommand(
		sub(maintStatus, "Show whether maintenance mode is on",
			`Show whether maintenance mode is on and the notice users see.`,
			`  fileparcel maintenance status
  fileparcel maintenance status --json`),
		sub(maintOn, "Keep users out with a maintenance notice",
			`Turn maintenance mode on. --message sets the notice users see; without it the
last notice (or a general one) is shown. "fileparcel maintenance off" lets
users back in.`,
			`  fileparcel maintenance on
  fileparcel maintenance on --message "Back at 14:00"`, "enable"),
		sub(maintOff, "Let users back in",
			`Turn maintenance mode off: the web app, shares and uploads work again.`,
			`  fileparcel maintenance off
  fileparcel maintenance off --json`, "disable"),
	)
	return cmd
}

// runMaintenance shows the maintenance state (action "status") or turns
// maintenance mode on or off; message is the notice of "on" (messageSet:
// --message was given).
func runMaintenance(cmd *cobra.Command, action, message string, messageSet bool) error {
	if messageSet && action != maintOn {
		return UsageError("--message only applies to \"maintenance on\"")
	}
	return WithClient(cmd, func(ctx context.Context, c *Client) error {
		st, err := readMaintenance(ctx, c)
		if err != nil {
			return err
		}
		if action == maintStatus {
			return Print(cmd, st, func(w io.Writer) error {
				state := Green("off")
				if st.Enabled {
					state = Yellow("ON")
				}
				fmt.Fprintf(w, "Maintenance mode: %s\n", state)
				if st.Enabled && st.Message != "" {
					fmt.Fprintf(w, "Message: %s\n", sanitizeCell(st.Message))
				}
				return nil
			})
		}
		on := action == maintOn
		changes := map[string]any{maintenanceKey: on}
		if on && messageSet {
			// Decided from the catalog: an error with Field
			// maintenance.message is usually a validation failure (too
			// long, control characters), which the server's own message
			// explains.
			if !st.messageSupported {
				return UsageError("this server does not support a maintenance message; run without --message")
			}
			changes[maintenanceMessageKey] = message
		}
		if _, err := patchSettings(ctx, cmd, c, changes); err != nil {
			return err
		}
		st.Enabled = on
		if on && messageSet {
			st.Message = message
		}
		if on {
			return done(cmd, st, "maintenance mode is ON (users see a maintenance notice; turn it off with \"fileparcel maintenance off\")")
		}
		return done(cmd, st, "maintenance mode is off")
	})
}
