package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"fileparcel/internal/home"
	"fileparcel/internal/svc/installer"
)

func init() { Register(newUpgradeCmd) }

func newUpgradeCmd() *cobra.Command {
	var o installer.UpgradeOptions
	var nonInter bool
	cmd := &cobra.Command{
		Use:   "upgrade <release.zip|binary>",
		Short: "Upgrade to a new release (with automatic rollback)",
		Long: `Upgrade the installed FileParcel to a new release: a release zip
(fileparcel-vN.zip; the binary for this platform is checked against its
SHA256SUMS) or a binary (checked against a SHA256SUMS file next to it or one
directory up; --force accepts an unverified binary).

Steps: pre-upgrade metadata backup, stop the service, keep the current binary
as bin/fileparcel.prev, install the new one atomically, refresh VERSION, docs/
and uninstall.sh, start the service (database migrations run at start) and
check https://127.0.0.1:<port>/healthz (pinned to the local CA) for 30 s. When
the new version is not healthy the previous binary is restored and restarted.

It asks before doing it; -y skips the question. Without a terminal (a script,
a cron job) there is nobody to ask and it goes ahead as with -y. --dry-run
prints the plan.`,
		Example: `  fileparcel upgrade ~/Downloads/fileparcel-v2.zip
  fileparcel upgrade --dry-run fileparcel-v2.zip
  fileparcel upgrade --force ./fileparcel-linux-amd64`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			h, err := home.Resolve(G.Home)
			if err != nil {
				return err
			}
			if !h.Exists() {
				return fmt.Errorf("%s is not a FileParcel installation; use \"fileparcel install\"", h.Dir())
			}
			rel, err := installer.PrepareRelease(args[0], installer.StagingDir(h), runtime.GOOS, runtime.GOARCH, o.Force)
			if err != nil {
				return err
			}
			defer rel.Close()
			if !rel.Verified {
				Warnf(cmd, "%s is not verified against a SHA256SUMS file (--force)", args[0])
			}
			o.Home, o.Binary, o.BinarySHA256, o.SourceDir = h, rel.Binary, rel.SHA256, rel.SourceDir
			o.Yes = G.Yes || nonInter
			return lcNewInstaller(cmd, lcCanPrompt(cmd, nonInter)).Upgrade(lcCtx(cmd), o)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&o.Force, "force", false, "accept a binary without a SHA256SUMS entry; continue when the pre-upgrade backup fails")
	f.BoolVar(&o.SkipBackup, "skip-backup", false, "do not create the pre-upgrade backup")
	f.BoolVar(&o.DryRun, "dry-run", false, "print the plan without changing anything")
	f.BoolVar(&nonInter, "non-interactive", false, "never prompt (same as -y)")
	_ = f.MarkHidden("non-interactive") // scripts use it; help shows -y
	return cmd
}
