package cli

import (
	"github.com/spf13/cobra"

	"fileparcel/internal/home"
	"fileparcel/internal/svc/installer"
)

func init() { Register(newUninstallCmd) }

func newUninstallCmd() *cobra.Command {
	var o installer.UninstallOptions
	var keepData, nonInter bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove FileParcel (keeps your data unless --purge)",
		Long: `Uninstall FileParcel (called by uninstall.sh): stop, disable and unregister the
service, disable linger when the installer enabled it and no other user service
needs it, and remove the "fileparcel" command link when it points into the home.
FileParcel's Tailscale Funnel and Serve entries are removed from Tailscale too
(also with --keep-data); entries you made yourself stay.

--keep-data (default) leaves the home directory with all files, keys and
backups; "install.sh --dir DIR" picks it up again and registers the service and
the command link anew. --purge also overwrites the master key and the
CA/certificate keys (also the copies restores keep in pre-restore-<date>/)
with random bytes and deletes the home
(guarded: only a directory containing fileparcel.toml, never a system or home
directory itself). On SSDs overwritten blocks may survive, but the data is
encrypted and unreadable without the destroyed master key.

--final-backup creates a full backup first; --backup-to DIR (outside the home,
created if missing) also copies it there. --final-backup together with --purge
needs --backup-to, since a backup left in the home would be deleted with it;
--purge alone makes no backup. The copy is made and checked by the
uninstaller; if it fails, nothing is removed.
With the service running the server makes the backup and uninstall waits as
long as it takes (Ctrl-C stops waiting; the backup job continues). With the
server stopped, a sealed master key is unlocked with the global
--passphrase-file/--passphrase-stdin or on the terminal; the backup needs it
only in passphrase encryption mode.
--remove-user deletes the system account the installer created.

` + confirmNote + ` --dry-run prints the plan.`,
		Example: `  fileparcel uninstall
  fileparcel uninstall --final-backup --backup-to ~/fileparcel-final --purge
  sudo fileparcel uninstall -y --purge --remove-user --home /opt/fileparcel`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			h, err := home.Resolve(G.Home)
			if err != nil {
				return err
			}
			o.Home = h
			o.Yes = G.Yes || nonInter
			return lcNewInstaller(cmd, lcCanPrompt(cmd, nonInter)).Uninstall(lcCtx(cmd), o)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&keepData, "keep-data", false, "keep the home directory and its data (default)")
	f.BoolVar(&o.Purge, "purge", false, "destroy the keys and delete the home directory with all data")
	f.BoolVar(&o.FinalBackup, "final-backup", false, "create a full backup before removing anything")
	f.StringVar(&o.BackupTo, "backup-to", "", "copy the final backup into DIR (outside the home, created if missing; implies --final-backup; needed when --final-backup is combined with --purge)")
	f.BoolVar(&o.RemoveUser, "remove-user", false, "delete the service account the installer created")
	f.BoolVar(&o.DryRun, "dry-run", false, "print the plan without changing anything")
	f.BoolVar(&nonInter, "non-interactive", false, "never prompt (same as -y)")
	_ = f.MarkHidden("non-interactive") // uninstall.sh documents it; help shows -y
	cmd.MarkFlagsMutuallyExclusive("keep-data", "purge")
	return cmd
}
