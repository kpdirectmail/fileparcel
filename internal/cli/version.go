package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"fileparcel/internal/buildinfo"
)

func init() { Register(newVersionCmd) }

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long: `Print the FileParcel version, commit, build date, Go version and platform
(--json for scripts).`,
		Example: `  fileparcel version
  fileparcel version --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			info := buildinfo.Get()
			return Print(cmd, info, func(w io.Writer) error {
				_, err := fmt.Fprintf(w, "FileParcel %s (commit %s, built %s, %s %s/%s)\n",
					info.Version, info.Commit, dash(info.Date), info.GoVersion, info.OS, info.Arch)
				return err
			})
		},
	}
}
