package cli

import (
	"errors"
	"os"

	"github.com/spf13/cobra"

	"fileparcel/internal/cli/clikit"
)

func init() {
	Register(newCompletionCmd)
	Register(newDocsCmd)
}

func newCompletionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion <bash|zsh|fish|powershell>",
		Short: "Set up tab completion for your shell",
		Long: `Print a completion script for your shell to standard output. Tab then
completes commands, flags and the values of flags with fixed choices, and
while the server runs (admin socket or --server) also names and ids from it:
users, groups, roles, permissions, setting keys, links, backups, jobs and
remote paths. It never opens a stopped installation and never completes a
secret.

Bash (needs the bash-completion package):
  mkdir -p ~/.local/share/bash-completion/completions
  fileparcel completion bash > ~/.local/share/bash-completion/completions/fileparcel
  # system-wide: fileparcel completion bash | sudo tee /etc/bash_completion.d/fileparcel

Zsh (a folder of your own for completion functions):
  mkdir -p ~/.zfunc
  fileparcel completion zsh > ~/.zfunc/_fileparcel
  # and in ~/.zshrc, before "autoload -U compinit; compinit":
  #   fpath=(~/.zfunc $fpath)

Fish:
  mkdir -p ~/.config/fish/completions
  fileparcel completion fish > ~/.config/fish/completions/fileparcel.fish

PowerShell:
  fileparcel completion powershell | Out-String | Invoke-Expression
  # permanently: add the line above to your $PROFILE

Start a new shell afterwards.`,
		Example: `  mkdir -p ~/.local/share/bash-completion/completions && fileparcel completion bash > ~/.local/share/bash-completion/completions/fileparcel
  mkdir -p ~/.zfunc && fileparcel completion zsh > ~/.zfunc/_fileparcel
  mkdir -p ~/.config/fish/completions && fileparcel completion fish > ~/.config/fish/completions/fileparcel.fish`,
		Args:                  cobra.ExactArgs(1),
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		DisableFlagsInUseLine: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			root, w := cmd.Root(), cmd.OutOrStdout()
			switch args[0] {
			case "bash":
				return root.GenBashCompletionV2(w, true)
			case "zsh":
				return root.GenZshCompletion(w)
			case "fish":
				return root.GenFishCompletion(w, true)
			case "powershell", "pwsh":
				return root.GenPowerShellCompletionWithDesc(w)
			}
			return UsageError("unsupported shell %q (bash, zsh, fish or powershell)", args[0])
		},
	}
	return cmd
}

func newDocsCmd() *cobra.Command {
	var markdown bool
	var out, title string
	cmd := &cobra.Command{
		Use:    "docs --markdown [-o FILE]",
		Short:  "Generate the command reference",
		Hidden: true,
		Long: `Generate a Markdown reference of every command (usage, description, flags and
examples) from the command tree. The output is deterministic and is embedded in
docs/COMMANDS.md (scripts/gen-cli-docs.sh).`,
		Example: `  fileparcel docs --markdown -o docs/cli-reference.md`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !markdown {
				return UsageError("choose an output format: --markdown")
			}
			w := cmd.OutOrStdout()
			var f *os.File
			if out != "" && out != "-" {
				var err error
				if f, err = os.Create(out); err != nil {
					return err
				}
				w = f
			}
			err := clikit.WriteMarkdown(w, cmd.Root(), clikit.MarkdownOptions{
				Title: title,
				Intro: "Every `fileparcel` command, generated from the program itself. " +
					"Run `fileparcel <command> --help` for the same information in the terminal.",
			})
			if f != nil {
				err = errors.Join(err, f.Close())
			}
			return err
		},
	}
	cmd.Flags().BoolVar(&markdown, "markdown", false, "write Markdown")
	addOutputFlag(cmd, &out, "write to this file instead of stdout")
	cmd.Flags().StringVar(&title, "title", "Command reference", "document title")
	return cmd
}
