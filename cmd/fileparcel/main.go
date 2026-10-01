// Command fileparcel is the FileParcel server and admin CLI.
package main

import (
	"os"

	"fileparcel/internal/cli"
)

func main() { os.Exit(cli.Execute()) }
