//go:build !linux && !darwin

package netinfo

// runningProcesses is implemented on Linux and macOS only.
func runningProcesses() map[string]bool { return nil }

// processArgs is implemented on Linux and macOS only.
func processArgs(string) [][]string { return nil }
