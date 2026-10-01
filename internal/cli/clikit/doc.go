// Package clikit holds self-contained helpers for the fileparcel CLI command
// files that do not depend on package cli itself: a terminal progress line
// for transfers, retry with exponential backoff, and the Markdown command
// reference generator behind the hidden "fileparcel docs --markdown"
// command. Keeping them in their own package avoids identifier clashes in the
// large cli package and keeps them unit-testable in isolation.
package clikit
