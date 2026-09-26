//go:build !windows

package main

// On Linux and macOS the installer never edits PATH, and a running binary
// can be deleted, so neither Windows step is needed.

func removeFromUserPath(string) (bool, error) { return false, nil }

func deleteAfterExit([]string, []string) error { return nil }
