//go:build !windows

package tui

import "os"

// enableEscapes is a no-op outside Windows: terminals there understand
// ANSI escape codes already.
func enableEscapes(*os.File) (func(), error) { return func() {}, nil }
