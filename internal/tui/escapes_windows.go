//go:build windows

package tui

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableEscapes turns on the console's ANSI escape handling (Windows 10
// and later), which cursor movement and colour need; the returned func
// restores the previous console mode.
func enableEscapes(f *os.File) (func(), error) {
	h := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return nil, err
	}
	if err := windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		return nil, err
	}
	return func() { _ = windows.SetConsoleMode(h, mode) }, nil
}
