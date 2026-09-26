package tui

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

// ErrNotTerminal means stdin or stdout isn't an interactive terminal (a
// pipe, a file, CI), so no menu can be shown.
var ErrNotTerminal = errors.New("not an interactive terminal")

// Terminal is the user's terminal, ready for menus.
type Terminal struct {
	in, out *os.File
	style   Style
	restore func()
}

// Open checks that stdin and stdout are a terminal and prepares it: on
// Windows that switches the console to understand ANSI escape codes.
// Close undoes it.
func Open() (*Terminal, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return nil, ErrNotTerminal
	}
	restore, err := enableEscapes(os.Stdout)
	if err != nil {
		return nil, fmt.Errorf("terminal: %w", err)
	}
	return &Terminal{in: os.Stdin, out: os.Stdout, style: Style{Color: ColorWanted()}, restore: restore}, nil
}

// Close puts the terminal back as it was.
func (t *Terminal) Close() {
	if t.restore != nil {
		t.restore()
	}
}

// Select shows a menu and returns the chosen option's index, Back for Esc,
// or ErrQuit for Ctrl-C. The terminal is in raw mode only while the menu
// is up, so everything else prints normally.
func (t *Terminal) Select(title string, opts []Option, def int) (int, error) {
	fd := int(t.in.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return Back, fmt.Errorf("terminal: %w", err)
	}
	defer func() { _ = term.Restore(fd, state) }()
	return Run(t.in, t.out, t.style, NewMenu(title, opts, def), "\r\n")
}

// Style is how this terminal shows colour.
func (t *Terminal) Style() Style { return t.style }

// Printf writes to the terminal.
func (t *Terminal) Printf(format string, a ...any) {
	fmt.Fprintf(t.out, format, a...)
}
