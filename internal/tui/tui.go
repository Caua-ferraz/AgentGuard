// Package tui draws the small interactive menus of `agentguard setup`: a
// list you move through with the arrow keys and pick from with Enter. It
// draws in place in the normal terminal (no full-screen mode) and leaves a
// one-line record of each answer, so the scrollback reads like a log of
// what was chosen.
//
// The menu logic (Menu, ParseKeys, Run) works on plain readers and writers
// so tests drive it with scripted key presses; Terminal adds the real
// terminal: raw mode for the duration of a menu, and colour when the
// terminal supports it.
package tui

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ErrQuit is returned when the user presses Ctrl-C (or Ctrl-D) in a menu.
var ErrQuit = errors.New("quit")

// Back is the choice Run returns when the user presses Esc or q.
const Back = -1

// Option is one line of a menu.
type Option struct {
	Label string
	Hint  string // shown dimmed after the label
	// Separator makes this line a divider: drawn, never selectable.
	Separator bool
}

// Key is a key press that means something to a menu.
type Key int

// The keys a menu understands. Everything else is ignored.
const (
	KeyNone Key = iota
	KeyUp
	KeyDown
	KeyEnter
	KeyBack
	KeyQuit
)

// ParseKeys turns raw terminal input into keys: the arrow keys (as the
// ESC [ A / ESC O A sequences terminals send), k/j, Enter, Esc or q for
// back, and Ctrl-C/Ctrl-D to quit. Unknown escape sequences are skipped
// whole, so a stray one never reads as Esc.
func ParseKeys(b []byte) []Key {
	var keys []Key
	for i := 0; i < len(b); i++ {
		switch c := b[i]; {
		case c == 0x1b && i+2 < len(b) && (b[i+1] == '[' || b[i+1] == 'O'):
			j := i + 2
			for j < len(b) && (b[j] < 0x40 || b[j] > 0x7e) {
				j++ // parameter bytes of a longer sequence
			}
			if j < len(b) {
				switch b[j] {
				case 'A':
					keys = append(keys, KeyUp)
				case 'B':
					keys = append(keys, KeyDown)
				}
			}
			i = j
		case c == 0x1b:
			keys = append(keys, KeyBack)
		case c == '\r' || c == '\n':
			keys = append(keys, KeyEnter)
		case c == 'k':
			keys = append(keys, KeyUp)
		case c == 'j':
			keys = append(keys, KeyDown)
		case c == 'q':
			keys = append(keys, KeyBack)
		case c == 0x03 || c == 0x04:
			keys = append(keys, KeyQuit)
		}
	}
	return keys
}

// Style decides whether output carries ANSI colour.
type Style struct{ Color bool }

func (s Style) wrap(code, text string) string {
	if !s.Color || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

// Bold, Dim, Accent, Good and Warn style text when colour is on.
func (s Style) Bold(t string) string   { return s.wrap("1", t) }
func (s Style) Dim(t string) string    { return s.wrap("2", t) }
func (s Style) Accent(t string) string { return s.wrap("36", t) }
func (s Style) Good(t string) string   { return s.wrap("32", t) }
func (s Style) Warn(t string) string   { return s.wrap("33", t) }

// Menu is one selectable list and where the cursor is in it.
type Menu struct {
	Title   string
	Options []Option
	Cursor  int
}

// NewMenu starts the cursor on def: on the next selectable option when def
// is a separator, on the first one when def is out of range.
func NewMenu(title string, opts []Option, def int) *Menu {
	m := &Menu{Title: title, Options: opts, Cursor: def}
	switch {
	case def < 0 || def >= len(opts):
		m.Cursor = -1
		m.Move(1)
	case opts[def].Separator:
		m.Move(1)
	}
	return m
}

// Move steps the cursor by delta (±1), wrapping around the ends and
// skipping separators.
func (m *Menu) Move(delta int) {
	n := len(m.Options)
	if n == 0 {
		return
	}
	c := m.Cursor
	for range n {
		c = (c + delta + n) % n
		if !m.Options[c].Separator {
			m.Cursor = c
			return
		}
	}
}

const hint = "↑/↓ move · Enter select · Esc back"

// Render is the menu as lines, without line endings.
func (m *Menu) Render(s Style) []string {
	lines := []string{" " + s.Bold(m.Title)}
	for i, o := range m.Options {
		switch {
		case o.Separator:
			lines = append(lines, "   "+s.Dim(strings.Repeat("─", 24)))
		case i == m.Cursor:
			lines = append(lines, " "+s.Accent("› "+o.Label)+hintText(s, o.Hint))
		default:
			lines = append(lines, "   "+o.Label+hintText(s, o.Hint))
		}
	}
	return append(lines, " "+s.Dim(hint))
}

func hintText(s Style, h string) string {
	if h == "" {
		return ""
	}
	return "  " + s.Dim(h)
}

// Run draws m on w, reads key presses from r until one picks an option,
// and returns its index (Back for Esc or q, ErrQuit for Ctrl-C). The menu
// is then replaced by one line recording the answer. newline is what ends
// a line: "\r\n" while the terminal is in raw mode.
func Run(r io.Reader, w io.Writer, s Style, m *Menu, newline string) (int, error) {
	drawn := 0
	draw := func() {
		if drawn > 0 {
			fmt.Fprintf(w, "\x1b[%dA\r\x1b[J", drawn) // back to the menu's first line, clear below
		}
		lines := m.Render(s)
		fmt.Fprint(w, strings.Join(lines, newline)+newline)
		drawn = len(lines)
	}
	clear := func() {
		if drawn > 0 {
			fmt.Fprintf(w, "\x1b[%dA\r\x1b[J", drawn)
		}
	}
	if s.Color {
		fmt.Fprint(w, "\x1b[?25l") // hide the cursor while the menu is up
		defer fmt.Fprint(w, "\x1b[?25h")
	}
	draw()
	buf := make([]byte, 64)
	for {
		n, err := r.Read(buf)
		for _, k := range ParseKeys(buf[:n]) {
			switch k {
			case KeyUp:
				m.Move(-1)
			case KeyDown:
				m.Move(1)
			case KeyEnter:
				if m.Cursor >= 0 {
					clear()
					fmt.Fprint(w, " "+s.Dim(m.Title)+" "+m.Options[m.Cursor].Label+newline)
					return m.Cursor, nil
				}
			case KeyBack:
				clear()
				return Back, nil
			case KeyQuit:
				clear()
				return Back, ErrQuit
			}
		}
		if err != nil {
			clear()
			if errors.Is(err, io.EOF) {
				return Back, ErrQuit
			}
			return Back, err
		}
		draw()
	}
}

// ColorWanted reports whether colour output is welcome: NO_COLOR unset
// (https://no-color.org) and not a dumb terminal.
func ColorWanted() bool {
	return os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
}
