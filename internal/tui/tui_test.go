package tui

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestParseKeys(t *testing.T) {
	cases := []struct {
		in   string
		want []Key
	}{
		{"\x1b[A", []Key{KeyUp}},
		{"\x1b[B\x1b[B\r", []Key{KeyDown, KeyDown, KeyEnter}},
		{"\x1bOA\x1bOB", []Key{KeyUp, KeyDown}}, // application cursor mode
		{"kj\n", []Key{KeyUp, KeyDown, KeyEnter}},
		{"\x1b", []Key{KeyBack}},
		{"q", []Key{KeyBack}},
		{"\x03", []Key{KeyQuit}},
		{"\x1b[1;5C\x1b[B", []Key{KeyDown}}, // unknown sequence skipped whole
		{"x", nil},
	}
	for _, c := range cases {
		got := ParseKeys([]byte(c.in))
		if len(got) != len(c.want) {
			t.Errorf("ParseKeys(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("ParseKeys(%q) = %v, want %v", c.in, got, c.want)
				break
			}
		}
	}
}

func testOptions() []Option {
	return []Option{
		{Label: "Open the dashboard"},
		{Label: "Update to v9.9.9", Hint: "you have v1.0.0"},
		{Separator: true},
		{Label: "Uninstall"},
	}
}

func TestMenuMoveSkipsSeparatorsAndWraps(t *testing.T) {
	m := NewMenu("t", testOptions(), 0)
	m.Move(1)
	m.Move(1)
	if m.Cursor != 3 {
		t.Fatalf("down twice from 0 = %d, want 3 (skipping the separator)", m.Cursor)
	}
	m.Move(1)
	if m.Cursor != 0 {
		t.Fatalf("down from the last option = %d, want 0 (wraps)", m.Cursor)
	}
	m.Move(-1)
	if m.Cursor != 3 {
		t.Fatalf("up from the first option = %d, want 3 (wraps)", m.Cursor)
	}
	if m := NewMenu("t", testOptions(), 2); m.Cursor != 3 {
		t.Fatalf("default on a separator starts at %d, want 3", m.Cursor)
	}
}

func TestRun(t *testing.T) {
	cases := []struct {
		name    string
		keys    string
		want    int
		wantErr error
	}{
		{"enter picks the default", "\r", 0, nil},
		{"arrows then enter", "\x1b[B\x1b[B\r", 3, nil},
		{"one step down", "\x1b[B\r", 1, nil},
		{"esc goes back", "\x1b", Back, nil},
		{"ctrl-c quits", "\x03", Back, ErrQuit},
		{"input ends", "", Back, ErrQuit},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			got, err := Run(strings.NewReader(c.keys), &out, Style{}, NewMenu("What now?", testOptions(), 0), "\n")
			if got != c.want || !errors.Is(err, c.wantErr) {
				t.Fatalf("Run = %d, %v; want %d, %v", got, err, c.want, c.wantErr)
			}
			if !strings.Contains(out.String(), "› Open the dashboard") {
				t.Errorf("the menu was never drawn:\n%s", out.String())
			}
			if c.want >= 0 && !strings.HasSuffix(out.String(), "What now? "+testOptions()[c.want].Label+"\n") {
				t.Errorf("no record of the answer at the end:\n%q", out.String())
			}
		})
	}
}

func TestRenderWithoutColorHasNoEscapes(t *testing.T) {
	lines := NewMenu("Title", testOptions(), 1).Render(Style{})
	joined := strings.Join(lines, "\n")
	if strings.Contains(joined, "\x1b") {
		t.Errorf("colourless render contains escape codes: %q", joined)
	}
	for _, want := range []string{" Title", " › Update to v9.9.9  you have v1.0.0", "   Uninstall", "Esc back"} {
		if !strings.Contains(joined, want) {
			t.Errorf("render lacks %q:\n%s", want, joined)
		}
	}
}
