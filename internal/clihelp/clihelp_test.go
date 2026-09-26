package clihelp

import (
	"bytes"
	"flag"
	"strings"
	"testing"
	"unicode/utf8"
)

func testFlags() *flag.FlagSet {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	u := fs.String("url", "http://localhost:8080", "Server URL")
	fs.StringVar(u, "guard-url", "http://localhost:8080", "Same as --url")
	fs.Bool("compress", true, "Gzip the archives")
	fs.Bool("dry-run", false, "Change nothing")
	fs.Int("port", 8080, "Port to listen on")
	fs.String("policy", "configs/default.yaml", "Policy file")
	fs.String("note", "", strings.Repeat("A long description that has to wrap. ", 6))
	fs.String("a-very-long-flag-name-for-the-label", "", "Goes on the next line")
	return fs
}

func TestWriteGroups_EveryFlagOnce(t *testing.T) {
	fs := testFlags()
	var out bytes.Buffer
	WriteGroups(&out, fs, []Group{{Title: "Main", Names: []string{"url", "port"}}}, Options{
		Aliases:     map[string]string{"guard-url": "url"},
		HideDefault: map[string]bool{"policy": true},
	})
	help := out.String()

	// Flags missing from the groups land under Ungrouped, so nothing is lost.
	if !strings.Contains(help, "\n"+Ungrouped+":\n") {
		t.Errorf("no %s group for the unlisted flags:\n%s", Ungrouped, help)
	}
	lines := strings.Split(help, "\n")
	fs.VisitAll(func(f *flag.Flag) {
		if f.Name == "guard-url" {
			return // an alias: on --url's line, checked below
		}
		n := 0
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if strings.HasPrefix(l, "--"+f.Name+" ") || strings.HasPrefix(l, "--"+f.Name+",") || l == "--"+f.Name {
				n++
			}
		}
		if n != 1 {
			t.Errorf("--%s starts %d help lines, want 1", f.Name, n)
		}
	})
	flat := strings.Join(strings.Fields(help), " ") // notes may wrap across lines
	for _, want := range []string{
		"--url, --guard-url string",                      // alias on its flag's line
		"(on by default; --compress=false turns it off)", // bool that defaults on
		"(default 8080)",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("help lacks %q:\n%s", want, help)
		}
	}
	for _, bad := range []string{"  --guard-url", "(default configs/default.yaml)", "--dry-run=false"} {
		if strings.Contains(help, bad) {
			t.Errorf("help contains %q:\n%s", bad, help)
		}
	}
	for _, line := range strings.Split(help, "\n") {
		if utf8.RuneCountInString(line) > Width {
			t.Errorf("line wider than %d: %q", Width, line)
		}
	}
}

func TestWriteFlags_Alphabetical(t *testing.T) {
	var out bytes.Buffer
	WriteFlags(&out, testFlags(), Options{Aliases: map[string]string{"guard-url": "url"}})
	help := out.String()
	if strings.Contains(help, Ungrouped) {
		t.Errorf("WriteFlags must list every flag under Flags:\n%s", help)
	}
	if strings.Index(help, "--compress") > strings.Index(help, "--port") {
		t.Errorf("flags are not in alphabetical order:\n%s", help)
	}
}

func TestWrap(t *testing.T) {
	lines := Wrap(strings.Repeat("word ", 40), 40)
	for _, l := range lines {
		if len(l) > 40 {
			t.Errorf("line %q is longer than 40", l)
		}
	}
	if got := strings.Join(lines, " "); got != strings.TrimSpace(strings.Repeat("word ", 40)) {
		t.Errorf("wrap lost or changed words: %q", got)
	}
	if got := Wrap("", 40); len(got) != 1 || got[0] != "" {
		t.Errorf("Wrap(\"\") = %q", got)
	}
}
