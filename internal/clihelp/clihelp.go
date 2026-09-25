// Package clihelp prints the flag section of a command's --help the same
// way for every AgentGuard binary: flags written as --flag, grouped under
// titles, descriptions wrapped to 80 columns, an alias on its flag's line,
// and a note saying how to turn off a bool flag that is on by default.
//
// It is internal to the module: agentguard, agentguard-mcp-gateway and
// agentguard-llm-proxy share it, and nothing outside imports it.
package clihelp

import (
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

// Width is the column the help wraps at.
const Width = 80

// labelMax is the widest flag label that still gets its description on the
// same line; a longer one puts the description on the next line.
const labelMax = 30

// Ungrouped is the title of the group that catches flags no group names.
// A help page that shows it has a flag missing from its group list.
const Ungrouped = "Ungrouped"

// Group is a titled set of flags, printed in the order given.
type Group struct {
	Title string
	Names []string
}

// Options adjusts how flags are printed.
type Options struct {
	// Aliases maps an alias to the flag it stands for. The alias is printed
	// on that flag's line ("--url, --guard-url string"), not on its own.
	Aliases map[string]string
	// HideDefault names flags whose "(default …)" note would mislead,
	// because the page explains what happens when the flag isn't given.
	HideDefault map[string]bool
}

// WriteGroups prints fs's flags under the given groups. A flag that is
// neither in a group nor an alias is printed under Ungrouped, so nothing
// is ever missing from the help.
func WriteGroups(w io.Writer, fs *flag.FlagSet, groups []Group, opt Options) {
	listed := map[string]bool{}
	for _, g := range groups {
		for _, n := range g.Names {
			listed[n] = true
		}
	}
	var rest []string
	fs.VisitAll(func(f *flag.Flag) {
		if !listed[f.Name] && opt.Aliases[f.Name] == "" {
			rest = append(rest, f.Name)
		}
	})
	if len(rest) > 0 {
		groups = append(groups, Group{Title: Ungrouped, Names: rest})
	}

	col := 0
	for _, g := range groups {
		for _, n := range g.Names {
			if f := fs.Lookup(n); f != nil {
				if l := utf8.RuneCountInString(label(f, opt)); l > col && l <= labelMax {
					col = l
				}
			}
		}
	}
	for i, g := range groups {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "%s:\n", g.Title)
		for _, n := range g.Names {
			if f := fs.Lookup(n); f != nil {
				writeFlag(w, f, col, opt)
			}
		}
	}
}

// WriteFlags prints every flag of fs, alphabetically, under "Flags:".
func WriteFlags(w io.Writer, fs *flag.FlagSet, opt Options) {
	var names []string
	fs.VisitAll(func(f *flag.Flag) {
		if opt.Aliases[f.Name] == "" {
			names = append(names, f.Name)
		}
	})
	sort.Strings(names)
	WriteGroups(w, fs, []Group{{Title: "Flags", Names: names}}, opt)
}

// label is the left column for f: "--port int", "--dashboard",
// "--url, --guard-url string".
func label(f *flag.Flag, opt Options) string {
	names := "--" + f.Name
	var aliases []string
	for alias, primary := range opt.Aliases {
		if primary == f.Name {
			aliases = append(aliases, alias)
		}
	}
	sort.Strings(aliases)
	for _, a := range aliases {
		names += ", --" + a
	}
	if typ, _ := flag.UnquoteUsage(f); typ != "" {
		return names + " " + typ
	}
	return names
}

// writeFlag prints one flag: its label, then its description wrapped to
// Width. A label wider than col puts the description on the next line.
func writeFlag(w io.Writer, f *flag.Flag, col int, opt Options) {
	_, usage := flag.UnquoteUsage(f)
	desc := usage + defaultNote(f, opt)
	lbl := label(f, opt)
	indent := 2 + col + 2
	lines := Wrap(desc, Width-indent)
	pad := strings.Repeat(" ", indent)
	if utf8.RuneCountInString(lbl) > col {
		fmt.Fprintf(w, "  %s\n", lbl)
		for _, l := range lines {
			fmt.Fprintf(w, "%s%s\n", pad, l)
		}
		return
	}
	for i, l := range lines {
		if i == 0 {
			fmt.Fprintf(w, "  %s%s  %s\n", lbl, strings.Repeat(" ", col-utf8.RuneCountInString(lbl)), l)
		} else {
			fmt.Fprintf(w, "%s%s\n", pad, l)
		}
	}
}

// defaultNote says what a flag does when it isn't given.
func defaultNote(f *flag.Flag, opt Options) string {
	typ, _ := flag.UnquoteUsage(f)
	switch {
	case opt.HideDefault[f.Name]:
		return ""
	case typ == "" && f.DefValue == "true":
		return fmt.Sprintf(" (on by default; --%s=false turns it off)", f.Name)
	case typ == "":
		return ""
	case f.DefValue == "" || f.DefValue == "0" || f.DefValue == "0s" || f.DefValue == "[]":
		return ""
	default:
		return fmt.Sprintf(" (default %s)", f.DefValue)
	}
}

// Wrap splits s into lines of at most width characters, breaking at
// spaces. A single word longer than width gets a line of its own.
func Wrap(s string, width int) []string {
	if width < 30 {
		width = 30
	}
	var lines []string
	line := ""
	for _, word := range strings.Fields(s) {
		switch {
		case line == "":
			line = word
		case utf8.RuneCountInString(line)+1+utf8.RuneCountInString(word) > width:
			lines = append(lines, line)
			line = word
		default:
			line += " " + word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		lines = []string{""}
	}
	return lines
}
