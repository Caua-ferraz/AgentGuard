package mcpgw

import (
	"bytes"
	"errors"
	"flag"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Caua-ferraz/AgentGuard/internal/clihelp"
)

// agentguard-mcp-gateway -h prints every flag in a group, as --flag, within 80 columns.
func TestParseConfig_HelpGroupsEveryFlag(t *testing.T) {
	var out bytes.Buffer
	_, err := ParseConfigWithOutput([]string{"-h"}, &out)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("err = %v, want flag.ErrHelp", err)
	}
	help := out.String()
	if strings.Contains(help, clihelp.Ungrouped+":") {
		t.Errorf("a flag is missing from the help groups:\n%s", help)
	}
	for _, want := range []string{`--upstream "<ns>:<cmd>"`, "--reconnect-cap duration", "--version", "AGENTGUARD_URL"} {
		if !strings.Contains(help, want) {
			t.Errorf("help lacks %q", want)
		}
	}
	for _, line := range strings.Split(help, "\n") {
		if utf8.RuneCountInString(line) > clihelp.Width {
			t.Errorf("line wider than %d: %q", clihelp.Width, line)
		}
		if strings.HasPrefix(line, "  -") && !strings.HasPrefix(line, "  --") {
			t.Errorf("flag written with one dash: %q", line)
		}
	}
}

// --reconnect-cap was parsed but never used: the gateway always waited up to
// 60s between restarts. BackoffSchedule applies it.
func TestBackoffSchedule(t *testing.T) {
	cases := []struct {
		maxWait time.Duration
		want    []time.Duration
	}{
		{0, DefaultBackoffSchedule},
		{60 * time.Second, DefaultBackoffSchedule},
		{2 * time.Minute, DefaultBackoffSchedule},
		{10 * time.Second, []time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second}},
		{5 * time.Second, []time.Duration{time.Second, 2 * time.Second, 5 * time.Second}},
		{500 * time.Millisecond, []time.Duration{500 * time.Millisecond}},
	}
	for _, c := range cases {
		got := BackoffSchedule(c.maxWait)
		if len(got) != len(c.want) {
			t.Errorf("BackoffSchedule(%s) = %v, want %v", c.maxWait, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("BackoffSchedule(%s) = %v, want %v", c.maxWait, got, c.want)
				break
			}
		}
	}
}
