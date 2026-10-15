package policy

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// A request body is at most 1 MiB, so a command can be a 1 MiB chain of
// wrappers. Each wrapper level used to join and keep every word after it,
// so such a chain took seconds and gigabytes: past the hook's timeout,
// which fails open by default. It must be decided quickly and with memory
// in proportion to its size.
func TestCheck_LongWrapperChainsStayCheap(t *testing.T) {
	eng := NewEngineFromPolicy(&Policy{Version: "1", Name: "chains", Rules: []RuleSet{{
		Scope:           "shell",
		Deny:            []Rule{{Pattern: ":(){ :|:& };:"}},
		RequireApproval: []Rule{{Pattern: "rm -rf *"}, {Pattern: "curl * | *sh"}},
		Allow:           []Rule{{Pattern: "*"}},
	}}})
	const size = 1 << 20
	chain := func(link, end string) string {
		return strings.Repeat(link, (size-len(end))/len(link)) + end
	}
	cases := []struct {
		name string
		cmd  string
	}{
		{"an env chain", chain("env ", "ls")},
		{"a timeout chain", chain("timeout 1 ", "ls")},
		{"an env -S chain", chain("env -S ", "ls")},
		{"one sudo with many options", "sudo " + chain("-u root ", "rm -rf /")},
		{"an env chain with syntax", chain("env ", "ls; ls")},
		{"a sudo chain", chain("sudo -u root ", "rm -rf /")},
		{"assignments before a command", chain("A=1 ", "rm -rf /")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			start := time.Now()
			got := eng.Check(ActionRequest{Scope: "shell", Command: c.cmd, AgentID: "a"}, LocalTenantID)
			elapsed := time.Since(start)
			runtime.ReadMemStats(&after)
			allocated := after.TotalAlloc - before.TotalAlloc
			t.Logf("%s: %s in %v, %d MiB allocated", c.name, got.Decision, elapsed, allocated>>20)
			// A quadratic chain needs seconds and gigabytes; a linear one
			// about 20 ms here.
			limit := 50 * time.Millisecond
			if raceDetector {
				limit *= 10
			}
			if elapsed > limit {
				t.Errorf("Check took %v, want under %v", elapsed, limit)
			}
			if allocated > 48*size {
				t.Errorf("Check allocated %d MiB for a 1 MiB command, want at most 48 MiB", allocated>>20)
			}
			if got.Decision == Allow && strings.Contains(c.cmd, "rm -rf") {
				t.Errorf("Check = ALLOW (%s), want approval or a deny", got.Reason)
			}
		})
	}
}

// Up to 16 wrappers (and two env -S strings) in one command are looked
// through; more is unparseable.
func TestParseShell_WrapperLimits(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"16 wrappers", strings.Repeat("nohup ", 16) + "ls", true},
		{"17 wrappers", strings.Repeat("nohup ", 17) + "ls", false},
		{"17 wrappers in a script", "bash -c '" + strings.Repeat("env ", 17) + "ls'", false},
		{"two env -S strings", "env -S 'env -S ls'", true},
		{"three env -S strings", `env -S 'env -S "env -S ls"'`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseShell(c.in)
			if (err == nil) != c.ok {
				t.Errorf("parseShell(%q) error = %v, want ok %v", c.in, err, c.ok)
			}
		})
	}
}

// The hot-path pre-check reads only the first words of a command that
// starts with a wrapper.
func TestIsCompoundShell_LongWrapperChainIsBounded(t *testing.T) {
	cmd := strings.Repeat("env ", 1<<18) + "ls"
	if n := testing.AllocsPerRun(5, func() { isCompoundShell(cmd) }); n > 64 {
		t.Errorf("isCompoundShell allocates %v times on a 1 MiB env chain, want a bounded number", n)
	}
}
