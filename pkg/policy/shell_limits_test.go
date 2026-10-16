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
	chain := func(n int, link, end string) string {
		return strings.Repeat(link, (n-len(end))/len(link)) + end
	}
	cases := []struct {
		name string
		cmd  func(n int) string
	}{
		{"an env chain", func(n int) string { return chain(n, "env ", "ls") }},
		{"a timeout chain", func(n int) string { return chain(n, "timeout 1 ", "ls") }},
		{"an env -S chain", func(n int) string { return chain(n, "env -S ", "ls") }},
		{"one sudo with many options", func(n int) string { return "sudo " + chain(n, "-u root ", "rm -rf /") }},
		{"an env chain with syntax", func(n int) string { return chain(n, "env ", "ls; ls") }},
		{"a sudo chain", func(n int) string { return chain(n, "sudo -u root ", "rm -rf /") }},
		{"assignments before a command", func(n int) string { return chain(n, "A=1 ", "rm -rf /") }},
	}
	check := func(cmd string) (Decision, string, time.Duration, uint64) {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		got := eng.Check(ActionRequest{Scope: "shell", Command: cmd, AgentID: "a"}, LocalTenantID)
		elapsed := time.Since(start)
		runtime.ReadMemStats(&after)
		return got.Decision, got.Reason, elapsed, after.TotalAlloc - before.TotalAlloc
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, quarter, _ := check(c.cmd(size / 4))
			cmd := c.cmd(size)
			decision, reason, full, allocated := check(cmd)
			t.Logf("%s: %s in %v (a quarter of it: %v), %d MiB allocated", c.name, decision, full, quarter, allocated>>20)
			// Linear work takes about 4 times as long for 4 times the
			// input; the quadratic chains took 16 times as long (seconds
			// and gigabytes at 1 MiB). Wall time alone is a poor bound:
			// CI runs this under -race and coverage on shared machines,
			// where a linear 1 MiB check takes most of a second. Short
			// runs are left alone, since their ratio is mostly noise.
			if full > 100*time.Millisecond && full > 10*quarter {
				t.Errorf("Check took %v for 1 MiB and %v for 256 KiB: it grows faster than linearly", full, quarter)
			}
			if full > 20*time.Second {
				t.Errorf("Check took %v for a 1 MiB command", full)
			}
			if allocated > 48*size {
				t.Errorf("Check allocated %d MiB for a 1 MiB command, want at most 48 MiB", allocated>>20)
			}
			if decision == Allow && strings.Contains(cmd, "rm -rf") {
				t.Errorf("Check = ALLOW (%s), want approval or a deny", reason)
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
			// In a nested script, the limit makes that script unparsed
			// (asked about) rather than the whole command unparseable.
			p, err := parseShell(c.in)
			unparsed := 0
			if err == nil {
				unparsed = len(p.Unparsed)
			}
			if ok := err == nil && unparsed == 0; ok != c.ok {
				t.Errorf("parseShell(%q) error = %v, unparsed %d, want ok %v", c.in, err, unparsed, c.ok)
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
