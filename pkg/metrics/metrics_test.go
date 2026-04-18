package metrics

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/deprecation"
)

func TestWritePrometheus_EmitsDeprecationCounters(t *testing.T) {
	deprecation.Reset()
	deprecation.Warn("test.metrics_alpha", "msg")
	deprecation.Warn("test.metrics_alpha", "msg")
	deprecation.Warn("test.metrics_beta", "msg")

	var buf bytes.Buffer
	WritePrometheus(&buf)
	out := buf.String()

	if !strings.Contains(out, "# TYPE agentguard_deprecations_used_total counter") {
		t.Fatalf("expected deprecation counter TYPE line, got:\n%s", out)
	}
	if !strings.Contains(out, `agentguard_deprecations_used_total{feature="test.metrics_alpha"} 2`) {
		t.Errorf("alpha counter missing or wrong value; output:\n%s", out)
	}
	if !strings.Contains(out, `agentguard_deprecations_used_total{feature="test.metrics_beta"} 1`) {
		t.Errorf("beta counter missing or wrong value; output:\n%s", out)
	}

	// Labels must appear in sorted order so scrape output is stable.
	alphaIdx := strings.Index(out, `feature="test.metrics_alpha"`)
	betaIdx := strings.Index(out, `feature="test.metrics_beta"`)
	if alphaIdx == -1 || betaIdx == -1 || alphaIdx >= betaIdx {
		t.Errorf("deprecation labels not in sorted order: alpha=%d beta=%d", alphaIdx, betaIdx)
	}
}

func TestWritePrometheus_NoDeprecationsEmitsHeaderOnly(t *testing.T) {
	deprecation.Reset()

	var buf bytes.Buffer
	WritePrometheus(&buf)
	out := buf.String()

	if !strings.Contains(out, "# TYPE agentguard_deprecations_used_total counter") {
		t.Fatalf("header must be present even when no features used, got:\n%s", out)
	}
	// No label lines should exist.
	if strings.Contains(out, "agentguard_deprecations_used_total{") {
		t.Errorf("unexpected deprecation label lines when no features used")
	}
}

func TestEscapeLabel(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"plain", "plain"},
		{`with"quote`, `with\"quote`},
		{`with\back`, `with\\back`},
		{"with\nnewline", `with\nnewline`},
		{`a"b\c` + "\n" + "d", `a\"b\\c\nd`},
	}
	for _, c := range cases {
		if got := escapeLabel(c.in); got != c.want {
			t.Errorf("escapeLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
