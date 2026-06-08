package audit

// Tests for the v0.6 tenant_id addition to the audit schema: the
// EffectiveTenant() default, byte-identity of single-tenant ("local")
// output, and tenant-scoped Query filtering. See
// docs/v0.6-ARCHITECTURE-PLAN.md § 3.3–3.4.

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

func TestEffectiveTenant(t *testing.T) {
	cases := map[string]struct {
		stored string
		want   string
	}{
		"empty defaults to local": {stored: "", want: policy.LocalTenantID},
		"explicit local":          {stored: "local", want: "local"},
		"non-local verbatim":      {stored: "acme", want: "acme"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := Entry{TenantID: tc.stored}.EffectiveTenant()
			if got != tc.want {
				t.Fatalf("EffectiveTenant(%q) = %q, want %q", tc.stored, got, tc.want)
			}
		})
	}
}

// TestLocalTenantByteIdentity asserts that an entry for the default tenant
// (TenantID == "") serializes WITHOUT a tenant_id key — the property that keeps
// single-tenant audit files byte-identical to pre-v0.6 output — while a
// non-local tenant serializes the field verbatim.
func TestLocalTenantByteIdentity(t *testing.T) {
	local, err := json.Marshal(Entry{AgentID: "bot", SessionID: "s1"})
	if err != nil {
		t.Fatalf("marshal local: %v", err)
	}
	if strings.Contains(string(local), "tenant_id") {
		t.Fatalf("local-tenant entry must omit tenant_id, got: %s", local)
	}

	acme, err := json.Marshal(Entry{AgentID: "bot", SessionID: "s1", TenantID: "acme"})
	if err != nil {
		t.Fatalf("marshal acme: %v", err)
	}
	if !strings.Contains(string(acme), `"tenant_id":"acme"`) {
		t.Fatalf("non-local entry must include tenant_id, got: %s", acme)
	}
}

// TestFileLoggerTenantScopedQuery verifies that QueryFilter.TenantID isolates
// entries by tenant, that an empty filter returns all tenants, and that an
// entry stored with an empty tenant_id matches a "local" filter (so the legacy
// /v1/audit route keeps returning local entries).
func TestFileLoggerTenantScopedQuery(t *testing.T) {
	logger, err := NewFileLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	// One entry stored as the default tenant ("" on disk), one as "acme".
	mustLog(t, logger, Entry{AgentID: "a-local", SessionID: "s"}) // local (empty)
	mustLog(t, logger, Entry{AgentID: "a-acme", SessionID: "s", TenantID: "acme"})

	count := func(filter QueryFilter) int {
		t.Helper()
		got, err := logger.Query(filter)
		if err != nil {
			t.Fatalf("Query(%+v): %v", filter, err)
		}
		return len(got)
	}

	if n := count(QueryFilter{}); n != 2 {
		t.Errorf("empty filter (all tenants): got %d, want 2", n)
	}
	if n := count(QueryFilter{TenantID: "local"}); n != 1 {
		t.Errorf(`TenantID="local": got %d, want 1 (the empty-tenant entry)`, n)
	}
	if got, _ := logger.Query(QueryFilter{TenantID: "local"}); len(got) == 1 && got[0].AgentID != "a-local" {
		t.Errorf(`TenantID="local" returned wrong entry: %q`, got[0].AgentID)
	}
	if n := count(QueryFilter{TenantID: "acme"}); n != 1 {
		t.Errorf(`TenantID="acme": got %d, want 1`, n)
	}
	if n := count(QueryFilter{TenantID: "ghost"}); n != 0 {
		t.Errorf(`TenantID="ghost": got %d, want 0`, n)
	}
}

func mustLog(t *testing.T, l *FileLogger, e Entry) {
	t.Helper()
	if err := l.Log(e); err != nil {
		t.Fatalf("Log: %v", err)
	}
}
