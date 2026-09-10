package policy

import (
	"testing"
	"time"
)

// BenchmarkEngineCheck_Local is the baseline hot-path policy evaluation for the
// local tenant.
func BenchmarkEngineCheck_Local(b *testing.B) {
	eng := NewEngineFromPolicy(&Policy{
		Version: "1", Name: "local",
		Rules: []RuleSet{{Scope: "shell", Allow: []Rule{{Pattern: "ls *"}}}},
	})
	req := ActionRequest{Scope: "shell", Command: "ls -la"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.Check(req, LocalTenantID)
	}
}

// BenchmarkEngineCheck_Tenant is the v0.6 per-tenant path: evaluate against a
// non-local tenant's policy resolved through the MultiTenantProvider cache.
// Must stay comparable to the local path (provider Get is an in-memory lookup).
func BenchmarkEngineCheck_Tenant(b *testing.B) {
	base := NewStaticPolicyProvider(&Policy{Version: "1", Name: "local"})
	src := &fakeSource{policies: map[string][]byte{"acme": shellAllow("acme", "deploy *")}}
	prov, _ := NewMultiTenantProvider(base, src)
	eng, _ := NewEngine(prov)
	defer eng.Close()
	req := ActionRequest{Scope: "shell", Command: "deploy x"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.Check(req, "acme")
	}
}

// BenchmarkMultiTenantProvider_Get measures the cached per-tenant policy lookup.
func BenchmarkMultiTenantProvider_Get(b *testing.B) {
	base := NewStaticPolicyProvider(&Policy{Version: "1", Name: "local"})
	src := &fakeSource{policies: map[string][]byte{"acme": shellAllow("acme", "deploy *")}}
	prov, _ := NewMultiTenantProvider(base, src)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = prov.Get("acme")
	}
}

// BenchmarkEngineCheck_RequirePrior measures the condition path that audit
// B1/B27 rewrote. The previous implementation opened the audit file and
// JSON-parsed every line here, while holding e.mu — so there was no meaningful
// "before" number to compare against; it scaled with the log, not the input.
//
// What these pin is that the replacement stays on the hot path's terms:
// allocation-free lookups that do not push Engine.Check past its 6 allocs/op
// budget (CLAUDE.md §1).
func BenchmarkEngineCheck_RequirePrior(b *testing.B) {
	eng := NewEngineFromPolicy(&Policy{
		Version: "1", Name: "bench",
		Rules: []RuleSet{{
			Scope: "shell",
			Allow: []Rule{{
				Pattern:    "write *",
				Conditions: []Condition{{RequirePrior: "read_file", TimeWindow: "1h"}},
			}},
		}},
	})
	idx := NewPriorActionIndex(time.Hour)
	eng.SetPriorActionQuerier(idx)
	idx.Record(LocalTenantID, "agent-1", "shell", "read_file", "", time.Now())

	req := ActionRequest{Scope: "shell", Command: "write out.txt", AgentID: "agent-1"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.Check(req, LocalTenantID)
	}
}

// BenchmarkEngineCheck_RequirePriorGlob is the same check with a glob pattern,
// which takes the scan branch instead of the O(1) exact hit. The scan is
// bounded by the actions one agent took in one scope, never by the audit log.
func BenchmarkEngineCheck_RequirePriorGlob(b *testing.B) {
	eng := NewEngineFromPolicy(&Policy{
		Version: "1", Name: "bench",
		Rules: []RuleSet{{
			Scope: "shell",
			Allow: []Rule{{
				Pattern:    "write *",
				Conditions: []Condition{{RequirePrior: "read_*", TimeWindow: "1h"}},
			}},
		}},
	})
	idx := NewPriorActionIndex(time.Hour)
	eng.SetPriorActionQuerier(idx)
	// A realistic spread of distinct actions for one agent in one scope.
	now := time.Now()
	for _, a := range []string{"read_file", "list_dir", "stat_file", "write_file", "delete_file"} {
		idx.Record(LocalTenantID, "agent-1", "shell", a, "", now)
	}

	req := ActionRequest{Scope: "shell", Command: "write out.txt", AgentID: "agent-1"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.Check(req, LocalTenantID)
	}
}
