package policy

import "testing"

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
