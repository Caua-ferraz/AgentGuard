package persist

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"github.com/Caua-ferraz/AgentGuard/pkg/proxy"
	"github.com/Caua-ferraz/AgentGuard/pkg/ratelimit"
	"github.com/Caua-ferraz/AgentGuard/pkg/store"
)

// BenchmarkSyncer_Flush measures one write-behind flush cycle (snapshot all
// sources + upsert) — the work the background ticker does. Off the hot path.
func BenchmarkSyncer_Flush(b *testing.B) {
	st, err := store.NewSQLiteStore(filepath.Join(b.TempDir(), "b.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer st.Close()
	lim := ratelimit.New()
	eng := policy.NewEngineFromPolicy(&policy.Policy{Version: "1", Name: "b"})
	q := proxy.NewApprovalQueue(0)
	for i := 0; i < 100; i++ {
		_ = lim.Allow(fmt.Sprintf("shell:local:a%d", i), 5, time.Minute)
		eng.RecordCost(fmt.Sprintf("s%d", i), 1)
	}
	sy := New(Config{Store: st, Limiter: lim, Engine: eng, Approvals: q})
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := sy.Flush(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSyncer_Hydrate measures boot hydration from a populated store.
func BenchmarkSyncer_Hydrate(b *testing.B) {
	st, err := store.NewSQLiteStore(filepath.Join(b.TempDir(), "b.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	costs := make([]store.CostState, 200)
	for i := range costs {
		costs[i] = store.CostState{TenantID: "local", SessionID: fmt.Sprintf("s%d", i), Cost: 1, LastUpdated: now}
	}
	_ = st.UpsertCosts(ctx, costs)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sy := New(Config{Store: st, Engine: policy.NewEngineFromPolicy(&policy.Policy{Version: "1", Name: "b"})})
		if err := sy.Hydrate(ctx); err != nil {
			b.Fatal(err)
		}
	}
}
