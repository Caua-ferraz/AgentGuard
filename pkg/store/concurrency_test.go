package store

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// TestSQLiteStore_ConcurrentWrites exercises many goroutines writing audit +
// cost rows at once — the production shape (buffered-audit workers flushing
// while the syncer flushes state). With MaxOpenConns(1) + busy_timeout, writes
// serialize at the handle with no SQLITE_BUSY error and no lost rows. Run with
// -race for the in-memory paths.
func TestSQLiteStore_ConcurrentWrites(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const workers, perWorker = 16, 12

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				if err := s.AppendAudit(ctx, []audit.Entry{{
					Timestamp: time.Now().UTC(), TenantID: "t",
					Request: policy.ActionRequest{Scope: "shell"},
					Result:  policy.CheckResult{Decision: policy.Allow},
				}}); err != nil {
					t.Errorf("AppendAudit: %v", err)
				}
				if err := s.UpsertCosts(ctx, []CostState{{
					TenantID: "t", SessionID: fmt.Sprintf("s-%d-%d", w, j), Cost: 1, LastUpdated: time.Now().UTC(),
				}}); err != nil {
					t.Errorf("UpsertCosts: %v", err)
				}
			}
		}(w)
	}
	wg.Wait()

	all, err := s.QueryAudit(ctx, "t", audit.QueryFilter{})
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	if len(all) != workers*perWorker {
		t.Errorf("concurrent audit writes: got %d rows, want %d (lost writes?)", len(all), workers*perWorker)
	}
	costs, err := s.LoadCosts(ctx)
	if err != nil {
		t.Fatalf("LoadCosts: %v", err)
	}
	if len(costs) != workers*perWorker {
		t.Errorf("concurrent cost upserts: got %d rows, want %d", len(costs), workers*perWorker)
	}
}
