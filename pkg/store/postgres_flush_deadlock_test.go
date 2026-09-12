package store

// postgres_flush_deadlock_test.go pins that concurrent write-behind flushes
// survive each other.
//
// Under three-node load every flush tick raced: each node builds its batch by
// ranging over a Go map, whose iteration order is randomized per call, and
// Postgres holds a row lock on each upserted row until commit. Two nodes
// writing the same keys in opposite orders is an AB/BA inversion, and the
// server breaks it the only way it can, by killing one transaction. A soak run
// produced 393 of them, 386 on approvals, and each one silently dropped that
// node's whole tick of writes.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// --- pure units (no database required) ---

// TestSortBatch_OrdersByConflictKey pins the ordering itself: ascending on the
// first key, with the second breaking ties. Any total order shared by all
// writers would prevent the deadlock; this one is pinned because it has to
// match the ON CONFLICT key to be the order Postgres actually locks in.
func TestSortBatch_OrdersByConflictKey(t *testing.T) {
	rows := []BucketState{
		{TenantID: "b", Key: "z"},
		{TenantID: "a", Key: "m"},
		{TenantID: "b", Key: "a"},
		{TenantID: "a", Key: "a"},
	}
	sortBatch(rows, func(b BucketState) (string, string) { return b.TenantID, b.Key })

	want := []string{"a/a", "a/m", "b/a", "b/z"}
	for i, w := range want {
		if got := rows[i].TenantID + "/" + rows[i].Key; got != w {
			t.Errorf("row %d = %q, want %q (full order %v)", i, got, w, rows)
		}
	}
}

// TestSortBatch_IsDeterministicAcrossShuffles is the property the fix actually
// rests on: two writers holding the same keys in different orders must arrive
// at the same sequence. Pinning a single shuffle would not catch a comparator
// that is merely stable.
func TestSortBatch_IsDeterministicAcrossShuffles(t *testing.T) {
	base := make([]CostState, 0, 50)
	for i := 0; i < 50; i++ {
		base = append(base, CostState{TenantID: fmt.Sprintf("t%d", i%5), SessionID: fmt.Sprintf("s%02d", i)})
	}
	key := func(c CostState) (string, string) { return c.TenantID, c.SessionID }

	var reference []string
	for round := 0; round < 8; round++ {
		shuffled := append([]CostState(nil), base...)
		rnd := rand.New(rand.NewSource(int64(round)))
		rnd.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

		sortBatch(shuffled, key)
		got := make([]string, len(shuffled))
		for i, c := range shuffled {
			got[i] = c.TenantID + "/" + c.SessionID
		}
		if reference == nil {
			reference = got
			continue
		}
		for i := range got {
			if got[i] != reference[i] {
				t.Fatalf("shuffle %d diverges at %d: %q vs %q -- writers would lock in different orders",
					round, i, got[i], reference[i])
			}
		}
	}
}

// TestIsDeadlock pins which failures are replayed. Retrying is only safe
// because a deadlock abort rolls the transaction back whole; classifying any
// other failure as a deadlock would replay work that may have partly landed.
func TestIsDeadlock(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"deadlock", &pgconn.PgError{Code: pgDeadlockCode}, true},
		{"wrapped deadlock", fmt.Errorf("store: migrate: %w", &pgconn.PgError{Code: pgDeadlockCode}), true},
		{"unique violation", &pgconn.PgError{Code: "23505"}, false},
		{"serialization failure", &pgconn.PgError{Code: "40001"}, false},
		{"plain error", errors.New("deadlock detected"), false},
		{"context deadline", context.DeadlineExceeded, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDeadlock(tc.err); got != tc.want {
				t.Errorf("isDeadlock(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// --- against a real server ---

// flushersSurvive drives the exact shape that failed in the cluster: several
// writers upserting one shared key set, each in its own order, over and over.
// Every call must succeed. Before the batches were sorted, this reproduced
// 40P01 within a few rounds.
func flushersSurvive[T any](t *testing.T, batch []T, upsert func(context.Context, []T) error) {
	t.Helper()
	const (
		writers = 4
		rounds  = 15
	)
	errs := make(chan error, writers*rounds)
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rnd := rand.New(rand.NewSource(seed))
			for r := 0; r < rounds; r++ {
				// Each writer's own order, as a fresh map range would produce.
				mine := append([]T(nil), batch...)
				rnd.Shuffle(len(mine), func(i, j int) { mine[i], mine[j] = mine[j], mine[i] })
				if err := upsert(context.Background(), mine); err != nil {
					errs <- fmt.Errorf("writer %d round %d: %w", seed, r, err)
					return
				}
			}
		}(int64(w))
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent flush failed: %v", err)
	}
}

// TestPostgresStore_ConcurrentApprovalFlushersSurvive covers the table that
// actually broke: 386 of the 393 deadlocks in the soak were on approvals, which
// carries by far the largest batch -- every pending and resolved entry,
// rewritten every tick.
func TestPostgresStore_ConcurrentApprovalFlushersSurvive(t *testing.T) {
	s := newTestPGStore(t)
	batch := make([]ApprovalRecord, 0, 60)
	for i := 0; i < 60; i++ {
		batch = append(batch, ApprovalRecord{
			TenantID: fmt.Sprintf("tenant-%d", i%3), ID: fmt.Sprintf("appr-%02d", i),
			CreatedAt: time.Now(), Decision: "ALLOW",
		})
	}
	flushersSurvive(t, batch, s.UpsertApprovals)
}

// TestPostgresStore_ConcurrentBucketFlushersSurvive covers the other table the
// soak caught, which took the remaining 7 deadlocks.
func TestPostgresStore_ConcurrentBucketFlushersSurvive(t *testing.T) {
	s := newTestPGStore(t)
	batch := make([]BucketState, 0, 60)
	for i := 0; i < 60; i++ {
		batch = append(batch, BucketState{
			TenantID: fmt.Sprintf("tenant-%d", i%3), Key: fmt.Sprintf("rate:key-%02d", i),
			Tokens: 10, Max: 100, Window: time.Minute, LastRefill: time.Now(),
		})
	}
	flushersSurvive(t, batch, s.UpsertBuckets)
}

// TestPostgresStore_ConcurrentCostFlushersSurvive covers session_costs, which
// the soak never stressed -- it ran too few distinct sessions to collide. Its
// conflict key carries no node_id, so it has exactly the same exposure as the
// two tables that did break, and it is only luck that separates them.
func TestPostgresStore_ConcurrentCostFlushersSurvive(t *testing.T) {
	s := newTestPGStore(t)
	batch := make([]CostState, 0, 60)
	for i := 0; i < 60; i++ {
		batch = append(batch, CostState{
			TenantID: fmt.Sprintf("tenant-%d", i%3), SessionID: fmt.Sprintf("sess-%02d", i),
			Cost: 0.25, LastUpdated: time.Now(),
		})
	}
	flushersSurvive(t, batch, s.UpsertCosts)
}

// TestPostgresStore_InTxRetriesDeadlock forces the inversion that sorting
// cannot remove -- two transactions taking the same two rows in opposite orders
// -- and pins that both callers still succeed. This is the case a purge DELETE
// scanning rows against a concurrent upsert produces.
func TestPostgresStore_InTxRetriesDeadlock(t *testing.T) {
	s := newTestPGStore(t)
	ctx := context.Background()

	seed := []BucketState{
		{TenantID: "t", Key: "A", Tokens: 1, Max: 10, Window: time.Minute, LastRefill: time.Now()},
		{TenantID: "t", Key: "B", Tokens: 1, Max: 10, Window: time.Minute, LastRefill: time.Now()},
	}
	if err := s.UpsertBuckets(ctx, seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Both transactions take their first row, then wait for the other to do the
	// same. Only the first attempt waits; a replay must not block on a barrier
	// its partner has already passed.
	var bothLocked sync.WaitGroup
	bothLocked.Add(2)

	touch := func(first, second string) error {
		attempt := 0
		return s.inTx(ctx, func(tx *sql.Tx) error {
			attempt++
			const upd = `UPDATE rate_buckets SET tokens = tokens + 1 WHERE tenant_id = $1 AND key = $2`
			if _, err := tx.ExecContext(ctx, upd, "t", first); err != nil {
				return err
			}
			if attempt == 1 {
				bothLocked.Done()
				bothLocked.Wait()
			}
			_, err := tx.ExecContext(ctx, upd, "t", second)
			return err
		})
	}

	results := make(chan error, 2)
	go func() { results <- touch("A", "B") }()
	go func() { results <- touch("B", "A") }()

	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Errorf("deadlocked transaction was not retried: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("timed out waiting for the deadlocking transactions")
		}
	}
}
