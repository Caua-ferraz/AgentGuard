// Package persist wires AgentGuard's in-memory fast-path state to a durable
// store.Store using the write-behind dual-tier model (docs/v0.6-ARCHITECTURE-
// PLAN.md §2.3–2.4).
//
// The Syncer is the ONLY component that bridges memory and disk. It:
//   - Hydrate(): on boot, loads persisted state back into the in-memory maps
//     (rate-limit buckets, session-cost accumulators, approval queue) so a
//     restart does not lose them.
//   - flush loop: on a ticker with a hard 1s floor, snapshots each in-memory
//     structure and upserts it to the store. This runs on its own goroutine
//     and NEVER touches the /v1/check request path, so the <3ms latency budget
//     is unaffected (CLAUDE.md rule #1).
//   - purge loop: periodically GCs stale rows (resolved approvals, idle costs,
//     fully-refilled buckets), mirroring the in-memory eviction.
//   - Close(): stops the loops and performs one final flush so the last second
//     of state is durable across a graceful shutdown.
package persist

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"github.com/Caua-ferraz/AgentGuard/pkg/proxy"
	"github.com/Caua-ferraz/AgentGuard/pkg/ratelimit"
	"github.com/Caua-ferraz/AgentGuard/pkg/store"
)

// MinFlushInterval is the hard floor on the flush cadence (plan §2.4): the
// syncer never writes more often than once per second, bounding write
// amplification / WAL churn.
const MinFlushInterval = 1 * time.Second

// DefaultPurgeInterval is how often stale rows are GC'd. Much coarser than the
// flush — GC is housekeeping, not durability.
const DefaultPurgeInterval = 1 * time.Minute

// flushTimeout bounds a single flush/purge so a wedged store cannot hang
// shutdown or pile up goroutines.
const flushTimeout = 10 * time.Second

// Config wires the syncer to the store and the in-memory sources. Any source
// may be nil (that slice is simply skipped), which keeps the syncer usable in
// focused tests.
type Config struct {
	Store     store.Store
	Limiter   *ratelimit.Limiter
	Engine    *policy.Engine
	Approvals *proxy.ApprovalQueue

	// FlushInterval is clamped up to MinFlushInterval. Zero => MinFlushInterval.
	FlushInterval time.Duration
	// PurgeInterval is how often GC runs. Zero => DefaultPurgeInterval.
	PurgeInterval time.Duration

	// Retention cutoffs for GC. Zero disables that purge (rows kept forever).
	CostTTL     time.Duration // idle session-cost rows
	ApprovalTTL time.Duration // resolved approvals
	BucketTTL   time.Duration // fully-refilled buckets
}

// Syncer drives the write-behind loops.
type Syncer struct {
	cfg      Config
	done     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// New builds a Syncer, clamping the flush interval to the 1s floor.
func New(cfg Config) *Syncer {
	if cfg.FlushInterval < MinFlushInterval {
		cfg.FlushInterval = MinFlushInterval
	}
	if cfg.PurgeInterval <= 0 {
		cfg.PurgeInterval = DefaultPurgeInterval
	}
	return &Syncer{cfg: cfg, done: make(chan struct{})}
}

// Hydrate loads persisted state into the in-memory structures. Call once, on
// boot, BEFORE the server starts serving traffic. A store read error is
// returned so the operator can decide whether to proceed with empty state.
func (s *Syncer) Hydrate(ctx context.Context) error {
	if s.cfg.Limiter != nil {
		buckets, err := s.cfg.Store.LoadBuckets(ctx)
		if err != nil {
			return err
		}
		snaps := make([]ratelimit.BucketSnapshot, 0, len(buckets))
		for _, b := range buckets {
			snaps = append(snaps, ratelimit.BucketSnapshot{
				Key: b.Key, Tokens: b.Tokens, Max: b.Max, Window: b.Window, LastRefill: b.LastRefill,
			})
		}
		s.cfg.Limiter.Restore(snaps)
	}
	if s.cfg.Engine != nil {
		costs, err := s.cfg.Store.LoadCosts(ctx)
		if err != nil {
			return err
		}
		snaps := make([]policy.CostSnapshot, 0, len(costs))
		for _, c := range costs {
			snaps = append(snaps, policy.CostSnapshot{
				Tenant: c.TenantID, Session: c.SessionID, Cost: c.Cost, LastUpdated: c.LastUpdated,
			})
		}
		s.cfg.Engine.RestoreCosts(snaps)
	}
	if s.cfg.Approvals != nil {
		recs, err := s.cfg.Store.LoadApprovals(ctx)
		if err != nil {
			return err
		}
		actions := make([]*proxy.PendingAction, 0, len(recs))
		for _, r := range recs {
			tenant := r.TenantID
			if tenant == store.TenantLocal {
				tenant = "" // proxy stores local as "" internally
			}
			actions = append(actions, &proxy.PendingAction{
				ID: r.ID, TenantID: tenant, Request: r.Request, Result: r.Result,
				CreatedAt: r.CreatedAt, Resolved: r.Resolved, Decision: r.Decision, ResolvedAt: r.ResolvedAt,
			})
		}
		s.cfg.Approvals.Restore(actions)
	}
	return nil
}

// Start launches the flush + purge goroutines. Hydrate first.
func (s *Syncer) Start() {
	s.wg.Add(1)
	go s.run()
}

func (s *Syncer) run() {
	defer s.wg.Done()
	flush := time.NewTicker(s.cfg.FlushInterval)
	defer flush.Stop()
	purge := time.NewTicker(s.cfg.PurgeInterval)
	defer purge.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-flush.C:
			s.flushWithTimeout()
		case <-purge.C:
			s.purgeWithTimeout()
		}
	}
}

func (s *Syncer) flushWithTimeout() {
	ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	defer cancel()
	if err := s.Flush(ctx); err != nil {
		log.Printf("persist: flush error: %v", err)
	}
}

func (s *Syncer) purgeWithTimeout() {
	ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	defer cancel()
	if err := s.Purge(ctx, time.Now()); err != nil {
		log.Printf("persist: purge error: %v", err)
	}
}

// Flush snapshots every in-memory source and upserts it to the store in one
// pass. Exposed (rather than purely internal) so tests and the shutdown path
// can force a synchronous flush. Safe to call concurrently with the flush loop
// only via Close (which stops the loop first).
func (s *Syncer) Flush(ctx context.Context) error {
	if s.cfg.Limiter != nil {
		snaps := s.cfg.Limiter.Snapshot()
		buckets := make([]store.BucketState, 0, len(snaps))
		for _, b := range snaps {
			buckets = append(buckets, store.BucketState{
				TenantID: tenantFromBucketKey(b.Key), Key: b.Key,
				Tokens: b.Tokens, Max: b.Max, Window: b.Window, LastRefill: b.LastRefill,
			})
		}
		if err := s.cfg.Store.UpsertBuckets(ctx, buckets); err != nil {
			return err
		}
	}
	if s.cfg.Engine != nil {
		snaps := s.cfg.Engine.SnapshotCosts()
		costs := make([]store.CostState, 0, len(snaps))
		for _, c := range snaps {
			costs = append(costs, store.CostState{
				TenantID: store.EffectiveTenant(c.Tenant), SessionID: c.Session,
				Cost: c.Cost, LastUpdated: c.LastUpdated,
			})
		}
		if err := s.cfg.Store.UpsertCosts(ctx, costs); err != nil {
			return err
		}
	}
	if s.cfg.Approvals != nil {
		snaps := s.cfg.Approvals.Snapshot()
		recs := make([]store.ApprovalRecord, 0, len(snaps))
		for _, pa := range snaps {
			recs = append(recs, store.ApprovalRecord{
				TenantID: store.EffectiveTenant(pa.TenantID), ID: pa.ID,
				Request: pa.Request, Result: pa.Result, CreatedAt: pa.CreatedAt,
				Resolved: pa.Resolved, Decision: pa.Decision, ResolvedAt: pa.ResolvedAt,
			})
		}
		if err := s.cfg.Store.UpsertApprovals(ctx, recs); err != nil {
			return err
		}
	}
	return nil
}

// Purge GCs stale rows relative to now. Each TTL of 0 disables its purge.
func (s *Syncer) Purge(ctx context.Context, now time.Time) error {
	if s.cfg.CostTTL > 0 {
		if _, err := s.cfg.Store.PurgeCosts(ctx, now.Add(-s.cfg.CostTTL)); err != nil {
			return err
		}
	}
	if s.cfg.ApprovalTTL > 0 {
		if _, err := s.cfg.Store.PurgeResolvedApprovals(ctx, now.Add(-s.cfg.ApprovalTTL)); err != nil {
			return err
		}
	}
	if s.cfg.BucketTTL > 0 {
		if _, err := s.cfg.Store.PurgeBuckets(ctx, now.Add(-s.cfg.BucketTTL)); err != nil {
			return err
		}
	}
	return nil
}

// Close stops the loops, waits for the goroutine to exit, then performs one
// final flush so the last interval of state is durable. Idempotent.
func (s *Syncer) Close() {
	s.stopOnce.Do(func() { close(s.done) })
	s.wg.Wait()
	// Final flush — the loop is stopped, so this is the only writer now.
	ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	defer cancel()
	if err := s.Flush(ctx); err != nil {
		log.Printf("persist: final flush error: %v", err)
	}
}

// tenantFromBucketKey extracts the tenant from a rate-limit bucket key in the
// proxy's "scope:tenant:agent" format (pkg/proxy/server.go). A malformed key
// (no tenant field) falls back to the local tenant so the row is always
// attributable — the store rejects an empty tenant.
func tenantFromBucketKey(key string) string {
	parts := strings.SplitN(key, ":", 3)
	if len(parts) >= 2 && parts[1] != "" {
		return parts[1]
	}
	return store.TenantLocal
}
