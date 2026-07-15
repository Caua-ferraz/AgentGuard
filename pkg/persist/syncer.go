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

	// NodeID identifies THIS node when writing multi-node reconciliation rows
	// (v1.0). Each node owns its own `(…, node_id)` consumption rows, so writes
	// are idempotent last-writer-wins with no cross-node read-modify-write race.
	// Empty NodeID disables reconciliation (a row cannot be attributed).
	NodeID string
	// ReconcileInterval is the cadence of the background rate-limit / cost
	// reconciliation loop. Zero disables it. Reconciliation also requires the
	// Store to satisfy the reconcileStore capability interface; when it does not
	// (or NodeID is empty, or this is 0) the reconcile loop never starts and the
	// hot-path limiter/engine state behaves exactly as in single-node mode.
	ReconcileInterval time.Duration
}

// reconcileStore is the unexported capability interface that the multi-node
// reconciler needs beyond the exported store.Store surface. It is satisfied by
// the concrete *store.SQLiteStore and *store.PostgresStore (which carry the six
// consumption methods), NOT by store.Store itself — the v1.0 lock (CLAUDE.md §4)
// freezes store.Store, so new store operations live on the concrete types and
// are reached here via a type assertion, mirroring cmd/agentguard's
// persistentStore pattern. A Store that does not satisfy this interface simply
// disables reconciliation.
type reconcileStore interface {
	UpsertRateConsumption(ctx context.Context, rows []store.RateConsumption) error
	LoadRateConsumption(ctx context.Context) ([]store.RateConsumption, error)
	PurgeRateConsumption(ctx context.Context, cutoff time.Time) (int, error)
	UpsertCostConsumption(ctx context.Context, rows []store.CostConsumption) error
	LoadCostConsumption(ctx context.Context) ([]store.CostConsumption, error)
	PurgeCostConsumption(ctx context.Context, cutoff time.Time) (int, error)
}

// approvalReconcileStore is the unexported capability the approval
// cross-node-visibility reconciler needs. LoadApprovals is already part of the
// exported store.Store surface (so every Store satisfies this today), but the
// reconciler gates through an explicit capability interface — mirroring
// reconcileStore — so arming is uniform with the rate/cost path and remains
// correct if the exported surface is ever narrowed. A Store that does not
// satisfy this simply disables approval reconciliation.
type approvalReconcileStore interface {
	LoadApprovals(ctx context.Context) ([]store.ApprovalRecord, error)
}

// rateReconcileState is the per-bucket reconcile bookkeeping (one goroutine
// owns it — only run()/reconcile touch it, so no lock is needed). It lets the
// reconciler derive THIS node's per-window consumption from successive
// Snapshot()s without ever instrumenting the hot-path Allow.
type rateReconcileState struct {
	hasPrev       bool
	lastTokens    int
	lastRefill    time.Time
	epoch         string // current window epoch (RFC3339Nano) being accumulated
	cumulative    int    // this node's absolute consumption in `epoch`
	othersApplied int    // other-node consumption already subtracted this epoch
}

// costStateKey partitions cost reconcile state by (tenant, session) — the same
// zero-trust partition checkCost uses, so tenant A can never reconcile into
// tenant B (CLAUDE.md §3).
type costStateKey struct {
	tenant  string
	session string
}

// costReconcileState mirrors rateReconcileState for session costs.
type costReconcileState struct {
	lastCost      float64 // local accumulator value already accounted for
	cumulative    float64 // this node's own absolute reservation (pushed)
	othersApplied float64 // other-node reservation already added this session
}

// Syncer drives the write-behind loops.
type Syncer struct {
	cfg      Config
	done     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	// Reconcile capability + state. rc is non-nil ONLY when reconciliation is
	// enabled (ReconcileInterval>0, NodeID set, and the store satisfies
	// reconcileStore); when nil the reconcile ticker never starts. The maps are
	// touched only by the single run() goroutine (and by tests calling reconcile
	// directly), so they need no additional synchronization.
	rc      reconcileStore
	rateRec map[string]*rateReconcileState
	costRec map[costStateKey]*costReconcileState

	// ra is non-nil ONLY when approval cross-node reconciliation is enabled
	// (same gate as rc: ReconcileInterval>0, NodeID set, and the store exposes
	// LoadApprovals). When nil, reconcileApprovals is never invoked and the
	// approval queue behaves exactly as in single-node mode. Touched only by the
	// single run() goroutine (and by tests calling reconcileApprovals directly).
	ra approvalReconcileStore
}

// New builds a Syncer, clamping the flush interval to the 1s floor. When
// ReconcileInterval>0, NodeID is set, and the store exposes the reconcile
// capability, the multi-node reconciler is armed; otherwise it stays disabled
// and the syncer behaves exactly as the v0.6 write-behind-only syncer.
func New(cfg Config) *Syncer {
	if cfg.FlushInterval < MinFlushInterval {
		cfg.FlushInterval = MinFlushInterval
	}
	if cfg.PurgeInterval <= 0 {
		cfg.PurgeInterval = DefaultPurgeInterval
	}
	s := &Syncer{cfg: cfg, done: make(chan struct{})}
	if cfg.ReconcileInterval > 0 && cfg.NodeID != "" && cfg.Store != nil {
		if rc, ok := cfg.Store.(reconcileStore); ok {
			s.rc = rc
			s.rateRec = make(map[string]*rateReconcileState)
			s.costRec = make(map[costStateKey]*costReconcileState)
		}
		if ra, ok := cfg.Store.(approvalReconcileStore); ok {
			s.ra = ra
		}
	}
	return s
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
				ConsumedAt: r.ConsumedAt, ResolvedVia: r.ResolvedVia, ResolvedFrom: r.ResolvedFrom,
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

	// The reconcile ticker exists only when reconciliation is armed. A nil
	// channel in the select simply never fires, so single-node / SQLite / no-caps
	// deployments run the exact v0.6 flush+purge loop with zero extra work.
	var reconcileC <-chan time.Time
	if s.rc != nil || s.ra != nil {
		rt := time.NewTicker(s.cfg.ReconcileInterval)
		defer rt.Stop()
		reconcileC = rt.C
	}

	for {
		select {
		case <-s.done:
			return
		case <-flush.C:
			s.flushWithTimeout()
		case <-purge.C:
			s.purgeWithTimeout()
		case <-reconcileC:
			s.reconcileWithTimeout()
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

func (s *Syncer) reconcileWithTimeout() {
	ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	defer cancel()
	if err := s.reconcile(ctx, time.Now()); err != nil {
		log.Printf("persist: reconcile error: %v", err)
	}
	// Approval cross-node visibility shares the reconcile ticker (design 1-A) and
	// is armed independently of rate/cost reconcile (both gate on the same
	// ReconcileInterval/NodeID, but the store capability check is separate). A
	// reconcile error here never blocks or crashes anything (CLAUDE.md §2).
	if s.ra != nil {
		if err := s.reconcileApprovals(ctx); err != nil {
			log.Printf("persist: approval reconcile error: %v", err)
		}
	}
}

// reconcile runs one multi-node reconciliation pass: derive this node's
// consumption since the last pass from Snapshot-diffs (NOT from the hot path),
// push its absolute cumulative to the shared store, then pull other nodes'
// consumption and fold the increment into the local limiter / cost accumulator.
//
// CLAUDE.md §1: this is background-only and reads the hot-path structures solely
// through their existing Snapshot()/SnapshotCosts() accessors; it NEVER
// instruments Allow/checkCost/RecordCost. The write-back happens through the
// chunked-lock ApplyDeltas/ApplyCostDeltas.
//
// SINGLE-NODE NO-OP: with one node_id, the "others" sum is always 0, so every
// adjustment is 0 and ApplyDeltas([])/ApplyCostDeltas([]) mutate nothing; the
// one own row pushed is never read back into tokens. The in-memory state — and
// thus every firewall decision — is byte-identical to reconciliation disabled.
func (s *Syncer) reconcile(ctx context.Context, now time.Time) error {
	if s.rc == nil {
		return nil
	}
	if err := s.reconcileRate(ctx, now); err != nil {
		return err
	}
	return s.reconcileCost(ctx, now)
}

// epochKey formats a window epoch the same way store.fmtTime does (UTC,
// RFC3339Nano) so a locally-derived epoch and a store-loaded WindowEpoch compare
// as strings without time.Time location/monotonic pitfalls.
func epochKey(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// reconcileRate reconciles the token buckets. Fixed-window semantics: on
// rollover Allow resets tokens to max and advances lastRefill by whole periods,
// so within a window tokens only decrease and the per-window consumption is an
// exact Snapshot-diff.
func (s *Syncer) reconcileRate(ctx context.Context, now time.Time) error {
	if s.cfg.Limiter == nil {
		return nil
	}
	snaps := s.cfg.Limiter.Snapshot()

	// Phase 1: fold this node's consumption-since-last-pass into a per-epoch
	// running cumulative, and stage the absolute cumulative for upsert.
	live := make(map[string]struct{}, len(snaps))
	var push []store.RateConsumption
	for _, sn := range snaps {
		live[sn.Key] = struct{}{}
		if sn.Window <= 0 {
			continue // no window => no derivable epoch
		}
		ek := epochKey(now.Truncate(sn.Window))
		st := s.rateRec[sn.Key]
		if st == nil {
			st = &rateReconcileState{}
			s.rateRec[sn.Key] = st
		}
		if st.epoch != ek {
			// New window: reset per-epoch running totals; drop cross-window tail.
			st.epoch = ek
			st.cumulative = 0
			st.othersApplied = 0
			st.hasPrev = false
		}

		var consumed int
		switch {
		case !st.hasPrev:
			// First observation this epoch: everything consumed so far this window.
			consumed = sn.Max - sn.Tokens
		case sn.LastRefill.Equal(st.lastRefill):
			// Same window: tokens only decrease.
			consumed = st.lastTokens - sn.Tokens
		default:
			// lastRefill advanced within our sampling gap: rebaseline to the newest
			// window, dropping the tail (best-effort per design).
			consumed = sn.Max - sn.Tokens
		}
		if consumed < 0 {
			consumed = 0
		}
		st.cumulative += consumed
		st.hasPrev = true
		st.lastTokens = sn.Tokens
		st.lastRefill = sn.LastRefill

		if st.cumulative > 0 {
			push = append(push, store.RateConsumption{
				TenantID:    tenantFromBucketKey(sn.Key),
				Key:         sn.Key,
				WindowEpoch: now.Truncate(sn.Window).UTC(),
				NodeID:      s.cfg.NodeID,
				Consumed:    st.cumulative,
				UpdatedAt:   now,
			})
		}
	}
	if err := s.rc.UpsertRateConsumption(ctx, push); err != nil {
		return err
	}

	// Phase 2: pull all rows, sum OTHER nodes' consumption per (key, epoch), and
	// apply only the incremental change since last pass (tracked in othersApplied
	// so we never re-subtract). Adjustments are negative (reduce remaining).
	allRows, err := s.rc.LoadRateConsumption(ctx)
	if err != nil {
		return err
	}
	type ke struct{ key, epoch string }
	others := make(map[ke]int)
	for _, r := range allRows {
		if r.NodeID == s.cfg.NodeID {
			continue
		}
		others[ke{key: r.Key, epoch: epochKey(r.WindowEpoch)}] += r.Consumed
	}
	var deltas []ratelimit.BucketDelta
	for _, sn := range snaps {
		if sn.Window <= 0 {
			continue
		}
		st := s.rateRec[sn.Key]
		if st == nil {
			continue
		}
		o := others[ke{key: sn.Key, epoch: st.epoch}]
		adjust := -(o - st.othersApplied)
		if adjust != 0 {
			deltas = append(deltas, ratelimit.BucketDelta{Key: sn.Key, TokenAdjust: adjust})
			st.othersApplied = o
			// Fold the adjustment into the diff baseline so next pass's
			// Snapshot-diff does NOT re-count this reconcile-induced token
			// reduction as local consumption (the feedback loop that would
			// otherwise cascade into over-subtraction). Mirrors the lastCost
			// baseline fold in reconcileCost.
			st.lastTokens += adjust
		}
	}
	s.cfg.Limiter.ApplyDeltas(deltas) // ApplyDeltas skips keys absent locally

	// Phase 3: drop reconcile state for buckets no longer live (evicted), so the
	// state map stays bounded and a reappearing bucket rebaselines cleanly.
	for k := range s.rateRec {
		if _, ok := live[k]; !ok {
			delete(s.rateRec, k)
		}
	}
	return nil
}

// reconcileCost reconciles session-cost accumulators. Session cost is monotonic
// within a session (no window/refill), so the model is simpler than rate: push
// this node's own cumulative reservation and add other nodes' cumulative into
// the local accumulator so checkCost's max_per_session compare sees ~global
// spend. Applied only to sessions present locally (skip absent), tenant-scoped.
func (s *Syncer) reconcileCost(ctx context.Context, now time.Time) error {
	if s.cfg.Engine == nil {
		return nil
	}
	snaps := s.cfg.Engine.SnapshotCosts()

	// Phase 1: derive this node's OWN reservation delta (excluding any others we
	// previously folded in, via the lastCost baseline) and stage the cumulative.
	live := make(map[costStateKey]struct{}, len(snaps))
	var push []store.CostConsumption
	for _, sn := range snaps {
		tenant := store.EffectiveTenant(sn.Tenant)
		k := costStateKey{tenant: tenant, session: sn.Session}
		live[k] = struct{}{}
		st := s.costRec[k]
		if st == nil {
			st = &costReconcileState{}
			s.costRec[k] = st
		}
		localDelta := sn.Cost - st.lastCost
		st.cumulative += localDelta
		if st.cumulative < 0 {
			st.cumulative = 0
		}
		st.lastCost = sn.Cost
		if st.cumulative > 0 {
			push = append(push, store.CostConsumption{
				TenantID:  tenant,
				SessionID: sn.Session,
				NodeID:    s.cfg.NodeID,
				Consumed:  st.cumulative,
				UpdatedAt: now,
			})
		}
	}
	if err := s.rc.UpsertCostConsumption(ctx, push); err != nil {
		return err
	}

	// Phase 2: pull others' cumulative per (tenant, session) and add only the
	// increment. Folding `adjust` into lastCost keeps the injected other-node
	// spend out of next pass's own-delta (no feedback loop).
	allRows, err := s.rc.LoadCostConsumption(ctx)
	if err != nil {
		return err
	}
	others := make(map[costStateKey]float64)
	for _, r := range allRows {
		if r.NodeID == s.cfg.NodeID {
			continue
		}
		others[costStateKey{tenant: r.TenantID, session: r.SessionID}] += r.Consumed
	}
	var deltas []policy.CostDelta
	for _, sn := range snaps {
		tenant := store.EffectiveTenant(sn.Tenant)
		k := costStateKey{tenant: tenant, session: sn.Session}
		st := s.costRec[k]
		if st == nil {
			continue
		}
		o := others[k]
		adjust := o - st.othersApplied
		if adjust != 0 {
			deltas = append(deltas, policy.CostDelta{Tenant: sn.Tenant, Session: sn.Session, CostAdjust: adjust})
			st.othersApplied = o
			st.lastCost += adjust
		}
	}
	s.cfg.Engine.ApplyCostDeltas(deltas)

	// Phase 3: prune state for sessions no longer local (swept), bounding memory.
	for k := range s.costRec {
		if _, ok := live[k]; !ok {
			delete(s.costRec, k)
		}
	}
	return nil
}

// approvalKey is the (tenant, id) merge key for cross-node approval
// reconciliation. Tenant is EffectiveTenant-normalized so a local-tenant row
// ("" in memory, "local" in the store) compares equal across both forms.
type approvalKey struct {
	tenant string
	id     string
}

// reconcileApprovals gives THIS node cross-node visibility of the shared
// approval queue: it loads all-tenant approval rows from the durable store and
// MERGES them into the local in-memory queue so a decision a human made on
// another node becomes visible here. Interval-driven (design 1-A); the
// Postgres LISTEN/NOTIFY nudge is a separate follow-up (1-A-notify).
//
// CLAUDE.md §1: background-only. It reads the queue solely through Snapshot() (a
// read-lock copy) to bound the write set, and writes solely through the
// chunked-lock ApplyRemote. The hot-path Lookup (pure in-memory RLock) is never
// touched — this function calls no method that takes the queue's write lock for
// an O(n) hold.
//
// CLAUDE.md §3: the merge key is (EffectiveTenant(TenantID), ID); a remote row
// for tenant X can only touch entry (X, ID). The per-key conflict resolution
// (DENY-wins, no-clobber of unflushed local pendings, never resurrect a resolved
// action) lives in ApplyRemote and is applied under the queue lock against the
// LIVE entry, so a concurrent local Resolve is authoritative.
//
// SINGLE-NODE NO-OP: with one node, LoadApprovals returns only this node's own
// rows, which are byte-equal to the local entries the syncer already flushed, so
// every candidate is filtered out as a no-op and ApplyRemote receives an empty
// batch — the in-memory queue is byte-identical to reconciliation disabled.
func (s *Syncer) reconcileApprovals(ctx context.Context) error {
	if s.ra == nil || s.cfg.Approvals == nil {
		return nil
	}
	recs, err := s.ra.LoadApprovals(ctx)
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		return nil
	}

	// Snapshot the local queue under its read lock (NO O(n) write hold) and index
	// by the merge key so we can drop remote rows that would provably not change
	// anything — this bounds the number of records ApplyRemote merges under the
	// write lock. The authoritative merge still runs in ApplyRemote against live
	// state; this filter never produces a false positive that could hide a real
	// update (see approvalMergeNoOp).
	local := make(map[approvalKey]*proxy.PendingAction)
	for _, pa := range s.cfg.Approvals.Snapshot() {
		local[approvalKey{tenant: store.EffectiveTenant(pa.TenantID), id: pa.ID}] = pa
	}

	remote := make([]*proxy.PendingAction, 0, len(recs))
	for _, r := range recs {
		tenant := r.TenantID
		if tenant == store.TenantLocal {
			tenant = "" // proxy stores the local tenant as "" internally (mirror Hydrate)
		}
		cand := &proxy.PendingAction{
			ID: r.ID, TenantID: tenant, Request: r.Request, Result: r.Result,
			CreatedAt: r.CreatedAt, Resolved: r.Resolved, Decision: r.Decision, ResolvedAt: r.ResolvedAt,
			ConsumedAt: r.ConsumedAt, ResolvedVia: r.ResolvedVia, ResolvedFrom: r.ResolvedFrom,
		}
		k := approvalKey{tenant: store.EffectiveTenant(r.TenantID), id: r.ID}
		if l, ok := local[k]; ok && approvalMergeNoOp(l, cand) {
			continue // identical / dominated by local => nothing for ApplyRemote to do
		}
		remote = append(remote, cand)
	}
	s.cfg.Approvals.ApplyRemote(remote)
	return nil
}

// approvalMergeNoOp reports whether merging remote r into local l is GUARANTEED
// to leave l unchanged, so the syncer can drop r before handing the batch to
// ApplyRemote (bounding write-lock work). It is deliberately CONSERVATIVE: a
// resolved approval is terminal, so the live entry can only advance
// pending->resolved between this snapshot and ApplyRemote, never back. It
// returns true only for cases that stay a no-op under that advancement, so there
// are no false positives that could drop a real update — a false negative merely
// defers the row to ApplyRemote's authoritative (and idempotent) merge.
func approvalMergeNoOp(l, r *proxy.PendingAction) bool {
	if !l.Resolved {
		// Local pending: a remote RESOLVED row would flip it (must pass); a remote
		// PENDING row is a no-op even if the live entry has since resolved (a
		// remote pending never resurrects / clobbers a resolved entry).
		return !r.Resolved
	}
	// Local resolved (terminal). A remote pending keeps local; a remote resolved
	// with a DIFFERING decision may flip via DENY-wins, so it must pass.
	if !r.Resolved {
		return true
	}
	if l.Decision != r.Decision {
		return false
	}
	// Same terminal decision. Still a real update when the remote carries a
	// one-shot consumption stamp this node lacks (the ALLOW was spent on
	// another node) — that must reach ApplyRemote or the ALLOW stays
	// replayable here. Consumption is monotonic (set-once, never cleared),
	// so "local already stamped" and "remote unstamped" both stay no-ops
	// even if the live entry advances after this snapshot.
	return !l.ConsumedAt.IsZero() || r.ConsumedAt.IsZero()
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
				ConsumedAt: pa.ConsumedAt, ResolvedVia: pa.ResolvedVia, ResolvedFrom: pa.ResolvedFrom,
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
	// Multi-node consumption rows reuse the same purge loop (design: "Consumption
	// -row purge reuses the purge loop"). Only runs when reconciliation is armed.
	// Rate rows follow BucketTTL; cost rows follow CostTTL. Stale (no-longer-
	// updated) rows age out by updated_at, mirroring the bucket/cost GC above.
	if s.rc != nil {
		if s.cfg.BucketTTL > 0 {
			if _, err := s.rc.PurgeRateConsumption(ctx, now.Add(-s.cfg.BucketTTL)); err != nil {
				return err
			}
		}
		if s.cfg.CostTTL > 0 {
			if _, err := s.rc.PurgeCostConsumption(ctx, now.Add(-s.cfg.CostTTL)); err != nil {
				return err
			}
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
