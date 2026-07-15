package policy

import (
	"errors"
	"fmt"
	"log"
	"runtime/debug"
	"sync"
	"sync/atomic"

	"gopkg.in/yaml.v3"
)

// safeCallback invokes cb(pol) with a deferred recover. A panic inside a
// Watch callback (e.g. a malformed policy update tripping a downstream
// invariant in gate.SetPolicy) would otherwise propagate up the file-
// watcher goroutine and silently kill the watcher — every subsequent
// policy update would then be dropped on the floor with no operator
// signal. This wrapper logs the panic with a full stack trace and returns
// normally so the caller's callback loop keeps running.
func safeCallback(cb func(*Policy), pol *Policy) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("policy: Watch callback panicked: %v\n%s", r, debug.Stack())
		}
	}()
	cb(pol)
}

// LocalTenantID is the single tenant identifier the bundled
// FilePolicyProvider recognises. The proxy passes "local" on every
// Engine.Check call; FilePolicyProvider rejects every other tenant
// value with ErrTenantNotFound.
//
// An empty tenantID is treated as a synonym for "local" so engine-internal
// call paths resolve to the only configured policy.
const LocalTenantID = "local"

// ErrTenantNotFound is returned by PolicyProvider.Get when the tenant has
// no associated policy. The proxy surfaces this as a synthetic DENY with
// Rule="deny:tenant:not_found" so the existing handleCheck flow does not
// need bespoke 404 handling. Multi-tenant providers (database, etcd) map
// a missing tenant to the same error.
var ErrTenantNotFound = errors.New("policy: tenant not found")

// PolicyProvider abstracts policy retrieval. Engine reads policies through
// this interface instead of loading from disk directly. Alternative
// implementations (database, etcd, S3) can satisfy the same interface
// without engine changes.
type PolicyProvider interface {
	// Get returns the current policy for tenantID. The returned *Policy is
	// a snapshot — callers must not mutate it (the engine treats it as
	// read-only and the file provider holds the same pointer). Returns
	// ErrTenantNotFound when no policy exists for the tenant.
	Get(tenantID string) (*Policy, error)

	// Watch registers a callback fired whenever the policy for tenantID
	// changes. Multiple Watch calls coexist. The returned stop function
	// unregisters the callback; calling it twice is safe. The callback is
	// invoked from a watcher goroutine without holding the provider's
	// internal lock, so callers may take their own locks freely.
	Watch(tenantID string, callback func(*Policy)) (stop func(), err error)

	// Validate parses+validates a policy without committing it. Used by
	// `agentguard validate` and admin endpoints. The error message is
	// intended for display to operators; it includes the YAML path of
	// any failing field.
	Validate(policyBytes []byte) error

	// Close releases provider resources (file watchers, DB connections).
	// Safe to call multiple times via sync.Once.
	Close() error
}

// parsePolicyBytes parses YAML and runs the same validation as LoadFromFile,
// minus the os.ReadFile step, returning the parsed *Policy. Factored out so
// providers can reuse it (FilePolicyProvider for raw-bytes Validate; the
// MultiTenantProvider for loading per-tenant policies from a store).
func parsePolicyBytes(data []byte) (*Policy, error) {
	var pol Policy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return nil, fmt.Errorf("parsing policy YAML: %w", err)
	}
	if pol.Version == "" {
		return nil, fmt.Errorf("policy missing required 'version' field")
	}
	if pol.Name == "" {
		return nil, fmt.Errorf("policy missing required 'name' field")
	}
	if err := validateFilesystemPaths(&pol); err != nil {
		return nil, err
	}
	if err := validateRedactionPatterns(&pol); err != nil {
		return nil, err
	}
	if err := validateToolScopeMap(&pol); err != nil {
		return nil, err
	}
	if err := validateTunables(&pol); err != nil {
		return nil, err
	}
	if err := validateRuleDurationsAndCounts(&pol); err != nil {
		return nil, err
	}
	if err := errorTimeWindowOnlyConditions(&pol); err != nil {
		return nil, err
	}

	// Fold rule domains to lower case once (case-insensitive domain matching;
	// see normalizeRuleDomains). Mirrors LoadFromFile so every YAML->Policy
	// path — file load, multi-tenant store load, and Validate — is consistent.
	normalizeRuleDomains(&pol)

	// Non-fatal lint: warn on path patterns whose '*' recurses across '/'.
	for _, w := range lintPathPatterns(&pol) {
		log.Print(w)
	}

	return &pol, nil
}

// validatePolicyBytes validates raw policy YAML without retaining the parsed
// document. Thin wrapper over parsePolicyBytes for the Validate() entry points.
func validatePolicyBytes(data []byte) error {
	_, err := parsePolicyBytes(data)
	return err
}

// FilePolicyProvider serves a single policy loaded from a YAML file. The
// only valid tenantID is "local" (or the empty string, treated as a
// synonym).
//
// Hot-reload is delegated to FileWatcher (pkg/policy/watcher.go), which
// prefers fsnotify and falls back to ModTime polling. On a successful
// reload the provider swaps its cached *Policy and fans the new pointer
// out to every Watch() callback registered with this provider.
type FilePolicyProvider struct {
	path string

	mu         sync.RWMutex
	pol        *Policy
	watcher    *FileWatcher
	callbacks  map[uint64]func(*Policy)
	nextID     uint64
	closeOnce  sync.Once
	closedFlag atomic.Bool
}

// NewFilePolicyProvider loads the policy at path, starts a FileWatcher,
// and returns a ready provider. A failed initial load surfaces as an
// error so operators see a missing or malformed file at boot rather than
// at the first Check call.
func NewFilePolicyProvider(path string) (*FilePolicyProvider, error) {
	pol, err := LoadFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading initial policy from %s: %w", path, err)
	}
	p := &FilePolicyProvider{
		path:      path,
		pol:       pol,
		callbacks: make(map[uint64]func(*Policy)),
	}
	w, err := WatchFile(path, p.onPolicyChange)
	if err != nil {
		// The file existed long enough for LoadFromFile to succeed; if
		// WatchFile cannot Stat it the disk is in an unstable state.
		// Surface the error rather than silently disabling hot-reload.
		return nil, fmt.Errorf("starting policy watcher on %s: %w", path, err)
	}
	p.watcher = w
	return p, nil
}

// Get returns the current policy for tenantID. Only "" and "local" are
// valid; every other tenantID returns ErrTenantNotFound.
func (p *FilePolicyProvider) Get(tenantID string) (*Policy, error) {
	if tenantID != "" && tenantID != LocalTenantID {
		return nil, ErrTenantNotFound
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.pol == nil {
		return nil, ErrTenantNotFound
	}
	return p.pol, nil
}

// Watch registers a callback for policy changes on tenantID. Returns a
// stop function the caller invokes to unregister; calling stop more than
// once is safe.
func (p *FilePolicyProvider) Watch(tenantID string, cb func(*Policy)) (func(), error) {
	if tenantID != "" && tenantID != LocalTenantID {
		return nil, ErrTenantNotFound
	}
	if cb == nil {
		return nil, fmt.Errorf("policy: Watch callback must not be nil")
	}
	p.mu.Lock()
	if p.closedFlag.Load() {
		p.mu.Unlock()
		return nil, fmt.Errorf("policy: provider is closed")
	}
	id := p.nextID
	p.nextID++
	p.callbacks[id] = cb
	p.mu.Unlock()

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			p.mu.Lock()
			delete(p.callbacks, id)
			p.mu.Unlock()
		})
	}
	return stop, nil
}

// Validate parses+validates raw YAML bytes without committing them.
// `agentguard validate` and any admin endpoints that pre-validate a policy
// before writing it to disk/DB go through here.
func (p *FilePolicyProvider) Validate(policyBytes []byte) error {
	return validatePolicyBytes(policyBytes)
}

// Close stops the watcher and clears registered callbacks. Idempotent.
func (p *FilePolicyProvider) Close() error {
	p.closeOnce.Do(func() {
		p.closedFlag.Store(true)
		if p.watcher != nil {
			p.watcher.Close()
		}
		p.mu.Lock()
		p.callbacks = nil
		p.mu.Unlock()
	})
	return nil
}

// onPolicyChange is the FileWatcher callback. It swaps the cached *Policy
// under the write lock, snapshots the callback list, releases the lock,
// and then invokes each callback. The lock is released before user code
// runs so a slow/blocking subscriber callback cannot stall a concurrent
// Get call or another reload.
func (p *FilePolicyProvider) onPolicyChange(newPol *Policy) {
	p.mu.Lock()
	if p.closedFlag.Load() {
		p.mu.Unlock()
		return
	}
	p.pol = newPol
	cbs := make([]func(*Policy), 0, len(p.callbacks))
	for _, cb := range p.callbacks {
		cbs = append(cbs, cb)
	}
	p.mu.Unlock()
	for _, cb := range cbs {
		safeCallback(cb, newPol)
	}
}

// StaticPolicyProvider serves a fixed *Policy without watching any file
// or database. Primary use case: tests that construct a Policy struct
// directly and want to drive Engine.Check without the disk dependency.
// Validate parses raw YAML and runs the standard checks but does NOT
// rebind the static policy — Validate is a pure function.
//
// StaticPolicyProvider also serves as the escape hatch for users who
// embed AgentGuard as a library and prefer to manage policy lifecycle
// themselves; UpdatePolicy lets them swap the served policy at runtime.
type StaticPolicyProvider struct {
	mu        sync.RWMutex
	pol       *Policy
	callbacks map[uint64]func(*Policy)
	nextID    uint64
	closed    atomic.Bool
	closeOnce sync.Once
}

// NewStaticPolicyProvider returns a provider that serves pol on every
// Get("local") / Get("") call. pol may be nil; callers can populate it
// later via UpdatePolicy.
func NewStaticPolicyProvider(pol *Policy) *StaticPolicyProvider {
	return &StaticPolicyProvider{
		pol:       pol,
		callbacks: make(map[uint64]func(*Policy)),
	}
}

// Get returns the static policy. Tenants other than "" and "local"
// produce ErrTenantNotFound. A nil policy also produces ErrTenantNotFound
// — callers must populate one via UpdatePolicy before first use.
func (p *StaticPolicyProvider) Get(tenantID string) (*Policy, error) {
	if tenantID != "" && tenantID != LocalTenantID {
		return nil, ErrTenantNotFound
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.pol == nil {
		return nil, ErrTenantNotFound
	}
	return p.pol, nil
}

// Watch registers a callback. Callbacks fire on every UpdatePolicy call.
func (p *StaticPolicyProvider) Watch(tenantID string, cb func(*Policy)) (func(), error) {
	if tenantID != "" && tenantID != LocalTenantID {
		return nil, ErrTenantNotFound
	}
	if cb == nil {
		return nil, fmt.Errorf("policy: Watch callback must not be nil")
	}
	p.mu.Lock()
	if p.closed.Load() {
		p.mu.Unlock()
		return nil, fmt.Errorf("policy: provider is closed")
	}
	id := p.nextID
	p.nextID++
	p.callbacks[id] = cb
	p.mu.Unlock()

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			p.mu.Lock()
			delete(p.callbacks, id)
			p.mu.Unlock()
		})
	}
	return stop, nil
}

// Validate parses+validates raw YAML bytes. Same semantics as
// FilePolicyProvider.Validate.
func (p *StaticPolicyProvider) Validate(policyBytes []byte) error {
	return validatePolicyBytes(policyBytes)
}

// UpdatePolicy swaps the served policy and notifies all watchers. This
// mirrors the runtime-mutation path that FilePolicyProvider exposes
// implicitly via file edits, so library embedders can drive hot-reloads
// from any source.
func (p *StaticPolicyProvider) UpdatePolicy(pol *Policy) {
	p.mu.Lock()
	if p.closed.Load() {
		p.mu.Unlock()
		return
	}
	p.pol = pol
	cbs := make([]func(*Policy), 0, len(p.callbacks))
	for _, cb := range p.callbacks {
		cbs = append(cbs, cb)
	}
	p.mu.Unlock()
	for _, cb := range cbs {
		safeCallback(cb, pol)
	}
}

// Close clears callbacks. Idempotent.
func (p *StaticPolicyProvider) Close() error {
	p.closeOnce.Do(func() {
		p.closed.Store(true)
		p.mu.Lock()
		p.callbacks = nil
		p.mu.Unlock()
	})
	return nil
}
