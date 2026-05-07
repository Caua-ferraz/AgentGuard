package policy

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// writeMinimalPolicy drops a minimal valid policy YAML at path. The
// write goes through a temp file + Rename so an in-flight FileWatcher
// sees a single atomic event rather than a partial write — matches the
// helper in watcher_test.go.
func writeMinimalPolicy(t *testing.T, path, name string) {
	t.Helper()
	body := []byte("version: \"1\"\nname: \"" + name + "\"\nrules:\n  - scope: shell\n    allow:\n      - pattern: \"ls *\"\n")
	tmp := path + ".writing"
	if err := os.WriteFile(tmp, body, 0600); err != nil {
		t.Fatalf("write tmp policy file: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename tmp policy file: %v", err)
	}
}

func TestFilePolicyProvider_Get_LocalTenant(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writeMinimalPolicy(t, path, "local-test")

	p, err := NewFilePolicyProvider(path)
	if err != nil {
		t.Fatalf("NewFilePolicyProvider: %v", err)
	}
	defer p.Close()

	pol, err := p.Get(LocalTenantID)
	if err != nil {
		t.Fatalf("Get(local) returned error: %v", err)
	}
	if pol == nil {
		t.Fatal("Get(local) returned nil policy")
	}
	if pol.Name != "local-test" {
		t.Errorf("expected policy name local-test, got %q", pol.Name)
	}

	if _, err := p.Get("unknown"); !errors.Is(err, ErrTenantNotFound) {
		t.Errorf("Get(unknown): expected ErrTenantNotFound, got %v", err)
	}
}

func TestFilePolicyProvider_Get_DefaultsLocalOnEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writeMinimalPolicy(t, path, "empty-string-tenant")

	p, err := NewFilePolicyProvider(path)
	if err != nil {
		t.Fatalf("NewFilePolicyProvider: %v", err)
	}
	defer p.Close()

	got, err := p.Get("")
	if err != nil {
		t.Fatalf(`Get("") returned error: %v`, err)
	}
	want, err := p.Get(LocalTenantID)
	if err != nil {
		t.Fatalf("Get(local) returned error: %v", err)
	}
	if got != want {
		// Same policy pointer, same identity.
		t.Errorf(`Get("") and Get(local) returned different *Policy pointers`)
	}
}

func TestFilePolicyProvider_Watch_FiresOnChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writeMinimalPolicy(t, path, "v1")

	p, err := NewFilePolicyProvider(path)
	if err != nil {
		t.Fatalf("NewFilePolicyProvider: %v", err)
	}
	defer p.Close()

	fired := make(chan *Policy, 4)
	stop, err := p.Watch(LocalTenantID, func(pol *Policy) {
		select {
		case fired <- pol:
		default:
		}
	})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	defer stop()

	// Bump the file mtime forward so the watcher's "newer modtime"
	// guard fires. fsnotify Write events also count, but on filesystems
	// where mtime granularity is 1s, two writes inside the same second
	// would otherwise race. Sleep through one second + buffer; the
	// watcher polls at DefaultPollInterval=2s, so the upper bound is
	// ~3s for the polling fallback path.
	time.Sleep(1100 * time.Millisecond)
	writeMinimalPolicy(t, path, "v2")

	select {
	case pol := <-fired:
		if pol == nil {
			t.Fatal("watch callback fired with nil policy")
		}
		if pol.Name != "v2" {
			t.Errorf("expected v2, got %q", pol.Name)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watch callback did not fire within 5s")
	}
}

func TestFilePolicyProvider_Watch_StopUnregisters(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writeMinimalPolicy(t, path, "v1")

	p, err := NewFilePolicyProvider(path)
	if err != nil {
		t.Fatalf("NewFilePolicyProvider: %v", err)
	}
	defer p.Close()

	var fires atomic.Int32
	stop, err := p.Watch(LocalTenantID, func(*Policy) {
		fires.Add(1)
	})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}

	// Unregister immediately, then mutate the file. The callback must
	// not fire after stop().
	stop()
	// Calling stop a second time is safe (sync.Once).
	stop()

	time.Sleep(1100 * time.Millisecond)
	writeMinimalPolicy(t, path, "v2")

	// Wait long enough for both fsnotify and the poll fallback to have
	// observed the change had the callback been live.
	time.Sleep(3 * time.Second)
	if got := fires.Load(); got != 0 {
		t.Errorf("callback fired %d times after stop(); expected 0", got)
	}
}

func TestFilePolicyProvider_Validate(t *testing.T) {
	p := &FilePolicyProvider{}

	t.Run("valid", func(t *testing.T) {
		body := []byte("version: \"1\"\nname: ok\nrules: []\n")
		if err := p.Validate(body); err != nil {
			t.Errorf("expected valid policy, got error: %v", err)
		}
	})

	t.Run("invalid_yaml", func(t *testing.T) {
		body := []byte("version: \"1\"\nname: oops\nrules: [unclosed")
		if err := p.Validate(body); err == nil {
			t.Error("expected error for malformed YAML, got nil")
		}
	})

	t.Run("missing_version", func(t *testing.T) {
		body := []byte("name: noversion\nrules: []\n")
		if err := p.Validate(body); err == nil {
			t.Error("expected error for missing version, got nil")
		}
	})

	t.Run("missing_name", func(t *testing.T) {
		body := []byte("version: \"1\"\nrules: []\n")
		if err := p.Validate(body); err == nil {
			t.Error("expected error for missing name, got nil")
		}
	})
}

func TestFilePolicyProvider_CloseIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writeMinimalPolicy(t, path, "close-test")

	p, err := NewFilePolicyProvider(path)
	if err != nil {
		t.Fatalf("NewFilePolicyProvider: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	// Second Close must not panic and must return nil.
	if err := p.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	// Watch on a closed provider returns an error rather than silently
	// holding a dangling callback.
	if _, err := p.Watch(LocalTenantID, func(*Policy) {}); err == nil {
		t.Error("Watch on closed provider should error")
	}
}

func TestStaticPolicyProvider_UpdatePolicy_FiresWatchers(t *testing.T) {
	pol := &Policy{Version: "1", Name: "v1"}
	prov := NewStaticPolicyProvider(pol)
	defer prov.Close()

	got := make(chan *Policy, 2)
	stop, err := prov.Watch(LocalTenantID, func(p *Policy) { got <- p })
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	defer stop()

	pol2 := &Policy{Version: "1", Name: "v2"}
	prov.UpdatePolicy(pol2)
	select {
	case fired := <-got:
		if fired.Name != "v2" {
			t.Errorf("expected v2, got %q", fired.Name)
		}
	case <-time.After(time.Second):
		t.Fatal("watcher did not fire within 1s")
	}
}

func TestEngineCheck_AcceptsTenantID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writeMinimalPolicy(t, path, "tenant-test")

	prov, err := NewFilePolicyProvider(path)
	if err != nil {
		t.Fatalf("NewFilePolicyProvider: %v", err)
	}
	defer prov.Close()

	eng, err := NewEngine(prov)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer eng.Close()

	res := eng.Check(ActionRequest{Scope: "shell", Command: "ls -la"}, LocalTenantID)
	if res.Decision != Allow {
		t.Errorf("Check(local): expected ALLOW, got %s (%s)", res.Decision, res.Reason)
	}

	// Empty tenant defaults to local.
	res = eng.Check(ActionRequest{Scope: "shell", Command: "ls -la"}, "")
	if res.Decision != Allow {
		t.Errorf(`Check(""): expected ALLOW (empty == local), got %s`, res.Decision)
	}
}

func TestEngineCheck_UnknownTenantDenies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writeMinimalPolicy(t, path, "unknown-tenant-test")

	prov, err := NewFilePolicyProvider(path)
	if err != nil {
		t.Fatalf("NewFilePolicyProvider: %v", err)
	}
	defer prov.Close()

	eng, err := NewEngine(prov)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer eng.Close()

	res := eng.Check(ActionRequest{Scope: "shell", Command: "ls -la"}, "tenant-does-not-exist")
	if res.Decision != Deny {
		t.Errorf("expected DENY for unknown tenant, got %s (%s)", res.Decision, res.Reason)
	}
	if res.Rule != "deny:tenant:not_found" {
		t.Errorf(`expected Rule="deny:tenant:not_found", got %q`, res.Rule)
	}
}

func TestNewEngine_NilProviderRejected(t *testing.T) {
	if _, err := NewEngine(nil); err == nil {
		t.Error("expected error for nil provider, got nil")
	}
}

// TestFilePolicyProvider_WatchCallbackPanicDoesNotKillWatcher is a
// regression test for R-Code H1 (audit-fixup F2). Before the fix, a
// panic inside a Watch callback (e.g. the wired gate.SetPolicy hitting
// a nil-deref on a malformed policy update) propagated up the file
// watcher's goroutine, killing it silently. Subsequent policy edits
// were then dropped on the floor with no operator signal. The fix
// wraps every callback dispatch in safeCallback (defer / recover +
// log).
//
// We register a Watch callback that panics on first invocation, then
// modify the policy file twice. The second modification's callback
// MUST still fire — proving the watcher goroutine survived the first
// panic.
func TestFilePolicyProvider_WatchCallbackPanicDoesNotKillWatcher(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writeMinimalPolicy(t, path, "v1")

	p, err := NewFilePolicyProvider(path)
	if err != nil {
		t.Fatalf("NewFilePolicyProvider: %v", err)
	}
	defer p.Close()

	var calls atomic.Int32
	fired := make(chan *Policy, 4)
	stop, err := p.Watch(LocalTenantID, func(pol *Policy) {
		n := calls.Add(1)
		if n == 1 {
			panic("simulated downstream panic on first policy update")
		}
		select {
		case fired <- pol:
		default:
		}
	})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	defer stop()

	// First mutation: the callback panics. We don't expect to receive on
	// `fired` for this one. We do expect the watcher goroutine to
	// survive — verified by the second mutation reaching us.
	time.Sleep(1100 * time.Millisecond)
	writeMinimalPolicy(t, path, "v2")

	// Wait for the first call to land before triggering the second so
	// we don't accidentally collapse the two events into one mtime tick
	// on coarse-resolution filesystems.
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if calls.Load() < 1 {
		t.Fatal("first callback (the panicking one) never fired; watcher may not have observed the file change at all")
	}

	// Second mutation: the callback must fire normally.
	time.Sleep(1100 * time.Millisecond)
	writeMinimalPolicy(t, path, "v3")

	select {
	case pol := <-fired:
		if pol == nil {
			t.Fatal("second callback fired with nil policy")
		}
		if pol.Name != "v3" {
			t.Errorf("expected v3 on second fire, got %q", pol.Name)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second callback did not fire within 5s — watcher goroutine died on the first panic (H1 regressed)")
	}

	if got := calls.Load(); got < 2 {
		t.Errorf("expected at least 2 callback invocations, got %d", got)
	}
}

// TestStaticPolicyProvider_UpdatePolicy_PanickingWatcherDoesNotPoisonOthers
// confirms that safeCallback is also applied on the StaticPolicyProvider
// dispatch path. A misbehaving consumer must not starve the rest of the
// registered watchers.
func TestStaticPolicyProvider_UpdatePolicy_PanickingWatcherDoesNotPoisonOthers(t *testing.T) {
	prov := NewStaticPolicyProvider(&Policy{Version: "1", Name: "v1"})
	defer prov.Close()

	stopBad, err := prov.Watch(LocalTenantID, func(*Policy) {
		panic("simulated panic in watcher A")
	})
	if err != nil {
		t.Fatalf("Watch A: %v", err)
	}
	defer stopBad()

	got := make(chan *Policy, 2)
	stopGood, err := prov.Watch(LocalTenantID, func(p *Policy) { got <- p })
	if err != nil {
		t.Fatalf("Watch B: %v", err)
	}
	defer stopGood()

	prov.UpdatePolicy(&Policy{Version: "1", Name: "v2"})

	select {
	case fired := <-got:
		if fired.Name != "v2" {
			t.Errorf("expected v2, got %q", fired.Name)
		}
	case <-time.After(time.Second):
		t.Fatal("good watcher did not fire after panicking watcher (H1 regressed on StaticPolicyProvider)")
	}
}
