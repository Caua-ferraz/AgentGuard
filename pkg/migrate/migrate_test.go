package migrate

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
)

// fakeMigration is a test double. Each field controls one observable
// behavior so tests can exercise the framework without real on-disk work.
type fakeMigration struct {
	id        string
	from, to  string
	desc      string
	detectOk  bool
	detectErr error
	migrateErr error
	verifyErr  error

	migrated bool
	verified bool
	dryRun   bool
}

func (f *fakeMigration) ID() string          { return f.id }
func (f *fakeMigration) FromVersion() string { return f.from }
func (f *fakeMigration) ToVersion() string   { return f.to }
func (f *fakeMigration) Description() string { return f.desc }

func (f *fakeMigration) Detect(ctx context.Context, env Env) (bool, error) {
	return f.detectOk, f.detectErr
}

func (f *fakeMigration) Migrate(ctx context.Context, env Env, dryRun bool) (Result, error) {
	f.migrated = true
	f.dryRun = dryRun
	if f.migrateErr != nil {
		return Result{}, f.migrateErr
	}
	return Result{
		MigrationID: f.id,
		From:        f.from,
		To:          f.to,
		DryRun:      dryRun,
		Stats:       map[string]int64{"records_migrated": 7},
	}, nil
}

func (f *fakeMigration) Verify(ctx context.Context, env Env) error {
	f.verified = true
	return f.verifyErr
}

func newFake(id string) *fakeMigration {
	return &fakeMigration{id: id, from: "1", to: "2", desc: id + " desc", detectOk: true}
}

func TestRegister_RejectsDuplicateID(t *testing.T) {
	ResetForTest()
	Register(newFake("v1_to_v2"))
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate ID")
		}
	}()
	Register(newFake("v1_to_v2"))
}

func TestRegister_RejectsNil(t *testing.T) {
	ResetForTest()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil migration")
		}
	}()
	Register(nil)
}

func TestRunStartup_RunsDetectedMigrations(t *testing.T) {
	ResetForTest()
	a := newFake("a")
	b := newFake("b")
	b.detectOk = false // skipped
	c := newFake("c")
	Register(a)
	Register(b)
	Register(c)

	if err := RunStartup(context.Background(), Env{}); err != nil {
		t.Fatalf("RunStartup: %v", err)
	}
	if !a.migrated || !a.verified {
		t.Errorf("a should have migrated+verified: migrated=%v verified=%v", a.migrated, a.verified)
	}
	if b.migrated {
		t.Errorf("b had Detect=false, should not have migrated")
	}
	if !c.migrated || !c.verified {
		t.Errorf("c should have migrated+verified")
	}
}

// TestRunStartup_SetsMigrationStatusMetric: each Migration triggers exactly
// one metric series — ran, skipped, or failed — so operators can tell from
// a scrape whether the deployment booted past the expected schema. Unique
// version labels isolate the test from prior test state.
func TestRunStartup_SetsMigrationStatusMetric(t *testing.T) {
	ResetForTest()
	ran := newFake("metric-ran")
	ran.from = "mA"
	ran.to = "mB"
	skipped := newFake("metric-skipped")
	skipped.from = "mC"
	skipped.to = "mD"
	skipped.detectOk = false
	Register(ran)
	Register(skipped)

	if err := RunStartup(context.Background(), Env{}); err != nil {
		t.Fatalf("RunStartup: %v", err)
	}

	if got := metrics.MigrationStatusFor("mA", "mB", metrics.MigrationStatusRan); got != 1 {
		t.Errorf("ran migration gauge = %d, want 1", got)
	}
	if got := metrics.MigrationStatusFor("mC", "mD", metrics.MigrationStatusSkipped); got != 1 {
		t.Errorf("skipped migration gauge = %d, want 1", got)
	}
	// The skipped migration must NOT have a "ran" row, and vice versa.
	if got := metrics.MigrationStatusFor("mA", "mB", metrics.MigrationStatusSkipped); got != 0 {
		t.Errorf("ran migration should not also be skipped; got=%d", got)
	}
	if got := metrics.MigrationStatusFor("mC", "mD", metrics.MigrationStatusRan); got != 0 {
		t.Errorf("skipped migration should not also be ran; got=%d", got)
	}
}

// TestRunStartup_MarksFailureInMetric: a migrate error stamps the failed
// gauge before returning so operators can see what was in flight when the
// process aborted.
func TestRunStartup_MarksFailureInMetric(t *testing.T) {
	ResetForTest()
	m := newFake("metric-failed")
	m.from = "fA"
	m.to = "fB"
	m.migrateErr = errors.New("boom-metric")
	Register(m)

	err := RunStartup(context.Background(), Env{})
	if err == nil {
		t.Fatal("expected error")
	}
	if got := metrics.MigrationStatusFor("fA", "fB", metrics.MigrationStatusFailed); got != 1 {
		t.Errorf("failed migration gauge = %d, want 1", got)
	}
}

func TestRunStartup_StopsOnError(t *testing.T) {
	ResetForTest()
	a := newFake("a")
	a.migrateErr = errors.New("boom")
	b := newFake("b")
	Register(a)
	Register(b)

	err := RunStartup(context.Background(), Env{})
	if err == nil {
		t.Fatal("expected error from migrate failure")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("error should wrap underlying cause: %v", err)
	}
	if b.migrated {
		t.Error("b must not run after a failed")
	}
}

func TestRunStartup_VerifyFailureAborts(t *testing.T) {
	ResetForTest()
	a := newFake("a")
	a.verifyErr = errors.New("post-verify bad")
	Register(a)

	err := RunStartup(context.Background(), Env{})
	if err == nil || !strings.Contains(err.Error(), "post-verify") {
		t.Fatalf("expected post-verify error, got %v", err)
	}
}

func TestRunStartup_NoMigrationsRegistered(t *testing.T) {
	ResetForTest()
	if err := RunStartup(context.Background(), Env{}); err != nil {
		t.Fatalf("empty registry should be a no-op, got %v", err)
	}
}

func TestRunCLI_List(t *testing.T) {
	ResetForTest()
	Register(newFake("zzz_last"))
	Register(newFake("aaa_first"))

	var buf bytes.Buffer
	env := Env{Stdout: &buf}
	err := RunCLI(context.Background(), env, CLIOptions{List: true})
	if err != nil {
		t.Fatalf("RunCLI list: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "aaa_first") || !strings.Contains(out, "zzz_last") {
		t.Errorf("list output missing migrations:\n%s", out)
	}
	// Sorted: aaa_first must appear before zzz_last regardless of reg order.
	if strings.Index(out, "aaa_first") > strings.Index(out, "zzz_last") {
		t.Errorf("list output not sorted:\n%s", out)
	}
}

func TestRunCLI_DryRunDoesNotVerify(t *testing.T) {
	ResetForTest()
	a := newFake("only")
	Register(a)

	logBuf := &bytes.Buffer{}
	lg := log.New(logBuf, "", 0)
	err := RunCLI(context.Background(), Env{Logger: lg, Stdout: &bytes.Buffer{}}, CLIOptions{DryRun: true})
	if err != nil {
		t.Fatalf("RunCLI dry-run: %v", err)
	}
	if !a.migrated {
		t.Error("dry-run should still call Migrate() with dryRun=true")
	}
	if !a.dryRun {
		t.Error("Migrate() should have been called with dryRun=true")
	}
	if a.verified {
		t.Error("dry-run must not call Verify()")
	}
}

func TestRunCLI_SpecificID(t *testing.T) {
	ResetForTest()
	a := newFake("a")
	a.detectOk = false // normally skipped
	b := newFake("b")
	Register(a)
	Register(b)

	err := RunCLI(context.Background(), Env{Stdout: &bytes.Buffer{}}, CLIOptions{ID: "a"})
	if err != nil {
		t.Fatalf("RunCLI id=a: %v", err)
	}
	if !a.migrated {
		t.Error("--id=a should run a even though Detect=false (operator override)")
	}
	if b.migrated {
		t.Error("--id=a must not touch b")
	}
}

func TestRunCLI_UnknownIDReturnsNotFound(t *testing.T) {
	ResetForTest()
	Register(newFake("only"))
	err := RunCLI(context.Background(), Env{Stdout: &bytes.Buffer{}}, CLIOptions{ID: "nope"})
	if !errors.Is(err, ErrMigrationNotFound) {
		t.Fatalf("expected ErrMigrationNotFound, got %v", err)
	}
}

func TestSummarizeStats_StableOrder(t *testing.T) {
	r := Result{
		DryRun: true,
		Stats: map[string]int64{
			"records_migrated": 10,
			"bytes_written":    20,
		},
	}
	out := summarizeStats(r)
	// Keys are sorted alphabetically: bytes_written before records_migrated.
	wantPrefix := "dry-run bytes_written=20 records_migrated=10"
	if out != wantPrefix {
		t.Errorf("summarizeStats = %q, want %q", out, wantPrefix)
	}
}
