package depaudit

import (
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// online reports whether live lookups (latest-version + OSV.dev) are enabled.
// Off by default so local `go test ./...` stays deterministic and offline; CI
// sets DEPAUDIT_ONLINE=1 so the gate is cross-checked against the live OSV.dev
// database.
func online() bool { return os.Getenv("DEPAUDIT_ONLINE") == "1" }

// loadFindings is the shared setup: locate the repo root, parse every manifest,
// load the registry, and evaluate under opts.
func loadFindings(t *testing.T, opts Options) []Finding {
	t.Helper()
	root, err := RepoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	deps, err := CollectDependencies(root)
	if err != nil {
		t.Fatalf("collect dependencies: %v", err)
	}
	if len(deps) == 0 {
		t.Fatal("no dependencies found — manifest parsing is broken")
	}
	reg, err := LoadRegistry()
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	return EvaluateWithOptions(deps, reg, opts)
}

// TestDependencyAudit_Gate is the blocking check. It fails the build only when a
// dependency is on a version with a known security vulnerability or performance
// regression that an available upgrade would resolve. Safe-but-behind passes.
// When DEPAUDIT_ONLINE=1 (CI) the security dimension is verified live against
// OSV.dev; offline it falls back to the curated registry.
func TestDependencyAudit_Gate(t *testing.T) {
	findings := loadFindings(t, Options{CheckOSV: online()})

	var unsafe []Finding
	for _, f := range findings {
		if !f.Safe {
			unsafe = append(unsafe, f)
		}
	}
	if len(unsafe) == 0 {
		t.Logf("all %d dependencies are on safe versions", len(findings))
		return
	}
	for _, f := range unsafe {
		ref := ""
		if f.Advisory != nil {
			ref = " (" + f.Advisory.Reference + ")"
		}
		t.Errorf("UNSAFE %s dependency %q @ %s: %s%s",
			f.Ecosystem, f.Name, f.Current, f.Reason, ref)
	}
	t.Errorf("%d dependency(ies) require an upgrade; see advisories.md to confirm or update the registry", len(unsafe))
}

// TestDependencyAudit_Report prints the full audit table (name, current,
// latest, safe, reason) for every dependency. Informational: it always passes.
// Run with -v; set DEPAUDIT_ONLINE=1 to populate the "latest" column.
func TestDependencyAudit_Report(t *testing.T) {
	on := online()
	findings := loadFindings(t, Options{FetchLatest: on, CheckOSV: on})

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Ecosystem != findings[j].Ecosystem {
			return findings[i].Ecosystem < findings[j].Ecosystem
		}
		return findings[i].Name < findings[j].Name
	})

	var b strings.Builder
	b.WriteString("\nAgentGuard dependency audit\n")
	if !on {
		b.WriteString("(offline — set DEPAUDIT_ONLINE=1 for latest-version + live OSV.dev security checks)\n")
	}
	fmt.Fprintf(&b, "%-4s %-32s %-24s %-14s %-5s %s\n", "ECO", "NAME", "CURRENT", "LATEST", "SAFE", "REASON")
	fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 124))

	safe, unsafe, osvVerified := 0, 0, 0
	for _, f := range findings {
		latest := f.Latest
		if latest == "" {
			latest = "-"
		}
		verdict := "yes"
		if !f.Safe {
			verdict = "NO"
			unsafe++
		} else {
			safe++
		}
		if f.OSVChecked {
			osvVerified++
		}
		fmt.Fprintf(&b, "%-4s %-32s %-24s %-14s %-5s %s\n",
			f.Ecosystem, truncate(f.Name, 32), truncate(f.Current, 24), truncate(latest, 14), verdict, f.Reason)
	}
	fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 124))
	fmt.Fprintf(&b, "%d dependencies — %d safe, %d unsafe\n", len(findings), safe, unsafe)
	if on {
		fmt.Fprintf(&b, "security: %d exact pins verified live against OSV.dev; %d registry-only "+
			"(Python ranges + Go pseudo-versions). performance: registry-only for all (no DB exists).\n",
			osvVerified, len(findings)-osvVerified)
	}
	t.Log(b.String())
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// ---- unit tests: prove the matcher fires on real fail conditions ------------

func TestExactAffected(t *testing.T) {
	adv := &Advisory{
		Ecosystem: "go", Package: "example.com/x", Kind: KindSecurity,
		Affected: []VersionRange{{Introduced: "1.0.0", Fixed: "1.2.7"}},
	}
	cases := []struct {
		ver     string
		wantHit bool
		wantFix string
		desc    string
	}{
		{"v1.0.0", true, "1.2.7", "at introduced ⇒ affected"},
		{"v1.2.6", true, "1.2.7", "below fix ⇒ affected"},
		{"v1.2.7", false, "", "at fix ⇒ safe"},
		{"v2.0.0", false, "", "above fix ⇒ safe"},
		{"v0.9.0", false, "", "below introduced ⇒ safe"},
	}
	for _, c := range cases {
		hit, fix := exactAffected(c.ver, adv)
		if hit != c.wantHit || fix != c.wantFix {
			t.Errorf("%s: exactAffected(%q) = (%v,%q), want (%v,%q)",
				c.desc, c.ver, hit, fix, c.wantHit, c.wantFix)
		}
	}
}

func TestExactAffected_NoFixDoesNotGate(t *testing.T) {
	adv := &Advisory{
		Ecosystem: "go", Package: "example.com/x", Kind: KindSecurity,
		Affected: []VersionRange{{Introduced: "0", Fixed: ""}},
	}
	hit, fix := exactAffected("v1.5.0", adv)
	if !hit || fix != "" {
		t.Fatalf("want affected-but-no-fix (true,\"\"), got (%v,%q)", hit, fix)
	}
	// Through Evaluate, a no-fix advisory must NOT mark the dependency unsafe.
	reg := &Registry{Advisories: []Advisory{*adv}}
	dep := Dependency{Ecosystem: "go", Name: "example.com/x", Current: "v1.5.0"}
	got := Evaluate([]Dependency{dep}, reg, false)
	if !got[0].Safe {
		t.Errorf("no-fix advisory must not fail the gate; reason=%q", got[0].Reason)
	}
}

func TestConstraintAffected(t *testing.T) {
	adv := func(fixed string) *Advisory {
		return &Advisory{
			Ecosystem: "python", Package: "demo", Kind: KindSecurity,
			Affected: []VersionRange{{Introduced: "0", Fixed: fixed}},
		}
	}
	cases := []struct {
		spec    string
		fixed   string
		wantHit bool
		desc    string
	}{
		{">=1.0,<2.0", "2.1.0", true, "ceiling locks below the fix ⇒ unsafe"},
		{">=1.0,<2.0", "1.5.0", false, "fix reachable within range ⇒ safe"},
		{">=1.0", "1.5.0", false, "open ceiling can reach the fix ⇒ safe"},
		{">=3.0,<4.0", "2.1.0", false, "range entirely above affected ⇒ safe"},
	}
	for _, c := range cases {
		hit, _ := constraintAffected(c.spec, adv(c.fixed))
		if hit != c.wantHit {
			t.Errorf("%s: constraintAffected(%q, fixed=%s) = %v, want %v",
				c.desc, c.spec, c.fixed, hit, c.wantHit)
		}
	}
}

func TestEvaluate_FlagsRealMatch(t *testing.T) {
	// A synthetic advisory whose fixed boundary sits above the pinned version
	// must drive Safe=false — proves the end-to-end gate path actually fails.
	reg := &Registry{Advisories: []Advisory{{
		ID: "TEST-0001", Ecosystem: "go", Package: "example.com/lib",
		Kind: KindPerformance, Summary: "O(n^2) parse regression.",
		Affected: []VersionRange{{Introduced: "1.0.0", Fixed: "1.4.0"}},
	}}}
	deps := []Dependency{{Ecosystem: "go", Name: "example.com/lib", Current: "v1.3.9"}}
	got := Evaluate(deps, reg, false)
	if got[0].Safe {
		t.Fatal("expected unsafe verdict for affected version")
	}
	if got[0].Advisory == nil || got[0].Advisory.Kind != KindPerformance {
		t.Fatalf("expected performance advisory attached, got %+v", got[0].Advisory)
	}
	if !strings.Contains(got[0].Reason, "1.4.0") {
		t.Errorf("reason should name the fix version, got %q", got[0].Reason)
	}
}

func TestVersionCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v1.2.3", "v1.2.3", 0},
		{"v1.2.3", "v1.2.4", -1},
		{"v1.3.0", "v1.2.9", 1},
		{"v1.2", "v1.2.0", 0},
		{"v2.0.0", "v1.9.9", 1},
		{"v1.0.0-rc1", "v1.0.0", -1}, // pre-release sorts below release
		{"v0.0.0-20250101000000-abc", "v0.0.0-20250620000000-def", -1},
	}
	for _, c := range cases {
		av, _ := parseVersion(c.a)
		bv, _ := parseVersion(c.b)
		if got := cmpVersion(av, bv); got != c.want {
			t.Errorf("cmpVersion(%s,%s)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

// TestDependencyAudit_OSVCanary is the live-integration canary. It exists so a
// green gate can never be confused with a silently-broken OSV integration
// (wrong endpoint, API change, parser regression, network misroute) — the
// failure mode where the gate "checks" nothing and passes everything.
//
// It queries OSV.dev for stable, permanent historical advisories that MUST flag
// a vulnerability-with-fix. It fails ONLY when OSV answers but our code misses a
// known vuln (a real break); it skips — never flakes red — when OSV is simply
// unreachable. Online-only (CI sets DEPAUDIT_ONLINE=1); offline it skips, so the
// broad `go test ./...` stays deterministic.
func TestDependencyAudit_OSVCanary(t *testing.T) {
	if !online() {
		t.Skip("set DEPAUDIT_ONLINE=1 (CI does) to verify the live OSV.dev integration")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	fixtures := []Dependency{
		{Ecosystem: "go", Name: "github.com/dgrijalva/jwt-go", Current: "v3.2.0"}, // GHSA-w73w-5m7g-f7qc
		{Ecosystem: "npm", Name: "lodash", Current: "4.17.11"},                    // GHSA-29mw-wpgm-hmr9
	}

	reachable := 0
	for _, d := range fixtures {
		vulns, queried, err := queryOSV(client, d)
		if err != nil || !queried {
			t.Logf("OSV unreachable for %s %s (%v) — skipping this fixture", d.Ecosystem, d.Name, err)
			continue
		}
		reachable++
		hasFix := false
		for _, v := range vulns {
			if v.Fixed != "" {
				hasFix = true
				break
			}
		}
		if !hasFix {
			t.Errorf("OSV INTEGRATION BROKEN: %s %s@%s returned %d vulns, none with a fix — "+
				"the gate would silently pass known-vulnerable deps", d.Ecosystem, d.Name, d.Current, len(vulns))
			continue
		}
		t.Logf("canary OK: %s %s@%s correctly flagged by live OSV.dev", d.Ecosystem, d.Name, d.Current)
	}
	if reachable == 0 {
		t.Skip("OSV.dev unreachable for all fixtures — integration not verifiable this run (gate degraded to registry-only)")
	}
}

// ---- OSV.dev response parsing (no network) ----------------------------------

func TestParseOSVResponse(t *testing.T) {
	// One fixable vuln, one with no fix, one withdrawn — exercises every branch.
	body := `{"vulns":[
	  {"id":"GO-2024-0001","summary":"bad thing",
	   "affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"1.9.0"},{"fixed":"1.2.0"}]}]}],
	   "references":[{"url":"https://example.com/adv"}]},
	  {"id":"GO-2024-0002","summary":"no fix yet",
	   "affected":[{"ranges":[{"events":[{"introduced":"0"}]}]}]},
	  {"id":"GO-2024-0003","summary":"withdrawn","withdrawn":"2024-01-01T00:00:00Z",
	   "affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}
	]}`
	got, err := parseOSVResponse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 findings (withdrawn dropped), got %d: %+v", len(got), got)
	}
	if got[0].ID != "GO-2024-0001" || got[0].Fixed != "1.2.0" {
		t.Errorf("want lowest fix 1.2.0 for GO-2024-0001, got %q", got[0].Fixed)
	}
	if got[0].Reference != "https://example.com/adv" {
		t.Errorf("want explicit reference URL, got %q", got[0].Reference)
	}
	if got[1].Fixed != "" {
		t.Errorf("GO-2024-0002 should have no fix, got %q", got[1].Fixed)
	}
	if got[1].Reference != "https://osv.dev/vulnerability/GO-2024-0002" {
		t.Errorf("want synthesized osv.dev ref, got %q", got[1].Reference)
	}
}

func TestOSVEcosystemMapping(t *testing.T) {
	for in, want := range map[string]string{"go": "Go", "python": "PyPI", "npm": "npm", "ruby": ""} {
		if got := osvEcosystem(in); got != want {
			t.Errorf("osvEcosystem(%q)=%q want %q", in, got, want)
		}
	}
}

// ---- manifest parser sanity against the real repo files ---------------------

func TestParsersFindKnownDeps(t *testing.T) {
	root, err := RepoRoot()
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	deps, err := CollectDependencies(root)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	want := map[string]string{ // name -> ecosystem we expect to have parsed
		"modernc.org/sqlite":           "go",
		"gopkg.in/yaml.v3":             "go",
		"github.com/fsnotify/fsnotify": "go",
		"langchain":                    "python",
		"typescript":                   "npm",
	}
	have := map[string]string{}
	for _, d := range deps {
		have[d.Name] = d.Ecosystem
	}
	for name, eco := range want {
		if have[name] != eco {
			t.Errorf("expected %s dependency %q to be parsed, got ecosystem %q", eco, name, have[name])
		}
	}
}
