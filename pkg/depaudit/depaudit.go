// Package depaudit is AgentGuard's dependency safety auditor.
//
// It answers one question across every ecosystem the project ships
// (Go module, Python SDK, TypeScript SDK): is each dependency on a *safe*
// version? "Safe" is defined deliberately loosely so the gate does not become
// busywork that fails the build every time an upstream cuts a routine release:
//
//	A dependency is SAFE if it is on the latest version, OR it is behind the
//	latest version but the gap introduces no known security vulnerability and
//	no known performance regression. Being merely "behind" is fine.
//
//	A dependency is UNSAFE only when its current version is hit by a known
//	security vulnerability or a known performance regression that an available
//	upgrade would resolve. That — and only that — fails the gate.
//
// The list of "known" issues lives in advisories.json (embedded below), a
// curated registry maintained from govulncheck / pip-audit / npm audit output
// and from upstream release notes / benchmark evidence for performance
// regressions (for which no automated database exists). See advisories.md.
//
// This package is intentionally stdlib-only and has zero production import
// surface: it is a CI/dev tool, not part of the <3ms hot path.
package depaudit

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed advisories.json
var advisoriesJSON []byte

// Kind classifies why an upgrade matters. Only these two kinds fail the gate.
type Kind string

const (
	KindSecurity    Kind = "security"
	KindPerformance Kind = "performance"
)

// VersionRange is an OSV-style affected interval: [Introduced, Fixed).
// Introduced "0" (or "") means "from the beginning". Fixed "" means no fixed
// release exists yet — in that case an upgrade would NOT resolve the issue, so
// per the contract it does not fail the gate (it is surfaced as a note).
type VersionRange struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

// Advisory is one known security or performance issue affecting a package.
type Advisory struct {
	ID        string         `json:"id"`
	Ecosystem string         `json:"ecosystem"` // go | python | npm
	Package   string         `json:"package"`
	Kind      Kind           `json:"kind"`
	Summary   string         `json:"summary"`
	Reference string         `json:"reference"`
	Affected  []VersionRange `json:"affected"`
}

// Registry is the parsed advisories.json.
type Registry struct {
	Advisories []Advisory `json:"advisories"`
}

// Dependency is one audited package across any ecosystem.
type Dependency struct {
	Ecosystem string // go | python | npm
	Name      string
	// Current is an exact version (Go pins, npm lockfile-resolved) or a PEP 508 /
	// npm version constraint when no exact version is available (Python extras).
	Current    string
	Constraint bool   // true when Current is a range, not an exact version
	Scope      string // direct | indirect | dev | optional:<extra> | build
}

// Finding is the per-dependency audit verdict.
type Finding struct {
	Dependency
	Latest     string    // best-effort; populated only when online lookup is enabled
	Safe       bool      // false ⇒ fails the gate
	Reason     string    // human-readable explanation for the report
	Advisory   *Advisory // the matched registry advisory when Safe is false
	Source     string    // what flagged it: "registry" | "osv.dev"
	Reference  string    // advisory URL for the report
	OSVChecked bool      // true ⇒ current version was cross-checked live against OSV.dev
	note       string    // non-gating note (e.g. a known issue with no fix yet)
}

// Options controls how Evaluate runs.
type Options struct {
	// FetchLatest populates Finding.Latest via the ecosystem registries
	// (informational only — never affects the Safe verdict).
	FetchLatest bool
	// CheckOSV cross-checks each exact-version dependency against the live
	// OSV.dev database. This is what makes "behind but safe" a *verified*
	// statement about the gap's security content rather than an assumption.
	CheckOSV bool
}

// LoadRegistry parses the embedded advisory registry.
func LoadRegistry() (*Registry, error) {
	var r Registry
	if err := json.Unmarshal(advisoriesJSON, &r); err != nil {
		return nil, fmt.Errorf("parse advisories.json: %w", err)
	}
	return &r, nil
}

// RepoRoot walks up from the current working directory to the module root
// (the directory holding go.mod). Tests run in the package directory, so the
// manifests we audit live a couple of levels up.
func RepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found walking up from working directory")
		}
		dir = parent
	}
}

// CollectDependencies parses every manifest under root into a flat list.
func CollectDependencies(root string) ([]Dependency, error) {
	var deps []Dependency

	goDeps, err := parseGoMod(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, err
	}
	deps = append(deps, goDeps...)

	pyDeps, err := parsePyproject(filepath.Join(root, "plugins", "python", "pyproject.toml"))
	if err != nil {
		return nil, err
	}
	deps = append(deps, pyDeps...)

	npmDeps, err := parsePackageJSON(
		filepath.Join(root, "plugins", "typescript", "package.json"),
		filepath.Join(root, "plugins", "typescript", "package-lock.json"),
	)
	if err != nil {
		return nil, err
	}
	deps = append(deps, npmDeps...)

	return deps, nil
}

// Evaluate is the backward-compatible entry point: registry-only verdict with
// an optional best-effort latest-version lookup for the report.
func Evaluate(deps []Dependency, reg *Registry, fetchLatest bool) []Finding {
	return EvaluateWithOptions(deps, reg, Options{FetchLatest: fetchLatest})
}

// EvaluateWithOptions produces a Finding for each dependency. The verdict is
// the union of two sources:
//
//  1. The curated registry (always, offline) — covers performance regressions,
//     which no database tracks, plus any manually-pinned advisory.
//  2. OSV.dev (when Options.CheckOSV, online) — the authoritative, always-current
//     security database, queried per exact pinned version across Go/PyPI/npm.
//
// OSV only ever *adds* findings; a network failure degrades to registry-only
// without erroring, so the gate cannot flake red on an OSV outage. Latest is
// fetched only when Options.FetchLatest and never affects Safe.
func EvaluateWithOptions(deps []Dependency, reg *Registry, opts Options) []Finding {
	var client *http.Client
	if opts.FetchLatest || opts.CheckOSV {
		client = &http.Client{Timeout: 8 * time.Second}
	}

	out := make([]Finding, 0, len(deps))
	for _, d := range deps {
		f := Finding{Dependency: d, Safe: true}

		// 1. Curated registry (offline; security + performance).
		for i := range reg.Advisories {
			a := &reg.Advisories[i]
			if !strings.EqualFold(a.Ecosystem, d.Ecosystem) || a.Package != d.Name {
				continue
			}
			affected, fix := matchAdvisory(d, a)
			if !affected {
				continue
			}
			if fix == "" {
				// Known issue with no fix: an upgrade cannot resolve it ⇒ note,
				// do not gate.
				if f.note == "" {
					f.note = fmt.Sprintf("known %s issue %s with no fixed release yet", a.Kind, a.ID)
				}
				continue
			}
			f.Safe = false
			f.Advisory = a
			f.Source = "registry"
			f.Reference = a.Reference
			f.Reason = fmt.Sprintf("%s %s — %s Fixed in %s; upgrade resolves it.", a.Kind, a.ID, a.Summary, fix)
			break
		}

		// 2. Live OSV.dev cross-check (authoritative security). Exact versions
		//    only — see queryOSV. Adds findings; never clears a registry hit.
		if opts.CheckOSV {
			if vulns, queried, err := queryOSV(client, d); queried && err == nil {
				f.OSVChecked = true
				for _, v := range vulns {
					if v.Fixed == "" {
						if f.note == "" {
							f.note = fmt.Sprintf("OSV %s affects this version but has no fixed release yet", v.ID)
						}
						continue
					}
					if f.Safe { // not already flagged by the registry
						f.Safe = false
						f.Source = "osv.dev"
						f.Reference = v.Reference
						f.Reason = fmt.Sprintf("security %s — %s Fixed in %s; upgrade resolves it (verified live via OSV.dev).",
							v.ID, summaryOr(v.Summary), v.Fixed)
					}
				}
			}
		}

		if opts.FetchLatest {
			f.Latest = fetchLatestVersion(client, d)
		}
		if f.Safe {
			f.Reason = safeReason(d, f.Latest, f.OSVChecked)
			if f.note != "" {
				f.Reason += " (" + f.note + ")"
			}
		}
		out = append(out, f)
	}
	return out
}

func summaryOr(s string) string {
	if strings.TrimSpace(s) == "" {
		return "known vulnerability."
	}
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

// matchAdvisory reports whether a dependency is affected by an advisory, and if
// so, the version that fixes it. Exact-version deps use point containment;
// constraint deps (Python ranges) are unsafe only when the allowed range
// overlaps the vulnerable interval AND cannot reach the fix — i.e. the policy
// locks the project below a security/perf fix. A merely-old floor whose range
// also permits a safe version is NOT flagged.
func matchAdvisory(d Dependency, a *Advisory) (affected bool, fix string) {
	if d.Constraint {
		return constraintAffected(d.Current, a)
	}
	return exactAffected(d.Current, a)
}

func exactAffected(cur string, a *Advisory) (bool, string) {
	v, ok := parseVersion(cur)
	if !ok {
		return false, ""
	}
	for _, r := range a.Affected {
		intro, _ := parseVersion(firstNonEmpty(r.Introduced, "0"))
		if r.Fixed == "" {
			if cmpVersion(v, intro) >= 0 {
				return true, "" // affected, no fix available
			}
			continue
		}
		fix, ok := parseVersion(r.Fixed)
		if !ok {
			continue
		}
		if cmpVersion(v, intro) >= 0 && cmpVersion(v, fix) < 0 {
			return true, r.Fixed
		}
	}
	return false, ""
}

func constraintAffected(spec string, a *Advisory) (bool, string) {
	iv := parseConstraint(spec)
	for _, r := range a.Affected {
		if r.Fixed == "" {
			continue // no upgrade can resolve it ⇒ not a gate failure
		}
		intro, _ := parseVersion(firstNonEmpty(r.Introduced, "0"))
		fix, ok := parseVersion(r.Fixed)
		if !ok {
			continue
		}
		// Affected interval [intro, fix) overlaps allowed [floor, ceil)?
		lo := maxVersion(intro, iv.floor)
		overlap := cmpVersion(lo, fix) < 0 && iv.below(lo)
		// Can the constraint install the fix (is fix inside the allowed range)?
		fixReachable := cmpVersion(fix, iv.floor) >= 0 && iv.below(fix)
		if overlap && !fixReachable {
			return true, r.Fixed
		}
	}
	return false, ""
}

// ---- version handling -------------------------------------------------------

type version struct {
	nums []int
	pre  string // pre-release / Go pseudo-version suffix; "" means a clean release
}

var trailingComment = regexp.MustCompile(`\s+//.*$`)

func parseVersion(s string) (version, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "=")
	if s == "" || s == "0" {
		return version{nums: []int{0}}, true
	}
	if i := strings.IndexByte(s, '+'); i >= 0 { // strip build metadata
		s = s[:i]
	}
	pre := ""
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return version{}, false // wildcard / non-numeric ⇒ uncomparable
		}
		nums = append(nums, n)
	}
	return version{nums: nums, pre: pre}, true
}

func cmpVersion(a, b version) int {
	n := len(a.nums)
	if len(b.nums) > n {
		n = len(b.nums)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(a.nums) {
			x = a.nums[i]
		}
		if i < len(b.nums) {
			y = b.nums[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	// Equal numeric core: a clean release outranks a pre-release/pseudo of the
	// same core; two pre-releases compare lexically (Go pseudo timestamps sort
	// correctly because they are fixed-width and lead the suffix).
	switch {
	case a.pre == "" && b.pre == "":
		return 0
	case a.pre == "":
		return 1
	case b.pre == "":
		return -1
	case a.pre < b.pre:
		return -1
	case a.pre > b.pre:
		return 1
	default:
		return 0
	}
}

func maxVersion(a, b version) version {
	if cmpVersion(a, b) >= 0 {
		return a
	}
	return b
}

// interval models a PEP 508 / npm constraint as [floor, ceil) with an optional
// inclusive upper bound (<=).
type interval struct {
	floor        version
	ceil         version
	hasCeil      bool
	ceilInclusiv bool
}

// below reports whether v is within the upper bound of the interval.
func (iv interval) below(v version) bool {
	if !iv.hasCeil {
		return true
	}
	c := cmpVersion(v, iv.ceil)
	if iv.ceilInclusiv {
		return c <= 0
	}
	return c < 0
}

func parseConstraint(spec string) interval {
	zero, _ := parseVersion("0")
	iv := interval{floor: zero}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(part), "^~"))
		switch {
		case strings.HasPrefix(part, ">="):
			if v, ok := parseVersion(part[2:]); ok {
				iv.floor = maxVersion(iv.floor, v)
			}
		case strings.HasPrefix(part, "<="):
			if v, ok := parseVersion(part[2:]); ok {
				iv.ceil, iv.hasCeil, iv.ceilInclusiv = v, true, true
			}
		case strings.HasPrefix(part, "=="):
			if v, ok := parseVersion(part[2:]); ok {
				iv.floor = v
				iv.ceil, iv.hasCeil, iv.ceilInclusiv = v, true, true
			}
		case strings.HasPrefix(part, ">"):
			if v, ok := parseVersion(part[1:]); ok {
				iv.floor = maxVersion(iv.floor, v)
			}
		case strings.HasPrefix(part, "<"):
			if v, ok := parseVersion(part[1:]); ok {
				iv.ceil, iv.hasCeil, iv.ceilInclusiv = v, true, false
			}
		}
	}
	return iv
}

// ---- manifest parsers -------------------------------------------------------

func parseGoMod(path string) ([]Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open go.mod: %w", err)
	}
	defer f.Close()

	var deps []Dependency
	inRequire := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "//"):
			continue
		case strings.HasPrefix(line, "require ("):
			inRequire = true
			continue
		case inRequire && line == ")":
			inRequire = false
			continue
		}
		spec := ""
		if inRequire {
			spec = line
		} else if strings.HasPrefix(line, "require ") {
			spec = strings.TrimPrefix(line, "require ")
		} else {
			continue
		}
		indirect := strings.Contains(spec, "// indirect")
		spec = trailingComment.ReplaceAllString(spec, "")
		fields := strings.Fields(spec)
		if len(fields) < 2 {
			continue
		}
		scope := "direct"
		if indirect {
			scope = "indirect"
		}
		deps = append(deps, Dependency{
			Ecosystem: "go",
			Name:      fields[0],
			Current:   fields[1],
			Scope:     scope,
		})
	}
	return deps, sc.Err()
}

var quoted = regexp.MustCompile(`"([^"]+)"`)
var pyName = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)`)
var extraKey = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9_-]*)\s*=\s*\[`)

func parsePyproject(path string) ([]Dependency, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pyproject.toml: %w", err)
	}
	var deps []Dependency
	seen := map[string]bool{}
	section, extra := "", ""
	for _, ln := range strings.Split(string(raw), "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "#") {
			continue // TOML comment — never a dependency, even mid-array
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = strings.Trim(t, "[]")
			extra = ""
			continue
		}
		switch section {
		case "project.optional-dependencies":
			if m := extraKey.FindStringSubmatch(t); m != nil {
				extra = m[1]
			}
		case "build-system":
			if !strings.HasPrefix(t, "requires") {
				continue // ignore build-backend etc.
			}
		default:
			continue
		}
		for _, m := range quoted.FindAllStringSubmatch(t, -1) {
			name, spec, ok := parseRequirement(m[1])
			if !ok || name == "agentguardproxy" { // skip self-referential extras
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			scope := "build"
			if section == "project.optional-dependencies" {
				scope = "optional:" + extra
			}
			deps = append(deps, Dependency{
				Ecosystem:  "python",
				Name:       name,
				Current:    firstNonEmpty(spec, "*"),
				Constraint: true,
				Scope:      scope,
			})
		}
	}
	return deps, nil
}

func parseRequirement(s string) (name, spec string, ok bool) {
	s = strings.TrimSpace(s)
	m := pyName.FindString(s)
	if m == "" {
		return "", "", false
	}
	rest := strings.TrimSpace(s[len(m):])
	if strings.HasPrefix(rest, "[") { // drop extras marker, keep specifier
		if i := strings.IndexByte(rest, ']'); i >= 0 {
			rest = strings.TrimSpace(rest[i+1:])
		}
	}
	// Drop environment markers (";" onward) — not relevant to version safety.
	if i := strings.IndexByte(rest, ';'); i >= 0 {
		rest = strings.TrimSpace(rest[:i])
	}
	return m, rest, true
}

func parsePackageJSON(pkgPath, lockPath string) ([]Dependency, error) {
	raw, err := os.ReadFile(pkgPath)
	if err != nil {
		return nil, fmt.Errorf("read package.json: %w", err)
	}
	var pj struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(raw, &pj); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}

	resolved := map[string]string{}
	if lr, err := os.ReadFile(lockPath); err == nil {
		var lock struct {
			Packages map[string]struct {
				Version string `json:"version"`
			} `json:"packages"`
		}
		if json.Unmarshal(lr, &lock) == nil {
			for k, v := range lock.Packages {
				if !strings.HasPrefix(k, "node_modules/") {
					continue
				}
				name := strings.TrimPrefix(k, "node_modules/")
				if strings.Contains(name, "/node_modules/") {
					continue // nested (transitive) — top-level resolution only
				}
				resolved[name] = v.Version
			}
		}
	}

	var deps []Dependency
	add := func(m map[string]string, scope string) {
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			cur, constraint := m[name], true
			if r, ok := resolved[name]; ok && r != "" {
				cur, constraint = r, false
			}
			deps = append(deps, Dependency{
				Ecosystem:  "npm",
				Name:       name,
				Current:    cur,
				Constraint: constraint,
				Scope:      scope,
			})
		}
	}
	add(pj.Dependencies, "direct")
	add(pj.DevDependencies, "dev")
	return deps, nil
}

// ---- online latest-version lookup (best effort) -----------------------------

func fetchLatestVersion(client *http.Client, d Dependency) string {
	var url string
	switch d.Ecosystem {
	case "go":
		url = "https://proxy.golang.org/" + escapeGoModule(d.Name) + "/@latest"
	case "python":
		url = "https://pypi.org/pypi/" + d.Name + "/json"
	case "npm":
		url = "https://registry.npmjs.org/" + d.Name
	default:
		return ""
	}
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	dec := json.NewDecoder(resp.Body)
	switch d.Ecosystem {
	case "go":
		var v struct {
			Version string `json:"Version"`
		}
		if dec.Decode(&v) == nil {
			return v.Version
		}
	case "python":
		var v struct {
			Info struct {
				Version string `json:"version"`
			} `json:"info"`
		}
		if dec.Decode(&v) == nil {
			return v.Info.Version
		}
	case "npm":
		var v struct {
			DistTags struct {
				Latest string `json:"latest"`
			} `json:"dist-tags"`
		}
		if dec.Decode(&v) == nil {
			return v.DistTags.Latest
		}
	}
	return ""
}

// escapeGoModule applies the Go module proxy's case-encoding (uppercase letters
// become "!" + lowercase) so mixed-case module paths resolve.
func escapeGoModule(path string) string {
	var b strings.Builder
	for _, r := range path {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func safeReason(d Dependency, latest string, osvChecked bool) string {
	// sec describes how thoroughly the security dimension was checked.
	sec := "no known advisory in the registry"
	if osvChecked {
		sec = "no known vulnerability (verified live via OSV.dev) and no performance regression in the registry"
	} else {
		sec = "no known security or performance advisory in the registry"
	}

	if d.Constraint {
		if latest == "" {
			return "allowed range carries " + sec
		}
		return fmt.Sprintf("constraint permits the latest (%s); %s", latest, sec)
	}
	if latest == "" {
		return "pinned version has " + sec
	}
	cur, ok := parseVersion(d.Current)
	lv, ok2 := parseVersion(latest)
	if ok && ok2 && cmpVersion(cur, lv) >= 0 {
		return "on the latest version; " + sec
	}
	return fmt.Sprintf("behind latest (%s) but the gap has %s; safe to defer", latest, sec)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
