package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"github.com/Caua-ferraz/AgentGuard/pkg/report"
)

var reportDay = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// reportEntries is a day of activity in the period, plus one entry the day
// before and one the day after, which the report must leave out.
func reportEntries() []audit.Entry {
	at := func(h int) time.Time { return reportDay.Add(time.Duration(h) * time.Hour) }
	e := func(ts time.Time, d policy.Decision, rule, id, cmd string) audit.Entry {
		return audit.Entry{
			Timestamp: ts, AgentID: "bot", SessionID: "s1",
			Request: policy.ActionRequest{Scope: "shell", Command: cmd, AgentID: "bot"},
			Result:  policy.CheckResult{Decision: d, Rule: rule, ApprovalID: id},
		}
	}
	return []audit.Entry{
		e(at(-1), policy.Allow, "allow:shell:ls", "", "early"),
		e(at(1), policy.Allow, "allow:shell:ls", "", "ls"),
		e(at(2), policy.Allow, "allow:shell:ls", "", "ls -la"),
		e(at(3), policy.Deny, "deny:shell:rm", "", "rm -rf /"),
		e(at(4), policy.Deny, "", "", "curl evil"),
		e(at(5), policy.RequireApproval, "require_approval:shell:make deploy", "ap_1", "make deploy"),
		e(at(6), policy.Allow, "allow:approved", "ap_1", "make deploy"),
		e(at(7), policy.RequireApproval, "require_approval:shell:make deploy", "ap_2", "make deploy"),
		e(at(8), policy.Allow, "allow:shell:ls", "", "ls /tmp"),
		e(at(25), policy.Allow, "allow:shell:ls", "", "late"),
	}
}

const reportInPeriod = 8 // reportEntries between reportDay and the next day

// writeRotatedLog writes reportEntries to dir/audit.jsonl, sealed with key,
// rotating and compressing every few entries.
func writeRotatedLog(t *testing.T, dir string, key []byte) string {
	t.Helper()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := audit.NewFileLoggerWithOptions(path, audit.FileLoggerOptions{
		Rotation: audit.RotationConfig{MaxSize: 1200, Compress: true},
		Seal:     &audit.SealConfig{Key: key},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range reportEntries() {
		if err := l.Log(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func decodeReport(t *testing.T, raw string) report.Report {
	t.Helper()
	var r report.Report
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("report is not JSON: %v\n%s", err, raw)
	}
	return r
}

var reportPeriodArgs = []string{"--since", "2026-10-01", "--until", "2026-10-02"}

func TestCLI_ReportFromFiles(t *testing.T) {
	dir := t.TempDir()
	key := []byte("report-seal-key")
	keyFile := filepath.Join(dir, "seal.key")
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeRotatedLog(t, dir, key)
	policyFile := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyFile, []byte("version: \"1\"\nname: p\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	args := append([]string{"report", "--audit-log", path, "--key-file", keyFile, "--policy", policyFile, "--output", "json"}, reportPeriodArgs...)
	res := agentguard(t, dir, nil, args...)
	if res.code != 0 {
		t.Fatalf("exit %d\n%s", res.code, res.stderr)
	}
	r := decodeReport(t, res.stdout)
	if r.Activity.Entries != reportInPeriod {
		t.Errorf("entries = %d, want %d", r.Activity.Entries, reportInPeriod)
	}
	if len(r.Source.Files) < 3 {
		t.Errorf("files = %v; the log should have rotated into archives", r.Source.Files)
	}
	if r.Integrity.Status != report.IntegrityIntact || r.Integrity.Head == nil || r.Integrity.Head.Seq != uint64(len(reportEntries())) {
		t.Errorf("integrity = %+v", r.Integrity)
	}
	if r.Integrity.KeyBased == nil || !*r.Integrity.KeyBased {
		t.Error("a keyed log is not reported as key based")
	}
	if r.Policy == nil || r.Policy.Found != "--policy" || len(r.Policy.SHA256) != 64 {
		t.Errorf("policy = %+v", r.Policy)
	}
	if r.Approvals.Requested != 2 || r.Approvals.Approved != 1 || r.Approvals.NoOutcome != 1 {
		t.Errorf("approvals = %+v", r.Approvals)
	}

	// Markdown to a file: stdout says where it went.
	out := filepath.Join(dir, "report.md")
	args = append([]string{"report", "--audit-log", path, "--key-file", keyFile, "--out-file", out}, reportPeriodArgs...)
	agentguard(t, dir, nil, args...).expect(t, 0, "Report written to "+out+" (audit entries in the period: 8; audit log: intact)", "")
	if b, err := os.ReadFile(out); err != nil || !strings.Contains(string(b), "## Control mapping (SOC 2)") {
		t.Errorf("report file: %v\n%s", err, b)
	}

	// Without the key the chain can't be checked: the report still comes,
	// and says so.
	args = append([]string{"report", "--audit-log", path, "--output", "json"}, reportPeriodArgs...)
	res = agentguard(t, dir, nil, args...)
	res.expect(t, 0, `"status": "not_verified"`, "give it with --key-file")
	if r := decodeReport(t, res.stdout); r.Integrity.Verify == nil || !r.Integrity.Verify.HashesUnchecked {
		t.Errorf("without the key the structure should still be checked: %+v", r.Integrity)
	}

	// A changed entry: exit 1, and the report is still written.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"command":"late"`) {
		t.Fatalf("the live file lacks the last entry:\n%s", b)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(b), `"command":"late"`, `"command":"LATE"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(dir, "broken.html")
	args = append([]string{"report", "--audit-log", path, "--key-file", keyFile, "--output", "html", "--out-file", broken}, reportPeriodArgs...)
	agentguard(t, dir, nil, args...).expect(t, 1, "audit log: broken", "failed verification")
	if b, err := os.ReadFile(broken); err != nil || !strings.Contains(string(b), "hash mismatch") {
		t.Errorf("broken report: %v", err)
	}

	// Files that can't be read exit 3.
	agentguard(t, dir, nil, "report", "--audit-log", filepath.Join(dir, "missing.jsonl")).expect(t, 3, "", "can't read the audit log")
	agentguard(t, dir, nil, "report", "--audit-log", path, "--key-file", "nope.key").expect(t, 3, "", "seal key file")
	agentguard(t, dir, nil, "report", "--audit-log", path, "--key-file", keyFile, "--policy", "nope.yaml").expect(t, 3, "", "--policy")
}

// The review's repros: logs whose seal is only claimed, or broken by an
// unsealed line, must not pass the seal checks.
func TestCLI_ReportSealClaims(t *testing.T) {
	key := []byte("report-seal-key")
	unsealedLine, _ := json.Marshal(audit.Entry{Timestamp: reportDay.Add(time.Hour), AgentID: "x", Request: policy.ActionRequest{Scope: "shell", Command: "forged"}})
	write := func(t *testing.T, dir string, seal *audit.SealConfig) string {
		path := filepath.Join(dir, "audit.jsonl")
		l, err := audit.NewFileLoggerWithOptions(path, audit.FileLoggerOptions{Seal: seal})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range reportEntries()[1:4] {
			if err := l.Log(e); err != nil {
				t.Fatal(err)
			}
		}
		_ = l.Close()
		return path
	}
	lines := func(t *testing.T, path string) []string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	}
	save := func(t *testing.T, path string, ls []string) {
		if err := os.WriteFile(path, []byte(strings.Join(ls, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name     string
		build    func(t *testing.T, dir string) string
		withKey  bool
		wantCode int
		want     map[string]string // posture check -> status
	}{
		{
			name: "an unsealed log under a forged keyed header, no key",
			build: func(t *testing.T, dir string) string {
				path := write(t, dir, nil)
				ls := lines(t, path)
				ls[0] = `{"_meta":{"schema_version":2,"created_at":"2026-10-01T00:00:00Z","seal":{"alg":"hmac-sha256","key_id":"` + audit.SealKeyID(key) + `"}}}`
				save(t, path, ls)
				return path
			},
			wantCode: 1,
			want:     map[string]string{"Audit log sealed": "fail", "Seal uses a secret key": "unknown"},
		},
		{
			name: "a keyed log with an unsealed line appended, no key",
			build: func(t *testing.T, dir string) string {
				path := write(t, dir, &audit.SealConfig{Key: key})
				save(t, path, append(lines(t, path), string(unsealedLine)))
				return path
			},
			wantCode: 1,
			want:     map[string]string{"Audit log sealed": "fail", "Entries outside the seal chain": "fail"},
		},
		{
			name:     "an unsealed log given --key-file",
			build:    func(t *testing.T, dir string) string { return write(t, dir, nil) },
			withKey:  true,
			wantCode: 1,
			want:     map[string]string{"Audit log sealed": "fail", "Seal uses a secret key": "warn"},
		},
		{
			name: "a SHA-256 log with an unsealed entry inserted",
			build: func(t *testing.T, dir string) string {
				path := write(t, dir, &audit.SealConfig{})
				ls := lines(t, path)
				save(t, path, append(ls[:2], append([]string{string(unsealedLine)}, ls[2:]...)...))
				return path
			},
			wantCode: 1,
			want:     map[string]string{"Audit log sealed": "fail", "Entries outside the seal chain": "fail"},
		},
		{
			name:     "an untouched keyed log, no key: a claim, not a pass",
			build:    func(t *testing.T, dir string) string { return write(t, dir, &audit.SealConfig{Key: key}) },
			wantCode: 0,
			want:     map[string]string{"Audit log sealed": "warn", "Seal uses a secret key": "unknown", "Entries outside the seal chain": "pass"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := tc.build(t, dir)
			args := append([]string{"report", "--audit-log", path, "--output", "json"}, reportPeriodArgs...)
			if tc.withKey {
				keyFile := filepath.Join(dir, "seal.key")
				if err := os.WriteFile(keyFile, key, 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--key-file", keyFile)
			}
			res := agentguard(t, dir, nil, args...)
			if res.code != tc.wantCode {
				t.Fatalf("exit %d, want %d\n%s", res.code, tc.wantCode, res.stderr)
			}
			r := decodeReport(t, res.stdout)
			got := map[string]string{}
			for _, c := range r.Posture {
				got[c.Name] = c.Status
			}
			for name, want := range tc.want {
				if got[name] != want {
					t.Errorf("%s = %q, want %q (integrity %s: %s)", name, got[name], want, r.Integrity.Status, r.Integrity.Summary)
				}
			}
		})
	}
}

// fakeAuditServer serves GET /v1/audit from a live file of entries, a few at
// a time, the way a 1.4 server does (filterTime) or an older one does (not).
type fakeAuditServer struct {
	*httptest.Server
	filterTime bool
	key        string // "" = no key needed
	head       func(w http.ResponseWriter, segment string)
	// redirectNoAuth sends a request without the key to a login page
	// that answers 200, like a reverse proxy with single sign-on.
	redirectNoAuth bool
	// garbage answers every page with [{}], whatever is asked.
	garbage bool
	// After rotateAfter pages, the live file rotates: rotated becomes the
	// whole live file and the segment changes, as on a file backend.
	rotateAfter int
	rotated     []audit.Entry

	mu       sync.Mutex
	entries  []audit.Entry
	segment  string
	pages    int
	requests []*http.Request
}

func newFakeAuditServer(t *testing.T, f *fakeAuditServer) *fakeAuditServer {
	if f.entries == nil {
		f.entries = reportEntries()
	}
	f.segment = "seg1"
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeAuditServer) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r)
	if r.URL.Path == "/login" {
		_, _ = w.Write([]byte("<html>sign in</html>"))
		return
	}
	if f.key != "" && r.Header.Get("Authorization") != "Bearer "+f.key {
		if f.redirectNoAuth {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/audit/head"):
		f.head(w, f.segment)
	case strings.HasSuffix(r.URL.Path, "/audit"):
		if f.garbage {
			_, _ = w.Write([]byte(`[{}]`))
			return
		}
		q := r.URL.Query()
		var matched []audit.Entry
		for _, e := range f.entries {
			if f.filterTime {
				since, _ := time.Parse(time.RFC3339Nano, q.Get("since"))
				until, _ := time.Parse(time.RFC3339Nano, q.Get("until"))
				if e.Timestamp.Before(since) || !e.Timestamp.Before(until) {
					continue
				}
			}
			matched = append(matched, e)
		}
		// A server clamps the limit to its maximum; 3 forces paging.
		limit, _ := strconv.Atoi(q.Get("limit"))
		limit = min(limit, 3)
		offset, _ := strconv.Atoi(q.Get("offset"))
		page := []audit.Entry{}
		if offset < len(matched) {
			page = matched[offset:min(offset+limit, len(matched))]
		}
		_ = json.NewEncoder(w).Encode(page)
		f.pages++
		if f.rotateAfter > 0 && f.pages == f.rotateAfter {
			f.entries, f.segment = f.rotated, "seg2"
		}
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeAuditServer) paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var p []string
	for _, r := range f.requests {
		p = append(p, r.URL.Path+"?"+r.URL.RawQuery)
	}
	return p
}

// auditPaths are the GET /v1/audit page requests, in order.
func (f *fakeAuditServer) auditPaths() []string {
	var p []string
	for _, path := range f.paths() {
		if strings.Contains(path, "/audit?") && strings.Contains(path, "offset=") {
			p = append(p, path)
		}
	}
	return p
}

func sealedHead(w http.ResponseWriter, segment string) {
	_ = json.NewEncoder(w).Encode(audit.Anchor{SegmentID: segment, Seq: 42, Hash: strings.Repeat("a", 64), At: reportDay})
}

func sealingOff(w http.ResponseWriter, _ string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"error":"audit sealing is off; start the server with --audit-seal (file audit backend only)"}`))
}

func noHeadRoute(w http.ResponseWriter, _ string) {
	http.Error(w, "404 page not found", http.StatusNotFound)
}

func TestCLI_ReportFromServer(t *testing.T) {
	cases := []struct {
		name          string
		srv           *fakeAuditServer
		extra         []string
		wantStatus    string
		wantOutside   int
		wantAuth      string // "yes", "no" or "unknown"
		wantPathStart string
	}{
		{
			name:  "a 1.4 server filters by time, pages, and needs the key",
			srv:   &fakeAuditServer{filterTime: true, key: "k", head: sealedHead},
			extra: []string{"--api-key", "k"}, wantStatus: report.IntegrityNotVerified, wantAuth: "yes", wantPathStart: "/v1/audit?",
		},
		{
			name:       "an older server ignores since and until and has no head route",
			srv:        &fakeAuditServer{head: noHeadRoute},
			wantStatus: report.IntegrityUnknown, wantOutside: 2, wantAuth: "no", wantPathStart: "/v1/audit?",
		},
		{
			name:  "a server with sealing off, asked for one tenant",
			srv:   &fakeAuditServer{filterTime: true, head: sealingOff},
			extra: []string{"--tenant-id", "acme"}, wantStatus: report.IntegrityNotSealed, wantAuth: "no", wantPathStart: "/v1/t/acme/audit?",
		},
		{
			// A 302 to a login page that answers 200 used to count as an
			// open audit API.
			name:  "a probe redirected to a login page proves nothing",
			srv:   &fakeAuditServer{filterTime: true, key: "k", head: sealedHead, redirectNoAuth: true},
			extra: []string{"--api-key", "k"}, wantStatus: report.IntegrityNotVerified, wantAuth: "unknown", wantPathStart: "/v1/audit?",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeAuditServer(t, tc.srv)
			args := append([]string{"report", "--url", srv.URL, "--output", "json"}, reportPeriodArgs...)
			res := agentguard(t, t.TempDir(), nil, append(args, tc.extra...)...)
			if res.code != 0 {
				t.Fatalf("exit %d\n%s", res.code, res.stderr)
			}
			r := decodeReport(t, res.stdout)
			if r.Activity.Entries != reportInPeriod {
				t.Errorf("entries = %d, want %d", r.Activity.Entries, reportInPeriod)
			}
			if r.Source.OutsidePeriod != tc.wantOutside {
				t.Errorf("outside period = %d, want %d", r.Source.OutsidePeriod, tc.wantOutside)
			}
			if r.Integrity.Status != tc.wantStatus {
				t.Errorf("integrity = %q (%s), want %q", r.Integrity.Status, r.Integrity.Summary, tc.wantStatus)
			}
			auth := "unknown"
			if r.Source.AuthRequired != nil {
				auth = map[bool]string{true: "yes", false: "no"}[*r.Source.AuthRequired]
			}
			if auth != tc.wantAuth {
				t.Errorf("auth required = %s, want %s", auth, tc.wantAuth)
			}
			if r.Policy != nil {
				t.Errorf("policy = %+v; with --url only --policy names one", r.Policy)
			}
			if len(r.Source.Warnings) != 0 {
				t.Errorf("warnings = %v", r.Source.Warnings)
			}
			pages := srv.auditPaths()
			if len(pages) < 3 {
				t.Fatalf("only %d audit pages fetched: %v", len(pages), srv.paths())
			}
			if !strings.HasPrefix(pages[0], tc.wantPathStart) {
				t.Errorf("first page %s, want %s…", pages[0], tc.wantPathStart)
			}
			for _, want := range []string{"order=asc", "since=2026-10-01T00%3A00%3A00Z", "until=2026-10-02T00%3A00%3A00Z"} {
				if !strings.Contains(pages[0], want) {
					t.Errorf("first page %s lacks %s", pages[0], want)
				}
			}
		})
	}

	srv := newFakeAuditServer(t, &fakeAuditServer{filterTime: true, key: "k", head: sealedHead})
	agentguard(t, t.TempDir(), nil, "report", "--url", srv.URL).expect(t, 3, "", "requires an API key")
	agentguard(t, t.TempDir(), nil, "report", "--url", "http://127.0.0.1:1").expect(t, 3, "", "Cannot connect to AgentGuard at http://127.0.0.1:1")
}

// A server that answers every page with the same thing used to be paged
// forever (105k requests in 3 seconds). It now stops at the second page.
func TestCLI_ReportServerThatRepeatsItself(t *testing.T) {
	srv := newFakeAuditServer(t, &fakeAuditServer{garbage: true, head: noHeadRoute})
	args := append([]string{"report", "--url", srv.URL}, reportPeriodArgs...)
	agentguard(t, t.TempDir(), nil, args...).expect(t, 3, "", "sends the same entries for every offset")
	if n := len(srv.auditPaths()); n > 5 {
		t.Errorf("%d page requests before giving up", n)
	}
}

// The live file rotates after two pages. Offset paging then read past the
// end of the new, short file and stopped, losing the entries written after
// the rotation, with no warning. Paging by time picks them up, and the
// changed seal head segment puts a warning in the report.
func TestCLI_ReportServerRotatesWhileReading(t *testing.T) {
	var after []audit.Entry
	for i := 0; i < 5; i++ {
		e := reportEntries()[1]
		e.Timestamp = reportDay.Add(20*time.Hour + time.Duration(i)*time.Minute)
		e.Request.Command = fmt.Sprintf("after rotation %d", i)
		after = append(after, e)
	}
	srv := newFakeAuditServer(t, &fakeAuditServer{filterTime: true, head: sealedHead, rotateAfter: 2, rotated: after})
	args := append([]string{"report", "--url", srv.URL, "--output", "json"}, reportPeriodArgs...)
	res := agentguard(t, t.TempDir(), nil, args...)
	if res.code != 0 {
		t.Fatalf("exit %d\n%s", res.code, res.stderr)
	}
	r := decodeReport(t, res.stdout)
	// Five entries before the rotation (two pages of three; the second
	// restarts at the last entry of the first, read once), then the five
	// written after it. The entries left in the old file are gone from
	// what the server can answer: that is what the warning is for.
	if r.Activity.Entries != 5+5 {
		t.Errorf("entries = %d, want 10", r.Activity.Entries)
	}
	if len(r.Source.Warnings) != 1 || !strings.Contains(r.Source.Warnings[0], "rotated while the report read it") {
		t.Errorf("warnings = %v", r.Source.Warnings)
	}
	if !strings.Contains(strings.Join(r.Limits, "\n"), "The entries may be incomplete") {
		t.Errorf("limits miss the rotation: %v", r.Limits)
	}
}

// A burst of entries a few milliseconds apart, more than a page of them,
// some written out of time order: paging by time must neither loop on the
// burst nor drop or repeat an entry.
func TestCLI_ReportServerBurst(t *testing.T) {
	var burst []audit.Entry
	for i := 0; i < 14; i++ {
		e := reportEntries()[1]
		ms := i
		if i%4 == 3 {
			ms = i - 2 // written after an entry stamped later
		}
		e.Timestamp = reportDay.Add(time.Hour + time.Duration(ms)*time.Millisecond)
		e.SessionID = fmt.Sprintf("s%d", i)
		burst = append(burst, e)
	}
	srv := newFakeAuditServer(t, &fakeAuditServer{filterTime: true, head: sealedHead, entries: burst})
	args := append([]string{"report", "--url", srv.URL, "--output", "json"}, reportPeriodArgs...)
	res := agentguard(t, t.TempDir(), nil, args...)
	if res.code != 0 {
		t.Fatalf("exit %d\n%s", res.code, res.stderr)
	}
	if r := decodeReport(t, res.stdout); r.Activity.Entries != 14 || r.Activity.SessionsSeen.Count != 14 {
		t.Errorf("entries = %d, sessions = %d; want 14 each", r.Activity.Entries, r.Activity.SessionsSeen.Count)
	}
}

// A user name and password in --url would be written into the report and
// sent as Basic auth on the probe that is meant to carry no credentials.
func TestCLI_ReportRejectsCredentialsInURL(t *testing.T) {
	res := agentguard(t, t.TempDir(), nil, "report", "--url", "http://admin:hunter2@guard.internal:8080")
	res.expect(t, 2, "", "--url must not hold a user name or password")
	if strings.Contains(res.stderr, "hunter2") {
		t.Errorf("the password is echoed: %s", res.stderr)
	}
	res = agentguard(t, t.TempDir(), nil, "report", "--url", "ftp://admin:hunter2@guard.internal")
	if res.code != 2 || strings.Contains(res.stderr, "hunter2") {
		t.Errorf("exit %d, stderr %s", res.code, res.stderr)
	}
}

func TestCLI_ReportMistakes(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"report", "extra"}, `unexpected argument "extra"`},
		{[]string{"report", "--output", "pdf"}, "--output must be md, json or html"},
		{[]string{"report", "--url", "http://x", "--audit-log", "a.jsonl"}, "not both"},
		{[]string{"report", "--url", "http://x", "--key-file", "k"}, "--key-file is for the audit log files"},
		{[]string{"report", "--api-key", "k"}, "go with --url"},
		{[]string{"report", "--url", "localhost:8080"}, "include the scheme"},
		{[]string{"report", "--since", "yesterday"}, `--since: "yesterday" is not a time`},
		{[]string{"report", "--since", "2026-10-02", "--until", "2026-10-01"}, "must be before --until"},
		{[]string{"report", "--sinse", "1h"}, "did you mean --since?"},
	}
	for _, tc := range cases {
		agentguard(t, dir, nil, tc.args...).expect(t, 2, "", tc.want)
	}
}

func TestParseReportTime(t *testing.T) {
	ref := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		in      string
		want    time.Time
		wantErr bool
	}{
		{in: "2026-10-01T09:30:00Z", want: time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC)},
		{in: "2026-10-01T09:30:00+02:00", want: time.Date(2026, 10, 1, 7, 30, 0, 0, time.UTC)},
		{in: "2026-10-01", want: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)},
		{in: "24h", want: ref.Add(-24 * time.Hour)},
		{in: "90m", want: ref.Add(-90 * time.Minute)},
		{in: "7d", want: ref.Add(-7 * 24 * time.Hour)},
		{in: "1d12h", want: ref.Add(-36 * time.Hour)},
		{in: "0d", want: ref},
		{in: "-1h", wantErr: true},
		{in: "d", wantErr: true},
		{in: "7days", wantErr: true},
		{in: "2026-13-01", wantErr: true},
	}
	for _, tc := range cases {
		got, err := parseReportTime(tc.in, ref)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseReportTime(%q) = %v, want an error", tc.in, got)
			}
			continue
		}
		if err != nil || !got.Equal(tc.want) {
			t.Errorf("parseReportTime(%q) = %v, %v; want %v", tc.in, got, err, tc.want)
		}
	}
}

func TestReportPeriodDefaults(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	p, err := reportPeriod("", "", now)
	if err != nil || !p.Until.Equal(now) || !p.Since.Equal(now.Add(-24*time.Hour)) {
		t.Errorf("default period = %+v, %v; want the 24h before now", p, err)
	}
	// A duration --since counts back from --until, not from now.
	p, err = reportPeriod("7d", "2026-10-01", now)
	if err != nil || !p.Since.Equal(time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("period = %+v, %v", p, err)
	}
}
