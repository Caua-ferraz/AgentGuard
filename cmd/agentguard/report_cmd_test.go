package main

import (
	"encoding/json"
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
	res.expect(t, 0, `"status": "not_verified"`, "give that key with --key-file")

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

// fakeAuditServer serves GET /v1/audit from entries, a few at a time, the
// way a 1.4 server does (filterTime) or an older one does (not).
type fakeAuditServer struct {
	*httptest.Server
	entries    []audit.Entry
	filterTime bool
	key        string // "" = no key needed
	head       func(w http.ResponseWriter)

	mu       sync.Mutex
	requests []*http.Request
}

func newFakeAuditServer(t *testing.T, filterTime bool, key string, head func(w http.ResponseWriter)) *fakeAuditServer {
	f := &fakeAuditServer{entries: reportEntries(), filterTime: filterTime, key: key, head: head}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeAuditServer) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r)
	f.mu.Unlock()
	if f.key != "" && r.Header.Get("Authorization") != "Bearer "+f.key {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/audit/head"):
		f.head(w)
	case strings.HasSuffix(r.URL.Path, "/audit"):
		q := r.URL.Query()
		var matched []audit.Entry
		for _, e := range f.entries {
			if f.filterTime {
				since, _ := time.Parse(time.RFC3339, q.Get("since"))
				until, _ := time.Parse(time.RFC3339, q.Get("until"))
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

func sealedHead(w http.ResponseWriter) {
	_ = json.NewEncoder(w).Encode(audit.Anchor{SegmentID: "seg1", Seq: 42, Hash: strings.Repeat("a", 64), At: reportDay})
}

func sealingOff(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"error":"audit sealing is off; start the server with --audit-seal (file audit backend only)"}`))
}

func noHeadRoute(w http.ResponseWriter) { http.Error(w, "404 page not found", http.StatusNotFound) }

func TestCLI_ReportFromServer(t *testing.T) {
	cases := []struct {
		name          string
		filterTime    bool
		key           string
		head          func(w http.ResponseWriter)
		extra         []string
		wantStatus    string
		wantOutside   int
		wantAuth      bool
		wantPathStart string
	}{
		{
			name: "a 1.4 server filters by time, pages, and needs the key", filterTime: true, key: "k",
			head: sealedHead, extra: []string{"--api-key", "k"},
			wantStatus: report.IntegrityNotVerified, wantAuth: true, wantPathStart: "/v1/audit?",
		},
		{
			name: "an older server ignores since and until and has no head route", filterTime: false,
			head:       noHeadRoute,
			wantStatus: report.IntegrityUnknown, wantOutside: 2, wantPathStart: "/v1/audit?",
		},
		{
			name: "a server with sealing off, asked for one tenant", filterTime: true,
			head: sealingOff, extra: []string{"--tenant-id", "acme"},
			wantStatus: report.IntegrityNotSealed, wantPathStart: "/v1/t/acme/audit?",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeAuditServer(t, tc.filterTime, tc.key, tc.head)
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
			if r.Source.AuthRequired == nil || *r.Source.AuthRequired != tc.wantAuth {
				t.Errorf("auth required = %v, want %v", r.Source.AuthRequired, tc.wantAuth)
			}
			if r.Policy != nil {
				t.Errorf("policy = %+v; with --url only --policy names one", r.Policy)
			}
			paths := srv.paths()
			if !strings.HasPrefix(paths[0], tc.wantPathStart) {
				t.Errorf("first request %s, want %s…", paths[0], tc.wantPathStart)
			}
			for _, want := range []string{"order=asc", "since=2026-10-01T00%3A00%3A00Z", "until=2026-10-02T00%3A00%3A00Z"} {
				if !strings.Contains(paths[0], want) {
					t.Errorf("first request %s lacks %s", paths[0], want)
				}
			}
			pages := 0
			for _, p := range paths {
				if strings.Contains(p, "offset=") {
					pages++
				}
			}
			if pages < 3 {
				t.Errorf("only %d audit pages fetched: %v", pages, paths)
			}
		})
	}

	srv := newFakeAuditServer(t, true, "k", sealedHead)
	agentguard(t, t.TempDir(), nil, "report", "--url", srv.URL).expect(t, 3, "", "requires an API key")
	agentguard(t, t.TempDir(), nil, "report", "--url", "http://127.0.0.1:1").expect(t, 3, "", "Cannot connect to AgentGuard at http://127.0.0.1:1")
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
