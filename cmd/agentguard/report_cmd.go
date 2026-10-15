package main

// report_cmd.go implements `agentguard report`: a compliance evidence
// report for a period, read from the audit log files (and verified with
// the audit verify code) or from a running server. The numbers and the
// renderers live in pkg/report; this file reads the log and picks the exit
// status.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Caua-ferraz/AgentGuard/cmd/internal/buildinfo"
	"github.com/Caua-ferraz/AgentGuard/internal/clihelp"
	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/report"
)

// Exit statuses of `agentguard report` (2 is exitUsage). They match
// `audit verify`: 1 when the log fails verification, 3 when it can't be
// read.
const (
	reportExitTampered = 1
	reportExitIO       = 3
)

// defaultReportSpan is how far back --since reaches when it isn't given.
const defaultReportSpan = 24 * time.Hour

var reportFlagGroups = []clihelp.Group{
	{Title: "Period", Names: []string{"since", "until"}},
	{Title: "Read the audit log files (the default)", Names: []string{"audit-log", "key-file"}},
	{Title: "Or ask a running server", Names: []string{"url", "api-key", "tenant-id"}},
	{Title: "Report", Names: []string{"policy", "output", "out-file"}},
}

// reportFlags holds the parsed `agentguard report` flags.
type reportFlags struct {
	since, until, auditLog, url, apiKey, tenant, policy, output, outFile string
	keyFiles                                                             repeatedFlag
}

func runReportCmd(args []string) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	f := &reportFlags{}
	fs.StringVar(&f.since, "since", "", "Start of the period, inclusive (default: 24h before --until)")
	fs.StringVar(&f.until, "until", "", "End of the period, exclusive (default: now)")
	fs.StringVar(&f.auditLog, "audit-log", "audit.jsonl", "The live audit log (the server's --audit-log). Its rotated archives are read too.")
	fs.Var(&f.keyFiles, "key-file", "HMAC seal key `file`, for audit verify (the server's --audit-seal-key-file). Repeatable.")
	fs.StringVar(&f.url, "url", "", "Read the audit log from this server instead of the files")
	fs.StringVar(&f.url, "guard-url", "", "Same as --url")
	fs.StringVar(&f.apiKey, "api-key", "", "Bearer token for --url. Env: AGENTGUARD_API_KEY, then the key agentguard setup saved")
	fs.StringVar(&f.tenant, "tenant-id", "", "Tenant to report on with --url (default local)")
	fs.StringVar(&f.policy, "policy", "", "Policy file to identify by SHA-256 (see below)")
	fs.StringVar(&f.output, "output", report.FormatMarkdown, "Format: md (Markdown), json or html (one self-contained page)")
	fs.StringVar(&f.outFile, "out-file", "", "Write the report to this file instead of stdout")
	usage := func(w io.Writer) { reportUsage(w, fs) }
	positional, code, ok := parseCommand(fs, usage, args)
	if !ok {
		return code
	}
	if len(positional) > 0 {
		return usageError("report", "unexpected argument %q (use --audit-log <file> to name the audit log)", positional[0])
	}
	if !isReportFormat(f.output) {
		return usageError("report", "--output must be md, json or html, not %q", f.output)
	}
	server := flagWasSet(fs, "url", "guard-url")
	switch {
	case server && flagWasSet(fs, "audit-log"):
		return usageError("report", "give --audit-log or --url, not both")
	case server && len(f.keyFiles) > 0:
		return usageError("report", "--key-file is for the audit log files; with --url the server's chain is not verified")
	case !server && flagWasSet(fs, "api-key", "tenant-id"):
		return usageError("report", "--api-key and --tenant-id go with --url")
	}
	if server {
		// A password in the URL would be written into the report, printed
		// in errors, and sent as Basic auth on the probe that is meant to
		// carry no credentials.
		if u, err := url.Parse(f.url); err == nil && u.User != nil {
			return usageError("report", "--url must not hold a user name or password (%s); give the API key with --api-key", u.Redacted())
		}
		// Only --url: AGENTGUARD_URL does not turn a report on the local
		// files into one on a server.
		base, err := checkServerURL(f.url)
		if err != nil {
			return usageError("report", "%v", err)
		}
		f.url = base
	}
	period, err := reportPeriod(f.since, f.until, time.Now().UTC())
	if err != nil {
		return usageError("report", "%v", err)
	}
	return executeReport(f, period, server, flagWasSet(fs, "policy"), os.Stdout, os.Stderr)
}

func reportUsage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprint(w, `Usage: agentguard report [flags]

Write a compliance evidence report for a period: what AgentGuard decided
(by decision, scope, agent and transport), the top deny and approval
rules, the approvals on record, whether the audit log is sealed and
intact, posture checks, and how this maps to SOC 2 criteria. It is
supporting evidence for an audit, not a certification.

By default it reads the audit log files (the live file and its rotated
archives, gzip or plain) and checks them as 'agentguard audit verify'
does. With --url it asks a running server instead; the seal chain is then
not verified, and a server with the file backend serves its live file
only.

`)
	clihelp.WriteGroups(w, fs, reportFlagGroups, clihelp.Options{Aliases: map[string]string{"guard-url": "url"}})
	fmt.Fprint(w, `
Times: RFC 3339 (2026-10-01T09:00:00Z), a date (2026-10-01, midnight
UTC), or a duration back in time (90m, 24h, 7d). --until counts back from
now and --since from --until.

Policy file: without --policy, the report names the file 'agentguard
server' would load (AGENTGUARD_POLICY, then configs/default.yaml, then the
installer's starter policy). With --url, only --policy is used.

Examples:
  agentguard report --since 7d --output html --out-file week.html
  agentguard report --since 2026-09-01 --until 2026-10-01 \
    --audit-log /var/lib/agentguard/audit.jsonl --key-file seal.key
  agentguard report --url http://guard.internal:8080 --output json

Exit status: 0 the report was written, 1 it was written but the audit log
failed verification, 2 command-line mistake, 3 the log or the server
can't be read.
`)
}

func isReportFormat(s string) bool {
	for _, f := range report.Formats {
		if s == f {
			return true
		}
	}
	return false
}

// reportPeriod resolves --since and --until. until counts back from now,
// since from until.
func reportPeriod(since, until string, now time.Time) (report.Period, error) {
	u := now
	if until != "" {
		t, err := parseReportTime(until, now)
		if err != nil {
			return report.Period{}, fmt.Errorf("--until: %v", err)
		}
		u = t
	}
	s := u.Add(-defaultReportSpan)
	if since != "" {
		t, err := parseReportTime(since, u)
		if err != nil {
			return report.Period{}, fmt.Errorf("--since: %v", err)
		}
		s = t
	}
	if !s.Before(u) {
		return report.Period{}, fmt.Errorf("--since (%s) must be before --until (%s)", s.Format(time.RFC3339), u.Format(time.RFC3339))
	}
	return report.Period{Since: s, Until: u}, nil
}

// daysPrefix matches a duration that starts with whole days: "7d", "1d12h".
var daysPrefix = regexp.MustCompile(`^(\d+)d(.*)$`)

// parseReportTime reads a time: RFC 3339, a date (midnight UTC), or a
// duration back from ref. Go durations have no day unit, so a leading
// "<n>d" is read as n×24h.
func parseReportTime(s string, ref time.Time) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse(time.DateOnly, s); err == nil {
		return t, nil
	}
	var d time.Duration
	rest := s
	if m := daysPrefix.FindStringSubmatch(s); m != nil {
		// 100000 days keeps the multiplication far from overflowing.
		if days, err := strconv.Atoi(m[1]); err == nil && days <= 100000 {
			d, rest = time.Duration(days)*24*time.Hour, m[2]
		}
	}
	if rest != "" {
		more, err := time.ParseDuration(rest)
		if err != nil || more < 0 {
			return time.Time{}, fmt.Errorf("%q is not a time; use RFC 3339 (2026-10-01T09:00:00Z), a date (2026-10-01) or a duration (24h, 7d)", s)
		}
		d += more
	}
	return ref.Add(-d).UTC(), nil
}

// executeReport reads the log, writes the report and returns the exit
// status.
func executeReport(f *reportFlags, period report.Period, server, policyExplicit bool, stdout, stderr io.Writer) int {
	r := &report.Report{
		GeneratedAt:       time.Now().UTC().Truncate(time.Second),
		AgentGuardVersion: version + " (" + buildinfo.Describe(commit) + ")",
		Period:            period,
	}

	pol, err := reportPolicy(f.policy, policyExplicit, server)
	if err != nil {
		fmt.Fprintf(stderr, "agentguard report: %v\n", err)
		return reportExitIO
	}
	r.Policy = pol

	if server {
		c := &reportClient{base: f.url, tenant: f.tenant, key: resolveClientAPIKey(f.apiKey), http: &http.Client{Timeout: 30 * time.Second}}
		if code := c.collect(r, stderr); code != 0 {
			return code
		}
	} else if code := collectFiles(r, f.auditLog, f.keyFiles, stderr); code != 0 {
		return code
	}
	report.Finish(r)

	var buf bytes.Buffer
	if err := report.Write(&buf, r, f.output); err != nil {
		fmt.Fprintf(stderr, "agentguard report: %v\n", err)
		return reportExitIO
	}
	if f.outFile == "" {
		if _, err := stdout.Write(buf.Bytes()); err != nil {
			fmt.Fprintf(stderr, "agentguard report: %v\n", err)
			return reportExitIO
		}
	} else {
		if err := os.WriteFile(f.outFile, buf.Bytes(), 0o600); err != nil {
			fmt.Fprintf(stderr, "agentguard report: %v\n", err)
			return reportExitIO
		}
		fmt.Fprintf(stdout, "Report written to %s (audit entries in the period: %d; audit log: %s).\n", f.outFile, r.Activity.Entries, r.Integrity.Status)
	}
	if r.Integrity.Status == report.IntegrityBroken {
		fmt.Fprintf(stderr, "agentguard report: the audit log failed verification: %s\n", r.Integrity.Summary)
		return reportExitTampered
	}
	return 0
}

// reportPolicy finds and hashes the policy file. Reading files, it looks
// where the server would; with --url only an explicit --policy counts,
// because a local file says nothing about the server's policy. No policy
// found is not an error: the report says so.
func reportPolicy(flagValue string, explicit, server bool) (*report.PolicyFile, error) {
	if server && !explicit {
		return nil, nil
	}
	path, note, err := findPolicy(flagValue, explicit)
	if err != nil {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if !explicit {
			return nil, nil
		}
		return nil, fmt.Errorf("--policy: %w", err)
	}
	found := "--policy"
	if !explicit {
		found = strings.TrimPrefix(note, "from ")
	}
	sum := sha256.Sum256(b)
	return &report.PolicyFile{Path: path, SHA256: hex.EncodeToString(sum[:]), Found: found}, nil
}

// collectFiles reads the audit log files into r: audit verify first, then
// every entry of the files it walks. It returns a non-zero exit status
// only when nothing can be reported.
func collectFiles(r *report.Report, path string, keyFiles []string, stderr io.Writer) int {
	r.Source = report.Source{Mode: report.SourceFile, AuditLog: path}
	opts := audit.VerifyOptions{}
	for _, kf := range keyFiles {
		key, err := audit.LoadSealKey(kf, false)
		if err != nil {
			fmt.Fprintf(stderr, "agentguard report: %v\n", err)
			return reportExitIO
		}
		opts.Keys = append(opts.Keys, key)
	}
	// Without a key, a log sealed with one still gets every check but its
	// hashes, so an entry added, removed or left unsealed is still caught.
	opts.WithoutKey = len(opts.Keys) == 0
	rep, err := audit.VerifyChain(path, opts)
	if err != nil {
		fmt.Fprintf(stderr, "agentguard report: can't read the audit log: %v (name it with --audit-log)\n", err)
		return reportExitIO
	}
	r.Integrity = report.FromVerify(rep)
	if rep.HashesUnchecked && rep.Break == nil {
		fmt.Fprintln(stderr, "agentguard report: the log is sealed with an HMAC key; give it with --key-file to verify the hashes. The report says they were not checked.")
	}

	files, err := audit.LogFiles(path)
	if err != nil {
		fmt.Fprintf(stderr, "agentguard report: can't read the audit log: %v\n", err)
		return reportExitIO
	}
	for _, f := range files {
		r.Source.Files = append(r.Source.Files, filepath.Base(f))
	}
	entries := func(yield func(audit.Entry) bool) {
		for _, f := range files {
			stop := false
			bad, err := audit.ReadEntries(f, func(e audit.Entry) {
				if !stop && !yield(e) {
					stop = true
				}
			})
			r.Source.BadLines += bad
			if err != nil {
				r.Source.ReadErrors = append(r.Source.ReadErrors, filepath.Base(f)+": "+err.Error())
			}
			if stop {
				return
			}
		}
	}
	r.Activity, r.Approvals = report.Aggregate(entries, r.Period)
	return 0
}
