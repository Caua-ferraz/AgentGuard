package main

// report_server.go is `agentguard report --url`: it reads a running
// server's audit log over GET /v1/audit for the report, with the checks a
// client can make on what the server says.

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/report"
)

// Bounds on reading a server, so a server that misbehaves (or something
// that is not AgentGuard) can't keep the report running forever.
const (
	// reportPageSize is the limit asked for on each GET /v1/audit page. The
	// server clamps it to its own maximum (1000 unless the policy changes
	// it), so nothing here assumes a page holds this many.
	reportPageSize = 1000
	// reportPageBytes caps one page's body: 1000 entries are a few MiB.
	reportPageBytes = 64 << 20
	// reportMaxRequests, reportMaxEntries and reportMaxTime stop a report
	// that reads too much; the files are the way to report on that much.
	reportMaxRequests = 50000
	reportMaxEntries  = 10_000_000
	reportMaxTime     = 30 * time.Minute
	// reportSkew is how far back from the last entry of a page the next
	// page starts. Entries reach the file slightly out of time order (the
	// buffered audit workers), so restarting exactly at the last timestamp
	// would skip an entry stamped a moment earlier but written later.
	// Entries seen twice are dropped by key.
	reportSkew = 2 * time.Second
)

// reportClient reads a server's audit log for the report.
type reportClient struct {
	base, tenant, key string
	http              *http.Client
}

// route is a /v1 path on the legacy route, or on the tenant mirror when a
// tenant was named (like the MCP gateway and the LLM proxy do).
func (c *reportClient) route(p string) string {
	if c.tenant == "" {
		return c.base + "/v1" + p
	}
	return c.base + "/v1/t/" + url.PathEscape(c.tenant) + p
}

func (c *reportClient) get(u string, auth bool) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if auth {
		attachAuth(req, c.key)
	}
	return c.http.Do(req)
}

// collect fills r from the server: the entries of the period, the seal
// head, and whether the audit API needs the key.
func (c *reportClient) collect(r *report.Report, stderr io.Writer) int {
	tenant := c.tenant
	if tenant == "" {
		tenant = "local"
	}
	r.Source = report.Source{Mode: report.SourceServer, Server: c.base, Tenant: tenant}

	before, _ := c.head()
	var fetchErr error
	entries := func(yield func(audit.Entry) bool) {
		fetchErr = c.pages(r, yield)
	}
	r.Activity, r.Approvals = report.Aggregate(entries, r.Period)
	if fetchErr != nil {
		var conn *connectError
		if errors.As(fetchErr, &conn) {
			cannotConnect(stderr, c.base, conn.err)
		} else {
			fmt.Fprintf(stderr, "agentguard report: %v\n", fetchErr)
		}
		return reportExitIO
	}

	after, integrity := c.head()
	r.Integrity = integrity
	if before != nil && after != nil && before.SegmentID != after.SegmentID {
		// GET /v1/audit on the file backend reads the live file only:
		// entries that rotated into an archive while the report paged
		// are gone from what the server can answer.
		r.Source.Warnings = append(r.Source.Warnings, fmt.Sprintf(
			"the server's live audit file rotated while the report read it (segment %s, then %s): entries written around the rotation may be missing; run the report with --audit-log on the server's files", before.SegmentID, after.SegmentID))
	}
	if c.key == "" {
		// The pages came back without a key: the audit API is open.
		open := false
		r.Source.AuthRequired = &open
	} else {
		r.Source.AuthRequired = c.authRequired()
	}
	return 0
}

// connectError is a request that never reached the server.
type connectError struct{ err error }

func (e *connectError) Error() string { return e.err.Error() }

// entryKey identifies an entry, to drop one the server sends twice.
func entryKey(e audit.Entry) [16]byte {
	b, _ := json.Marshal(e)
	sum := sha256.Sum256(b)
	var k [16]byte
	copy(k[:], sum[:])
	return k
}

// pages walks GET /v1/audit oldest first and yields the entries of the
// period, each once.
//
// It pages by time, not by offset: each page starts at the last
// timestamp seen (less reportSkew), and entries already seen are dropped
// by key. An offset into the server's live file is wrong as soon as the
// file rotates; a timestamp still means the same thing. The offset is used
// only to step past a page of entries that all share the window.
//
// The since/until parameters are part of GET /v1/audit from 1.4 (the
// sessions work). A server that predates them ignores them: the first
// entry before the requested since gives that away, and the walk falls
// back to offset paging from where it is. Entries outside the period are
// dropped here either way.
func (c *reportClient) pages(r *report.Report, yield func(audit.Entry) bool) error {
	var (
		seen      = map[[16]byte]struct{}{}
		cursor    = r.Period.Since
		offset    = 0
		highWater = 0     // furthest file position a server ignoring since has sent
		legacy    = false // the server ignores since: page by offset
		prevFirst [16]byte
		prevOff   = -1
		prevCur   time.Time
		start     = time.Now()
	)
	for req := 0; ; req++ {
		switch {
		case req >= reportMaxRequests, len(seen) >= reportMaxEntries, time.Since(start) > reportMaxTime:
			return fmt.Errorf("stopped after %d requests, %d entries and %s: that is more than a report reads from a server; run it with --audit-log on the server's files, or narrow --since and --until", req, len(seen), time.Since(start).Round(time.Second))
		}
		params := url.Values{}
		params.Set("order", "asc")
		params.Set("limit", strconv.Itoa(reportPageSize))
		params.Set("offset", strconv.Itoa(offset))
		params.Set("since", cursor.Format(time.RFC3339Nano))
		params.Set("until", r.Period.Until.Format(time.RFC3339Nano))
		resp, err := c.get(c.route("/audit")+"?"+params.Encode(), true)
		if err != nil {
			return &connectError{err}
		}
		page, err := decodeAuditPage(resp, c.key, c.base)
		if err != nil {
			return err
		}
		if len(page) == 0 {
			return nil
		}

		// The same first entry at a new offset (and the same since) means
		// the server ignores offset: it would send this page forever.
		first := entryKey(page[0])
		if req > 0 && first == prevFirst && offset != prevOff && cursor.Equal(prevCur) {
			return fmt.Errorf("the server at %s sends the same entries for every offset; is it an AgentGuard server?", c.base)
		}
		prevFirst, prevOff, prevCur = first, offset, cursor
		highWater = max(highWater, offset+len(page))
		if !legacy {
			for _, e := range page {
				if e.Timestamp.Before(cursor) {
					legacy = true
					break
				}
			}
		}

		fresh := 0
		for _, e := range page {
			k := entryKey(e)
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			fresh++
			r.Source.Fetched++
			if !r.Period.Contains(e.Timestamp) {
				r.Source.OutsidePeriod++
				continue
			}
			if !yield(e) {
				return nil
			}
		}

		switch {
		case legacy:
			// Every request so far, read as a server that ignores since,
			// covered the file from 0 to highWater.
			offset = highWater
		case fresh == 0:
			offset += len(page)
		default:
			next := page[len(page)-1].Timestamp.Add(-reportSkew)
			if next.After(cursor) {
				cursor, offset = next, 0
			} else {
				offset += len(page)
			}
		}
	}
}

func decodeAuditPage(resp *http.Response, key, base string) ([]audit.Entry, error) {
	defer resp.Body.Close()
	body := io.LimitReader(resp.Body, reportPageBytes)
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, errors.New(authFailure(key))
	case resp.StatusCode != http.StatusOK:
		raw, _ := io.ReadAll(io.LimitReader(body, 64<<10))
		var msg map[string]string
		_ = json.Unmarshal(raw, &msg)
		return nil, fmt.Errorf("GET /v1/audit: the server answered HTTP %d: %s", resp.StatusCode, serverMessage(msg, raw))
	}
	var page []audit.Entry
	if err := json.NewDecoder(body).Decode(&page); err != nil {
		return nil, fmt.Errorf("unreadable answer from %s (is it an AgentGuard server?): %v", base, err)
	}
	return page, nil
}

// head reads GET /v1/audit/head and describes it. The server answers 404
// with a JSON error when sealing is off; a server older than 1.4 has no
// such route and answers a plain-text 404. The anchor is nil unless the
// server returned one.
func (c *reportClient) head() (*audit.Anchor, report.Integrity) {
	resp, err := c.get(c.route("/audit/head"), true)
	if err != nil {
		return nil, report.FromServerHead(nil, false, "GET /v1/audit/head failed ("+connectFailure(err)+")")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	switch resp.StatusCode {
	case http.StatusOK:
		var a audit.Anchor
		if err := json.Unmarshal(raw, &a); err != nil || a.Seq == 0 {
			return nil, report.FromServerHead(nil, false, "the server's GET /v1/audit/head answer is unreadable")
		}
		return &a, report.FromServerHead(&a, false, "")
	case http.StatusNotFound:
		var body map[string]string
		if json.Unmarshal(raw, &body) == nil && body["error"] != "" {
			return nil, report.FromServerHead(nil, true, "")
		}
		return nil, report.FromServerHead(nil, false, "the server has no GET /v1/audit/head (it is older than 1.4)")
	}
	return nil, report.FromServerHead(nil, false, fmt.Sprintf("GET /v1/audit/head answered HTTP %d", resp.StatusCode))
}

// authRequired asks for one audit entry without the key. It returns nil
// when the answer says neither yes nor no. A redirect is not followed: a
// login page answering 200 says nothing about the audit API.
func (c *reportClient) authRequired() *bool {
	probe := &http.Client{
		Timeout:       c.http.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequest(http.MethodGet, c.route("/audit")+"?limit=1", nil)
	if err != nil {
		return nil
	}
	resp, err := probe.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var required bool
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		required = true
	case http.StatusOK:
		// Open only if it really answered with audit entries.
		var entries []json.RawMessage
		if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&entries) != nil {
			return nil
		}
		required = false
	default:
		return nil
	}
	return &required
}
