package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
)

func TestIntegrity(t *testing.T) {
	head := &audit.Anchor{SegmentID: "seg", Seq: 9, Hash: "h", At: t0}
	cases := []struct {
		name       string
		in         Integrity
		wantStatus string
		wantKey    string // "yes", "no" or "" for nil
		wantHead   uint64
		wantText   string
	}{
		{
			name:       "a keyed chain that verified is intact",
			in:         FromVerify(&audit.VerifyReport{OK: true, Entries: 3, FirstSeq: 1, LastSeq: 3, LastHash: "x", Seals: []string{"hmac-sha256 key k"}}),
			wantStatus: IntegrityIntact, wantKey: "yes", wantHead: 3, wantText: "seq 1 to 3",
		},
		{
			name:       "a plain chain that verified is intact but not keyed",
			in:         FromVerify(&audit.VerifyReport{OK: true, Entries: 1, FirstSeq: 1, LastSeq: 1, Seals: []string{"sha256"}}),
			wantStatus: IntegrityIntact, wantKey: "no", wantHead: 1,
		},
		{
			name: "a break names the file and line",
			in: FromVerify(&audit.VerifyReport{Entries: 1, LastSeq: 1, Seals: []string{"sha256"},
				Break: &audit.VerifyBreak{File: "audit.jsonl", Line: 4, Reason: "hash mismatch"}}),
			wantStatus: IntegrityBroken, wantKey: "no", wantHead: 1, wantText: "at audit.jsonl:4: hash mismatch",
		},
		{
			name:       "a log with no seal is not sealed",
			in:         FromVerify(&audit.VerifyReport{OK: true, Unsealed: 5}),
			wantStatus: IntegrityNotSealed, wantText: "--audit-seal",
		},
		{
			name:       "a keyed log without --key-file is not verified",
			in:         FromKeyNeeded(&audit.SealKeyNeededError{KeyID: "abc", File: "audit.jsonl"}),
			wantStatus: IntegrityNotVerified, wantKey: "yes", wantText: "key id abc",
		},
		{
			name:       "a server head is sealed but not verified",
			in:         FromServerHead(head, false, ""),
			wantStatus: IntegrityNotVerified, wantHead: 9, wantText: "did not check the chain",
		},
		{
			name:       "a server that says sealing is off is not sealed",
			in:         FromServerHead(nil, true, ""),
			wantStatus: IntegrityNotSealed,
		},
		{
			name:       "an older server without the head route is unknown",
			in:         FromServerHead(nil, false, "the server has no GET /v1/audit/head"),
			wantStatus: IntegrityUnknown, wantText: "no GET /v1/audit/head",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in
			if in.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q (%s)", in.Status, tc.wantStatus, in.Summary)
			}
			key := ""
			if in.KeyBased != nil {
				key = map[bool]string{true: "yes", false: "no"}[*in.KeyBased]
			}
			if key != tc.wantKey {
				t.Errorf("key based = %q, want %q", key, tc.wantKey)
			}
			var seq uint64
			if in.Head != nil {
				seq = in.Head.Seq
			}
			if seq != tc.wantHead {
				t.Errorf("head seq = %d, want %d", seq, tc.wantHead)
			}
			if !strings.Contains(in.Summary, tc.wantText) {
				t.Errorf("summary %q lacks %q", in.Summary, tc.wantText)
			}
		})
	}
}

func TestAssess(t *testing.T) {
	yes, no := true, false
	intact := FromVerify(&audit.VerifyReport{OK: true, Entries: 3, FirstSeq: 1, LastSeq: 3, Seals: []string{"hmac-sha256 key k"}})
	cases := []struct {
		name string
		r    Report
		want map[string]string // check name -> status
	}{
		{
			name: "a verified keyed log with masked secrets passes the file checks",
			r: Report{Source: Source{Mode: SourceFile}, Integrity: intact,
				Activity: Activity{RedactedEntries: 2}},
			want: map[string]string{
				"Audit log sealed": CheckPass, "Seal uses a secret key": CheckPass, "Seal chain verified": CheckPass,
				"Entries outside the seal chain": CheckPass, "Unreadable lines": CheckPass,
				"Secrets masked in the log": CheckPass, "Audit API requires an API key": CheckUnknown,
			},
		},
		{
			name: "a broken chain, bad lines and an unmasked secret fail",
			r: Report{Source: Source{Mode: SourceFile, BadLines: 2},
				Integrity: FromVerify(&audit.VerifyReport{Seals: []string{"sha256"}, Unsealed: 4, Break: &audit.VerifyBreak{Reason: "seq gap"}}),
				Activity:  Activity{UnmaskedSecretEntries: 1, RedactedEntries: 5}},
			want: map[string]string{
				"Seal uses a secret key": CheckWarn, "Seal chain verified": CheckFail,
				"Entries outside the seal chain": CheckWarn, "Unreadable lines": CheckWarn,
				"Secrets masked in the log": CheckFail,
			},
		},
		{
			name: "a file that can't be read to the end fails the line check",
			r:    Report{Source: Source{Mode: SourceFile, ReadErrors: []string{"x.gz: damaged"}}, Integrity: intact},
			want: map[string]string{"Unreadable lines": CheckFail},
		},
		{
			name: "an unsealed log warns and nothing about secrets is known",
			r:    Report{Source: Source{Mode: SourceFile}, Integrity: FromVerify(&audit.VerifyReport{OK: true, Unsealed: 7})},
			want: map[string]string{
				"Audit log sealed": CheckWarn, "Seal uses a secret key": CheckWarn, "Seal chain verified": CheckWarn,
				"Entries outside the seal chain": CheckWarn, "Secrets masked in the log": CheckUnknown,
			},
		},
		{
			name: "a sealed server that requires a key",
			r: Report{Source: Source{Mode: SourceServer, AuthRequired: &yes},
				Integrity: FromServerHead(&audit.Anchor{Seq: 1, Hash: "h", At: time.Now()}, false, "")},
			want: map[string]string{
				"Audit log sealed": CheckPass, "Seal uses a secret key": CheckUnknown, "Seal chain verified": CheckUnknown,
				"Entries outside the seal chain": CheckUnknown, "Unreadable lines": CheckUnknown,
				"Audit API requires an API key": CheckPass,
			},
		},
		{
			name: "an open server fails the API key check",
			r:    Report{Source: Source{Mode: SourceServer, AuthRequired: &no}, Integrity: FromServerHead(nil, false, "older server")},
			want: map[string]string{"Audit log sealed": CheckUnknown, "Audit API requires an API key": CheckFail},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := map[string]string{}
			for _, c := range Assess(&tc.r) {
				got[c.Name] = c.Status
				if c.Detail == "" {
					t.Errorf("%s has no detail", c.Name)
				}
			}
			for name, want := range tc.want {
				if got[name] != want {
					t.Errorf("%s = %q, want %q", name, got[name], want)
				}
			}
		})
	}
}

func TestControlsAndLimits(t *testing.T) {
	r := fixtureReport()
	var ids []string
	for _, c := range r.Controls {
		ids = append(ids, c.Criterion)
		if c.Shows == "" || len(c.Where) == 0 {
			t.Errorf("%s says nothing or points nowhere", c.Criterion)
		}
	}
	if got := strings.Join(ids, " "); got != "CC6.1 CC6.6 CC7.2 CC7.3 CC8.1" {
		t.Errorf("criteria = %s", got)
	}

	server := &Report{Source: Source{Mode: SourceServer, Tenant: "acme"}}
	if got := strings.Join(Limits(server), "\n"); !strings.Contains(got, "rotated archives are not included") || !strings.Contains(got, `"acme"`) {
		t.Errorf("server limits miss the live-file and tenant caveats:\n%s", got)
	}
}
