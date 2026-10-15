package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
)

// Integrity methods: how the report learned about the audit log's seal.
const (
	// MethodVerify: the files were checked with audit verify.
	MethodVerify = "verify"
	// MethodSealHead: the server's GET /v1/audit/head was read. The chain
	// itself was not checked.
	MethodSealHead = "seal_head"
)

// Integrity statuses.
const (
	IntegrityIntact      = "intact"       // the chain verified
	IntegrityBroken      = "broken"       // audit verify found tampering or damage
	IntegrityNotSealed   = "not_sealed"   // the log has no seal chain
	IntegrityNotVerified = "not_verified" // sealed, but the chain was not checked
	IntegrityUnknown     = "unknown"      // can't tell whether the log is sealed
)

// Integrity is what the report knows about the audit log's seal chain.
type Integrity struct {
	Method string `json:"method"`
	Status string `json:"status"`
	// Summary is one sentence for a person.
	Summary string `json:"summary"`
	// Seals says how the entries are sealed, e.g. "hmac-sha256 key
	// 3f9a…" or "sha256", in the order they appear. Empty when unknown.
	Seals []string `json:"seals,omitempty"`
	// KeyBased is true for an HMAC key, false for plain SHA-256, nil when
	// not sealed or not known. It is read from the log's _meta header,
	// which anyone who can write the file can forge: only Status intact
	// confirms it.
	KeyBased *bool `json:"key_based"`
	// Head is the latest seal anchor: the last sealed entry's seq and hash.
	Head *Head `json:"head,omitempty"`
	// Verify is audit verify's full report (verify method only).
	Verify *audit.VerifyReport `json:"verify,omitempty"`
}

// Head is a seal anchor: the entry with this seq has this hash. SegmentID
// and At are set when a server reported it.
type Head struct {
	Seq       uint64     `json:"seq"`
	Hash      string     `json:"hash"`
	SegmentID string     `json:"segment_id,omitempty"`
	At        *time.Time `json:"at,omitempty"`
}

// FromVerify describes the outcome of audit.VerifyChain.
func FromVerify(rep *audit.VerifyReport) Integrity {
	in := Integrity{Method: MethodVerify, Verify: rep, Seals: rep.Seals}
	if len(rep.Seals) > 0 {
		keyed := strings.HasPrefix(rep.Seals[len(rep.Seals)-1], audit.SealAlgHMACSHA256)
		in.KeyBased = &keyed
	}
	if rep.LastSeq > 0 {
		in.Head = &Head{Seq: rep.LastSeq, Hash: rep.LastHash}
	}
	switch {
	case rep.Break != nil:
		in.Status = IntegrityBroken
		where := rep.Break.File
		if rep.Break.Line > 0 {
			where = fmt.Sprintf("%s:%d", rep.Break.File, rep.Break.Line)
		}
		if where != "" {
			where = " at " + where
		}
		in.Summary = fmt.Sprintf("agentguard audit verify found the chain broken%s: %s.", where, strings.TrimSuffix(rep.Break.Reason, "."))
	case rep.Entries == 0 && rep.PrunedBefore == 0 && len(rep.Seals) == 0:
		in.Status, in.KeyBased = IntegrityNotSealed, nil
		in.Summary = "The audit log is not sealed (the server runs without --audit-seal), so tampering with it can't be detected."
	case rep.Entries == 0 && rep.PrunedBefore == 0 && rep.Unsealed > 0:
		// A seal declared after every entry protects none of them: never
		// "intact".
		in.Status, in.KeyBased = IntegrityNotSealed, nil
		in.Summary = fmt.Sprintf("None of the %s in the log is sealed: the seal is declared only after them, so tampering with them can't be detected.", plural(int(rep.Unsealed), "entry", "entries"))
	case !rep.OK:
		in.Status = IntegrityBroken
		in.Summary = "agentguard audit verify failed: an anchor does not match the log."
	case rep.HashesUnchecked:
		// Checked WithoutKey: the structure holds, the hashes are unknown.
		in.Status = IntegrityNotVerified
		in.Summary = fmt.Sprintf("The log says it is sealed with an HMAC key, and its structure holds for %s (seq %d to %d): every entry after the seal is sealed, seq has no gaps, each prev_hash links to the entry before. Without --key-file the hashes were not checked, so a rewrite can't be ruled out.", plural(int(rep.Entries), "sealed entry", "sealed entries"), rep.FirstSeq, rep.LastSeq)
	default:
		in.Status = IntegrityIntact
		in.Summary = fmt.Sprintf("agentguard audit verify checked %s (seq %d to %d): the chain is intact.", plural(int(rep.Entries), "sealed entry", "sealed entries"), rep.FirstSeq, rep.LastSeq)
	}
	return in
}

// FromServerHead describes a server's GET /v1/audit/head answer: a head
// (sealed), sealingOff (the server says sealing is off), or neither (an
// older server without the route, or an error, given as why).
func FromServerHead(head *audit.Anchor, sealingOff bool, why string) Integrity {
	in := Integrity{Method: MethodSealHead}
	switch {
	case head != nil:
		in.Status = IntegrityNotVerified
		in.Head = &Head{Seq: head.Seq, Hash: head.Hash, SegmentID: head.SegmentID}
		if !head.At.IsZero() {
			at := head.At.UTC()
			in.Head.At = &at
		}
		in.Summary = "The server's audit log is sealed. The report read its head; it did not check the chain (run the report with --audit-log on the log files, or agentguard audit verify, for that)."
	case sealingOff:
		in.Status = IntegrityNotSealed
		in.Summary = "The server says its audit log is not sealed (no --audit-seal), so tampering with it can't be detected."
	default:
		in.Status = IntegrityUnknown
		in.Summary = "Unknown whether the audit log is sealed: " + why + "."
	}
	return in
}
