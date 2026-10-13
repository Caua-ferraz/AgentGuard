package main

// audit_verify.go implements `agentguard audit verify`: an offline check of
// a sealed audit log (--audit-seal) and its rotated archives. It reads files
// only, so it works on a copy, on a stopped server, or on another machine.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/Caua-ferraz/AgentGuard/internal/clihelp"
	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
)

// Exit statuses of `agentguard audit verify` (2 is exitUsage).
const (
	verifyExitBroken = 1
	verifyExitIO     = 3
)

// repeatedFlag collects every value of a flag given more than once.
type repeatedFlag []string

func (r *repeatedFlag) String() string     { return strings.Join(*r, ",") }
func (r *repeatedFlag) Set(v string) error { *r = append(*r, v); return nil }

func runAuditVerifyCmd(args []string) int {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	auditPath := fs.String("audit-log", "audit.jsonl", "The live audit log (the server's --audit-log). Its rotated archives are found from its header.")
	var keyFiles, anchorArgs repeatedFlag
	fs.Var(&keyFiles, "key-file", "HMAC key `file` (the server's --audit-seal-key-file). Repeat it for a log sealed under more than one key.")
	fs.Var(&anchorArgs, "anchor", "A published anchor to check, as `seq:hash` (from an 'audit anchor' log line or GET /v1/audit/head). Repeatable.")
	output := fs.String("output", "text", "Output format: text or json")
	usage := func(w io.Writer) {
		fmt.Fprint(w, `Usage: agentguard audit verify [flags]

Check a sealed audit log (server --audit-seal) for tampering: every entry's
hash, the seq and prev_hash links between entries, and the links between
the live file and its rotated archives (gzip or plain). It reads the files
only; the server does not need to run.

A log that verifies was not changed by anyone without the key. The newest
entries could still have been cut off: check published anchors with
--anchor to rule that out.

`)
		clihelp.WriteFlags(w, fs, clihelp.Options{})
		fmt.Fprint(w, `
Examples:
  agentguard audit verify --audit-log /var/lib/agentguard/audit.jsonl \
    --key-file /var/lib/agentguard/audit-seal.key
  agentguard audit verify --anchor 1200:3f9a...e1 --output json

Exit status: 0 the chain is intact, 1 it is broken or an anchor does not
match, 2 command-line mistake (or the log needs --key-file), 3 a file
can't be read.
`)
	}
	positional, code, ok := parseCommand(fs, usage, args)
	if !ok {
		return code
	}
	if len(positional) > 0 {
		return usageError("audit verify", "unexpected argument %q (use --audit-log <file> to name the audit log)", positional[0])
	}
	if *output != "text" && *output != "json" {
		return usageError("audit verify", "--output must be text or json, not %q", *output)
	}
	opts := audit.VerifyOptions{}
	for _, a := range anchorArgs {
		anchor, err := parseAnchor(a)
		if err != nil {
			return usageError("audit verify", "%v", err)
		}
		opts.Anchors = append(opts.Anchors, anchor)
	}
	for _, kf := range keyFiles {
		key, err := audit.LoadSealKey(kf, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentguard audit verify: %v\n", err)
			return verifyExitIO
		}
		opts.Keys = append(opts.Keys, key)
	}

	rep, err := audit.VerifyChain(*auditPath, opts)
	var needKey *audit.SealKeyNeededError
	switch {
	case errors.As(err, &needKey):
		return usageError("audit verify", "%v", err)
	case err != nil:
		fmt.Fprintf(os.Stderr, "agentguard audit verify: %v\n", err)
		return verifyExitIO
	}

	if *output == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		writeVerifyReport(os.Stdout, *auditPath, rep)
	}
	if !rep.OK {
		return verifyExitBroken
	}
	return 0
}

// parseAnchor reads a --anchor value: seq:hash, the hash 64 hex characters.
func parseAnchor(s string) (audit.Anchor, error) {
	seqStr, hash, found := strings.Cut(s, ":")
	seq, err := strconv.ParseUint(seqStr, 10, 64)
	if !found || err != nil || seq == 0 {
		return audit.Anchor{}, fmt.Errorf("--anchor %q: want seq:hash, e.g. 1200:3f9a… (seq is a number from 1)", s)
	}
	hash = strings.ToLower(hash)
	if b, err := hex.DecodeString(hash); err != nil || len(b) != 32 {
		return audit.Anchor{}, fmt.Errorf("--anchor %q: the hash must be 64 hex characters", s)
	}
	return audit.Anchor{Seq: seq, Hash: hash}, nil
}

// writeVerifyReport prints the report for a person.
func writeVerifyReport(w io.Writer, path string, rep *audit.VerifyReport) {
	fmt.Fprintf(w, "Audit log: %s\n", path)
	fmt.Fprintf(w, "Files:     %d, oldest first\n", len(rep.Segments))
	for _, s := range rep.Segments {
		fmt.Fprintf(w, "  %s\n", s)
	}
	if rep.Entries > 0 {
		fmt.Fprintf(w, "Sealed:    %d entries, seq %d to %d\n", rep.Entries, rep.FirstSeq, rep.LastSeq)
	} else {
		fmt.Fprintf(w, "Sealed:    no entries\n")
	}
	if len(rep.Seals) > 0 {
		fmt.Fprintf(w, "Seal:      %s\n", strings.Join(rep.Seals, ", then "))
	}
	if rep.PrunedBefore > 0 {
		fmt.Fprintf(w, "The chain starts at seq %d (older files were pruned).\n", rep.PrunedBefore+1)
	}
	if rep.Unsealed > 0 {
		fmt.Fprintf(w, "%d entries were written before sealing began; they are not protected.\n", rep.Unsealed)
	}
	for _, s := range rep.Seals {
		if s == audit.SealAlgSHA256 {
			fmt.Fprintln(w, "Note: plain SHA-256 entries only show naive edits; anyone who can write the file can recompute them. Check anchors, or seal with a key.")
			break
		}
	}
	for _, warn := range rep.Warnings {
		fmt.Fprintf(w, "Warning: %s\n", warn)
	}
	for _, a := range rep.Anchors {
		fmt.Fprintf(w, "Anchor %d:%s: %s\n", a.Seq, shortHash(a.Hash), anchorText(a, rep))
	}
	switch {
	case rep.Break != nil && rep.Break.Line > 0:
		fmt.Fprintf(w, "BROKEN at %s:%d: %s\n", rep.Break.File, rep.Break.Line, rep.Break.Reason)
	case rep.Break != nil && rep.Break.File != "":
		fmt.Fprintf(w, "BROKEN in %s: %s\n", rep.Break.File, rep.Break.Reason)
	case rep.Break != nil:
		fmt.Fprintf(w, "BROKEN: %s\n", rep.Break.Reason)
	case !rep.OK:
		fmt.Fprintln(w, "FAILED: an anchor does not match the log.")
	default:
		fmt.Fprintln(w, "OK: the chain is intact.")
	}
}

func anchorText(a audit.AnchorResult, rep *audit.VerifyReport) string {
	switch a.Status {
	case audit.AnchorMatch:
		return "matches"
	case audit.AnchorMismatch:
		return "DOES NOT MATCH (the log has " + shortHash(a.Found) + ")"
	case audit.AnchorMissing:
		return fmt.Sprintf("MISSING: the log ends at seq %d, so entries after it were removed", rep.LastSeq)
	case audit.AnchorNotCheckable:
		return "not checkable: that seq is in the pruned part of the log"
	default:
		return "not checked: the chain breaks before it"
	}
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "…"
}
