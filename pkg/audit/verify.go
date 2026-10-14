package audit

// verify.go — offline verification of a sealed audit log (`agentguard audit
// verify`). It reads files only: no server, no checkpoint, no lock.

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// VerifyOptions configures VerifyChain.
type VerifyOptions struct {
	// Keys are the HMAC keys the log may be sealed with, matched by key id.
	// More than one is needed only when the key was changed over time.
	Keys [][]byte
	// Anchors are published heads to check: the entry with Anchor.Seq must
	// have Anchor.Hash. Other Anchor fields are ignored.
	Anchors []Anchor
}

// VerifyBreak is the first place the chain does not hold.
type VerifyBreak struct {
	File   string `json:"file,omitempty"`
	Line   int    `json:"line,omitempty"`
	Reason string `json:"reason"`
}

// Anchor check outcomes, as reported in AnchorResult.Status.
const (
	AnchorMatch        = "match"
	AnchorMismatch     = "mismatch"
	AnchorMissing      = "missing"       // the log ends before this seq: entries were removed
	AnchorNotCheckable = "not_checkable" // this seq is in the pruned part of the log
	AnchorNotChecked   = "not_checked"   // the chain breaks before this seq
)

// AnchorResult is the outcome of one --anchor.
type AnchorResult struct {
	Seq    uint64 `json:"seq"`
	Hash   string `json:"hash"`
	Status string `json:"status"`
	Found  string `json:"found,omitempty"` // the hash the log has for Seq, on a mismatch
}

// VerifyReport is what VerifyChain found.
type VerifyReport struct {
	// OK is true when every sealed entry verified, the files link up, and
	// no anchor mismatched or is missing.
	OK bool `json:"ok"`
	// Segments are the files walked, oldest first (base names).
	Segments []string `json:"segments"`
	// Entries is the number of sealed entries verified; FirstSeq..LastSeq
	// their range, LastHash the hash of the last one.
	Entries  uint64 `json:"entries"`
	FirstSeq uint64 `json:"first_seq,omitempty"`
	LastSeq  uint64 `json:"last_seq,omitempty"`
	LastHash string `json:"last_hash,omitempty"`
	// PrunedBefore is set when the oldest surviving file continues a chain
	// whose earlier files were pruned: the chain starts at PrunedBefore+1.
	PrunedBefore uint64 `json:"pruned_before,omitempty"`
	// Unsealed counts entries written before sealing began. They are not
	// protected by the chain.
	Unsealed uint64 `json:"unsealed"`
	// Seals lists how the entries are sealed ("hmac-sha256 key <id>",
	// "sha256"), in the order they appear.
	Seals    []string       `json:"seals,omitempty"`
	Warnings []string       `json:"warnings,omitempty"`
	Break    *VerifyBreak   `json:"break,omitempty"`
	Anchors  []AnchorResult `json:"anchors,omitempty"`
}

// SealKeyNeededError is returned when the log is sealed with an HMAC key
// and no key was given: nothing can be verified without it.
type SealKeyNeededError struct {
	KeyID string
	File  string
}

func (e *SealKeyNeededError) Error() string {
	return fmt.Sprintf("%s is sealed with an HMAC key (key id %s); give that key with --key-file", e.File, e.KeyID)
}

// VerifyChain checks the sealed chain of the audit log at livePath and the
// rotated archives it links back to (gzip or plain), oldest first.
//
// The returned error is for problems reading the files (missing live file,
// permissions) and for *SealKeyNeededError. Everything the files themselves
// get wrong — a changed byte, a missing or reordered line, a cut line, a
// broken link between files, a corrupt archive — is reported in
// VerifyReport.Break with OK false.
func VerifyChain(livePath string, opts VerifyOptions) (*VerifyReport, error) {
	if _, err := os.Stat(livePath); err != nil {
		return nil, err
	}
	files, warnings, linkBreak := chainFiles(livePath)

	v := &verifier{
		keys:    map[string][]byte{},
		anchors: map[uint64]string{},
		rep:     &VerifyReport{Warnings: warnings},
	}
	for _, k := range opts.Keys {
		v.keys[SealKeyID(k)] = k
	}
	for _, a := range opts.Anchors {
		v.anchors[a.Seq] = ""
	}
	for _, f := range files {
		v.rep.Segments = append(v.rep.Segments, filepath.Base(f))
	}

	for i, f := range files {
		if err := v.file(f, i == 0); err != nil {
			return nil, err
		}
		if v.keyNeeded != nil {
			return nil, v.keyNeeded
		}
		if v.rep.Break != nil {
			break
		}
	}

	rep := v.rep
	if v.pendingCut != nil && rep.Break == nil {
		rep.Break = v.pendingCut
	}
	if rep.Break == nil && linkBreak != nil {
		rep.Break = linkBreak
	}
	if rep.Break == nil && len(opts.Keys) > 0 && len(rep.Seals) == 0 {
		rep.Break = &VerifyBreak{Reason: "the log is not sealed: no _meta line declares a seal, so nothing in it is tied to your key"}
	}
	if rep.Break == nil && len(opts.Keys) > 0 && !v.sawHMAC && rep.Entries > 0 {
		rep.Break = &VerifyBreak{Reason: "no entry is sealed with a key: the log uses plain SHA-256, which anyone who can write the file can recompute"}
	}
	if rep.Break == nil && rep.Entries == 0 && rep.PrunedBefore == 0 {
		rep.Warnings = append(rep.Warnings, "no sealed entries: is the server running with --audit-seal?")
	}

	rep.OK = rep.Break == nil
	for _, a := range opts.Anchors {
		r := AnchorResult{Seq: a.Seq, Hash: a.Hash}
		found, seen := v.anchors[a.Seq]
		switch {
		case seen && found != "":
			if found == a.Hash {
				r.Status = AnchorMatch
			} else {
				r.Status, r.Found = AnchorMismatch, found
			}
		case rep.Break != nil:
			r.Status = AnchorNotChecked
		case a.Seq <= rep.PrunedBefore:
			r.Status = AnchorNotCheckable
		default:
			r.Status = AnchorMissing
		}
		if r.Status == AnchorMismatch || r.Status == AnchorMissing {
			rep.OK = false
		}
		rep.Anchors = append(rep.Anchors, r)
	}
	return rep, nil
}

// chainFiles walks _meta.rotated_from back from the live file and returns
// the files oldest first.
//
// A link to a file that is gone ends the walk: that is what pruning leaves.
// But pruning deletes the oldest archives first, and archive names sort in
// write order, so an archive left on disk that is older than the missing
// one, or any unlinked archive behind a missing link, means a file was
// removed or a header's rotated_from was rewritten. Both are returned as
// a break: otherwise every archive behind the gap would go unverified.
// Older archives with no link to them from a file that starts a chain (no
// rotated_from, no chain_prev) are only a warning: a log started over.
func chainFiles(livePath string) ([]string, []string, *VerifyBreak) {
	files := []string{livePath}
	seen := map[string]bool{livePath: true}
	dir := filepath.Dir(livePath)
	base := filepath.Base(livePath)
	cur := livePath
	missing := ""      // base name of a rotated_from target that is gone
	linksBack := false // the oldest file continues a chain (it names a predecessor or has chain_prev)
	for depth := 0; depth < maxRotationChainDepth; depth++ {
		m, err := readMetaAny(cur)
		if err != nil || m == nil {
			break
		}
		linksBack = m.RotatedFrom != "" || m.ChainSeq > 0 || m.ChainPrev != ""
		if m.RotatedFrom == "" {
			break
		}
		p := filepath.Join(dir, filepath.Base(m.RotatedFrom))
		if seen[p] {
			break
		}
		if _, err := os.Stat(p); err != nil {
			missing = filepath.Base(m.RotatedFrom)
			break
		}
		seen[p] = true
		files = append(files, p)
		cur = p
	}
	for i, j := 0, len(files)-1; i < j; i, j = i+1, j-1 {
		files[i], files[j] = files[j], files[i]
	}

	names, err := listArchives(livePath)
	if err != nil {
		return files, nil, nil
	}
	// oldest is the stamp of the oldest linked archive; "" when the walk
	// reached no archive, so every archive on disk is older than it.
	oldest := ""
	if files[0] != livePath {
		oldest = archiveStamp(filepath.Base(files[0]), base)
	}
	var warnings []string
	for _, name := range names {
		if seen[filepath.Join(dir, name)] {
			continue
		}
		stamp := archiveStamp(name, base)
		switch {
		case oldest != "" && stamp > oldest:
			return files, warnings, &VerifyBreak{File: name,
				Reason: "segment link broken: this archive is newer than the oldest linked file but no file links to it (a header's rotated_from was rewritten to skip it)"}
		case missing != "":
			// Pruning removes the oldest archives first, so the missing file
			// would be the newest pruned one and nothing unlinked could be
			// left: an archive still on disk means a file was removed or
			// rotated_from rewritten.
			return files, warnings, &VerifyBreak{File: filepath.Base(files[0]), Line: 1,
				Reason: fmt.Sprintf("segment link broken: the file before this one, %s, is missing, but the archive %s is still there and nothing links to it; pruning removes the oldest archives first, so a file was removed or rotated_from rewritten", missing, name)}
		case missing == "" && linksBack && stamp != oldest:
			return files, warnings, &VerifyBreak{File: filepath.Base(files[0]), Line: 1,
				Reason: fmt.Sprintf("segment link broken: this file continues a chain but names no file before it, while the archive %s is still there", name)}
		default:
			warnings = append(warnings, fmt.Sprintf("archive %s is not linked from the files after it; it was not verified", name))
		}
	}
	return files, warnings, nil
}

// verifier is VerifyChain's state while it walks the files.
type verifier struct {
	keys    map[string][]byte
	anchors map[uint64]string // seq -> hash the log has for it ("" until seen)
	rep     *VerifyReport

	seal    *SealInfo // how the entries from here on are sealed
	h       hash.Hash
	sawHMAC bool

	keyNeeded *SealKeyNeededError

	started  bool // the chain has begun: every entry from here must be sealed
	nextSeq  uint64
	lastHash string

	// pendingCut is a line that is not valid JSON after sealing began. It is
	// a break unless the next line is the _meta line the logger writes after
	// an interrupted write, resuming the chain exactly where it stopped.
	pendingCut *VerifyBreak
}

// sealing reports whether entries from here on must be sealed: the chain has
// begun, or a _meta line has declared a seal. The logger writes that line
// before the first sealed entry, so an unsealed entry after it was inserted
// (or sealing was turned off, which also leaves the log unprotected).
func (v *verifier) sealing() bool { return v.started || v.seal != nil }

func (v *verifier) fail(file string, line int, format string, args ...any) {
	v.rep.Break = &VerifyBreak{File: filepath.Base(file), Line: line, Reason: fmt.Sprintf(format, args...)}
}

// file verifies one segment. first is true for the oldest surviving file.
func (v *verifier) file(path string, first bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			v.fail(path, 0, "can't decompress the archive (%v): it was changed or damaged", err)
			return nil
		}
		defer func() { _ = gz.Close() }()
		r = gz
	}
	br := bufio.NewReaderSize(r, 64*1024)

	for lineNo := 1; ; lineNo++ {
		raw, err := br.ReadBytes('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			if isCorruptArchive(err) {
				v.fail(path, lineNo, "can't decompress the archive (%v): it was changed or damaged", err)
				return nil
			}
			return fmt.Errorf("read %s: %w", path, err)
		}
		complete := len(raw) > 0 && raw[len(raw)-1] == '\n'
		line := bytes.TrimRight(raw, "\r\n")
		if len(bytes.TrimSpace(line)) > 0 {
			if !complete {
				if v.sealing() || bytes.Contains(line, []byte(hashFieldPrefix)) {
					v.fail(path, lineNo, "the line is incomplete: the file was cut mid-line (a crash during a write, or truncation)")
					return nil
				}
				v.rep.Unsealed++
			} else if !v.line(path, lineNo, line, first) {
				return nil
			}
			if v.rep.Break != nil {
				return nil
			}
		}
		if errors.Is(err, io.EOF) {
			if v.pendingCut != nil && v.rep.Break == nil {
				v.rep.Break, v.pendingCut = v.pendingCut, nil
			}
			return nil
		}
	}
}

// isCorruptArchive tells a damaged gzip stream apart from an I/O error.
func isCorruptArchive(err error) bool {
	var corrupt flate.CorruptInputError
	return errors.Is(err, gzip.ErrChecksum) || errors.Is(err, gzip.ErrHeader) ||
		errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &corrupt)
}

// line verifies one complete line. It returns false when verification must
// stop without a break (a key is needed).
func (v *verifier) line(path string, lineNo int, line []byte, first bool) bool {
	if bytes.HasPrefix(bytes.TrimLeft(line, " \t"), metaLinePrefix) {
		var env metaEnvelope
		if err := json.Unmarshal(line, &env); err != nil {
			if v.sealing() {
				v.fail(path, lineNo, "the _meta line is not valid JSON")
			}
			return true
		}
		if cut := v.pendingCut; cut != nil {
			v.pendingCut = nil
			m := env.Meta
			wantSeq, wantPrev := uint64(0), ""
			if v.started {
				wantSeq, wantPrev = v.nextSeq-1, v.lastHash
			}
			if lineNo == 1 || m.Seal == nil || m.ChainSeq != wantSeq || m.ChainPrev != wantPrev {
				v.rep.Break = cut
				return true
			}
			v.rep.Warnings = append(v.rep.Warnings, fmt.Sprintf("%s:%d is a line cut short by an interrupted write; the chain resumes after it with nothing missing", cut.File, cut.Line))
		}
		if lineNo == 1 {
			v.header(path, &env.Meta, first)
		}
		if v.rep.Break == nil && env.Meta.Seal != nil {
			return v.setSeal(path, lineNo, env.Meta.Seal)
		}
		return true
	}

	var e struct {
		Seq      uint64 `json:"seq"`
		PrevHash string `json:"prev_hash"`
		Hash     string `json:"hash"`
	}
	if v.pendingCut != nil {
		// Two bad lines in a row, or a cut line followed by an entry rather
		// than the logger's resume line: the cut line is the break.
		v.rep.Break = v.pendingCut
		return true
	}
	if err := json.Unmarshal(line, &e); err != nil {
		if v.sealing() {
			v.pendingCut = &VerifyBreak{File: filepath.Base(path), Line: lineNo, Reason: "the line is not valid JSON: it was changed"}
		} else {
			v.rep.Unsealed++
		}
		return true
	}
	if e.Hash == "" {
		if v.sealing() {
			v.fail(path, lineNo, "the entry has no hash, but the log is sealed from an earlier line: it was inserted, or sealing was turned off")
		} else {
			v.rep.Unsealed++
		}
		return true
	}
	if v.seal == nil {
		v.fail(path, lineNo, "the entry is sealed but no _meta line before it says how")
		return true
	}
	body, sum, ok := splitSealedLine(line)
	if !ok || sum != e.Hash {
		v.fail(path, lineNo, `the hash field is malformed or is not the last field of the line`)
		return true
	}
	v.h.Reset()
	v.h.Write(body)
	if want := hex.EncodeToString(v.h.Sum(nil)); want != sum {
		v.fail(path, lineNo, "hash mismatch: the entry was changed after it was written (or it was sealed with another key)")
		return true
	}

	switch {
	case !v.started:
		if e.Seq != 1 || e.PrevHash != "" {
			v.fail(path, lineNo, "the first sealed entry has seq %d, not 1: the entries before it are missing", e.Seq)
			return true
		}
		v.started = true
		v.rep.FirstSeq = 1
	case e.Seq == 1 && e.PrevHash == "":
		v.fail(path, lineNo, "the chain starts over at seq 1 after seq %d: the log was reset or the entries before this one replaced", v.nextSeq-1)
		return true
	case e.Seq != v.nextSeq:
		v.fail(path, lineNo, "seq gap: expected seq %d, found %d (entries removed, added or reordered)", v.nextSeq, e.Seq)
		return true
	case e.PrevHash != v.lastHash:
		v.fail(path, lineNo, "prev_hash mismatch: the entry does not follow the one before it (lines spliced in from elsewhere)")
		return true
	}

	if _, want := v.anchors[e.Seq]; want {
		v.anchors[e.Seq] = e.Hash
	}
	if e.Seq > 1 {
		// prev_hash is covered by this entry's hash, so it also vouches for
		// the previous entry's hash — which checks an anchor at the last
		// pruned seq too.
		if found, want := v.anchors[e.Seq-1]; want && found == "" {
			v.anchors[e.Seq-1] = e.PrevHash
		}
	}
	if v.seal.Alg == SealAlgHMACSHA256 {
		v.sawHMAC = true
	}
	v.rep.Entries++
	v.rep.LastSeq, v.rep.LastHash = e.Seq, e.Hash
	v.nextSeq, v.lastHash = e.Seq+1, e.Hash
	return true
}

// header checks how a file's first line links it to the files before it.
func (v *verifier) header(path string, m *MetaRecord, first bool) {
	linked := m.ChainSeq > 0 || m.ChainPrev != ""
	switch {
	case first:
		if linked {
			// The files this one continues were pruned. Its chain_prev is
			// vouched for by the first entry's prev_hash.
			v.rep.PrunedBefore = m.ChainSeq
			v.rep.FirstSeq = m.ChainSeq + 1
			v.started = true
			v.nextSeq, v.lastHash = m.ChainSeq+1, m.ChainPrev
		}
	case v.started:
		if m.Seal == nil {
			v.fail(path, 1, "segment link broken: this file is not sealed but the files before it are")
		} else if m.ChainSeq != v.nextSeq-1 {
			v.fail(path, 1, "segment link broken: the header says the previous file ends at seq %d, but it ends at seq %d", m.ChainSeq, v.nextSeq-1)
		} else if m.ChainPrev != v.lastHash {
			v.fail(path, 1, "segment link broken: the header's chain_prev %s is not the previous file's last hash %s", shortHash(m.ChainPrev), shortHash(v.lastHash))
		}
	case linked:
		v.fail(path, 1, "segment link broken: the header continues a chain at seq %d that the files before it don't have", m.ChainSeq)
	}
}

// setSeal switches to the sealing a _meta line declares.
func (v *verifier) setSeal(path string, lineNo int, s *SealInfo) bool {
	switch s.Alg {
	case SealAlgHMACSHA256:
		key, ok := v.keys[s.KeyID]
		if !ok {
			if len(v.keys) == 0 {
				v.keyNeeded = &SealKeyNeededError{KeyID: s.KeyID, File: filepath.Base(path)}
				return false
			}
			v.fail(path, lineNo, "sealed with key id %s, but no --key-file has that id (yours: %s)", s.KeyID, strings.Join(v.keyIDs(), ", "))
			return true
		}
		v.h = hmac.New(sha256.New, key)
	case SealAlgSHA256:
		if v.sawHMAC {
			v.fail(path, lineNo, "sealing switches from an HMAC key to plain SHA-256 here: the entries after this line could have been rewritten by anyone")
			return true
		}
		v.h = sha256.New()
	default:
		v.fail(path, lineNo, "unknown seal algorithm %q", s.Alg)
		return true
	}
	if v.seal == nil || *v.seal != *s {
		desc := s.Alg
		if s.KeyID != "" {
			desc += " key " + s.KeyID
		}
		if n := len(v.rep.Seals); n == 0 || v.rep.Seals[n-1] != desc {
			v.rep.Seals = append(v.rep.Seals, desc)
		}
	}
	info := *s
	v.seal = &info
	return true
}

func (v *verifier) keyIDs() []string {
	ids := make([]string, 0, len(v.keys))
	for id := range v.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// shortHash shortens a hash for messages.
func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12] + "…"
	}
	if h == "" {
		return "(none)"
	}
	return h
}
