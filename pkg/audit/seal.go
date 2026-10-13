package audit

// seal.go — the optional tamper-evident hash chain of the file backend
// (v1.4, `agentguard server --audit-seal`).
//
// Each sealed entry carries seq (1, 2, 3, ... across rotations), prev_hash
// (the hash of the entry before it) and hash. The hash covers the entry's
// exact bytes as written, minus the hash field itself, so any program that
// can read a line and run SHA-256 or HMAC-SHA256 can check it without
// re-encoding JSON:
//
//	line := `{...,"seq":7,"prev_hash":"ab..","hash":"cd.."}`
//	body := line minus its trailing `,"hash":"<64 hex>"}`, plus `}`
//	hash == hex(HMAC-SHA256(key, body))   or   hex(SHA-256(body)) without a key
//
// Sealing is not encryption: entries stay readable. It makes edits,
// deletions and reordering detectable by `agentguard audit verify`. Without
// a key anyone who can write the file can recompute the chain, so a plain
// SHA-256 chain only catches naive edits; anchors published off the box
// (see Anchor) are what pin the head.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
)

// Seal algorithms, as written in MetaRecord.Seal.Alg.
const (
	SealAlgHMACSHA256 = "hmac-sha256"
	SealAlgSHA256     = "sha256"
)

// SealInfo is the `seal` object of a `_meta` line: how the entries after it
// are sealed. KeyID identifies the HMAC key without revealing it (see
// SealKeyID); it is empty for plain SHA-256.
type SealInfo struct {
	Alg   string `json:"alg"`
	KeyID string `json:"key_id,omitempty"`
}

// SealConfig turns sealing on for a FileLogger.
type SealConfig struct {
	// Key is the HMAC-SHA256 key. Empty means a plain SHA-256 chain.
	Key []byte
	// NodeID is written into each header as node_id (the server's
	// --node-id), so a verifier can tell which node wrote a file.
	NodeID string
}

// SealKeyID returns the key's public identifier: the hex of the first 8
// bytes of SHA-256(key).
func SealKeyID(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:8])
}

func (c SealConfig) info() SealInfo {
	if len(c.Key) == 0 {
		return SealInfo{Alg: SealAlgSHA256}
	}
	return SealInfo{Alg: SealAlgHMACSHA256, KeyID: SealKeyID(c.Key)}
}

// LoadSealKey reads an HMAC seal key file. The key is the file's content
// with surrounding whitespace removed, so a hex key written by `agentguard
// setup` or `openssl rand -hex 32 > key` works as is. With strictPerms (the
// server), a key file that other users can read is refused on Unix: anyone
// holding the key can forge a valid chain.
func LoadSealKey(path string, strictPerms bool) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("seal key file: %w", err)
	}
	if strictPerms && runtime.GOOS != "windows" && info.Mode().Perm()&0o004 != 0 {
		return nil, fmt.Errorf("seal key file %s can be read by every user on this machine; run 'chmod 600 %s'", path, path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("seal key file: %w", err)
	}
	key := bytes.TrimSpace(b)
	if len(key) == 0 {
		return nil, fmt.Errorf("seal key file %s is empty; put a random key in it (e.g. 'openssl rand -hex 32 > %s')", path, path)
	}
	return key, nil
}

// Anchor is a published head of the chain: the entry with this seq has this
// hash. Copied somewhere the audit host cannot rewrite (a SIEM, a ticket),
// it lets `agentguard audit verify --anchor seq:hash` prove that nothing up
// to seq was changed or removed afterwards, even by someone holding the key.
type Anchor struct {
	SegmentID string    `json:"segment_id"`
	Seq       uint64    `json:"seq"`
	Hash      string    `json:"hash"`
	At        time.Time `json:"at"`
}

// SealHeader is implemented by loggers that can report the head of a sealed
// chain (FileLogger, and the wrappers that forward to one). ok is false when
// sealing is off.
type SealHeader interface {
	SealHead() (a Anchor, ok bool)
}

// sealer is a FileLogger's chain state. Every field is guarded by the
// logger's mu: entries are sealed in file order because they are sealed
// under the same lock that writes them.
type sealer struct {
	cfg  SealConfig
	info SealInfo
	h    hash.Hash // HMAC or SHA-256; Reset before each use

	seq     uint64 // seq of the last sealed entry (0: none yet)
	last    string // its hash
	headSeg string // segment_id of the file that holds it

	anchoredSeq uint64 // seq of the last published anchor
}

func newSealer(cfg SealConfig) *sealer {
	s := &sealer{cfg: cfg, info: cfg.info()}
	if len(cfg.Key) > 0 {
		s.h = hmac.New(sha256.New, cfg.Key)
	} else {
		s.h = sha256.New()
	}
	return s
}

// sum returns the hex hash of b under this sealer's algorithm and key.
func (s *sealer) sum(b []byte) string {
	s.h.Reset()
	s.h.Write(b)
	return hex.EncodeToString(s.h.Sum(nil))
}

// line seals e as the next entry of the chain and returns the bytes to
// write (newline included) with the new seq and hash. It does not advance
// the chain; call advance once the write succeeded.
func (s *sealer) line(e Entry) ([]byte, uint64, string, error) {
	e.Seq = s.seq + 1
	e.PrevHash = s.last
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		return nil, 0, "", err
	}
	h := s.sum(b)
	out := make([]byte, 0, len(b)+len(hashFieldPrefix)+len(h)+3)
	out = append(out, b[:len(b)-1]...) // drop the closing brace
	out = append(out, hashFieldPrefix...)
	out = append(out, h...)
	out = append(out, '"', '}', '\n')
	return out, e.Seq, h, nil
}

func (s *sealer) advance(seq uint64, h, segID string) {
	s.seq, s.last, s.headSeg = seq, h, segID
}

// meta fills the seal fields of a header (or of the mid-file `_meta` line
// written when sealing resumes on an existing file).
func (s *sealer) meta(m *MetaRecord) {
	info := s.info
	m.Seal = &info
	m.ChainPrev = s.last
	m.ChainSeq = s.seq
	m.NodeID = s.cfg.NodeID
}

func (s *sealer) head() Anchor {
	return Anchor{SegmentID: s.headSeg, Seq: s.seq, Hash: s.last, At: time.Now().UTC()}
}

// hashFieldPrefix is what precedes the hex hash at the end of a sealed line.
const hashFieldPrefix = `,"hash":"`

// sealedLineSuffixLen is len(`,"hash":"` + 64 hex + `"}`).
const sealedLineSuffixLen = len(hashFieldPrefix) + 64 + 2

// splitSealedLine returns the bytes a sealed line's hash covers and the hash
// it carries. line has no trailing newline. ok is false when the line does
// not end with a well-formed hash field.
func splitSealedLine(line []byte) (body []byte, sum string, ok bool) {
	if len(line) < sealedLineSuffixLen+2 {
		return nil, "", false
	}
	cut := len(line) - sealedLineSuffixLen
	suffix := line[cut:]
	if !bytes.HasPrefix(suffix, []byte(hashFieldPrefix)) || !bytes.HasSuffix(suffix, []byte(`"}`)) {
		return nil, "", false
	}
	hexSum := suffix[len(hashFieldPrefix) : len(suffix)-2]
	for _, c := range hexSum {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return nil, "", false
		}
	}
	body = make([]byte, 0, cut+1)
	body = append(body, line[:cut]...)
	body = append(body, '}')
	return body, string(hexSum), true
}

// SealHead reports the head of the chain: the last sealed entry's seq, hash
// and segment. ok is false when sealing is off. It takes the logger's lock
// briefly and does no I/O.
func (l *FileLogger) SealHead() (Anchor, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seal == nil {
		return Anchor{}, false
	}
	return l.seal.head(), true
}

// SealHead forwards to the wrapped logger.
func (l *transformLogger) SealHead() (Anchor, bool) {
	if h, ok := l.inner.(SealHeader); ok {
		return h.SealHead()
	}
	return Anchor{}, false
}

// SealHead forwards to the underlying logger. Entries still in the queue are
// not part of the chain yet, so the head can trail the newest request.
func (b *BufferedAsyncLogger) SealHead() (Anchor, bool) {
	if h, ok := b.underlying.(SealHeader); ok {
		return h.SealHead()
	}
	return Anchor{}, false
}

// publishAnchorLocked writes the chain head to the log (which reaches
// journald, syslog or a SIEM) and to the agentguard_audit_seal_seq gauge,
// unless nothing was sealed since the last anchor. Caller holds l.mu.
func (l *FileLogger) publishAnchorLocked() {
	s := l.seal
	if s == nil || s.seq == 0 || s.seq == s.anchoredSeq {
		return
	}
	a := s.head()
	log.Printf("audit anchor segment=%s seq=%d hash=%s", a.SegmentID, a.Seq, a.Hash)
	metrics.SetAuditSealSeq(a.Seq)
	s.anchoredSeq = a.Seq
}

// StartAnchoring publishes an anchor every interval (when something was
// sealed since the last one) until stop is called. Anchors are also
// published at each rotation and on Close. It is a no-op when sealing is
// off or interval <= 0. The ticker runs on its own goroutine and only takes
// the logger's lock for an in-memory read: no anchor work reaches the
// /v1/check path.
func (l *FileLogger) StartAnchoring(interval time.Duration) (stop func()) {
	l.mu.Lock()
	sealed := l.seal != nil
	l.mu.Unlock()
	if !sealed || interval <= 0 {
		return func() {}
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				l.mu.Lock()
				l.publishAnchorLocked()
				l.mu.Unlock()
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(done)
			<-finished
		})
	}
}

// maxTailRead bounds how much of an existing live file resumeSeal reads
// back from its end: one maximum-size line (the 4 MiB readers accept) plus
// a byte, so the last line is always seen whole.
const maxTailRead = 4*1024*1024 + 1

// sealTail is what the end of an existing live file says about the chain.
type sealTail struct {
	seq     uint64
	hash    string
	headSeg string
	// partial is true when the file does not end with a newline: the last
	// write was cut short (a crash mid-write).
	partial bool
	// lastMeta is the last line when it is a `_meta` line, so a restart that
	// would write an identical seal line can skip it.
	lastMeta *MetaRecord
}

// readSealTail reads the end of the live file at path to recover the chain
// head: the last sealed entry's seq and hash, or the chain_seq/chain_prev of
// the newest `_meta` line when no entry follows it. liveSeg is the file's
// own segment_id. An unsealed last entry means no chain to continue.
func readSealTail(path, liveSeg string) (sealTail, error) {
	var t sealTail
	f, err := os.Open(path)
	if err != nil {
		return t, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return t, err
	}
	size := info.Size()
	if size == 0 {
		return t, nil
	}
	n := size
	if n > maxTailRead {
		n = maxTailRead
	}
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, size-n); err != nil && !errors.Is(err, io.EOF) {
		return t, err
	}
	whole := n == size // buf starts at the first line of the file

	if buf[len(buf)-1] != '\n' {
		t.partial = true
		i := bytes.LastIndexByte(buf, '\n')
		buf = buf[:i+1] // i == -1 leaves nothing
	}
	lines := bytes.Split(bytes.TrimSuffix(buf, []byte{'\n'}), []byte{'\n'})
	if !whole && len(lines) > 0 {
		lines = lines[1:] // starts mid-line
	}

	found := false // seq and hash are known; now only the segment is sought
	for i := len(lines) - 1; i >= 0; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 {
			continue
		}
		isHeader := whole && i == 0
		if bytes.HasPrefix(line, metaLinePrefix) {
			var env metaEnvelope
			if json.Unmarshal(line, &env) != nil {
				continue
			}
			if i == len(lines)-1 {
				m := env.Meta
				t.lastMeta = &m
			}
			if !found {
				t.seq, t.hash = env.Meta.ChainSeq, env.Meta.ChainPrev
				if t.seq == 0 {
					return t, nil // nothing was sealed before this line
				}
				found = true
			}
			if isHeader {
				// No entry in this file yet: the head is the last entry of
				// the file it was rotated from.
				if env.Meta.RotatedFrom != "" {
					if m, err := readMetaAny(filepath.Join(filepath.Dir(path), filepath.Base(env.Meta.RotatedFrom))); err == nil && m != nil {
						t.headSeg = m.SegmentID
					}
				}
				return t, nil
			}
			continue
		}
		var e struct {
			Seq  uint64 `json:"seq"`
			Hash string `json:"hash"`
		}
		if json.Unmarshal(line, &e) != nil {
			continue // corrupt line: keep looking back
		}
		if !found {
			if e.Hash == "" {
				return sealTail{partial: t.partial}, nil // unsealed: start a new chain
			}
			t.seq, t.hash = e.Seq, e.Hash
		}
		t.headSeg = liveSeg
		return t, nil
	}
	if found {
		t.headSeg = liveSeg
	}
	return t, nil
}

// resumeSeal continues the chain of an existing live file: it recovers the
// head from the file's end, compares it with the replay checkpoint, and
// appends a `_meta` line recording how the entries after it are sealed.
// Caller holds l.mu (or owns l exclusively, as the constructor does).
func (l *FileLogger) resumeSeal(path string) error {
	t, err := readSealTail(path, l.segID)
	if err != nil {
		return fmt.Errorf("read the end of the audit log to continue its seal: %w", err)
	}
	if t.partial {
		// End the cut line so the next entry starts on a line of its own.
		// verify reports the cut line; the chain continues from the last
		// whole entry before it.
		log.Printf("WARNING audit: %s ends with an incomplete line (a write was cut short); continuing the seal chain from the last whole entry", path)
		if _, err := l.file.Write([]byte{'\n'}); err != nil {
			return fmt.Errorf("terminate incomplete audit line: %w", err)
		}
	}
	l.seal.advance(t.seq, t.hash, t.headSeg)
	l.seal.anchoredSeq = 0

	if cp, err := ReadCheckpoint(path); err == nil && cp != nil && cp.LastSeq > 0 {
		if t.seq < cp.LastSeq || (t.seq == cp.LastSeq && t.hash != cp.LastHash) {
			log.Printf("WARNING audit: %s ends at seq %d (hash %s) but the replay checkpoint recorded seq %d (hash %s): entries may have been removed (possible truncation). Run 'agentguard audit verify'.",
				path, t.seq, t.hash, cp.LastSeq, cp.LastHash)
			metrics.IncAuditSealTailMismatch()
		}
	}

	m := MetaRecord{SchemaVersion: CurrentSchemaVersion, CreatedAt: time.Now().UTC(), SegmentID: l.segID}
	l.seal.meta(&m)
	// A restart with nothing written since the last one finds a line that
	// already says the same; writing it again would only grow the file.
	if t.partial || t.lastMeta == nil || !sameSealState(t.lastMeta, &m) {
		if err := l.enc.Encode(metaEnvelope{Meta: m}); err != nil {
			return fmt.Errorf("write seal header: %w", err)
		}
	}
	l.publishAnchorLocked()
	return nil
}

func sameSealState(a, b *MetaRecord) bool {
	return a.Seal != nil && b.Seal != nil && *a.Seal == *b.Seal &&
		a.ChainPrev == b.ChainPrev && a.ChainSeq == b.ChainSeq && a.NodeID == b.NodeID
}
