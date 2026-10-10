package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// writeSegment writes an audit file holding only the given header.
func writeSegment(t *testing.T, path string, m MetaRecord) {
	t.Helper()
	b, err := json.Marshal(metaEnvelope{Meta: m})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestPlanReplaySegments_SameCreatedAtDifferentSegments is the regression test
// for the flaky TestReplayWithCheckpoint_FollowsRotationChain (seen on Windows
// CI). Files were identified by `_meta.created_at`, and a coarse clock can give
// a file and its successor the same timestamp. Replay then took the live file
// for the checkpointed one and resumed at a byte offset inside the wrong file,
// skipping every entry in the archive.
func TestPlanReplaySegments_SameCreatedAtDifferentSegments(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "audit.jsonl")
	archive := filepath.Join(dir, "audit.jsonl.20261010T000000Z")
	same := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)

	old := MetaRecord{SchemaVersion: CurrentSchemaVersion, CreatedAt: same, SegmentID: "aaaa"}
	cur := MetaRecord{SchemaVersion: CurrentSchemaVersion, CreatedAt: same, SegmentID: "bbbb",
		RotatedFrom: filepath.Base(archive)}
	writeSegment(t, archive, old)
	writeSegment(t, live, cur)

	cp := &Checkpoint{Offset: 10, FileID: fileIDOf(&old), Counts: &DecisionCounts{}}
	segs := planReplaySegments(live, 1000, &cur, cp)

	if len(segs) != 2 {
		t.Fatalf("got %d segments %+v, want the archive then the live file", len(segs), segs)
	}
	if segs[0].path != archive || segs[0].start != cp.Offset {
		t.Errorf("first segment = %+v, want %s from offset %d", segs[0], archive, cp.Offset)
	}
	if segs[1].path != live || segs[1].start != 0 {
		t.Errorf("second segment = %+v, want %s from 0", segs[1], live)
	}
}

// TestFileIDOf_PreV14HeadersKeepTheirIdentity: a header written before v1.4 has
// no segment_id, and checkpoints written then stored its created_at. Upgrading
// must not make those checkpoints stop matching.
func TestFileIDOf_PreV14HeadersKeepTheirIdentity(t *testing.T) {
	at := time.Date(2026, 9, 1, 12, 0, 0, 123456789, time.UTC)
	legacy := &MetaRecord{SchemaVersion: CurrentSchemaVersion, CreatedAt: at}
	if got, want := fileIDOf(legacy), at.Format(time.RFC3339Nano); got != want {
		t.Errorf("fileIDOf(pre-v1.4 header) = %q, want %q", got, want)
	}
	if got := fileIDOf(&MetaRecord{CreatedAt: at, SegmentID: "abc"}); got != "abc" {
		t.Errorf("fileIDOf prefers segment_id: got %q", got)
	}
	if got := fileIDOf(nil); got != "" {
		t.Errorf("fileIDOf(nil) = %q, want empty", got)
	}
}

// TestNewFiles_GetDistinctSegmentIDs: every header the logger writes (a new
// file, and each file rotation opens) carries its own segment_id.
func TestNewFiles_GetDistinctSegmentIDs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := NewFileLoggerWithRotation(path, RotationConfig{MaxSize: 400})
	if err != nil {
		t.Fatal(err)
	}
	first, err := readMetaAny(path)
	if err != nil || first == nil {
		t.Fatalf("read first header: %v", err)
	}
	rotateOnce(t, l, dir, "seg", policy.Allow)
	l.Close()
	second, err := readMetaAny(path)
	if err != nil || second == nil {
		t.Fatalf("read header after rotation: %v", err)
	}
	if len(first.SegmentID) != 32 || len(second.SegmentID) != 32 {
		t.Fatalf("segment ids %q and %q, want 32 hex characters each", first.SegmentID, second.SegmentID)
	}
	if first.SegmentID == second.SegmentID {
		t.Error("rotation reused the previous file's segment_id")
	}
}
