package audit

import (
	"log"
)

// Checkpointer is implemented by loggers that can keep the replay
// checkpoint current themselves (FileLogger, and the wrappers that forward to
// one).
type Checkpointer interface {
	// EnableCheckpoints starts checkpoint maintenance from the lifetime tally
	// initial, which covers the live file up to atOffset. It reports whether
	// the logger (or the logger it wraps) supports it.
	EnableCheckpoints(initial DecisionCounts, atOffset int64) bool
}

// EnableCheckpoints makes the FileLogger maintain <path>.replay-checkpoint
// from now on. It counts every entry it writes on top of initial (the tally
// the startup replay produced through atOffset, including entries appended
// since, e.g. by an overflow drain) and writes the checkpoint after every
// rotation — before old archives are pruned — and on Close.
//
// Without it the checkpoint is only written at startup; once rotation prunes
// the file it points to, the next startup can only recount the files that
// are left.
func (l *FileLogger) EnableCheckpoints(initial DecisionCounts, atOffset int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	path := l.file.Name()
	counts := initial
	if info, err := l.file.Stat(); err == nil && info.Size() > atOffset {
		if err := replayFile(path, atOffset, func(e Entry) { counts.add(e.Result.Decision) }); err != nil {
			log.Printf("WARN audit: counting entries written after the startup replay: %v", err)
		}
	}
	l.cpCounts = counts
	l.cpEnabled = true
	if m, err := ReadMeta(path); err == nil {
		l.cpFileID = fileIDOf(m)
	}
	return true
}

// writeCheckpointLocked persists the checkpoint for the live file's current
// end. The caller holds l.mu. A failure is logged; the next startup then
// resumes from the previous checkpoint.
func (l *FileLogger) writeCheckpointLocked() {
	info, err := l.file.Stat()
	if err != nil {
		log.Printf("WARN audit: replay checkpoint not written (stat %s: %v)", l.file.Name(), err)
		return
	}
	counts := l.cpCounts
	cp := Checkpoint{Offset: info.Size(), AuditSize: info.Size(), FileID: l.cpFileID, Counts: &counts}
	if err := WriteCheckpoint(l.file.Name(), cp); err != nil {
		log.Printf("WARN audit: replay checkpoint not written: %v", err)
	}
}

// EnableCheckpoints forwards to the wrapped logger.
func (l *transformLogger) EnableCheckpoints(initial DecisionCounts, atOffset int64) bool {
	if c, ok := l.inner.(Checkpointer); ok {
		return c.EnableCheckpoints(initial, atOffset)
	}
	return false
}

// EnableCheckpoints forwards to the underlying logger.
func (b *BufferedAsyncLogger) EnableCheckpoints(initial DecisionCounts, atOffset int64) bool {
	if c, ok := b.underlying.(Checkpointer); ok {
		return c.EnableCheckpoints(initial, atOffset)
	}
	return false
}
