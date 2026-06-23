package main

// audit_setup.go assembles the audit trail for `agentguard serve`:
// backend selection (JSONL file vs durable store), startup migrations,
// rotation, and the async buffering that keeps audit I/O off the
// /v1/check hot path. Extracted from runServe so the construction rules
// and the shutdown ordering are testable instead of living as a tangle
// of branches and LIFO defers in main.

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/migrate"
	"github.com/Caua-ferraz/AgentGuard/pkg/store"
)

// auditPipeline is the constructed audit logger plus its shutdown
// sequence. Close runs the cleanups in registered order — drain the
// async buffer first, then close the base logger — making the order
// explicit instead of relying on defer LIFO interleaving in runServe.
// The store itself (when the backend is "store") is NOT closed here;
// its lifecycle belongs to whoever opened it, and it must outlive the
// buffer drain.
type auditPipeline struct {
	Logger   audit.Logger
	cleanups []func() error
}

// Close shuts the pipeline down in order. Errors are logged, not
// returned: at shutdown there is nobody left to retry, but the operator
// must see a failed drain (it means buffered entries spilled to the
// overflow file or were lost).
func (p *auditPipeline) Close() {
	for _, fn := range p.cleanups {
		if err := fn(); err != nil {
			log.Printf("WARNING: audit shutdown: %v", err)
		}
	}
}

// buildAuditPipeline constructs the audit trail per the serve flags.
// st must be non-nil when storeAudit is true.
//
// Contract rule #1 (Latency is God): a store-backed audit logger writes
// to SQLite, which must never happen synchronously on the /v1/check
// path — so the store backend forces async buffering even if the
// operator passed --audit-buffered=false (fine for the cheap file
// append; a DB write per request would blow the <3ms budget).
func buildAuditPipeline(auditPath string, storeAudit bool, st store.Store, rotOpts auditRotationOpts, bufOpts auditBufferedOpts) (*auditPipeline, error) {
	if storeAudit && !bufOpts.Enabled {
		log.Printf("WARNING: --audit-backend=store requires async buffering to keep DB writes off the /v1/check hot path; forcing --audit-buffered=true.")
		bufOpts.Enabled = true
	}

	p := &auditPipeline{}

	if storeAudit {
		p.Logger = store.NewAuditLogger(st)
	} else {
		// Run startup migrations BEFORE opening the file audit logger. An
		// in-place rewrite (e.g. v040_to_v041 prepending a _meta header)
		// has to happen before we start appending new entries — otherwise
		// the next write would land in a file the migration is about to
		// rename.
		migEnv := migrate.Env{
			AuditLogPath:   auditPath,
			CheckpointPath: auditPath + audit.CheckpointSuffix,
		}
		if err := migrate.RunStartup(context.Background(), migEnv); err != nil {
			return nil, fmt.Errorf("startup migration: %w", err)
		}

		// Rotation is on by default (100 MiB live cap, 30-day retention,
		// 5 archives, gzip). Setting --audit-max-size-mb=0 disables
		// rotation entirely (unbounded growth).
		rotCfg := audit.RotationConfig{
			MaxFiles: rotOpts.MaxBackups,
			Compress: rotOpts.Compress,
		}
		if rotOpts.MaxSizeMB > 0 {
			rotCfg.MaxSize = int64(rotOpts.MaxSizeMB) * 1024 * 1024
		}
		if rotOpts.MaxAgeDays > 0 {
			rotCfg.MaxAge = time.Duration(rotOpts.MaxAgeDays) * 24 * time.Hour
		}

		var fileLogger *audit.FileLogger
		var err error
		if rotCfg.MaxSize > 0 || rotCfg.MaxFiles > 0 || rotCfg.MaxAge > 0 {
			fileLogger, err = audit.NewFileLoggerWithRotation(auditPath, rotCfg)
		} else {
			fileLogger, err = audit.NewFileLogger(auditPath)
		}
		if err != nil {
			return nil, fmt.Errorf("audit log: %w", err)
		}
		p.Logger = fileLogger
		p.cleanups = append(p.cleanups, fileLogger.Close)
	}

	if bufOpts.Enabled {
		overflowPath := bufOpts.OverflowPath
		if overflowPath == "" {
			overflowPath = auditPath + ".overflow.jsonl"
		}
		bufLogger, err := audit.NewBufferedAsyncLogger(p.Logger, audit.BufferedAsyncOpts{
			QueueSize:    bufOpts.QueueSize,
			Workers:      bufOpts.Workers,
			OverflowPath: overflowPath,
		})
		if err != nil {
			return nil, fmt.Errorf("buffered audit logger: %w", err)
		}
		// Drain runs before the base logger's Close (prepend keeps the
		// cleanup list in run order).
		p.Logger = bufLogger
		p.cleanups = append([]func() error{bufLogger.Close}, p.cleanups...)
	}

	return p, nil
}
