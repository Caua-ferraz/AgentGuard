package store

import (
	"context"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
)

// auditLoggerAdapter adapts a Store's AuditSink to the audit.Logger interface,
// so a store-backed audit trail can be wrapped by audit.BufferedAsyncLogger and
// consumed by the proxy exactly like a FileLogger — the request path still only
// enqueues (write-behind), never blocking on the DB.
//
// Query delegates to the tenant-scoped QueryAudit: filter.TenantID selects the
// tenant (empty = all tenants, the operator/global view). Close is a no-op
// because the Store's lifecycle is owned by whoever opened it.
type auditLoggerAdapter struct{ s Store }

// NewAuditLogger returns an audit.Logger backed by the given Store.
func NewAuditLogger(s Store) audit.Logger { return auditLoggerAdapter{s: s} }

func (a auditLoggerAdapter) Log(e audit.Entry) error {
	return a.s.AppendAudit(context.Background(), []audit.Entry{e})
}

func (a auditLoggerAdapter) Query(f audit.QueryFilter) ([]audit.Entry, error) {
	return a.s.QueryAudit(context.Background(), f.TenantID, f)
}

func (a auditLoggerAdapter) Close() error { return nil }
