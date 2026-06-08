package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// PutPolicy stores (or replaces) the policy document for a tenant. The bytes
// are stored verbatim; validation is the caller's responsibility (the CLI and
// MultiTenantProvider validate before/after). Rejects an empty tenant.
func (s *SQLiteStore) PutPolicy(ctx context.Context, tenantID string, policyYAML []byte) error {
	if tenantID == "" {
		return ErrTenantRequired
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO policies (tenant_id, policy_yaml, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(tenant_id) DO UPDATE SET
			policy_yaml=excluded.policy_yaml, updated_at=excluded.updated_at`,
		tenantID, string(policyYAML), fmtTime(time.Now().UTC()))
	if err != nil {
		return fmt.Errorf("store: put policy %q: %w", tenantID, err)
	}
	return nil
}

// GetPolicyYAML returns the stored policy document for a tenant. ok=false when
// the tenant has no policy row (distinct from an error).
func (s *SQLiteStore) GetPolicyYAML(ctx context.Context, tenantID string) ([]byte, bool, error) {
	if tenantID == "" {
		return nil, false, ErrTenantRequired
	}
	var y string
	err := s.db.QueryRowContext(ctx, `SELECT policy_yaml FROM policies WHERE tenant_id = ?`, tenantID).Scan(&y)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("store: get policy %q: %w", tenantID, err)
	}
	return []byte(y), true, nil
}

// ListPolicyTenants returns every tenant id that has a stored policy, sorted.
// Used by MultiTenantProvider to eager-load all tenants on boot.
func (s *SQLiteStore) ListPolicyTenants(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT tenant_id FROM policies ORDER BY tenant_id`)
	if err != nil {
		return nil, fmt.Errorf("store: list policy tenants: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return out, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeletePolicy removes a tenant's policy. ok reports whether a row existed.
func (s *SQLiteStore) DeletePolicy(ctx context.Context, tenantID string) (bool, error) {
	if tenantID == "" {
		return false, ErrTenantRequired
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM policies WHERE tenant_id = ?`, tenantID)
	if err != nil {
		return false, fmt.Errorf("store: delete policy %q: %w", tenantID, err)
	}
	return rowsAffected(res) > 0, nil
}
