package proxy

// Tenant ID propagation for the URL routing layer.
//
// Two URL families coexist:
//
//   - Legacy /v1/...                 — always evaluates against tenant "local".
//   - Tenant-aware /v1/t/{tenant}/... — extracts the tenant from the URL.
//
// Both families flow through the same handler chain. The handler reads the
// effective tenant via TenantIDFromContext, defaulting to LocalTenantID when
// nothing is set (the legacy path). The tenant value is currently consumed
// only by Engine.Check; the approval queue, audit log, SSE bus, and rate
// limiter are still single-tenant.
//
// TODO(v0.6): shard ApprovalQueue / SSE bus / audit query / rate limiter
// by tenantID. Today the tenant ID is threaded through the request context
// but only Engine.Check actually partitions on it.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// tenantCtxKeyT is the unexported context-key type for the tenant ID. Using
// a typed key keeps the value out of the context.WithValue type-safety
// gotchas (a string key would collide with any caller that happens to use
// the same string).
type tenantCtxKeyT struct{}

var tenantCtxKey = tenantCtxKeyT{}

// WithTenantID returns a context derived from ctx that carries tenantID.
// Empty values are stored verbatim; readers (TenantIDFromContext) decide
// how to default.
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantCtxKey, tenantID)
}

// TenantIDFromContext returns the tenant ID stamped on ctx by withTenant,
// or LocalTenantID when nothing is set (legacy /v1/... routes that did not
// run through withTenant). The empty string is also coerced to
// LocalTenantID so callers never have to special-case it.
func TenantIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(tenantCtxKey).(string); ok && v != "" {
		return v
	}
	return policy.LocalTenantID
}

// withTenant is the route middleware applied to every /v1/t/{tenant}/...
// route. It extracts the tenant via r.PathValue("tenant") (Go 1.22+
// wildcard syntax), validates it against the engine's PolicyProvider,
// stamps it on the request context, and forwards to the wrapped handler.
//
// Validation policy:
//   - Empty tenant — coerced to LocalTenantID. The mux never actually
//     produces an empty match for `{tenant}` (Go 1.22+ requires the
//     segment to be non-empty), but defensive coercion keeps the
//     behavior predictable if a future router rewrite changes that.
//   - tenant == LocalTenantID — fast-path: skip the provider lookup so
//     the hot path stays equivalent to the legacy URL family.
//   - Any other tenant — consult Engine.PolicyForTenant. ErrTenantNotFound
//     surfaces as 404 + structured JSON body. Any other error is
//     surfaced as 500 (provider infrastructure issue).
//
// The 404 body shape matches the /v1/t/{tenant}/health 404 (added by
// A10), so SDKs and operators see a single error envelope across every
// tenant-aware endpoint.
func (s *Server) withTenant(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant := r.PathValue("tenant")
		if tenant == "" {
			tenant = policy.LocalTenantID
		}
		if tenant != policy.LocalTenantID {
			if _, err := s.cfg.Engine.PolicyForTenant(tenant); err != nil {
				w.Header().Set("Content-Type", "application/json")
				if errors.Is(err, policy.ErrTenantNotFound) {
					w.WriteHeader(http.StatusNotFound)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": "tenant not found"})
					return
				}
				// Provider infrastructure failure (DB down etc.) — distinct
				// from a missing tenant. Surface as 500 so operators alert
				// separately from "tenant typo" 404s.
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "policy provider error"})
				return
			}
		}
		r = r.WithContext(WithTenantID(r.Context(), tenant))
		next(w, r)
	}
}
