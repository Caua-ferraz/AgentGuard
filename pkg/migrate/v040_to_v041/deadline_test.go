package v040_to_v041

import (
	"testing"
	"time"
)

// RemovalDeadline is the date after which this migration package must be
// deleted. It exists to make an operational decision visible in code: the
// v040_to_v041 migration only exists to help users skip the v0.4.1 boundary,
// and per docs/DEPRECATIONS.md (`audit.migration.v040_to_v041`) it is
// scheduled for removal in v0.4.3.
//
// v0.4.1 cut date: 2026-04-18. v0.4.3 removal target: within ~12 months.
// Padding gives us 2027-07-01 — enough time for two minor releases and a
// final grace window, but soon enough that a slip forces a conscious
// review rather than letting dead migration code pile up for years.
//
// If you are reading this because the test failed:
//  1. Upgrade docs/DEPRECATIONS.md: move the row from Active to Removed.
//  2. Drop CHANGELOG entry for v0.4.3 (or current release).
//  3. Delete pkg/migrate/v040_to_v041/ and the blank import in
//     cmd/agentguard/main.go.
//  4. Keep a standalone `agentguard-migrate` tool for users still on
//     v0.4.0 files — see the DEPRECATIONS migration-path column.
var RemovalDeadline = time.Date(2027, 7, 1, 0, 0, 0, 0, time.UTC)

// TestRemovalDeadline is a tripwire: once RemovalDeadline has passed and
// nobody has deleted this package, CI fails with a clear action list.
//
// The alternative — hoping we remember to delete old migrations on our own
// — has a poor track record. A failing test with instructions in it is the
// shortest path from "oops we left this in" to "cleanup PR merged".
func TestRemovalDeadline(t *testing.T) {
	if time.Now().UTC().Before(RemovalDeadline) {
		return
	}
	t.Fatalf(`v040_to_v041 migration is past its removal deadline (%s).

Action required (see package docstring for full checklist):
  1. Update docs/DEPRECATIONS.md — move audit.migration.v040_to_v041 to Removed.
  2. Add a CHANGELOG entry naming the removal.
  3. Delete pkg/migrate/v040_to_v041/ and the blank import in cmd/agentguard/main.go.

If v0.4.3 has slipped and the migration legitimately still needs to ship,
edit RemovalDeadline above and document the slip in docs/DEPRECATIONS.md.`,
		RemovalDeadline.Format("2006-01-02"),
	)
}
