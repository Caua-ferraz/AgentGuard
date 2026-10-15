// Package report builds the compliance evidence report of `agentguard
// report`: what AgentGuard decided over a period, how far the audit log
// that recorded it can be trusted, and how that maps to SOC 2 criteria.
//
// It does no I/O. The caller reads the audit log (files or a server), runs
// the checks it can, and hands the entries to Aggregate as an iterator; the
// renderers write the finished Report as Markdown, JSON or HTML. That keeps
// every number in the report testable from a fixed list of entries.
//
// The JSON form is a stable shape for 1.x: fields are only ever added.
// FormatVersion changes only if that ever stops being true. See
// docs/COMPLIANCE.md.
package report

import "time"

// FormatVersion is the version of the report's JSON shape.
const FormatVersion = 1

// Report is the whole report. Its JSON form is what `--output json` prints.
type Report struct {
	FormatVersion int `json:"format_version"`
	// GeneratedAt is when the report was made (UTC).
	GeneratedAt time.Time `json:"generated_at"`
	// AgentGuardVersion is the version of the binary that made the report,
	// e.g. "1.4.0 (abc1234)".
	AgentGuardVersion string `json:"agentguard_version"`
	Period            Period `json:"period"`
	Source            Source `json:"source"`
	// Policy is the policy file the report names, or nil when none was
	// given or found.
	Policy    *PolicyFile `json:"policy"`
	Integrity Integrity   `json:"integrity"`
	Activity  Activity    `json:"activity"`
	Approvals Approvals   `json:"approvals"`
	Posture   []Check     `json:"posture"`
	Controls  []Control   `json:"controls"`
	// Limits says what the report can't show. Read it with the numbers.
	Limits []string `json:"limits"`
}

// Period is the time range the report covers: Since inclusive, Until
// exclusive, both UTC.
type Period struct {
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
}

// Contains reports whether t falls in the period.
func (p Period) Contains(t time.Time) bool {
	return !t.Before(p.Since) && t.Before(p.Until)
}

// Source modes.
const (
	SourceFile   = "file"   // the audit log files were read directly
	SourceServer = "server" // a running server was asked over GET /v1/audit
)

// Source says where the entries came from.
type Source struct {
	Mode string `json:"mode"`
	// AuditLog is the live audit file (file mode).
	AuditLog string `json:"audit_log,omitempty"`
	// Files are the files read, oldest first, by base name (file mode).
	Files []string `json:"files,omitempty"`
	// BadLines counts lines in those files that are not audit entries
	// (file mode; always 0 in server mode, where the server skips them).
	BadLines int `json:"bad_lines"`
	// ReadErrors are files that could not be read to the end (file mode).
	// Entries before the error are in the report.
	ReadErrors []string `json:"read_errors,omitempty"`
	// Server is the server's URL and Tenant the tenant asked for (server
	// mode; Tenant is "local" for the legacy /v1/audit route).
	Server string `json:"server,omitempty"`
	Tenant string `json:"tenant,omitempty"`
	// Fetched counts the entries the server returned, and OutsidePeriod
	// those of them the report dropped because their timestamp is outside
	// the period: a server older than 1.4 does not filter by time.
	Fetched       int `json:"fetched,omitempty"`
	OutsidePeriod int `json:"outside_period,omitempty"`
	// AuthRequired is whether the server refused an audit query that
	// carried no API key (server mode). nil when it was not checked.
	AuthRequired *bool `json:"auth_required,omitempty"`
}

// PolicyFile identifies a policy file by content.
type PolicyFile struct {
	Path string `json:"path"`
	// SHA256 is the hex SHA-256 of the file's bytes when the report was
	// made.
	SHA256 string `json:"sha256"`
	// Found says how the file was chosen: "--policy", "AGENTGUARD_POLICY",
	// "the default" or "found automatically".
	Found string `json:"found"`
}

// Count is one name and how many entries had it.
type Count struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Tally is a breakdown of entries by one field: how many different values
// it had, and the most frequent ones, most first (ties by name).
type Tally struct {
	Distinct int     `json:"distinct"`
	Top      []Count `json:"top"`
}

// NameList is the set of values a field had: how many, and the first of
// them in sorted order. Truncated is true when Names does not hold them all.
type NameList struct {
	Count     int      `json:"count"`
	Names     []string `json:"names"`
	Truncated bool     `json:"truncated"`
}

// Check is one posture check.
type Check struct {
	Name string `json:"name"`
	// Status is pass, warn, fail or unknown (it can't be told from what the
	// report read).
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// Check statuses.
const (
	CheckPass    = "pass"
	CheckWarn    = "warn"
	CheckFail    = "fail"
	CheckUnknown = "unknown"
)

// Control maps the report's evidence to one SOC 2 criterion. It is
// supporting evidence for that criterion, not a finding that it is met.
type Control struct {
	Criterion string `json:"criterion"`
	Title     string `json:"title"`
	// Shows is what this report holds that bears on the criterion.
	Shows string `json:"shows"`
	// Where names the report's sections that hold it.
	Where []string `json:"where"`
}
