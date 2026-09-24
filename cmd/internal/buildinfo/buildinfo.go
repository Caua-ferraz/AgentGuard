// Package buildinfo reads the Go build information stamped into the
// AgentGuard binaries. Builds that skip the Makefile's -ldflags — `go
// install …@vX.Y.Z`, a plain `go build`, a Docker build without a COMMIT
// build arg — keep the "dev" commit placeholder; this package lets them
// still report a meaningful identifier, and lets the update check tell a
// tagged release from a development build.
package buildinfo

import (
	"regexp"
	"runtime/debug"
)

// Read is debug.ReadBuildInfo. It is a variable only so tests can stub it.
var Read = debug.ReadBuildInfo

var releaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// ReleaseVersion returns the main module's version when it is a tagged
// release such as "v1.1.1": what `go install <module>/cmd/…@v1.1.1` (or
// `@latest`) records, and what `go build` records on a clean checkout of a
// release tag (Go 1.24+). It returns "" for everything else — "(devel)",
// pseudo-versions of untagged commits, pre-releases and "+dirty" builds.
func ReleaseVersion() string {
	bi, ok := Read()
	if !ok || bi == nil {
		return ""
	}
	if releaseTag.MatchString(bi.Main.Version) {
		return bi.Main.Version
	}
	return ""
}

// Describe returns the identifier printed next to the version for a binary
// whose -ldflags-injected commit is commit. For the "dev" placeholder it
// falls back to build info: the short VCS revision of a source build (with
// "-dirty" when the tree was modified), else the module version of a `go
// install` build ("module v1.1.1"), else "dev".
func Describe(commit string) string {
	if commit != "dev" {
		return commit
	}
	bi, ok := Read()
	if !ok || bi == nil {
		return commit
	}
	var rev string
	var dirty bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev != "" {
		if len(rev) > 7 {
			rev = rev[:7]
		}
		if dirty {
			rev += "-dirty"
		}
		return rev
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return "module " + v
	}
	return commit
}
