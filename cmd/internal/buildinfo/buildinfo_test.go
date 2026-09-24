package buildinfo

import (
	"runtime/debug"
	"testing"
)

// stub replaces Read for the test's lifetime.
func stub(t *testing.T, bi *debug.BuildInfo, ok bool) {
	t.Helper()
	prev := Read
	Read = func() (*debug.BuildInfo, bool) { return bi, ok }
	t.Cleanup(func() { Read = prev })
}

func info(version string, settings ...debug.BuildSetting) *debug.BuildInfo {
	return &debug.BuildInfo{Main: debug.Module{Path: "github.com/Caua-ferraz/AgentGuard", Version: version}, Settings: settings}
}

func TestReleaseVersion(t *testing.T) {
	cases := []struct {
		name    string
		version string
		ok      bool
		want    string
	}{
		{"go install @v1.1.1", "v1.1.1", true, "v1.1.1"},
		{"source build", "(devel)", true, ""},
		{"pseudo-version (untagged commit)", "v1.1.2-0.20260923120000-abcdef123456", true, ""},
		{"dirty build of a tag", "v1.1.1+dirty", true, ""},
		{"pre-release", "v1.2.0-rc1", true, ""},
		{"no build info", "", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stub(t, info(c.version), c.ok)
			if got := ReleaseVersion(); got != c.want {
				t.Errorf("ReleaseVersion() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestDescribe(t *testing.T) {
	rev := debug.BuildSetting{Key: "vcs.revision", Value: "0123456789abcdef"}
	clean := debug.BuildSetting{Key: "vcs.modified", Value: "false"}
	dirty := debug.BuildSetting{Key: "vcs.modified", Value: "true"}
	cases := []struct {
		name   string
		commit string
		bi     *debug.BuildInfo
		want   string
	}{
		{"ldflags commit wins", "abc1234", info("(devel)", rev, clean), "abc1234"},
		{"source build: short revision", "dev", info("(devel)", rev, clean), "0123456"},
		{"source build with local changes", "dev", info("(devel)", rev, dirty), "0123456-dirty"},
		{"go install: module version", "dev", info("v1.1.1"), "module v1.1.1"},
		{"nothing known", "dev", info("(devel)"), "dev"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stub(t, c.bi, true)
			if got := Describe(c.commit); got != c.want {
				t.Errorf("Describe(%q) = %q, want %q", c.commit, got, c.want)
			}
		})
	}
}
