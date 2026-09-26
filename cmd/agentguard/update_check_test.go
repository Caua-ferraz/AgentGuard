package main

// Tests for the startup update check (review finding R4): the enforcement
// server must never call out, dev builds must stay silent, and the check
// must be bounded and harmless in every failure mode.

import (
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/cmd/internal/buildinfo"
)

// pointUpdateCheckAt redirects the check to a local server for the test's
// lifetime and reports how many requests it received.
func pointUpdateCheckAt(t *testing.T, handler http.HandlerFunc) *atomic.Int64 {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		handler(w, r)
	}))
	prev := updateCheckEndpoint
	updateCheckEndpoint = srv.URL
	t.Cleanup(func() {
		updateCheckEndpoint = prev
		srv.Close()
	})
	return &hits
}

func releaseJSON(tag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"` + tag + `"}`))
	}
}

func TestShouldSkipUpdateCheck(t *testing.T) {
	cases := []struct {
		name       string
		version    string
		commit     string
		subcommand string
		env        string // "" = unset
		want       bool
	}{
		{"release build, interactive subcommand", "1.0.0", "abc1234", "check", "", false},
		{"server never calls out", "1.0.0", "abc1234", "server", "", true},
		{"serve (alias of server) never calls out", "1.0.0", "abc1234", "serve", "", true},
		{"help does not wait on the network", "1.0.0", "abc1234", "--help", "", true},
		{"mistyped command", "1.0.0", "abc1234", "sever", "", true},
		{"version checks", "1.0.0", "abc1234", "--version", "", false},
		{"dev commit (plain go build)", "1.0.0", "dev", "check", "", true},
		{"dev version string", "1.0.0-dev", "abc1234", "check", "", true},
		{"empty version", "", "abc1234", "check", "", true},
		{"env opt-out", "1.0.0", "abc1234", "check", "1", true},
		{"env opt-out any value", "1.0.0", "abc1234", "status", "yes", true},
		{"env 0 does not opt out", "1.0.0", "abc1234", "check", "0", false},
		{"no subcommand (usage)", "1.0.0", "abc1234", "", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.env != "" {
				t.Setenv("AGENTGUARD_NO_UPDATE_CHECK", c.env)
			} else {
				t.Setenv("AGENTGUARD_NO_UPDATE_CHECK", "")
			}
			if got := shouldSkipUpdateCheck(c.version, c.commit, c.subcommand); got != c.want {
				t.Errorf("shouldSkipUpdateCheck(%q,%q,%q) = %v, want %v", c.version, c.commit, c.subcommand, got, c.want)
			}
		})
	}
}

// A binary built without the Makefile's -ldflags keeps commit=dev. Whether it
// is a release build is decided from Go build info: `go install …@vX.Y.Z` and
// `@latest` record the tag and must check; source builds must not.
func TestShouldSkipUpdateCheck_DevCommitUsesBuildInfo(t *testing.T) {
	t.Setenv("AGENTGUARD_NO_UPDATE_CHECK", "")
	cases := []struct {
		name          string
		moduleVersion string
		want          bool
	}{
		{"go install @v1.1.1", "v1.1.1", false},
		{"go build of a checkout", "(devel)", true},
		{"go install @master (pseudo-version)", "v1.1.2-0.20260923120000-abcdef123456", true},
		{"modified checkout of a tag", "v1.1.1+dirty", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prev := buildinfo.Read
			buildinfo.Read = func() (*debug.BuildInfo, bool) {
				return &debug.BuildInfo{Main: debug.Module{Version: c.moduleVersion}}, true
			}
			t.Cleanup(func() { buildinfo.Read = prev })
			if got := shouldSkipUpdateCheck("1.1.1", "dev", "check"); got != c.want {
				t.Errorf("shouldSkipUpdateCheck(dev commit, module %q) = %v, want %v", c.moduleVersion, got, c.want)
			}
			// server (and its serve alias) never calls out, whatever the build.
			for _, sub := range []string{"server", "serve"} {
				if !shouldSkipUpdateCheck("1.1.1", "dev", sub) {
					t.Errorf("%s must always skip (module %q)", sub, c.moduleVersion)
				}
			}
		})
	}
}

func TestStartUpdateCheck_ServerNeverCallsOut(t *testing.T) {
	t.Setenv("AGENTGUARD_NO_UPDATE_CHECK", "")
	hits := pointUpdateCheckAt(t, releaseJSON("v9.9.9"))

	for _, sub := range []string{"server", "serve"} {
		done := startUpdateCheck("1.0.0", "abc1234", sub)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("%s must return an already-closed channel (no goroutine, no request)", sub)
		}
	}
	time.Sleep(150 * time.Millisecond) // give a stray goroutine time to show up
	if got := hits.Load(); got != 0 {
		t.Fatalf("server made %d outbound request(s); want 0", got)
	}
}

func TestStartUpdateCheck_InteractiveSubcommandCallsOutOnce(t *testing.T) {
	t.Setenv("AGENTGUARD_NO_UPDATE_CHECK", "")
	// Same version as the binary: the request happens but nothing prints.
	hits := pointUpdateCheckAt(t, releaseJSON("v1.0.0"))

	done := startUpdateCheck("1.0.0", "abc1234", "check")
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("update check did not finish")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("interactive subcommand made %d request(s); want exactly 1", got)
	}
}

func TestFetchUpdateNotice(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		want    string // substring; "" means silent
	}{
		{"newer patch", releaseJSON("v1.0.1"), "v1.0.1"},
		{"newer major pre-release tag", releaseJSON("v2.0.0-rc1"), "v2.0.0"},
		{"same version", releaseJSON("v1.0.0"), ""},
		{"older version", releaseJSON("v0.9.9"), ""},
		{"tag without v prefix", releaseJSON("1.1.0"), "v1.1.0"},
		{"empty tag", releaseJSON(""), ""},
		{"non-200", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }, ""},
		{"garbage body", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>")) }, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pointUpdateCheckAt(t, c.handler)
			got := fetchUpdateNotice("1.0.0", "abc1234")
			if c.want == "" && got != "" {
				t.Fatalf("want silence, got %q", got)
			}
			if c.want != "" && !strings.Contains(got, c.want) {
				t.Fatalf("want notice mentioning %q, got %q", c.want, got)
			}
			if got != "" && !strings.Contains(got, "releases/latest") {
				t.Errorf("notice must link to the releases page: %q", got)
			}
			if got != "" {
				for _, part := range []string{"is available", "(you have v1.0.0)", "Update: "} {
					if !strings.Contains(got, part) {
						t.Errorf("notice %q lacks %q", got, part)
					}
				}
				if strings.Contains(got, "deprecated") {
					t.Errorf("a newer release does not make this one deprecated: %q", got)
				}
			}
		})
	}
}

func TestFetchUpdateNotice_HangingServerIsBounded(t *testing.T) {
	pointUpdateCheckAt(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // never answer; the client's deadline ends it
	})
	start := time.Now()
	got := fetchUpdateNotice("1.0.0", "abc1234")
	elapsed := time.Since(start)
	if got != "" {
		t.Errorf("hanging server must yield silence, got %q", got)
	}
	if elapsed > updateHTTPTimeout+time.Second {
		t.Errorf("update check took %s; must be bounded by %s", elapsed, updateHTTPTimeout)
	}
}

func TestWaitForUpdateCheck_DoesNotBlockPastTimeout(t *testing.T) {
	never := make(chan struct{})
	start := time.Now()
	waitForUpdateCheck(never, 50*time.Millisecond)
	if el := time.Since(start); el > time.Second {
		t.Fatalf("waited %s for a check that never finishes", el)
	}
	waitForUpdateCheck(nil, time.Hour) // nil must return immediately
}

func TestVersionIsNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.0.1", "1.0.0", true},
		{"1.1.0", "1.0.9", true},
		{"2.0.0", "1.9.9", true},
		{"1.10.0", "1.9.9", true},
		{"1.0.0", "1.0.0", false},
		{"0.9.9", "1.0.0", false},
		{"1.0.0-rc1", "1.0.0", false},
		{"1.0.0", "1.0.0-rc1", false},
		{"garbage", "1.0.0", false},
	}
	for _, c := range cases {
		if got := versionIsNewer(c.a, c.b); got != c.want {
			t.Errorf("versionIsNewer(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestSubcommandOf(t *testing.T) {
	if got := subcommandOf([]string{"agentguard", "serve", "--port", "1"}); got != "serve" {
		t.Errorf("got %q", got)
	}
	if got := subcommandOf([]string{"agentguard"}); got != "" {
		t.Errorf("got %q, want empty", got)
	}
	if got := subcommandOf(nil); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// The notice names the update command for the way this copy was installed:
// the container image, `go install`, or the one-line installer for its OS.
func TestUpdateCommand(t *testing.T) {
	cases := []struct {
		name, distribution, commit, moduleVersion, goos, want string
	}{
		{"container image", "container", "abc1234", "", "linux", updateByDockerImage},
		{"go install @v1.2.0", "", "dev", "v1.2.0", "linux", updateByGoInstall},
		{"go install on Windows", "", "dev", "v1.2.0", "windows", updateByGoInstall},
		{"release archive, Linux", "", "abc1234", "", "linux", updateByInstallSh},
		{"release archive, macOS", "", "abc1234", "", "darwin", updateByInstallSh},
		{"release archive, Windows", "", "abc1234", "", "windows", updateByInstallPs1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("AGENTGUARD_DISTRIBUTION", c.distribution)
			prevRead, prevGOOS := buildinfo.Read, goos
			buildinfo.Read = func() (*debug.BuildInfo, bool) {
				return &debug.BuildInfo{Main: debug.Module{Version: c.moduleVersion}}, true
			}
			goos = c.goos
			t.Cleanup(func() { buildinfo.Read, goos = prevRead, prevGOOS })
			if got := updateCommand(c.commit); got != c.want {
				t.Errorf("updateCommand(%q) = %q, want %q", c.commit, got, c.want)
			}
		})
	}
}
