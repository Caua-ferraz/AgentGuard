package main

// Tests for the startup update check (review finding R4): the enforcement
// server must never call out, dev builds must stay silent, and the check
// must be bounded and harmless in every failure mode.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
		{"serve never calls out", "1.0.0", "abc1234", "serve", "", true},
		{"dev commit (plain go build)", "1.0.0", "dev", "check", "", true},
		{"dev version string", "1.0.0-dev", "abc1234", "check", "", true},
		{"empty version", "", "abc1234", "check", "", true},
		{"env opt-out", "1.0.0", "abc1234", "check", "1", true},
		{"env opt-out any value", "1.0.0", "abc1234", "status", "yes", true},
		{"env 0 does not opt out", "1.0.0", "abc1234", "check", "0", false},
		{"no subcommand (usage)", "1.0.0", "abc1234", "", "", false},
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

func TestStartUpdateCheck_ServeNeverCallsOut(t *testing.T) {
	t.Setenv("AGENTGUARD_NO_UPDATE_CHECK", "")
	hits := pointUpdateCheckAt(t, releaseJSON("v9.9.9"))

	done := startUpdateCheck("1.0.0", "abc1234", "serve")
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("serve must return an already-closed channel (no goroutine, no request)")
	}
	time.Sleep(150 * time.Millisecond) // give a stray goroutine time to show up
	if got := hits.Load(); got != 0 {
		t.Fatalf("serve made %d outbound request(s); want 0", got)
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
			got := fetchUpdateNotice("1.0.0")
			if c.want == "" && got != "" {
				t.Fatalf("want silence, got %q", got)
			}
			if c.want != "" && !strings.Contains(got, c.want) {
				t.Fatalf("want notice mentioning %q, got %q", c.want, got)
			}
			if got != "" && !strings.Contains(got, "releases/latest") {
				t.Errorf("notice must link to the releases page: %q", got)
			}
		})
	}
}

func TestFetchUpdateNotice_HangingServerIsBounded(t *testing.T) {
	pointUpdateCheckAt(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // never answer; the client's deadline ends it
	})
	start := time.Now()
	got := fetchUpdateNotice("1.0.0")
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
