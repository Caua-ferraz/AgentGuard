package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Update check: a single, best-effort lookup of the latest published
// AgentGuard release. Prints one line to stderr when a newer version
// exists and otherwise stays silent.
//
// Design constraints (from feature spec):
//   - At most one notice per CLI invocation.
//   - MUST NOT slow down or interfere with the command — bounded wait,
//     all errors swallowed.
//   - No new external dependencies.
const (
	updateCheckEndpoint = "https://api.github.com/repos/Caua-ferraz/AgentGuard/releases/latest"
	updateHTTPTimeout   = 1500 * time.Millisecond
)

// updatePrinted ensures the notice is emitted at most once per process,
// even if both the goroutine and the wait path race on draining.
var updatePrinted atomic.Bool

// startUpdateCheck launches a background goroutine that asks GitHub for
// the latest release. The goroutine prints the deprecation notice itself
// when it finishes — caller need only block briefly via waitForUpdateCheck
// so the print lands before subcommand output.
//
// Returns a channel that is closed when the goroutine exits. Always non-
// nil so callers can select on it unconditionally.
func startUpdateCheck(currentVersion string) <-chan struct{} {
	done := make(chan struct{})
	if shouldSkipUpdateCheck(currentVersion) {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		notice := fetchUpdateNotice(currentVersion)
		if notice != "" && updatePrinted.CompareAndSwap(false, true) {
			fmt.Fprintln(os.Stderr, notice)
		}
	}()
	return done
}

// waitForUpdateCheck blocks up to timeout for the update goroutine to
// finish. If the goroutine takes longer it keeps running in the
// background — its print may still land mid-output, which is acceptable
// per the "do not interfere" constraint.
func waitForUpdateCheck(done <-chan struct{}, timeout time.Duration) {
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

func shouldSkipUpdateCheck(currentVersion string) bool {
	if currentVersion == "" || strings.Contains(currentVersion, "dev") {
		return true
	}
	if v := os.Getenv("AGENTGUARD_NO_UPDATE_CHECK"); v != "" && v != "0" {
		return true
	}
	return false
}

func fetchUpdateNotice(currentVersion string) string {
	ctx, cancel := context.WithTimeout(context.Background(), updateHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, updateCheckEndpoint, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "AgentGuard/"+currentVersion)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return ""
	}
	latest := strings.TrimPrefix(payload.TagName, "v")
	if latest == "" || !versionIsNewer(latest, currentVersion) {
		return ""
	}
	return fmt.Sprintf("Notice: agentguard v%s is deprecated, version v%s available — https://github.com/Caua-ferraz/AgentGuard/releases/latest", currentVersion, latest)
}

// versionIsNewer reports whether a > b under semver major.minor.patch
// ordering. Non-numeric suffixes are stripped so a "1.0.0-rc1" tag
// degrades to (1,0,0). Both inputs assumed to be without "v" prefix.
func versionIsNewer(a, b string) bool {
	aMaj, aMin, aPat := parseVersionTriple(a)
	bMaj, bMin, bPat := parseVersionTriple(b)
	if aMaj != bMaj {
		return aMaj > bMaj
	}
	if aMin != bMin {
		return aMin > bMin
	}
	return aPat > bPat
}

func parseVersionTriple(v string) (int, int, int) {
	parts := strings.SplitN(v, ".", 3)
	out := [3]int{}
	for i := 0; i < 3 && i < len(parts); i++ {
		s := parts[i]
		end := 0
		for end < len(s) && s[end] >= '0' && s[end] <= '9' {
			end++
		}
		if end == 0 {
			continue
		}
		n, err := strconv.Atoi(s[:end])
		if err != nil {
			continue
		}
		out[i] = n
	}
	return out[0], out[1], out[2]
}
