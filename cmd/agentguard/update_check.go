package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Caua-ferraz/AgentGuard/cmd/internal/buildinfo"
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
//   - The `serve` subcommand never performs the check. The enforcement
//     server's outbound connections must be exactly the ones the operator
//     configured (policy notifiers, the durable store, nothing else) — see
//     docs/THREAT_MODEL.md. Interactive subcommands keep the notice.
const (
	defaultUpdateCheckEndpoint = "https://api.github.com/repos/Caua-ferraz/AgentGuard/releases/latest"
	updateHTTPTimeout          = 1500 * time.Millisecond

	// Where the notice points, and the update command for each way of
	// installing AgentGuard (see updateCommand).
	latestReleaseURL    = "https://github.com/Caua-ferraz/AgentGuard/releases/latest"
	updateByInstallSh   = "curl -fsSL " + latestReleaseURL + "/download/install.sh | sh"
	updateByInstallPs1  = "irm " + latestReleaseURL + "/download/install.ps1 | iex"
	updateByGoInstall   = "go install github.com/Caua-ferraz/AgentGuard/cmd/agentguard@latest"
	updateByDockerImage = "docker pull ghcr.io/caua-ferraz/agentguard:latest, then recreate the container"
)

// updateCheckEndpoint is the URL the check queries. A variable (not a
// const) only so tests can point it at a local server; production code
// never reassigns it.
var updateCheckEndpoint = defaultUpdateCheckEndpoint

// goos is runtime.GOOS; a variable only so tests can pick the platform.
var goos = runtime.GOOS

// updatePrinted ensures the notice is emitted at most once per process,
// even if both the goroutine and the wait path race on draining.
var updatePrinted atomic.Bool

// startUpdateCheck launches a background goroutine that asks GitHub for
// the latest release. The goroutine prints the update notice itself
// when it finishes — caller need only block briefly via waitForUpdateCheck
// so the print lands before subcommand output.
//
// Returns a channel that is closed when the goroutine exits. Always non-
// nil so callers can select on it unconditionally. When the check is
// skipped (see shouldSkipUpdateCheck) the channel is already closed and
// no network request is ever made.
func startUpdateCheck(currentVersion, currentCommit, subcommand string) <-chan struct{} {
	done := make(chan struct{})
	if shouldSkipUpdateCheck(currentVersion, currentCommit, subcommand) {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		notice := fetchUpdateNotice(currentVersion, currentCommit)
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

// shouldSkipUpdateCheck reports whether this invocation must not call out.
//
//   - `serve`: never. The long-running enforcement server makes no outbound
//     connection of its own.
//   - Dev builds: an untagged version string ("dev" anywhere in it), or the
//     "dev" commit placeholder on a binary whose Go build info carries no
//     tagged release version. `go install …@vX.Y.Z` / `@latest` builds keep
//     commit=dev (no -ldflags) but record the tag, so they DO check; a
//     `go build` of an untagged or modified checkout does not.
//   - AGENTGUARD_NO_UPDATE_CHECK set to anything other than "0".
func shouldSkipUpdateCheck(currentVersion, currentCommit, subcommand string) bool {
	if subcommand == "serve" {
		return true
	}
	if currentVersion == "" || strings.Contains(currentVersion, "dev") {
		return true
	}
	if currentCommit == "dev" && buildinfo.ReleaseVersion() == "" {
		return true
	}
	if v := os.Getenv("AGENTGUARD_NO_UPDATE_CHECK"); v != "" && v != "0" {
		return true
	}
	return false
}

// fetchUpdateNotice returns the one-line notice when a newer release is
// published, naming the command that updates this copy, and "" otherwise.
func fetchUpdateNotice(currentVersion, currentCommit string) string {
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
	return fmt.Sprintf("Notice: AgentGuard v%s is available (you have v%s). Update: %s — what's new: %s",
		latest, currentVersion, updateCommand(currentCommit), latestReleaseURL)
}

// updateCommand is how this copy of agentguard updates, by the way it was
// installed:
//   - the container image, whose Dockerfile sets AGENTGUARD_DISTRIBUTION=container;
//   - `go install`: the "dev" commit placeholder on a binary whose Go build
//     info records a tagged release — the same signal shouldSkipUpdateCheck
//     uses to tell it from a source build;
//   - otherwise a release archive, from the one-line installer for this OS.
func updateCommand(currentCommit string) string {
	switch {
	case os.Getenv("AGENTGUARD_DISTRIBUTION") == "container":
		return updateByDockerImage
	case currentCommit == "dev" && buildinfo.ReleaseVersion() != "":
		return updateByGoInstall
	case goos == "windows":
		return updateByInstallPs1
	default:
		return updateByInstallSh
	}
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
