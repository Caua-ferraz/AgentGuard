package main

// setup_release.go: updating in place, the way the one-line installers do
// it — the release archive for this OS and CPU, checked against the
// release's checksums.txt, then the three binaries swapped by rename so a
// running server keeps going until it restarts.

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const releaseRepo = "Caua-ferraz/AgentGuard"

// maxArchiveBytes caps a download; a release archive is ~30 MB.
const maxArchiveBytes = 256 << 20

// latestRelease asks GitHub for the newest release's version (no "v").
func latestRelease(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, updateCheckEndpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "AgentGuard/"+version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub answered HTTP %d", resp.StatusCode)
	}
	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	v := strings.TrimPrefix(payload.TagName, "v")
	if v == "" {
		return "", errors.New("GitHub returned no release tag")
	}
	return v, nil
}

// releaseArchive is the archive name for a version on this machine.
func releaseArchive(v, goos, goarch string) string {
	name := fmt.Sprintf("agentguard_%s_%s_%s", v, goos, goarch)
	if goos == "windows" {
		return name + ".zip"
	}
	return name + ".tar.gz"
}

// releaseBase is where a version's files are: AGENTGUARD_DOWNLOAD_URL (a
// mirror, like the installers accept) or the GitHub release.
func releaseBase(v string) string {
	if u := os.Getenv("AGENTGUARD_DOWNLOAD_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "https://github.com/" + releaseRepo + "/releases/download/v" + v
}

// downloadRelease fetches a version's archive, checks it against
// checksums.txt, and returns the three binaries' contents by tool name.
func downloadRelease(ctx context.Context, m machine, v string) (map[string][]byte, error) {
	base := releaseBase(v)
	archive := releaseArchive(v, m.goos, m.goarch)
	client := &http.Client{Timeout: 10 * time.Minute}

	sums, err := fetch(ctx, client, base+"/checksums.txt", 1<<20)
	if err != nil {
		return nil, err
	}
	want := checksumFor(sums, archive)
	if want == "" {
		return nil, fmt.Errorf("%s is not listed in checksums.txt", archive)
	}
	data, err := fetch(ctx, client, base+"/"+archive, maxArchiveBytes)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != want {
		return nil, fmt.Errorf("checksum mismatch for %s (expected %s, got %s)", archive, want, got)
	}
	return extractTools(m, archive, data)
}

func fetch(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AgentGuard/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("download %s: larger than %d bytes", url, limit)
	}
	return b, nil
}

// checksumFor finds name in sha256sum output ("<hash>  <name>", or
// "<hash> *<name>" in binary mode).
func checksumFor(sums []byte, name string) string {
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == name {
			return strings.ToLower(fields[0])
		}
	}
	return ""
}

// extractTools pulls the three binaries out of a release archive.
func extractTools(m machine, archive string, data []byte) (map[string][]byte, error) {
	wanted := map[string]string{} // file name in the archive -> tool
	for _, t := range tools {
		wanted[m.exeName(t)] = t
	}
	out := map[string][]byte{}
	take := func(name string, r io.Reader) error {
		// Windows PowerShell's Compress-Archive writes "dir\file": a zip
		// built by hand for a mirror may look like that.
		if t, ok := wanted[path.Base(strings.ReplaceAll(name, `\`, "/"))]; ok {
			b, err := io.ReadAll(io.LimitReader(r, maxArchiveBytes))
			if err != nil {
				return err
			}
			out[t] = b
		}
		return nil
	}
	if strings.HasSuffix(archive, ".zip") {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", archive, err)
		}
		for _, f := range zr.File {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			err = take(f.Name, rc)
			rc.Close()
			if err != nil {
				return nil, err
			}
		}
	} else {
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", archive, err)
		}
		tr := tar.NewReader(gz)
		for {
			h, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("%s: %w", archive, err)
			}
			if h.Typeflag == tar.TypeReg {
				if err := take(h.Name, tr); err != nil {
					return nil, err
				}
			}
		}
	}
	for _, t := range tools {
		if len(out[t]) == 0 {
			return nil, fmt.Errorf("%s has no %s", archive, m.exeName(t))
		}
	}
	return out, nil
}

// replaceTools writes the new binaries over the old ones. On Linux and
// macOS each goes to a temporary name and is renamed over the old file,
// which a running copy survives. Windows can't overwrite a running .exe but
// can rename it, so the old one is moved to <name>.old first and deleted
// when it can be (now, or on the next update or setup run).
func replaceTools(m machine, bins map[string][]byte) error {
	for _, t := range tools {
		target := filepath.Join(m.binDir, m.exeName(t))
		if m.goos == "windows" {
			old := target + ".old"
			_ = os.Remove(old)
			if fileExists(target) {
				if err := os.Rename(target, old); err != nil {
					return fmt.Errorf("move %s aside: %w", target, err)
				}
			}
			if err := os.WriteFile(target, bins[t], 0o755); err != nil {
				_ = os.Rename(old, target)
				return fmt.Errorf("write %s: %w", target, err)
			}
			_ = os.Remove(old)
			continue
		}
		tmp := filepath.Join(m.binDir, "."+t+".new")
		if err := os.WriteFile(tmp, bins[t], 0o755); err != nil {
			return fmt.Errorf("write %s: %w", tmp, err)
		}
		if err := os.Rename(tmp, target); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("replace %s: %w", target, err)
		}
	}
	return nil
}

// cleanOldTools deletes the <name>.exe.old files a Windows update left
// behind while a copy was running.
func cleanOldTools(m machine) {
	if m.goos != "windows" {
		return
	}
	for _, t := range tools {
		_ = os.Remove(filepath.Join(m.binDir, m.exeName(t)+".old"))
	}
}

// writable reports whether files can be created in dir.
func writable(dir string) bool {
	f, err := os.CreateTemp(dir, ".agentguard-write-test-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}
