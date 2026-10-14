package main

import (
	"strings"
	"testing"
)

// TestWebFetchTargets_ReadsHostsLikeGemini: the host the hook checks must
// be the host Gemini CLI's web_fetch connects to. A pattern of our own read
// "HTTPS://169.254.169.254/" as no URL at all (so the call went unchecked)
// and "https://x(@169.254.169.254/" as host x, both of which reach the
// cloud metadata address past a network deny rule.
func TestWebFetchTargets_ReadsHostsLikeGemini(t *testing.T) {
	cases := []struct {
		url, prompt string
		want        []string // hosts
		wantErr     string
	}{
		{"", "summarize https://example.com/page please", []string{"example.com"}, ""},
		{"", "summarize HTTPS://169.254.169.254/", []string{"169.254.169.254"}, ""},
		{"", "summarize https://x(@169.254.169.254/latest/meta-data/", []string{"169.254.169.254"}, ""},
		{"", "summarize https://a'@169.254.169.254/", []string{"169.254.169.254"}, ""},
		{"", "summarize https://a[@169.254.169.254/", []string{"169.254.169.254"}, ""},
		{"", `summarize https://a"@169.254.169.254/`, []string{"169.254.169.254"}, ""},
		{"", `summarize https:\\169.254.169.254\latest`, nil, "no http(s) URL"},
		{"", `read https://\169.254.169.254/x`, []string{"169.254.169.254"}, ""},
		{"", "read http://0xa9fea9fe/ and http://2852039166/", []string{"169.254.169.254", "169.254.169.254"}, ""},
		{"", "read http://0251.0376.0251.0376/", []string{"169.254.169.254"}, ""},
		{"", "read http://169.254.169.254.:80/", []string{"169.254.169.254"}, ""},
		{"", "read http://%31%36%39.254.169.254/", []string{"169.254.169.254"}, ""},
		{"", "read http://Example.COM:8080/x", []string{"example.com"}, ""},
		{"", "read http://[::1]:8080/", []string{"::1"}, ""},
		{"https://evil.example/", "", []string{"evil.example"}, ""},
		{"https://evil.example/", "and https://other.example", []string{"evil.example", "other.example"}, ""},
		{"", "ftp://files.example/x and https://ok.example", []string{"ok.example"}, ""},
		{"", "no url here", nil, "no http(s) URL"},
		{"", "", nil, "no http(s) URL"},
		{"", "https:///path-only", []string{"path-only"}, ""}, // WHATWG skips extra slashes
		{"", "https://@/x", nil, "no host"},
	}
	for _, tc := range cases {
		got, err := webFetchTargets(tc.url, tc.prompt)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("url=%q prompt=%q: err = %v, want one containing %q", tc.url, tc.prompt, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("url=%q prompt=%q: %v", tc.url, tc.prompt, err)
			continue
		}
		var hosts []string
		for _, g := range got {
			hosts = append(hosts, g.host)
		}
		if strings.Join(hosts, ",") != strings.Join(tc.want, ",") {
			t.Errorf("url=%q prompt=%q: hosts %v, want %v", tc.url, tc.prompt, hosts, tc.want)
		}
	}
}
