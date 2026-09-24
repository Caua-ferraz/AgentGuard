package proxy

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

const secretValue = "s3cretvalue123"

func withRedactor(c *Config) { c.Redactor = notify.DefaultRedactor() }

func TestPendingList_RedactedButStoredRequestIntact(t *testing.T) {
	srv := newTestServer(t, withRedactor)
	ts := httptest.NewServer(srv.http.Handler)
	defer ts.Close()
	auth := func(r *http.Request) { r.Header.Set("Authorization", "Bearer test-secret") }

	cmd := "sudo echo token=" + secretValue
	body := `{"scope":"shell","command":"` + cmd + `","agent_id":"a"}`
	resp, err := http.Post(ts.URL+"/v1/check", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var res policy.CheckResult
	_ = json.NewDecoder(resp.Body).Decode(&res)
	resp.Body.Close()
	if res.Decision != policy.RequireApproval {
		t.Fatalf("decision = %s", res.Decision)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/pending", nil)
	auth(req)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	_, _ = bufio.NewReader(resp.Body).WriteTo(&sb)
	resp.Body.Close()
	if strings.Contains(sb.String(), secretValue) || !strings.Contains(sb.String(), "[REDACTED]") {
		t.Errorf("/api/pending = %s", sb.String())
	}

	// The queue keeps the original request: approving and replaying the
	// exact command still matches.
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/v1/approve/"+res.ApprovalID, nil)
	auth(req)
	if resp, err = http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("approve: %v %v", err, resp)
	}
	resp.Body.Close()
	replay := `{"scope":"shell","command":"` + cmd + `","agent_id":"a","approval_id":"` + res.ApprovalID + `"}`
	resp, err = http.Post(ts.URL+"/v1/check", "application/json", strings.NewReader(replay))
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewDecoder(resp.Body).Decode(&res)
	resp.Body.Close()
	if res.Decision != policy.Allow {
		t.Errorf("replay after redacted listing = %s (%s), want ALLOW", res.Decision, res.Reason)
	}
}

func TestEventStream_Redacted(t *testing.T) {
	srv := newTestServer(t, withRedactor)
	ts := httptest.NewServer(srv.http.Handler)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/stream", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Wait for the subscription to register, then trigger a check.
	deadline := time.Now().Add(2 * time.Second)
	for srv.approval.watcherCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	body := `{"scope":"shell","command":"echo password=` + secretValue + `"}`
	if r, err := http.Post(ts.URL+"/v1/check", "application/json", strings.NewReader(body)); err == nil {
		r.Body.Close()
	}

	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "data: ") || strings.Contains(line, secretValue) || !strings.Contains(line, "[REDACTED]") {
		t.Errorf("SSE line = %q", line)
	}
}

// watcherCount reports the number of SSE subscribers (test helper).
func (q *ApprovalQueue) watcherCount() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.watchers)
}

func TestAuditQuery_OrderParam(t *testing.T) {
	srv := newTestServer(t)
	ts := httptest.NewServer(srv.http.Handler)
	defer ts.Close()
	for _, cmd := range []string{"ls one", "ls two", "ls three"} {
		r, err := http.Post(ts.URL+"/v1/check", "application/json", strings.NewReader(`{"scope":"shell","command":"`+cmd+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
	}
	get := func(q string) (int, []string) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/audit?"+q, nil)
		req.Header.Set("Authorization", "Bearer test-secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var entries []struct {
			Request policy.ActionRequest `json:"request"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&entries)
		var cmds []string
		for _, e := range entries {
			cmds = append(cmds, e.Request.Command)
		}
		return resp.StatusCode, cmds
	}
	if code, cmds := get("order=desc&limit=2"); code != 200 || strings.Join(cmds, ",") != "ls three,ls two" {
		t.Errorf("order=desc: %d %v", code, cmds)
	}
	if code, cmds := get("limit=2"); code != 200 || strings.Join(cmds, ",") != "ls one,ls two" {
		t.Errorf("default order: %d %v", code, cmds)
	}
	if code, _ := get("order=newest"); code != http.StatusBadRequest {
		t.Errorf("order=newest: %d, want 400", code)
	}
}

func TestNewServer_BindAddress(t *testing.T) {
	cases := []struct {
		key, bind, want string
	}{
		{"k", "", ":9123"},
		{"", "", "127.0.0.1:9123"},
		{"k", "127.0.0.1", "127.0.0.1:9123"},
		{"k", "::1", "[::1]:9123"},
		{"k", "0.0.0.0", "0.0.0.0:9123"},
		{"", "localhost", "localhost:9123"},
		{"", "0.0.0.0", "127.0.0.1:9123"}, // no key: never a non-loopback bind
	}
	for _, c := range cases {
		srv := newTestServer(t, func(cfg *Config) { cfg.Port = 9123; cfg.APIKey = c.key; cfg.BindHost = c.bind })
		if srv.http.Addr != c.want {
			t.Errorf("key=%q bind=%q: Addr = %q, want %q", c.key, c.bind, srv.http.Addr, c.want)
		}
	}
	for host, want := range map[string]bool{"localhost": true, "127.0.0.1": true, "127.5.5.5": true, "::1": true, "[::1]": true, "": false, "0.0.0.0": false, "::": false, "10.0.0.1": false, "example.com": false} {
		if got := IsLoopbackHost(host); got != want {
			t.Errorf("IsLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}
