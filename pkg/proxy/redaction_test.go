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
