package policy

import "testing"

func TestCheck_DomainFromURL(t *testing.T) {
	pol := &Policy{Version: "1", Name: "t", Rules: []RuleSet{{
		Scope: "network",
		Allow: []Rule{{Domain: "api.github.com"}, {Domain: "*.googleapis.com"}},
		Deny:  []Rule{{Domain: "*.evil.com"}},
	}}}
	eng := NewEngineFromPolicy(pol)
	cases := []struct {
		req  ActionRequest
		want Decision
	}{
		{ActionRequest{Scope: "network", URL: "https://api.github.com/repos"}, Allow},
		{ActionRequest{Scope: "network", URL: "HTTPS://API.GITHUB.COM:443/x"}, Allow},
		{ActionRequest{Scope: "network", URL: "https://storage.googleapis.com/b"}, Allow},
		{ActionRequest{Scope: "network", URL: "https://x.evil.com/"}, Deny},
		{ActionRequest{Scope: "network", URL: "https://api.github.com@evil.com/"}, Deny},
		{ActionRequest{Scope: "network", URL: "https://evil.com#@api.github.com"}, Deny},
		{ActionRequest{Scope: "network", URL: `https://evil.com\.api.github.com/`}, Deny},
		{ActionRequest{Scope: "network", URL: "api.github.com/repos"}, Deny}, // no scheme: not guessed
		{ActionRequest{Scope: "network", URL: "https://[::1]:8080/"}, Deny},
		// An explicit domain still wins over the URL.
		{ActionRequest{Scope: "network", Domain: "evil.com", URL: "https://api.github.com/"}, Deny},
		{ActionRequest{Scope: "network", Domain: "api.github.com", URL: "https://evil.com/"}, Allow},
	}
	for _, c := range cases {
		if got := eng.Check(c.req, LocalTenantID); got.Decision != c.want {
			t.Errorf("Check(domain=%q url=%q) = %s (%s), want %s", c.req.Domain, c.req.URL, got.Decision, got.Rule, c.want)
		}
	}
}
