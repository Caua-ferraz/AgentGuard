package policy

import "testing"

func TestCanonicalHost(t *testing.T) {
	cases := []struct{ in, want string }{
		{"example.com", "example.com"},
		{"metadata.google.internal.", "metadata.google.internal"},
		{"169.254.169.254", "169.254.169.254"},
		{"0xa9fea9fe", "169.254.169.254"},
		{"0XA9FEA9FE", "169.254.169.254"},
		{"2852039166", "169.254.169.254"},
		{"0251.0376.0251.0376", "169.254.169.254"},
		{"0xa9.0xfe.0xa9.0xfe", "169.254.169.254"},
		{"169.254.43518", "169.254.169.254"},
		{"169.16689662", "169.254.169.254"},
		{"127.1", "127.0.0.1"},
		{"169.254.169.254.", "169.254.169.254"},
		{"::ffff:169.254.169.254", "169.254.169.254"},
		{"::ffff:a9fe:a9fe", "169.254.169.254"},
		{"[::ffff:a9fe:a9fe]", "169.254.169.254"},
		{"0:0:0:0:0:0:0:1", "::1"},
		{"fe80::1%eth0", "fe80::1"},
		// Not IP addresses: left alone.
		{"1password.com", "1password.com"},
		{"8.8.8.8.nip.io", "8.8.8.8.nip.io"},
		{"256.1.1.1", "256.1.1.1"},
		{"1.2.3.4.5", "1.2.3.4.5"},
		{"4294967296", "4294967296"},
		{"09.1.1.1", "09.1.1.1"},
		{"*.internal", "*.internal"},
		// A domain field written by a caller or a model.
		{"example.com:8080", "example.com"},
		{"169.254.169.254:80", "169.254.169.254"},
		{"0xa9fea9fe:80", "169.254.169.254"},
		{"[::ffff:a9fe:a9fe]:80", "169.254.169.254"},
		{"user@169.254.169.254", "169.254.169.254"},
		{"a@b@169.254.169.254", "169.254.169.254"},
		{" 169.254.169.254\t", "169.254.169.254"},
		{"metadata.google.internal..", "metadata.google.internal"},
		{"1.2.3.04", "1.2.3.4"},
		{"example.com:http", "example.com:http"},
		// Unicode a WHATWG parser folds to ASCII.
		{"１６９.２５４.１６９.２５４", "169.254.169.254"},
		{"169。254。169。254", "169.254.169.254"},
		{"169．254｡169.254", "169.254.169.254"},
		{"ｍｅｔａｄａｔａ.google.internal", "metadata.google.internal"},
		{"ⓜetadata.google.internal", "metadata.google.internal"},
		{"①⑥⑨.254.169.254", "169.254.169.254"},
		{"Ｍｅｔａｄａｔａ.Google.Internal", "metadata.google.internal"},
		{"bücher.example", "bücher.example"},
		// Invisible characters a URL parser drops.
		{"169.254.169.2\u00ad54", "169.254.169.254"},
		{"169.254.169.254\u00ad", "169.254.169.254"},
		{"meta\u00addata.google.internal", "metadata.google.internal"},
		{"metadata.google.internal\u200b", "metadata.google.internal"},
		{"169.254\u2060.169.254", "169.254.169.254"},
		{"169.254.169.254\ufeff", "169.254.169.254"},
		{"169.254.\ufe0f169.254", "169.254.169.254"},
		{"169.254.169.254\u034f", "169.254.169.254"},
		{"169.254.169.254\u3164", "169.254.169.254"},
		// Joiners are kept: the parser keeps them, so the host is another one.
		{"git\u200dhub.com", "git\u200dhub.com"},
		{"git\u200chub.com", "git\u200chub.com"},
		{"", ""},
		{".", "."},
	}
	for _, tc := range cases {
		if got := canonicalHost(tc.in); got != tc.want {
			t.Errorf("canonicalHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A deny on the metadata endpoint holds whichever way the request spells the
// host, through the domain field or a URL, and through an exact or a wildcard
// rule. Before, every spelling below was allowed by the catch-all.
func TestCheck_DomainRulesSeeEverySpellingOfAHost(t *testing.T) {
	pol := &Policy{
		Name: "hosts",
		Rules: []RuleSet{{
			Scope: "network",
			Deny: []Rule{
				{Domain: "169.254.169.254"},
				{Domain: "metadata.google.internal"},
				{Domain: "*.corp.internal"},
			},
			Allow: []Rule{{Domain: "*"}},
		}},
	}
	e := NewEngineFromPolicy(pol)
	denied := []ActionRequest{
		{Scope: "network", Domain: "0xa9fea9fe"},
		{Scope: "network", Domain: "2852039166"},
		{Scope: "network", Domain: "169.254.169.254."},
		{Scope: "network", Domain: "::ffff:a9fe:a9fe"},
		{Scope: "network", URL: "http://0251.0376.0251.0376/latest/meta-data/"},
		{Scope: "network", URL: "http://[::ffff:169.254.169.254]/latest/"},
		{Scope: "network", URL: "http://metadata.google.internal./computeMetadata/v1/"},
		{Scope: "network", URL: "http://METADATA.Google.Internal/computeMetadata/v1/"},
		{Scope: "network", Domain: "db.corp.internal."},
		{Scope: "network", Domain: "169.254.169.254:80"},
		{Scope: "network", Domain: "user@0xa9fea9fe"},
		{Scope: "network", URL: "http://１６９.２５４.１６９.２５４/latest/meta-data"},
		{Scope: "network", URL: "http://169。254。169。254/latest/meta-data"},
		{Scope: "network", URL: "http://ｍｅｔａｄａｔａ.google.internal/computeMetadata/v1/"},
		{Scope: "network", URL: "http://ⓜetadata.google.internal/"},
		{Scope: "network", URL: "http://169.254.169.2\u00ad54/latest/meta-data/"},
		{Scope: "network", URL: "http://metadata.google.internal\u200b/computeMetadata/v1/"},
	}
	for _, req := range denied {
		if res := e.Check(req, "local"); res.Decision != Deny {
			t.Errorf("%+v: decision %s (rule %q), want DENY", req, res.Decision, res.Rule)
		}
	}
	for _, req := range []ActionRequest{
		{Scope: "network", Domain: "example.com"},
		{Scope: "network", URL: "https://1password.com/"},
		{Scope: "network", Domain: "8.8.8.8"},
	} {
		if res := e.Check(req, "local"); res.Decision != Allow {
			t.Errorf("%+v: decision %s (rule %q), want ALLOW", req, res.Decision, res.Rule)
		}
	}
}

// A port or userinfo in a rule's domain is part of the rule: dropping it
// would let "localhost:3000" allow every port on localhost.
func TestCheck_RuleDomainKeepsItsPort(t *testing.T) {
	pol := &Policy{Name: "port", Rules: []RuleSet{{
		Scope: "network",
		Allow: []Rule{{Domain: "localhost:3000"}},
	}}}
	e := NewEngineFromPolicy(pol)
	for _, req := range []ActionRequest{
		{Scope: "network", Domain: "localhost:22"},
		{Scope: "network", URL: "http://localhost:22/"},
		{Scope: "network", Domain: "localhost"},
	} {
		if res := e.Check(req, "local"); res.Decision != Deny {
			t.Errorf("%+v: decision %s (rule %q), want DENY", req, res.Decision, res.Rule)
		}
	}
}

// Joiners make a different host, so they must not turn a lookalike into an
// allowed name.
func TestCheck_JoinerLookalikeIsNotTheAllowedHost(t *testing.T) {
	pol := &Policy{Name: "joiners", Rules: []RuleSet{{
		Scope: "network",
		Allow: []Rule{{Domain: "github.com"}},
	}}}
	e := NewEngineFromPolicy(pol)
	if res := e.Check(ActionRequest{Scope: "network", URL: "https://git\u200dhub.com/"}, "local"); res.Decision != Deny {
		t.Errorf("git+ZWJ+hub.com: decision %s (rule %q), want DENY", res.Decision, res.Rule)
	}
}
