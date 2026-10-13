package filter

import "strings"

import "testing"

func TestParseBlocklistLine(t *testing.T) {
	cases := map[string]string{
		"||example.com^":        "example.com",
		"||ads.example.com^":    "ads.example.com",
		"0.0.0.0 tracker.net":   "tracker.net",
		"127.0.0.1 bad.org":     "bad.org",
		"*.doubleclick.net":     "doubleclick.net",
		"plain-domain.com":      "plain-domain.com",
		"! comment":             "",
		"# comment":             "",
		"[Adblock Plus 2.0]":    "",
		"||example.com^$third":  "", // option rule, not a plain domain
		"/regex/":               "",
		"||example.com/path":    "",
		"localhost":             "", // no dot
		"  ||spaced.example^  ": "spaced.example",
	}
	for in, want := range cases {
		if got := parseBlocklistLine(in); got != want {
			t.Errorf("parseBlocklistLine(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBlocklistMatching(t *testing.T) {
	b := NewBlocklist()
	n := b.LoadReader(strings.NewReader(
		"! header\n||example.com^\n0.0.0.0 tracker.net\n*.adserver.io\n"))
	if n != 3 {
		t.Fatalf("loaded %d domains, want 3", n)
	}
	blocked := []string{
		"example.com.", "www.example.com.", "a.b.example.com",
		"tracker.net", "adserver.io", "cdn.adserver.io.",
	}
	for _, q := range blocked {
		if !b.Blocked(q) {
			t.Errorf("Blocked(%q) = false, want true", q)
		}
	}
	allowed := []string{"example.org.", "notexample.com.", "net.", "example.net."}
	for _, q := range allowed {
		if b.Blocked(q) {
			t.Errorf("Blocked(%q) = true, want false", q)
		}
	}
}

func TestBlocklistAllow(t *testing.T) {
	b := NewBlocklist()
	b.LoadReader(strings.NewReader("||oisd.nl^\n"))
	// Without an exception, the listed domain and subdomains are blocked.
	if !b.Blocked("zzztest.oisd.nl.") {
		t.Fatal("precondition: zzztest.oisd.nl should be blocked by ||oisd.nl^")
	}
	b.Allow("zzztest.oisd.nl")
	if b.Blocked("zzztest.oisd.nl.") {
		t.Error("allowlisted domain still blocked")
	}
	if b.Blocked("a.zzztest.oisd.nl.") {
		t.Error("subdomain of allowlisted domain still blocked")
	}
	// A sibling not on the allowlist stays blocked.
	if !b.Blocked("other.oisd.nl.") {
		t.Error("non-allowlisted sibling should remain blocked")
	}
}

func TestBlocklistAddCanary(t *testing.T) {
	b := NewBlocklist()
	b.Add("use-application-dns.net")
	if !b.Blocked("use-application-dns.net.") {
		t.Error("Firefox DoH canary not blocked after Add")
	}
	if b.Blocked("example.net.") {
		t.Error("unrelated domain blocked")
	}
}
