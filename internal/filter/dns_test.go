package filter

import "testing"

func TestSafeHost(t *testing.T) {
	cases := []struct {
		q    string
		want string
		ok   bool
	}{
		{"www.google.com.", "forcesafesearch.google.com.", true},
		{"google.com.", "forcesafesearch.google.com.", true},
		{"www.google.co.uk.", "forcesafesearch.google.com.", true},
		{"google.de.", "forcesafesearch.google.com.", true},
		{"www.youtube.com.", "restrict.youtube.com.", true},
		{"m.youtube.com.", "restrict.youtube.com.", true},
		{"www.bing.com.", "strict.bing.com.", true},
		{"duckduckgo.com.", "safe.duckduckgo.com.", true},
		{"example.com.", "", false},
		{"notgoogle.com.", "", false},
		{"maps.google.com.", "", false}, // only search endpoints, not every subdomain
	}
	for _, c := range cases {
		got, ok := safeHost(c.q)
		if ok != c.ok || got != c.want {
			t.Errorf("safeHost(%q) = (%q,%v), want (%q,%v)", c.q, got, ok, c.want, c.ok)
		}
	}
}
