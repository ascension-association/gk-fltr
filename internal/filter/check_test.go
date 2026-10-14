package filter

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestChecker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abp":
			w.Write([]byte("||tracker.example^\n||ok.example^\n"))
		case "/hosts":
			w.Write([]byte("0.0.0.0 ads.tracker.example\n"))
		case "/allow":
			w.Write([]byte("cdn.tracker.example    #Breaks images\n"))
		case "/cidr":
			w.Write([]byte("# ranges\n203.0.113.0/24\n198.51.100.7\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := NewChecker(CheckerConfig{
		DomainURLs:    []string{srv.URL + "/abp", srv.URL + "/hosts", srv.URL + "/missing"},
		DomainSources: []DomainSource{{Name: "-block", Domains: []string{"bad.example"}}},
		AllowURLs:     []string{srv.URL + "/allow"},
		AllowSources:  []DomainSource{{Name: "-allow", Domains: []string{"ok.example"}}},
		IPURLs:        []string{srv.URL + "/cidr"},
		IPSources:     []IPSource{{Name: "-block-ips", Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}},
		AllowIPs:      []netip.Addr{netip.MustParseAddr("203.0.113.50"), netip.MustParseAddr("192.0.2.1")},
	})

	hits, allowed := c.Domain("Ads.Tracker.Example.")
	if len(hits) != 2 || len(allowed) != 0 {
		t.Fatalf("ads.tracker.example: hits %v allowed %v", hits, allowed)
	}
	if hits[0] != (Hit{List: srv.URL + "/abp", Entry: "tracker.example"}) || hits[1] != (Hit{List: srv.URL + "/hosts", Entry: "ads.tracker.example"}) {
		t.Errorf("ads.tracker.example: hits %v", hits)
	}
	if hits, _ := c.Domain("www.bad.example"); len(hits) != 1 || hits[0].List != "-block" {
		t.Errorf("www.bad.example: hits %v", hits)
	}
	if hits, allowed := c.Domain("ok.example"); len(hits) != 1 || len(allowed) != 1 || allowed[0] != (Hit{List: "-allow", Entry: "ok.example"}) {
		t.Errorf("ok.example: hits %v allowed %v", hits, allowed)
	}
	if hits, allowed := c.Domain("cdn.tracker.example"); len(hits) != 1 || len(allowed) != 1 || allowed[0] != (Hit{List: srv.URL + "/allow", Entry: "cdn.tracker.example"}) {
		t.Errorf("cdn.tracker.example: hits %v allowed %v", hits, allowed)
	}
	if hits, _ := c.Domain("clean.example"); len(hits) != 0 {
		t.Errorf("clean.example: hits %v", hits)
	}

	if hits, _ := c.IP(netip.MustParseAddr("203.0.113.9")); len(hits) != 1 || hits[0].Entry != "203.0.113.0/24" {
		t.Errorf("203.0.113.9: hits %v", hits)
	}
	// On the allowlist: the range list is overridden.
	if hits, allowed := c.IP(netip.MustParseAddr("203.0.113.50")); len(hits) != 0 || len(allowed) != 1 {
		t.Errorf("203.0.113.50: hits %v allowed %v", hits, allowed)
	}
	// On the allowlist, but individually listed: still blocked.
	if hits, _ := c.IP(netip.MustParseAddr("::ffff:192.0.2.1")); len(hits) != 1 || hits[0].List != "-block-ips" {
		t.Errorf("192.0.2.1: hits %v", hits)
	}
	if hits, _ := c.IP(netip.MustParseAddr("198.51.100.8")); len(hits) != 0 {
		t.Errorf("198.51.100.8: hits %v", hits)
	}
}
