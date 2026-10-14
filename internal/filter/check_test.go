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
		case "/cidr":
			w.Write([]byte("# ranges\n203.0.113.0/24\n198.51.100.7\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := NewChecker(
		[]string{srv.URL + "/abp", srv.URL + "/hosts", srv.URL + "/missing"},
		[]DomainSource{{Name: "-block", Domains: []string{"bad.example"}}},
		[]string{"ok.example"},
		[]string{srv.URL + "/cidr"},
		[]IPSource{{Name: "-block-ips", Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}},
	)

	hits, allowed := c.Domain("Ads.Tracker.Example.")
	if len(hits) != 2 || allowed != "" {
		t.Fatalf("ads.tracker.example: hits %v allowed %q", hits, allowed)
	}
	if hits[0] != (Hit{srv.URL + "/abp", "tracker.example"}) || hits[1] != (Hit{srv.URL + "/hosts", "ads.tracker.example"}) {
		t.Errorf("ads.tracker.example: hits %v", hits)
	}
	if hits, _ := c.Domain("www.bad.example"); len(hits) != 1 || hits[0].List != "-block" {
		t.Errorf("www.bad.example: hits %v", hits)
	}
	if hits, allowed := c.Domain("ok.example"); len(hits) != 1 || allowed != "ok.example" {
		t.Errorf("ok.example: hits %v allowed %q", hits, allowed)
	}
	if hits, _ := c.Domain("clean.example"); len(hits) != 0 {
		t.Errorf("clean.example: hits %v", hits)
	}

	if hits := c.IP(netip.MustParseAddr("203.0.113.9")); len(hits) != 1 || hits[0].Entry != "203.0.113.0/24" {
		t.Errorf("203.0.113.9: hits %v", hits)
	}
	if hits := c.IP(netip.MustParseAddr("::ffff:192.0.2.1")); len(hits) != 1 || hits[0].List != "-block-ips" {
		t.Errorf("192.0.2.1: hits %v", hits)
	}
	if hits := c.IP(netip.MustParseAddr("198.51.100.8")); len(hits) != 0 {
		t.Errorf("198.51.100.8: hits %v", hits)
	}
}
