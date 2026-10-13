package filter

import (
	"testing"

	"github.com/miekg/dns"
)

func TestStripECHRecords(t *testing.T) {
	https := &dns.HTTPS{
		SVCB: dns.SVCB{
			Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET},
			Priority: 1,
			Target:   "example.com.",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
				&dns.SVCBECHConfig{ECH: []byte{0xAA, 0xBB, 0xCC}},
			},
		},
	}
	// An A record should be untouched.
	a := &dns.A{Hdr: dns.RR_Header{Name: "example.com."}}

	rrs := []dns.RR{https, a}
	if n := stripECHRecords(rrs); n != 1 {
		t.Fatalf("stripECHRecords removed %d params, want 1", n)
	}
	for _, p := range https.Value {
		if p.Key() == dns.SVCB_ECHCONFIG {
			t.Fatal("ECH param survived stripping")
		}
	}
	if len(https.Value) != 1 {
		t.Fatalf("expected 1 remaining param (alpn), got %d", len(https.Value))
	}
	// Idempotent: a second pass removes nothing.
	if n := stripECHRecords(rrs); n != 0 {
		t.Fatalf("second pass removed %d, want 0", n)
	}
}
