package filter

import (
	"net/netip"
	"testing"
)

func TestParseCIDRLine(t *testing.T) {
	cases := []struct {
		in   string
		want string // "" => not ok
	}{
		{"1.2.3.0/24", "1.2.3.0/24"},
		{"10.0.0.5", "10.0.0.5/32"},
		{"2001:db8::/32", "2001:db8::/32"},
		{"203.0.113.0/24 # some label", "203.0.113.0/24"},
		{"  198.51.100.0/22  ", "198.51.100.0/22"},
		{"# comment", ""},
		{"; comment", ""},
		{"", ""},
		{"not-an-ip", ""},
		{"1.2.3.4/24", "1.2.3.0/24"}, // masked
	}
	for _, c := range cases {
		p, ok := parseCIDRLine(c.in)
		if c.want == "" {
			if ok {
				t.Errorf("parseCIDRLine(%q) ok=true, want skipped", c.in)
			}
			continue
		}
		if !ok || p.String() != c.want {
			t.Errorf("parseCIDRLine(%q) = (%q,%v), want %q", c.in, p.String(), ok, c.want)
		}
	}
}

func TestIntervalBounds(t *testing.T) {
	// 10.0.0.0/24 -> [10.0.0.0, 10.0.1.0)
	start, end, ok := intervalBounds(netip.MustParsePrefix("10.0.0.0/24"))
	if !ok {
		t.Fatal("ok=false for /24")
	}
	s, _ := netip.AddrFromSlice(start)
	e, _ := netip.AddrFromSlice(end)
	if s.String() != "10.0.0.0" || e.String() != "10.0.1.0" {
		t.Fatalf("bounds = [%s,%s), want [10.0.0.0,10.0.1.0)", s, e)
	}

	// single host /32 -> [x, x+1)
	start, end, ok = intervalBounds(netip.MustParsePrefix("192.0.2.5/32"))
	if !ok {
		t.Fatal("ok=false for /32")
	}
	s, _ = netip.AddrFromSlice(start)
	e, _ = netip.AddrFromSlice(end)
	if s.String() != "192.0.2.5" || e.String() != "192.0.2.6" {
		t.Fatalf("bounds = [%s,%s), want [192.0.2.5,192.0.2.6)", s, e)
	}

	// IPv6 /64
	start, end, ok = intervalBounds(netip.MustParsePrefix("2001:db8::/64"))
	if !ok {
		t.Fatal("ok=false for v6 /64")
	}
	s, _ = netip.AddrFromSlice(start)
	e, _ = netip.AddrFromSlice(end)
	if s.String() != "2001:db8::" || e.String() != "2001:db8:0:1::" {
		t.Fatalf("v6 bounds = [%s,%s)", s, e)
	}
}
