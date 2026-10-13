package firewall

import (
	"net/netip"
	"testing"
)

func TestKeyRoundTrip(t *testing.T) {
	for _, tc := range []struct{ c, s string }{
		{"192.168.1.10:50000", "142.250.1.1:443"},
		{"[fd00::10]:50000", "[2001:db8::1]:443"},
	} {
		c, s := netip.MustParseAddrPort(tc.c), netip.MustParseAddrPort(tc.s)
		m, ok := parseKey(key(17, c, s))
		if !ok || m.Proto != 17 || m.Client != c || m.Server != s {
			t.Errorf("parseKey(key(%s, %s)) = %+v, %v", c, s, m, ok)
		}
	}
}
