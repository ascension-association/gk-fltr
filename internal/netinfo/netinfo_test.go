package netinfo

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseRoutes(t *testing.T) {
	rs := ParseRoutes4(strings.NewReader(`Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
uplink0	00000000	0100A8C0	0003	0	0	0	00000000	0	0	0
uplink0	0000A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
lan0	0001A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
wg0	00000000	00000000	0000	0	0	0	00000000	0	0	0
ppp0	00000000	00000000	0001	0	0	0	00000000	0	0	0
`))
	rs = append(rs, ParseRoutes6(strings.NewReader(`00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 uplink6
fd000000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 lan0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
`))...)
	var got []string
	for _, r := range rs {
		got = append(got, r.Iface+" "+r.Gateway.String())
	}
	// wg0 is down and lo is a reject route; ppp0 has no gateway.
	want := "uplink0 192.168.0.1,ppp0 invalid IP,uplink6 fe80::1%uplink6"
	if strings.Join(got, ",") != want {
		t.Errorf("routes = %q, want %q", strings.Join(got, ","), want)
	}
}

func TestHexLEToIP(t *testing.T) {
	// /proc/net/route stores the gateway little-endian: reverse of dotted order.
	for hexStr, want := range map[string]string{
		"0101A8C0": "192.168.1.1",
		"011FA8C0": "192.168.31.1",
		"0100007F": "127.0.0.1",
		"00000000": "0.0.0.0",
	} {
		if got, err := HexLEToIP(hexStr); err != nil || got.String() != want {
			t.Errorf("HexLEToIP(%q) = %s, %v; want %s", hexStr, got, err, want)
		}
	}
	if _, err := HexLEToIP("zzzz"); err == nil {
		t.Error("expected error for bad hex")
	}
}

func TestOneArmed(t *testing.T) {
	gw := Route{Iface: "eth0", Gateway: mustAddr("192.168.1.1")}
	for _, tc := range []struct {
		routable []string
		routes   []Route
		want     string
	}{
		{[]string{"eth0"}, []Route{gw}, "eth0"},                                          // next to the router
		{[]string{"lan0", "uplink0"}, []Route{{"uplink0", mustAddr("203.0.113.1")}}, ""}, // the router
		{[]string{"eth0"}, nil, ""},                                                      // no default route yet
		{[]string{"ppp0"}, []Route{{Iface: "ppp0"}}, ""},                                 // point-to-point uplink, no gateway
		{nil, []Route{gw}, ""},
	} {
		if got, ok := oneArmed(tc.routable, tc.routes); got != tc.want || ok != (tc.want != "") {
			t.Errorf("oneArmed(%v, %v) = %q, %v; want %q", tc.routable, tc.routes, got, ok, tc.want)
		}
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
