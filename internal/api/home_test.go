package api

import (
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"
)

func testHome() *HomeNet {
	p := netip.MustParsePrefix
	return &HomeNet{
		Interfaces: func() ([]Interface, error) {
			return []Interface{
				{Name: "lo", Loopback: true, Addrs: []netip.Prefix{p("127.0.0.1/8")}},
				{Name: "lan0", Addrs: []netip.Prefix{p("192.168.1.1/24"), p("fd00::1/64"), p("fe80::1/64")}},
				// Behind an ISP router: the uplink's network is private too.
				{Name: "uplink0", Addrs: []netip.Prefix{p("192.168.0.5/24"), p("fe80::2/64")}},
			}, nil
		},
		DefaultRoutes: func() map[string]bool { return map[string]bool{"uplink0": true} },
	}
}

func TestHomeNet(t *testing.T) {
	h := testHome()
	for ip, want := range map[string]bool{
		"192.168.1.20":        true,
		"::ffff:192.168.1.20": true,
		"fd00::9":             true,
		"127.0.0.1":           true,
		"::1":                 true,
		"fe80::5%lan0":        true,
		"192.168.0.9":         false, // the ISP router's network
		"fe80::5%uplink0":     false,
		"fe80::5":             false,
		"10.0.0.1":            false,
		"100.64.0.5":          false,
		"203.0.113.5":         false,
	} {
		if got := h.Contains(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Contains(%s) = %v, want %v", ip, got, want)
		}
	}
	if as := h.Addrs(); len(as) != 2 || as[0].String() != "192.168.1.1" || as[1].String() != "fd00::1" {
		t.Errorf("Addrs() = %v", as)
	}
}

func TestHomeListenerClosesOutsiders(t *testing.T) {
	f := newFixture(t)
	f.srv.cfg.Home = func(netip.Addr) bool { return false }
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	if err := f.srv.Listen([]string{addr}); err != nil {
		t.Fatal(err)
	}
	defer f.srv.Close()
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err == nil {
		c.Close()
		t.Fatal("TLS handshake succeeded from outside the home network")
	}
}

// With gk-network, gk-fltr runs on a one-armed box: its only interface
// carries the default route (to the real router) and is the home LAN.
func TestHomeNetOneArmed(t *testing.T) {
	p := netip.MustParsePrefix
	h := &HomeNet{
		Interfaces: func() ([]Interface, error) {
			return []Interface{
				{Name: "lo", Loopback: true, Addrs: []netip.Prefix{p("127.0.0.1/8")}},
				{Name: "eth0", Addrs: []netip.Prefix{p("192.168.1.2/24"), p("fe80::2/64")}},
				{Name: "wlan0"}, // present but unused, as on a Raspberry Pi
			}, nil
		},
		DefaultRoutes: func() map[string]bool { return map[string]bool{"eth0": true} },
	}
	for ip, want := range map[string]bool{
		"192.168.1.20": true,
		"fe80::5%eth0": true,
		"192.168.0.9":  false,
		"10.0.0.1":     false,
	} {
		if got := h.Contains(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Contains(%s) = %v, want %v", ip, got, want)
		}
	}
	if as := h.Addrs(); len(as) != 1 || as[0].String() != "192.168.1.2" {
		t.Errorf("Addrs() = %v", as)
	}
}
