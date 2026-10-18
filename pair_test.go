package main

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/ascension-association/gk-fltr/internal/api"
)

func TestAPIAddresses(t *testing.T) {
	for _, tc := range []struct {
		flag []string
		want []string
		err  bool
	}{
		{nil, []string{":8443"}, false},
		{[]string{"off"}, nil, false},
		{[]string{"192.168.1.1:8443", "[fd00::1]:8443"}, []string{"192.168.1.1:8443", "[fd00::1]:8443"}, false},
		{[]string{"off", ":8443"}, nil, true},
		{[]string{"203.0.113.1:8443"}, nil, true},
		{[]string{"192.168.1.1"}, nil, true}, // no port
	} {
		got, err := apiAddresses(tc.flag)
		if (err != nil) != tc.err || !slices.Equal(got, tc.want) {
			t.Errorf("apiAddresses(%q) = %q, %v", tc.flag, got, err)
		}
	}
}

func TestPairingURL(t *testing.T) {
	home := &api.HomeNet{
		Interfaces: func() ([]api.Interface, error) {
			return []api.Interface{
				{Name: "uplink0", Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.0.5/24")}},
				{Name: "lan0", Addrs: []netip.Prefix{netip.MustParsePrefix("fd00::1/64"), netip.MustParsePrefix("192.168.1.1/24")}},
			}, nil
		},
		DefaultRoutes: func() map[string]bool { return map[string]bool{"uplink0": true} },
	}
	for _, tc := range []struct {
		apiURL string
		addrs  []string
		want   string
	}{
		{"", []string{":8443"}, "https://192.168.1.1:8443"}, // the LAN, not the private uplink
		{"", []string{"[::]:9000"}, "https://192.168.1.1:9000"},
		{"", []string{"[fd00::1]:8443"}, "https://[fd00::1]:8443"},
		{"https://router.lan:8443", []string{":8443"}, "https://router.lan:8443"},
	} {
		if got, ok := pairingURL(tc.apiURL, tc.addrs, home); !ok || got != tc.want {
			t.Errorf("pairingURL(%q, %q) = %q, %v; want %q", tc.apiURL, tc.addrs, got, ok, tc.want)
		}
	}
	empty := &api.HomeNet{
		Interfaces:    func() ([]api.Interface, error) { return nil, nil },
		DefaultRoutes: func() map[string]bool { return nil },
	}
	if _, ok := pairingURL("", []string{":8443"}, empty); ok {
		t.Error("pairingURL without a LAN address: ok")
	}
}
