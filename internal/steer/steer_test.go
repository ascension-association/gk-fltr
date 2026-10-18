package steer

import (
	"net"
	"net/netip"
	"testing"

	"github.com/mdlayher/arp"
)

type sent struct {
	senderIP netip.Addr
	to       string
}

func testSteerer(t *testing.T) (*Steerer, *[]sent) {
	t.Helper()
	var out []sent
	s := &Steerer{
		selfMAC: mustMAC("02:00:00:00:00:fe"),
		selfIP:  netip.MustParseAddr("192.168.1.2"),
		subnet:  netip.MustParsePrefix("192.168.1.0/24"),
		gateway: netip.MustParseAddr("192.168.1.1"),
		gwMAC:   mustMAC("02:00:00:00:00:01"),
		write: func(p *arp.Packet, to net.HardwareAddr) error {
			out = append(out, sent{p.SenderIP, to.String()})
			return nil
		},
	}
	return s, &out
}

func mustMAC(s string) net.HardwareAddr { m, _ := net.ParseMAC(s); return m }

func TestAdd(t *testing.T) {
	s, out := testSteerer(t)
	phone := mustMAC("02:00:00:00:00:10")

	if !s.Add(netip.MustParseAddr("192.168.1.10"), phone) {
		t.Fatal("new client not added")
	}
	// It is steered at once: the client hears the gateway is at our MAC,
	// and the gateway hears the client is.
	want := []sent{{netip.MustParseAddr("192.168.1.1"), phone.String()}, {netip.MustParseAddr("192.168.1.10"), "02:00:00:00:00:01"}}
	if len(*out) != 2 || (*out)[0] != want[0] || (*out)[1] != want[1] {
		t.Errorf("sent %v, want %v", *out, want)
	}
	if s.Add(netip.MustParseAddr("192.168.1.10"), phone) || s.Len() != 1 {
		t.Error("known client added again")
	}
	// A new device took the address: follow its MAC.
	if !s.Add(netip.MustParseAddr("192.168.1.10"), mustMAC("02:00:00:00:00:11")) || s.Len() != 1 {
		t.Error("MAC change not applied")
	}

	for _, tc := range []struct {
		ip, mac string
	}{
		{"192.168.1.1", "02:00:00:00:00:20"},   // the gateway's address
		{"192.168.1.2", "02:00:00:00:00:20"},   // ours
		{"192.168.1.30", "02:00:00:00:00:fe"},  // our own packets
		{"192.168.1.30", "02:00:00:00:00:01"},  // the gateway's packets
		{"192.168.2.30", "02:00:00:00:00:20"},  // another subnet
		{"192.168.1.255", "02:00:00:00:00:20"}, // broadcast
		{"192.168.1.0", "02:00:00:00:00:20"},   // network address
	} {
		if s.Add(netip.MustParseAddr(tc.ip), mustMAC(tc.mac)) {
			t.Errorf("Add(%s, %s) accepted", tc.ip, tc.mac)
		}
	}
	if s.Len() != 1 {
		t.Errorf("Len = %d, want 1", s.Len())
	}
}
