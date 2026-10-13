package netpkt

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// valid reports whether the ones' complement sum over b (plus c) checks out.
func valid(c uint32, b []byte) bool { return fold(sum(c, b)) == 0xffff }

func TestPortUnreachable(t *testing.T) {
	client := netip.MustParseAddrPort("192.168.1.10:50000")
	server := netip.MustParseAddrPort("203.0.113.10:443")
	orig := UDP(client, server, make([]byte, 1200))

	pkt := PortUnreachable(server.Addr(), orig)
	if len(pkt) != 576 {
		t.Errorf("len = %d, want 576", len(pkt))
	}
	if !valid(0, pkt[:20]) {
		t.Error("bad IPv4 header checksum")
	}
	if got := netip.AddrFrom4([4]byte(pkt[16:20])); got != client.Addr() {
		t.Errorf("sent to %s, want %s", got, client.Addr())
	}
	icmp := pkt[20:]
	if icmp[0] != 3 || icmp[1] != 3 || !valid(0, icmp) {
		t.Errorf("ICMP header %x, checksum valid %v", icmp[:4], valid(0, icmp))
	}
	if !bytes.Equal(icmp[8:36], orig[:28]) {
		t.Error("ICMP does not quote the original headers")
	}

	c6 := netip.MustParseAddrPort("[fd00::10]:50000")
	s6 := netip.MustParseAddrPort("[2001:db8::1]:443")
	pkt = PortUnreachable(s6.Addr(), UDP(c6, s6, make([]byte, 1300)))
	if len(pkt) != 1280 || pkt[6] != 58 {
		t.Fatalf("len = %d next header = %d, want 1280, 58", len(pkt), pkt[6])
	}
	icmp = pkt[40:]
	c := sum(sum(0, s6.Addr().AsSlice()), c6.Addr().AsSlice()) + 58 + uint32(len(icmp))
	if icmp[0] != 1 || icmp[1] != 4 || !valid(c, icmp) {
		t.Errorf("ICMPv6 header %x, checksum valid %v", icmp[:4], valid(c, icmp))
	}
	if binary.BigEndian.Uint16(pkt[4:6]) != uint16(len(icmp)) {
		t.Error("bad IPv6 payload length")
	}
}
