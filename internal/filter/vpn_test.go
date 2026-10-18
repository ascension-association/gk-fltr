package filter

import (
	"bytes"
	"testing"

	"github.com/google/nftables/expr"
)

func TestMatchWireGuardInit(t *testing.T) {
	exprs := matchWireGuardInit()
	type check struct {
		off, len uint32
		want     []byte
	}
	want := []check{
		{4, 2, []byte{0, 156}},     // UDP length: 8-byte header + 148-byte initiation
		{8, 4, []byte{1, 0, 0, 0}}, // message type 1 + 3 reserved zero bytes
	}
	var got []check
	for i, e := range exprs {
		p, ok := e.(*expr.Payload)
		if !ok {
			continue
		}
		if p.Base != expr.PayloadBaseTransportHeader {
			t.Errorf("payload %d: base %v, want transport header", i, p.Base)
		}
		c, ok := exprs[i+1].(*expr.Cmp)
		if !ok || c.Op != expr.CmpOpEq {
			t.Fatalf("payload %d not followed by an eq cmp", i)
		}
		got = append(got, check{p.Offset, p.Len, c.Data})
	}
	if len(got) != len(want) {
		t.Fatalf("got %d payload matches, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].off != want[i].off || got[i].len != want[i].len || !bytes.Equal(got[i].want, want[i].want) {
			t.Errorf("match %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if m, ok := exprs[1].(*expr.Cmp); !ok || !bytes.Equal(m.Data, []byte{protoUDP}) {
		t.Errorf("first match is not l4proto udp")
	}
}

func TestVPNPorts(t *testing.T) {
	seen := map[L4Port]bool{}
	for _, p := range VPNPorts {
		if p.Proto != protoTCP && p.Proto != protoUDP {
			t.Errorf("%s: bad proto %d", p.Name, p.Proto)
		}
		if p.Port == 0 {
			t.Errorf("%s: zero port", p.Name)
		}
		// Never drop DNS or web traffic outright.
		switch p.Port {
		case 53, 80, 443:
			t.Errorf("%s: port %d would break normal browsing", p.Name, p.Port)
		}
		if seen[p] {
			t.Errorf("duplicate VPN port %+v", p)
		}
		seen[p] = true
	}
}

func TestVPNDomains(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range VPNDomains {
		if got := parseBlocklistLine(d); got != d {
			t.Errorf("VPN domain %q parses as %q", d, got)
		}
		if seen[d] {
			t.Errorf("duplicate VPN domain %q", d)
		}
		seen[d] = true
	}
}
