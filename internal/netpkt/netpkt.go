// Package netpkt builds raw IPv4/IPv6 packets.
package netpkt

import (
	"encoding/binary"
	"net/netip"
)

// TCP flag bits.
const (
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
)

// TCP returns an IP packet (v4 or v6, following src) carrying a TCP segment
// with valid checksums. src and dst must be of the same address family.
func TCP(src, dst netip.AddrPort, seq, ack uint32, flags uint8, payload []byte) []byte {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:], src.Port())
	binary.BigEndian.PutUint16(tcp[2:], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	copy(tcp[20:], payload)
	return ip(src.Addr(), dst.Addr(), 6, tcp, 16, true)
}

// UDP returns an IP packet carrying a UDP datagram with valid checksums.
func UDP(src, dst netip.AddrPort, payload []byte) []byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:], src.Port())
	binary.BigEndian.PutUint16(udp[2:], dst.Port())
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], payload)
	return ip(src.Addr(), dst.Addr(), 17, udp, 6, true)
}

// PortUnreachable returns an ICMP (or ICMPv6) port unreachable error sent
// from "from" to the source of orig, an IP packet that "from" rejects. On a
// connected UDP socket the recipient sees ECONNREFUSED.
func PortUnreachable(from netip.Addr, orig []byte) []byte {
	if len(orig) < 1 {
		return nil
	}
	var (
		to    netip.Addr
		max   int
		msg   []byte
		proto uint8
	)
	switch orig[0] >> 4 {
	case 4:
		if len(orig) < 20 {
			return nil
		}
		// Destination unreachable, port unreachable (RFC 792), quoting as
		// much of the original as fits in a 576 byte datagram (RFC 1812).
		to, max, proto = netip.AddrFrom4([4]byte(orig[12:16])), 576-28, 1
		msg = []byte{3, 3, 0, 0, 0, 0, 0, 0}
	case 6:
		if len(orig) < 40 {
			return nil
		}
		// Destination unreachable, port unreachable (RFC 4443), quoting as
		// much of the original as fits in the minimum MTU.
		to, max, proto = netip.AddrFrom16([16]byte(orig[8:24])), 1280-48, 58
		msg = []byte{1, 4, 0, 0, 0, 0, 0, 0}
	default:
		return nil
	}
	if len(orig) > max {
		orig = orig[:max]
	}
	msg = append(msg, orig...)
	if proto == 1 {
		// ICMPv4 has no pseudo-header.
		binary.BigEndian.PutUint16(msg[2:], ^fold(sum(0, msg)))
		return ip(from, to, proto, msg, 2, false)
	}
	return ip(from, to, proto, msg, 2, true)
}

// ip prepends an IP header to l4 and, if pseudo is set, fills in the L4
// checksum (which covers the pseudo-header) at csumOff.
func ip(src, dst netip.Addr, proto uint8, l4 []byte, csumOff int, pseudo bool) []byte {
	var pkt []byte
	if src.Is4() {
		pkt = make([]byte, 20+len(l4))
		h := pkt[:20]
		h[0] = 0x45
		binary.BigEndian.PutUint16(h[2:], uint16(len(pkt)))
		h[6] = 0x40 // don't fragment
		h[8] = 64
		h[9] = proto
		s, d := src.As4(), dst.As4()
		copy(h[12:], s[:])
		copy(h[16:], d[:])
		binary.BigEndian.PutUint16(h[10:], ^fold(sum(0, h)))
		copy(pkt[20:], l4)
	} else {
		pkt = make([]byte, 40+len(l4))
		h := pkt[:40]
		h[0] = 0x60
		binary.BigEndian.PutUint16(h[4:], uint16(len(l4)))
		h[6] = proto
		h[7] = 64
		s, d := src.As16(), dst.As16()
		copy(h[8:], s[:])
		copy(h[24:], d[:])
		copy(pkt[40:], l4)
	}
	if !pseudo {
		return pkt
	}
	seg := pkt[len(pkt)-len(l4):]
	// Pseudo-header checksum.
	s, d := src.AsSlice(), dst.AsSlice()
	c := sum(0, s)
	c = sum(c, d)
	c += uint32(proto) + uint32(len(seg))
	binary.BigEndian.PutUint16(seg[csumOff:], ^fold(sum(c, seg)))
	return pkt
}

func sum(c uint32, b []byte) uint32 {
	for len(b) >= 2 {
		c += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		c += uint32(b[0]) << 8
	}
	return c
}

func fold(c uint32) uint16 {
	for c > 0xffff {
		c = c>>16 + c&0xffff
	}
	return uint16(c)
}
