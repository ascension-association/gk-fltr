package engine

import (
	"encoding/binary"
	"net/netip"
)

const (
	protoTCP = 6
	protoUDP = 17

	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

// pktInfo is what the engine needs from a packet's IP and L4 headers.
type pktInfo struct {
	proto      uint8
	src, dst   netip.AddrPort
	seq, ack   uint32 // TCP only
	flags      uint8  // TCP only
	payloadLen int    // L4 payload length
}

// parse decodes an IPv4 or IPv6 packet carrying TCP or UDP.
func parse(b []byte) (pktInfo, bool) {
	if len(b) < 1 {
		return pktInfo{}, false
	}
	var (
		info     pktInfo
		src, dst netip.Addr
		l4       []byte
	)
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return info, false
		}
		ihl := int(b[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(b[2:4]))
		if ihl < 20 || total < ihl || len(b) < ihl {
			return info, false
		}
		if total > len(b) {
			total = len(b) // truncated capture
		}
		if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			return info, false // non-first fragment
		}
		info.proto = b[9]
		src = netip.AddrFrom4([4]byte(b[12:16]))
		dst = netip.AddrFrom4([4]byte(b[16:20]))
		l4 = b[ihl:total]
	case 6:
		if len(b) < 40 {
			return info, false
		}
		src = netip.AddrFrom16([16]byte(b[8:24]))
		dst = netip.AddrFrom16([16]byte(b[24:40]))
		next, off := b[6], 40
		end := 40 + int(binary.BigEndian.Uint16(b[4:6]))
		if end > len(b) {
			end = len(b)
		}
		// Skip common extension headers.
		for next == 0 || next == 43 || next == 60 || next == 44 {
			if off+8 > end {
				return info, false
			}
			if next == 44 {
				if binary.BigEndian.Uint16(b[off+2:off+4])&0xfff8 != 0 {
					return info, false // non-first fragment
				}
				next, off = b[off], off+8
				continue
			}
			next, off = b[off], off+(int(b[off+1])+1)*8
		}
		if off > end {
			return info, false
		}
		info.proto = next
		l4 = b[off:end]
	default:
		return info, false
	}

	switch info.proto {
	case protoTCP:
		if len(l4) < 20 {
			return info, false
		}
		doff := int(l4[12]>>4) * 4
		if doff < 20 || doff > len(l4) {
			return info, false
		}
		info.seq = binary.BigEndian.Uint32(l4[4:8])
		info.ack = binary.BigEndian.Uint32(l4[8:12])
		info.flags = l4[13]
		info.payloadLen = len(l4) - doff
	case protoUDP:
		if len(l4) < 8 {
			return info, false
		}
		info.payloadLen = len(l4) - 8
	default:
		return info, false
	}
	info.src = netip.AddrPortFrom(src.Unmap(), binary.BigEndian.Uint16(l4[0:2]))
	info.dst = netip.AddrPortFrom(dst.Unmap(), binary.BigEndian.Uint16(l4[2:4]))
	return info, true
}
