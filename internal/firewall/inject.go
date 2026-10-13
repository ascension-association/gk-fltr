package firewall

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"

	"github.com/ascension-association/gk-fltr/internal/netpkt"
)

// Injector sends packets through raw sockets, so that a client whose flow
// was blocked fails immediately instead of waiting for a timeout: a TCP RST
// for TCP, an ICMP port unreachable for UDP (QUIC).
type Injector struct {
	fd4, fd6 int
}

// NewInjector opens the raw sockets. IPv6 is optional.
func NewInjector() (*Injector, error) {
	fd4, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("raw IPv4 socket: %w", err)
	}
	fd6, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		fd6 = -1
	}
	return &Injector{fd4: fd4, fd6: fd6}, nil
}

// Reset sends a TCP RST from "from" to "to" with sequence number seq.
func (in *Injector) Reset(from, to netip.AddrPort, seq uint32) error {
	return in.send(to.Addr(), netpkt.TCP(from, to, seq, 0, netpkt.RST, nil))
}

// Nudge sends "to" a bare ACK from "from" with random (almost certainly
// out-of-window) sequence numbers, which makes "to" answer with a duplicate
// ACK (RFC 793, RFC 5961). Once a flow is in the block set, that answer hits
// the "reject with tcp reset" rule and the kernel resets "to" with exactly
// the sequence number it expects. This ends established connections for
// which gk-fltr has no current packet to build a RST from.
func (in *Injector) Nudge(from, to netip.AddrPort) error {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	seq, ack := binary.BigEndian.Uint32(b[:4]), binary.BigEndian.Uint32(b[4:])
	return in.send(to.Addr(), netpkt.TCP(from, to, seq, ack, netpkt.ACK, nil))
}

// Unreachable sends the source of trigger, a packet addressed to "from", an
// ICMP port unreachable error from "from".
func (in *Injector) Unreachable(from netip.Addr, trigger []byte) error {
	pkt := netpkt.PortUnreachable(from, trigger)
	if pkt == nil {
		return fmt.Errorf("cannot quote %d byte packet", len(trigger))
	}
	var to netip.Addr
	if from.Is4() {
		to = netip.AddrFrom4([4]byte(pkt[16:20]))
	} else {
		to = netip.AddrFrom16([16]byte(pkt[24:40]))
	}
	return in.send(to, pkt)
}

func (in *Injector) send(to netip.Addr, pkt []byte) error {
	if to.Is4() {
		return unix.Sendto(in.fd4, pkt, 0, &unix.SockaddrInet4{Addr: to.As4()})
	}
	if in.fd6 < 0 {
		return fmt.Errorf("no raw IPv6 socket")
	}
	// The port must be zero for raw sockets.
	return unix.Sendto(in.fd6, pkt, 0, &unix.SockaddrInet6{Addr: to.As16()})
}

// Close closes the raw sockets.
func (in *Injector) Close() error {
	if in.fd6 >= 0 {
		unix.Close(in.fd6)
	}
	return unix.Close(in.fd4)
}
