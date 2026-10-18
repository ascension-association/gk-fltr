// Package steer implements targeted ARP steering: it redirects selected
// client devices' traffic through this host (which then forwards it on to the
// real gateway) so that filtering rules can be applied in-path.
//
// This is the non-destructive, "inline filter" model. It deliberately does NOT
// exhaust or disable the existing DHCP server or gateway; the real router keeps
// running and this host forwards every packet it receives. If forwarding is
// off, do not run this: steering without forwarding would black-hole the
// managed clients.
package steer

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/mdlayher/arp"
)

// Target is a client device to steer through this host.
type Target struct {
	IP  netip.Addr
	MAC net.HardwareAddr // resolved at startup
}

// Steerer maintains ARP cache entries on managed clients and on the gateway so
// that both believe this host owns the other end's IP. Clients can be added
// while it runs (Add, Watch).
type Steerer struct {
	iface   *net.Interface
	selfMAC net.HardwareAddr
	selfIP  netip.Addr
	subnet  netip.Prefix
	gateway netip.Addr
	gwMAC   net.HardwareAddr
	targets []*Target
	every   time.Duration

	client *arp.Client
	// write sends an ARP packet; it is client.WriteTo except in tests.
	write func(p *arp.Packet, to net.HardwareAddr) error
	mu    sync.Mutex
}

// Config configures a Steerer.
type Config struct {
	Interface string        // e.g. "eth0"
	Gateway   netip.Addr    // the real router this host forwards to
	Targets   []netip.Addr  // client IPs to manage; resolved by New
	Known     []Target      // clients to manage whose MACs are already known
	Interval  time.Duration // re-assertion interval (0 => 2s)
}

// New resolves the interface and the MACs of the gateway and every target.
func New(cfg Config) (*Steerer, error) {
	ifi, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", cfg.Interface, err)
	}
	c, err := arp.Dial(ifi)
	if err != nil {
		return nil, fmt.Errorf("arp dial: %w", err)
	}
	interval := cfg.Interval
	if interval == 0 {
		interval = 2 * time.Second
	}
	subnet, self, err := ifaceIPv4Prefix(ifi)
	if err != nil {
		c.Close()
		return nil, err
	}
	s := &Steerer{
		iface:   ifi,
		selfMAC: ifi.HardwareAddr,
		selfIP:  self,
		subnet:  subnet.Masked(),
		gateway: cfg.Gateway,
		every:   interval,
		client:  c,
		write:   c.WriteTo,
	}

	s.client.SetDeadline(time.Now().Add(5 * time.Second))
	s.gwMAC, err = s.client.Resolve(cfg.Gateway)
	if err != nil {
		return nil, fmt.Errorf("resolve gateway %s: %w", cfg.Gateway, err)
	}

	for _, ip := range cfg.Targets {
		s.client.SetDeadline(time.Now().Add(5 * time.Second))
		mac, err := s.client.Resolve(ip)
		if err != nil {
			log.Printf("steer: skipping %s: resolve failed: %v", ip, err)
			continue
		}
		s.targets = append(s.targets, &Target{IP: ip, MAC: mac})
		log.Printf("steer: managing %s (%s)", ip, mac)
	}
	s.client.SetDeadline(time.Time{})
	if len(cfg.Targets) > 0 && len(s.targets) == 0 {
		return nil, fmt.Errorf("no reachable targets")
	}
	for _, t := range cfg.Known {
		s.targets = append(s.targets, &Target{IP: t.IP, MAC: t.MAC})
		log.Printf("steer: managing %s (%s)", t.IP, t.MAC)
	}
	return s, nil
}

// Len returns the number of managed clients.
func (s *Steerer) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.targets)
}

// Add starts managing the client ip at mac, or updates its MAC, and steers
// it at once. It ignores addresses outside the interface's subnet, this
// host and the gateway, and reports whether anything changed.
func (s *Steerer) Add(ip netip.Addr, mac net.HardwareAddr) bool {
	if !s.manageable(ip) || len(mac) != 6 || bytes.Equal(mac, s.selfMAC) || bytes.Equal(mac, s.gwMAC) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.find(ip)
	switch {
	case t == nil:
		t = &Target{IP: ip, MAC: slices.Clone(mac)}
		s.targets = append(s.targets, t)
		log.Printf("steer: managing new client %s (%s)", ip, mac)
	case !bytes.Equal(t.MAC, mac):
		log.Printf("steer: client %s moved from %s to %s", ip, t.MAC, mac)
		t.MAC = slices.Clone(mac)
	default:
		return false
	}
	s.assertOne(t)
	return true
}

// manageable reports whether ip is a client address on this subnet.
func (s *Steerer) manageable(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.Is4() && s.subnet.Contains(ip) && isUnicastHost(ip, s.subnet) && ip != s.selfIP && ip != s.gateway
}

// find returns the target with ip. Called with s.mu held.
func (s *Steerer) find(ip netip.Addr) *Target {
	for _, t := range s.targets {
		if t.IP == ip {
			return t
		}
	}
	return nil
}

// Watch adds clients as they announce themselves: devices joining the
// network broadcast ARP for their own address (RFC 5227) and for the
// gateway, which this reads. It returns when the Steerer is closed.
func (s *Steerer) Watch() {
	for {
		p, _, err := s.client.Read()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(100 * time.Millisecond) // e.g. a malformed packet
			continue
		}
		// Probes (sender 0.0.0.0) only ask whether an address is free;
		// the announcement that follows has the sender's address.
		if p.SenderIP.IsUnspecified() {
			continue
		}
		s.Add(p.SenderIP, p.SenderHardwareAddr)
	}
}

// reply sends an unsolicited ARP reply claiming senderIP lives at s.selfMAC,
// delivered to dstHW/dstIP.
func (s *Steerer) reply(senderIP netip.Addr, dstHW net.HardwareAddr, dstIP netip.Addr) error {
	p, err := arp.NewPacket(arp.OperationReply, s.selfMAC, senderIP, dstHW, dstIP)
	if err != nil {
		return err
	}
	return s.write(p, dstHW)
}

// assert pushes one round of ARP entries to every managed client and the gateway.
func (s *Steerer) assert() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.targets {
		s.assertOne(t)
	}
}

// assertOne pushes the ARP entries for one client. Called with s.mu held.
func (s *Steerer) assertOne(t *Target) {
	// Tell the client: gateway is at our MAC.
	if err := s.reply(s.gateway, t.MAC, t.IP); err != nil {
		log.Printf("steer: client %s: %v", t.IP, err)
	}
	// Tell the gateway: client is at our MAC.
	if err := s.reply(t.IP, s.gwMAC, s.gateway); err != nil {
		log.Printf("steer: gateway for %s: %v", t.IP, err)
	}
}

// Run asserts steering entries every interval until stop is closed.
func (s *Steerer) Run(stop <-chan struct{}) {
	t := time.NewTicker(s.every)
	defer t.Stop()
	s.assert()
	for {
		select {
		case <-stop:
			s.restore()
			return
		case <-t.C:
			s.assert()
		}
	}
}

// restore sends correct ARP mappings so clients and gateway recover quickly
// instead of waiting for their caches to time out when we stop.
func (s *Steerer) restore() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.targets {
		// client: gateway is really at gwMAC
		if p, err := arp.NewPacket(arp.OperationReply, s.gwMAC, s.gateway, t.MAC, t.IP); err == nil {
			_ = s.write(p, t.MAC)
		}
		// gateway: client is really at its own MAC
		if p, err := arp.NewPacket(arp.OperationReply, t.MAC, t.IP, s.gwMAC, s.gateway); err == nil {
			_ = s.write(p, s.gwMAC)
		}
	}
	log.Printf("steer: restored %d client(s)", len(s.targets))
}

// Close releases the ARP socket.
func (s *Steerer) Close() error { return s.client.Close() }
