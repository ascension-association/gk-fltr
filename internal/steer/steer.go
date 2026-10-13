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
	"fmt"
	"log"
	"net"
	"net/netip"
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
// that both believe this host owns the other end's IP.
type Steerer struct {
	iface   *net.Interface
	selfMAC net.HardwareAddr
	gateway netip.Addr
	gwMAC   net.HardwareAddr
	targets []*Target
	every   time.Duration

	client *arp.Client
	mu     sync.Mutex
}

// Config configures a Steerer.
type Config struct {
	Interface string        // e.g. "eth0"
	Gateway   netip.Addr    // the real router this host forwards to
	Targets   []netip.Addr  // client IPs to manage
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
	s := &Steerer{
		iface:   ifi,
		selfMAC: ifi.HardwareAddr,
		gateway: cfg.Gateway,
		every:   interval,
		client:  c,
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
	if len(s.targets) == 0 {
		return nil, fmt.Errorf("no reachable targets")
	}
	return s, nil
}

// reply sends an unsolicited ARP reply claiming senderIP lives at s.selfMAC,
// delivered to dstHW/dstIP.
func (s *Steerer) reply(senderIP netip.Addr, dstHW net.HardwareAddr, dstIP netip.Addr) error {
	p, err := arp.NewPacket(arp.OperationReply, s.selfMAC, senderIP, dstHW, dstIP)
	if err != nil {
		return err
	}
	return s.client.WriteTo(p, dstHW)
}

// assert pushes one round of ARP entries to every managed client and the gateway.
func (s *Steerer) assert() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.targets {
		// Tell the client: gateway is at our MAC.
		if err := s.reply(s.gateway, t.MAC, t.IP); err != nil {
			log.Printf("steer: client %s: %v", t.IP, err)
		}
		// Tell the gateway: client is at our MAC.
		if err := s.reply(t.IP, s.gwMAC, s.gateway); err != nil {
			log.Printf("steer: gateway for %s: %v", t.IP, err)
		}
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
			_ = s.client.WriteTo(p, t.MAC)
		}
		// gateway: client is really at its own MAC
		if p, err := arp.NewPacket(arp.OperationReply, t.MAC, t.IP, s.gwMAC, s.gateway); err == nil {
			_ = s.client.WriteTo(p, s.gwMAC)
		}
	}
	log.Printf("steer: restored %d client(s)", len(s.targets))
}

// Close releases the ARP socket.
func (s *Steerer) Close() error { return s.client.Close() }
