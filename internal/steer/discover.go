package steer

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/mdlayher/arp"
)

// DiscoverClients ARP-scans the interface's IPv4 subnet and returns the hosts
// that respond, excluding this host and the gateway. These are the devices the
// appliance can manage when you ask it to steer the whole LAN. Hosts already
// steered answer too: the scan asks them directly.
func DiscoverClients(iface string, gateway netip.Addr, perHost time.Duration) ([]Target, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", iface, err)
	}
	prefix, self, err := ifaceIPv4Prefix(ifi)
	if err != nil {
		return nil, err
	}
	if perHost == 0 {
		perHost = 200 * time.Millisecond
	}

	c, err := arp.Dial(ifi)
	if err != nil {
		return nil, fmt.Errorf("arp dial: %w", err)
	}
	defer c.Close()

	var found []Target
	for ip := prefix.Masked().Addr().Next(); prefix.Contains(ip); ip = ip.Next() {
		if ip == self || ip == gateway || !isUnicastHost(ip, prefix) {
			continue
		}
		c.SetDeadline(time.Now().Add(perHost))
		mac, err := c.Resolve(ip)
		if err != nil {
			continue // no reply within window => treat as absent
		}
		found = append(found, Target{IP: ip, MAC: mac})
	}
	return found, nil
}

// ifaceIPv4Prefix returns the first IPv4 prefix and address on the interface.
func ifaceIPv4Prefix(ifi *net.Interface) (netip.Prefix, netip.Addr, error) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return netip.Prefix{}, netip.Addr{}, err
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipn.IP.To4()
		if ip4 == nil {
			continue
		}
		ones, _ := ipn.Mask.Size()
		addr, ok := netip.AddrFromSlice(ip4)
		if !ok {
			continue
		}
		return netip.PrefixFrom(addr, ones), addr, nil
	}
	return netip.Prefix{}, netip.Addr{}, fmt.Errorf("no IPv4 address on %s", ifi.Name)
}

// isUnicastHost excludes the network and broadcast addresses of the prefix.
func isUnicastHost(ip netip.Addr, p netip.Prefix) bool {
	if ip == p.Masked().Addr() {
		return false // network address
	}
	// Broadcast = all host bits set.
	b := ip.As4()
	bits := p.Bits()
	hostBits := 32 - bits
	if hostBits <= 0 {
		return true
	}
	v := binary.BigEndian.Uint32(b[:])
	mask := uint32((1 << hostBits) - 1)
	return v&mask != mask
}
