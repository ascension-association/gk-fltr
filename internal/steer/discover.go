package steer

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/mdlayher/arp"
)

// DiscoverGateway returns the default-route gateway for the given interface by
// reading /proc/net/route. This lets the appliance find the existing router
// automatically instead of being told its IP.
func DiscoverGateway(iface string) (netip.Addr, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return netip.Addr{}, fmt.Errorf("open route table: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		name, dest, gw, flags := fields[0], fields[1], fields[2], fields[3]
		if name != iface || dest != "00000000" {
			continue // not this iface, or not the default route
		}
		// Flags must include RTF_UP(0x1) and RTF_GATEWAY(0x2).
		var fl uint64
		fmt.Sscanf(flags, "%x", &fl)
		if fl&0x2 == 0 {
			continue
		}
		ip, err := hexLEtoIP(gw)
		if err != nil {
			return netip.Addr{}, err
		}
		return ip, nil
	}
	return netip.Addr{}, fmt.Errorf("no default gateway found on %s", iface)
}

// hexLEtoIP parses a little-endian hex IPv4 (as /proc/net/route stores it):
// the four bytes are in reverse of dotted-quad order, so "0101A8C0" is
// 192.168.1.1.
func hexLEtoIP(h string) (netip.Addr, error) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 4 {
		return netip.Addr{}, fmt.Errorf("bad route hex %q", h)
	}
	return netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]}), nil
}

// DiscoverClients ARP-scans the interface's IPv4 subnet and returns the hosts
// that respond, excluding this host and the gateway. These are the devices the
// appliance can manage when you ask it to steer the whole LAN.
func DiscoverClients(iface string, gateway netip.Addr, perHost time.Duration) ([]netip.Addr, error) {
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

	var found []netip.Addr
	for ip := prefix.Masked().Addr().Next(); prefix.Contains(ip); ip = ip.Next() {
		if ip == self || ip == gateway || !isUnicastHost(ip, prefix) {
			continue
		}
		c.SetDeadline(time.Now().Add(perHost))
		if _, err := c.Resolve(ip); err != nil {
			continue // no reply within window => treat as absent
		}
		found = append(found, ip)
		log.Printf("steer: discovered client %s", ip)
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
