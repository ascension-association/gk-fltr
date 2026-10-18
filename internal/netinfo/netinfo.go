// Package netinfo reads this host's default routes from /proc, for both
// gk-fltr (which interfaces are uplinks) and gk-network (which router to
// steer traffic to).
package netinfo

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Route is a default route.
type Route struct {
	Iface   string
	Gateway netip.Addr // invalid if the route has no gateway
}

// Route flags from <linux/route.h> and <linux/ipv6_route.h>.
const (
	rtfUp      = 0x1
	rtfGateway = 0x2
	rtfReject  = 0x200
)

// DefaultRoutes returns the host's IPv4 and IPv6 default routes.
func DefaultRoutes() []Route {
	var rs []Route
	if f, err := os.Open("/proc/net/route"); err == nil {
		rs = append(rs, ParseRoutes4(f)...)
		f.Close()
	}
	if f, err := os.Open("/proc/net/ipv6_route"); err == nil {
		rs = append(rs, ParseRoutes6(f)...)
		f.Close()
	}
	return rs
}

// Uplinks returns the names of the interfaces that carry a default route.
func Uplinks() map[string]bool {
	m := map[string]bool{}
	for _, r := range DefaultRoutes() {
		m[r.Iface] = true
	}
	return m
}

// Gateway returns the IPv4 default gateway on iface.
func Gateway(iface string) (netip.Addr, error) {
	for _, r := range DefaultRoutes() {
		if r.Iface == iface && r.Gateway.Is4() {
			return r.Gateway, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no default gateway found on %s", iface)
}

// ParseRoutes4 returns the default routes in /proc/net/route format.
func ParseRoutes4(r io.Reader) []Route {
	var rs []Route
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		// Iface Destination Gateway Flags RefCnt Use Metric Mask ...
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&rtfUp == 0 {
			continue
		}
		rt := Route{Iface: f[0]}
		if flags&rtfGateway != 0 {
			rt.Gateway, _ = HexLEToIP(f[2])
		}
		rs = append(rs, rt)
	}
	return rs
}

// ParseRoutes6 returns the default routes in /proc/net/ipv6_route format.
func ParseRoutes6(r io.Reader) []Route {
	var rs []Route
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		// dest destlen src srclen nexthop metric refcnt use flags iface
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[0] != strings.Repeat("0", 32) || f[1] != "00" || f[9] == "lo" {
			continue
		}
		flags, err := strconv.ParseUint(f[8], 16, 32)
		if err != nil || flags&rtfUp == 0 || flags&rtfReject != 0 {
			continue
		}
		rt := Route{Iface: f[9]}
		if b, err := hex.DecodeString(f[4]); err == nil && flags&rtfGateway != 0 {
			if a, ok := netip.AddrFromSlice(b); ok {
				rt.Gateway = a.WithZone(f[9])
			}
		}
		rs = append(rs, rt)
	}
	return rs
}

// HexLEToIP parses an IPv4 address as /proc/net/route stores it:
// little-endian hex, so "0101A8C0" is 192.168.1.1.
func HexLEToIP(h string) (netip.Addr, error) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 4 {
		return netip.Addr{}, fmt.Errorf("bad route hex %q", h)
	}
	return netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]}), nil
}

// OneArmed reports whether this host sits on the LAN with a single
// interface, next to the router rather than being it: exactly one interface
// has a routable address, and it has the IPv4 default gateway. It returns
// that interface.
func OneArmed() (iface string, ok bool) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", false
	}
	var routable []string
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLinkLocalUnicast() {
				routable = append(routable, ifc.Name)
				break
			}
		}
	}
	return oneArmed(routable, DefaultRoutes())
}

func oneArmed(routable []string, routes []Route) (string, bool) {
	if len(routable) != 1 {
		return "", false
	}
	for _, r := range routes {
		if r.Iface == routable[0] && r.Gateway.Is4() {
			return r.Iface, true
		}
	}
	return "", false
}
