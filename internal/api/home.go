package api

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/ascension-association/gk-fltr/internal/netinfo"
)

// HomeNet decides which addresses are on the home network: the subnets of
// this host's interfaces other than the uplinks (those carrying a default
// route), plus loopback. Private addresses alone are not enough: behind an
// ISP router, the uplink's network is private too.
//
// A host whose only addressed interfaces are uplinks sits on the home LAN
// itself, as with gk-network steering traffic through a one-armed box, so
// then the uplinks' subnets are home.
//
// Interfaces change (DHCP, interfaces coming up after gk-fltr), so the view
// is refreshed every few seconds.
type HomeNet struct {
	// Interfaces and DefaultRoutes default to the host's; tests replace them.
	Interfaces    func() ([]Interface, error)
	DefaultRoutes func() map[string]bool // interface names with a default route

	mu      sync.Mutex
	checked time.Time
	ifaces  map[string]bool // home interfaces, by name
	nets    []netip.Prefix  // home subnets
	addrs   []netip.Addr    // this host's addresses on them
}

// Interface is a network interface and its addresses.
type Interface struct {
	Name     string
	Loopback bool
	Addrs    []netip.Prefix // address with its subnet length, e.g. 192.168.1.1/24
}

const homeRefresh = 5 * time.Second

func (h *HomeNet) refresh() {
	if time.Since(h.checked) < homeRefresh && h.ifaces != nil {
		return
	}
	h.checked = time.Now()
	list, routes := h.Interfaces, h.DefaultRoutes
	if list == nil {
		list = hostInterfaces
	}
	if routes == nil {
		routes = netinfo.Uplinks
	}
	ifs, err := list()
	if err != nil {
		return // keep the previous view
	}
	uplinks := routes()
	oneArmed := true
	for _, ifc := range ifs {
		if !ifc.Loopback && !uplinks[ifc.Name] && hasRoutable(ifc) {
			oneArmed = false
		}
	}
	h.ifaces, h.nets, h.addrs = map[string]bool{}, nil, nil
	for _, ifc := range ifs {
		if ifc.Loopback || (uplinks[ifc.Name] && !oneArmed) {
			continue
		}
		h.ifaces[ifc.Name] = true
		for _, a := range ifc.Addrs {
			if a.Addr().IsLinkLocalUnicast() {
				continue // matched by zone in Contains
			}
			h.nets = append(h.nets, a.Masked())
			h.addrs = append(h.addrs, a.Addr())
		}
	}
}

// hasRoutable reports whether ifc has an address other than link-local.
func hasRoutable(ifc Interface) bool {
	for _, a := range ifc.Addrs {
		if !a.Addr().IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

// Contains reports whether ip is on the home network. A link-local ip
// counts only with the zone of a home interface.
func (h *HomeNet) Contains(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.IsLoopback() {
		return true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.refresh()
	if ip.IsLinkLocalUnicast() {
		return h.ifaces[ip.Zone()]
	}
	ip = ip.WithZone("")
	for _, n := range h.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Addrs returns this host's addresses on the home network, IPv4 first.
func (h *HomeNet) Addrs() []netip.Addr {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.refresh()
	var v4, v6 []netip.Addr
	for _, a := range h.addrs {
		if a.Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	return append(v4, v6...)
}

func hostInterfaces() ([]Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Interface
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		i := Interface{Name: ifc.Name, Loopback: ifc.Flags&net.FlagLoopback != 0}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				ip, _ := netip.AddrFromSlice(n.IP)
				ones, _ := n.Mask.Size()
				i.Addrs = append(i.Addrs, netip.PrefixFrom(ip.Unmap(), ones))
			}
		}
		out = append(out, i)
	}
	return out, nil
}

// homeListener closes connections from outside the home network before
// any TLS or HTTP happens on them.
type homeListener struct {
	net.Listener
	home func(netip.Addr) bool
}

func (l homeListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil && l.home(ap.Addr()) {
			return c, nil
		}
		c.Close()
	}
}
