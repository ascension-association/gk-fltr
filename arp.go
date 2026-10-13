package main

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"strings"
)

// lookupARP finds the MAC address of an IPv4 neighbor in /proc/net/arp.
// It is a fallback for packets that arrived without a link-layer address.
func lookupARP(ip netip.Addr) net.HardwareAddr {
	if !ip.Is4() {
		return nil
	}
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil
	}
	defer f.Close()
	want := ip.String()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		// IP address  HW type  Flags  HW address  Mask  Device
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[0] != want || fields[2] == "0x0" {
			continue
		}
		if hw, err := net.ParseMAC(fields[3]); err == nil {
			return hw
		}
	}
	return nil
}
