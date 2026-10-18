// Package filter contains the in-path enforcement that runs once traffic is
// steered through this host: enabling IP forwarding (so we relay rather than
// drop) and, later, DNS filtering and time-of-day rules.
package filter

import (
	"fmt"
	"os"
	"path/filepath"
)

// procSys is where sysctls live; tests point it elsewhere.
var procSys = "/proc/sys"

// EnableForwarding turns on IPv4 forwarding so steered client traffic is
// relayed to the real gateway instead of being dropped. Without this, ARP
// steering degrades into a denial of service, which is not the goal.
func EnableForwarding() error {
	path := filepath.Join(procSys, "net/ipv4/ip_forward")
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		return fmt.Errorf("enable ip_forward: %w", err)
	}
	return nil
}

// ForwardingEnabled reports whether IPv4 forwarding is currently on.
func ForwardingEnabled() bool {
	b, err := os.ReadFile(filepath.Join(procSys, "net/ipv4/ip_forward"))
	return err == nil && len(b) > 0 && b[0] == '1'
}

// redirectPaths are the send_redirects sysctls for iface. The kernel sends
// redirects on an interface if either its own setting or "all" is on.
func redirectPaths(iface string) []string {
	return []string{
		filepath.Join(procSys, "net/ipv4/conf/all/send_redirects"),
		filepath.Join(procSys, "net/ipv4/conf", iface, "send_redirects"),
	}
}

// DisableRedirects stops the kernel from sending ICMP redirects on iface.
// Steered traffic leaves through the interface it arrived on, so the kernel
// would otherwise tell clients to send it straight to the gateway, past
// this host and its filtering.
func DisableRedirects(iface string) error {
	for _, p := range redirectPaths(iface) {
		if err := os.WriteFile(p, []byte("0\n"), 0o644); err != nil {
			return fmt.Errorf("disable ICMP redirects: %w", err)
		}
	}
	return nil
}

// RedirectsDisabled reports whether ICMP redirects are off on iface.
func RedirectsDisabled(iface string) bool {
	for _, p := range redirectPaths(iface) {
		b, err := os.ReadFile(p)
		if err != nil || len(b) == 0 || b[0] != '0' {
			return false
		}
	}
	return true
}
