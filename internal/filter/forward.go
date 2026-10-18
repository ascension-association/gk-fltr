// Package filter contains the in-path enforcement that runs once traffic is
// steered through this host: enabling IP forwarding (so we relay rather than
// drop) and, later, DNS filtering and time-of-day rules.
package filter

import (
	"fmt"
	"os"
)

// EnableForwarding turns on IPv4 forwarding so steered client traffic is
// relayed to the real gateway instead of being dropped. Without this, ARP
// steering degrades into a denial of service, which is not the goal.
func EnableForwarding() error {
	const path = "/proc/sys/net/ipv4/ip_forward"
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		return fmt.Errorf("enable ip_forward: %w", err)
	}
	return nil
}

// ForwardingEnabled reports whether IPv4 forwarding is currently on.
func ForwardingEnabled() bool {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	return err == nil && len(b) > 0 && b[0] == '1'
}
