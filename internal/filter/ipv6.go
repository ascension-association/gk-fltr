package filter

import (
	"fmt"
	"os"
)

// DisableIPv6OnHost turns off IPv6 on the appliance itself via sysctl, so the
// box does not originate or accept IPv6. It is best-effort: on a kernel built
// without IPv6 the sysctl paths are absent and it returns nil.
//
// This hardens the appliance, but the lever that actually keeps steered
// clients on the filtered IPv4 path is the resolver withholding AAAA records
// (SafeSearch.SetBlockIPv6) plus the nftables forward-drop of IPv6.
func DisableIPv6OnHost(iface string) error {
	paths := []string{
		"/proc/sys/net/ipv6/conf/all/disable_ipv6",
		"/proc/sys/net/ipv6/conf/default/disable_ipv6",
	}
	if iface != "" {
		paths = append(paths, fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", iface))
	}
	for _, p := range paths {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			continue // kernel without IPv6, or no such iface yet
		}
		if err := os.WriteFile(p, []byte("1\n"), 0o644); err != nil {
			return fmt.Errorf("disable ipv6 (%s): %w", p, err)
		}
	}
	return nil
}
