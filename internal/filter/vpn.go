package filter

import (
	"fmt"
	"log"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// VPN blocking (-block-vpn) works in three layers, since no single one covers
// both commercial VPN services and the self-hosted / mesh tools:
//
//   - protocol: WireGuard handshakes are dropped on any UDP port, and the
//     default ports of other VPN/mesh protocols are dropped (VPNPorts)
//   - DNS: VPN provider, proxy, and VPN-tool domains are sinkholed
//     (VPNDomainBlocklists plus VPNDomains), which stops apps from signing in,
//     fetching server lists, or falling back to HTTPS transports
//   - IP: known commercial VPN server ranges are dropped (VPNIPBlocklists)
//
// IPsec/IKE (UDP 500/4500, ESP) is deliberately not blocked: phones use it for
// carrier Wi-Fi calling. Commercial IKEv2 VPNs are still covered by the DNS
// and IP layers.

// VPNDomainBlocklists are DNS blocklists loaded alongside the domain lists
// when VPN blocking is enabled: HaGeZi's Encrypted DNS/VPN/Tor/Proxy Bypass
// list (commercial VPNs, proxies, iCloud Private Relay, Psiphon, Lantern,
// Outline, ZeroTier, and more). See https://github.com/hagezi/dns-blocklists.
var VPNDomainBlocklists = []string{
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
}

// VPNDomains are sinkholed when VPN blocking is enabled, in addition to
// VPNDomainBlocklists: the control planes, relays, and download sites of VPN /
// mesh-network tools that list does not cover (from
// https://gist.github.com/mrbluecoat/e725474483dbd81b6195bd3b9b31aae0), plus
// the WireGuard-over-HTTPS/QUIC fallbacks of Tailscale and Cloudflare WARP.
var VPNDomains = []string{
	"anywherelan.com",             // Anywherelan
	"brook.app",                   // Brook
	"txthinking.com",              // Brook
	"cloudflareclient.com",        // Cloudflare WARP
	"easytier.cn",                 // EasyTier
	"easytier.top",                // EasyTier
	"eduvpn.org",                  // eduVPN
	"firezone.dev",                // Firezone
	"gnunet.org",                  // GNUnet
	"headscale.net",               // Headscale
	"husarnet.com",                // Husarnet
	"hysteria.network",            // Hysteria
	"i2pd.website",                // i2pd
	"lokinet.org",                 // Lokinet
	"masq.ai",                     // MASQ
	"defined.net",                 // Nebula (Defined Networking)
	"netbird.io",                  // Netbird
	"netmaker.io",                 // Netmaker
	"netmaker.org",                // Netmaker
	"omniedge.io",                 // OmniEdge
	"openvpn.com",                 // OpenVPN Connect / CloudConnexa
	"openvpn.net",                 // OpenVPN
	"openziti.io",                 // OpenZiti
	"orchid.com",                  // Orchid
	"pairmesh.com",                // PairMesh
	"pomerium.com",                // Pomerium
	"rosenpass.eu",                // Rosenpass
	"softether.org",               // SoftEther
	"strongswan.org",              // strongSwan
	"tailscale.com",               // Tailscale
	"tailscale.io",                // Tailscale
	"tinc-vpn.org",                // Tinc
	"v2fly.org",                   // V2Ray
	"v2ray.com",                   // V2Ray
	"wireguard.com",               // WireGuard
	"yggdrasil-network.github.io", // Yggdrasil
}

// VPNIPBlocklists are CIDR lists loaded alongside the IP range lists when VPN
// blocking is enabled: X4BNet's list of commercial VPN provider ranges. See
// https://github.com/X4BNet/lists_vpn.
var VPNIPBlocklists = []string{
	"https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
}

// L4Port is a transport protocol and destination port to drop.
type L4Port struct {
	Proto byte
	Port  uint16
	Name  string
}

// VPNPorts are the default ports of VPN / mesh protocols, dropped when VPN
// blocking is enabled. Tools that run over 443 or random ports are left to the
// DNS and IP layers.
var VPNPorts = []L4Port{
	{protoUDP, 51820, "WireGuard"},
	{protoUDP, 1194, "OpenVPN"},
	{protoTCP, 1194, "OpenVPN"},
	{protoTCP, 1723, "PPTP"},
	{protoUDP, 1701, "L2TP"},
	{protoUDP, 655, "Tinc"},
	{protoTCP, 655, "Tinc"},
	{protoTCP, 5555, "SoftEther"},
	{protoUDP, 9993, "ZeroTier"},
	{protoUDP, 4242, "Nebula"},
	{protoUDP, 1090, "Lokinet"},
	{protoUDP, 7654, "n2n"},
	{protoUDP, 3210, "VpnCloud"},
	{protoUDP, 11010, "EasyTier"},
	{protoTCP, 11010, "EasyTier"},
	{protoUDP, 11011, "EasyTier"},
}

// matchWireGuardInit builds a match for a WireGuard handshake initiation on
// any UDP port: a 148-byte payload (UDP length 156 with the 8-byte header)
// whose first four bytes are message type 1 plus three reserved zero bytes,
// i.e. "udp length 156 @th,64,32 0x01000000".
func matchWireGuardInit() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protoUDP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 4, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 156}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 8, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1, 0, 0, 0}},
	}
}

// BlockVPN drops forwarded WireGuard handshake initiations on any UDP port, so
// no WireGuard tunnel (self-hosted or commercial VPN) can come up, plus all
// traffic to VPNPorts. Obfuscated variants that alter or wrap the handshake
// (AmneziaWG, udp2raw, wstunnel) are not matched here.
func (b *IPBlocker) BlockVPN() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.conn.AddRule(&nftables.Rule{
		Table: b.table, Chain: b.chain,
		Exprs: append(matchWireGuardInit(), &expr.Verdict{Kind: expr.VerdictDrop}),
	})
	for _, p := range VPNPorts {
		b.conn.AddRule(&nftables.Rule{
			Table: b.table, Chain: b.chain,
			Exprs: append(matchL4Port(p.Proto, p.Port), &expr.Verdict{Kind: expr.VerdictDrop}),
		})
	}
	if err := b.conn.Flush(); err != nil {
		return fmt.Errorf("block VPN: %w", err)
	}
	log.Printf("nft: WireGuard handshakes and %d VPN ports dropped", len(VPNPorts))
	return nil
}
