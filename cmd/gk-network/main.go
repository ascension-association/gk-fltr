// Command gk-network is a gokrazy appliance that enforces parental-control
// network rules on your own LAN without replacing your existing router.
//
// It keeps your router as the DHCP server and gateway, and uses targeted ARP
// steering to pull selected client devices' traffic through this host, which
// forwards it on to the real gateway. Because forwarding stays on, managed
// devices keep full connectivity; the point is to put a filtering choke point
// in the path, not to disrupt the network.
//
// Only operate this on a network you own and administer, against devices you
// are responsible for (e.g. your household's). It is not a tool for use on
// networks or devices that are not yours.
//
// Usage:
//
//	gk-network -i eth0 -gw 192.168.1.1 -targets 192.168.1.50,192.168.1.51
package main

import (
	"flag"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ben-auo/gk-network/internal/filter"
	"github.com/ben-auo/gk-network/internal/steer"
)

func main() {
	iface := flag.String("i", "eth0", "LAN interface")
	gw := flag.String("gw", "auto", `existing gateway/router IP, or "auto" to detect the default route`)
	targetsCSV := flag.String("targets", "all", `comma-separated client IPs to manage, or "all" to steer every discovered LAN host`)
	dnsAddr := flag.String("dns", ":53", `address for the safe-search DNS resolver, or "" to disable`)
	// Default to Safe Surfer's family-filtering resolvers (safesurfer.io).
	upstream1 := flag.String("upstream", "4.150.168.57", "primary upstream DNS server (IPv4, :53 assumed if no port)")
	upstream2 := flag.String("upstream2", "104.197.28.121", "secondary/failover upstream DNS server (IPv4, :53 assumed if no port)")
	blocklistsCSV := flag.String("blocklists", "", "comma-separated blocklist URLs for DNS sinkholing (default: OISD Small + OISD NSFW)")
	blockCSV := flag.String("block", "", "comma-separated domains to always sinkhole (added to the built-in defaults)")
	allowCSV := flag.String("allow", "", "comma-separated domains to never sinkhole (allowlist; added to the built-in defaults)")
	blockNFT := flag.Bool("block-nft", false, "install nftables named sets (blocked_v4/blocked_v6) and a forward-path drop rule")
	blockIPsCSV := flag.String("block-ips", "", "comma-separated IPs to seed into the nftables block sets (implies -block-nft)")
	ipBlocklistsCSV := flag.String("ip-blocklists", "", "comma-separated CIDR blocklist URLs (gz ok) for nftables range blocking (default: DoH + malicious-source lists; \"none\" disables)")
	blockCountries := flag.Bool("block-countries", true, "block forwarded traffic to IP ranges of the full/partial U.S. entry-suspension countries (CRS IN12631; uses nftables)")
	allowIPv6 := flag.Bool("ipv6", false, "allow IPv6 (disabled by default, since it can bypass IPv4 filtering)")
	allowECH := flag.Bool("ech", false, "allow TLS 1.3 Encrypted Client Hello (blocked by default; it hides SNI from filtering)")
	blockEncDNS := flag.Bool("block-encrypted-dns", true, "block DoT/DoQ (port 853) and known DoH endpoints so clients can't bypass filtering (uses nftables)")
	redirectDNS := flag.Bool("redirect-dns", true, "transparently redirect steered clients' port-53 DNS to this resolver (requires the resolver on :53; uses nftables)")
	refresh := flag.Duration("refresh", 12*time.Hour, "how often to re-fetch domain and IP blocklists (0 disables)")
	flag.Parse()

	// Resolve the existing gateway: either the default route, or an explicit IP.
	var gwIP netip.Addr
	if *gw == "auto" {
		var err error
		gwIP, err = steer.DiscoverGateway(*iface)
		if err != nil {
			log.Fatalf("auto gateway: %v", err)
		}
		log.Printf("discovered existing gateway %s on %s", gwIP, *iface)
	} else {
		var err error
		gwIP, err = netip.ParseAddr(*gw)
		if err != nil {
			log.Fatalf("invalid gateway IP %q", *gw)
		}
	}

	// Resolve the client set: either "all" discovered hosts, or an explicit list.
	var targets []netip.Addr
	if strings.TrimSpace(*targetsCSV) == "all" {
		var err error
		targets, err = steer.DiscoverClients(*iface, gwIP, 0)
		if err != nil {
			log.Fatalf("discover clients: %v", err)
		}
		if len(targets) == 0 {
			log.Fatal("no clients discovered on the LAN")
		}
	} else {
		for _, s := range strings.Split(*targetsCSV, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			ip, err := netip.ParseAddr(s)
			if err != nil {
				log.Fatalf("invalid target IP %q", s)
			}
			targets = append(targets, ip)
		}
	}
	if len(targets) == 0 {
		log.Fatal("no target IPs given")
	}

	if err := filter.EnableForwarding(); err != nil {
		log.Fatalf("%v", err)
	}
	if !filter.ForwardingEnabled() {
		log.Fatal("ip_forward did not take effect; refusing to steer (would black-hole clients)")
	}
	log.Print("ip forwarding enabled")

	// IPv6 is disabled by default: it's a common way to bypass IPv4-based
	// filtering (ARP steering only covers IPv4). Disabling it on the host now
	// also covers the DNS resolver and nft rules configured below.
	if !*allowIPv6 {
		if err := filter.DisableIPv6OnHost(*iface); err != nil {
			log.Printf("ipv6: %v (continuing; DNS AAAA stripping still applies)", err)
		} else {
			log.Print("ipv6: disabled on appliance")
		}
	}

	// nftables IP blocking (named sets + forward drop rule). Encrypted-DNS
	// blocking and IPv6 forward-drop also need these rules, so enable nft when
	// any of them is requested.
	// The DNS redirect requires the resolver to be listening on port 53.
	dnsOn53 := false
	if *dnsAddr != "" {
		if _, p, err := net.SplitHostPort(*dnsAddr); err == nil && p == "53" {
			dnsOn53 = true
		}
	}
	doRedirectDNS := *redirectDNS && dnsOn53

	// CIDR range lists: -ip-blocklists (the defaults when empty, nothing when
	// "none"), plus the suspended-country ranges unless -block-countries=false.
	var ipURLs []string // kept for periodic refresh
	switch v := strings.TrimSpace(*ipBlocklistsCSV); {
	case strings.EqualFold(v, "none"):
	case v == "":
		ipURLs = append(ipURLs, filter.DefaultIPBlocklists...)
	default:
		for _, u := range strings.Split(v, ",") {
			if u = strings.TrimSpace(u); u != "" {
				ipURLs = append(ipURLs, u)
			}
		}
	}
	if *blockCountries {
		ipURLs = append(ipURLs, filter.CountryBlocklistURLs(filter.SuspendedCountries, *allowIPv6)...)
	}
	ipBlockEnabled := len(ipURLs) > 0
	needNFT := *blockNFT || *blockIPsCSV != "" || *blockEncDNS || ipBlockEnabled || doRedirectDNS
	var blocker *filter.IPBlocker
	if needNFT {
		var err error
		blocker, err = filter.NewIPBlocker("gknetwork")
		if err != nil {
			log.Fatalf("nft block: %v", err)
		}
		if *blockIPsCSV != "" {
			var ips []netip.Addr
			for _, s := range strings.Split(*blockIPsCSV, ",") {
				s = strings.TrimSpace(s)
				if s == "" {
					continue
				}
				ip, err := netip.ParseAddr(s)
				if err != nil {
					log.Fatalf("invalid -block-ips entry %q", s)
				}
				ips = append(ips, ip)
			}
			if err := blocker.AddIPs(ips); err != nil {
				log.Fatalf("seed block set: %v", err)
			}
			log.Printf("nft: seeded %d blocked IP(s)", len(ips))
		}
		if !*allowIPv6 {
			if err := blocker.DropForwardedIPv6(); err != nil {
				log.Fatalf("nft ipv6 drop: %v", err)
			}
		}
		if *blockEncDNS {
			if err := blocker.BlockDoT(); err != nil {
				log.Fatalf("nft block DoT: %v", err)
			}
			if err := blocker.BlockDoH(filter.DefaultDoHEndpoints); err != nil {
				log.Fatalf("nft block DoH: %v", err)
			}
		}
		if doRedirectDNS {
			if err := blocker.RedirectDNS(); err != nil {
				log.Fatalf("nft redirect dns: %v", err)
			}
		}
		if ipBlockEnabled {
			prefixes := filter.LoadIPBlocklists(ipURLs)
			if len(prefixes) > 0 {
				if err := blocker.BlockCIDRs(prefixes); err != nil {
					log.Fatalf("nft block CIDRs: %v", err)
				}
			}
		}
	}

	// Safe-search DNS resolver. Steered clients that use this host for DNS get
	// forced-safe answers for the covered sites, blocked domains sinkholed, and
	// normal resolution for the rest.
	var bl *filter.Blocklist
	var dnsURLs []string
	var extra []string
	if *dnsAddr != "" {
		ss := filter.NewSafeSearch(withDNSPort(*upstream1), withDNSPort(*upstream2))
		ss.SetBlockIPv6(!*allowIPv6)
		ss.SetAllowECH(*allowECH)

		// DNS domain blocklist (OISD Small + NSFW by default).
		for _, u := range strings.Split(*blocklistsCSV, ",") {
			if u = strings.TrimSpace(u); u != "" {
				dnsURLs = append(dnsURLs, u)
			}
		}
		// Individually blocked domains (built-in defaults plus -block entries),
		// kept across refreshes.
		extra = append(extra, filter.DefaultBlockDomains...)
		for _, d := range strings.Split(*blockCSV, ",") {
			if d = strings.TrimSpace(d); d != "" {
				extra = append(extra, d)
			}
		}
		if *blockEncDNS {
			// Sinkhole bypass bootstrap domains (Firefox DoH canary, Brave Tor,
			// Oblivious DoH).
			extra = append(extra, filter.DefaultBypassDomains...)
		}
		bl = filter.NewBlocklist()
		// Allowlist (never sinkholed): built-in defaults plus -allow entries.
		for _, d := range filter.DefaultAllowDomains {
			bl.Allow(d)
		}
		for _, d := range strings.Split(*allowCSV, ",") {
			if d = strings.TrimSpace(d); d != "" {
				bl.Allow(d)
			}
		}
		bl.LoadDefaults(dnsURLs) // uses OISD defaults when dnsURLs is empty
		for _, d := range extra {
			bl.Add(d)
		}
		ss.SetBlocklist(bl)

		go func() {
			if err := ss.ListenAndServe(*dnsAddr); err != nil {
				log.Fatalf("dns resolver: %v", err)
			}
		}()
	}

	// Periodically re-fetch both blocklist layers so daily-updated lists stay
	// current without a restart.
	if *refresh > 0 && (bl != nil || (blocker != nil && ipBlockEnabled)) {
		go func() {
			t := time.NewTicker(*refresh)
			defer t.Stop()
			for range t.C {
				if bl != nil {
					bl.Reload(dnsURLs, extra...)
				}
				if blocker != nil && ipBlockEnabled {
					if prefixes := filter.LoadIPBlocklists(ipURLs); len(prefixes) > 0 {
						if err := blocker.ReplaceCIDRs(prefixes); err != nil {
							log.Printf("refresh: %v", err)
						}
					}
				}
			}
		}()
		log.Printf("blocklist refresh every %s", *refresh)
	}

	s, err := steer.New(steer.Config{
		Interface: *iface,
		Gateway:   gwIP,
		Targets:   targets,
	})
	if err != nil {
		log.Fatalf("steer: %v", err)
	}
	defer s.Close()

	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Print("stopping, restoring ARP caches...")
		close(stop)
	}()

	log.Printf("steering %d client(s) via %s through %s", len(targets), *iface, gwIP)
	s.Run(stop)
	log.Print("done")
}

// withDNSPort returns addr unchanged if it already carries a port, otherwise it
// appends the standard DNS port 53. Empty input stays empty (ignored upstream).
func withDNSPort(addr string) string {
	if addr == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, "53")
}
