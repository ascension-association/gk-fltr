package filter

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// DefaultIPBlocklists are the CIDR/IP range lists loaded into the nftables
// interval sets when none are specified. These block known DoH servers (which
// would otherwise bypass the DNS/SNI filtering), known malicious sources,
// Tor relays, and open SSL proxies.
// CIDR (.netset), single-IP (.ipset / .txt), and gzipped forms are all
// handled.
var DefaultIPBlocklists = []string{
	"https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv4.txt",
	"https://iplists.firehol.org/files/firehol_level1.netset",
	"https://iplists.firehol.org/files/firehol_level2.netset",
	"https://iplists.firehol.org/files/iblocklist_pedophiles.netset",
	"https://iplists.firehol.org/files/iblocklist_onion_router.netset",
	"https://iplists.firehol.org/files/et_tor.ipset",
	"https://iplists.firehol.org/files/dm_tor.ipset",
	"https://iplists.firehol.org/files/tor_exits.ipset",
	"https://iplists.firehol.org/files/sslproxies.ipset",
}

// reservedV4 and reservedV6 are address ranges that must never be blocked:
// private, loopback, link-local, CGNAT, documentation, multicast, and reserved
// space. Public bogon lists (e.g. Team Cymru fullbogons inside FireHOL level1)
// include these, and blocking them would reject the LAN itself — the gateway,
// other hosts, and all return traffic to clients.
var reservedV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

var reservedV6 = []netip.Prefix{
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),  // unique local
	netip.MustParsePrefix("fe80::/10"), // link-local
	netip.MustParsePrefix("ff00::/8"),  // multicast
}

// IsReservedPrefix reports whether p overlaps any reserved range and therefore
// must not be added to a destination block set.
func IsReservedPrefix(p netip.Prefix) bool {
	res := reservedV4
	if p.Addr().Is6() {
		res = reservedV6
	}
	for _, r := range res {
		if r.Overlaps(p) {
			return true
		}
	}
	return false
}

// LoadCIDRs fetches a CIDR blocklist, transparently gunzipping it if the body
// is gzip-compressed (detected by magic bytes, regardless of the URL's
// archiveformat parameter), and parses one CIDR or bare IP per line. Comment
// lines (# or ;) and blanks are skipped. It returns the parsed prefixes.
func LoadCIDRs(url string) ([]netip.Prefix, error) {
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %s", url, resp.Status)
	}

	br := bufio.NewReader(resp.Body)
	var r io.Reader = br
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("gunzip %s: %w", url, err)
		}
		defer gz.Close()
		r = gz
	}

	var prefixes []netip.Prefix
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if p, ok := parseCIDRLine(sc.Text()); ok {
			prefixes = append(prefixes, p)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	return prefixes, nil
}

// parseCIDRLine parses one line as a CIDR prefix or a bare IP (treated as a
// host prefix). It returns ok=false for comments, blanks, and unparseable
// lines.
func parseCIDRLine(line string) (netip.Prefix, bool) {
	s := strings.TrimSpace(line)
	if s == "" || s[0] == '#' || s[0] == ';' {
		return netip.Prefix{}, false
	}
	// Drop any trailing inline comment.
	if i := strings.IndexAny(s, "#;"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if s == "" {
		return netip.Prefix{}, false
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		return netip.PrefixFrom(addr, bits), true
	}
	return netip.Prefix{}, false
}

// LoadIPBlocklists loads the given CIDR list URLs (or DefaultIPBlocklists if
// none) and returns all parsed prefixes. Per-list failures are logged, not
// fatal.
func LoadIPBlocklists(urls []string) []netip.Prefix {
	if len(urls) == 0 {
		urls = DefaultIPBlocklists
	}
	var all []netip.Prefix
	for _, u := range urls {
		pfx, err := LoadCIDRs(u)
		if err != nil {
			log.Printf("ip-blocklist: %v", err)
			continue
		}
		log.Printf("ip-blocklist: loaded %d ranges from %s", len(pfx), u)
		all = append(all, pfx...)
	}
	return all
}
