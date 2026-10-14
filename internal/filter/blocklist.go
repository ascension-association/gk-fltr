package filter

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// DefaultBlocklists are the lists loaded when none are specified: OISD Small
// (ads/trackers/malware) and OISD NSFW (adult content), both served in ABP
// syntax (see https://oisd.nl/), plus HaGeZi Anti-Piracy (piracy sites),
// HaGeZi Gambling (gambling sites), and HaGeZi NSFW (adult content not in
// OISD NSFW), all as plain domains (see
// https://github.com/hagezi/dns-blocklists), StevenBlack's fakenews-only
// hosts file (see https://github.com/StevenBlack/hosts), HaGeZi's Native
// Tracker lists (built-in telemetry from device vendors, apps, and OSes),
// HaGeZi Pop-Up Ads (pop-up, pop-under, and malicious ad domains), HaGeZi
// Fake (fake stores, scams, and fraud sites), and ShadowWhisperer's Gambling,
// Malware, Remote (remote-control tools), Risk, Scam, Shock (gore), and Typo
// (typosquatting) lists (see https://github.com/ShadowWhisperer/BlockLists).
var DefaultBlocklists = []string{
	"https://small.oisd.nl/",
	"https://nsfw.oisd.nl/",
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/anti.piracy-onlydomains.txt",
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling-onlydomains.txt",
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt",
	"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-only/hosts",
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.amazon-onlydomains.txt",
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.apple-onlydomains.txt",
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.huawei-onlydomains.txt",
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.winoffice-onlydomains.txt",
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.samsung-onlydomains.txt",
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.tiktok-onlydomains.txt",
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.lgwebos-onlydomains.txt",
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.roku-onlydomains.txt",
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.vivo-onlydomains.txt",
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.oppo-realme-onlydomains.txt",
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.xiaomi-onlydomains.txt",
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/popupads-onlydomains.txt",
	"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt",
	"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Gambling",
	"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Malware",
	"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Remote",
	"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Risk",
	"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Scam",
	"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Shock",
	"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Typo",
}

// DefaultBypassDomains are individual domains sinkholed when bypass /
// encrypted-DNS blocking is enabled: the Firefox DoH canary (resolving it to
// NXDOMAIN keeps Firefox's auto-DoH off), Brave's Tor bootstrap host,
// Cloudflare's Oblivious DoH endpoint, and the Tor Project site (Tor Browser
// downloads and bridge distribution).
var DefaultBypassDomains = []string{
	"use-application-dns.net",
	"tor.bravesoftware.com",
	"odoh.cloudflare-dns.com",
	"torproject.org",
}

// DefaultBlockDomains are individual domains always sinkholed, in addition to
// the loaded lists.
var DefaultBlockDomains = []string{
	"bad-example.com",
	"badexample.com",

	// Prediction markets and betting exchanges the gambling lists miss.
	"polymarket.us", // Polymarket's US site; polymarket.com is in the gambling lists
	"limitless.exchange",
	"myriad.markets",
	"hedgehog.markets",
	"zeitgeist.pm",
	"augur.net",
	"insight.markets",
	"sporttrade.app",
	"forecastex.com",   // Interactive Brokers' event contracts
	"manifold.markets", // play money
	"metaculus.com",    // forecasting
}

// DefaultForceBlockDomains are always sinkholed, even when an allowlist covers
// them: blocked subdomains of domains the loaded allowlists allow whole.
var DefaultForceBlockDomains = []string{
	"easy-vpn.comodo.com", // Comodo VPN; comodo.com is in BadBlock's certs whitelist

	// VPN/proxy buckets in S3 regions allowed whole by ShadowWhisperer's Whitelist.
	"cg-extension.s3-eu-west-1.amazonaws.com", // CyberGhost browser extension
	"dsl-app.s3.us-east-2.amazonaws.com",
	"innov-windows.s3.us-east-2.amazonaws.com",
	"tokna.s3-us-west-1.amazonaws.com",
}

// DefaultAllowDomains are never sinkholed even if a loaded list contains them.
// zzztest.oisd.nl is OISD's test entry (present in their lists on purpose).
// azure-devices.net (Azure IoT Hub, used by smart-home devices) and
// amazonworkspaces.com (Amazon WorkSpaces) are in ShadowWhisperer's Remote
// list but are not remote-control tools. dnsforfamily.com (a family-filtering
// DNS provider) is in HaGeZi's encrypted-DNS bypass list, as is opendns.com;
// only OpenDNS FamilyShield is allowed, since the rest of opendns.com includes
// unfiltered resolvers. Likewise only Yandex DNS Family mode is allowed out of
// dns.yandex.net, only AdGuard DNS Family Protection out of adguard-dns.com,
// and only Control D Family Friendly out of freedns.controld.com (its DoH URL
// freedns.controld.com/family shares a hostname with the unfiltered resolver,
// so only the DoT hostname can be allowed). Safe Surfer (the default upstream)
// runs only family-filtering resolvers, so its domains are allowed in full.
// For CleanBrowsing only the Family filter's DoT hostname is allowed: its DoH
// host doh.cleanbrowsing.org also serves the Security filter, which does not
// block adult content. neverssl.com, msftconnecttest.com, and
// captive.apple.com are connectivity / captive-portal checks that devices rely
// on to detect a working connection.
var DefaultAllowDomains = []string{
	"zzztest.oisd.nl",
	"azure-devices.net",
	"amazonworkspaces.com",
	"dnsforfamily.com",
	"familyshield.opendns.com",
	"family.dot.dns.yandex.net",
	"family.adguard-dns.com",
	"family.freedns.controld.com",
	"safesurfer.io",
	"safesurfer.co.nz",
	"family-filter-dns.cleanbrowsing.org",
	"neverssl.com",
	"msftconnecttest.com",
	"captive.apple.com",
}

// DefaultAllowlists are allowlist URLs loaded when none are specified:
// ShadowWhisperer's Whitelist of domains that blocklists commonly catch but
// whose blocking breaks apps, devices, and sites (see
// https://github.com/ShadowWhisperer/BlockLists), and BadBlock's captive
// portal, certificate (OCSP/CRL), time, push notification, safe browsing, and
// captcha whitelists (see https://github.com/celenityy/BadBlock). BadBlock's
// combined whitelist is deliberately not used: its misc/ISP entries (e.g.
// free.fr, s3.amazonaws.com, adguard-vpn.com) reopen porn and VPN/Tor/DoH
// bypasses.
var DefaultAllowlists = []string{
	"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Whitelists/Whitelist",
	"https://raw.githubusercontent.com/celenityy/BadBlock/pages/wildcards-no-star/captive_whitelist.txt",
	"https://raw.githubusercontent.com/celenityy/BadBlock/pages/wildcards-no-star/certs_whitelist.txt",
	"https://raw.githubusercontent.com/celenityy/BadBlock/pages/wildcards-no-star/time_whitelist.txt",
	"https://raw.githubusercontent.com/celenityy/BadBlock/pages/wildcards-no-star/push_whitelist.txt",
	"https://raw.githubusercontent.com/celenityy/BadBlock/pages/wildcards-no-star/safe-browsing_whitelist.txt",
	"https://raw.githubusercontent.com/celenityy/BadBlock/pages/wildcards-no-star/captcha_whitelist.txt",
}

// DefaultAllowIPs are never blocked by the IP range lists even if a loaded list
// contains them: the family-filtering resolvers of OpenDNS FamilyShield, Yandex
// DNS Family, AdGuard DNS Family Protection, UltraDNS Public Family Secure,
// DNS for Family, Control D Family Friendly, Safe Surfer, and CleanBrowsing
// Family filter.
var DefaultAllowIPs = []netip.Addr{
	netip.MustParseAddr("208.67.222.123"), netip.MustParseAddr("208.67.220.123"), // OpenDNS FamilyShield
	netip.MustParseAddr("77.88.8.7"), netip.MustParseAddr("77.88.8.3"), // Yandex DNS Family
	netip.MustParseAddr("2a02:6b8::feed:a11"), netip.MustParseAddr("2a02:6b8:0:1::feed:a11"), // Yandex DNS Family v6
	netip.MustParseAddr("156.154.70.3"), netip.MustParseAddr("156.154.71.3"), // UltraDNS Public Family Secure
	netip.MustParseAddr("2610:a1:1018::3"), netip.MustParseAddr("2610:a1:1019::3"), // UltraDNS Public Family Secure v6
	netip.MustParseAddr("94.140.14.15"), netip.MustParseAddr("94.140.15.16"), // AdGuard DNS Family Protection
	netip.MustParseAddr("2a10:50c0::bad1:ff"), netip.MustParseAddr("2a10:50c0::bad2:ff"), // AdGuard DNS Family Protection v6
	netip.MustParseAddr("94.130.180.225"), netip.MustParseAddr("78.47.64.161"), // DNS for Family
	netip.MustParseAddr("76.76.2.4"), netip.MustParseAddr("76.76.10.4"), // Control D Family Friendly
	netip.MustParseAddr("2606:1a40::4"), netip.MustParseAddr("2606:1a40:1::4"), // Control D Family Friendly v6
	netip.MustParseAddr("4.150.168.57"), netip.MustParseAddr("104.197.28.121"), // Safe Surfer
	netip.MustParseAddr("185.228.168.168"), netip.MustParseAddr("185.228.169.168"), // CleanBrowsing Family filter
	netip.MustParseAddr("2a0d:2a00:1::"), netip.MustParseAddr("2a0d:2a00:2::"), // CleanBrowsing Family filter v6
}

// Blocklist is a set of blocked domains with subdomain matching: if a domain
// is listed, every name ending in it is blocked too. An allowlist of
// exceptions takes precedence. The DNS resolver consults it and sinkholes
// matches.
type Blocklist struct {
	mu      sync.RWMutex
	blocked map[string]struct{}
	allowed map[string]struct{}
	forced  map[string]struct{} // blocked even when allowed; kept across Reload
}

// NewBlocklist returns an empty blocklist.
func NewBlocklist() *Blocklist {
	return &Blocklist{
		blocked: make(map[string]struct{}),
		allowed: make(map[string]struct{}),
		forced:  make(map[string]struct{}),
	}
}

// ForceBlock adds a domain (and all its subdomains) that is blocked even when
// the allowlist covers it.
func (b *Blocklist) ForceBlock(domain string) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if d == "" {
		return
	}
	b.mu.Lock()
	b.forced[d] = struct{}{}
	b.mu.Unlock()
}

// Allow adds a domain (and all its subdomains) to the allowlist, so it is never
// reported as blocked regardless of the loaded lists.
func (b *Blocklist) Allow(domain string) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if d == "" {
		return
	}
	b.mu.Lock()
	b.allowed[d] = struct{}{}
	b.mu.Unlock()
}

// matches reports whether name, or any parent domain of it, is a key in set.
// The caller holds at least a read lock.
func matches(set map[string]struct{}, name string) bool {
	_, ok := matchKey(set, name)
	return ok
}

// matchKey returns the key in set that covers name: name itself or its
// nearest listed parent domain. The caller holds at least a read lock.
func matchKey(set map[string]struct{}, name string) (string, bool) {
	n := name
	for {
		if _, ok := set[n]; ok {
			return n, true
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			return "", false
		}
		n = n[i+1:]
	}
}

// Add inserts a single domain (and thereby all its subdomains) into the list.
func (b *Blocklist) Add(domain string) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if d == "" {
		return
	}
	b.mu.Lock()
	b.blocked[d] = struct{}{}
	b.mu.Unlock()
}

// Len reports how many base domains are loaded.
func (b *Blocklist) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.blocked)
}

// Blocked reports whether qname (a DNS name, trailing dot optional) is covered
// by the list, either exactly or as a subdomain of a listed domain.
func (b *Blocklist) Blocked(qname string) bool {
	n := strings.ToLower(strings.TrimSuffix(qname, "."))
	if n == "" {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if matches(b.forced, n) {
		return true
	}
	if matches(b.allowed, n) {
		return false // allowlist takes precedence over the loaded lists
	}
	return matches(b.blocked, n)
}

// Match returns the listed domain covering qname (qname itself or a parent),
// ignoring the allowlist.
func (b *Blocklist) Match(qname string) (string, bool) {
	n := strings.ToLower(strings.TrimSuffix(qname, "."))
	if n == "" {
		return "", false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return matchKey(b.blocked, n)
}

// AllowMatch returns the allowlist entry covering qname, if any.
func (b *Blocklist) AllowMatch(qname string) (string, bool) {
	n := strings.ToLower(strings.TrimSuffix(qname, "."))
	if n == "" {
		return "", false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return matchKey(b.allowed, n)
}

// LoadURL fetches and parses a blocklist, merging it into the set. It returns
// the number of domains added.
func (b *Blocklist) LoadURL(url string) (int, error) {
	return b.loadURL(url, false)
}

// LoadAllowURL fetches and parses a list like LoadURL, but merges it into the
// allowlist. It returns the number of domains added.
func (b *Blocklist) LoadAllowURL(url string) (int, error) {
	return b.loadURL(url, true)
}

func (b *Blocklist) loadURL(url string, allow bool) (int, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("fetch %s: status %s", url, resp.Status)
	}
	if allow {
		return b.loadReader(resp.Body, b.allowed), nil
	}
	return b.LoadReader(resp.Body), nil
}

// LoadReader parses one domain per line in ABP (`||domain^`), hosts
// (`0.0.0.0 domain`), or plain-domain form, ignoring comments and rules that
// are not simple domain matches. It returns the number of domains added.
func (b *Blocklist) LoadReader(r io.Reader) int {
	return b.loadReader(r, b.blocked)
}

// loadReader parses r into set (b.blocked or b.allowed).
func (b *Blocklist) loadReader(r io.Reader, set map[string]struct{}) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	added := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		d := parseBlocklistLine(sc.Text())
		if d == "" {
			continue
		}
		if _, exists := set[d]; !exists {
			set[d] = struct{}{}
			added++
		}
	}
	return added
}

// parseBlocklistLine extracts a bare domain from one blocklist line, or "" if
// the line is a comment, blank, or a rule we can't honor as a plain domain.
func parseBlocklistLine(line string) string {
	s := strings.TrimSpace(line)
	if s == "" {
		return ""
	}
	switch s[0] {
	case '!', '#', '[': // ABP/hosts comments and ABP header
		return ""
	}
	// Trailing "  # comment" (ShadowWhisperer lists). ABP "##" cosmetic rules
	// have no space before the '#' and are rejected below.
	if i := strings.IndexByte(s, '#'); i > 0 && (s[i-1] == ' ' || s[i-1] == '\t') {
		s = strings.TrimSpace(s[:i])
	}

	// hosts form: "0.0.0.0 domain" or "127.0.0.1 domain"
	if strings.HasPrefix(s, "0.0.0.0 ") || strings.HasPrefix(s, "127.0.0.1 ") {
		fields := strings.Fields(s)
		if len(fields) >= 2 {
			s = fields[1]
		}
	}

	// ABP form: ||domain^  (with optional leading/trailing markers)
	s = strings.TrimPrefix(s, "||")
	s = strings.TrimSuffix(s, "^")
	s = strings.TrimPrefix(s, "*.")

	// Reject anything that isn't a plain domain (paths, wildcards, options,
	// regex anchors, schemes, cosmetic "##" rules).
	if strings.ContainsAny(s, "/*$|^?=# \t") {
		return ""
	}
	if s == "" || !strings.Contains(s, ".") {
		return ""
	}
	return strings.ToLower(s)
}

// Reload fetches urls (or DefaultBlocklists if empty) and allowURLs into fresh
// sets, adds the extra blocked and allow domains, then atomically swaps the
// contents in. Readers calling Blocked concurrently see either the old or the
// new sets, never a partial one.
func (b *Blocklist) Reload(urls, allowURLs, extra, allow []string) {
	tmp := NewBlocklist()
	for _, d := range allow {
		tmp.Allow(d)
	}
	tmp.LoadAllowlists(allowURLs)
	tmp.LoadDefaults(urls)
	for _, d := range extra {
		tmp.Add(d)
	}
	tmp.mu.RLock()
	m, a := tmp.blocked, tmp.allowed
	tmp.mu.RUnlock()

	b.mu.Lock()
	b.blocked, b.allowed = m, a
	b.mu.Unlock()
	log.Printf("blocklist: reloaded, %d domains (%d allowlisted)", len(m), len(a))
}

// LoadAllowlists loads the given allowlist URLs. Failures on individual lists
// are logged, not fatal.
func (b *Blocklist) LoadAllowlists(urls []string) {
	for _, u := range urls {
		n, err := b.LoadAllowURL(u)
		if err != nil {
			log.Printf("allowlist: %v", err)
			continue
		}
		log.Printf("allowlist: loaded %d domains from %s", n, u)
	}
}

// LoadDefaults loads the given URLs (or DefaultBlocklists if none) and logs a
// summary. Failures on individual lists are logged, not fatal.
func (b *Blocklist) LoadDefaults(urls []string) {
	if len(urls) == 0 {
		urls = DefaultBlocklists
	}
	for _, u := range urls {
		n, err := b.LoadURL(u)
		if err != nil {
			log.Printf("blocklist: %v", err)
			continue
		}
		log.Printf("blocklist: loaded %d domains from %s", n, u)
	}
	log.Printf("blocklist: %d domains blocked in total", b.Len())
}
