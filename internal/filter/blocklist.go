package filter

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
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
// HaGeZi Pop-Up Ads (pop-up, pop-under, and malicious ad domains), and HaGeZi
// Fake (fake stores, scams, and fraud sites).
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
}

// DefaultAllowDomains are never sinkholed even if a loaded list contains them.
// zzztest.oisd.nl is OISD's test entry (present in their lists on purpose).
var DefaultAllowDomains = []string{
	"zzztest.oisd.nl",
}

// Blocklist is a set of blocked domains with subdomain matching: if a domain
// is listed, every name ending in it is blocked too. An allowlist of
// exceptions takes precedence. The DNS resolver consults it and sinkholes
// matches.
type Blocklist struct {
	mu      sync.RWMutex
	blocked map[string]struct{}
	allowed map[string]struct{}
}

// NewBlocklist returns an empty blocklist.
func NewBlocklist() *Blocklist {
	return &Blocklist{
		blocked: make(map[string]struct{}),
		allowed: make(map[string]struct{}),
	}
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
	if matches(b.allowed, n) {
		return false // allowlist takes precedence
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
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("fetch %s: status %s", url, resp.Status)
	}
	return b.LoadReader(resp.Body), nil
}

// LoadReader parses one domain per line in ABP (`||domain^`), hosts
// (`0.0.0.0 domain`), or plain-domain form, ignoring comments and rules that
// are not simple domain matches. It returns the number of domains added.
func (b *Blocklist) LoadReader(r io.Reader) int {
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
		if _, exists := b.blocked[d]; !exists {
			b.blocked[d] = struct{}{}
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
	// regex anchors, schemes).
	if strings.ContainsAny(s, "/*$|^?= \t") {
		return ""
	}
	if s == "" || !strings.Contains(s, ".") {
		return ""
	}
	return strings.ToLower(s)
}

// Reload fetches urls (or DefaultBlocklists if empty) into a fresh set, adds
// any extra domains, then atomically swaps the contents in. Readers calling
// Blocked concurrently see either the old or the new set, never a partial one.
func (b *Blocklist) Reload(urls []string, extra ...string) {
	tmp := NewBlocklist()
	tmp.LoadDefaults(urls)
	for _, d := range extra {
		tmp.Add(d)
	}
	tmp.mu.RLock()
	m := tmp.blocked
	tmp.mu.RUnlock()

	b.mu.Lock()
	b.blocked = m
	b.mu.Unlock()
	log.Printf("blocklist: reloaded, %d domains", len(m))
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
