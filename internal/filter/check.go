package filter

import (
	"log"
	"net/netip"
	"strings"
	"sync"
)

// DomainSource is a named group of individually listed domains, e.g. the
// -block entries or the built-in VPN tool domains.
type DomainSource struct {
	Name    string
	Domains []string
}

// IPSource is a named group of individually listed addresses, e.g. the
// -block-ips entries or the DoH endpoints.
type IPSource struct {
	Name  string
	Addrs []netip.Addr
}

// Hit is one list that covers a checked domain or IP, with the entry that
// matched (the domain itself or a parent domain, or the containing range).
type Hit struct {
	List  string
	Entry string
}

type namedDomains struct {
	name string
	bl   *Blocklist
}

type namedPrefixes struct {
	name     string
	prefixes []netip.Prefix
}

// Checker answers which lists block a given domain or IP. Unlike the merged
// Blocklist the resolver uses, it keeps every list separate so it can name
// the ones that match.
type Checker struct {
	domains []namedDomains
	ips     []namedPrefixes
	allow   *Blocklist
}

// checkFetchWorkers bounds concurrent list downloads in NewChecker.
const checkFetchWorkers = 8

// NewChecker fetches each domain list URL and IP list URL into its own set
// and adds the individually listed sources. Lists that fail to fetch are
// logged and skipped.
func NewChecker(domainURLs []string, domainSources []DomainSource, allow []string, ipURLs []string, ipSources []IPSource) *Checker {
	c := &Checker{allow: NewBlocklist()}
	for _, d := range allow {
		c.allow.Allow(d)
	}

	c.domains = make([]namedDomains, len(domainURLs))
	c.ips = make([]namedPrefixes, len(ipURLs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, checkFetchWorkers)
	for i, u := range domainURLs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			bl := NewBlocklist()
			if _, err := bl.LoadURL(u); err != nil {
				log.Printf("check: %v", err)
				return
			}
			c.domains[i] = namedDomains{u, bl}
		}()
	}
	for i, u := range ipURLs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			pfx, err := LoadCIDRs(u)
			if err != nil {
				log.Printf("check: %v", err)
				return
			}
			c.ips[i] = namedPrefixes{u, pfx}
		}()
	}
	wg.Wait()

	for _, s := range domainSources {
		bl := NewBlocklist()
		for _, d := range s.Domains {
			bl.Add(d)
		}
		c.domains = append(c.domains, namedDomains{s.Name, bl})
	}
	for _, s := range ipSources {
		var pfx []netip.Prefix
		for _, a := range s.Addrs {
			pfx = append(pfx, netip.PrefixFrom(a, a.BitLen()))
		}
		c.ips = append(c.ips, namedPrefixes{s.Name, pfx})
	}
	return c
}

// Domain returns every domain list covering name, and the allowlist entry
// that overrides them (empty if none). A name is sinkholed when it has hits
// and no allowlist entry.
func (c *Checker) Domain(name string) (hits []Hit, allowedBy string) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	for _, l := range c.domains {
		if l.bl == nil { // fetch failed
			continue
		}
		if e, ok := l.bl.Match(name); ok {
			hits = append(hits, Hit{List: l.name, Entry: e})
		}
	}
	allowedBy, _ = c.allow.AllowMatch(name)
	return hits, allowedBy
}

// IP returns every IP list with a range containing addr. Reserved addresses
// (see IsReservedPrefix) are never loaded into the block sets, so callers
// should check that first.
func (c *Checker) IP(addr netip.Addr) []Hit {
	addr = addr.Unmap()
	var hits []Hit
	for _, l := range c.ips {
		for _, p := range l.prefixes {
			if p.Contains(addr) {
				hits = append(hits, Hit{List: l.name, Entry: p.String()})
				break
			}
		}
	}
	return hits
}

// IsReservedAddr reports whether addr is in a reserved range that is never
// blocked (private, loopback, link-local, and the like).
func IsReservedAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	return IsReservedPrefix(netip.PrefixFrom(addr, addr.BitLen()))
}

// SafeSearchHost returns the forced safe-search host qname is answered with,
// if it is one of the covered search sites.
func SafeSearchHost(qname string) (string, bool) {
	h, ok := safeHost(qname)
	return strings.TrimSuffix(h, "."), ok
}
