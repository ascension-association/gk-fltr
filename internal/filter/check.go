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
	Force   bool // blocked even when an allowlist covers it
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
	List   string
	Entry  string
	Forced bool // from a Force source: the allowlist does not override it
}

type namedDomains struct {
	name  string
	bl    *Blocklist
	force bool
}

type namedPrefixes struct {
	name     string
	prefixes []netip.Prefix
	listed   bool // individually listed addresses: the IP allowlist doesn't apply
}

// Checker answers which lists block a given domain or IP. Unlike the merged
// Blocklist the resolver uses, it keeps every list separate so it can name
// the ones that match.
type Checker struct {
	domains  []namedDomains
	allow    []namedDomains
	ips      []namedPrefixes
	allowIPs []netip.Addr
}

// checkFetchWorkers bounds concurrent list downloads in NewChecker.
const checkFetchWorkers = 8

// CheckerConfig is the configuration a Checker reports against: the URLs and
// individually listed sources of each layer, as the appliance would load them.
type CheckerConfig struct {
	DomainURLs    []string
	DomainSources []DomainSource
	AllowURLs     []string
	AllowSources  []DomainSource
	IPURLs        []string
	IPSources     []IPSource
	AllowIPs      []netip.Addr // never blocked by the IP range lists
}

// NewChecker fetches each domain, allowlist, and IP list URL into its own set
// and adds the individually listed sources. Lists that fail to fetch are
// logged and skipped.
func NewChecker(cfg CheckerConfig) *Checker {
	c := &Checker{allowIPs: cfg.AllowIPs}
	domainURLs, ipURLs := cfg.DomainURLs, cfg.IPURLs

	c.domains = make([]namedDomains, len(domainURLs))
	c.allow = make([]namedDomains, len(cfg.AllowURLs))
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
			c.domains[i] = namedDomains{u, bl, false}
		}()
	}
	for i, u := range cfg.AllowURLs {
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
			c.allow[i] = namedDomains{u, bl, false}
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
			c.ips[i] = namedPrefixes{u, pfx, false}
		}()
	}
	wg.Wait()

	for _, s := range cfg.DomainSources {
		c.domains = append(c.domains, namedDomains{s.Name, sourceList(s), s.Force})
	}
	for _, s := range cfg.AllowSources {
		c.allow = append(c.allow, namedDomains{s.Name, sourceList(s), false})
	}
	for _, s := range cfg.IPSources {
		var pfx []netip.Prefix
		for _, a := range s.Addrs {
			pfx = append(pfx, netip.PrefixFrom(a, a.BitLen()))
		}
		c.ips = append(c.ips, namedPrefixes{s.Name, pfx, true})
	}
	return c
}

// sourceList returns a Blocklist holding the domains of s.
func sourceList(s DomainSource) *Blocklist {
	bl := NewBlocklist()
	for _, d := range s.Domains {
		bl.Add(d)
	}
	return bl
}

// Domain returns every domain list covering name, and every allowlist that
// covers it. A name is sinkholed when it has a Forced hit, or hits and no
// allowlist hits.
func (c *Checker) Domain(name string) (hits, allowedBy []Hit) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	return matchAll(c.domains, name), matchAll(c.allow, name)
}

func matchAll(lists []namedDomains, name string) []Hit {
	var hits []Hit
	for _, l := range lists {
		if l.bl == nil { // fetch failed
			continue
		}
		if e, ok := l.bl.Match(name); ok {
			hits = append(hits, Hit{List: l.name, Entry: e, Forced: l.force})
		}
	}
	return hits
}

// IP returns every IP list covering addr: hits block it, and allowed are
// range-list hits overridden by the IP allowlist (individually listed
// addresses, such as -block-ips, still apply). Reserved addresses (see
// IsReservedPrefix) are never loaded into the block sets, so callers should
// check that first.
func (c *Checker) IP(addr netip.Addr) (hits, allowed []Hit) {
	addr = addr.Unmap()
	onAllowlist := false
	for _, a := range c.allowIPs {
		if a.Unmap() == addr {
			onAllowlist = true
		}
	}
	for _, l := range c.ips {
		for _, p := range l.prefixes {
			if !p.Contains(addr) {
				continue
			}
			h := Hit{List: l.name, Entry: p.String()}
			if onAllowlist && !l.listed {
				allowed = append(allowed, h)
			} else {
				hits = append(hits, h)
			}
			break
		}
	}
	return hits, allowed
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
