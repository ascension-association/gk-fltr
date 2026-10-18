package filter

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// SafeSearch is a DNS resolver that enforces search-engine and video safe
// search for the clients steered through this appliance. For the handful of
// sites that publish a "forced safe" endpoint it answers with a CNAME to that
// endpoint (and the endpoint's addresses); every other query is forwarded
// unchanged to the upstream resolver.
//
// This is the standard, provider-supported mechanism — the same records a
// school or a parental-control box hands out. It does not inspect, log, or
// alter any other traffic.
type SafeSearch struct {
	upstreams []string // tried in order; later entries are failover
	client    *dns.Client
	blocklist *Blocklist // optional; nil disables domain blocking
	blockIPv6 bool       // when true, answer AAAA with empty NODATA
	stripECH  bool       // when true, remove the ech param from HTTPS/SVCB answers

	mu    sync.RWMutex
	cache map[string]cacheEntry // safe-host -> addresses, briefly cached
}

// SetBlocklist attaches a domain blocklist; matching names are sinkholed
// (answered NXDOMAIN) before any rewrite or forward.
func (s *SafeSearch) SetBlocklist(b *Blocklist) { s.blocklist = b }

// SetBlockIPv6 controls whether AAAA queries are answered with empty NODATA
// (true) so clients fall back to the filtered IPv4 path, or resolved normally
// (false).
func (s *SafeSearch) SetBlockIPv6(block bool) { s.blockIPv6 = block }

type cacheEntry struct {
	msgs []dns.RR
	exp  time.Time
}

// NewSafeSearch returns a resolver forwarding non-safe-search queries to the
// given upstreams (each host:port, e.g. "4.150.168.57:53"), tried in order so
// the first is primary and the rest are failover. Empty entries are ignored.
func NewSafeSearch(upstreams ...string) *SafeSearch {
	var up []string
	for _, u := range upstreams {
		if strings.TrimSpace(u) != "" {
			up = append(up, u)
		}
	}
	return &SafeSearch{
		upstreams: up,
		client:    &dns.Client{Timeout: 4 * time.Second},
		cache:     make(map[string]cacheEntry),
		stripECH:  true, // block TLS 1.3 ECH by default (hides SNI from filtering)
	}
}

// SetAllowECH controls TLS 1.3 Encrypted Client Hello. When allow is false
// (the default) the resolver strips the ech parameter from HTTPS/SVCB answers,
// so clients fall back to a plaintext SNI the filter can see.
func (s *SafeSearch) SetAllowECH(allow bool) { s.stripECH = !allow }

// stripECHRecords removes any ECH SvcParam from HTTPS/SVCB records in rrs,
// modifying them in place. It returns the number of params removed.
func stripECHRecords(rrs []dns.RR) int {
	removed := 0
	for _, rr := range rrs {
		var params *[]dns.SVCBKeyValue
		switch x := rr.(type) {
		case *dns.HTTPS:
			params = &x.Value
		case *dns.SVCB:
			params = &x.Value
		default:
			continue
		}
		kept := (*params)[:0]
		for _, p := range *params {
			if p.Key() == dns.SVCB_ECHCONFIG {
				removed++
				continue
			}
			kept = append(kept, p)
		}
		*params = kept
	}
	return removed
}

// exchange sends m to each upstream in order, returning the first success.
func (s *SafeSearch) exchange(m *dns.Msg) (*dns.Msg, error) {
	var lastErr error
	for _, up := range s.upstreams {
		in, _, err := s.client.Exchange(m, up)
		if err == nil && in != nil {
			return in, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no upstream resolvers configured")
	}
	return nil, lastErr
}

// safeHost maps a queried name to its provider-published safe-search endpoint,
// or returns ("", false) if the name is not covered.
func safeHost(qname string) (string, bool) {
	n := strings.ToLower(strings.TrimSuffix(qname, "."))
	switch {
	// Google Search: www.google.<tld> and google.<tld> -> forcesafesearch.
	case n == "google.com" || n == "www.google.com" ||
		strings.HasPrefix(n, "www.google.") || isGoogleCCTLD(n):
		return "forcesafesearch.google.com.", true

	// YouTube -> Restricted Mode (strict).
	case n == "www.youtube.com" || n == "m.youtube.com" ||
		n == "youtube.com" || n == "youtubei.googleapis.com" ||
		n == "youtube.googleapis.com" || n == "www.youtube-nocookie.com":
		return "restrict.youtube.com.", true

	// Bing.
	case n == "bing.com" || n == "www.bing.com":
		return "strict.bing.com.", true

	// DuckDuckGo.
	case n == "duckduckgo.com" || n == "www.duckduckgo.com":
		return "safe.duckduckgo.com.", true
	}
	return "", false
}

// isGoogleCCTLD matches "google.<cctld>" / "www.google.<cctld>" forms like
// google.co.uk without enumerating every TLD.
func isGoogleCCTLD(n string) bool {
	n = strings.TrimPrefix(n, "www.")
	return strings.HasPrefix(n, "google.") && strings.Count(n, ".") <= 2
}

func (s *SafeSearch) handler(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}
	q := r.Question[0]

	// Sinkhole blocked domains before anything else.
	if s.blocklist != nil && s.blocklist.Blocked(q.Name) {
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
		_ = w.WriteMsg(resp)
		return
	}

	// With IPv6 disabled, hand back empty NODATA for AAAA so clients use IPv4
	// (which stays on the filtered path) instead of routing around us over v6.
	if s.blockIPv6 && q.Qtype == dns.TypeAAAA {
		resp := new(dns.Msg)
		resp.SetReply(r) // NOERROR, no answers => NODATA
		resp.RecursionAvailable = true
		_ = w.WriteMsg(resp)
		return
	}

	// Only rewrite address-style lookups; forward everything else.
	rewritable := q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeHTTPS
	if safe, ok := safeHost(q.Name); ok && rewritable {
		s.answerSafe(w, r, q, safe)
		return
	}
	s.forward(w, r)
}

// answerSafe replies with a CNAME from the queried name to the safe endpoint,
// plus the endpoint's own records for the requested type.
func (s *SafeSearch) answerSafe(w dns.ResponseWriter, r *dns.Msg, q dns.Question, safe string) {
	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Authoritative = false
	resp.RecursionAvailable = true

	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: safe,
	}
	resp.Answer = append(resp.Answer, cname)

	for _, rr := range s.resolveSafe(safe, q.Qtype) {
		resp.Answer = append(resp.Answer, rr)
	}
	if err := w.WriteMsg(resp); err != nil {
		log.Printf("dns: write safe reply for %s: %v", q.Name, err)
	}
}

// resolveSafe looks up the safe endpoint's records (cached briefly).
func (s *SafeSearch) resolveSafe(safe string, qtype uint16) []dns.RR {
	key := fmt.Sprintf("%s/%d", safe, qtype)
	s.mu.RLock()
	if e, ok := s.cache[key]; ok && time.Now().Before(e.exp) {
		s.mu.RUnlock()
		return e.msgs
	}
	s.mu.RUnlock()

	m := new(dns.Msg)
	m.SetQuestion(safe, qtype)
	m.RecursionDesired = true
	in, err := s.exchange(m)
	if err != nil || in == nil {
		log.Printf("dns: upstream lookup of %s failed: %v", safe, err)
		return nil
	}
	if s.stripECH {
		stripECHRecords(in.Answer)
	}
	s.mu.Lock()
	s.cache[key] = cacheEntry{msgs: in.Answer, exp: time.Now().Add(60 * time.Second)}
	s.mu.Unlock()
	return in.Answer
}

// forward proxies a query to the upstream resolver unchanged.
func (s *SafeSearch) forward(w dns.ResponseWriter, r *dns.Msg) {
	in, err := s.exchange(r)
	if err != nil || in == nil {
		fail := new(dns.Msg)
		fail.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(fail)
		return
	}
	if s.stripECH {
		stripECHRecords(in.Answer)
		stripECHRecords(in.Extra)
	}
	_ = w.WriteMsg(in)
}

// ListenAndServe starts UDP and TCP listeners on addr (e.g. ":53") and blocks
// until one of them fails.
func (s *SafeSearch) ListenAndServe(addr string) error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handler)

	udp := &dns.Server{Addr: addr, Net: "udp", Handler: mux}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: mux}

	errc := make(chan error, 2)
	go func() { errc <- udp.ListenAndServe() }()
	go func() { errc <- tcp.ListenAndServe() }()
	log.Printf("dns: safe-search resolver listening on %s (upstreams %v)", addr, s.upstreams)
	return <-errc
}
