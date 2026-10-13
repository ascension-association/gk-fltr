package filter

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"net/netip"
	"sort"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	protoTCP = 6
	protoUDP = 17
)

// IPBlocker manages nftables named sets of blocked destination IPs and a drop
// rule on the forward path. The sets are named (blocked_v4 / blocked_v6) so you
// can inspect or update them live from the shell, e.g.:
//
//	nft list set inet gknetwork blocked_v4
//	nft add element inet gknetwork blocked_v4 { 203.0.113.5 }
//
// Because the drop rule lives in the forward hook, it only affects traffic
// routed through this appliance — i.e. the clients it steers.
type IPBlocker struct {
	tableName string
	set4Name  string
	set6Name  string

	mu    sync.Mutex
	conn  *nftables.Conn
	table *nftables.Table
	chain *nftables.Chain
	set4  *nftables.Set
	set6  *nftables.Set
	doh4  *nftables.Set
	doh6  *nftables.Set
	cidr4 *nftables.Set
	cidr6 *nftables.Set
	cur4  map[string]ival // current v4 intervals, merged + non-overlapping
	cur6  map[string]ival // current v6 intervals
}

// ival is a half-open address interval [start, end) as raw big-endian bytes
// (4 for v4, 16 for v6), the form nftables interval sets store.
type ival struct {
	start, end []byte
}

func ivalKey(start, end []byte) string { return string(start) + "\x00" + string(end) }

// NewIPBlocker installs the table, named sets, forward chain, and drop rules,
// then flushes them to the kernel. Requires CAP_NET_ADMIN.
func NewIPBlocker(tableName string) (*IPBlocker, error) {
	if tableName == "" {
		tableName = "gknetwork"
	}
	c, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("nftables open: %w", err)
	}
	b := &IPBlocker{
		tableName: tableName,
		set4Name:  "blocked_v4",
		set6Name:  "blocked_v6",
		conn:      c,
	}

	// Remove any leftover table from a previous run so re-adding sets, rules,
	// and elements does not fail with EEXIST. Done in its own flush and ignored
	// when the table does not exist yet.
	c.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: tableName})
	_ = c.Flush()

	b.table = c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: tableName})

	b.set4 = &nftables.Set{Table: b.table, Name: b.set4Name, KeyType: nftables.TypeIPAddr}
	if err := c.AddSet(b.set4, nil); err != nil {
		return nil, fmt.Errorf("add set %s: %w", b.set4Name, err)
	}
	b.set6 = &nftables.Set{Table: b.table, Name: b.set6Name, KeyType: nftables.TypeIP6Addr}
	if err := c.AddSet(b.set6, nil); err != nil {
		return nil, fmt.Errorf("add set %s: %w", b.set6Name, err)
	}

	accept := nftables.ChainPolicyAccept
	b.chain = c.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    b.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &accept,
	})

	// ip daddr @blocked_v4 drop
	c.AddRule(&nftables.Rule{
		Table: b.table, Chain: b.chain,
		Exprs: rejectByDstAddr(false, b.set4),
	})
	// ip6 daddr @blocked_v6 drop
	c.AddRule(&nftables.Rule{
		Table: b.table, Chain: b.chain,
		Exprs: rejectByDstAddr(true, b.set6),
	})

	if err := c.Flush(); err != nil {
		return nil, fmt.Errorf("nftables flush: %w", err)
	}
	log.Printf("nft: table inet %s ready (sets %s, %s on forward hook)", tableName, b.set4Name, b.set6Name)
	return b, nil
}

// matchDstInSet builds "ipX daddr @set" (no verdict). The inet family needs an
// nfproto guard so the payload is read as the right L3 header.
func matchDstInSet(v6 bool, set *nftables.Set) []expr.Any {
	proto := byte(2) // NFPROTO_IPV4
	off, length := uint32(16), uint32(4)
	if v6 {
		proto = 10 // NFPROTO_IPV6
		off, length = 24, 16
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: length},
		&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
	}
}

// rejectByDstAddr builds "ipX daddr @set reject". Unlike a silent drop, reject
// returns an ICMP admin-prohibited immediately, so clients fail fast instead of
// waiting out a connect timeout. The ICMPX form works for both v4 and v6.
func rejectByDstAddr(v6 bool, set *nftables.Set) []expr.Any {
	return append(matchDstInSet(v6, set), &expr.Reject{
		Type: unix.NFT_REJECT_ICMPX_UNREACH,
		Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED,
	})
}

// matchL4Port builds "meta l4proto <proto> @transport dport == port".
func matchL4Port(proto byte, port uint16) []expr.Any {
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, port)
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: pb},
	}
}

// DropForwardedIPv6 appends a forward-hook rule dropping all forwarded IPv6
// traffic, so steered clients cannot use IPv6 to bypass the IPv4 filtering.
func (b *IPBlocker) DropForwardedIPv6() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.conn.AddRule(&nftables.Rule{
		Table: b.table, Chain: b.chain,
		Exprs: []expr.Any{
			// meta nfproto ipv6
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10}}, // NFPROTO_IPV6
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})
	if err := b.conn.Flush(); err != nil {
		return fmt.Errorf("add ipv6 drop rule: %w", err)
	}
	log.Printf("nft: forwarded IPv6 dropped (IPv6 disabled)")
	return nil
}

// DefaultDoHEndpoints is a built-in list of well-known public DoH resolver
// IPs. Blocking port 443 to these stops the common "browser uses its own
// encrypted DNS" bypass without affecting other HTTPS traffic.
var DefaultDoHEndpoints = []netip.Addr{
	netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1"), // Cloudflare
	netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4"), // Google
	netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("149.112.112.112"), // Quad9
	netip.MustParseAddr("208.67.222.222"), netip.MustParseAddr("208.67.220.220"), // OpenDNS
	netip.MustParseAddr("94.140.14.14"), netip.MustParseAddr("94.140.15.15"), // AdGuard
	netip.MustParseAddr("2606:4700:4700::1111"), netip.MustParseAddr("2606:4700:4700::1001"), // Cloudflare v6
	netip.MustParseAddr("2001:4860:4860::8888"), netip.MustParseAddr("2001:4860:4860::8844"), // Google v6
	netip.MustParseAddr("2620:fe::fe"), netip.MustParseAddr("2620:fe::9"), // Quad9 v6
}

// BlockDoT drops forwarded DNS-over-TLS and DNS-over-QUIC, both of which use
// port 853 (TCP and UDP respectively).
func (b *IPBlocker) BlockDoT() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.conn.AddRule(&nftables.Rule{
		Table: b.table, Chain: b.chain,
		Exprs: append(matchL4Port(protoTCP, 853), &expr.Verdict{Kind: expr.VerdictDrop}),
	})
	b.conn.AddRule(&nftables.Rule{
		Table: b.table, Chain: b.chain,
		Exprs: append(matchL4Port(protoUDP, 853), &expr.Verdict{Kind: expr.VerdictDrop}),
	})
	if err := b.conn.Flush(); err != nil {
		return fmt.Errorf("block DoT/DoQ (853): %w", err)
	}
	log.Print("nft: DoT/DoQ (port 853) dropped")
	return nil
}

// TorPorts are the default Tor relay ORPort (9001) and DirPort (9030).
var TorPorts = []uint16{9001, 9030}

// BlockTor drops forwarded TCP to the default Tor relay ports, so clients
// can't reach the Tor network through relays on their standard ports.
func (b *IPBlocker) BlockTor() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range TorPorts {
		b.conn.AddRule(&nftables.Rule{
			Table: b.table, Chain: b.chain,
			Exprs: append(matchL4Port(protoTCP, p), &expr.Verdict{Kind: expr.VerdictDrop}),
		})
	}
	if err := b.conn.Flush(); err != nil {
		return fmt.Errorf("block Tor ports %v: %w", TorPorts, err)
	}
	log.Printf("nft: Tor ports %v dropped", TorPorts)
	return nil
}

// BlockDoH creates named sets doh_v4/doh_v6 of DoH endpoint IPs and drops
// forwarded port-443 traffic to them. Other HTTPS traffic is unaffected.
func (b *IPBlocker) BlockDoH(ips []netip.Addr) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.doh4 = &nftables.Set{Table: b.table, Name: "doh_v4", KeyType: nftables.TypeIPAddr}
	if err := b.conn.AddSet(b.doh4, nil); err != nil {
		return fmt.Errorf("add set doh_v4: %w", err)
	}
	b.doh6 = &nftables.Set{Table: b.table, Name: "doh_v6", KeyType: nftables.TypeIP6Addr}
	if err := b.conn.AddSet(b.doh6, nil); err != nil {
		return fmt.Errorf("add set doh_v6: %w", err)
	}

	var e4, e6 []nftables.SetElement
	for _, ip := range ips {
		if ip.Is4() {
			a := ip.As4()
			e4 = append(e4, nftables.SetElement{Key: a[:]})
		} else if ip.Is6() {
			a := ip.As16()
			e6 = append(e6, nftables.SetElement{Key: a[:]})
		}
	}
	if len(e4) > 0 {
		if err := b.conn.SetAddElements(b.doh4, e4); err != nil {
			return err
		}
	}
	if len(e6) > 0 {
		if err := b.conn.SetAddElements(b.doh6, e6); err != nil {
			return err
		}
	}

	// ip daddr @doh_v4 tcp dport 443 drop
	v4 := append(matchDstInSet(false, b.doh4), matchL4Port(protoTCP, 443)...)
	v4 = append(v4, &expr.Verdict{Kind: expr.VerdictDrop})
	b.conn.AddRule(&nftables.Rule{Table: b.table, Chain: b.chain, Exprs: v4})

	// ip6 daddr @doh_v6 tcp dport 443 drop
	v6 := append(matchDstInSet(true, b.doh6), matchL4Port(protoTCP, 443)...)
	v6 = append(v6, &expr.Verdict{Kind: expr.VerdictDrop})
	b.conn.AddRule(&nftables.Rule{Table: b.table, Chain: b.chain, Exprs: v6})

	if err := b.conn.Flush(); err != nil {
		return fmt.Errorf("block DoH endpoints: %w", err)
	}
	log.Printf("nft: DoH endpoints dropped on 443 (%d addresses)", len(ips))
	return nil
}

// BlockCIDRs creates interval named sets cidr_v4/cidr_v6 from the given
// prefixes and drops forwarded traffic whose destination falls in any of them.
// Intended for large range lists such as the FireHOL feeds. A /0
// prefix is skipped (it would blackhole everything).
func (b *IPBlocker) BlockCIDRs(prefixes []netip.Prefix) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.cur4, b.cur6 = buildIntervals(prefixes)

	// Create the (empty) sets and drop rules first, then add the elements in
	// batches: a single netlink message holding every element overflows the
	// socket (EMSGSIZE) on large lists.
	b.cidr4 = &nftables.Set{Table: b.table, Name: "cidr_v4", KeyType: nftables.TypeIPAddr, Interval: true}
	if err := b.conn.AddSet(b.cidr4, nil); err != nil {
		return fmt.Errorf("add set cidr_v4: %w", err)
	}
	b.cidr6 = &nftables.Set{Table: b.table, Name: "cidr_v6", KeyType: nftables.TypeIP6Addr, Interval: true}
	if err := b.conn.AddSet(b.cidr6, nil); err != nil {
		return fmt.Errorf("add set cidr_v6: %w", err)
	}

	b.conn.AddRule(&nftables.Rule{Table: b.table, Chain: b.chain, Exprs: rejectByDstAddr(false, b.cidr4)})
	b.conn.AddRule(&nftables.Rule{Table: b.table, Chain: b.chain, Exprs: rejectByDstAddr(true, b.cidr6)})

	if err := b.conn.Flush(); err != nil {
		return fmt.Errorf("create cidr sets: %w", err)
	}

	if err := b.sendBatched(b.cidr4, addElements(b.cur4), false); err != nil {
		return fmt.Errorf("fill cidr_v4: %w", err)
	}
	if err := b.sendBatched(b.cidr6, addElements(b.cur6), false); err != nil {
		return fmt.Errorf("fill cidr_v6: %w", err)
	}
	log.Printf("nft: CIDR ranges dropped (%d v4, %d v6)", len(b.cur4), len(b.cur6))
	return nil
}

// sendBatched adds or deletes set elements in chunks, flushing after each, so
// no single netlink message grows past the socket's size limit. The batch size
// is even so interval start/end pairs are never split across flushes.
func (b *IPBlocker) sendBatched(set *nftables.Set, elems []nftables.SetElement, del bool) error {
	const batch = 2000
	for i := 0; i < len(elems); i += batch {
		j := min(i+batch, len(elems))
		var err error
		if del {
			err = b.conn.SetDeleteElements(set, elems[i:j])
		} else {
			err = b.conn.SetAddElements(set, elems[i:j])
		}
		if err != nil {
			return err
		}
		if err := b.conn.Flush(); err != nil {
			return fmt.Errorf("batch flush: %w", err)
		}
	}
	return nil
}

// ReplaceCIDRs updates the cidr_v4/cidr_v6 sets to match prefixes by applying
// only the difference from what is currently loaded — adding new ranges and
// deleting removed ones — rather than rebuilding the sets. The drop rules are
// left untouched. It returns an error if BlockCIDRs has not been called yet.
func (b *IPBlocker) ReplaceCIDRs(prefixes []netip.Prefix) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cidr4 == nil || b.cidr6 == nil {
		return fmt.Errorf("cidr sets not initialized")
	}

	want4, want6 := buildIntervals(prefixes)
	add4, del4 := diffIvals(b.cur4, want4)
	add6, del6 := diffIvals(b.cur6, want6)

	if len(add4)+len(del4)+len(add6)+len(del6) == 0 {
		log.Print("nft: CIDR ranges unchanged")
		return nil
	}

	apply := func(set *nftables.Set, add, del map[string]ival) error {
		if err := b.sendBatched(set, addElements(add), false); err != nil {
			return err
		}
		return b.sendBatched(set, delElements(del), true)
	}
	if err := apply(b.cidr4, add4, del4); err != nil {
		return fmt.Errorf("update cidr_v4: %w", err)
	}
	if err := apply(b.cidr6, add6, del6); err != nil {
		return fmt.Errorf("update cidr_v6: %w", err)
	}

	b.cur4, b.cur6 = want4, want6
	log.Printf("nft: CIDR ranges updated (+%d/-%d v4, +%d/-%d v6)",
		len(add4), len(del4), len(add6), len(del6))
	return nil
}

// buildIntervals converts prefixes into merged, non-overlapping v4 and v6
// interval sets. Merging is required because the blocklists overlap and
// adjoin, and an nftables interval set rejects overlapping elements (EEXIST).
// /0 and ranges whose end would overflow are skipped.
func buildIntervals(prefixes []netip.Prefix) (v4, v6 map[string]ival) {
	var i4, i6 []ival
	for _, p := range prefixes {
		p = p.Masked()
		if p.Bits() == 0 {
			continue
		}
		if IsReservedPrefix(p) {
			continue // never block the LAN / reserved space
		}
		start, end, ok := intervalBounds(p)
		if !ok {
			continue
		}
		if p.Addr().Is4() {
			i4 = append(i4, ival{start, end})
		} else {
			i6 = append(i6, ival{start, end})
		}
	}
	return mergeIvals(i4), mergeIvals(i6)
}

// mergeIvals sorts intervals by start and coalesces any that overlap or adjoin
// (next.start <= cur.end, end being exclusive), returning them keyed by
// start/end so they can be diffed.
func mergeIvals(ivs []ival) map[string]ival {
	out := make(map[string]ival)
	if len(ivs) == 0 {
		return out
	}
	sort.Slice(ivs, func(i, j int) bool {
		if c := bytes.Compare(ivs[i].start, ivs[j].start); c != 0 {
			return c < 0
		}
		return bytes.Compare(ivs[i].end, ivs[j].end) < 0
	})
	cur := ivs[0]
	for _, nx := range ivs[1:] {
		if bytes.Compare(nx.start, cur.end) <= 0 { // overlap or adjacency
			if bytes.Compare(nx.end, cur.end) > 0 {
				cur.end = nx.end
			}
			continue
		}
		out[ivalKey(cur.start, cur.end)] = cur
		cur = nx
	}
	out[ivalKey(cur.start, cur.end)] = cur
	return out
}

// diffIvals returns the intervals to add (in want but not cur) and to delete
// (in cur but not want).
func diffIvals(cur, want map[string]ival) (add, del map[string]ival) {
	add = make(map[string]ival)
	del = make(map[string]ival)
	for k, v := range want {
		if _, ok := cur[k]; !ok {
			add[k] = v
		}
	}
	for k, v := range cur {
		if _, ok := want[k]; !ok {
			del[k] = v
		}
	}
	return add, del
}

// addElements builds interval SetElements (start + IntervalEnd end).
func addElements(ivs map[string]ival) []nftables.SetElement {
	var e []nftables.SetElement
	for _, v := range ivs {
		e = append(e, nftables.SetElement{Key: v.start}, nftables.SetElement{Key: v.end, IntervalEnd: true})
	}
	return e
}

// delElements builds SetElements identifying intervals to remove by start key.
func delElements(ivs map[string]ival) []nftables.SetElement {
	var e []nftables.SetElement
	for _, v := range ivs {
		e = append(e, nftables.SetElement{Key: v.start})
	}
	return e
}

// intervalBounds returns the interval [start, end) for a prefix as raw address
// bytes: start is the network address, end is the first address after the
// range. ok is false if the end would overflow the address space.
func intervalBounds(p netip.Prefix) (start, end []byte, ok bool) {
	addr := p.Addr()
	bits := addr.BitLen() // 32 or 128
	hostBits := uint(bits - p.Bits())

	if addr.Is4() {
		b := addr.As4()
		v := uint64(binary.BigEndian.Uint32(b[:]))
		endV := v + (uint64(1) << hostBits)
		if endV > 0xffffffff {
			return nil, nil, false
		}
		s := make([]byte, 4)
		e := make([]byte, 4)
		binary.BigEndian.PutUint32(s, uint32(v))
		binary.BigEndian.PutUint32(e, uint32(endV))
		return s, e, true
	}

	b := addr.As16()
	z := new(big.Int).SetBytes(b[:])
	size := new(big.Int).Lsh(big.NewInt(1), hostBits)
	endZ := new(big.Int).Add(z, size)
	if endZ.BitLen() > 128 {
		return nil, nil, false
	}
	return leftPad(z.Bytes(), 16), leftPad(endZ.Bytes(), 16), true
}

// leftPad left-pads b with zero bytes to length n.
func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b[len(b)-n:]
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// RedirectDNS transparently redirects forwarded plaintext DNS (UDP and TCP
// port 53) to this host's own resolver via a nat prerouting chain. This forces
// steered clients onto the filtering resolver no matter which DNS server they
// are configured to use, and it runs before the forward reject rules, so DNS
// to an otherwise-blocked resolver IP (e.g. 8.8.8.8, which is also a DoH
// endpoint) still works. The local resolver must listen on port 53.
func (b *IPBlocker) RedirectDNS() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	accept := nftables.ChainPolicyAccept
	nat := b.conn.AddChain(&nftables.Chain{
		Name:     "dnsredirect",
		Table:    b.table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
		Policy:   &accept,
	})
	for _, proto := range []byte{protoUDP, protoTCP} {
		exprs := append(matchL4Port(proto, 53), &expr.Redir{})
		b.conn.AddRule(&nftables.Rule{Table: b.table, Chain: nat, Exprs: exprs})
	}
	if err := b.conn.Flush(); err != nil {
		return fmt.Errorf("redirect dns: %w", err)
	}
	log.Print("nft: plaintext DNS (port 53) redirected to local resolver")
	return nil
}

// AddIP adds one destination IP to the matching named set and flushes.
func (b *IPBlocker) AddIP(ip netip.Addr) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	var set *nftables.Set
	var key []byte
	if ip.Is4() {
		set = b.set4
		a := ip.As4()
		key = a[:]
	} else {
		set = b.set6
		a := ip.As16()
		key = a[:]
	}
	if err := b.conn.SetAddElements(set, []nftables.SetElement{{Key: key}}); err != nil {
		return fmt.Errorf("add %s: %w", ip, err)
	}
	return b.conn.Flush()
}

// AddIPs adds several IPs, flushing once. Invalid entries are skipped.
func (b *IPBlocker) AddIPs(ips []netip.Addr) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	var e4, e6 []nftables.SetElement
	for _, ip := range ips {
		if ip.Is4() {
			a := ip.As4()
			e4 = append(e4, nftables.SetElement{Key: a[:]})
		} else if ip.Is6() {
			a := ip.As16()
			e6 = append(e6, nftables.SetElement{Key: a[:]})
		}
	}
	if len(e4) > 0 {
		if err := b.conn.SetAddElements(b.set4, e4); err != nil {
			return err
		}
	}
	if len(e6) > 0 {
		if err := b.conn.SetAddElements(b.set6, e6); err != nil {
			return err
		}
	}
	return b.conn.Flush()
}
