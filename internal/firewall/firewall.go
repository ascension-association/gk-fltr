// Package firewall installs gk-fltr's nftables table and blocks flows in it.
//
// The table is self-contained and does not touch other tables:
//
//	table inet <name> {
//		set block4 { type inet_proto . ipv4_addr . inet_service . ipv4_addr . inet_service; flags timeout; }
//		set block6 { type inet_proto . ipv6_addr . inet_service . ipv6_addr . inet_service; flags timeout; }
//		set meter4 { ...; flags timeout; counter; }  # flows admitted under an allowance
//		set meter6 { ...; flags timeout; counter; }
//		set allow4 { ... }  # queue mode only
//		set allow6 { ... }  # queue mode only
//		chain forward {
//			type filter hook forward priority <prio>; policy accept;
//			# client -> server packets of blocked flows
//			meta l4proto tcp  meta l4proto . ip saddr . th sport . ip daddr . th dport @block4 counter reject with tcp reset
//			meta l4proto != tcp meta l4proto . ip saddr . th sport . ip daddr . th dport @block4 counter reject with icmpx admin-prohibited
//			# server -> client packets of blocked flows
//			meta l4proto tcp  meta l4proto . ip daddr . th dport . ip saddr . th sport @block4 counter reject with tcp reset
//			meta l4proto != tcp meta l4proto . ip daddr . th dport . ip saddr . th sport @block4 counter drop
//			... (same for ipv6 / @block6)
//
//			# Metered flows are counted per flow and skip classification.
//			meta l4proto . ip saddr . th sport . ip daddr . th dport @meter4 accept
//			meta l4proto . ip daddr . th dport . ip saddr . th sport @meter4 accept
//			... (same for ipv6 / @meter6)
//
//			# Queue mode: flows already allowed skip the queue ...
//			meta l4proto . ip saddr . th sport . ip daddr . th dport @allow4 accept
//			meta l4proto . ip daddr . th dport . ip saddr . th sport @allow4 accept
//			... (same for ipv6 / @allow6)
//			# ... and the first packets of every other connection wait for gk-fltr.
//			# With FailOpen the queue rules also get "bypass".
//			ct packets < <n> ct direction original queue num <q>
//			ct packets < <n> ct direction reply    queue num <q+1>
//
//			# Log mode: the first packets are copied to gk-fltr instead.
//			ct packets < <n> ct direction original log group <g> prefix "o"
//			ct packets < <n> ct direction reply    log group <g> prefix "r"
//		}
//	}
package firewall

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Log prefixes marking a packet's conntrack direction (log mode).
const (
	PrefixOriginal = "o"
	PrefixReply    = "r"
)

// Mode selects how packets reach gk-fltr.
type Mode int

const (
	// ModeQueue holds the first packets of each connection in NFQUEUE until
	// gk-fltr issues a verdict (needs CONFIG_NFT_QUEUE).
	ModeQueue Mode = iota
	// ModeLog copies the first packets of each connection to gk-fltr via
	// NFLOG and lets them pass (needs CONFIG_NETFILTER_NETLINK_LOG).
	ModeLog
)

func (m Mode) String() string {
	if m == ModeQueue {
		return "queue"
	}
	return "log"
}

// Options configures the nftables table.
type Options struct {
	Table        string        // table name (family inet)
	Priority     int32         // forward chain priority
	Mode         Mode          // how packets reach gk-fltr
	Queue        uint16        // queue mode: original direction uses Queue, reply Queue+1
	Group        uint16        // log mode: NFLOG group
	Packets      uint64        // hand packets to gk-fltr while ct packets < Packets
	BlockTimeout time.Duration // how long a blocked flow stays in the block set
	AllowTimeout time.Duration // queue mode: how long an allowed flow skips the queue
	MeterTimeout time.Duration // how long a metered flow stays in the meter set (default 24h)
	// FailOpen makes the queue rules accept packets while no gk-fltr is
	// listening ("bypass"). Otherwise they are dropped (fail closed).
	FailOpen bool
}

// Firewall is an installed gk-fltr table.
type Firewall struct {
	mu           sync.Mutex
	opts         Options
	conn         *nftables.Conn
	table        *nftables.Table
	block4       *nftables.Set
	block6       *nftables.Set
	allow4       *nftables.Set
	allow6       *nftables.Set
	meter4       *nftables.Set
	meter6       *nftables.Set
	keyV4, keyV6 nftables.SetDatatype
	// elems remembers the block and meter set elements and when they expire,
	// so that install can restore them after the table was flushed.
	elems map[*nftables.Set]map[string]time.Time
}

// Setup enables conntrack accounting (needed for "ct packets") and
// (re)creates the table.
func Setup(o Options) (*Firewall, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, err
	}
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: o.Table}
	fw := &Firewall{
		opts:  o,
		conn:  c,
		table: t,
		keyV4: nftables.MustConcatSetType(nftables.TypeInetProto, nftables.TypeIPAddr,
			nftables.TypeInetService, nftables.TypeIPAddr, nftables.TypeInetService),
		keyV6: nftables.MustConcatSetType(nftables.TypeInetProto, nftables.TypeIP6Addr,
			nftables.TypeInetService, nftables.TypeIP6Addr, nftables.TypeInetService),
	}
	set := func(name string, key nftables.SetDatatype, timeout time.Duration) *nftables.Set {
		return &nftables.Set{Table: t, Name: name, Concatenation: true, HasTimeout: true, Timeout: timeout, KeyType: key}
	}
	fw.block4 = set("block4", fw.keyV4, o.BlockTimeout)
	fw.block6 = set("block6", fw.keyV6, o.BlockTimeout)
	if o.Mode == ModeQueue {
		fw.allow4 = set("allow4", fw.keyV4, o.AllowTimeout)
		fw.allow6 = set("allow6", fw.keyV6, o.AllowTimeout)
	}
	if fw.opts.MeterTimeout <= 0 {
		fw.opts.MeterTimeout = 24 * time.Hour
	}
	fw.meter4 = set("meter4", fw.keyV4, fw.opts.MeterTimeout)
	fw.meter6 = set("meter6", fw.keyV6, fw.opts.MeterTimeout)
	fw.meter4.Counter, fw.meter6.Counter = true, true
	fw.elems = map[*nftables.Set]map[string]time.Time{
		fw.block4: {}, fw.block6: {}, fw.meter4: {}, fw.meter6: {},
	}

	fw.mu.Lock()
	defer fw.mu.Unlock()
	if err := fw.install(); err != nil {
		return nil, err
	}
	return fw, nil
}

// Ensure reinstalls the table if something removed it, such as another
// program flushing the whole ruleset. It reports whether the table had to be
// reinstalled.
func (fw *Firewall) Ensure() (bool, error) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	tables, err := fw.conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return false, err
	}
	for _, t := range tables {
		if t.Name == fw.table.Name {
			return false, nil
		}
	}
	return true, fw.install()
}

// install (re)creates the table. Called with fw.mu held.
func (fw *Firewall) install() error {
	if err := os.WriteFile("/proc/sys/net/netfilter/nf_conntrack_acct", []byte("1\n"), 0o644); err != nil {
		return fmt.Errorf("enabling conntrack accounting: %w", err)
	}

	c, t, o := fw.conn, fw.table, fw.opts
	// Add-then-delete removes a stale table left behind by a crash.
	c.AddTable(t)
	c.DelTable(t)
	c.AddTable(t)

	now := time.Now()
	for _, s := range []*nftables.Set{fw.block4, fw.block6, fw.meter4, fw.meter6, fw.allow4, fw.allow6} {
		if s == nil {
			continue
		}
		// Restore remembered elements (none on first install).
		var elems []nftables.SetElement
		for k, exp := range fw.elems[s] {
			if left := exp.Sub(now); left > time.Second {
				elems = append(elems, nftables.SetElement{Key: []byte(k), Timeout: left.Truncate(time.Millisecond)})
			} else {
				delete(fw.elems[s], k)
			}
		}
		if err := c.AddSet(s, elems); err != nil {
			return fmt.Errorf("adding set %s: %w", s.Name, err)
		}
	}

	policy := nftables.ChainPolicyAccept
	chain := c.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    t,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityRef(nftables.ChainPriority(o.Priority)),
		Policy:   &policy,
	})
	rule := func(exprs ...expr.Any) {
		c.AddRule(&nftables.Rule{Table: t, Chain: chain, Exprs: exprs})
	}

	for _, set := range []*nftables.Set{fw.block4, fw.block6} {
		for _, reply := range []bool{false, true} {
			for _, tcp := range []bool{true, false} {
				l4op := expr.CmpOpEq
				if !tcp {
					l4op = expr.CmpOpNeq
				}
				exprs := []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{Op: l4op, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
				}
				exprs = append(exprs, lookup(set == fw.block6, set, reply)...)
				exprs = append(exprs, &expr.Counter{})
				switch {
				case tcp:
					exprs = append(exprs, &expr.Reject{Type: unix.NFT_REJECT_TCP_RST})
				case !reply:
					exprs = append(exprs, &expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED})
				default:
					exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictDrop})
				}
				rule(exprs...)
			}
		}
	}

	// Metered flows: counted by the sets' per-element counters.
	for _, set := range []*nftables.Set{fw.meter4, fw.meter6} {
		for _, reply := range []bool{false, true} {
			exprs := lookup(set == fw.meter6, set, reply)
			rule(append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})...)
		}
	}

	for _, dir := range []struct {
		ct     byte
		queue  uint16
		prefix string
	}{
		{0, o.Queue, PrefixOriginal},  // IP_CT_DIR_ORIGINAL
		{1, o.Queue + 1, PrefixReply}, // IP_CT_DIR_REPLY
	} {
		exprs := firstPackets(o.Packets, dir.ct)
		if o.Mode == ModeQueue {
			q := &expr.Queue{Num: dir.queue}
			if o.FailOpen {
				q.Flag = expr.QueueFlagBypass
			}
			exprs = append(exprs, q)
		} else {
			exprs = append(exprs, &expr.Log{
				Key:   1<<unix.NFTA_LOG_GROUP | 1<<unix.NFTA_LOG_PREFIX,
				Group: o.Group,
				Data:  []byte(dir.prefix),
			})
		}
		if o.Mode == ModeQueue && dir.ct == 0 {
			// Allowed flows skip the queue, in both directions.
			for _, set := range []*nftables.Set{fw.allow4, fw.allow6} {
				for _, reply := range []bool{false, true} {
					exprs := lookup(set == fw.allow6, set, reply)
					rule(append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})...)
				}
			}
		}
		rule(exprs...)
	}

	if err := c.Flush(); err != nil {
		return fmt.Errorf("installing nftables table %q in %s mode: %w", o.Table, o.Mode, err)
	}
	return nil
}

// lookup matches packets of flows in set. Set keys are oriented from client
// to server, so reply packets are looked up with addresses swapped.
func lookup(v6 bool, set *nftables.Set, reply bool) []expr.Any {
	nfproto, addrLen, saddr, daddr := byte(unix.NFPROTO_IPV4), uint32(4), uint32(12), uint32(16)
	if v6 {
		nfproto, addrLen, saddr, daddr = unix.NFPROTO_IPV6, 16, 8, 24
	}
	clientAddr, clientPort, serverAddr, serverPort := saddr, uint32(0), daddr, uint32(2)
	if reply {
		clientAddr, clientPort, serverAddr, serverPort = daddr, 2, saddr, 0
	}

	reg := uint32(unix.NFT_REG32_00)
	start := reg
	load := func(base expr.PayloadBase, off, n uint32) expr.Any {
		e := &expr.Payload{DestRegister: reg, Base: base, Offset: off, Len: n}
		reg += (n + 3) / 4
		return e
	}
	exprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nfproto}},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: reg},
	}
	reg++
	return append(exprs,
		load(expr.PayloadBaseNetworkHeader, clientAddr, addrLen),
		load(expr.PayloadBaseTransportHeader, clientPort, 2),
		load(expr.PayloadBaseNetworkHeader, serverAddr, addrLen),
		load(expr.PayloadBaseTransportHeader, serverPort, 2),
		&expr.Lookup{SourceRegister: start, SetName: set.Name, SetID: set.ID},
	)
}

// firstPackets matches packets in conntrack direction ctDir while the
// connection has seen fewer than n packets (both directions).
func firstPackets(n uint64, ctDir byte) []expr.Any {
	limit := make([]byte, 8)
	binary.BigEndian.PutUint64(limit, n)
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeyPKTS, Register: 1},
		&expr.Byteorder{SourceRegister: 1, DestRegister: 1, Op: expr.ByteorderHton, Len: 8, Size: 8},
		&expr.Cmp{Op: expr.CmpOpLt, Register: 1, Data: limit},
		&expr.Ct{Key: expr.CtKeyDIRECTION, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{ctDir}},
	}
}

func key(proto uint8, client, server netip.AddrPort) []byte {
	k := []byte{proto, 0, 0, 0}
	k = append(k, client.Addr().AsSlice()...)
	k = binary.BigEndian.AppendUint16(k, client.Port())
	k = append(k, 0, 0)
	k = append(k, server.Addr().AsSlice()...)
	k = binary.BigEndian.AppendUint16(k, server.Port())
	return append(k, 0, 0)
}

func (fw *Firewall) add(v4, v6 *nftables.Set, timeout time.Duration, proto uint8, client, server netip.AddrPort) error {
	set := v4
	if client.Addr().Is6() {
		set = v6
	}
	k := key(proto, client, server)
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if err := fw.conn.SetAddElements(set, []nftables.SetElement{{Key: k, Timeout: timeout}}); err != nil {
		return err
	}
	if err := fw.conn.Flush(); err != nil {
		return err
	}
	if m := fw.elems[set]; m != nil {
		m[string(k)] = time.Now().Add(timeout)
	}
	return nil
}

func (fw *Firewall) del(v4, v6 *nftables.Set, proto uint8, client, server netip.AddrPort) error {
	set := v4
	if client.Addr().Is6() {
		set = v6
	}
	k := key(proto, client, server)
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if _, ok := fw.elems[set][string(k)]; !ok {
		return nil
	}
	delete(fw.elems[set], string(k))
	if err := fw.conn.SetDeleteElements(set, []nftables.SetElement{{Key: k}}); err != nil {
		return err
	}
	return fw.conn.Flush()
}

// Meter lets a flow (oriented client -> server) pass while counting its
// bytes; see MeterCounters.
func (fw *Firewall) Meter(proto uint8, client, server netip.AddrPort) error {
	return fw.add(fw.meter4, fw.meter6, fw.opts.MeterTimeout, proto, client, server)
}

// Unmeter removes a flow from the meter set.
func (fw *Firewall) Unmeter(proto uint8, client, server netip.AddrPort) error {
	return fw.del(fw.meter4, fw.meter6, proto, client, server)
}

// Metered is a metered flow and the bytes it has moved (both directions).
type Metered struct {
	Proto          uint8
	Client, Server netip.AddrPort
	Bytes          uint64
}

// MeterCounters returns all metered flows with their byte counters.
func (fw *Firewall) MeterCounters() ([]Metered, error) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	var ms []Metered
	for _, set := range []*nftables.Set{fw.meter4, fw.meter6} {
		elems, err := fw.conn.GetSetElements(set)
		if err != nil {
			return nil, fmt.Errorf("reading set %s: %w", set.Name, err)
		}
		for _, e := range elems {
			m, ok := parseKey(e.Key)
			if !ok {
				continue
			}
			if e.Counter != nil {
				m.Bytes = e.Counter.Bytes
			}
			ms = append(ms, m)
		}
	}
	return ms, nil
}

// parseKey decodes a set key built by key.
func parseKey(k []byte) (Metered, bool) {
	var m Metered
	switch len(k) {
	case 20:
		m.Client = netip.AddrPortFrom(netip.AddrFrom4([4]byte(k[4:8])), binary.BigEndian.Uint16(k[8:10]))
		m.Server = netip.AddrPortFrom(netip.AddrFrom4([4]byte(k[12:16])), binary.BigEndian.Uint16(k[16:18]))
	case 44:
		m.Client = netip.AddrPortFrom(netip.AddrFrom16([16]byte(k[4:20])), binary.BigEndian.Uint16(k[20:22]))
		m.Server = netip.AddrPortFrom(netip.AddrFrom16([16]byte(k[24:40])), binary.BigEndian.Uint16(k[40:42]))
	default:
		return m, false
	}
	m.Proto = k[0]
	return m, true
}

// Block adds a flow (oriented client -> server) to the block set. The block
// rules come first, so this also stops a metered flow.
func (fw *Firewall) Block(proto uint8, client, server netip.AddrPort) error {
	return fw.add(fw.block4, fw.block6, fw.opts.BlockTimeout, proto, client, server)
}

// Allow lets the rest of a flow bypass the queue. It does nothing in log mode.
func (fw *Firewall) Allow(proto uint8, client, server netip.AddrPort) error {
	if fw.allow4 == nil {
		return nil
	}
	return fw.add(fw.allow4, fw.allow6, fw.opts.AllowTimeout, proto, client, server)
}

// Close removes the table.
func (fw *Firewall) Close() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	fw.conn.DelTable(fw.table)
	return fw.conn.Flush()
}

// Mode reports how packets reach gk-fltr.
func (fw *Firewall) Mode() Mode { return fw.opts.Mode }
