// Package engine tracks flows, classifies them with nDPI and decides, once
// per flow, whether the flow is a blocked protocol from a matching source.
package engine

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ascension-association/gk-fltr/internal/ndpi"
	"github.com/ascension-association/gk-fltr/internal/policy"
)

// Dir is a packet's conntrack direction, when known.
type Dir uint8

const (
	DirUnknown  Dir = iota // first packet seen is treated as client->server
	DirOriginal            // sent by the connection's initiator (client)
	DirReply               // sent by the responder (server)
)

// Packet is one captured packet.
type Packet struct {
	Data   []byte // starting at the IP header
	Time   time.Time
	Dir    Dir
	HwAddr net.HardwareAddr // link-layer source address, if known
}

// Tuple identifies a flow, oriented from client to server.
type Tuple struct {
	Proto  uint8 // 6 (TCP) or 17 (UDP)
	Client netip.AddrPort
	Server netip.AddrPort
}

// Decision is the engine's final verdict on a flow.
type Decision struct {
	Tuple
	MAC    net.HardwareAddr // client MAC, if known
	Class  string           // nDPI classification, e.g. "TLS.YouTube"
	Host   string           // SNI / host name, if any
	JA4    string           // JA4 client fingerprint, if any
	Label  string           // name of the client software, from Config.Label
	Target bool             // classified as one of the blocked protocols
	Block  bool             // Target, matched the policy, and no allowance left
	Rule   string           // policy rule that matched
	// For rules with a daily allowance: who it belongs to, how large it is,
	// and whether this flow was admitted under it (Metered, so not Block).
	User      string
	Group     string
	Allowance time.Duration
	Metered   bool
	ResetSeq  uint32 // sequence number for a RST from server to client
	CanReset  bool   // ResetSeq is valid (TCP only)
	// Trigger is the client->server packet that completed classification of
	// a UDP flow (e.g. a QUIC Initial), quoted in an ICMP error to the client.
	Trigger []byte
}

// Config configures an Engine.
type Config struct {
	Module      *ndpi.Module
	Protocols   []uint16 // nDPI protocol IDs to block
	MaxPackets  int      // give up classifying a flow after this many packets
	IdleTimeout time.Duration
	MaxFlows    int
	// FailClosed drops packets of new flows the engine cannot track (flow
	// table full, allocation failure) instead of accepting them.
	FailClosed bool
	// LookupMAC resolves a client IP to a MAC when the packet capture did
	// not supply one (e.g. via /proc/net/arp). Optional.
	LookupMAC func(netip.Addr) net.HardwareAddr
	// Label names the client software with a JA4 fingerprint, or returns
	// "" if unknown. Optional.
	Label func(ja4 string) string
	// OnDecision is called once per flow, outside the engine's lock.
	OnDecision func(Decision)
	// Admit reports whether a matched source still has allowance left
	// (only called for rules with an allowance). If nil, nothing is admitted.
	Admit func(policy.Match) bool
}

type flowKey struct {
	proto uint8
	a, b  netip.AddrPort
}

type flow struct {
	tuple   Tuple
	nf      *ndpi.Flow
	mac     net.HardwareAddr
	packets int
	last    time.Time
	done    bool
	blocked bool
}

// Engine classifies flows. It is safe for concurrent use.
type Engine struct {
	cfg    Config
	policy atomic.Pointer[policy.Policy]

	mu    sync.Mutex
	flows map[flowKey]*flow
}

// New returns an Engine applying p.
func New(cfg Config, p *policy.Policy) *Engine {
	if cfg.MaxPackets <= 0 {
		cfg.MaxPackets = 24
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 2 * time.Minute
	}
	if cfg.MaxFlows <= 0 {
		cfg.MaxFlows = 262144
	}
	e := &Engine{cfg: cfg, flows: make(map[flowKey]*flow)}
	e.policy.Store(p)
	return e
}

// SetPolicy replaces the policy for flows decided from now on.
func (e *Engine) SetPolicy(p *policy.Policy) { e.policy.Store(p) }

// Handle processes one packet.
// Verdict is what should happen to a packet held in a queue.
type Verdict int

const (
	Accept Verdict = iota
	Drop           // the packet belongs to a blocked flow
)

// Handle processes one packet and returns its verdict. When the packet
// completes a flow's classification, OnDecision runs before Handle returns.
func (e *Engine) Handle(p Packet) Verdict {
	d, ok, v := e.handle(p)
	if ok && e.cfg.OnDecision != nil {
		e.cfg.OnDecision(d)
	}
	return v
}

func (e *Engine) handle(p Packet) (Decision, bool, Verdict) {
	info, ok := parse(p.Data)
	if !ok {
		return Decision{}, false, Accept
	}
	key := flowKey{proto: info.proto, a: info.src, b: info.dst}
	if key.a.Compare(key.b) > 0 {
		key.a, key.b = key.b, key.a
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	f := e.flows[key]
	if f == nil {
		if len(e.flows) >= e.cfg.MaxFlows {
			return Decision{}, false, e.untracked()
		}
		t := Tuple{Proto: info.proto, Client: info.src, Server: info.dst}
		if p.Dir == DirReply {
			t.Client, t.Server = t.Server, t.Client
		}
		nf := e.cfg.Module.NewFlow()
		if nf == nil {
			return Decision{}, false, e.untracked()
		}
		f = &flow{tuple: t, nf: nf}
		e.flows[key] = f
	}
	f.last = p.Time
	if f.done {
		if f.blocked {
			return Decision{}, false, Drop
		}
		return Decision{}, false, Accept
	}

	fromClient := info.src == f.tuple.Client
	dir := ndpi.DirServerToClient
	if fromClient {
		dir = ndpi.DirClientToServer
		if f.mac == nil && len(p.HwAddr) > 0 {
			f.mac = append(net.HardwareAddr(nil), p.HwAddr...)
		}
	}
	f.packets++

	r := e.cfg.Module.Process(f.nf, p.Data, uint64(p.Time.UnixMilli()), dir)
	if !e.isTarget(r) && !r.State.Final() {
		if f.packets < e.cfg.MaxPackets {
			return Decision{}, false, Accept
		}
		r = e.cfg.Module.GiveUp(f.nf)
	}
	d := e.decide(f, r, info, fromClient, p.Data)
	if d.Block {
		return d, true, Drop
	}
	return d, true, Accept
}

// untracked is the verdict for a packet of a flow the engine cannot track.
func (e *Engine) untracked() Verdict {
	if e.cfg.FailClosed {
		return Drop
	}
	return Accept
}

func (e *Engine) isTarget(r ndpi.Result) bool {
	for _, id := range e.cfg.Protocols {
		if r.Has(id) {
			return true
		}
	}
	return false
}

// decide finalizes f. Called with e.mu held.
func (e *Engine) decide(f *flow, r ndpi.Result, info pktInfo, fromClient bool, data []byte) Decision {
	f.done = true
	f.nf.Free()
	f.nf = nil

	d := Decision{
		Tuple:  f.tuple,
		MAC:    f.mac,
		Class:  e.cfg.Module.Describe(r),
		Host:   r.Host,
		JA4:    r.JA4,
		Target: e.isTarget(r),
	}
	if d.JA4 != "" && e.cfg.Label != nil {
		d.Label = e.cfg.Label(d.JA4)
	}
	if d.MAC == nil && e.cfg.LookupMAC != nil {
		d.MAC = e.cfg.LookupMAC(f.tuple.Client.Addr())
	}
	if d.Target {
		if m, ok := e.policy.Load().Match(f.tuple.Client.Addr(), d.MAC, d.JA4); ok {
			d.Rule, d.User, d.Group, d.Allowance = m.Rule, m.User, m.Group, m.Allowance
			d.Block = true
			if m.Allowance > 0 && e.cfg.Admit != nil && e.cfg.Admit(m) {
				d.Block, d.Metered = false, true
			}
		}
		f.blocked = d.Block
	}
	if info.proto == protoUDP && fromClient && d.Block {
		d.Trigger = append([]byte(nil), data...)
	}
	if info.proto == protoTCP {
		switch {
		case fromClient && info.flags&tcpACK != 0:
			// The client acknowledges up to the server's next sequence number.
			d.ResetSeq, d.CanReset = info.ack, true
		case !fromClient:
			n := uint32(info.payloadLen)
			if info.flags&(tcpSYN|tcpFIN) != 0 {
				n++
			}
			d.ResetSeq, d.CanReset = info.seq+n, true
		}
	}
	return d
}

// Expire forgets flows idle for longer than the idle timeout and returns
// how many flows remain.
func (e *Engine) Expire(now time.Time) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, f := range e.flows {
		if now.Sub(f.last) > e.cfg.IdleTimeout {
			f.nf.Free()
			delete(e.flows, k)
		}
	}
	return len(e.flows)
}

// Drain gives up on all undecided flows (e.g. at the end of a capture file)
// and reports their decisions.
func (e *Engine) Drain() {
	var ds []Decision
	e.mu.Lock()
	for _, f := range e.flows {
		if !f.done {
			ds = append(ds, e.decide(f, e.cfg.Module.GiveUp(f.nf), pktInfo{}, false, nil))
		}
	}
	e.mu.Unlock()
	if e.cfg.OnDecision != nil {
		for _, d := range ds {
			e.cfg.OnDecision(d)
		}
	}
}

// Close frees all flow state.
func (e *Engine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, f := range e.flows {
		f.nf.Free()
		delete(e.flows, k)
	}
}
