package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/quic"

	"github.com/ascension-association/gk-fltr/internal/ndpi"
	"github.com/ascension-association/gk-fltr/internal/netpkt"
	"github.com/ascension-association/gk-fltr/internal/policy"
)

// clientHello returns the TLS ClientHello record Go's TLS stack sends for sni.
func clientHello(t *testing.T, sni string) []byte {
	t.Helper()
	c := &recordConn{}
	tc := tls.Client(c, &tls.Config{ServerName: sni, NextProtos: []string{"h2", "http/1.1"}})
	_ = tc.Handshake() // fails at the first read, after the hello is written
	if len(c.written) == 0 {
		t.Fatal("no ClientHello written")
	}
	return c.written
}

type recordConn struct {
	net.Conn
	written []byte
}

func (c *recordConn) Write(b []byte) (int, error) {
	c.written = append(c.written, b...)
	return len(b), nil
}
func (c *recordConn) Read([]byte) (int, error)    { return 0, errors.New("eof") }
func (c *recordConn) Close() error                { return nil }
func (c *recordConn) SetDeadline(time.Time) error { return nil }

var (
	clientMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	server    = netip.MustParseAddrPort("142.250.1.1:443")
)

const serverISN, clientISN = 5000, 1000

// tlsFlow feeds a TCP handshake followed by a ClientHello for sni.
func tlsFlow(t *testing.T, e *Engine, client netip.AddrPort, sni string) {
	t.Helper()
	now := time.Now()
	hello := clientHello(t, sni)
	for _, p := range []Packet{
		{Dir: DirOriginal, HwAddr: clientMAC, Data: netpkt.TCP(client, server, clientISN, 0, netpkt.SYN, nil)},
		{Dir: DirReply, Data: netpkt.TCP(server, client, serverISN, clientISN+1, netpkt.SYN|netpkt.ACK, nil)},
		{Dir: DirOriginal, HwAddr: clientMAC, Data: netpkt.TCP(client, server, clientISN+1, serverISN+1, netpkt.ACK, nil)},
		{Dir: DirOriginal, HwAddr: clientMAC, Data: netpkt.TCP(client, server, clientISN+1, serverISN+1, netpkt.ACK|netpkt.PSH, hello)},
	} {
		p.Time = now
		e.Handle(p)
	}
}

func newEngine(t *testing.T, p *policy.Policy) (*Engine, *[]Decision) {
	t.Helper()
	mod, err := ndpi.New(ndpi.LicenseNotForProfit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mod.Close)
	yt, ok := mod.ProtoID("YouTube")
	if !ok {
		t.Fatal("nDPI does not know YouTube")
	}
	var got []Decision
	e := New(Config{
		Module:     mod,
		Protocols:  []uint16{yt},
		OnDecision: func(d Decision) { got = append(got, d) },
	}, p)
	t.Cleanup(e.Close)
	return e, &got
}

func mustPolicy(t *testing.T, rules string) *policy.Policy {
	t.Helper()
	var b policy.Builder
	if err := b.Parse(strings.NewReader(rules)); err != nil {
		t.Fatal(err)
	}
	return b.Policy()
}

func TestBlockYouTubeByIP(t *testing.T) {
	e, got := newEngine(t, mustPolicy(t, "ip 192.168.1.0/24"))
	client := netip.MustParseAddrPort("192.168.1.10:50000")
	tlsFlow(t, e, client, "www.youtube.com")

	if len(*got) != 1 {
		t.Fatalf("got %d decisions, want 1", len(*got))
	}
	d := (*got)[0]
	if !d.Target || !d.Block || d.Rule != "ip 192.168.1.0/24" {
		t.Fatalf("decision = %+v, want blocked by ip rule", d)
	}
	if d.Client != client || d.Server != server || d.Proto != 6 {
		t.Errorf("tuple = %+v", d.Tuple)
	}
	if d.MAC.String() != clientMAC.String() {
		t.Errorf("MAC = %s, want %s", d.MAC, clientMAC)
	}
	if !strings.HasPrefix(d.JA4, "t13d") {
		t.Errorf("JA4 = %q, want TLS 1.3 fingerprint", d.JA4)
	}
	if !d.CanReset || d.ResetSeq != serverISN+1 {
		t.Errorf("reset seq = %d (%v), want %d", d.ResetSeq, d.CanReset, serverISN+1)
	}
	t.Logf("%s host=%s ja4=%s", d.Class, d.Host, d.JA4)
}

func TestBlockByMACAndJA4(t *testing.T) {
	// Learn the fingerprint of Go's TLS client first.
	e, got := newEngine(t, mustPolicy(t, ""))
	tlsFlow(t, e, netip.MustParseAddrPort("10.0.0.2:40000"), "www.youtube.com")
	if len(*got) != 1 || !(*got)[0].Target || (*got)[0].Block {
		t.Fatalf("empty policy: decisions = %+v, want one unblocked YouTube flow", *got)
	}
	ja4 := (*got)[0].JA4
	parts := strings.Split(ja4, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4 %q: want three sections", ja4)
	}

	for _, rules := range []string{
		"mac " + clientMAC.String(),
		"ja4 " + ja4,
		"ja4 *_" + parts[1] + "_*",
	} {
		e, got := newEngine(t, mustPolicy(t, rules))
		tlsFlow(t, e, netip.MustParseAddrPort("10.0.0.2:40000"), "rr3---sn-abc.googlevideo.com")
		if len(*got) != 1 || !(*got)[0].Block {
			t.Errorf("rules %q: decisions = %+v, want blocked", rules, *got)
		}
	}
}

func TestLabel(t *testing.T) {
	e, got := newEngine(t, mustPolicy(t, ""))
	e.cfg.Label = func(ja4 string) string {
		if strings.HasPrefix(ja4, "t13d") {
			return "Go TLS"
		}
		return ""
	}
	tlsFlow(t, e, netip.MustParseAddrPort("10.0.0.2:40000"), "www.youtube.com")
	if len(*got) != 1 || (*got)[0].Label != "Go TLS" {
		t.Fatalf("decisions = %+v, want one labelled \"Go TLS\"", *got)
	}
}

func TestOtherTrafficNotBlocked(t *testing.T) {
	e, got := newEngine(t, mustPolicy(t, "ip 0.0.0.0/0"))
	tlsFlow(t, e, netip.MustParseAddrPort("192.168.1.10:50001"), "en.wikipedia.org")
	for _, d := range *got {
		if d.Target || d.Block {
			t.Fatalf("non-YouTube flow decided as %+v", d)
		}
	}
}

func TestParse(t *testing.T) {
	c6 := netip.MustParseAddrPort("[fd00::10]:1234")
	s6 := netip.MustParseAddrPort("[2001:db8::1]:443")
	info, ok := parse(netpkt.TCP(c6, s6, 7, 9, netpkt.ACK, []byte("abc")))
	if !ok || info.src != c6 || info.dst != s6 || info.seq != 7 || info.ack != 9 || info.payloadLen != 3 {
		t.Errorf("parse v6 tcp = %+v, %v", info, ok)
	}
	c4 := netip.MustParseAddrPort("192.168.1.2:5353")
	info, ok = parse(netpkt.UDP(c4, server, []byte("hello")))
	if !ok || info.proto != protoUDP || info.src != c4 || info.payloadLen != 5 {
		t.Errorf("parse v4 udp = %+v, %v", info, ok)
	}
}

// quicInitials returns the first flight of UDP payloads a QUIC client sends
// when connecting with sni.
func quicInitials(t *testing.T, sni string) [][]byte {
	t.Helper()
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ep, err := quic.Listen("udp", "127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		ep.Close(ctx)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ep.Dial(ctx, "udp", srv.LocalAddr().String(), &quic.Config{
		TLSConfig: &tls.Config{ServerName: sni, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13},
	})

	var dgrams [][]byte
	buf := make([]byte, 65535)
	srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, _, err := srv.ReadFromUDP(buf)
		if err != nil {
			break
		}
		dgrams = append(dgrams, append([]byte(nil), buf[:n]...))
		srv.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	}
	if len(dgrams) == 0 {
		t.Fatal("QUIC client sent nothing")
	}
	t.Logf("QUIC client sent %d datagrams for %s", len(dgrams), sni)
	return dgrams
}

func quicFlow(t *testing.T, e *Engine, client netip.AddrPort, sni string) {
	t.Helper()
	for _, d := range quicInitials(t, sni) {
		e.Handle(Packet{Dir: DirOriginal, HwAddr: clientMAC, Time: time.Now(), Data: netpkt.UDP(client, server, d)})
	}
}

func TestBlockYouTubeQUIC(t *testing.T) {
	e, got := newEngine(t, mustPolicy(t, "ip 192.168.1.0/24"))
	client := netip.MustParseAddrPort("192.168.1.10:50000")
	quicFlow(t, e, client, "www.youtube.com")

	if len(*got) != 1 {
		t.Fatalf("got %d decisions, want 1", len(*got))
	}
	d := (*got)[0]
	if !d.Target || !d.Block || d.Tuple.Proto != 17 || d.Client != client {
		t.Fatalf("decision = %+v, want blocked UDP flow", d)
	}
	if info, ok := parse(d.Trigger); !ok || info.proto != protoUDP || info.src != client || info.dst != server {
		t.Errorf("Trigger = %+v, %v; want the client's UDP packet", info, ok)
	}
	if !strings.HasPrefix(d.JA4, "q13") {
		t.Errorf("JA4 = %q, want QUIC fingerprint", d.JA4)
	}
	t.Logf("%s host=%s ja4=%s", d.Class, d.Host, d.JA4)

	// Other QUIC traffic is left alone.
	e, got = newEngine(t, mustPolicy(t, "ip 192.168.1.0/24"))
	quicFlow(t, e, client, "www.example.com")
	for _, d := range *got {
		if d.Target || d.Block {
			t.Fatalf("non-YouTube QUIC flow decided as %+v", d)
		}
	}
}

func TestVerdicts(t *testing.T) {
	client := netip.MustParseAddrPort("192.168.1.10:50002")
	now := time.Now()
	for _, tc := range []struct {
		sni  string
		want []Verdict // SYN, SYN-ACK, ACK, ClientHello, next client packet
	}{
		{"www.youtube.com", []Verdict{Accept, Accept, Accept, Drop, Drop}},
		{"en.wikipedia.org", []Verdict{Accept, Accept, Accept, Accept, Accept}},
	} {
		e, _ := newEngine(t, mustPolicy(t, "ip 192.168.1.0/24"))
		hello := clientHello(t, tc.sni)
		pkts := []Packet{
			{Dir: DirOriginal, Data: netpkt.TCP(client, server, clientISN, 0, netpkt.SYN, nil)},
			{Dir: DirReply, Data: netpkt.TCP(server, client, serverISN, clientISN+1, netpkt.SYN|netpkt.ACK, nil)},
			{Dir: DirOriginal, Data: netpkt.TCP(client, server, clientISN+1, serverISN+1, netpkt.ACK, nil)},
			{Dir: DirOriginal, Data: netpkt.TCP(client, server, clientISN+1, serverISN+1, netpkt.ACK|netpkt.PSH, hello)},
			{Dir: DirOriginal, Data: netpkt.TCP(client, server, clientISN+1+uint32(len(hello)), serverISN+1, netpkt.ACK, nil)},
		}
		for i, p := range pkts {
			p.Time = now
			if got := e.Handle(p); got != tc.want[i] {
				t.Errorf("%s: packet %d verdict = %v, want %v", tc.sni, i, got, tc.want[i])
			}
		}
	}
}

func TestUntrackedVerdict(t *testing.T) {
	mod, err := ndpi.New(ndpi.LicenseNotForProfit)
	if err != nil {
		t.Fatal(err)
	}
	defer mod.Close()
	syn := func(port uint16) Packet {
		c := netip.AddrPortFrom(netip.MustParseAddr("192.168.1.10"), port)
		return Packet{Dir: DirOriginal, Time: time.Now(), Data: netpkt.TCP(c, server, 1, 0, netpkt.SYN, nil)}
	}
	for _, closed := range []bool{false, true} {
		e := New(Config{Module: mod, MaxFlows: 1, FailClosed: closed}, mustPolicy(t, ""))
		want := Accept
		if closed {
			want = Drop
		}
		if v := e.Handle(syn(1)); v != Accept {
			t.Errorf("FailClosed=%v: tracked flow verdict = %v, want Accept", closed, v)
		}
		if v := e.Handle(syn(2)); v != want {
			t.Errorf("FailClosed=%v: untracked flow verdict = %v, want %v", closed, v, want)
		}
		e.Close()
	}
}

func TestAllowance(t *testing.T) {
	client := netip.MustParseAddrPort("192.168.1.10:50003")
	for _, left := range []bool{true, false} {
		e, got := newEngine(t, mustPolicy(t, "mac "+clientMAC.String()+" user=alice allow=2h"))
		var asked policy.Match
		e.cfg.Admit = func(m policy.Match) bool { asked = m; return left }
		tlsFlow(t, e, client, "www.youtube.com")
		if len(*got) != 1 {
			t.Fatalf("left=%v: %d decisions", left, len(*got))
		}
		d := (*got)[0]
		if d.Block == left || d.Metered != left || d.User != "alice" || d.Group != "user:alice" || d.Allowance != 2*time.Hour {
			t.Errorf("left=%v: decision = %+v", left, d)
		}
		if asked.Group != "user:alice" {
			t.Errorf("Admit asked about %+v", asked)
		}
	}
}
