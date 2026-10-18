package main

import (
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ascension-association/gk-fltr/internal/engine"
	"github.com/ascension-association/gk-fltr/internal/labels"
	"github.com/ascension-association/gk-fltr/internal/netpkt"
)

type helloConn struct {
	net.Conn
	written []byte
}

func (c *helloConn) Write(b []byte) (int, error) {
	c.written = append(c.written, b...)
	return len(b), nil
}
func (c *helloConn) Read([]byte) (int, error) { return 0, errors.New("eof") }
func (c *helloConn) Close() error             { return nil }

// tlsPcap writes a capture of a TLS connection to sni.
func tlsPcap(t *testing.T, sni string) string {
	t.Helper()
	hc := &helloConn{}
	_ = tls.Client(hc, &tls.Config{ServerName: sni}).Handshake()
	mac := []byte{2, 0, 0, 0, 0, 0x10}
	c := netip.MustParseAddrPort("192.168.1.10:40000")
	s := netip.MustParseAddrPort("203.0.113.10:443")
	return writePcap(t,
		ether(mac, netpkt.TCP(c, s, 1000, 0, netpkt.SYN, nil)),
		ether(mac, netpkt.TCP(s, c, 5000, 1001, netpkt.SYN|netpkt.ACK, nil)),
		ether(mac, netpkt.TCP(c, s, 1001, 5001, netpkt.ACK, nil)),
		ether(mac, netpkt.TCP(c, s, 1001, 5001, netpkt.ACK|netpkt.PSH, hc.written)),
	)
}

func TestInspectLearn(t *testing.T) {
	pcap := tlsPcap(t, "en.wikipedia.org")
	file := filepath.Join(t.TempDir(), "labels.txt")
	for range 2 { // the second run finds the fingerprint already labelled
		if err := inspect([]string{"-labels", file, "-learn", "Go TLS", pcap}); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(file)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "t13d") || !strings.HasSuffix(lines[0], "  Go TLS") {
		t.Fatalf("labels file = %q, want one t13d... entry labelled Go TLS", data)
	}
	l, err := labels.ParseFile(file)
	if err != nil {
		t.Fatal(err)
	}
	ja4 := strings.Fields(lines[0])[0]
	if got := l.Lookup(ja4); got != "Go TLS" {
		t.Errorf("Lookup(%s) = %q", ja4, got)
	}

	if err := inspect([]string{"-learn", "x", pcap}); err == nil {
		t.Error("-learn without -labels: no error")
	}
}

func TestFormatDecisionLabel(t *testing.T) {
	d := engine.Decision{Tuple: engine.Tuple{Proto: 17}, Class: "QUIC.YouTube", JA4: "q13d", Label: "Chrome (QUIC)"}
	if s := formatDecision(d); !strings.HasSuffix(s, ` ja4=q13d client="Chrome (QUIC)"`) {
		t.Errorf("formatDecision = %q", s)
	}
	d.Label = "curl"
	if s := formatDecision(d); !strings.HasSuffix(s, " client=curl") {
		t.Errorf("formatDecision = %q", s)
	}
}
