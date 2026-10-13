// Command tlsprobe is a TLS/QUIC test server and client used by
// scripts/netns-test.sh.
//
//	tlsprobe server :443                                 (TLS over TCP and QUIC)
//	tlsprobe client 203.0.113.10:443 www.youtube.com     (TLS over TCP)
//	tlsprobe quic 203.0.113.10:443 www.youtube.com       (QUIC)
//
// The server also streams data endlessly on the next port (e.g. :444), like
// a video. Stream clients read it for at most a duration:
//
//	tlsprobe stream 203.0.113.10:444 www.youtube.com 20s       (TLS over TCP)
//	tlsprobe quic-stream 203.0.113.10:444 www.youtube.com 20s  (QUIC)
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/quic"
)

func main() {
	switch os.Args[1] {
	case "server":
		server(os.Args[2])
	case "client":
		tcpClient(os.Args[2], os.Args[3])
	case "quic":
		quicClient(os.Args[2], os.Args[3])
	case "stream", "quic-stream":
		d, err := time.ParseDuration(os.Args[4])
		if err != nil {
			panic(err)
		}
		if os.Args[1] == "stream" {
			tcpStream(os.Args[2], os.Args[3], d)
		} else {
			quicStream(os.Args[2], os.Args[3], d)
		}
	}
}

func server(addr string) {
	// Never outlive the test that started us.
	time.AfterFunc(2*time.Minute, func() { os.Exit(0) })
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"*"}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"h3"}}

	host, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	go streamServer(net.JoinHostPort(host, strconv.Itoa(p+1)), cfg)

	qe, err := quic.Listen("udp", addr, &quic.Config{TLSConfig: cfg})
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			c, err := qe.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				s, err := c.AcceptStream(context.Background())
				if err != nil {
					return
				}
				io.ReadAll(s)
				io.WriteString(s, "hello "+c.ConnectionState().ServerName+"\n")
				s.Close()
			}()
		}
	}()

	l, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		panic(err)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer c.Close()
			c.(*tls.Conn).Handshake()
			io.WriteString(c, "hello "+c.(*tls.Conn).ConnectionState().ServerName+"\n")
		}()
	}
}

// streamServer writes 32 KiB every 50 ms to every client, over TLS and QUIC.
func streamServer(addr string, cfg *tls.Config) {
	chunk := make([]byte, 32<<10)
	feed := func(w io.Writer) {
		for {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			if f, ok := w.(interface{ Flush() error }); ok {
				f.Flush()
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	qe, err := quic.Listen("udp", addr, &quic.Config{TLSConfig: cfg})
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			c, err := qe.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				s, err := c.AcceptStream(context.Background())
				if err != nil {
					return
				}
				feed(s)
			}()
		}
	}()
	l, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		panic(err)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go func() { defer c.Close(); feed(c) }()
	}
}

func report(sni string, start time.Time, n int64, err error) {
	fmt.Printf("%s: STREAM ended after %v, %d bytes: %v\n", sni, time.Since(start).Round(100*time.Millisecond), n, err)
}

func tcpStream(addr, sni string, max time.Duration) {
	start := time.Now()
	d := &net.Dialer{Timeout: 5 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	if err != nil {
		report(sni, start, 0, err)
		return
	}
	c.SetDeadline(start.Add(max))
	n, err := io.Copy(io.Discard, c)
	report(sni, start, n, err)
}

func quicStream(addr, sni string, max time.Duration) {
	start := time.Now()
	var n atomic.Int64
	ctx, cancel := context.WithTimeout(context.Background(), max)
	defer cancel()
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		report(sni, start, 0, err)
		return
	}
	uc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		report(sni, start, 0, err)
		return
	}
	ep, err := quic.NewEndpoint(connectedUDP{uc, func(err error) { report(sni, start, n.Load(), err); os.Exit(0) }}, nil)
	if err != nil {
		report(sni, start, 0, err)
		return
	}
	c, err := ep.Dial(ctx, "udp", addr, &quic.Config{
		TLSConfig: &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"h3"}},
	})
	if err != nil {
		report(sni, start, 0, err)
		return
	}
	s, err := c.NewStream(ctx)
	if err != nil {
		report(sni, start, 0, err)
		return
	}
	s.SetReadContext(ctx)
	io.WriteString(s, "hi")
	s.Flush()
	buf := make([]byte, 64<<10)
	for {
		k, err := s.Read(buf)
		n.Add(int64(k))
		if err != nil {
			report(sni, start, n.Load(), err)
			return
		}
	}
}

func tcpClient(addr, sni string) {
	start := time.Now()
	d := &net.Dialer{Timeout: 5 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	if err != nil {
		fmt.Printf("%s: FAIL after %v: %v\n", sni, time.Since(start).Round(time.Millisecond), err)
		return
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(c)
	fmt.Printf("%s: OK after %v: %q %v\n", sni, time.Since(start).Round(time.Millisecond), b, err)
}

// connectedUDP adapts a connected UDP socket, as browsers use for QUIC, to
// net.PacketConn. Unlike an unconnected socket it reports ICMP errors,
// which it passes to onErr.
type connectedUDP struct {
	*net.UDPConn
	onErr func(error)
}

func (c connectedUDP) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, err := c.Read(b)
		if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) {
			c.onErr(err)
			continue
		}
		return n, c.RemoteAddr(), err
	}
}

func (c connectedUDP) WriteTo(b []byte, _ net.Addr) (int, error) { return c.Write(b) }

func quicClient(addr, sni string) {
	start := time.Now()
	fail := func(err error) {
		fmt.Printf("%s: FAIL after %v: %v\n", sni, time.Since(start).Round(time.Millisecond), err)
		os.Exit(0)
	}
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fail(err)
	}
	uc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		fail(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ep, err := quic.NewEndpoint(connectedUDP{uc, fail}, nil)
	if err != nil {
		fail(err)
	}
	c, err := ep.Dial(ctx, "udp", addr, &quic.Config{
		TLSConfig: &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"h3"}},
	})
	if err != nil {
		fail(err)
	}
	s, err := c.NewStream(ctx)
	if err != nil {
		fail(err)
	}
	s.SetReadContext(ctx)
	io.WriteString(s, "hi")
	s.CloseWrite()
	b, err := io.ReadAll(s)
	fmt.Printf("%s: OK after %v: %q %v\n", sni, time.Since(start).Round(time.Millisecond), b, err)
}
