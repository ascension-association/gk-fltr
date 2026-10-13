package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/ascension-association/gk-fltr/internal/netpkt"
)

func writePcap(t *testing.T, frames ...[]byte) string {
	t.Helper()
	var b bytes.Buffer
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:], 2)
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[16:], 65535)
	binary.LittleEndian.PutUint32(hdr[20:], linkEthernet)
	b.Write(hdr)
	for i, f := range frames {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:], 1700000000)
		binary.LittleEndian.PutUint32(rec[4:], uint32(i))
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(f)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(f)))
		b.Write(rec)
		b.Write(f)
	}
	path := filepath.Join(t.TempDir(), "test.pcap")
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func ether(src []byte, ip []byte) []byte {
	f := append(make([]byte, 6), src...)
	f = binary.BigEndian.AppendUint16(f, 0x0800)
	return append(f, ip...)
}

func TestPcapReader(t *testing.T) {
	mac := []byte{2, 0, 0, 0, 0, 0x10}
	c := netip.MustParseAddrPort("192.168.1.10:40000")
	s := netip.MustParseAddrPort("203.0.113.10:443")
	syn := netpkt.TCP(c, s, 1, 0, netpkt.SYN, nil)
	arp := append(make([]byte, 12), 0x08, 0x06, 0, 1)

	f, err := os.Open(writePcap(t, ether(mac, syn), arp))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := newPcapReader(f)
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.next()
	if err != nil || !bytes.Equal(p.Data, syn) || !bytes.Equal(p.HwAddr, mac) {
		t.Fatalf("first packet = %+v, %v", p, err)
	}
	if p, err := r.next(); err != nil || p.Data != nil {
		t.Fatalf("ARP frame: got %+v, %v; want nil Data", p, err)
	}
	if _, err := r.next(); err != io.EOF {
		t.Fatalf("got %v, want EOF", err)
	}
}
