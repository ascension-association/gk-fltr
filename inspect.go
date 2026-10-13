package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/ascension-association/gk-fltr/internal/engine"
	"github.com/ascension-association/gk-fltr/internal/policy"
)

// inspect classifies the flows in a pcap file and prints the decision the
// router would make for each, which is handy for finding JA4 fingerprints
// and testing rules.
func inspect(args []string) error {
	fs := flag.NewFlagSet("gk-fltr inspect", flag.ExitOnError)
	var c common
	c.register(fs)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: gk-fltr inspect [flags] FILE.pcap\n\nflags:\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}

	pol, err := c.policy()
	if err != nil {
		return err
	}
	mod, protos, err := c.module()
	if err != nil {
		return err
	}
	defer mod.Close()

	eng := engine.New(engine.Config{
		Module:      mod,
		Protocols:   protos,
		MaxPackets:  c.maxPackets,
		IdleTimeout: 24 * time.Hour,
		MaxFlows:    1 << 20,
		// Usage is not tracked offline: sources with an allowance are shown
		// as METER, i.e. allowed while they have time left.
		Admit: func(policy.Match) bool { return true },
		OnDecision: func(d engine.Decision) {
			if d.Target || c.verbose {
				fmt.Println(formatDecision(d))
			}
		},
	}, pol)
	defer eng.Close()

	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := newPcapReader(f)
	if err != nil {
		return err
	}
	for {
		p, err := r.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if p.Data != nil {
			eng.Handle(p)
		}
	}
	eng.Drain()
	return nil
}

// Link types we can strip to the IP header.
const (
	linkEthernet  = 1
	linkRaw       = 101
	linkLinuxSLL  = 113
	linkIPv4      = 228
	linkIPv6      = 229
	linkLinuxSLL2 = 276
)

type pcapReader struct {
	r        *bufio.Reader
	order    binary.ByteOrder
	nanos    bool
	linkType uint32
	hdr      [16]byte
}

func newPcapReader(r io.Reader) (*pcapReader, error) {
	pr := &pcapReader{r: bufio.NewReaderSize(r, 1<<16)}
	var gh [24]byte
	if _, err := io.ReadFull(pr.r, gh[:]); err != nil {
		return nil, fmt.Errorf("reading pcap header: %w", err)
	}
	switch binary.LittleEndian.Uint32(gh[:4]) {
	case 0xa1b2c3d4:
		pr.order = binary.LittleEndian
	case 0xa1b23c4d:
		pr.order, pr.nanos = binary.LittleEndian, true
	case 0xd4c3b2a1:
		pr.order = binary.BigEndian
	case 0x4d3cb2a1:
		pr.order, pr.nanos = binary.BigEndian, true
	case 0x0a0d0d0a:
		return nil, errors.New("pcapng is not supported; convert with: editcap -F pcap in.pcapng out.pcap")
	default:
		return nil, errors.New("not a pcap file")
	}
	pr.linkType = pr.order.Uint32(gh[20:24]) & 0x0fffffff
	switch pr.linkType {
	case linkEthernet, linkRaw, linkLinuxSLL, linkLinuxSLL2, linkIPv4, linkIPv6:
	default:
		return nil, fmt.Errorf("unsupported pcap link type %d", pr.linkType)
	}
	return pr, nil
}

// next returns the next packet. Packets that are not IP have nil Data.
func (pr *pcapReader) next() (engine.Packet, error) {
	if _, err := io.ReadFull(pr.r, pr.hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			err = io.EOF // truncated capture
		}
		return engine.Packet{}, err
	}
	sec, frac := pr.order.Uint32(pr.hdr[0:4]), pr.order.Uint32(pr.hdr[4:8])
	incl := pr.order.Uint32(pr.hdr[8:12])
	if incl > 1<<18 {
		return engine.Packet{}, fmt.Errorf("pcap record too large (%d bytes)", incl)
	}
	buf := make([]byte, incl)
	if _, err := io.ReadFull(pr.r, buf); err != nil {
		return engine.Packet{}, io.EOF
	}
	if !pr.nanos {
		frac *= 1000
	}
	p := engine.Packet{Time: time.Unix(int64(sec), int64(frac))}

	var etherType uint16
	switch pr.linkType {
	case linkEthernet:
		if len(buf) < 14 {
			return p, nil
		}
		p.HwAddr = net.HardwareAddr(buf[6:12])
		etherType, buf = binary.BigEndian.Uint16(buf[12:14]), buf[14:]
		for (etherType == 0x8100 || etherType == 0x88a8) && len(buf) >= 4 {
			etherType, buf = binary.BigEndian.Uint16(buf[2:4]), buf[4:]
		}
	case linkLinuxSLL:
		if len(buf) < 16 {
			return p, nil
		}
		if binary.BigEndian.Uint16(buf[4:6]) == 6 {
			p.HwAddr = net.HardwareAddr(buf[6:12])
		}
		etherType, buf = binary.BigEndian.Uint16(buf[14:16]), buf[16:]
	case linkLinuxSLL2:
		if len(buf) < 20 {
			return p, nil
		}
		if buf[11] == 6 {
			p.HwAddr = net.HardwareAddr(buf[12:18])
		}
		etherType, buf = binary.BigEndian.Uint16(buf[0:2]), buf[20:]
	}
	if etherType != 0 && etherType != 0x0800 && etherType != 0x86dd {
		return p, nil
	}
	p.Data = buf
	return p, nil
}
