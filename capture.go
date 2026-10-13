package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/florianl/go-nflog/v2"
	"github.com/florianl/go-nfqueue/v2"
	"github.com/mdlayher/netlink"

	"github.com/ascension-association/gk-fltr/internal/engine"
	"github.com/ascension-association/gk-fltr/internal/firewall"
)

// listenQueue receives the packets of one conntrack direction from NFQUEUE
// queue num and sets each packet's verdict from the engine.
func listenQueue(ctx context.Context, num uint16, dir engine.Dir, failOpen bool, eng *engine.Engine) (io.Closer, error) {
	// GSO: don't make the kernel segment large packets just to queue them.
	flags := uint32(nfqueue.NfQaCfgFlagGSO)
	if failOpen {
		// Accept packets rather than drop them if gk-fltr falls behind and
		// the queue fills up.
		flags |= nfqueue.NfQaCfgFlagFailOpen
	}
	q, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      num,
		MaxPacketLen: 0xffff,
		MaxQueueLen:  4096,
		Copymode:     nfqueue.NfQnlCopyPacket,
		Flags:        flags,
	})
	if err != nil {
		return nil, fmt.Errorf("opening nfqueue %d: %w", num, err)
	}
	_ = q.SetOption(netlink.NoENOBUFS, true)

	err = q.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		verdict := nfqueue.NfAccept
		if a.Payload != nil {
			p := engine.Packet{Data: *a.Payload, Time: time.Now(), Dir: dir}
			if a.HwAddr != nil {
				p.HwAddr = *a.HwAddr
			}
			if eng.Handle(p) == engine.Drop {
				verdict = nfqueue.NfDrop
			}
		}
		if err := q.SetVerdict(*a.PacketID, verdict); err != nil {
			log.Printf("nfqueue %d: setting verdict: %v", num, err)
		}
		return 0
	}, func(err error) int {
		if ctx.Err() != nil {
			return 1
		}
		log.Printf("nfqueue %d: %v", num, err)
		return 0
	})
	if err != nil {
		q.Close()
		return nil, fmt.Errorf("registering nfqueue %d: %w", num, err)
	}
	return q, nil
}

// listenLog receives copies of packets from NFLOG group and feeds them to
// the engine. The packets themselves have already been accepted.
func listenLog(ctx context.Context, group uint16, eng *engine.Engine) (io.Closer, error) {
	nf, err := nflog.Open(&nflog.Config{
		Group:    group,
		Copymode: nflog.CopyPacket,
		Bufsize:  0xffff,
	})
	if err != nil {
		return nil, fmt.Errorf("opening nflog group %d: %w", group, err)
	}
	// Losing a few packets under load is fine; don't abort on ENOBUFS.
	_ = nf.SetOption(netlink.NoENOBUFS, true)

	err = nf.RegisterWithErrorFunc(ctx, func(a nflog.Attribute) int {
		if a.Payload == nil {
			return 0
		}
		p := engine.Packet{Data: *a.Payload, Time: time.Now()}
		if a.Timestamp != nil {
			p.Time = *a.Timestamp
		}
		if a.Prefix != nil {
			switch *a.Prefix {
			case firewall.PrefixOriginal:
				p.Dir = engine.DirOriginal
			case firewall.PrefixReply:
				p.Dir = engine.DirReply
			}
		}
		if a.HwAddr != nil {
			p.HwAddr = *a.HwAddr
		}
		eng.Handle(p)
		return 0
	}, func(err error) int {
		if ctx.Err() != nil {
			return 1
		}
		log.Printf("nflog: %v", err)
		return 0
	})
	if err != nil {
		nf.Close()
		return nil, fmt.Errorf("registering nflog hook: %w", err)
	}
	return nf, nil
}

type closers []io.Closer

func (cs closers) Close() error {
	for _, c := range cs {
		c.Close()
	}
	return nil
}

// startCapture binds the packet receivers for mode and then installs the
// nftables table that feeds them, so no packet is queued without a reader.
func startCapture(ctx context.Context, mode firewall.Mode, opts firewall.Options, eng *engine.Engine) (*firewall.Firewall, io.Closer, error) {
	var cs closers
	if mode == firewall.ModeQueue {
		for _, q := range []struct {
			num uint16
			dir engine.Dir
		}{{opts.Queue, engine.DirOriginal}, {opts.Queue + 1, engine.DirReply}} {
			c, err := listenQueue(ctx, q.num, q.dir, opts.FailOpen, eng)
			if err != nil {
				cs.Close()
				return nil, nil, err
			}
			cs = append(cs, c)
		}
	} else {
		c, err := listenLog(ctx, opts.Group, eng)
		if err != nil {
			return nil, nil, err
		}
		cs = append(cs, c)
	}
	opts.Mode = mode
	fw, err := firewall.Setup(opts)
	if err != nil {
		cs.Close()
		return nil, nil, err
	}
	return fw, cs, nil
}
