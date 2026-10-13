// gk-net blocks YouTube (or other nDPI-detected protocols) on a gokrazy
// router for sources matching an IP address, MAC address or JA4 fingerprint.
//
// The first packets of every forwarded connection are handed to userspace,
// inline via NFQUEUE or as copies via NFLOG, and classified with nDPI. Flows
// that match are dropped and added to an nftables set that rejects the rest
// of the connection. TCP clients are sent a RST and
// UDP (QUIC) clients an ICMP port unreachable, so they fail immediately.
//
// Usage:
//
//	gk-net [flags]                 run on the router
//	gk-net inspect [flags] FILE    classify a pcap file offline
//	gk-net protocols [QUERY...]    search the protocols nDPI can detect
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	_ "time/tzdata" // gokrazy has no zoneinfo files; needed for -timezone

	"github.com/ascension-association/gk-net/internal/blocklog"
	"github.com/ascension-association/gk-net/internal/engine"
	"github.com/ascension-association/gk-net/internal/firewall"
	"github.com/ascension-association/gk-net/internal/ndpi"
	"github.com/ascension-association/gk-net/internal/netpkt"
	"github.com/ascension-association/gk-net/internal/policy"
	"github.com/ascension-association/gk-net/internal/quota"
)

// listFlag collects repeated flag values; comma-separated values are split.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(s string) error {
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			*l = append(*l, v)
		}
	}
	return nil
}

// common holds the flags shared by run and inspect.
type common struct {
	ips, macs, ja4s listFlag
	rulesFile       string
	protos          string
	license         string
	maxPackets      int
	verbose         bool
	allowance       time.Duration
}

func (c *common) register(fs *flag.FlagSet) {
	fs.Var(&c.ips, "ip", "block sources with this IP address or prefix (repeatable)")
	fs.Var(&c.macs, "mac", "block sources with this MAC address (repeatable)")
	fs.Var(&c.ja4s, "ja4", "block sources with this JA4 fingerprint; '*' wildcards allowed (repeatable)")
	fs.StringVar(&c.rulesFile, "rules", "", "file with one rule per line: \"ip|mac|ja4 <value> [user=NAME] [allow=DURATION]\"; reloaded when it changes")
	fs.DurationVar(&c.allowance, "allowance", 0, "daily allowance for rules and users without allow= (0: always blocked)")
	fs.StringVar(&c.protos, "protocols", "YouTube,YouTubeUpload,YouTubeKids", "comma-separated nDPI protocol names, or category:NAME for a whole category, to block (see: gk-net protocols)")
	fs.StringVar(&c.license, "ndpi-license", "not-for-profit", "nDPI license mode: not-for-profit, for-profit-lgpl or for-profit-dual")
	fs.IntVar(&c.maxPackets, "max-packets", 24, "packets per flow to inspect before giving up")
	fs.BoolVar(&c.verbose, "v", false, "log every classified flow, not just blocked ones")
}

func (c *common) policy() (*policy.Policy, error) {
	var b policy.Builder
	if c.allowance < 0 || c.allowance > 24*time.Hour {
		return nil, fmt.Errorf("invalid -allowance %s", c.allowance)
	}
	b.SetDefaultAllowance(c.allowance)
	for _, kv := range []struct {
		kind string
		vals []string
	}{{"ip", c.ips}, {"mac", c.macs}, {"ja4", c.ja4s}} {
		for _, v := range kv.vals {
			if err := b.Add(kv.kind, v); err != nil {
				return nil, err
			}
		}
	}
	if c.rulesFile != "" {
		if err := b.ParseFile(c.rulesFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return b.Policy(), nil
}

func (c *common) module() (*ndpi.Module, []uint16, error) {
	lic, err := ndpi.ParseLicense(c.license)
	if err != nil {
		return nil, nil, err
	}
	mod, err := ndpi.New(lic)
	if err != nil {
		return nil, nil, err
	}
	ids, err := resolveProtocols(mod, c.protos)
	if err != nil {
		mod.Close()
		return nil, nil, err
	}
	if len(ids) == 0 {
		mod.Close()
		return nil, nil, errors.New("no protocols to block")
	}
	return mod, ids, nil
}

func formatDecision(d engine.Decision) string {
	verdict := "allow"
	switch {
	case d.Block:
		verdict = "BLOCK"
	case d.Metered:
		verdict = "METER" // allowed under an allowance
	}
	proto := "udp"
	if d.Tuple.Proto == 6 {
		proto = "tcp"
	}
	s := fmt.Sprintf("%s %s %s -> %s %s", verdict, proto, d.Client, d.Server, d.Class)
	if d.MAC != nil {
		s += " mac=" + d.MAC.String()
	}
	if d.Host != "" {
		s += " host=" + d.Host
	}
	if d.JA4 != "" {
		s += " ja4=" + d.JA4
	}
	if d.Rule != "" {
		s += " rule=" + strings.ReplaceAll(d.Rule, " ", ":")
	}
	if d.User != "" {
		s += " user=" + d.User
	}
	if d.Allowance > 0 {
		s += " allowance=" + fmtDur(d.Allowance)
	}
	return s
}

// fmtDur formats d like "1h30m" or "45m".
func fmtDur(d time.Duration) string {
	s := d.Round(time.Second).String()
	s = strings.TrimSuffix(s, "0s")
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	if s == "" {
		return "0s"
	}
	return s
}

// groupName renders an allowance group for logs: "alice" for a user, or the
// rule for a rule's own allowance.
func groupName(g string) string {
	if u, ok := strings.CutPrefix(g, "user:"); ok {
		return u
	}
	return strings.TrimPrefix(g, "rule:")
}

func main() {
	log.SetFlags(0)
	if len(os.Args) > 1 && os.Args[1] == "protocols" {
		if err := protocols(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "inspect" {
		if err := inspect(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("gk-net", flag.ExitOnError)
	var c common
	c.register(fs)
	var (
		mode         = fs.String("mode", "auto", "how packets reach gk-net: queue (inline, needs CONFIG_NFT_QUEUE), log (passive, needs CONFIG_NETFILTER_NETLINK_LOG) or auto (queue; falls back to log only with -fail-open)")
		failOpen     = fs.Bool("fail-open", false, "let traffic through unfiltered when gk-net is down, overloaded or cannot track a flow (default: fail closed, drop new connections' packets)")
		blockLog     = fs.String("block-log", "", "append blocked flows as JSON lines to this file, e.g. /perm/gk-net/blocks.jsonl")
		blockLogMax  = fs.Int64("block-log-max-size", 10<<20, "rotate the block log to FILE.1 when it exceeds this many bytes (0: no limit)")
		table        = fs.String("table", "gk_net", "nftables table name (family inet)")
		priority     = fs.Int("priority", -10, "forward chain priority")
		queueNum     = fs.Uint("queue-num", 4269, "NFQUEUE numbers used in queue mode (this one and the next)")
		group        = fs.Uint("nflog-group", 4269, "NFLOG group used in log mode")
		blockTimeout = fs.Duration("block-timeout", 10*time.Minute, "how long a blocked connection stays blocked")
		noReset      = fs.Bool("no-reset", false, "do not send TCP RSTs or ICMP errors to blocked clients")
		statePath    = fs.String("state", "", "file where allowance use is kept across restarts, e.g. /perm/gk-net/state.json")
		resetTime    = fs.String("reset-time", "00:00", "local time of day (HH:MM) when daily allowances reset")
		timezone     = fs.String("timezone", "Local", "timezone for -reset-time, e.g. America/Denver (gokrazy's Local is UTC unless TZ is set)")
		activeBytes  = fs.Uint64("active-bytes", 64<<10, "bytes a user's allowed connections must move in a usage interval for it to count as active")
		usageEvery   = fs.Duration("usage-interval", time.Minute, "how often allowance use is measured; each active interval is charged in full")
	)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: gk-net [flags]\n       gk-net inspect [flags] FILE.pcap\n       gk-net protocols [flags] [QUERY...]\n\nflags:\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if *mode != "auto" && *mode != "queue" && *mode != "log" {
		return fmt.Errorf("invalid -mode %q (want auto, queue or log)", *mode)
	}
	if *queueNum > 0xfffe {
		return fmt.Errorf("invalid -queue-num %d", *queueNum)
	}
	loc, err := time.LoadLocation(*timezone)
	if err != nil {
		return fmt.Errorf("invalid -timezone: %w", err)
	}
	resetAt, err := time.Parse("15:04", *resetTime)
	if err != nil {
		return fmt.Errorf("invalid -reset-time %q (want HH:MM)", *resetTime)
	}
	if *usageEvery < time.Second {
		return fmt.Errorf("invalid -usage-interval %s", *usageEvery)
	}

	pol, err := c.policy()
	if err != nil {
		return err
	}
	if pol.Empty() {
		log.Printf("warning: no rules configured; nothing will be blocked")
	}
	var curPol atomic.Pointer[policy.Policy]
	curPol.Store(pol)

	tracker := quota.New(quota.Config{
		Location:    loc,
		ResetAt:     time.Duration(resetAt.Hour())*time.Hour + time.Duration(resetAt.Minute())*time.Minute,
		Interval:    *usageEvery,
		ActiveBytes: *activeBytes,
		StatePath:   *statePath,
	})
	if err := tracker.Load(time.Now()); err != nil {
		log.Printf("loading allowance state: %v (starting fresh)", err)
	}
	defer func() {
		if err := tracker.Save(); err != nil {
			log.Printf("saving allowance state: %v", err)
		}
	}()
	var trackerDirty atomic.Bool
	mod, protos, err := c.module()
	if err != nil {
		return err
	}
	defer mod.Close()

	var blocks *blocklog.Writer
	if *blockLog != "" {
		if blocks, err = blocklog.Open(*blockLog, *blockLogMax); err != nil {
			return fmt.Errorf("opening block log: %w", err)
		}
		defer blocks.Close()
	}

	var inj *firewall.Injector
	if !*noReset {
		if inj, err = firewall.NewInjector(); err != nil {
			return err
		}
		defer inj.Close()
	}

	// fw is set once capture has started; no decisions happen before that.
	var fw *firewall.Firewall
	eng := engine.New(engine.Config{
		Module:     mod,
		Protocols:  protos,
		MaxPackets: c.maxPackets,
		FailClosed: !*failOpen,
		LookupMAC:  lookupARP,
		Admit: func(m policy.Match) bool {
			return tracker.Remaining(m.Group, m.Allowance, time.Now()) > 0
		},
		OnDecision: func(d engine.Decision) {
			if d.Metered {
				if err := fw.Meter(d.Tuple.Proto, d.Client, d.Server); err != nil {
					log.Printf("metering %s -> %s: %v", d.Client, d.Server, err)
				}
				info := quota.Info{Class: d.Class, Host: d.Host, JA4: d.JA4, Rule: d.Rule, User: d.User}
				if d.MAC != nil {
					info.MAC = d.MAC.String()
				}
				tracker.Track(quota.Flow(d.Tuple), d.Group, info)
				trackerDirty.Store(true)
				left := tracker.Remaining(d.Group, d.Allowance, time.Now())
				log.Printf("%s left=%s", formatDecision(d), fmtDur(left))
				return
			}
			if !d.Block {
				// In queue mode, let the rest of the flow skip the queue.
				if err := fw.Allow(d.Tuple.Proto, d.Client, d.Server); err != nil {
					log.Printf("allowing %s -> %s: %v", d.Client, d.Server, err)
				}
				if c.verbose {
					log.Print(formatDecision(d))
				}
				return
			}
			if err := fw.Block(d.Tuple.Proto, d.Client, d.Server); err != nil {
				log.Printf("blocking %s -> %s: %v", d.Client, d.Server, err)
			}
			if inj != nil && d.CanReset {
				if err := inj.Reset(d.Server, d.Client, d.ResetSeq); err != nil {
					log.Printf("resetting %s: %v", d.Client, err)
				}
			}
			if inj != nil && d.Trigger != nil {
				if err := inj.Unreachable(d.Server.Addr(), d.Trigger); err != nil {
					log.Printf("sending ICMP unreachable to %s: %v", d.Client, err)
				}
			}
			log.Print(formatDecision(d))
			if blocks != nil {
				if err := blocks.Write(blockEntry(d, fw.Mode(), time.Now())); err != nil {
					log.Printf("writing block log: %v", err)
				}
			}
		},
	}, pol)
	defer eng.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	opts := firewall.Options{
		Table:        *table,
		Priority:     int32(*priority),
		Queue:        uint16(*queueNum),
		Group:        uint16(*group),
		Packets:      uint64(c.maxPackets) + 8, // both directions count; leave headroom
		BlockTimeout: *blockTimeout,
		AllowTimeout: 5 * time.Minute,
		FailOpen:     *failOpen,
	}
	var capture io.Closer
	if *mode == "log" {
		if !*failOpen {
			log.Printf("warning: log mode is passive and cannot fail closed; traffic is unfiltered while gk-net is down")
		}
		fw, capture, err = startCapture(ctx, firewall.ModeLog, opts, eng)
	} else {
		fw, capture, err = startCapture(ctx, firewall.ModeQueue, opts, eng)
		if err != nil && *mode == "auto" {
			if !*failOpen {
				return fmt.Errorf("queue mode unavailable: %w\n"+
					"Failing closed needs queue mode (CONFIG_NFT_QUEUE). Use -mode=log or -fail-open to run without it.", err)
			}
			log.Printf("queue mode unavailable (%v); falling back to log mode", err)
			fw, capture, err = startCapture(ctx, firewall.ModeLog, opts, eng)
		}
	}
	if err != nil {
		return err
	}
	defer func() {
		// Remove the rules before closing the receivers.
		if err := fw.Close(); err != nil {
			log.Printf("removing nftables table: %v", err)
		}
		capture.Close()
	}()

	mname := "queue (inline)"
	if fw.Mode() == firewall.ModeLog {
		mname = "log (passive)"
	}
	failure := "fail-closed"
	if *failOpen || fw.Mode() == firewall.ModeLog {
		failure = "fail-open"
	}
	log.Printf("gk-net running in %s mode, %s: %s; blocking %s", mname, failure, pol, c.protos)

	// Metered flows from before a restart are still open; keep counting them.
	for _, f := range tracker.Flows() {
		if err := fw.Meter(f.Proto, f.Client, f.Server); err != nil {
			log.Printf("restoring metered flow %s -> %s: %v", f.Client, f.Server, err)
		}
	}
	usageTick := time.NewTicker(*usageEvery)
	defer usageTick.Stop()

	rulesMtime := modTime(c.rulesFile)
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	// Checking is cheap; keep any window without the table (e.g. after
	// another program flushes the ruleset) short.
	ensure := time.NewTicker(time.Second)
	defer ensure.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("shutting down")
			return nil
		case <-ensure.C:
			if reinstalled, err := fw.Ensure(); err != nil {
				log.Printf("checking nftables table: %v", err)
			} else if reinstalled {
				log.Printf("nftables table %q was removed (ruleset flush?); reinstalled", *table)
			}
		case now := <-usageTick.C:
			ms, err := fw.MeterCounters()
			if err != nil {
				log.Printf("reading allowance counters: %v", err)
				continue
			}
			counters := make(map[quota.Flow]uint64, len(ms))
			for _, m := range ms {
				counters[quota.Flow{Proto: m.Proto, Client: m.Client, Server: m.Server}] = m.Bytes
			}
			res := tracker.Tick(now, counters, curPol.Load().Allowance)
			if res.Reset {
				log.Printf("new day: allowances reset")
			}
			if c.verbose {
				for g, used := range res.Charged {
					log.Printf("allowance %s: used %s today", groupName(g), fmtDur(used))
				}
			}
			for g, a := range res.Exhausted {
				log.Printf("allowance %s: %s used up; blocking its connections until %s",
					groupName(g), fmtDur(a), tracker.PeriodStart(now).AddDate(0, 0, 1).Format("Mon 15:04 MST"))
			}
			for _, cut := range res.Cut {
				if err := fw.Block(cut.Proto, cut.Client, cut.Server); err != nil {
					log.Printf("blocking %s -> %s: %v", cut.Client, cut.Server, err)
				}
				if err := fw.Unmeter(cut.Proto, cut.Client, cut.Server); err != nil {
					log.Printf("unmetering %s -> %s: %v", cut.Client, cut.Server, err)
				}
				// End the connection now rather than when the client next sends.
				if inj != nil {
					var err error
					if cut.Proto == 6 {
						err = inj.Nudge(cut.Server, cut.Client)
					} else {
						err = inj.Unreachable(cut.Server.Addr(), netpkt.UDP(cut.Client, cut.Server, nil))
					}
					if err != nil {
						log.Printf("ending %s -> %s: %v", cut.Client, cut.Server, err)
					}
				}
				d := engine.Decision{
					Tuple: engine.Tuple(cut.Flow), Class: cut.Info.Class, Host: cut.Info.Host, JA4: cut.Info.JA4,
					Target: true, Block: true, Rule: cut.Info.Rule, User: cut.Info.User, Group: cut.Group,
				}
				d.MAC, _ = net.ParseMAC(cut.Info.MAC)
				d.Allowance, _ = curPol.Load().Allowance(cut.Group)
				log.Print(formatDecision(d))
				if blocks != nil {
					e := blockEntry(d, fw.Mode(), now)
					e.Reason = "allowance_exhausted"
					if err := blocks.Write(e); err != nil {
						log.Printf("writing block log: %v", err)
					}
				}
			}
			if res.Reset || len(res.Charged) > 0 || len(res.Cut) > 0 || trackerDirty.Swap(false) {
				if err := tracker.Save(); err != nil {
					log.Printf("saving allowance state: %v", err)
				}
			}
		case now := <-tick.C:
			eng.Expire(now)
			if mt := modTime(c.rulesFile); !mt.Equal(rulesMtime) {
				rulesMtime = mt
				if p, err := c.policy(); err != nil {
					log.Printf("reloading rules: %v (keeping previous rules)", err)
				} else {
					eng.SetPolicy(p)
					curPol.Store(p)
					log.Printf("reloaded rules: %s", p)
				}
			}
		}
	}
}

func blockEntry(d engine.Decision, mode firewall.Mode, now time.Time) blocklog.Entry {
	e := blocklog.Entry{
		Time:       now.UTC(),
		Proto:      "udp",
		Client:     d.Client.Addr().String(),
		ClientPort: d.Client.Port(),
		Server:     d.Server.Addr().String(),
		ServerPort: d.Server.Port(),
		Class:      d.Class,
		Host:       d.Host,
		JA4:        d.JA4,
		Mode:       mode.String(),
	}
	if d.Tuple.Proto == 6 {
		e.Proto = "tcp"
	}
	if d.MAC != nil {
		e.MAC = d.MAC.String()
	}
	e.Rule.Type, e.Rule.Value, _ = strings.Cut(d.Rule, " ")
	e.User = d.User
	e.Reason = "rule"
	if d.Allowance > 0 {
		e.Reason = "allowance_exhausted"
		e.Allowance = fmtDur(d.Allowance)
	}
	return e
}

func modTime(path string) time.Time {
	if path == "" {
		return time.Time{}
	}
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}
