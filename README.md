# gk-net

gk-net is a single static binary for a [gokrazy](https://gokrazy.org/) router.
It uses [nDPI](https://github.com/ntop/nDPI) to block YouTube for chosen
sources. A source can be matched by any of the following:

- **IP address or prefix**, such as `192.168.1.23` or `192.168.1.0/28`
- **MAC address**, such as `aa:bb:cc:dd:ee:ff`
- **JA4 client fingerprint**, such as `t13d1516h2_8daaf6152771_02713d6af862`.
  Patterns can use `*`, for example `t13d*_8daaf6152771_*`.

YouTube is the default, but gk-net can block anything nDPI detects, such as
Instagram, Facebook or TikTok, or whole categories like social networks. See
[Choosing what to block](#choosing-what-to-block).

Sources can also get a **daily allowance**, for example 2 hours of YouTube per
day, measured in active minutes and shared by a user's devices. See
[Daily allowances](#daily-allowances).

## How it works

1. gk-net installs its own nftables table, `inet gk_net`. The table has one
   forward chain at priority -10. Other tables are left alone.
2. The chain hands the first ~32 packets of each forwarded connection to gk-net.
   It uses the `ct packets` and `ct direction` expressions. This happens in one
   of two modes:
   - **Queue (inline)**: the packets are held in **NFQUEUE** until gk-net
     decides. The packet that identifies YouTube, such as the TLS ClientHello
     or QUIC Initial, is dropped, so nothing from a blocked connection reaches
     the server. Once a connection is allowed, it goes into an allow set, and
     its remaining packets skip the queue. Needs `CONFIG_NFT_QUEUE`.
   - **Log (passive)**: copies of the packets go to gk-net over **NFLOG**,
     and the packets themselves pass immediately. The block lands right behind
     the packet that identified YouTube, so that one packet (usually the
     ClientHello) still reaches the server. Needs
     `CONFIG_NETFILTER_NETLINK_LOG`.

   `-mode=auto` (the default) uses queue mode. It falls back to log mode only
   with `-fail-open`, because log mode cannot fail closed (see below).
3. gk-net feeds those packets to nDPI. This step identifies YouTube from the
   TLS/QUIC SNI or the HTTP host, and computes the client's JA4 fingerprint.
   The client's MAC address comes from the packet's link-layer header, or from
   `/proc/net/arp` if the header is missing.
4. Suppose a flow is YouTube (`YouTube`, `YouTubeUpload` or `YouTubeKids`) and
   its source matches a rule. gk-net then adds the flow's 5-tuple to an
   nftables set that has a timeout.
5. After that, the chain rejects every packet of the flow in the kernel. It
   sends a TCP RST for TCP and an ICMP admin-prohibited message for QUIC.
   gk-net also tells the client right away, so the connection fails at once
   instead of hanging:
   - for TCP, a RST built from the client's own ACK number
   - for QUIC, an ICMP port unreachable that quotes the client's Initial
     packet. On the connected UDP sockets that browsers use for QUIC, this
     becomes an immediate `ECONNREFUSED`. The browser then falls back to TCP,
     which is blocked as well.

Blocking is decided per connection, so other Google services on the same server
IPs keep working.

### Failing closed (default) or open

By default gk-net **fails closed**. If it crashes or hangs, its queue rules
stay installed with no one listening. If it falls behind until the queue
fills, or cannot track a new flow, the packets are dropped instead of passing
unfiltered. Already-established connections keep working, but new connections
stall until gk-net is back. On gokrazy, gk-net is restarted automatically, and
a restarted gk-net takes over the leftover rules. Stopping gk-net on purpose
(SIGTERM, such as stopping it from the gokrazy web interface) removes its table
and restores normal traffic.

With `-fail-open`, the queue rules use `bypass` and the queue is opened in
fail-open mode, so traffic passes unfiltered while gk-net is down or
overloaded.

Log mode only sees copies of packets, so it always fails open. gk-net warns
about this when started with `-mode=log`, and without `-fail-open`,
`-mode=auto` refuses to start rather than fall back to it.

### Kernel requirements

All of these must be built in (`=y`): `NF_TABLES_INET`, `NFT_CT`,
`NFT_REJECT_INET`, `NF_CONNTRACK`, and at least one of the following:

- `NFT_QUEUE` and `NETFILTER_NETLINK_QUEUE`, for queue mode
- `NETFILTER_NETLINK_LOG` and `NFT_LOG`, for log mode

The stock gokrazy kernels support log mode only, so they need `-mode=log` (or
`-fail-open`). [kernel.q6a](https://github.com/ascension-association/kernel.q6a),
for the Radxa Dragon Q6A, supports both modes, so gk-net runs inline and fails
closed there.

### QUIC

QUIC is handled like TCP. nDPI decrypts the QUIC Initial packets (their keys
are public, derived from the connection ID) and reads the SNI and JA4
fingerprint from the ClientHello. This works even when the ClientHello spans
several Initial packets, as it does with the post-quantum key shares that
current browsers send. QUIC JA4 fingerprints start with `q`, for example
`q13d0313h3_55b375c5d22e_4156cdf64688`, while TLS-over-TCP ones start with `t`.
A JA4 rule therefore matches only one transport unless you use a wildcard
such as `*_55b375c5d22e_*`.

## Building

You need Go, [zig](https://ziglang.org/download/) (0.16 is tested), which is the
C cross compiler, and autotools (`autoconf automake libtool pkg-config make`).

```sh
make ndpi   # downloads nDPI 6.0 and builds a static libndpi.a for amd64 and arm64
make        # builds bin/gk-net-amd64 and bin/gk-net-arm64 (fully static, about 5 MB)
make test
```

To build for one architecture only, run `make ndpi ARCHS=arm64` and
`make ARCHS=arm64`.

`scripts/netns-test.sh` runs an end-to-end test without root. It uses
unprivileged network namespaces to build client, router and server
namespaces, runs gk-net with real nftables and NFQUEUE or NFLOG, and checks
the following:
- TLS-over-TCP and QUIC connections to YouTube hostnames fail immediately,
  while other connections succeed.
- Every block is written to the JSON block log.
- After `kill -9`, new connections stall (fail closed) or pass (fail open).

Pass gk-net flags after the binary to choose the configuration:

```sh
scripts/netns-test.sh bin/gk-net-amd64 -ip 192.168.1.10              # queue, fail closed
scripts/netns-test.sh bin/gk-net-amd64 -ip 192.168.1.10 -fail-open
scripts/netns-test.sh bin/gk-net-amd64 -mode log -ip 192.168.1.10
```

`scripts/netns-allowance-test.sh` tests daily allowances the same way: a 4
second allowance, measured every second, cuts off TCP and QUIC streams, and the
use survives a restart.

## Deploying on gokrazy

gokrazy has no C runtime, so the binary must be fully statically linked, with
cgo pointed at zig. The nDPI libraries are built locally, so add gk-net from a
local checkout rather than by module path:

```sh
git clone https://github.com/ascension-association/gk-net
cd gk-net && make ndpi ARCHS=arm64      # or amd64
gok -i router add .
```

Then add the following to `~/gokrazy/router/config.json`. The `-target` must
match your device: `aarch64-linux-musl` for the Dragon Q6A, a Raspberry Pi or
another arm64 device, and `x86_64-linux-musl` for a PC.

```json
"PackageConfig": {
    "github.com/ascension-association/gk-net": {
        "GoBuildEnvironment": [
            "CGO_ENABLED=1",
            "CC=zig cc -target aarch64-linux-musl"
        ],
        "GoBuildFlags": [
            "-ldflags=-s -w -linkmode=external '-extldflags=-static -s'"
        ],
        "CommandLineFlags": [
            "-rules=/perm/gk-net/rules.txt",
            "-block-log=/perm/gk-net/blocks.jsonl",
            "-state=/perm/gk-net/state.json",
            "-timezone=America/Denver"
        ]
    }
}
```

`zig` must be on your `PATH` when you run `gok update`.

Rules can go in `CommandLineFlags`, for example `"-ip=192.168.1.0/28"` or
`"-mac=aa:bb:cc:dd:ee:ff"`. They can also go in a rules file on the permanent
partition. gk-net checks the rules file every 15 seconds and reloads it when it
changes, so you can edit it over breakglass without redeploying:

```
# /perm/gk-net/rules.txt
# <ip|mac|ja4> <value> [user=NAME] [allow=DURATION]
mac aa:bb:cc:dd:ee:01 user=alice allow=2h   # Alice's phone
ip  192.168.1.23      user=alice            # Alice's laptop: shares her 2h
mac aa:bb:cc:dd:ee:02 user=bob   allow=1h   # Bob's tablet
ip  192.168.1.0/28                          # kids' VLAN: always blocked
ja4 t13d1516h2_8daaf6152771_*               # a smart TV app: always blocked
```

The first rule that matches a source applies, so put more specific rules
(single devices) before broader ones (subnets).

gk-net logs to stdout, which shows up in the gokrazy web interface. At startup it
logs which mode it runs in, for example
`gk-net running in queue (inline) mode`. If queue mode was unavailable, it also
logs why it fell back. Each blocked flow is logged like this:

```
BLOCK tcp 192.168.1.10:49020 -> 142.250.1.1:443 TLS.YouTube mac=02:00:00:00:00:10 host=www.youtube.com ja4=t13d1516h2_8daaf6152771_02713d6af862 rule=ip:192.168.1.0/28
```

### Block log

With `-block-log=PATH`, gk-net also appends each blocked flow to `PATH` as one
JSON object per line (JSON Lines). gk-net creates the file, and its directory,
if needed:

```json
{"time":"2026-10-12T22:19:17.702995018Z","proto":"tcp","client":"192.168.1.10","client_port":35338,"server":"142.250.1.1","server_port":443,"mac":"02:00:00:00:00:10","class":"TLS.YouTube","host":"www.youtube.com","ja4":"t13d1516h2_8daaf6152771_02713d6af862","rule":{"type":"ip","value":"192.168.1.0/28"},"mode":"queue"}
```

`time` is in UTC. `mac`, `host` and `ja4` are left out when unknown. `rule`
is the rule that matched. When the file would exceed `-block-log-max-size`
(10 MiB by default), it is renamed to `PATH.1`, replacing any older one, and a
new file is started. This bounds the space it uses on `/perm` to about twice
that size. Only blocks are logged; use `-v` to see every classified flow in the
regular log.

### Daily allowances

A rule with `allow=DURATION` (at most `24h`) lets its sources use YouTube for
that long each day instead of blocking it outright:

- **Users.** Rules with the same `user=NAME` share one allowance, so a user
  can have several devices, identified by IP or MAC. A user's allowance is set
  with `allow=` on any of their rules (if it is set more than once, the values
  must agree). A rule with `allow=` but no user has an allowance of its own.
  `-allowance=DURATION` sets the allowance of rules and users that have no
  `allow=`. The default is 0, which means always blocked.
- **Active minutes.** Only time spent actually using YouTube counts. gk-net
  admits a user's YouTube connections while they have time left, and counts
  each connection's bytes with nftables per-element counters. Every minute
  (`-usage-interval`) in which a user's YouTube connections moved at least
  64 KiB (`-active-bytes`) is charged as one minute. Video playback moves
  megabytes per minute. A paused video or an idle background tab only sends
  keepalives, so it isn't charged. A user watching on two devices at once is
  charged once per minute, not twice.
- **Running out.** When a user's time is used up, gk-net blocks their open
  YouTube connections, which then end immediately. TCP connections are reset;
  QUIC connections get an ICMP error. New YouTube connections are blocked until
  the reset. These blocks are written to the block log with
  `"reason":"allowance_exhausted"`.
- **Daily reset.** Allowances reset at `-reset-time` (default `00:00`) in
  `-timezone`. On gokrazy the local timezone is UTC unless set, so set
  `-timezone`, for example `-timezone=America/Denver`. The timezone database
  is built into the binary.
- **Persistence.** With `-state=PATH`, gk-net keeps each user's use for the
  day, and the connections it is metering, in a JSON file. A restart doesn't
  reset anyone's time, and connections metered before the restart keep being
  counted.

The log shows metered connections and how much time is left:

```
METER tcp 192.168.1.10:55590 -> 142.250.1.1:443 TLS.YouTube mac=aa:bb:cc:dd:ee:01 host=www.youtube.com ... rule=mac:aa:bb:cc:dd:ee:01 user=alice allowance=2h left=1h12m
allowance alice: 2h used up; blocking its connections until Tue 00:00 MDT
```

With `-v`, gk-net also logs each minute charged. `state.json` shows the use so
far today, in seconds, under `used_seconds`.

The accuracy is one usage interval. The interval in which a connection starts
is charged in full, so someone may get up to a minute less than the full
allowance. Changes to the rules file apply within 15 seconds. If you lower an
allowance below what a user has already used, or remove it, their open YouTube
connections are cut at the next usage interval.

### If the nftables ruleset is flushed

If another program flushes the whole nftables ruleset (for example
`nft flush ruleset`), gk-net's table goes with it. gk-net checks for its
table every second and reinstalls it if it is missing, including its blocked
and metered connections. Filtering pauses during that window, and traffic
passes unfiltered then even when failing closed, because the rules themselves
are gone.

## Choosing what to block

`-protocols` takes a comma-separated list of nDPI protocol names, and
`category:NAME` for every protocol in a category. The default is
`YouTube,YouTubeUpload,YouTubeKids`. Names are case-insensitive. Use the
`protocols` subcommand to find names:

```
$ gk-net protocols insta face
NAME               CATEGORY       BREED
Facebook           SocialNetwork  Fun
FacebookMessenger  Chat           Acceptable
FacebookVoip       VoIP           Acceptable
Instagram          SocialNetwork  Fun
```

The subcommand matches each query against protocol names and categories.
Related options:

- `gk-net protocols -category SocialNetwork` lists one category.
- `gk-net protocols -categories` lists all categories with their protocol
  counts.
- `gk-net protocols` with no query lists everything, about 490 protocols.

For example:

```
-protocols=YouTube,YouTubeUpload,YouTubeKids,Instagram,Facebook,FbookReelStory,TikTok
-protocols=YouTube,YouTubeUpload,YouTubeKids,category:SocialNetwork
```

Check a category's members before blocking all of it. `Video`, for
example, includes Zoom, and YouTube itself is in `Media`.

A service often appears as several protocols. Facebook's reels and stories
are listed as `FbookReelStory`, for example, and YouTube Kids as `YouTubeKids`,
so search before relying on a single name. Rules, allowances and the block log
cover all listed protocols together: an `allow=2h` allowance is 2 hours of
any of them combined. The run and `inspect` commands report an unknown name or
category at startup.

## Finding JA4 fingerprints

- Run gk-net with `-v`. It then logs every classified flow with its MAC, host
  and JA4, not just the blocked ones.
- Or capture traffic on any Linux machine and classify the capture offline,
  using the same flags as on the router:

  ```sh
  tcpdump -i eth0 -w capture.pcap
  ./bin/gk-net-amd64 inspect -v -ja4 't13d1516h2_*' capture.pcap
  ```

  `inspect` reads classic pcap files (Ethernet, raw IP, Linux SLL/SLL2). It
  does not read pcapng; convert with `editcap -F pcap in.pcapng out.pcap`.

A JA4 fingerprint identifies the **client software**, not the device: all
current Chrome browsers share one fingerprint. JA4 rules work best for apps
with a distinctive TLS stack, such as a smart TV's YouTube app.

## Flags

| Flag | Default | Description |
|---|---|---|
| `-ip`, `-mac`, `-ja4` | | Rules; repeatable or comma-separated |
| `-rules` | | Rules file; reloaded when it changes |
| `-allowance` | `0` | Daily allowance for rules and users without `allow=`; 0 means always blocked |
| `-state` | | File where allowance use is kept across restarts |
| `-reset-time`, `-timezone` | `00:00`, `Local` | When daily allowances reset |
| `-usage-interval` | `1m` | How often use is measured; each active interval is charged in full |
| `-active-bytes` | `65536` | Bytes per interval for YouTube use to count as active |
| `-protocols` | `YouTube,YouTubeUpload,YouTubeKids` | nDPI protocol names, or `category:NAME`, to block; see `gk-net protocols` |
| `-block-timeout` | `10m` | How long a blocked connection stays in the set |
| `-max-packets` | `24` | Packets per flow to classify before giving up |
| `-mode` | `auto` | `queue` (inline), `log` (passive) or `auto` (queue; log only with `-fail-open`) |
| `-fail-open` | `false` | Let traffic through unfiltered when gk-net is down or overloaded |
| `-block-log` | | Append blocked flows as JSON lines to this file |
| `-block-log-max-size` | `10485760` | Rotate the block log to `FILE.1` beyond this many bytes; 0 for no limit |
| `-no-reset` | `false` | Don't send TCP RSTs or ICMP errors to blocked clients |
| `-queue-num` | `4269` | NFQUEUE numbers in queue mode; this one and the next are used |
| `-nflog-group` | `4269` | NFLOG group in log mode |
| `-table`, `-priority` | `gk_net`, `-10` | nftables table name and forward chain priority |
| `-ndpi-license` | `not-for-profit` | nDPI 6 license mode; see below |
| `-v` | `false` | Log every classified flow |

## Limitations

- **Only forwarded traffic is seen.** This covers LAN-to-internet traffic. It
  does not cover devices on the same L2 segment or the router's own traffic.
- **MAC matching** works only for clients directly attached to one of the
  router's L2 segments. Phones may use a randomized MAC per network.
- **Encrypted Client Hello (ECH)**: if YouTube starts accepting ECH, the SNI
  would be hidden and detection would rely on nDPI's other heuristics. VPNs and
  proxies also bypass gk-net.
- **QUIC connection migration**: a QUIC connection that changes address after
  its handshake has no ClientHello for nDPI to see. Blocked connections never
  finish the handshake, so this only matters if gk-net was not running when the
  connection was set up.

## Licensing

gk-net is BSD-3-Clause. It statically links nDPI, which is LGPLv3, with some
dissectors dual-licensed from nDPI 6.0 on (see nDPI's `README.license.md`).
`-ndpi-license` selects which dissectors are enabled:

- `not-for-profit`: all dissectors; for non-commercial use
- `for-profit-lgpl`: LGPL dissectors only
- `for-profit-dual`: all dissectors; requires a commercial license from ntop

Because this repository includes the build scripts, anyone can relink the
binary against a modified nDPI.
