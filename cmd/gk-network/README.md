## gk-network

Basic network safety for gokrazy. Uses targeted ARP steering to block malware and enforce family-friendly DNS.

### Usage

```
gok add github.com/ascension-association/gk-network
gok update
```

### Example

```
gk-network
# wait a few minutes for initialization to complete
nslookup bad-example.com
```

### Options

Run `gk-network -help` to list all flags and their defaults.

- `-i`        LAN interface (default `eth0`)
- `-gw`       user-defined IP or `auto` to use the current router's default gateway (default `auto`)
- `-targets`  comma-separated client IPs, or `all` to ARP-scan the subnet and steer every discovered host (self and gateway excluded; default `all`)
- `-dns`       listen address for the safe-search resolver (default `:53`; `""` disables)
- `-upstream`   primary upstream DNS server (default `4.150.168.57`; `:53` assumed)
- `-upstream2`  secondary/failover upstream DNS server (default `104.197.28.121`)
- `-blocklists` comma-separated blocklist URLs (default: OISD Small + OISD NSFW + HaGeZi Anti-Piracy)
- `-block`      comma-separated domains to always sinkhole (adds to built-in defaults)
- `-allow`      comma-separated domains to never sinkhole (allowlist; adds to built-in defaults)
- `-block-nft`  install nftables named sets + forward-path drop rule
- `-block-ips`  comma-separated IPs to seed into the block sets (implies `-block-nft`)
- `-ip-blocklists` CIDR range blocklist URLs, gz ok (default: DoH + malicious-source lists; `none` disables)
- `-block-countries` block forwarded traffic to IP ranges of the [full/partial U.S. entry-suspension countries](https://www.congress.gov/crs-product/IN12631) (default on; `-block-countries=false` disables; uses nftables)
- `-ipv6`       allow IPv6 (disabled by default)
- `-ech`        allow TLS 1.3 Encrypted Client Hello (blocked by default)
- `-block-encrypted-dns` block DoT/DoQ + known DoH endpoints + Tor relay ports 9001/9030 (default on; uses nftables)
- `-block-vpn` block VPNs: WireGuard handshakes on any UDP port, default VPN / mesh protocol ports, VPN provider and tool domains, and commercial VPN server IP ranges (default on; `-block-vpn=false` disables; uses nftables)
- `-redirect-dns` transparently redirect clients' port-53 DNS to this resolver (default on; needs resolver on :53)
- `-refresh`    how often to re-fetch domain + IP blocklists (default `12h`; `0` disables)

### Safe-Search

| Site                         | Answer                        |
|------------------------------|-------------------------------|
| google.com / www.google.<tld> | forcesafesearch.google.com   |
| youtube.com, m./www.youtube.com, youtube*.googleapis.com | restrict.youtube.com |
| bing.com / www.bing.com      | strict.bing.com               |
| duckduckgo.com               | safe.duckduckgo.com           |

### Automatic Refresh

Many of these lists update daily. The appliance re-fetches both layers on an interval (default every `12h`, `-refresh 0` to disable):

- the domain lists are reloaded into a fresh set and swapped in atomically, so the resolver never sees a half-built list
- the CIDR ranges are diffed against what is currently loaded and only the changed entries are added/removed in `cidr_v4`/`cidr_v6` (the drop rules are left untouched)
- an unchanged list does no netlink work at all
- a failed fetch during refresh is logged and the previous list stays in effect

### Additional Security

- Cloudflare Oblivious DoH (ODOH) blocked by default
- Firefox DoH blocked by default
- various Tor elements blocked

### Credits & Thanks

- [FireHOL](https://iplists.firehol.org/)
    - [level1](https://iplists.firehol.org/?ipset=firehol_level1)
        - [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/): blocks botnet C&C servers
        - [SANS Internet Storm Center (dshield)](https://dshield.org/): blocks emerging cyber threats
        - [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/): blocks networks used by professional spam or cyber-crime operations, and used for dissemination of malware, trojan downloaders, botnet controllers, or other kinds of malicious activity
    - [level2](https://iplists.firehol.org/?ipset=firehol_level2)
        - [blocklist.de](https://www.blocklist.de/en/): blocks hackers actively attempting fraud/abuse
        - [GreenSnow](https://greensnow.co/): blocks hackers actively attempting fraud/abuse
    - [dm_tor](https://iplists.firehol.org/?ipset=dm_tor) ([dan.me.uk](https://www.dan.me.uk/tornodes)): blocks Tor relays
    - [et_tor](https://iplists.firehol.org/?ipset=et_tor) ([Emerging Threats](https://rules.emergingthreats.net/)): blocks Tor relays
    - [iblocklist_onion_router](https://iplists.firehol.org/?ipset=iblocklist_onion_router) ([I-Blocklist](https://www.iblocklist.com/)): blocks Tor relays
    - [sslproxies](https://iplists.firehol.org/?ipset=sslproxies) ([SSLProxies](https://www.sslproxies.org/)): blocks open SSL proxies
    - [tor_exits](https://iplists.firehol.org/?ipset=tor_exits) ([Tor Project](https://check.torproject.org/)): blocks Tor exit relays
- [HaGeZi](https://github.com/hagezi/dns-blocklists): blocks piracy sites, encrypted DNS, VPN, Tor, and proxy bypass domains
- [I-Blocklist](https://www.iblocklist.com/list?list=dufcxgnbjsdwmwctgfuj): blocks people who have shared child pornography in the P2P community
- [ipdeny](https://www.ipdeny.com/): provides geo data
- [oisd](https://oisd.nl/): blocks ads, malware, and porn
- [Safe Surfer](https://safesurfer.io): provides family-friendly upstream DNS filtering
- [X4BNet](https://github.com/X4BNet/lists_vpn): blocks VPNs

