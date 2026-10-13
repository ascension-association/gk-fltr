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
- `-blocklists` comma-separated blocklist URLs (default: OISD Small + OISD NSFW)
- `-block`      comma-separated domains to always sinkhole (adds to built-in defaults)
- `-allow`      comma-separated domains to never sinkhole (allowlist; adds to built-in defaults)
- `-block-nft`  install nftables named sets + forward-path drop rule
- `-block-ips`  comma-separated IPs to seed into the block sets (implies `-block-nft`)
- `-ip-blocklists` CIDR range blocklist URLs, gz ok (default: DoH + malicious-source lists; `none` disables)
- `-ipv6`       allow IPv6 (disabled by default)
- `-ech`        allow TLS 1.3 Encrypted Client Hello (blocked by default)
- `-block-encrypted-dns` block DoT/DoQ + known DoH endpoints (default on; uses nftables)
- `-redirect-dns` transparently redirect clients' port-53 DNS to this resolver (default on; needs resolver on :53)
- `-refresh`    how often to re-fetch domain + IP blocklists (default `12h`; `0` disables)

Note: DNS filtering by [Safe Surfer](https://safesurfer.io); content block by [oisd](https://oisd.nl/); malware block by [FireHOL](https://iplists.firehol.org/?ipset=firehol_level1)

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

- IPv6 disabled by default
- TLS 1.3 Encrypted Client Hello blocked by default
- Encrypted DNS (DoH / DoT / DoQ) blocked by default
- Firefox DoH blocked by default
- Brave's built-in Tor blocked by default
- Cloudflare Oblivious DoH (ODOH) blocked by default
