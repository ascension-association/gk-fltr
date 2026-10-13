#!/bin/sh
# End-to-end test in unprivileged network namespaces (no root needed); see
# scripts/netns-lib.sh for the topology.
#
# The client opens TLS-over-TCP and QUIC connections with various SNIs. The
# YouTube ones must fail at once (TCP reset / ICMP port unreachable) and the
# others must succeed. Every block must appear in the JSON block log. Finally
# gk-net is killed with SIGKILL: new connections must then stall (fail closed)
# or, with -fail-open or -mode=log, pass (fail open).
#
# usage: scripts/netns-test.sh [bin/gk-net-amd64] [gk-net flags...]
#        (default flags: -ip 192.168.1.10)
# Set NFT_DUMP=1 to print gk-net's nftables table at the end.
set -eu
. "$(dirname "$0")/netns-lib.sh"
netns_init "$@"
shift $NETNS_SHIFT
[ $# -eq 0 ] && set -- -ip 192.168.1.10

gk_start -block-log "$WORK/blocks.jsonl" "$@"

for sni in www.example.com en.wikipedia.org; do
  check client $sni ok
  check quic $sni ok
done
for sni in www.youtube.com rr1---sn-abc.googlevideo.com; do
  check client $sni reset    # TCP: RST from gk-net
  check quic $sni refused    # QUIC: ICMP unreachable from gk-net or the reject rule
done
[ -n "${NFT_DUMP:-}" ] && nft list table inet gk_net

n=$(grep -c '"rule":{"type":' blocks.jsonl 2>/dev/null || true)
if [ "$n" = 4 ]; then echo "PASS block log has 4 entries"; else echo "FAIL block log has ${n:-0} entries, want 4"; fail=1; fi
head -1 blocks.jsonl 2>/dev/null || true

want=stall
case " $* " in *" -fail-open "*|*" -fail-open=true "*|*" -mode log "*|*" -mode=log "*) want=ok ;; esac
gk_stop KILL
echo "gk-net killed with SIGKILL; want new connections to $want"
check client www.example.com $want
check quic www.example.com $want

netns_cleanup
echo "--- gk-net log"; cat gk.log
exit $fail
