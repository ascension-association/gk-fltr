# Shared setup for the end-to-end tests in unprivileged network namespaces
# (no root needed). Source it from a test script, then call netns_init "$@".
#
#   client (192.168.1.10, MAC 02:00:00:00:00:10) -- router -- server (203.0.113.10)
#
# The server (test/tlsprobe) answers TLS and QUIC on :443 and streams data
# endlessly on :444. gk-net runs in the router namespace, which is the one the
# test script itself runs in.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# netns_init re-executes the calling script inside a new user and network
# namespace, then builds the topology. Afterwards $GK is the gk-net binary,
# "$@" are the remaining arguments, and $WORK is a temporary directory.
# The caller must pass its arguments through: netns_init "$@"; shift $NETNS_SHIFT
netns_init() {
  if [ "${IN_NETNS:-}" != 1 ]; then
    GK="$(realpath "${1:-$ROOT/bin/gk-net-amd64}")"
    [ $# -gt 0 ] && shift
    WORK="$(mktemp -d)"
    trap 'rm -rf "$WORK"' EXIT
    (cd "$ROOT" && CGO_ENABLED=0 go build -o "$WORK/tlsprobe" ./test/tlsprobe)
    IN_NETNS=1 WORK="$WORK" unshare -rn --kill-child "$0" "$GK" "$@"
    exit $?
  fi
  GK="$1"
  NETNS_SHIFT=1
  PROBE="$WORK/tlsprobe"
  cd "$WORK"

  ip link set lo up
  echo 1 > /proc/sys/net/ipv4/ip_forward
  unshare -n sleep 1000 & C=$!
  unshare -n sleep 1000 & SV=$!
  sleep 0.3
  ip link add vc type veth peer name vc0
  ip link set vc0 netns $C
  ip link add vs type veth peer name vs0
  ip link set vs0 netns $SV
  ip addr add 192.168.1.1/24 dev vc && ip link set vc up
  ip addr add 203.0.113.1/24 dev vs && ip link set vs up
  nsenter -t $C -n sh -c 'ip link set lo up; ip link set vc0 address 02:00:00:00:00:10;
    ip addr add 192.168.1.10/24 dev vc0; ip link set vc0 up; ip route add default via 192.168.1.1'
  nsenter -t $SV -n sh -c 'ip link set lo up; ip addr add 203.0.113.10/24 dev vs0;
    ip link set vs0 up; ip route add default via 203.0.113.1'
  nsenter -t $SV -n "$PROBE" server :443 >/dev/null 2>&1 & P=$!
  G=
  fail=0
}

# gk_start starts gk-net with the given flags, logging to gk.log.
gk_start() {
  "$GK" "$@" >> gk.log 2>&1 & G=$!
  sleep 1
  kill -0 $G 2>/dev/null || { echo "gk-net failed to start:"; cat gk.log; netns_cleanup; exit 1; }
}

# gk_stop stops gk-net with the given signal (default TERM).
gk_stop() {
  kill -"${1:-TERM}" $G 2>/dev/null || echo "gk-net exited early"
  wait $G 2>/dev/null || true
}

# probe runs tlsprobe in the client namespace.
probe() { nsenter -t $C -n "$PROBE" "$@"; }

# check MODE SNI WANT: MODE is client (TLS over TCP) or quic; WANT is ok,
# reset, refused (ICMP error) or stall (timeout).
check() {
  out="$(probe "$1" 203.0.113.10:443 "$2")"
  case "$3:$out" in
    ok:*'"hello '*|reset:*'connection reset'*|refused:*'connection refused'*|refused:*'no route to host'*|stall:*timeout*|stall:*deadline*)
      echo "PASS $1 $2 ($3): ${out#*: }" ;;
    *) echo "FAIL $1 $2: want $3, got: $out"; fail=1 ;;
  esac
}

netns_cleanup() {
  pkill -P $P 2>/dev/null || true
  kill $P $C $SV 2>/dev/null || true
}
