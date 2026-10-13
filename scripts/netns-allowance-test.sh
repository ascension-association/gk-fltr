#!/bin/sh
# End-to-end test of daily allowances in unprivileged network namespaces (no
# root needed); see scripts/netns-lib.sh for the topology.
#
# The client (user "kid", identified by MAC) gets a 4 s allowance, measured
# in 1 s intervals. A YouTube stream must run, be cut off once the allowance
# is used up, and new YouTube connections must then be blocked, also after
# gk-fltr restarts (the use is persisted). Other sites keep working.
#
# usage: scripts/netns-allowance-test.sh [bin/gk-fltr-amd64] [gk-fltr flags...]
#        e.g. -mode log
set -eu
. "$(dirname "$0")/netns-lib.sh"
netns_init "$@"
shift $NETNS_SHIFT

cat > rules.txt <<'EOF'
mac 02:00:00:00:00:10 user=kid allow=4s
EOF
flags="-rules rules.txt -state state.json -block-log blocks.jsonl -usage-interval 1s -active-bytes 10000 -v"

# stream KIND WANT_MIN WANT_MAX: stream YouTube for up to 20 s; it must be cut
# off (reset / ICMP error) after between WANT_MIN and WANT_MAX seconds.
stream() {
  out="$(probe "$1" 203.0.113.10:444 www.youtube.com 20s)"
  secs=$(echo "$out" | sed -n 's/.*ended after \([0-9.]*\)s.*/\1/p')
  case "$out" in
    *'connection reset'*|*'connection refused'*|*'no route to host'*)
      if awk "BEGIN{exit !($secs >= $2 && $secs <= $3)}"; then
        echo "PASS $1 cut off after ${secs}s: ${out#*: }"; return
      fi ;;
  esac
  echo "FAIL $1: want cut off after $2-$3 s, got: $out"; fail=1
}

gk_start $flags "$@"
check client www.example.com ok
stream stream 3 8            # TCP: uses up the 4 s allowance
check client www.youtube.com reset
check quic www.youtube.com refused
check client www.example.com ok

used=$(sed -n 's/.*"user:kid": \([0-9]*\).*/\1/p' state.json)
if [ "${used:-0}" -ge 4 ]; then echo "PASS state.json: kid used ${used}s"; else echo "FAIL state.json: kid used ${used:-?}s, want >= 4"; fail=1; fi
n=$(grep -c '"reason":"allowance_exhausted"' blocks.jsonl || true)
if [ "$n" -ge 3 ]; then echo "PASS block log: $n allowance_exhausted entries"; else echo "FAIL block log: $n allowance_exhausted entries, want >= 3"; fail=1; fi

echo "restarting gk-fltr"
gk_stop TERM
gk_start $flags "$@"
check client www.youtube.com reset    # still used up after the restart
gk_stop TERM

echo "new day: fresh state, QUIC stream"
rm -f state.json
gk_start $flags "$@"
stream quic-stream 3 8       # QUIC: uses up the allowance again
check quic www.youtube.com refused
gk_stop TERM

netns_cleanup
echo "--- gk-fltr log"; cat gk.log
exit $fail
