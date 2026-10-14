package filter

import (
	"net/netip"
	"testing"
)

func mustPrefixes(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestBuildIntervalsMerges(t *testing.T) {
	// Overlapping (/24 contains /25), adjacent (two /25s meet), and a /0 that
	// must be skipped.
	// Use public ranges (private ones are intentionally filtered out).
	v4, v6 := buildIntervals(mustPrefixes(
		"1.2.3.0/24", "1.2.3.0/25", // overlap -> one interval
		"1.2.4.0/25", "1.2.4.128/25", // adjacent -> 1.2.4.0/24
		"0.0.0.0/0",     // skipped
		"2001:db8::/48", // v6
	))
	// 1.2.3.0/24 and 1.2.4.0/24 are adjacent too, so all of 1.2.3.0-1.2.4.255
	// collapses to a single interval.
	if len(v4) != 1 {
		t.Errorf("v4 merged to %d intervals, want 1: %v", len(v4), v4)
	}
	if len(v6) != 1 {
		t.Errorf("v6 = %d intervals, want 1", len(v6))
	}
	for _, iv := range v4 {
		s, _ := netip.AddrFromSlice(iv.start)
		e, _ := netip.AddrFromSlice(iv.end)
		if s.String() != "1.2.3.0" || e.String() != "1.2.5.0" {
			t.Errorf("merged v4 = [%s,%s), want [1.2.3.0,1.2.5.0)", s, e)
		}
	}
}

func TestBuildIntervalsSkipsReserved(t *testing.T) {
	// Private/LAN and other reserved ranges (as found in bogon lists) must be
	// dropped so the block set never rejects the LAN itself.
	v4, v6 := buildIntervals(mustPrefixes(
		"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12",
		"169.254.0.0/16", "127.0.0.0/8", "100.64.0.0/10",
		"8.8.8.8/32",    // public, kept
		"fc00::/7",      // ULA, skipped
		"2001:db8::/48", // documentation is not in reserved list, kept
	))
	if len(v4) != 1 {
		t.Errorf("v4 kept %d, want 1 (only 8.8.8.8): %v", len(v4), v4)
	}
	for _, iv := range v4 {
		s, _ := netip.AddrFromSlice(iv.start)
		if s.String() != "8.8.8.8" {
			t.Errorf("v4 kept start %s, want 8.8.8.8", s)
		}
	}
	if len(v6) != 1 {
		t.Errorf("v6 kept %d, want 1 (fc00::/7 skipped)", len(v6))
	}
}

func TestDiffIvals(t *testing.T) {
	cur, _ := buildIntervals(mustPrefixes("1.0.0.0/24", "1.0.4.0/24", "1.0.8.0/24"))
	want, _ := buildIntervals(mustPrefixes("1.0.4.0/24", "1.0.8.0/24", "1.0.12.0/24"))

	add, del := diffIvals(cur, want)
	if len(add) != 1 || len(del) != 1 {
		t.Fatalf("diff = (+%d,-%d), want (1,1)", len(add), len(del))
	}
	for _, v := range add {
		s, _ := netip.AddrFromSlice(v.start)
		if s.String() != "1.0.12.0" {
			t.Errorf("add start = %s, want 1.0.12.0", s)
		}
	}
	for _, v := range del {
		s, _ := netip.AddrFromSlice(v.start)
		if s.String() != "1.0.0.0" {
			t.Errorf("del start = %s, want 1.0.0.0", s)
		}
	}

	// Identical sets => no changes.
	add, del = diffIvals(want, want)
	if len(add) != 0 || len(del) != 0 {
		t.Errorf("identical diff = (+%d,-%d), want (0,0)", len(add), len(del))
	}
}

func TestCIDRStats(t *testing.T) {
	var b IPBlocker
	b.cur4, b.cur6 = buildIntervals([]netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"), // reserved (documentation): skipped
		netip.MustParsePrefix("1.2.3.0/24"),
		netip.MustParsePrefix("1.2.3.128/25"), // inside the /24: merged
		netip.MustParsePrefix("5.6.0.0/16"),
		netip.MustParsePrefix("8.8.8.8/32"),
		netip.MustParsePrefix("2001:db8::/32"),
	})
	r4, r6, a4 := b.CIDRStats()
	if r4 != 3 || r6 != 1 || a4 != 256+65536+1 {
		t.Errorf("CIDRStats = %d, %d, %d; want 3, 1, %d", r4, r6, a4, 256+65536+1)
	}
}
