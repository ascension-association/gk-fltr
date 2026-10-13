package quota

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"
	_ "time/tzdata"
)

var (
	denver, _   = time.LoadLocation("America/Denver")
	alicePhone  = Flow{6, netip.MustParseAddrPort("192.168.1.10:50000"), netip.MustParseAddrPort("142.250.1.1:443")}
	aliceLaptop = Flow{17, netip.MustParseAddrPort("192.168.1.11:50001"), netip.MustParseAddrPort("142.250.1.2:443")}
	bobTablet   = Flow{6, netip.MustParseAddrPort("192.168.1.12:50002"), netip.MustParseAddrPort("142.250.1.1:443")}
)

func allowances(m map[string]time.Duration) func(string) (time.Duration, bool) {
	return func(g string) (time.Duration, bool) { a, ok := m[g]; return a, ok }
}

func TestPeriodStart(t *testing.T) {
	tr := New(Config{Location: denver, ResetAt: 4 * time.Hour})
	for _, tc := range []struct{ now, want string }{
		{"2026-10-12T10:00:00-06:00", "2026-10-12T04:00:00-06:00"},
		{"2026-10-12T03:59:00-06:00", "2026-10-11T04:00:00-06:00"},
		{"2026-10-12T04:00:00-06:00", "2026-10-12T04:00:00-06:00"},
		// DST ends 2026-11-01 at 02:00 MDT; the reset stays at 04:00 local.
		{"2026-11-01T12:00:00-07:00", "2026-11-01T04:00:00-07:00"},
	} {
		now, _ := time.Parse(time.RFC3339, tc.now)
		want, _ := time.Parse(time.RFC3339, tc.want)
		if got := tr.PeriodStart(now); !got.Equal(want) {
			t.Errorf("PeriodStart(%s) = %s, want %s", tc.now, got, want)
		}
	}
}

func TestChargeAndCut(t *testing.T) {
	tr := New(Config{Location: denver, Interval: time.Minute, ActiveBytes: 1000})
	allow := allowances(map[string]time.Duration{"user:alice": 3 * time.Minute, "user:bob": time.Hour})
	now := time.Date(2026, 10, 12, 15, 0, 0, 0, denver)

	tr.Track(alicePhone, "user:alice", Info{Host: "www.youtube.com"})
	tr.Track(aliceLaptop, "user:alice", Info{})
	tr.Track(bobTablet, "user:bob", Info{})

	tick := func(c map[Flow]uint64) TickResult {
		now = now.Add(time.Minute)
		return tr.Tick(now, c, allow)
	}
	// Minute 1: both of alice's devices active; one minute charged (not two).
	r := tick(map[Flow]uint64{alicePhone: 600, aliceLaptop: 600, bobTablet: 10})
	if r.Charged["user:alice"] != time.Minute || len(r.Charged) != 1 {
		t.Fatalf("minute 1 charged %v, want alice 1m only (bob below threshold)", r.Charged)
	}
	// Minute 2: idle (keepalives only).
	r = tick(map[Flow]uint64{alicePhone: 700, aliceLaptop: 700, bobTablet: 20})
	if len(r.Charged) != 0 {
		t.Fatalf("minute 2 charged %v, want nothing", r.Charged)
	}
	if got := tr.Remaining("user:alice", 3*time.Minute, now); got != 2*time.Minute {
		t.Fatalf("remaining = %v, want 2m", got)
	}
	// Minutes 3-4: active; alice runs out after minute 4. The laptop flow
	// has ended (missing from counters) and is forgotten.
	tick(map[Flow]uint64{alicePhone: 5000, bobTablet: 30})
	r = tick(map[Flow]uint64{alicePhone: 9000, bobTablet: 40})
	if len(r.Cut) != 1 || r.Cut[0].Flow != alicePhone || r.Cut[0].Info.Host != "www.youtube.com" || r.Exhausted["user:alice"] != 3*time.Minute {
		t.Fatalf("minute 4: cut %+v exhausted %v, want alice's phone", r.Cut, r.Exhausted)
	}
	if got := tr.Remaining("user:alice", 3*time.Minute, now); got != 0 {
		t.Fatalf("remaining after cut = %v, want 0", got)
	}

	// Next day after midnight: reset.
	now = time.Date(2026, 10, 13, 0, 0, 30, 0, denver)
	r = tr.Tick(now, map[Flow]uint64{bobTablet: 50}, allow)
	if !r.Reset || tr.Used("user:alice", now) != 0 {
		t.Errorf("after midnight: reset %v, alice used %v; want reset and 0", r.Reset, tr.Used("user:alice", now))
	}
}

func TestRemovedGroupAndShrunkAllowance(t *testing.T) {
	tr := New(Config{Interval: time.Minute, ActiveBytes: 1})
	now := time.Now()
	tr.Track(alicePhone, "user:alice", Info{})
	tr.Track(bobTablet, "user:bob", Info{})
	// alice's rule was deleted: forget her flow. bob's allowance was removed
	// (now always blocked): cut his.
	r := tr.Tick(now, map[Flow]uint64{alicePhone: 1, bobTablet: 1}, allowances(map[string]time.Duration{"user:bob": 0}))
	if len(r.Cut) != 1 || r.Cut[0].Flow != bobTablet || len(tr.Flows()) != 0 {
		t.Fatalf("cut %+v, flows left %v; want bob cut, nothing tracked", r.Cut, tr.Flows())
	}
}

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	now := time.Date(2026, 10, 12, 15, 0, 0, 0, denver)
	cfg := Config{Location: denver, Interval: time.Minute, ActiveBytes: 1, StatePath: path}

	tr := New(cfg)
	tr.Track(alicePhone, "user:alice", Info{Host: "www.youtube.com"})
	tr.Tick(now, map[Flow]uint64{alicePhone: 100}, allowances(map[string]time.Duration{"user:alice": time.Hour}))
	if err := tr.Save(); err != nil {
		t.Fatal(err)
	}

	// Same day: use and flows are restored.
	tr2 := New(cfg)
	if err := tr2.Load(now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := tr2.Used("user:alice", now.Add(time.Hour)); got != time.Minute {
		t.Errorf("same day: used = %v, want 1m", got)
	}
	if fs := tr2.Flows(); len(fs) != 1 || fs[0] != alicePhone {
		t.Errorf("same day: flows = %v", fs)
	}

	// Next day: use is discarded.
	tr3 := New(cfg)
	if err := tr3.Load(now.Add(24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := tr3.Used("user:alice", now.Add(24*time.Hour)); got != 0 {
		t.Errorf("next day: used = %v, want 0", got)
	}
}
