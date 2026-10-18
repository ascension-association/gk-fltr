// Package quota tracks daily allowances of "active minutes".
//
// Flows admitted under an allowance are metered: gk-fltr puts them in an
// nftables set with a byte counter per flow, and passes the counters to Tick
// at a fixed interval. Each interval in which a group's flows moved at least
// ActiveBytes counts as one interval of use. Once a group's use reaches its
// allowance, Tick returns the group's flows so they can be cut off. Use
// resets daily at a fixed local time, as do extra time granted for the day
// (AddExtra) and pauses (SetPaused).
package quota

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Flow identifies a metered flow, oriented from client to server.
type Flow struct {
	Proto  uint8
	Client netip.AddrPort
	Server netip.AddrPort
}

// Info describes a metered flow for logging.
type Info struct {
	MAC   string `json:"mac,omitempty"`
	Class string `json:"class,omitempty"`
	Host  string `json:"host,omitempty"`
	JA4   string `json:"ja4,omitempty"`
	Rule  string `json:"rule,omitempty"`
	User  string `json:"user,omitempty"`
}

// Cutoff is a metered flow whose group has used up its allowance or was
// paused.
type Cutoff struct {
	Flow
	Group  string
	Info   Info
	Paused bool
}

// TickResult reports what a Tick did.
type TickResult struct {
	Reset   bool                     // a new day started; all use was cleared
	Charged map[string]time.Duration // groups charged this tick -> use so far today
	Cut     []Cutoff                 // flows to block
	// Exhausted lists groups that ran out this tick, with their allowance
	// including extra time.
	Exhausted map[string]time.Duration
	Paused    map[string]bool // paused groups whose flows were cut this tick
}

// Config configures a Tracker.
type Config struct {
	Location    *time.Location // timezone of ResetAt
	ResetAt     time.Duration  // time of day the allowance resets, e.g. 4h for 04:00
	Interval    time.Duration  // how often Tick is called; the unit of use
	ActiveBytes uint64         // bytes per interval for a group to count as active
	StatePath   string         // where use is persisted; empty: not persisted
}

type tracked struct {
	group string
	info  Info
	bytes uint64
}

// Tracker tracks use per group. It is safe for concurrent use.
type Tracker struct {
	cfg Config

	mu     sync.Mutex
	period time.Time // start of the current day
	used   map[string]time.Duration
	extra  map[string]time.Duration
	paused map[string]bool
	flows  map[Flow]*tracked
}

// New returns a Tracker.
func New(cfg Config) *Tracker {
	if cfg.Location == nil {
		cfg.Location = time.Local
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	return &Tracker{
		cfg:    cfg,
		used:   make(map[string]time.Duration),
		extra:  make(map[string]time.Duration),
		paused: make(map[string]bool),
		flows:  make(map[Flow]*tracked),
	}
}

// PeriodStart returns the start of the day containing now.
func (t *Tracker) PeriodStart(now time.Time) time.Time {
	l := now.In(t.cfg.Location)
	h, m := int(t.cfg.ResetAt/time.Hour), int(t.cfg.ResetAt%time.Hour/time.Minute)
	start := time.Date(l.Year(), l.Month(), l.Day(), h, m, 0, 0, t.cfg.Location)
	if l.Before(start) {
		start = time.Date(l.Year(), l.Month(), l.Day()-1, h, m, 0, 0, t.cfg.Location)
	}
	return start
}

// rollover starts a new day if needed. Called with t.mu held.
func (t *Tracker) rollover(now time.Time) bool {
	p := t.PeriodStart(now)
	if p.Equal(t.period) {
		return false
	}
	t.period = p
	t.used = make(map[string]time.Duration)
	t.extra = make(map[string]time.Duration)
	t.paused = make(map[string]bool)
	return true
}

// Remaining returns how much of allowance, plus extra time, group has left
// today. A paused group has none left.
func (t *Tracker) Remaining(group string, allowance time.Duration, now time.Time) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rollover(now)
	if t.paused[group] {
		return 0
	}
	if r := allowance + t.extra[group] - t.used[group]; r > 0 {
		return r
	}
	return 0
}

// Usage is a group's use and adjustments for today.
type Usage struct {
	Used   time.Duration
	Extra  time.Duration
	Paused bool
}

// Usage returns group's usage today.
func (t *Tracker) Usage(group string, now time.Time) Usage {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rollover(now)
	return Usage{Used: t.used[group], Extra: t.extra[group], Paused: t.paused[group]}
}

// AddExtra grants group d more time today (or takes it back if d is
// negative; extra time never drops below zero) and returns the new total.
func (t *Tracker) AddExtra(group string, d time.Duration, now time.Time) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rollover(now)
	e := max(t.extra[group]+d, 0)
	if e == 0 {
		delete(t.extra, group)
	} else {
		t.extra[group] = e
	}
	return e
}

// SetPaused pauses group until the next reset, or resumes it. Open flows of
// a paused group are cut off at the next Tick.
func (t *Tracker) SetPaused(group string, paused bool, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rollover(now)
	if paused {
		t.paused[group] = true
	} else {
		delete(t.paused, group)
	}
}

// Used returns group's use today.
func (t *Tracker) Used(group string, now time.Time) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rollover(now)
	return t.used[group]
}

// Track starts metering flow for group.
func (t *Tracker) Track(f Flow, group string, info Info) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.flows[f] = &tracked{group: group, info: info}
}

// Flows returns the metered flows, e.g. to re-add them to nftables after a
// restart.
func (t *Tracker) Flows() []Flow {
	t.mu.Lock()
	defer t.mu.Unlock()
	fs := make([]Flow, 0, len(t.flows))
	for f := range t.flows {
		fs = append(fs, f)
	}
	return fs
}

// Tick charges use from counters, the current byte totals of the metered
// flows (flows missing from counters have ended and are forgotten).
// allowance returns a group's current allowance and whether the group still
// exists; flows of groups that no longer exist are forgotten, not cut off.
func (t *Tracker) Tick(now time.Time, counters map[Flow]uint64, allowance func(group string) (time.Duration, bool)) TickResult {
	t.mu.Lock()
	defer t.mu.Unlock()
	res := TickResult{
		Reset:     t.rollover(now),
		Charged:   map[string]time.Duration{},
		Exhausted: map[string]time.Duration{},
		Paused:    map[string]bool{},
	}

	active := map[string]uint64{}
	for f, tr := range t.flows {
		c, ok := counters[f]
		if !ok {
			delete(t.flows, f)
			continue
		}
		delta := c - tr.bytes
		if c < tr.bytes {
			delta = c // counter restarted (element re-added)
		}
		tr.bytes = c
		active[tr.group] += delta
	}
	for g, b := range active {
		if b >= t.cfg.ActiveBytes && b > 0 {
			t.used[g] += t.cfg.Interval
			res.Charged[g] = t.used[g]
		}
	}

	for f, tr := range t.flows {
		a, ok := allowance(tr.group)
		if !ok {
			delete(t.flows, f)
			continue
		}
		switch {
		case t.paused[tr.group]:
			res.Cut = append(res.Cut, Cutoff{Flow: f, Group: tr.group, Info: tr.info, Paused: true})
			res.Paused[tr.group] = true
			delete(t.flows, f)
		case t.used[tr.group] >= a+t.extra[tr.group]:
			res.Cut = append(res.Cut, Cutoff{Flow: f, Group: tr.group, Info: tr.info})
			res.Exhausted[tr.group] = a + t.extra[tr.group]
			delete(t.flows, f)
		}
	}
	sort.Slice(res.Cut, func(i, j int) bool { return res.Cut[i].Client.Compare(res.Cut[j].Client) < 0 })
	return res
}

// state is the on-disk form of a Tracker.
type state struct {
	Period time.Time        `json:"period"`
	Used   map[string]int64 `json:"used_seconds"`
	Extra  map[string]int64 `json:"extra_seconds,omitempty"`
	Paused []string         `json:"paused,omitempty"`
	Flows  []stateFlow      `json:"flows,omitempty"`
}

type stateFlow struct {
	Proto  uint8          `json:"proto"`
	Client netip.AddrPort `json:"client"`
	Server netip.AddrPort `json:"server"`
	Group  string         `json:"group"`
	Info   Info           `json:"info"`
}

// Save writes the state file atomically. It does nothing without a path.
func (t *Tracker) Save() error {
	if t.cfg.StatePath == "" {
		return nil
	}
	t.mu.Lock()
	st := state{Period: t.period, Used: map[string]int64{}}
	for g, d := range t.used {
		st.Used[g] = int64(d / time.Second)
	}
	for g, d := range t.extra {
		if st.Extra == nil {
			st.Extra = map[string]int64{}
		}
		st.Extra[g] = int64(d / time.Second)
	}
	for g := range t.paused {
		st.Paused = append(st.Paused, g)
	}
	sort.Strings(st.Paused)
	for f, tr := range t.flows {
		st.Flows = append(st.Flows, stateFlow{f.Proto, f.Client, f.Server, tr.group, tr.info})
	}
	t.mu.Unlock()

	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(t.cfg.StatePath), 0o755); err != nil {
		return err
	}
	tmp := t.cfg.StatePath + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, t.cfg.StatePath)
}

// Load restores the state file, if any. Use from an earlier day is
// discarded; metered flows are kept so they can be re-added to nftables.
func (t *Tracker) Load(now time.Time) error {
	if t.cfg.StatePath == "" {
		return nil
	}
	b, err := os.ReadFile(t.cfg.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("%s: %w", t.cfg.StatePath, err)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rollover(now)
	if st.Period.Equal(t.period) {
		for g, s := range st.Used {
			t.used[g] = time.Duration(s) * time.Second
		}
		for g, s := range st.Extra {
			t.extra[g] = time.Duration(s) * time.Second
		}
		for _, g := range st.Paused {
			t.paused[g] = true
		}
	}
	for _, sf := range st.Flows {
		t.flows[Flow{sf.Proto, sf.Client, sf.Server}] = &tracked{group: sf.Group, info: sf.Info}
	}
	return nil
}
