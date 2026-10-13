// Package policy decides which traffic sources are subject to blocking.
//
// Each rule matches sources by IP address or prefix, MAC address, or JA4
// client fingerprint (JA4 patterns may use '*' wildcards, e.g.
// "t13d*_8daaf6152771_*"). The first matching rule, in the order the rules
// were added, applies.
//
// A rule may give its sources a daily allowance ("allow=2h"), during which
// blocked protocols are permitted. Rules naming the same user ("user=alice")
// share one allowance, so a user can be several devices. Rules with an
// allowance but no user each have their own allowance.
package policy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

// Rule is one source rule.
type Rule struct {
	Kind  string // "ip", "mac" or "ja4"
	Value string // normalized value

	prefix netip.Prefix
	mac    string

	user      string
	allowance time.Duration // 0: use the user's or the default allowance
}

func (r *Rule) String() string { return r.Kind + " " + r.Value }

// Match is the result of matching a source.
type Match struct {
	Rule string // e.g. "ip 192.168.1.0/24"
	// Group identifies who an allowance belongs to: "user:<name>" or, for a
	// rule without a user, "rule:<rule>". Empty if there is no allowance.
	Group     string
	User      string        // user name, if any
	Allowance time.Duration // daily allowance; 0 means always blocked
}

// Policy is an immutable list of rules.
type Policy struct {
	rules []*Rule
	// allowances holds each user's allowance after defaults are applied.
	allowances map[string]time.Duration
	def        time.Duration
}

// Builder accumulates rules. The zero value is ready to use.
type Builder struct {
	rules      []*Rule
	allowances map[string]time.Duration
	def        time.Duration
}

// SetDefaultAllowance sets the allowance for rules and users that don't
// specify one. The default is 0 (always blocked).
func (b *Builder) SetDefaultAllowance(d time.Duration) { b.def = d }

var userName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// Add adds a rule given as kind ("ip", "mac" or "ja4"), value and optional
// attributes "user=<name>" and "allow=<duration>".
func (b *Builder) Add(kind, value string, attrs ...string) error {
	r := &Rule{Kind: strings.ToLower(kind)}
	value = strings.TrimSpace(value)
	switch r.Kind {
	case "ip":
		if strings.Contains(value, "/") {
			pfx, err := netip.ParsePrefix(value)
			if err != nil {
				return fmt.Errorf("invalid ip prefix %q: %w", value, err)
			}
			r.prefix = pfx.Masked()
		} else {
			addr, err := netip.ParseAddr(value)
			if err != nil {
				return fmt.Errorf("invalid ip address %q: %w", value, err)
			}
			addr = addr.Unmap()
			r.prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		r.Value = r.prefix.String()
	case "mac":
		hw, err := net.ParseMAC(value)
		if err != nil {
			return fmt.Errorf("invalid mac address %q: %w", value, err)
		}
		r.mac = hw.String()
		r.Value = r.mac
	case "ja4":
		v := strings.ToLower(value)
		if v == "" {
			return fmt.Errorf("empty ja4 pattern")
		}
		if _, err := path.Match(v, ""); err != nil {
			return fmt.Errorf("invalid ja4 pattern %q: %w", value, err)
		}
		r.Value = v
	default:
		return fmt.Errorf("unknown rule type %q (want ip, mac or ja4)", kind)
	}

	for _, a := range attrs {
		k, v, ok := strings.Cut(a, "=")
		if !ok {
			return fmt.Errorf("invalid attribute %q (want user=NAME or allow=DURATION)", a)
		}
		switch k {
		case "user":
			if !userName.MatchString(v) {
				return fmt.Errorf("invalid user name %q (letters, digits, '_', '.', '-')", v)
			}
			if r.Kind == "ja4" {
				return fmt.Errorf("user= applies to ip and mac rules only (a JA4 fingerprint identifies software, not a device)")
			}
			r.user = v
		case "allow":
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 || d > 24*time.Hour {
				return fmt.Errorf("invalid allowance %q (want a duration such as 2h or 90m, at most 24h)", v)
			}
			r.allowance = d
		default:
			return fmt.Errorf("unknown attribute %q (want user= or allow=)", k)
		}
	}
	if r.user != "" && r.allowance > 0 {
		if b.allowances == nil {
			b.allowances = make(map[string]time.Duration)
		}
		if prev, ok := b.allowances[r.user]; ok && prev != r.allowance {
			return fmt.Errorf("conflicting allowances for user %s: %s and %s", r.user, prev, r.allowance)
		}
		b.allowances[r.user] = r.allowance
	}
	b.rules = append(b.rules, r)
	return nil
}

// AddIP, AddMAC and AddJA4 add plain rules.
func (b *Builder) AddIP(s string) error  { return b.Add("ip", s) }
func (b *Builder) AddMAC(s string) error { return b.Add("mac", s) }
func (b *Builder) AddJA4(s string) error { return b.Add("ja4", s) }

// Parse reads rules, one per line:
//
//	<ip|mac|ja4> <value> [user=<name>] [allow=<duration>]
//
// Blank lines and text after '#' are ignored.
func (b *Builder) Parse(r io.Reader) error {
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 2 {
			return fmt.Errorf("line %d: want \"<ip|mac|ja4> <value> [user=NAME] [allow=DURATION]\", got %q", n, strings.TrimSpace(line))
		}
		if err := b.Add(fields[0], fields[1], fields[2:]...); err != nil {
			return fmt.Errorf("line %d: %w", n, err)
		}
	}
	return sc.Err()
}

// ParseFile reads rules from the file at path.
func (b *Builder) ParseFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := b.Parse(f); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// Policy returns the accumulated rules.
func (b *Builder) Policy() *Policy {
	p := &Policy{
		rules:      append([]*Rule(nil), b.rules...),
		allowances: make(map[string]time.Duration),
		def:        b.def,
	}
	for _, r := range p.rules {
		if r.user != "" {
			a, ok := b.allowances[r.user]
			if !ok {
				a = b.def
			}
			p.allowances[r.user] = a
		}
	}
	return p
}

// Empty reports whether the policy has no rules (and so matches nothing).
func (p *Policy) Empty() bool { return len(p.rules) == 0 }

// String summarizes the rule counts.
func (p *Policy) String() string {
	n := map[string]int{}
	for _, r := range p.rules {
		n[r.Kind]++
	}
	s := fmt.Sprintf("%d ip, %d mac, %d ja4 rules", n["ip"], n["mac"], n["ja4"])
	if len(p.allowances) > 0 {
		s += fmt.Sprintf(", %d users", len(p.allowances))
	}
	return s
}

// Match returns the first rule matching a source. mac and ja4 may be empty
// when unknown.
func (p *Policy) Match(ip netip.Addr, mac net.HardwareAddr, ja4 string) (Match, bool) {
	ip = ip.Unmap()
	macStr := ""
	if len(mac) > 0 {
		macStr = mac.String()
	}
	ja4 = strings.ToLower(ja4)
	for _, r := range p.rules {
		var ok bool
		switch r.Kind {
		case "ip":
			ok = r.prefix.Contains(ip)
		case "mac":
			ok = macStr != "" && r.mac == macStr
		case "ja4":
			ok = ja4 != ""
			if ok {
				ok, _ = path.Match(r.Value, ja4)
			}
		}
		if !ok {
			continue
		}
		m := Match{Rule: r.String(), User: r.user}
		switch {
		case r.user != "":
			m.Allowance = p.allowances[r.user]
			m.Group = "user:" + r.user
		case r.allowance > 0:
			m.Allowance = r.allowance
		default:
			m.Allowance = p.def
		}
		if m.Allowance > 0 && m.Group == "" {
			m.Group = "rule:" + r.String()
		}
		return m, true
	}
	return Match{}, false
}

// Allowance returns the current daily allowance of group, as matched by
// Match. ok is false if no rule defines the group any more. A zero
// allowance means the group's sources are now always blocked.
func (p *Policy) Allowance(group string) (allowance time.Duration, ok bool) {
	if user, isUser := strings.CutPrefix(group, "user:"); isUser {
		a, ok := p.allowances[user]
		return a, ok
	}
	if rule, isRule := strings.CutPrefix(group, "rule:"); isRule {
		for _, r := range p.rules {
			if r.user == "" && r.String() == rule {
				a := r.allowance
				if a == 0 {
					a = p.def
				}
				return a, true
			}
		}
	}
	return 0, false
}
