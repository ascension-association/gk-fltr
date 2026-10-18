package policy

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestMatch(t *testing.T) {
	var b Builder
	err := b.Parse(strings.NewReader(`
# kids' devices
ip  192.168.1.0/28
ip  fd00::42
mac AA:BB:CC:DD:EE:FF   # tablet
ja4 t13d1516h2_8daaf6152771_*
`))
	if err != nil {
		t.Fatal(err)
	}
	p := b.Policy()
	mac := func(s string) net.HardwareAddr { hw, _ := net.ParseMAC(s); return hw }

	for _, tc := range []struct {
		ip, mac, ja4 string
		want         string
	}{
		{ip: "192.168.1.5", want: "ip 192.168.1.0/28"},
		{ip: "::ffff:192.168.1.5", want: "ip 192.168.1.0/28"},
		{ip: "192.168.1.20"},
		{ip: "fd00::42", want: "ip fd00::42/128"},
		{ip: "192.168.1.20", mac: "aa:bb:cc:dd:ee:ff", want: "mac aa:bb:cc:dd:ee:ff"},
		{ip: "192.168.1.20", mac: "aa:bb:cc:dd:ee:00"},
		{ip: "192.168.1.20", ja4: "T13D1516H2_8DAAF6152771_02713D6AF862", want: "ja4 t13d1516h2_8daaf6152771_*"},
		{ip: "192.168.1.20", ja4: "t13d1516h2_000000000000_02713d6af862"},
	} {
		m, ok := p.Match(netip.MustParseAddr(tc.ip), mac(tc.mac), tc.ja4)
		if m.Rule != tc.want || ok != (tc.want != "") {
			t.Errorf("Match(%s, %s, %s) = %q, %v; want %q", tc.ip, tc.mac, tc.ja4, m.Rule, ok, tc.want)
		}
		if m.Allowance != 0 || m.Group != "" {
			t.Errorf("Match(%s): plain rule has allowance %v group %q", tc.ip, m.Allowance, m.Group)
		}
	}
}

func TestAllowances(t *testing.T) {
	var b Builder
	b.SetDefaultAllowance(30 * time.Minute)
	err := b.Parse(strings.NewReader(`
mac 02:00:00:00:00:01 user=alice allow=2h   # phone
ip  192.168.1.23      user=alice            # laptop
mac 02:00:00:00:00:02 user=bob
ip  192.168.1.0/28    allow=1h
ip  192.168.2.0/24
ja4 q13d*
`))
	if err != nil {
		t.Fatal(err)
	}
	p := b.Policy()
	mac := func(s string) net.HardwareAddr { hw, _ := net.ParseMAC(s); return hw }

	for _, tc := range []struct {
		ip, mac   string
		group     string
		allowance time.Duration
	}{
		// First match wins: alice's phone is in 192.168.1.0/28 too.
		{"192.168.1.5", "02:00:00:00:00:01", "user:alice", 2 * time.Hour},
		{"192.168.1.23", "", "user:alice", 2 * time.Hour},
		{"192.168.1.6", "02:00:00:00:00:02", "user:bob", 30 * time.Minute},
		{"192.168.1.7", "", "rule:ip 192.168.1.0/28", time.Hour},
		{"192.168.2.9", "", "rule:ip 192.168.2.0/24", 30 * time.Minute},
	} {
		m, ok := p.Match(netip.MustParseAddr(tc.ip), mac(tc.mac), "")
		if !ok || m.Group != tc.group || m.Allowance != tc.allowance {
			t.Errorf("Match(%s, %s) = %+v, %v; want group %q allowance %v", tc.ip, tc.mac, m, ok, tc.group, tc.allowance)
		}
		if a, ok := p.Allowance(tc.group); !ok || a != tc.allowance {
			t.Errorf("Allowance(%q) = %v, %v; want %v", tc.group, a, ok, tc.allowance)
		}
	}
	if _, ok := p.Allowance("user:carol"); ok {
		t.Error("Allowance(user:carol): unknown user reported as defined")
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{
		"ip 300.1.1.1", "mac nope", "ja4 [", "dns youtube.com", "ip",
		"ip 10.0.0.1 allow=forever", "ip 10.0.0.1 allow=25h", "ip 10.0.0.1 color=red",
		"ip 10.0.0.1 user=a/b", "ja4 t13* user=alice",
		"ip 10.0.0.1 user=alice allow=1h\nip 10.0.0.2 user=alice allow=2h",
	} {
		var b Builder
		if err := b.Parse(strings.NewReader(in)); err == nil {
			t.Errorf("Parse(%q): expected error", in)
		}
	}
}

func TestSetAllowanceAndUsers(t *testing.T) {
	var b Builder
	b.SetDefaultAllowance(30 * time.Minute)
	if err := b.Parse(strings.NewReader(`
mac 02:00:00:00:00:01 user=alice allow=2h
ip  192.168.1.23      user=alice
mac 02:00:00:00:00:02 user=bob
`)); err != nil {
		t.Fatal(err)
	}
	for _, kv := range []struct {
		user string
		d    time.Duration
	}{{"alice", time.Hour}, {"bob", 0}, {"carol", 45 * time.Minute}} {
		if err := b.SetAllowance(kv.user, kv.d); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []struct {
		user string
		d    time.Duration
	}{{"a/b", time.Hour}, {"dave", 25 * time.Hour}, {"dave", -time.Minute}} {
		if err := b.SetAllowance(bad.user, bad.d); err == nil {
			t.Errorf("SetAllowance(%q, %v): no error", bad.user, bad.d)
		}
	}
	p := b.Policy()

	m, _ := p.Match(netip.MustParseAddr("192.168.1.23"), nil, "")
	if m.Group != "user:alice" || m.Allowance != time.Hour {
		t.Errorf("alice match = %+v, want overridden 1h", m)
	}
	m, _ = p.Match(netip.MustParseAddr("192.168.1.50"), mustMAC("02:00:00:00:00:02"), "")
	if m.Group != "user:bob" || m.Allowance != 0 {
		t.Errorf("bob match = %+v, want group with no allowance", m)
	}
	if a, ok := p.Allowance("user:carol"); !ok || a != 45*time.Minute {
		t.Errorf("Allowance(user:carol) = %v, %v", a, ok)
	}

	us := p.Users()
	var names []string
	for _, u := range us {
		names = append(names, u.Name)
	}
	if strings.Join(names, ",") != "alice,bob,carol" {
		t.Fatalf("Users() = %v", names)
	}
	if strings.Join(us[0].Rules, ";") != "mac 02:00:00:00:00:01;ip 192.168.1.23/32" || len(us[2].Rules) != 0 {
		t.Errorf("Users() rules = %+v", us)
	}
}

func mustMAC(s string) net.HardwareAddr { hw, _ := net.ParseMAC(s); return hw }
