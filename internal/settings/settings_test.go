package settings

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/ascension-association/gk-fltr/internal/policy"
)

func TestSaveLoadApply(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if s, err := Load(path); err != nil || len(s.Users) != 0 {
		t.Fatalf("Load(missing) = %+v, %v", s, err)
	}
	hour := int64(3600)
	s := &Settings{Users: map[string]User{
		"alice": {AllowanceSeconds: &hour, Devices: []Device{{"mac", "02:00:00:00:00:01"}}},
		"bob":   {Devices: []Device{{"ip", "192.168.1.40/32"}}},
	}}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	c := s.Clone()
	*c.Users["alice"].AllowanceSeconds = 1
	c.Users["alice"].Devices[0].Value = "x"
	if *s.Users["alice"].AllowanceSeconds != 3600 || s.Users["alice"].Devices[0].Value != "02:00:00:00:00:01" {
		t.Fatal("Clone shares memory with the original")
	}

	var b policy.Builder
	b.SetDefaultAllowance(30 * time.Minute)
	if err := s.Apply(&b); err != nil {
		t.Fatal(err)
	}
	p := b.Policy()
	if a, ok := p.Allowance("user:alice"); !ok || a != time.Hour {
		t.Errorf("alice allowance = %v, %v", a, ok)
	}
	if m, _ := p.Match(netip.MustParseAddr("192.168.1.40"), nil, ""); m.User != "bob" || m.Allowance != 30*time.Minute {
		t.Errorf("bob match = %+v", m)
	}

	bad := &Settings{Users: map[string]User{"carol": {Devices: []Device{{"ja4", "t13*"}}}}}
	if err := bad.Apply(&policy.Builder{}); err == nil {
		t.Error("ja4 device: no error")
	}
}
