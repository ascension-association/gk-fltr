package filter

import (
	"strings"
	"testing"
)

func TestSuspendedCountries(t *testing.T) {
	// 19 full + 20 partial suspension countries, plus the Palestinian Authority.
	if got := len(SuspendedCountries); got != 40 {
		t.Fatalf("len(SuspendedCountries) = %d, want 40", got)
	}
	seen := map[string]bool{}
	for _, c := range SuspendedCountries {
		if len(c) != 2 || c != strings.ToLower(c) {
			t.Errorf("bad country code %q", c)
		}
		if seen[c] {
			t.Errorf("duplicate country code %q", c)
		}
		seen[c] = true
	}
}

func TestCountryBlocklistURLs(t *testing.T) {
	got := CountryBlocklistURLs([]string{" IR ", "", "cu"}, false)
	want := []string{
		"https://www.ipdeny.com/ipblocks/data/aggregated/ir-aggregated.zone",
		"https://www.ipdeny.com/ipblocks/data/aggregated/cu-aggregated.zone",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("url[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	got = CountryBlocklistURLs([]string{"ir"}, true)
	if len(got) != 2 || got[1] != "https://www.ipdeny.com/ipv6/ipaddresses/aggregated/ir-aggregated.zone" {
		t.Errorf("with IPv6: got %v", got)
	}
}
