package main

import "testing"

func TestHasFlag(t *testing.T) {
	args := []string{"-targets=192.168.1.50", "--ech", "-ipv6"}
	for name, want := range map[string]bool{"targets": true, "ech": true, "ipv6": true, "i": false, "gw": false} {
		if got := hasFlag(args, name); got != want {
			t.Errorf("hasFlag(%q) = %v, want %v", name, got, want)
		}
	}
	if !hasFlag([]string{"-i", "eth1"}, "i") || !hasFlag([]string{"-i=eth1"}, "i") {
		t.Error("hasFlag misses -i")
	}
}
