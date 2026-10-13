package main

import (
	"testing"

	"github.com/ascension-association/gk-net/internal/ndpi"
)

func TestResolveProtocols(t *testing.T) {
	mod, err := ndpi.New(ndpi.LicenseNotForProfit)
	if err != nil {
		t.Fatal(err)
	}
	defer mod.Close()
	id := func(name string) uint16 { i, _ := mod.ProtoID(name); return i }

	ids, err := resolveProtocols(mod, "instagram, Facebook,instagram")
	if err != nil || len(ids) != 2 || ids[0] != id("Instagram") || ids[1] != id("Facebook") {
		t.Errorf("names: got %v, %v; want [Instagram Facebook] deduplicated", ids, err)
	}

	ids, err = resolveProtocols(mod, "YouTube,category:socialnetwork")
	if err != nil {
		t.Fatal(err)
	}
	has := map[uint16]bool{}
	for _, i := range ids {
		has[i] = true
	}
	for _, name := range []string{"YouTube", "Instagram", "Facebook", "TikTok"} {
		if !has[id(name)] {
			t.Errorf("category:socialnetwork: %s missing from %d ids", name, len(ids))
		}
	}
	if has[id("WhatsApp")] {
		t.Error("category:socialnetwork includes WhatsApp (a Chat protocol)")
	}

	for _, bad := range []string{"NoSuchProtocol", "category:NoSuchCategory"} {
		if _, err := resolveProtocols(mod, bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}
