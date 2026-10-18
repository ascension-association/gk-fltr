package steer

import "testing"

func TestHexLEtoIP(t *testing.T) {
	// /proc/net/route stores the gateway little-endian: reverse of dotted order.
	cases := map[string]string{
		"0101A8C0": "192.168.1.1",
		"011FA8C0": "192.168.31.1",
		"0100007F": "127.0.0.1",
		"00000000": "0.0.0.0",
	}
	for hexStr, want := range cases {
		got, err := hexLEtoIP(hexStr)
		if err != nil {
			t.Errorf("hexLEtoIP(%q) error: %v", hexStr, err)
			continue
		}
		if got.String() != want {
			t.Errorf("hexLEtoIP(%q) = %s, want %s", hexStr, got, want)
		}
	}
	if _, err := hexLEtoIP("zzzz"); err == nil {
		t.Error("expected error for bad hex")
	}
}
