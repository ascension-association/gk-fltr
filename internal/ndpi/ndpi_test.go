package ndpi

import "testing"

func TestProtocols(t *testing.T) {
	m, err := New(LicenseNotForProfit)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ps := m.Protocols()
	if len(ps) < 300 {
		t.Fatalf("only %d protocols", len(ps))
	}
	byName := map[string]ProtoInfo{}
	for _, p := range ps {
		byName[p.Name] = p
	}
	for _, name := range []string{"YouTube", "Instagram", "Facebook", "TikTok"} {
		p, ok := byName[name]
		if !ok {
			t.Errorf("%s not listed", name)
			continue
		}
		if id, _ := m.ProtoID(name); id != p.ID {
			t.Errorf("%s: listed id %d, ProtoID %d", name, p.ID, id)
		}
		if p.Category == "" || p.Breed == "" {
			t.Errorf("%s: missing category/breed: %+v", name, p)
		}
		t.Logf("%+v", p)
	}
}
