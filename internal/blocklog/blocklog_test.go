package blocklog

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func lines(t *testing.T, path string) []Entry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var es []Entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		es = append(es, e)
	}
	return es
}

func TestWriteAndRotate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "blocks.jsonl")
	e := Entry{
		Time: time.Date(2026, 10, 12, 15, 0, 0, 0, time.UTC), Proto: "tcp",
		Client: "192.168.1.10", ClientPort: 50000, Server: "142.250.1.1", ServerPort: 443,
		MAC: "02:00:00:00:00:10", Class: "TLS.YouTube", Host: "www.youtube.com",
		JA4: "t13d1516h2_8daaf6152771_02713d6af862", Rule: Rule{Type: "ip", Value: "192.168.1.0/24"}, Mode: "queue",
	}
	line, _ := json.Marshal(e)
	size := int64(len(line) + 1)

	w, err := Open(path, 3*size) // room for exactly three lines
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		e.ClientPort = uint16(50000 + i)
		if err := w.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()

	old, cur := lines(t, path+".1"), lines(t, path)
	if len(old) != 3 || len(cur) != 1 {
		t.Fatalf("got %d rotated + %d current lines, want 3 + 1", len(old), len(cur))
	}
	if cur[0].ClientPort != 50003 || cur[0].Rule.Value != "192.168.1.0/24" || cur[0].Host != "www.youtube.com" {
		t.Errorf("current entry = %+v", cur[0])
	}

	// Reopening appends instead of truncating.
	w, err = Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(e)
	w.Close()
	if n := len(lines(t, path)); n != 2 {
		t.Errorf("after reopen: %d lines, want 2", n)
	}
}
