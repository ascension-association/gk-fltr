package api

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ascension-association/gk-fltr/internal/blocklog"
	"github.com/ascension-association/gk-fltr/internal/policy"
	"github.com/ascension-association/gk-fltr/internal/quota"
	"github.com/ascension-association/gk-fltr/internal/settings"
)

const rules = `
mac 02:00:00:00:00:01 user=alice allow=2h
ip  192.168.1.0/24
`

type fixture struct {
	t     *testing.T
	srv   *Server
	token string
	dir   string
	now   time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	creds, created, err := LoadCredentials(filepath.Join(dir, "api"))
	if err != nil || !created {
		t.Fatalf("LoadCredentials = %v, %v", created, err)
	}
	f := &fixture{t: t, token: creds.Token, dir: dir, now: time.Date(2026, 10, 12, 15, 0, 0, 0, time.UTC)}

	build := func(s *settings.Settings) (*policy.Policy, error) {
		var b policy.Builder
		if err := s.Apply(&b); err != nil {
			return nil, err
		}
		if err := b.Parse(strings.NewReader(rules)); err != nil {
			return nil, err
		}
		return b.Policy(), nil
	}
	var pol atomic.Pointer[policy.Policy]
	p, _ := build(&settings.Settings{})
	pol.Store(p)

	tr := quota.New(quota.Config{Location: time.UTC, Interval: time.Minute})
	f.srv = New(Config{
		Credentials:  creds,
		SettingsPath: filepath.Join(dir, "api", "settings.json"),
		Tracker:      tr,
		Policy:       pol.Load,
		Apply: func(s *settings.Settings) error {
			p, err := build(s)
			if err == nil {
				pol.Store(p)
			}
			return err
		},
		Status: func() Status {
			return Status{Mode: "queue", FailClosed: true, Protocols: []string{"YouTube"}, Started: f.now.Add(-time.Hour)}
		},
		BlockLog: filepath.Join(dir, "blocks.jsonl"),
		Home:     testHome().Contains,
		Now:      func() time.Time { return f.now },
	})
	return f
}

// do sends a request with the token and decodes the JSON response into out.
func (f *fixture) do(method, path, body string, out any) int {
	f.t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "192.168.1.50:40000"
	r.Header.Set("Authorization", "Bearer "+f.token)
	w := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(w, r)
	if out != nil && w.Code < 300 {
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			f.t.Fatalf("%s %s: %v in %q", method, path, err, w.Body)
		}
	}
	return w.Code
}

func TestAuth(t *testing.T) {
	f := newFixture(t)
	if code := f.do("GET", "/api/v1/status", "", nil); code != http.StatusOK {
		t.Fatalf("with token: %d", code)
	}
	bad := func(remote string) int {
		r := httptest.NewRequest("GET", "/api/v1/status", nil)
		r.RemoteAddr = remote
		r.Header.Set("Authorization", "Bearer nope")
		w := httptest.NewRecorder()
		f.srv.Handler().ServeHTTP(w, r)
		return w.Code
	}
	for i := range maxFails {
		if code := bad("192.168.1.66:1234"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d, want 401", i, code)
		}
	}
	if code := bad("192.168.1.66:1234"); code != http.StatusTooManyRequests {
		t.Fatalf("after %d failures: %d, want 429", maxFails, code)
	}
	if code := bad("192.168.1.67:1234"); code != http.StatusUnauthorized {
		t.Fatalf("other address: %d, want 401", code)
	}
	for _, remote := range []string{"203.0.113.5:1234", "100.64.0.5:1234", "[2001:db8::1]:1234", "192.168.0.9:1234"} {
		r := httptest.NewRequest("GET", "/api/v1/status", nil)
		r.RemoteAddr = remote
		r.Header.Set("Authorization", "Bearer "+f.token)
		w := httptest.NewRecorder()
		f.srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("from %s with token: %d, want 403", remote, w.Code)
		}
	}
	f.now = f.now.Add(2 * time.Minute)
	if code := bad("192.168.1.66:1234"); code != http.StatusUnauthorized {
		t.Fatalf("a minute later: %d, want 401", code)
	}
}

func TestStatus(t *testing.T) {
	f := newFixture(t)
	var st struct {
		Mode          string         `json:"mode"`
		UptimeSeconds int64          `json:"uptime_seconds"`
		NextReset     time.Time      `json:"next_reset"`
		Rules         map[string]int `json:"rules"`
		Users         int            `json:"users"`
	}
	f.do("GET", "/api/v1/status", "", &st)
	if st.Mode != "queue" || st.UptimeSeconds != 3600 || st.Rules["ip"] != 1 || st.Rules["mac"] != 1 || st.Users != 1 ||
		!st.NextReset.Equal(time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("status = %+v", st)
	}
}

func TestUsers(t *testing.T) {
	f := newFixture(t)

	// bob is new: one device and no allowance (always blocked).
	var u User
	if code := f.do("PUT", "/api/v1/users/bob", `{"allowance_seconds":0,"devices":[{"type":"ip","value":"192.168.1.40"},{"type":"mac","value":"02:00:00:00:00:0B"}]}`, &u); code != http.StatusOK {
		t.Fatalf("PUT bob: %d", code)
	}
	if u.Name != "bob" || !u.Managed || u.AllowanceSeconds != 0 || len(u.Devices) != 2 ||
		u.Devices[0] != (UserDevice{"ip", "192.168.1.40/32", "settings"}) || u.Devices[1].Value != "02:00:00:00:00:0b" {
		t.Fatalf("bob = %+v", u)
	}
	// The app's device rule comes before the rules file's subnet rule.
	if m, _ := f.srv.cfg.Policy().Match(netip.MustParseAddr("192.168.1.40"), nil, ""); m.User != "bob" {
		t.Errorf("192.168.1.40 matches %+v, want bob", m)
	}

	// alice comes from the rules file; the app overrides her allowance and
	// adds a device.
	f.do("PUT", "/api/v1/users/alice", `{"allowance_seconds":3600,"devices":[{"type":"ip","value":"192.168.1.23"}]}`, &u)
	if u.AllowanceSeconds != 3600 || u.RemainingSeconds != 3600 || len(u.Devices) != 2 ||
		u.Devices[0].Source != "settings" || u.Devices[1] != (UserDevice{"mac", "02:00:00:00:00:01", "rules"}) {
		t.Fatalf("alice = %+v", u)
	}

	var us []User
	f.do("GET", "/api/v1/users", "", &us)
	if len(us) != 2 || us[0].Name != "alice" || us[1].Name != "bob" {
		t.Fatalf("users = %+v", us)
	}
	saved, _ := settings.Load(f.srv.cfg.SettingsPath)
	if len(saved.Users) != 2 || *saved.Users["alice"].AllowanceSeconds != 3600 {
		t.Errorf("settings file = %+v", saved)
	}

	for _, body := range []string{
		`{"allowance_seconds":90000}`,
		`{"devices":[{"type":"ja4","value":"t13*"}]}`,
		`{"devices":[{"type":"ip","value":"999.1.1.1"}]}`,
		`{}`,
		`{"allowance":3600}`,
		`not json`,
	} {
		if code := f.do("PUT", "/api/v1/users/carol", body, nil); code != http.StatusBadRequest {
			t.Errorf("PUT carol %s: %d, want 400", body, code)
		}
	}
	if code := f.do("PUT", "/api/v1/users/a%2Fb", `{"allowance_seconds":60}`, nil); code != http.StatusBadRequest {
		t.Errorf("PUT bad name: %d, want 400", code)
	}

	// Deleting alice's settings leaves her rules-file definition.
	if code := f.do("DELETE", "/api/v1/users/alice", "", nil); code != http.StatusNoContent {
		t.Fatalf("DELETE alice: %d", code)
	}
	f.do("GET", "/api/v1/users/alice", "", &u)
	if u.Managed || u.AllowanceSeconds != 7200 || len(u.Devices) != 1 {
		t.Errorf("alice after delete = %+v", u)
	}
	if code := f.do("DELETE", "/api/v1/users/alice", "", nil); code != http.StatusNotFound {
		t.Errorf("DELETE alice again: %d, want 404", code)
	}
	if code := f.do("GET", "/api/v1/users/zed", "", nil); code != http.StatusNotFound {
		t.Errorf("GET zed: %d, want 404", code)
	}
}

func TestExtraAndPause(t *testing.T) {
	f := newFixture(t)
	var u User
	if code := f.do("POST", "/api/v1/users/alice/extra", `{"seconds":1800}`, &u); code != http.StatusOK {
		t.Fatalf("extra: %d", code)
	}
	if u.ExtraSeconds != 1800 || u.RemainingSeconds != 7200+1800 {
		t.Fatalf("after extra: %+v", u)
	}
	f.do("PUT", "/api/v1/users/alice/pause", "", &u)
	if !u.Paused || u.RemainingSeconds != 0 {
		t.Fatalf("paused: %+v", u)
	}
	f.do("DELETE", "/api/v1/users/alice/pause", "", &u)
	if u.Paused || u.RemainingSeconds != 9000 {
		t.Fatalf("resumed: %+v", u)
	}
	// Extra time is for today only.
	f.now = f.now.Add(24 * time.Hour)
	f.do("GET", "/api/v1/users/alice", "", &u)
	if u.ExtraSeconds != 0 || u.RemainingSeconds != 7200 {
		t.Fatalf("next day: %+v", u)
	}

	if code := f.do("POST", "/api/v1/users/zed/extra", `{"seconds":60}`, nil); code != http.StatusNotFound {
		t.Errorf("extra for unknown user: %d, want 404", code)
	}
	if code := f.do("POST", "/api/v1/users/alice/extra", `{"seconds":0}`, nil); code != http.StatusBadRequest {
		t.Errorf("zero extra: %d, want 400", code)
	}
}

func TestDevices(t *testing.T) {
	f := newFixture(t)
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	f.srv.Seen(netip.MustParseAddr("192.168.1.10"), mac, "Chrome", "t13d_x_y", "www.youtube.com", f.now)
	f.srv.Seen(netip.MustParseAddr("192.168.1.10"), mac, "", "", "dns.google", f.now.Add(time.Second))
	f.srv.Seen(netip.MustParseAddr("10.9.9.9"), nil, "", "", "", f.now.Add(2*time.Second))

	var ds []Device
	f.do("GET", "/api/v1/devices", "", &ds)
	if len(ds) != 2 {
		t.Fatalf("devices = %+v", ds)
	}
	if ds[0].IP != "10.9.9.9" || ds[0].User != "" || ds[0].Rule != "" {
		t.Errorf("newest device = %+v", ds[0])
	}
	if d := ds[1]; d.MAC != "02:00:00:00:00:01" || d.Label != "Chrome" || d.Host != "dns.google" || d.User != "alice" {
		t.Errorf("alice's phone = %+v", d)
	}
}

func TestBlocks(t *testing.T) {
	f := newFixture(t)
	w, err := blocklog.Open(f.srv.cfg.BlockLog, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		e := blocklog.Entry{Time: f.now.Add(time.Duration(i) * time.Minute), Client: "192.168.1.10", Class: "TLS.YouTube"}
		if i%2 == 0 {
			e.User = "alice"
		}
		w.Write(e)
	}
	w.Close()

	var es []blocklog.Entry
	f.do("GET", "/api/v1/blocks", "", &es)
	if len(es) != 5 {
		t.Fatalf("all: %d entries", len(es))
	}
	q := url.Values{"since": {f.now.Add(time.Minute).Format(time.RFC3339)}, "user": {"alice"}}
	f.do("GET", "/api/v1/blocks?"+q.Encode(), "", &es)
	if len(es) != 2 || !es[0].Time.Equal(f.now.Add(2*time.Minute)) {
		t.Fatalf("since+user: %+v", es)
	}
	f.do("GET", "/api/v1/blocks?limit=2", "", &es)
	if len(es) != 2 || !es[1].Time.Equal(f.now.Add(4*time.Minute)) {
		t.Fatalf("limit: %+v", es)
	}
	if code := f.do("GET", "/api/v1/blocks?limit=0", "", nil); code != http.StatusBadRequest {
		t.Errorf("limit=0: %d", code)
	}
	os.Remove(f.srv.cfg.BlockLog)
	f.do("GET", "/api/v1/blocks", "", &es)
	if len(es) != 0 {
		t.Errorf("no log: %+v", es)
	}
}

func TestCredentials(t *testing.T) {
	dir := t.TempDir()
	c1, created, err := LoadCredentials(dir)
	if err != nil || !created {
		t.Fatal(created, err)
	}
	c2, created, err := LoadCredentials(dir)
	if err != nil || created || c2.Token != c1.Token || c2.Pin != c1.Pin {
		t.Fatalf("second load: created=%v err=%v; token/pin changed", created, err)
	}
	if len(c1.Token) != 64 || !strings.HasPrefix(c1.Pin, "sha256/") || len(c1.Pin) != 7+44 {
		t.Errorf("token %q pin %q", c1.Token, c1.Pin)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "token")); fi.Mode().Perm() != 0o600 {
		t.Errorf("token mode %v", fi.Mode())
	}

	uri := c1.PairingURI("https://192.168.1.1:8443")
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "gkfltr" || u.Host != "pair" {
		t.Fatalf("PairingURI = %q", uri)
	}
	if q := u.Query(); q.Get("url") != "https://192.168.1.1:8443" || q.Get("token") != c1.Token || q.Get("pin") != c1.Pin {
		t.Errorf("PairingURI query = %v", q)
	}
	text, err := QRText(uri)
	if err != nil || strings.Count(text, "\n") < 20 {
		t.Errorf("QRText: %v\n%s", err, text)
	}
	if png, err := QRPNG(uri); err != nil || string(png[1:4]) != "PNG" {
		t.Errorf("QRPNG: %v", err)
	}
}

func TestListenTLSPin(t *testing.T) {
	f := newFixture(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	if err := f.srv.Listen([]string{addr}); err != nil {
		t.Fatal(err)
	}
	defer f.srv.Close()

	// What the app does: trust the certificate only if its key matches the pin.
	var pin string
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			pin = "sha256/" + base64.StdEncoding.EncodeToString(sum[:])
			return nil
		},
	}}}
	req, _ := http.NewRequest("GET", "https://"+addr+"/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer "+f.token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || pin != f.srv.cfg.Credentials.Pin {
		t.Errorf("status %d, pin %q, want %q", resp.StatusCode, pin, f.srv.cfg.Credentials.Pin)
	}
}
