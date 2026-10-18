package filter

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRedirects(t *testing.T) {
	procSys = t.TempDir()
	t.Cleanup(func() { procSys = "/proc/sys" })
	for _, d := range []string{"all", "eth0"} {
		dir := filepath.Join(procSys, "net/ipv4/conf", d)
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(dir, "send_redirects"), []byte("1\n"), 0o644)
	}

	if RedirectsDisabled("eth0") {
		t.Fatal("RedirectsDisabled with both on")
	}
	if err := DisableRedirects("eth0"); err != nil {
		t.Fatal(err)
	}
	if !RedirectsDisabled("eth0") {
		t.Fatal("RedirectsDisabled = false after DisableRedirects")
	}
	// The kernel sends redirects if "all" is on, whatever the interface says.
	os.WriteFile(filepath.Join(procSys, "net/ipv4/conf/all/send_redirects"), []byte("1\n"), 0o644)
	if RedirectsDisabled("eth0") {
		t.Error("RedirectsDisabled with all=1")
	}
	if err := DisableRedirects("eth9"); err == nil {
		t.Error("DisableRedirects on a missing interface: no error")
	}
}
