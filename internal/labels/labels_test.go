package labels

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLookup(t *testing.T) {
	l, err := Parse(strings.NewReader(`
# browsers
q13d0313h3_55b375c5d22e_*	Chrome (QUIC)
*_55b375c5d22e_*           Chromium-family   # any transport
T13D1516H2_8DAAF6152771_02713D6AF862 smart TV
`))
	if err != nil {
		t.Fatal(err)
	}
	if l.Len() != 3 {
		t.Fatalf("Len() = %d, want 3", l.Len())
	}
	for _, tc := range []struct{ ja4, want string }{
		{"q13d0313h3_55b375c5d22e_4156cdf64688", "Chrome (QUIC)"},
		{"t13d1516h2_55b375c5d22e_02713d6af862", "Chromium-family"},
		{"T13D1516H2_8daaf6152771_02713d6af862", "smart TV"},
		{"t13d1516h2_8daaf6152771_000000000000", ""},
		{"", ""},
	} {
		if got := l.Lookup(tc.ja4); got != tc.want {
			t.Errorf("Lookup(%q) = %q, want %q", tc.ja4, got, tc.want)
		}
	}

	var none *Labels
	if got := none.Lookup("q13d0313h3_55b375c5d22e_4156cdf64688"); got != "" || none.Len() != 0 {
		t.Errorf("nil Labels: Lookup = %q, Len = %d", got, none.Len())
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{
		"q13d0313h3_55b375c5d22e_4156cdf64688\n", // no label
		"q13d[_*  bad pattern\n",
	} {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("Parse(%q): no error", in)
		}
	}
}

func TestAppend(t *testing.T) {
	name := filepath.Join(t.TempDir(), "labels.txt")
	if l, err := ParseFile(name); err != nil || l.Len() != 0 {
		t.Fatalf("ParseFile(missing) = %v entries, %v", l.Len(), err)
	}
	if err := Append(name, "Chrome", []string{"Q13D0313H3_55B375C5D22E_4156CDF64688"}); err != nil {
		t.Fatal(err)
	}
	// An unterminated last line, as a hand edit might leave it.
	f, _ := os.OpenFile(name, os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString("*_8daaf6152771_* smart TV")
	f.Close()
	if err := Append(name, " Firefox ", []string{"t13d1715h2_5b57614c22b0_3d5424432f57"}); err != nil {
		t.Fatal(err)
	}

	l, err := ParseFile(name)
	if err != nil {
		t.Fatal(err)
	}
	for ja4, want := range map[string]string{
		"q13d0313h3_55b375c5d22e_4156cdf64688": "Chrome",
		"t13d1516h2_8daaf6152771_02713d6af862": "smart TV",
		"t13d1715h2_5b57614c22b0_3d5424432f57": "Firefox",
	} {
		if got := l.Lookup(ja4); got != want {
			t.Errorf("Lookup(%s) = %q, want %q", ja4, got, want)
		}
	}

	for _, bad := range []string{"", "  ", "a # b", "a\nb"} {
		if err := Append(name, bad, []string{"x"}); err == nil {
			t.Errorf("Append(label %q): no error", bad)
		}
	}
}
