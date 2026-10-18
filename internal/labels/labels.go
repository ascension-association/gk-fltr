// Package labels names client software by its JA4 fingerprint, so logs can
// say "Chrome (QUIC)" next to an opaque hash.
//
// A labels file has one entry per line, a JA4 pattern ('*' wildcards
// allowed) followed by a label that may contain spaces:
//
//	q13d0313h3_55b375c5d22e_*  Chrome (QUIC)
//	*_55b375c5d22e_*           Chromium-family
//
// The first matching entry applies. Blank lines and text after '#' are
// ignored.
package labels

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

type entry struct {
	pattern, label string
}

// Labels is an immutable list of entries. A nil *Labels has no entries.
type Labels struct {
	entries []entry
}

// Parse reads entries from r.
func Parse(r io.Reader) (*Labels, error) {
	l := &Labels{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		i := strings.IndexAny(line, " \t")
		if i < 0 {
			return nil, fmt.Errorf("line %d: want \"<ja4 pattern> <label>\", got %q", n, line)
		}
		pat, label := strings.ToLower(line[:i]), strings.TrimSpace(line[i:])
		if _, err := path.Match(pat, ""); err != nil {
			return nil, fmt.Errorf("line %d: invalid ja4 pattern %q: %w", n, pat, err)
		}
		l.entries = append(l.entries, entry{pat, label})
	}
	return l, sc.Err()
}

// ParseFile reads entries from the file at name. A missing file has no
// entries.
func ParseFile(name string) (*Labels, error) {
	f, err := os.Open(name)
	if errors.Is(err, os.ErrNotExist) {
		return &Labels{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	l, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return l, nil
}

// Len returns the number of entries.
func (l *Labels) Len() int {
	if l == nil {
		return 0
	}
	return len(l.entries)
}

// Lookup returns the label of the first entry matching ja4, or "" if none
// does or ja4 is empty.
func (l *Labels) Lookup(ja4 string) string {
	if l == nil || ja4 == "" {
		return ""
	}
	ja4 = strings.ToLower(ja4)
	for _, e := range l.entries {
		if ok, _ := path.Match(e.pattern, ja4); ok {
			return e.label
		}
	}
	return ""
}

// CheckLabel reports whether label can be stored in a labels file.
func CheckLabel(label string) error {
	switch {
	case strings.TrimSpace(label) == "":
		return errors.New("empty label")
	case strings.ContainsAny(label, "#\r\n"):
		return fmt.Errorf("invalid label %q (no '#' or line breaks)", label)
	}
	return nil
}

// Append adds an entry for each JA4 in ja4s to the file at name, creating
// it if needed.
func Append(name, label string, ja4s []string) error {
	if err := CheckLabel(label); err != nil {
		return err
	}
	if len(ja4s) == 0 {
		return nil
	}
	f, err := os.OpenFile(name, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	var b strings.Builder
	// Don't join our first entry onto an unterminated last line.
	if fi, err := f.Stat(); err == nil && fi.Size() > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, fi.Size()-1); err == nil && last[0] != '\n' {
			b.WriteByte('\n')
		}
	}
	for _, j := range ja4s {
		fmt.Fprintf(&b, "%s  %s\n", strings.ToLower(j), strings.TrimSpace(label))
	}
	if _, err := f.WriteString(b.String()); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
