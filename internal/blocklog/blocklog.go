// Package blocklog appends blocked flows to a file as JSON Lines (one JSON
// object per line), rotating the file when it grows too large.
package blocklog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is one blocked flow.
type Entry struct {
	Time       time.Time `json:"time"`
	Proto      string    `json:"proto"` // "tcp" or "udp"
	Client     string    `json:"client"`
	ClientPort uint16    `json:"client_port"`
	Server     string    `json:"server"`
	ServerPort uint16    `json:"server_port"`
	MAC        string    `json:"mac,omitempty"`
	Class      string    `json:"class"` // nDPI classification, e.g. "TLS.YouTube"
	Host       string    `json:"host,omitempty"`
	JA4        string    `json:"ja4,omitempty"`
	Label      string    `json:"client_label,omitempty"` // client software, from the labels file
	Rule       Rule      `json:"rule"`
	User       string    `json:"user,omitempty"`
	// Reason is "rule" for a rule without allowance, "allowance_exhausted"
	// when the source's daily allowance was used up.
	Reason    string `json:"reason"`
	Allowance string `json:"allowance,omitempty"` // daily allowance, e.g. "2h"
	Mode      string `json:"mode"`                // "queue" or "log"
}

// Rule is the policy rule that matched.
type Rule struct {
	Type  string `json:"type"` // "ip", "mac" or "ja4"
	Value string `json:"value"`
}

// Writer appends entries to a file. It is safe for concurrent use.
type Writer struct {
	mu      sync.Mutex
	path    string
	maxSize int64
	f       *os.File
	size    int64
}

// Open opens (creating it and its directory if needed) the log at path.
// When the file would grow beyond maxSize bytes it is renamed to path+".1",
// replacing any previous one, and a new file is started. maxSize <= 0 means
// no limit.
func Open(path string, maxSize int64) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	w := &Writer{path: path, maxSize: maxSize}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) open() error {
	f, err := os.OpenFile(w.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.f, w.size = f, fi.Size()
	return nil
}

// Write appends e as one line.
func (w *Writer) Write(e Entry) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.maxSize > 0 && w.size > 0 && w.size+int64(len(line)) > w.maxSize {
		w.f.Close()
		if err := os.Rename(w.path, w.path+".1"); err != nil {
			return fmt.Errorf("rotating %s: %w", w.path, err)
		}
		if err := w.open(); err != nil {
			return err
		}
	}
	n, err := w.f.Write(line)
	w.size += int64(n)
	return err
}

// Close closes the file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Close()
}
