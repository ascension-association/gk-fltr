package network

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The test binary doubles as a stand-in gk-network: with GKN_SOCKET set,
// it holds that control socket, logs "hello", and runs until told to stop.
// It records each start in GKN_STARTS, and with GKN_CRASH_FIRST, its first
// run exits with status 1 shortly after starting.
func TestMain(m *testing.M) {
	if name := os.Getenv("GKN_SOCKET"); name != "" {
		fakeNetwork(name)
		return
	}
	os.Exit(m.Run())
}

func fakeNetwork(name string) {
	ctl, err := Listen(name)
	if errors.Is(err, ErrRunning) {
		os.Exit(ExitRunning)
	}
	if err != nil {
		os.Exit(2)
	}
	f, _ := os.OpenFile(os.Getenv("GKN_STARTS"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	f.WriteString("start\n")
	f.Close()
	b, _ := os.ReadFile(os.Getenv("GKN_STARTS"))
	log.SetFlags(0)
	log.SetOutput(ctl)
	log.Printf("hello %d", strings.Count(string(b), "\n"))
	if os.Getenv("GKN_CRASH_FIRST") != "" && strings.Count(string(b), "\n") == 1 {
		time.Sleep(200 * time.Millisecond)
		os.Exit(1)
	}
	<-ctl.Stopping()
	log.Print("bye")
	ctl.Close()
}

type harness struct {
	t      *testing.T
	socket string
	starts string
	env    []string

	mu    sync.Mutex
	lines []string
	seen  chan struct{}
}

var socketSeq int

func newHarness(t *testing.T, env ...string) *harness {
	socketSeq++
	h := &harness{
		t:      t,
		socket: fmt.Sprintf("gk-network-test-%d-%d", os.Getpid(), socketSeq),
		starts: filepath.Join(t.TempDir(), "starts"),
		seen:   make(chan struct{}, 100),
	}
	h.env = append(append(os.Environ(), "GKN_SOCKET="+h.socket, "GKN_STARTS="+h.starts), env...)
	return h
}

func (h *harness) command() *exec.Cmd {
	cmd := exec.Command(os.Args[0])
	cmd.Env = h.env
	return cmd
}

func (h *harness) logf(format string, args ...any) {
	h.mu.Lock()
	h.lines = append(h.lines, fmt.Sprintf(format, args...))
	h.mu.Unlock()
	h.seen <- struct{}{}
}

// waitLog waits for a log line containing s.
func (h *harness) waitLog(s string) {
	h.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		h.mu.Lock()
		for _, l := range h.lines {
			if strings.Contains(l, s) {
				h.mu.Unlock()
				return
			}
		}
		h.mu.Unlock()
		select {
		case <-h.seen:
		case <-deadline:
			h.t.Fatalf("no log line with %q in %q", s, h.lines)
		}
	}
}

func (h *harness) startCount() int {
	b, _ := os.ReadFile(h.starts)
	return strings.Count(string(b), "\n")
}

// run starts a Supervisor and returns a function that stops it and waits.
func (h *harness) run() (stop func()) {
	s := &Supervisor{Socket: h.socket, Command: h.command, Logf: h.logf, Backoff: 50 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			h.t.Fatal("Supervisor.Run did not return")
		}
	}
}

func (h *harness) socketGone() bool {
	for range 50 {
		c, err := Dial(h.socket)
		if err != nil {
			return true
		}
		c.Close()
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func TestSuperviseStartAndStop(t *testing.T) {
	h := newHarness(t)
	stop := h.run()
	h.waitLog("gk-network: hello 1")
	stop()
	h.waitLog("asked to stop")
	if !h.socketGone() {
		t.Error("gk-network still running after stop")
	}
	if n := h.startCount(); n != 1 {
		t.Errorf("started %d times, want 1", n)
	}
}

func TestSuperviseAttachesToRunning(t *testing.T) {
	h := newHarness(t)
	// A gk-network left running by a gk-fltr that crashed.
	orphan := h.command()
	if err := orphan.Start(); err != nil {
		t.Fatal(err)
	}
	for i := 0; ; i++ {
		if c, err := Dial(h.socket); err == nil {
			c.Close()
			break
		}
		if i > 200 {
			t.Fatal("stand-in gk-network did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}

	stop := h.run()
	h.waitLog("already running; attached")
	h.waitLog("gk-network: hello 1") // logged before anyone attached
	stop()
	if err := orphan.Wait(); err != nil {
		t.Errorf("orphan exit: %v", err)
	}
	if n := h.startCount(); n != 1 {
		t.Errorf("started %d times, want 1 (no second instance)", n)
	}
}

func TestSuperviseRestartsAfterExit(t *testing.T) {
	h := newHarness(t, "GKN_CRASH_FIRST=1")
	stop := h.run()
	h.waitLog("gk-network: hello 1")
	h.waitLog("gk-network exited (exit status 1); restarting")
	h.waitLog("gk-network: hello 2")
	stop()
	if !h.socketGone() {
		t.Error("gk-network still running after stop")
	}
}

func TestControl(t *testing.T) {
	name := fmt.Sprintf("gk-network-test-%d-control", os.Getpid())
	c, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := Listen(name); !errors.Is(err, ErrRunning) {
		t.Fatalf("second Listen: %v, want ErrRunning", err)
	}

	// Lines logged while no one listens are kept, up to maxPending.
	for i := range maxPending + 10 {
		fmt.Fprintf(c, "line %d\n", i)
	}
	conn, err := Dial(name)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("logs\n"))
	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "line 10\n") {
		t.Errorf("first replayed line = %q, want line 10 (oldest kept)", buf[:n])
	}

	stop, err := Dial(name)
	if err != nil {
		t.Fatal(err)
	}
	stop.Write([]byte("stop\n"))
	stop.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ = stop.Read(buf)
	if string(buf[:n]) != "ok\n" {
		t.Errorf("stop reply = %q", buf[:n])
	}
	select {
	case <-c.Stopping():
	case <-time.After(5 * time.Second):
		t.Error("Stopping not closed")
	}
}
