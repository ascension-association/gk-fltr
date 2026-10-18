package network

import (
	"bufio"
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// SocketName is the abstract Unix socket gk-network listens on.
const SocketName = "gk-network"

// ExitRunning is gk-network's exit status when another instance holds the
// control socket.
const ExitRunning = 3

// ErrRunning means another gk-network holds the control socket.
var ErrRunning = errors.New("gk-network is already running")

// maxPending bounds the log lines kept while no one is attached.
const maxPending = 500

// Control is gk-network's control socket. Holding it ensures a single
// instance. A client sends one line:
//
//	logs   receive log lines (those held while no one was attached, then new
//	       ones) until the connection closes; a new "logs" client replaces it
//	stop   stop gk-network; answered with "ok"
//
// Only processes of the same user may connect. Control is also an
// io.Writer for the log package.
type Control struct {
	ln         *net.UnixListener
	stopping   chan struct{}
	stopOnce   sync.Once
	attached   chan struct{}
	attachOnce sync.Once

	mu      sync.Mutex
	sub     net.Conn
	pending [][]byte
}

// Listen takes the control socket name, or returns ErrRunning.
func Listen(name string) (*Control, error) {
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: "@" + name, Net: "unix"})
	if errors.Is(err, syscall.EADDRINUSE) {
		return nil, ErrRunning
	}
	if err != nil {
		return nil, err
	}
	c := &Control{ln: ln, stopping: make(chan struct{}), attached: make(chan struct{})}
	go c.serve()
	return c, nil
}

// Stopping is closed when a client asks gk-network to stop.
func (c *Control) Stopping() <-chan struct{} { return c.stopping }

// Attached is closed when a log client first attaches.
func (c *Control) Attached() <-chan struct{} { return c.attached }

// Close releases the socket and detaches any log client.
func (c *Control) Close() error {
	c.mu.Lock()
	if c.sub != nil {
		c.sub.Close()
		c.sub = nil
	}
	c.mu.Unlock()
	return c.ln.Close()
}

// Write sends one log line to the attached client, or holds it until one
// attaches. It never fails, so logging never blocks gk-network.
func (c *Control) Write(p []byte) (int, error) {
	line := append([]byte(nil), p...)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sub != nil {
		c.sub.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := c.sub.Write(line); err == nil {
			return len(p), nil
		}
		c.sub.Close()
		c.sub = nil
	}
	if len(c.pending) >= maxPending {
		c.pending = c.pending[1:]
	}
	c.pending = append(c.pending, line)
	return len(p), nil
}

func (c *Control) serve() {
	for {
		conn, err := c.ln.AcceptUnix()
		if err != nil {
			return
		}
		go c.handle(conn)
	}
}

func (c *Control) handle(conn *net.UnixConn) {
	if !sameUser(conn) {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	cmd, err := r.ReadString('\n')
	if err != nil {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})
	switch cmd {
	case "stop\n":
		c.stopOnce.Do(func() { close(c.stopping) })
		conn.Write([]byte("ok\n"))
		conn.Close()
	case "logs\n":
		c.mu.Lock()
		if c.sub != nil {
			c.sub.Close()
		}
		c.sub = conn
		for len(c.pending) > 0 {
			conn.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := conn.Write(c.pending[0]); err != nil {
				break
			}
			c.pending = c.pending[1:]
		}
		c.mu.Unlock()
		c.attachOnce.Do(func() { close(c.attached) })
		// The client only reads; its closing ends the subscription.
		r.ReadByte()
		c.mu.Lock()
		if c.sub == conn {
			c.sub = nil
		}
		c.mu.Unlock()
		conn.Close()
	default:
		conn.Close()
	}
}

// sameUser reports whether conn's peer runs as this process's user.
func sameUser(conn *net.UnixConn) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	var cred *syscall.Ucred
	raw.Control(func(fd uintptr) {
		cred, err = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	return err == nil && cred != nil && int(cred.Uid) == os.Getuid()
}

// Dial connects to the control socket name.
func Dial(name string) (*net.UnixConn, error) {
	return net.DialUnix("unix", nil, &net.UnixAddr{Name: "@" + name, Net: "unix"})
}
