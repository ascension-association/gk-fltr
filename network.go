package main

import (
	"context"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ascension-association/gk-fltr/internal/netinfo"
	"github.com/ascension-association/gk-fltr/internal/network"
)

// oneArmedCheck is how long the box must keep looking like it sits next
// to the router before -network=auto starts gk-network. A router can look
// like that briefly at boot, before its LAN interface has an address, and
// gk-network there would steer the uplink's network.
const oneArmedCheck = 15 * time.Second

// superviseNetwork runs gk-network until ctx ends. With auto, it first
// waits until this box is a one-interface box next to the router, and
// steers that interface unless args name one.
func superviseNetwork(ctx context.Context, auto bool, args []string) {
	if auto {
		iface, ok := waitOneArmed(ctx)
		if !ok {
			return
		}
		if !hasFlag(args, "i") {
			args = append([]string{"-i", iface}, args...)
		}
	}
	exe, err := os.Executable()
	if err != nil {
		log.Printf("gk-network: %v", err)
		return
	}
	log.Printf("starting gk-network %s", strings.Join(args, " "))
	s := network.Supervisor{
		Socket: network.SocketName,
		Command: func() *exec.Cmd {
			return exec.Command(exe, append([]string{"network", "-supervised"}, args...)...)
		},
		Logf:    log.Printf,
		Backoff: 10 * time.Second,
	}
	s.Run(ctx)
}

// waitOneArmed returns the interface once the box has looked one-armed on
// two checks oneArmedCheck apart, or false if ctx ends first.
func waitOneArmed(ctx context.Context) (string, bool) {
	logged := false
	prev := ""
	for {
		iface, ok := netinfo.OneArmed()
		switch {
		case ok && iface == prev:
			return iface, true
		case ok:
			prev = iface
		default:
			prev = ""
			if !logged {
				log.Printf("gk-network not started: this box doesn't look like a one-interface box next to the router (-network=on starts it anyway)")
				logged = true
			}
		}
		t := time.NewTimer(oneArmedCheck)
		select {
		case <-ctx.Done():
			t.Stop()
			return "", false
		case <-t.C:
		}
	}
}

// hasFlag reports whether args set the flag name.
func hasFlag(args []string, name string) bool {
	for _, a := range args {
		a = strings.TrimLeft(a, "-")
		if a == name || strings.HasPrefix(a, name+"=") {
			return true
		}
	}
	return false
}
