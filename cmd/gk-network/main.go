// Command gk-network steers a LAN's traffic through this host with ARP and
// filters it: safe-search DNS, and malware, VPN and country blocking. See
// README.md. gk-fltr can also run it for you as "gk-fltr network".
package main

import (
	"os"

	"github.com/ascension-association/gk-fltr/internal/network"
)

func main() { network.Main(os.Args[1:]) }
