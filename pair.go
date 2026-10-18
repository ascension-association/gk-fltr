package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"

	"github.com/ascension-association/gk-fltr/internal/api"
)

// pair shows the QR code that pairs the app with gk-fltr's API.
func pair(args []string) error {
	fs := flag.NewFlagSet("gk-fltr pair", flag.ExitOnError)
	var addrs listFlag
	fs.Var(&addrs, "api", "gk-fltr's -api setting (default :8443)")
	dir := fs.String("api-dir", "/perm/gk-fltr/api", "the API's directory, as given to gk-fltr")
	apiURL := fs.String("api-url", "", "URL the app uses to reach the API (default: this host's LAN address)")
	png := fs.String("png", "", "also write the QR code to this PNG file")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: gk-fltr pair [flags]\n\nShows the QR code the app scans to pair with gk-fltr.\n\nflags:\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	addrs, err := apiAddresses(addrs)
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return errors.New("pair: the app API is off")
	}
	u, ok := pairingURL(*apiURL, addrs, &api.HomeNet{})
	if !ok {
		return errors.New("pair: no LAN address found; give -api-url, e.g. -api-url=https://192.168.1.1:8443")
	}
	creds, _, err := api.LoadCredentials(*dir)
	if err != nil {
		return err
	}
	return printPairing(os.Stdout, creds, u, *png)
}

// apiAddresses returns the addresses the API listens on given the -api
// flag: :8443 by default, none for "off". Public addresses are refused.
func apiAddresses(flag []string) ([]string, error) {
	switch {
	case len(flag) == 0:
		return []string{":8443"}, nil
	case slices.Contains(flag, "off"):
		if len(flag) > 1 {
			return nil, errors.New("-api=off cannot be combined with addresses")
		}
		return nil, nil
	}
	for _, a := range flag {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			return nil, fmt.Errorf("invalid -api %q: %w", a, err)
		}
		if ip, err := netip.ParseAddr(host); err == nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
			return nil, fmt.Errorf("invalid -api %q: a public address; the app API is for the home network only", a)
		}
	}
	return flag, nil
}

// printPairing writes the pairing QR code and URI to w, and the QR code to
// the PNG file png unless it is empty.
func printPairing(w io.Writer, creds *api.Credentials, baseURL, png string) error {
	uri := creds.PairingURI(baseURL)
	text, err := api.QRText(uri)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "Scan with the gk-fltr app to pair it with %s:\n%s\n%s\n"+
		"Keep this secret: it grants control of gk-fltr. Delete token in the API directory to unpair all apps.\n",
		baseURL, text, uri)
	if png != "" {
		b, err := api.QRPNG(uri)
		if err != nil {
			return err
		}
		if err := os.WriteFile(png, b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// pairingURL returns the URL the app should use: apiURL if set, else one
// built from the first API address, using this host's first home network
// address if it names none. ok is false if there is no such address yet.
func pairingURL(apiURL string, addrs []string, home *api.HomeNet) (u string, ok bool) {
	if apiURL != "" {
		return apiURL, true
	}
	host, port, err := net.SplitHostPort(addrs[0])
	if err != nil {
		return "", false
	}
	if ip, err := netip.ParseAddr(host); host == "" || (err == nil && ip.IsUnspecified()) {
		as := home.Addrs()
		if len(as) == 0 {
			return "", false
		}
		host = as[0].String()
	}
	return "https://" + net.JoinHostPort(host, port), true
}
