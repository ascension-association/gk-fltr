package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"rsc.io/qr"
)

// Credentials are what an app needs to talk to gk-fltr: a bearer token and
// the pin of gk-fltr's self-signed TLS certificate.
type Credentials struct {
	Token string
	Cert  tls.Certificate
	// Pin is the SHA-256 hash of the certificate's public key (SPKI), as
	// "sha256/<base64>", the format OkHttp's CertificatePinner uses.
	Pin string
}

// LoadCredentials reads the token and certificate from dir, creating them
// on first use. created reports whether the token is new, so pairing
// details can be shown.
func LoadCredentials(dir string) (c *Credentials, created bool, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, err
	}
	c = &Credentials{}
	tokenPath := filepath.Join(dir, "token")
	b, err := os.ReadFile(tokenPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		raw := make([]byte, 32)
		rand.Read(raw)
		c.Token = hex.EncodeToString(raw)
		if err := os.WriteFile(tokenPath, []byte(c.Token+"\n"), 0o600); err != nil {
			return nil, false, err
		}
		created = true
	case err != nil:
		return nil, false, err
	default:
		c.Token = strings.TrimSpace(string(b))
		if len(c.Token) < 32 {
			return nil, false, fmt.Errorf("%s: token too short; delete the file to make a new one", tokenPath)
		}
	}

	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if _, err := os.Stat(certPath); errors.Is(err, os.ErrNotExist) {
		if err := newCert(certPath, keyPath); err != nil {
			return nil, false, fmt.Errorf("creating TLS certificate: %w", err)
		}
	}
	if c.Cert, err = tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		return nil, false, err
	}
	leaf, err := x509.ParseCertificate(c.Cert.Certificate[0])
	if err != nil {
		return nil, false, err
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	c.Pin = "sha256/" + base64.StdEncoding.EncodeToString(sum[:])
	return c, created, nil
}

// newCert writes a long-lived self-signed certificate. Apps trust it by its
// pin, not by name, so it needs no particular host name or address.
func newCert(certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "gk-fltr"
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "gk-fltr " + host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(30, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// PairingURI returns the URI an app scans to pair with gk-fltr at baseURL,
// e.g. "gkfltr://pair?pin=sha256%2F...&token=...&url=https%3A%2F%2F192.168.1.1%3A8443".
func (c *Credentials) PairingURI(baseURL string) string {
	return "gkfltr://pair?" + url.Values{"url": {baseURL}, "token": {c.Token}, "pin": {c.Pin}}.Encode()
}

// QRText renders text as a QR code for a terminal, two modules per
// character row. Like qrencode -t UTF8, it draws light modules as blocks,
// so it scans on a dark background.
func QRText(text string) (string, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	const quiet = 2
	light := func(x, y int) bool {
		if x < 0 || y < 0 || x >= code.Size || y >= code.Size {
			return true
		}
		return !code.Black(x, y)
	}
	var b strings.Builder
	for y := -quiet; y < code.Size+quiet; y += 2 {
		for x := -quiet; x < code.Size+quiet; x++ {
			switch top, bot := light(x, y), light(x, y+1); {
			case top && bot:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bot:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// QRPNG renders text as a QR code PNG image.
func QRPNG(text string) ([]byte, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return nil, err
	}
	code.Scale = 8
	return code.PNG(), nil
}
