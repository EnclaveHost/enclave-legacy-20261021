// A WebPKI certificate for the domain's OWN key, so a browser can use the app without a warning while TLS still
// ends here and the key never leaves this domain.
//
// The key is the one minted at start (domtls.Mint) and bound into every attestation report: a CA certificate is
// only another carrier for the SAME key, so a verifying client sees exactly the SPKI it always saw, and a browser
// sees a certificate it trusts. Nothing here creates, exports or replaces the key.
//
// The NAME comes from this domain's own SEV-SNP HOST_DATA, read back from its own hardware report: the deployment id
// the manager launched it for (m4/guestd), whose first 4 bytes are the app-zone label, <8 hex>.<zone>. No request
// field, header or file names it, so a host cannot make this domain ask for, or serve, another deployment's name. A
// domain launched with no HOST_DATA has no name and serves only its self-signed certificate, as before.
//
// ONE EXCEPTION, where there is no SNP at all: a Hyper-V partition (tier T0-hv, windows/vbslike). There the launcher
// in the root partition names the domain at load (m3 monitor `load` field `name`, written root-owned to /cert.name)
// and the front accepts it only in exactly the <8 hex>.<zone> shape (launcherName). That is the launcher's word, and
// it is honest only because on that tier the launcher already signs the reports and can read the domain's memory:
// it is inside the trust boundary either way. An SNP domain never takes a name from this file.
//
//	GET  /.well-known/enclave-csr   a PKCS#10 request for exactly {CN=name, SAN=[name]}, signed by the domain's key
//	POST /.well-known/enclave-cert  a PEM chain: installed only if the leaf's public key IS the domain's key, the leaf
//	                                is valid for the name, and it is valid now. Anyone may post one; the only thing a
//	                                post can change is which certificate carries this same key for this same name.
//
// The certificate is served only when the ClientHello names exactly that name; every other handshake (the
// verifying client that connects by address, the manager's own checks) still gets the self-signed carrier.
//
// A direct guest may also certify the names its OWNER committed in the startup package (names.go). Those are the
// owner's word, not proof of control, so a certificate for one is installed only if it chains to the WebPKI roots
// measured into this image: then a CA validated the name through its normal DNS authority, whoever asked it to.
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	csrPath      = "/.well-known/enclave-csr"
	certPath     = "/.well-known/enclave-cert"
	maxCertChain = 64 << 10
)

type certState struct {
	name         string // "" = no deployment bound: nothing to certify
	key          crypto.Signer
	spki         []byte
	self         *tls.Certificate
	mu           sync.RWMutex
	installed    *tls.Certificate
	aliases      map[string]*certState
	aliasesUntil time.Time
	// roots: when set (owner-committed names), an installed chain must verify to these measured roots for the name
	roots *x509.CertPool
}

// nameFromHostData: <first 4 bytes of the deployment id, hex>.<zone>, or "" when HOST_DATA is all zero or no zone.
func nameFromHostData(hd []byte, zone string) string {
	if len(hd) != 32 || zone == "" || bytes.Equal(hd, make([]byte, 32)) {
		return ""
	}
	return hex.EncodeToString(hd[:4]) + "." + zone
}

// launcherName reads the name a launcher gave this domain at load (the m3 monitor writes it, root-owned and
// read-only, as /cert.name). Accepted only in exactly the shape a HOST_DATA-derived name has, in this front's zone;
// anything else is no name at all.
func launcherName(path, zone string) string {
	if path == "" || zone == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	n := strings.TrimSpace(string(b))
	label, rest, ok := strings.Cut(n, ".")
	if !ok || rest != zone || len(label) != 8 {
		return ""
	}
	if _, err := hex.DecodeString(label); err != nil || strings.ToLower(label) != label {
		return ""
	}
	return n
}

func (c *certState) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if alias := c.forName(strings.ToLower(hello.ServerName)); alias != nil && alias != c {
		return alias.getCertificate(hello)
	}
	if c.name != "" && strings.EqualFold(hello.ServerName, c.name) {
		c.mu.RLock()
		inst := c.installed
		c.mu.RUnlock()
		if inst != nil {
			return inst, nil
		}
	}
	return c.self, nil
}

func (c *certState) csr() ([]byte, error) {
	der, err := c.csrDER()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func (c *certState) csrDER() ([]byte, error) {
	if c.name == "" {
		return nil, errors.New("this domain has no deployment name to certify: no SEV-SNP HOST_DATA names one, and no launcher named it at load")
	}
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: c.name}, DNSNames: []string{c.name}}, c.key)
}

// current is the certificate installed for this name, if any.
func (c *certState) current() *x509.Certificate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.installed == nil {
		return nil
	}
	return c.installed.Leaf
}

// install checks a chain and, if it carries THIS key for THIS name and is valid now, serves it from the next
// handshake on. The chain's CA path is not judged here - this domain holds no root store, and a chain a browser
// cannot build only costs a warning, never the key - but its shape is: PEM CERTIFICATE blocks only, at most 8.
func (c *certState) install(chain []byte, now time.Time) (*x509.Certificate, error) {
	if c.name == "" {
		return nil, errors.New("this domain has no name to certify (no deployment bound)")
	}
	var ders [][]byte
	rest := chain
	for len(ders) <= 8 {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("the chain holds a %q block; only certificates are accepted", b.Type)
		}
		ders = append(ders, b.Bytes)
	}
	if len(ders) == 0 || len(ders) > 8 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("not a PEM chain of 1 to 8 certificates")
	}
	leaf, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return nil, fmt.Errorf("the leaf does not parse: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(spki, c.spki) {
		return nil, errors.New("the leaf's public key is not this domain's key")
	}
	if err := leaf.VerifyHostname(c.name); err != nil {
		return nil, fmt.Errorf("the leaf is not for %s: %w", c.name, err)
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("the leaf is not valid now (%s .. %s)", leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	inter := x509.NewCertPool()
	for i, d := range ders[1:] {
		ic, err := x509.ParseCertificate(d)
		if err != nil {
			return nil, fmt.Errorf("chain certificate %d does not parse: %w", i+1, err)
		}
		inter.AddCert(ic)
	}
	if c.roots != nil {
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: c.name, Roots: c.roots, Intermediates: inter, CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return nil, fmt.Errorf("an owner-committed name needs a chain to this image's measured WebPKI roots: %w", err)
		}
	}
	inst := &tls.Certificate{Certificate: ders, PrivateKey: c.key, Leaf: leaf}
	c.mu.Lock()
	c.installed = inst
	c.mu.Unlock()
	return leaf, nil
}

func (c *certState) serveCSR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	target := c.forName(r.URL.Query().Get("name"))
	if target == nil {
		http.Error(w, "name is not authorized for this deployment", http.StatusForbidden)
		return
	}
	p, err := target.csr()
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("content-type", "application/pkcs10")
	_, _ = w.Write(p)
}

func (c *certState) serveInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxCertChain))
	if err != nil {
		http.Error(w, "the chain exceeds its bound", http.StatusRequestEntityTooLarge)
		return
	}
	target := c.forName(r.URL.Query().Get("name"))
	if target == nil {
		http.Error(w, "name is not authorized for this deployment", http.StatusForbidden)
		return
	}
	leaf, err := target.install(body, time.Now())
	if err != nil {
		http.Error(w, "refused: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	fmt.Printf("DOM certificate installed for %s: issuer %q, valid until %s\n", target.name, leaf.Issuer.CommonName,
		leaf.NotAfter.UTC().Format(time.RFC3339))
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"installed": target.name, "notAfter": leaf.NotAfter.UTC().Format(time.RFC3339),
		"issuer": leaf.Issuer.CommonName})
}
