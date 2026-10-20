package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"enclave.host/isolation/m2/release"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type secretSink struct {
	bytes.Buffer
	closed  bool
	onWrite func() // what must already be true when the runtime's first byte is written
}

func (s *secretSink) Write(p []byte) (int, error) {
	if s.onWrite != nil {
		s.onWrite()
	}
	return s.Buffer.Write(p)
}
func (s *secretSink) Close() error { s.closed = true; return nil }

// egressWorld is a Shield domain's egress surroundings in a temp dir: the measured /app.config (owned by the test user,
// standing in for root), the monitor's /etc/hosts (owned by this "front"), a free forwarder port, and a host egress
// endpoint that records each header it is sent.
type egressWorld struct {
	eg      *shieldEgress
	headers chan string
	audited []netip.AddrPort
	mu      sync.Mutex
	lines   []string // the console: the front's own line, and the forwarders' (from their goroutines)
}

func (w *egressWorld) console() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.lines...)
}

func newEgressWorld(t *testing.T, config string) *egressWorld {
	t.Helper()
	dir := t.TempDir()
	cfg, hosts := filepath.Join(dir, "app.config"), filepath.Join(dir, "hosts")
	if config != "" {
		if err := os.WriteFile(cfg, []byte(config), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(hosts, []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	host, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { host.Close() })
	w := &egressWorld{headers: make(chan string, 16)}
	go func() {
		for {
			c, err := host.Accept()
			if err != nil {
				return
			}
			line, _ := bufio.NewReader(c).ReadString('\n')
			w.headers <- line
			c.Write([]byte("refused\n"))
			c.Close()
		}
	}()
	pl, err := net.Listen("tcp", "127.64.0.2:0")
	if err != nil {
		t.Skipf("no 127.64.0.0/16 loopback here: %v", err)
	}
	port := pl.Addr().(*net.TCPAddr).Port
	pl.Close()
	w.eg = &shieldEgress{config: cfg, configUID: os.Getuid(), hosts: hosts, port: port,
		upstream: func() (net.Conn, error) { return net.Dial("tcp", host.Addr().String()) },
		audit:    func(want []netip.AddrPort) error { w.audited = want; return nil },
		logf: func(f string, a ...any) {
			w.mu.Lock()
			w.lines = append(w.lines, fmt.Sprintf(f, a...))
			w.mu.Unlock()
		}}
	return w
}

func secretFixture(t *testing.T) (*front, *secretSink, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	key, e := release.NewSealKey()
	if e != nil {
		t.Fatal(e)
	}
	id, _ := release.ID("0x" + hex.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	var nonce [32]byte
	rand.Read(nonce[:])
	pipe := &secretSink{}
	eg := newEgressWorld(t, `{"bucket":"jot-notes","endpoint":"$R2_ENDPOINT"}`).eg
	f := &front{secrets: &shieldSecrets{id: id, text: "0x" + hex.EncodeToString(id[:]), key: key, nonce: nonce, until: time.Now().Add(time.Minute), pipe: pipe, pins: []ed25519.PublicKey{pub}, egress: eg}}
	t.Cleanup(func() {
		if f.secrets.fwd != nil {
			f.secrets.fwd.Close()
		}
	})
	return f, pipe, priv
}
func sealForTest(t *testing.T, s *shieldSecrets, signer ed25519.PrivateKey, plain map[string]any) map[string]string {
	t.Helper()
	eph, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	pub, e := ecdh.X25519().NewPublicKey(s.key.Public())
	if e != nil {
		t.Fatal(e)
	}
	shared, e := eph.ECDH(pub)
	if e != nil {
		t.Fatal(e)
	}
	info := append([]byte("enclave-secrets-release-v1 seal\n"), s.id[:]...)
	info = append(info, eph.PublicKey().Bytes()...)
	info = append(info, s.key.Public()...)
	key, e := hkdf.Key(sha256.New, shared, s.nonce[:], string(info), 32)
	if e != nil {
		t.Fatal(e)
	}
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(block)
	iv := make([]byte, 12)
	rand.Read(iv)
	pt, _ := json.Marshal(plain)
	sealed := append(eph.PublicKey().Bytes(), iv...)
	sealed = g.Seal(sealed, iv, pt, nil)
	digest, _ := release.ResponseDigest(s.id, s.nonce, s.key.Public(), sealed)
	sig := ed25519.Sign(signer, digest[:])
	return map[string]string{"nonce": hex.EncodeToString(s.nonce[:]), "sealed": base64.StdEncoding.EncodeToString(sealed), "sig": base64.StdEncoding.EncodeToString(sig), "keyId": release.KeyID(signer.Public().(ed25519.PublicKey))}
}
func postSecret(f *front, b map[string]string) int {
	raw, _ := json.Marshal(b)
	r := httptest.NewRequest("POST", shieldSecretsPath, bytes.NewReader(raw))
	w := httptest.NewRecorder()
	f.serveShieldSecrets(w, r)
	return w.Code
}
func TestShieldSecretInstallAuthenticatesThenWritesPipeOnce(t *testing.T) {
	f, sink, priv := secretFixture(t)
	plain := map[string]any{"id": f.secrets.text, "config": nil, "secrets": map[string]string{"API_KEY": "synthetic-value"}, "issuedAt": time.Now().UTC().Format(time.RFC3339Nano)}
	b := sealForTest(t, f.secrets, priv, plain)
	wrong := map[string]string{}
	for k, v := range b {
		wrong[k] = v
	}
	wrong["sig"] = base64.StdEncoding.EncodeToString(make([]byte, 64))
	if postSecret(f, wrong) != 403 || sink.Len() != 0 {
		t.Fatal("untrusted release wrote plaintext")
	}
	if postSecret(f, b) != 200 || !sink.closed || sink.String() != `{"API_KEY":"synthetic-value"}` {
		t.Fatal("valid release did not reach only private pipe")
	}
	if postSecret(f, b) != 409 {
		t.Fatal("replay accepted")
	}
}
func TestShieldReleaseRejectsWrongTenantExpiredConfigAndNativeControls(t *testing.T) {
	for _, kind := range []string{"tenant", "expired", "config", "native"} {
		t.Run(kind, func(t *testing.T) {
			f, sink, priv := secretFixture(t)
			p := map[string]any{"id": f.secrets.text, "config": nil, "secrets": map[string]string{"API_KEY": "ok"}, "issuedAt": time.Now().UTC().Format(time.RFC3339Nano)}
			switch kind {
			case "tenant":
				p["id"] = "0x" + hex.EncodeToString(bytes.Repeat([]byte{8}, 32))
			case "expired":
				p["issuedAt"] = time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339Nano)
			case "config":
				p["config"] = map[string]string{"x": "unmeasured"}
			case "native":
				p["secrets"] = map[string]string{"LD_PRELOAD": "/evil"}
			}
			if postSecret(f, sealForTest(t, f.secrets, priv, p)) != 403 || sink.Len() != 0 {
				t.Fatal("invalid release accepted")
			}
		})
	}
}

var _ io.WriteCloser = (*secretSink)(nil)

func validRelease(t *testing.T, f *front, priv ed25519.PrivateKey, secrets map[string]string) map[string]string {
	t.Helper()
	return sealForTest(t, f.secrets, priv, map[string]any{"id": f.secrets.text, "config": nil, "secrets": secrets,
		"issuedAt": time.Now().UTC().Format(time.RFC3339Nano)})
}

// Jot: the endpoint is a staged secret. By the time the runtime's first byte is written, the allowlist has been derived
// from the measured config RESOLVED with the released secrets, the forwarder for that origin is listening, /etc/hosts
// names it and nothing else, and the audit has seen exactly that listener. The forwarder then carries the tenant's stream
// to the host naming its OWN origin.
func TestShieldEgressIsUpBeforeTheRuntimeGetsItsSecrets(t *testing.T) {
	f, sink, priv := secretFixture(t)
	w := newEgressWorld(t, `{"bucket":"jot-notes","endpoint":"$R2_ENDPOINT","accessKeyId":"$R2_KEY"}`)
	f.secrets.egress = w.eg
	var checked bool
	sink.onWrite = func() {
		checked = true
		hosts, _ := os.ReadFile(w.eg.hosts)
		if string(hosts) != "127.0.0.1 localhost\n127.64.0.2 acct0123.r2.cloudflarestorage.com\n" {
			t.Errorf("/etc/hosts when the runtime got its secrets:\n%s", hosts)
		}
		a := netip.AddrPortFrom(netip.MustParseAddr("127.64.0.2"), uint16(w.eg.port))
		if len(w.audited) != 1 || w.audited[0] != a {
			t.Errorf("the audit saw %v, want exactly the one forwarder %v", w.audited, a)
		}
		c, err := net.DialTimeout("tcp", a.String(), time.Second)
		if err != nil {
			t.Errorf("the forwarder was not listening when the runtime got its secrets: %v", err)
			return
		}
		c.Write([]byte("tenant TLS ClientHello"))
		select {
		case h := <-w.headers:
			if h != "egress-v1 acct0123.r2.cloudflarestorage.com 443\n" {
				t.Errorf("the forwarder asked the host for %q", h)
			}
		case <-time.After(5 * time.Second):
			t.Error("the forwarder never reached the host's egress endpoint")
		}
		c.Close()
	}
	b := validRelease(t, f, priv, map[string]string{"R2_ENDPOINT": "https://acct0123.r2.cloudflarestorage.com", "R2_KEY": "synthetic"})
	if code := postSecret(f, b); code != 200 || !checked || !sink.closed {
		t.Fatalf("status %d, pipe written %v closed %v", code, checked, sink.closed)
	}
	if !strings.Contains(sink.String(), `"R2_ENDPOINT"`) {
		t.Fatal("the runtime did not get its secrets")
	}
	ready := 0
	for _, l := range w.console() {
		if strings.Contains(l, "acct0123") || strings.Contains(l, "r2.") || strings.Contains(l, "synthetic") || !strings.HasPrefix(l, "DOM ") {
			t.Fatalf("a console line carries config or secret text, or is not a DOM statement: %q", l)
		}
		if strings.Contains(l, "DOM egress: 1 allowed origin(s), 0 config URL(s) refused") {
			ready++
		}
	}
	if ready != 1 {
		t.Fatalf("console %q", w.console())
	}
}

// Every way the egress setup can fail: 503, NOTHING written to the runtime's pipe, the pipe closed (secretrun reads EOF
// and the domain ends), and the release spent.
func TestShieldEgressFailureWritesNothingToTheRuntime(t *testing.T) {
	secrets := map[string]string{"R2_ENDPOINT": "https://acct0123.r2.cloudflarestorage.com"}
	for name, breakIt := range map[string]func(t *testing.T, w *egressWorld){
		"no egress path":         nil,
		"config writable":        func(t *testing.T, w *egressWorld) { os.Chmod(w.eg.config, 0o644) },
		"config another owner's": func(t *testing.T, w *egressWorld) { w.eg.configUID = os.Getuid() + 1 },
		"config a symlink": func(t *testing.T, w *egressWorld) {
			real := w.eg.config + ".real"
			os.Rename(w.eg.config, real)
			os.Symlink(real, w.eg.config)
		},
		"config does not resolve": func(t *testing.T, w *egressWorld) {
			os.Remove(w.eg.config)
			os.WriteFile(w.eg.config, []byte(`not json $R2_ENDPOINT`), 0o444)
		},
		"forwarder cannot bind": func(t *testing.T, w *egressWorld) {
			l, err := net.Listen("tcp", fmt.Sprintf("127.64.0.2:%d", w.eg.port))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { l.Close() })
		},
		"no hosts file":      func(t *testing.T, w *egressWorld) { os.Remove(w.eg.hosts) },
		"hosts not writable": func(t *testing.T, w *egressWorld) { os.Chmod(w.eg.hosts, 0o444) },
		"hosts a symlink": func(t *testing.T, w *egressWorld) {
			real := w.eg.hosts + ".real"
			os.Rename(w.eg.hosts, real)
			os.Symlink(real, w.eg.hosts)
		},
		"listener audit fails": func(t *testing.T, w *egressWorld) {
			w.eg.audit = func([]netip.AddrPort) error { return fmt.Errorf("a UDP socket is bound") }
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, sink, priv := secretFixture(t)
			if breakIt == nil {
				f.secrets.egress = nil
			} else {
				w := newEgressWorld(t, `{"endpoint":"$R2_ENDPOINT"}`)
				breakIt(t, w)
				f.secrets.egress = w.eg
			}
			sink.onWrite = func() { t.Error("the runtime's pipe was written") }
			b := validRelease(t, f, priv, secrets)
			if code := postSecret(f, b); code != 503 || sink.Len() != 0 || !sink.closed {
				t.Fatalf("status %d, %d bytes to the runtime, closed %v", code, sink.Len(), sink.closed)
			}
			if postSecret(f, b) != 409 {
				t.Fatal("a release whose egress failed was not spent")
			}
			if f.secrets.fwd != nil {
				t.Fatal("a forwarder survived a failed setup")
			}
		})
	}
}

// publicWebWorld is newEgressWorld for a domain the monitor marked public-web, its listeners on free loopback ports.
func publicWebWorld(t *testing.T, config string, marker os.FileMode) *egressWorld {
	t.Helper()
	w := newEgressWorld(t, config)
	w.eg.publicWebMarker = filepath.Join(filepath.Dir(w.eg.config), "egress.public-web")
	if marker != 0 {
		if err := os.WriteFile(w.eg.publicWebMarker, []byte("1\n"), marker); err != nil {
			t.Fatal(err)
		}
	}
	w.eg.publicListen, w.eg.dnsListen = "127.0.0.1:0", "127.0.0.1:0"
	return w
}

// A public-web domain: its configured origin's forwarder, the SOCKS front and the DNS stub are all listening and audited
// before the runtime gets a byte, and a tenant's CONNECT (risc-box's handshake: user/password only) reaches the host as
// egress-web-v1 naming exactly that target.
func TestShieldPublicWebIsUpBeforeTheRuntimeGetsItsSecrets(t *testing.T) {
	f, sink, priv := secretFixture(t)
	w := publicWebWorld(t, `{"egress":"public-web","endpoint":"$R2_ENDPOINT"}`, 0o444)
	f.secrets.egress = w.eg
	var checked bool
	sink.onWrite = func() {
		checked = true
		if len(w.audited) != 3 {
			t.Errorf("the audit saw %v, want the forwarder, the SOCKS front and the DNS stub", w.audited)
			return
		}
		c, err := net.DialTimeout("tcp", w.audited[1].String(), time.Second)
		if err != nil {
			t.Errorf("the SOCKS front was not listening when the runtime got its secrets: %v", err)
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		c.Write([]byte{5, 1, 2})
		var b [10]byte
		if _, err := io.ReadFull(c, b[:2]); err != nil || b[0] != 5 || b[1] != 2 {
			t.Errorf("greeting answered % x", b[:2])
			return
		}
		c.Write(append([]byte{1, 5}, append([]byte("guest"), append([]byte{10}, "public-web"...)...)...))
		if _, err := io.ReadFull(c, b[:2]); err != nil || b[0] != 1 || b[1] != 0 {
			t.Errorf("auth answered % x", b[:2])
			return
		}
		c.Write(append(append([]byte{5, 1, 0, 3, 11}, "example.org"...), 0x1f, 0x90))
		select {
		case h := <-w.headers:
			if h != "egress-web-v1 example.org 8080\n" {
				t.Errorf("the SOCKS front asked the host for %q", h)
			}
		case <-time.After(5 * time.Second):
			t.Error("the SOCKS front never reached the host's egress endpoint")
		}
		if _, err := io.ReadFull(c, b[:]); err != nil || b[1] != 4 { // this world's host refuses everything
			t.Errorf("a refused CONNECT answered % x (%v)", b, err)
		}
	}
	if code := postSecret(f, validRelease(t, f, priv, map[string]string{"R2_ENDPOINT": "https://acct0123.r2.cloudflarestorage.com"})); code != 200 || !checked {
		t.Fatalf("status %d, pipe written %v", code, checked)
	}
	hosts, _ := os.ReadFile(w.eg.hosts)
	if !strings.Contains(string(hosts), " acct0123.r2.cloudflarestorage.com\n") {
		t.Fatalf("a public-web domain lost its configured origin: %q", hosts)
	}
	web := 0
	for _, l := range w.console() {
		if strings.Contains(l, "example.org") || strings.Contains(l, "acct0123") || !strings.HasPrefix(l, "DOM ") {
			t.Fatalf("console line %q", l)
		}
		if strings.HasPrefix(l, "DOM egress: public web:") {
			web++
		}
	}
	if web != 1 {
		t.Fatalf("console %q", w.console())
	}
}

// The mode and the monitor's marker must agree, both ways, or the runtime gets nothing.
func TestShieldPublicWebNeedsTheMonitorsMarker(t *testing.T) {
	for name, tc := range map[string]struct {
		config string
		marker os.FileMode
	}{
		"public-web without the marker":   {`{"egress":"public-web"}`, 0},
		"the marker without public-web":   {`{"egress":"public-https"}`, 0o444},
		"a secret cannot set the mode":    {`{"egress":"$MODE"}`, 0o444},
		"a marker the runtime could edit": {`{"egress":"public-web"}`, 0o666},
	} {
		t.Run(name, func(t *testing.T) {
			f, sink, priv := secretFixture(t)
			w := publicWebWorld(t, tc.config, tc.marker)
			f.secrets.egress = w.eg
			sink.onWrite = func() { t.Error("the runtime's pipe was written") }
			if code := postSecret(f, validRelease(t, f, priv, map[string]string{"MODE": "public-web"})); code != 503 || sink.Len() != 0 {
				t.Fatalf("status %d, %d bytes to the runtime", code, sink.Len())
			}
		})
	}
}

// A config with no https URL opens nothing, writes a hosts file naming nothing, and still lets the runtime start.
func TestShieldEgressWithNothingToReach(t *testing.T) {
	f, sink, priv := secretFixture(t)
	w := newEgressWorld(t, `{"greeting":"$GREETING"}`)
	f.secrets.egress = w.eg
	if postSecret(f, validRelease(t, f, priv, map[string]string{"GREETING": "hi"})) != 200 || sink.Len() == 0 {
		t.Fatal("a domain with nothing to reach did not start")
	}
	hosts, _ := os.ReadFile(w.eg.hosts)
	if string(hosts) != "127.0.0.1 localhost\n" || len(w.audited) != 0 {
		t.Fatalf("hosts %q audited %v", hosts, w.audited)
	}
}

// Production wiring: the front cannot make a secret channel without an egress path.
func TestNewShieldSecretsRequiresAnEgressPath(t *testing.T) {
	if _, err := newShieldSecrets(&secretSink{}, "/nonexistent", nil); err == nil || !strings.Contains(err.Error(), "egress") {
		t.Fatalf("newShieldSecrets without egress: %v", err)
	}
}
