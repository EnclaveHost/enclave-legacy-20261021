package main

// End to end on one Linux host, every hop real except the two that need a partition:
//
//	tenant (net/http, TLS to the real name) -> what /etc/hosts says: the guest's egress.Forwarder on 127.64.0.N
//	  -> [a TCP stream standing in for AF_VSOCK + hv_sock + shielded-bridge, which relays bytes unchanged]
//	  -> run(): this program's flags, Server and Dialer -> a SOCKS5 test entry on loopback
//	  -> a local TLS origin standing in for the R2 endpoint.
//
// The SOCKS entry maps the judged PUBLIC literal it is asked for to the local origin, which is how the test reaches a
// "public" address without leaving the host; it also records every request, so the tests see exactly what the host asked.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"enclave.host/isolation/m2/egress"
)

// ---- a CA and a TLS origin ----

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "shield-egress test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// origin is an HTTPS server for `name` that stores what is PUT to it.
type origin struct {
	ln     net.Listener
	mu     sync.Mutex
	stored map[string]string
}

func newOrigin(t *testing.T, ca *testCA, name string) *origin {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	o := &origin{ln: ln, stored: map[string]string{}}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "PUT only", 405)
			return
		}
		b, _ := io.ReadAll(r.Body)
		o.mu.Lock()
		o.stored[r.URL.Path] = string(b)
		o.mu.Unlock()
		fmt.Fprintf(w, "stored %d", len(b))
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return o
}

// ---- a SOCKS5 entry ----

type socksEntry struct {
	ln    net.Listener
	route map[string]string // judged literal "ip:443" -> where the test origin really is
	mu    sync.Mutex
	asked []string // "ipv4 93.184.216.34:443", "name x.example:443", ...
}

func newSOCKS(t *testing.T, route map[string]string) *socksEntry {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &socksEntry{ln: ln, route: route}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *socksEntry) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.asked...)
}

func (s *socksEntry) handle(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 3)
	if _, err := io.ReadFull(c, b); err != nil || !bytes.Equal(b, []byte{5, 1, 0}) {
		return
	}
	c.Write([]byte{5, 0})
	h := make([]byte, 4)
	if _, err := io.ReadFull(c, h); err != nil || h[0] != 5 || h[1] != 1 {
		return
	}
	var kind, addr string
	switch h[3] {
	case 1, 4:
		ip := make([]byte, map[byte]int{1: 4, 4: 16}[h[3]])
		io.ReadFull(c, ip)
		a, _ := netip.AddrFromSlice(ip)
		kind, addr = map[byte]string{1: "ipv4", 4: "ipv6"}[h[3]], a.String()
	case 3:
		n := make([]byte, 1)
		io.ReadFull(c, n)
		name := make([]byte, n[0])
		io.ReadFull(c, name)
		kind, addr = "name", string(name)
	default:
		return
	}
	p := make([]byte, 2)
	io.ReadFull(c, p)
	target := net.JoinHostPort(addr, fmt.Sprint(binary.BigEndian.Uint16(p)))
	s.mu.Lock()
	s.asked = append(s.asked, kind+" "+target)
	s.mu.Unlock()
	to, ok := s.route[target]
	var up net.Conn
	var err error
	if ok {
		up, err = net.Dial("tcp", to)
	}
	if !ok || err != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}) // connection refused
		return
	}
	defer up.Close()
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	c.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, c); done <- struct{}{} }()
	go func() { io.Copy(c, up); done <- struct{}{} }()
	<-done
}

// ---- this program, in-process ----

type fakeDNS map[string][]string

func (f fakeDNS) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	ips, ok := f[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	var out []netip.Addr
	for _, s := range ips {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type running struct {
	addr  string
	log   *syncBuf
	stdin *io.PipeWriter
	done  chan error
}

// start runs shield-egress with args (plus -listen 127.0.0.1:0) until the test ends or stdin is closed.
func start(t *testing.T, args ...string) *running {
	t.Helper()
	pr, pw := io.Pipe()
	outR, outW := io.Pipe()
	r := &running{log: &syncBuf{}, stdin: pw, done: make(chan error, 1)}
	go func() {
		r.done <- run(context.Background(), append([]string{"-listen", "127.0.0.1:0"}, args...), pr, outW, r.log)
		outW.Close()
	}()
	line, err := bufio.NewReader(outR).ReadString('\n')
	if err != nil {
		t.Fatalf("no ready line: %v (log %q)", err, r.log.String())
	}
	f := strings.Fields(line)
	if len(f) < 3 || f[0] != "shield-egress" || f[1] != "ready" || !strings.HasPrefix(f[2], "listen=") {
		t.Fatalf("ready line %q", line)
	}
	r.addr = strings.TrimPrefix(f[2], "listen=")
	go io.Copy(io.Discard, outR)
	t.Cleanup(func() { pw.Close() })
	return r
}

// guest is the domain's side: a forwarder per allowed origin, whose upstream is a plain TCP stream to shield-egress
// (in a partition: AF_VSOCK to CID 2 port 9443, which shielded-bridge relays to the same address byte for byte).
func guest(t *testing.T, to string, origins ...string) *egress.Forwarder {
	t.Helper()
	probe, err := net.Listen("tcp", "127.64.0.1:0")
	if err != nil {
		t.Skipf("no 127.64.0.0/16 loopback here: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	p := &egress.Policy{}
	for _, o := range origins {
		p.Origins = append(p.Origins, egress.Origin{Host: o})
	}
	f := &egress.Forwarder{Policy: p, Port: port, Upstream: func() (net.Conn, error) { return net.Dial("tcp", to) }}
	ctx, cancel := context.WithCancel(context.Background())
	if err := f.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(cancel)
	return f
}

// tenant is the app: it resolves names the way /etc/hosts in its domain does (the forwarder's address, or nothing) and
// runs TLS to the real name itself.
func tenant(f *egress.Forwarder, ca *testCA) *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: ca.pool},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(addr)
			a, ok := f.Addr(host)
			if !ok {
				return nil, errors.New("no such host in /etc/hosts")
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", a.String())
		}}}
}

func put(c *http.Client, url, body string) (string, error) {
	req, _ := http.NewRequest(http.MethodPut, url, strings.NewReader(body))
	res, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		return "", fmt.Errorf("status %d", res.StatusCode)
	}
	return string(b), nil
}

func withDNS(t *testing.T, dns fakeDNS) {
	t.Helper()
	old := lookup
	lookup = dns
	t.Cleanup(func() { lookup = old })
}

// eventually waits for the server's one outcome line for a stream.
func eventually(t *testing.T, log *syncBuf, want string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if strings.Contains(log.String(), want) {
			return
		}
	}
	t.Fatalf("no %q in the log: %q", want, log.String())
}

const public = "93.184.216.34"

func TestAJotWriteReachesTheOriginThroughForwarderServerAndSOCKSOnly(t *testing.T) {
	ca := newCA(t)
	o := newOrigin(t, ca, "notes.example")
	withDNS(t, fakeDNS{"notes.example": {public}})
	socks := newSOCKS(t, map[string]string{public + ":443": o.ln.Addr().String()})
	r := start(t, "-socks", socks.ln.Addr().String())
	f := guest(t, r.addr, "notes.example")
	got, err := put(tenant(f, ca), "https://notes.example/jot/note-1?X-Amz-Signature=synthetic", "hello from a partition")
	if err != nil {
		t.Fatal(err)
	}
	if got != "stored 22" || o.stored["/jot/note-1"] != "hello from a partition" {
		t.Fatalf("origin answered %q, stored %v", got, o.stored)
	}
	if q := socks.requests(); len(q) != 1 || q[0] != "ipv4 "+public+":443" {
		t.Fatalf("the SOCKS entry was asked %v: it must be asked for the JUDGED literal only, never a name", q)
	}
	eventually(t, r.log, "guest 1 egress open")
	for _, leak := range []string{"notes.example", public, "/jot", "note-1", "X-Amz", "hello", "127.0.0.1"} {
		if strings.Contains(r.log.String(), leak) {
			t.Fatalf("the host log carries %q: %q", leak, r.log.String())
		}
	}
}

func TestNonPublicAnswersAreRefusedAndTheEntryIsNeverAsked(t *testing.T) {
	ca := newCA(t)
	cases := fakeDNS{"loop.example": {"127.0.0.1"}, "private.example": {"10.0.0.7"}, "meta.example": {"169.254.169.254"},
		"cgnat.example": {"100.64.1.1"}, "mixed.example": {public, "192.168.1.1"}, "v6loop.example": {"::1"},
		"mapped.example": {"::ffff:10.1.1.1"}, "nat64.example": {"64:ff9b::a00:1"}}
	withDNS(t, cases)
	o := newOrigin(t, ca, "unused.example")
	socks := newSOCKS(t, map[string]string{public + ":443": o.ln.Addr().String()})
	r := start(t, "-socks", socks.ln.Addr().String())
	var names []string
	for n := range cases {
		names = append(names, n)
	}
	f := guest(t, r.addr, names...)
	c := tenant(f, ca)
	for _, n := range names {
		if _, err := put(c, "https://"+n+"/x", "secret note"); err == nil {
			t.Fatalf("%s: a write reached a non-public answer", n)
		}
	}
	eventually(t, r.log, "refused:non-public-answer")
	if n := strings.Count(r.log.String(), "refused:non-public-answer"); n != len(names) {
		t.Fatalf("%d of %d refused as non-public: %q", n, len(names), r.log.String())
	}
	if q := socks.requests(); len(q) != 0 {
		t.Fatalf("the SOCKS entry was asked %v for a name with a non-public answer", q)
	}
}

// The entry down: the stream is refused (connect) and nothing else is tried. That nothing is dialed DIRECTLY is proven
// at the dialer, where the direct path can be observed (egress socks_test.go, shield_test.go); here the outcome is end to end.
func TestTheSOCKSEntryDownIsARefusalNeverAFallback(t *testing.T) {
	ca := newCA(t)
	withDNS(t, fakeDNS{"notes.example": {public}})
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()
	r := start(t, "-socks", deadAddr)
	f := guest(t, r.addr, "notes.example")
	if _, err := put(tenant(f, ca), "https://notes.example/jot/n", "x"); err == nil {
		t.Fatal("a write succeeded with the SOCKS entry down")
	}
	eventually(t, r.log, "guest 1 egress refused:connect")
	if strings.Contains(r.log.String(), "egress open") {
		t.Fatal("a stream opened with the entry down")
	}
}

func TestTheHostSideListNarrowsWhatTheGuestMayReach(t *testing.T) {
	ca := newCA(t)
	o := newOrigin(t, ca, "notes.example")
	other := newOrigin(t, ca, "other.example")
	withDNS(t, fakeDNS{"notes.example": {public}, "other.example": {"93.184.216.35"}})
	socks := newSOCKS(t, map[string]string{public + ":443": o.ln.Addr().String(), "93.184.216.35:443": other.ln.Addr().String()})
	r := start(t, "-socks", socks.ln.Addr().String(), "-allow", "https://notes.example")
	f := guest(t, r.addr, "notes.example", "other.example")
	c := tenant(f, ca)
	if _, err := put(c, "https://other.example/x", "x"); err == nil {
		t.Fatal("a name off the host's list was reached")
	}
	eventually(t, r.log, "refused:not-allowed")
	if got, err := put(c, "https://notes.example/jot/n", "ok"); err != nil || got != "stored 2" {
		t.Fatalf("the listed name: %q %v", got, err)
	}
	if q := socks.requests(); len(q) != 1 || q[0] != "ipv4 "+public+":443" {
		t.Fatalf("SOCKS asked %v", q)
	}
}

// A guest that speaks egress-v1 itself (not through a forwarder) gets nothing the m2 rules refuse.
func TestTheProtocolRefusesWhatAGuestCouldAskForDirectly(t *testing.T) {
	withDNS(t, fakeDNS{})
	socks := newSOCKS(t, nil)
	r := start(t, "-socks", socks.ln.Addr().String())
	for hdr, code := range map[string]string{
		"egress-v1 10.0.0.1 443\n":         "refused:name",
		"egress-v1 127.0.0.1 443\n":        "refused:name",
		"egress-v1 [::1] 443\n":            "refused:name",
		"egress-v1 localhost 443\n":        "refused:name",
		"egress-v1 notes.example 80\n":     "refused:header",
		"CONNECT notes.example:443 HTTP\n": "refused:header",
		"egress-v1 nowhere.example 443\n":  "refused:resolve",
	} {
		before := strings.Count(r.log.String(), code)
		c, err := net.Dial("tcp", r.addr)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(c, hdr)
		got, _ := bufio.NewReader(c).ReadString('\n')
		c.Close()
		if got != "refused\n" {
			t.Fatalf("%q answered %q", hdr, got)
		}
		eventually(t, r.log, code)
		if strings.Count(r.log.String(), code) != before+1 {
			t.Fatalf("%q: want one more %s: %q", hdr, code, r.log.String())
		}
	}
	if q := socks.requests(); len(q) != 0 {
		t.Fatalf("SOCKS asked %v", q)
	}
}

func TestFlagsThatWouldOpenADirectOrNonLoopbackPathAreRefused(t *testing.T) {
	for _, args := range [][]string{
		{}, // no upstream: there is no direct path
		{"-listen", "0.0.0.0:0", "-socks", "127.0.0.1:30489"},     // listening beyond loopback
		{"-listen", "192.168.1.5:0", "-socks", "127.0.0.1:30489"}, // likewise
		{"-socks", "10.0.0.1:1080"},                               // a SOCKS entry off this host
		{"-socks", "proxy.example:1080"},                          // a name: no resolution for the entry
		{"-socks", "127.0.0.1:30489", "-app-routes", "routes.json", "-deployment", "0x" + strings.Repeat("a", 64)},
		{"-app-routes", "routes.json"},                              // a route belongs to a deployment
		{"-app-routes", "routes.json", "-deployment", "0xA77D0C57"}, // not a deployment id
		{"-socks", "127.0.0.1:30489", "-deployment", "0x" + strings.Repeat("a", 64)},
		{"-socks", "127.0.0.1:30489", "-allow", "http://notes.example"}, // not https
		{"-socks", "127.0.0.1:30489", "-allow", "https://10.0.0.1"},     // not a DNS name
		{"-socks", "127.0.0.1:30489", "extra"},
	} {
		if err := run(context.Background(), args, strings.NewReader(""), io.Discard, io.Discard); err == nil {
			t.Fatalf("%q accepted", args)
		}
	}
	// a well-formed routes configuration parses (its file is read per stream, and a missing one refuses the stream)
	if _, err := parse([]string{"-app-routes", "routes.json", "-deployment", "0x" + strings.Repeat("a", 64)}, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestAMissingRoutesFileRefusesEveryStream(t *testing.T) {
	withDNS(t, fakeDNS{"notes.example": {public}})
	r := start(t, "-app-routes", t.TempDir()+"/absent.json", "-deployment", "0x"+strings.Repeat("a7", 32))
	c, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, "egress-v1 notes.example 443\n")
	got, _ := bufio.NewReader(c).ReadString('\n')
	c.Close()
	if got != "refused\n" {
		t.Fatalf("answered %q", got)
	}
	eventually(t, r.log, "guest 1 egress refused:admit")
}

func TestStdinEOFEndsTheProcess(t *testing.T) {
	socks := newSOCKS(t, nil)
	r := start(t, "-socks", socks.ln.Addr().String())
	r.stdin.Close()
	select {
	case err := <-r.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still running after its stdin closed")
	}
	if c, err := net.DialTimeout("tcp", r.addr, time.Second); err == nil {
		c.Close()
		t.Fatal("still accepting after its stdin closed")
	}
}
