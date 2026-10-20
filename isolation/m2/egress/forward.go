package egress

// The wire between the guest's forwarder and the host's egress server (vsock in a guest, any stream in tests):
//
//	guest -> host:  "egress-v1 <host> 443\n"      the LISTENER's bound origin, never bytes the tenant sent
//	host  -> guest: "ok\n" | "refused\n"          then, after ok, raw bytes both ways (the tenant's TLS, end to end)
//
// The tenant never speaks this protocol: it connects to a loopback address that /etc/hosts gave an allowed name,
// the listener there already knows its one origin, and whatever the tenant writes is payload after the header.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	protoVersion = "egress-v1"
	maxHeader    = 300
)

// ---- guest side ----

// Forwarder runs one loopback listener per allowed origin.
type Forwarder struct {
	PublicListen string // test override; empty uses PublicSOCKSAddress
	DNSListen    string // Shield public-web DNS stub; empty uses PublicDNSAddress
	publicAddr   netip.AddrPort
	publicSlots  chan struct{}
	Policy       *Policy
	Port         int                      // 443 in a guest; a free port in tests
	Upstream     func() (net.Conn, error) // a new stream to the host's egress server (vsock to the host CID in a guest)
	Logf         func(string, ...any)     // the guest's own log; never a URL or header, only the origin's index and outcome

	mu    sync.Mutex
	ls    []net.Listener
	addrs map[string]netip.Addr // host -> its loopback address
}

// loopbackFor gives origin i its own address in 127.64.0.0/16 (127/8 is all loopback on Linux).
func loopbackFor(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{127, 64, byte((i + 1) / 250), byte((i+1)%250 + 1)})
}

// HostsFile is /etc/hosts for the guest: ONLY the allowed names, each on its own loopback address, so an unlisted
// name does not resolve at all (the guest has no other resolver).
func (f *Forwarder) HostsFile() string {
	var b strings.Builder
	b.WriteString("127.0.0.1 localhost\n")
	for i, o := range f.Policy.Origins {
		fmt.Fprintf(&b, "%s %s\n", loopbackFor(i), o.Host)
	}
	return b.String()
}

// Start binds every listener and serves until ctx ends. A bind failure is fatal: a guest that could not enforce its
// allowlist must not start the tenant.
func (f *Forwarder) Start(ctx context.Context) error {
	if f.Policy == nil || (f.Policy.PublicHTTPS && f.Policy.PublicWeb) {
		return errors.New("egress requires one unambiguous policy")
	}
	f.addrs = map[string]netip.Addr{}
	for i, o := range f.Policy.Origins {
		a := loopbackFor(i)
		l, err := net.Listen("tcp", netip.AddrPortFrom(a, uint16(f.Port)).String())
		if err != nil {
			f.Close()
			return fmt.Errorf("egress listener %d: %w", i, err)
		}
		f.mu.Lock()
		f.ls = append(f.ls, l)
		f.addrs[o.Host] = a
		f.mu.Unlock()
		go f.serve(ctx, l, i, o)
	}
	if f.Policy.PublicHTTPS {
		if err := f.startPublic(ctx); err != nil {
			f.Close()
			return err
		}
	}
	if f.Policy.PublicWeb {
		if err := f.startPublicWeb(ctx); err != nil {
			f.Close()
			return err
		}
	}
	go func() { <-ctx.Done(); f.Close() }()
	return nil
}

func (f *Forwarder) track(l net.Listener) {
	f.mu.Lock()
	f.ls = append(f.ls, l)
	f.mu.Unlock()
}

// Listeners is every address this forwarder listens on: what the guest's listener audit must find, and nothing else.
func (f *Forwarder) Listeners() []netip.AddrPort {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]netip.AddrPort, 0, len(f.ls))
	for _, l := range f.ls {
		out = append(out, l.Addr().(*net.TCPAddr).AddrPort())
	}
	return out
}

// Addr is where the tenant reaches an origin (what /etc/hosts says), for tests and the guest's self-check.
func (f *Forwarder) Addr(host string) (netip.AddrPort, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.addrs[host]
	return netip.AddrPortFrom(a, uint16(f.Port)), ok
}

func (f *Forwarder) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, l := range f.ls {
		l.Close()
	}
	f.ls = nil
}

func (f *Forwarder) serve(ctx context.Context, l net.Listener, idx int, o Origin) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go f.forward(c, idx, o)
	}
}

func (f *Forwarder) forward(tenant net.Conn, idx int, o Origin) {
	defer tenant.Close()
	up, err := DialOrigin(f.Upstream, o)
	if err != nil {
		f.logf("egress origin #%d: %s", idx, dialClass(err))
		return
	}
	defer up.Close()
	splice(tenant, tenant, up, up) // up's reader already holds anything the host sent after "ok"
}

// DialOrigin opens one stream to origin o through the host: the header for THIS origin, the host's "ok", then a
// connection the caller runs TLS over (the forwarder for the tenant; the front for its own release). The caller
// never writes a byte before the host has accepted the header. Its errors name no origin.
// DialOrigin's failures, a CLOSED set: the guest front logs which one (dialClass), and nothing else of an error, so no
// error type added later can carry content to the console (enclave-e3's L1 on the console guard).
var (
	errNoPath     = errors.New("no path to the host")
	errPathFailed = errors.New("the host's egress path failed")
	errRefused    = errors.New("refused by the host")
)

// dialClass is what the guest may log about a DialOrigin failure: one of the closed set above, else "failed".
func dialClass(err error) string {
	for _, e := range []error{errNoPath, errPathFailed, errRefused} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return "failed"
}

func DialOrigin(upstream func() (net.Conn, error), o Origin) (net.Conn, error) {
	up, err := upstream()
	if err != nil {
		return nil, errNoPath
	}
	up.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := fmt.Fprintf(up, "%s %s 443\n", protoVersion, o.Host); err != nil {
		up.Close()
		return nil, errPathFailed
	}
	br := bufio.NewReaderSize(up, 64)
	line, err := br.ReadString('\n')
	if err != nil || line != "ok\n" {
		up.Close()
		return nil, errRefused
	}
	up.SetDeadline(time.Time{})
	return &bufConn{Conn: up, r: br}, nil
}

// bufConn reads what the header exchange already buffered before reading the stream again.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// CloseWrite keeps splice's half-close: the wrapper would otherwise hide the stream's own CloseWrite, and a tenant
// that shut its write side would lose the reply still coming back.
func (c *bufConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

func (f *Forwarder) logf(format string, a ...any) {
	if f.Logf != nil {
		f.Logf(format, a...)
	}
}

// ---- host side ----

// Server is the host's egress endpoint: one per host, serving every guest; `cidOf` says which guest a stream is
// from (the vsock peer CID), so the dialer's per-guest caps apply.
//
// What the host OBSERVES and what it RECORDS are different things, and both are stated plainly. Forwarding
// necessarily shows the host each connection's destination hostname (it resolves it, so its DNS resolver sees the
// query too), the address it dials, the port, and the timing and volume: this is controlled egress, not
// traffic-analysis privacy. But a destination can come from a secret (the owner's config resolves secret values into
// URLs), so the log RECORDS only the guest's CID and a bounded outcome code - "open" or "refused:<Reason>" - never the
// hostname, an address or a raw network error (Codex's review of f109bf8d).
type Server struct {
	Dialer *Dialer
	CIDOf  func(net.Conn) uint32
	Admit  func(cid uint32) bool // only guests the host's manager launched (guestd admitCID); anything else is refused
	Log    *log.Logger           // "guest <cid> egress open|refused:<reason>", and "egress accept: <errno>" on a transient accept failure
}

// Serve refuses to start without CIDOf: with no way to tell guests apart, every guest would share ONE set of caps
// and one guest could starve the rest (enclave-99).
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	if s.CIDOf == nil {
		return errors.New("egress server: CIDOf is required (per-guest caps need to know which guest a stream is from)")
	}
	if s.Dialer == nil {
		return errors.New("egress server: no dialer")
	}
	if s.Admit == nil {
		// any VM on the host can reach this vsock port; only the manager's own guests may use it (enclave-99)
		return errors.New("egress server: Admit is required (it serves only the guests the host's manager launched)")
	}
	go func() { <-ctx.Done(); l.Close() }()
	backoff := 5 * time.Millisecond
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return err
			}
			// EMFILE, ECONNABORTED, ...: transient. Returning would end the host's manager, and with it every guest it
			// is starting (enclave-99), so wait and accept again. The notice names the error only, never a guest's.
			if s.Log != nil {
				s.Log.Printf("egress accept: %v (retrying in %s)", err, backoff)
			}
			time.Sleep(backoff)
			if backoff *= 2; backoff > time.Second {
				backoff = time.Second
			}
			continue
		}
		backoff = 5 * time.Millisecond
		go s.handle(ctx, c)
	}
}

func (s *Server) handle(ctx context.Context, g net.Conn) {
	defer g.Close()
	cid := s.CIDOf(g)
	if !s.Admit(cid) {
		s.outcome(cid, "refused:"+string(ReasonAdmit)) // before a byte of its header is read
		io.WriteString(g, "refused\n")
		return
	}
	g.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReaderSize(g, maxHeader)
	if _, err := br.Peek(1); err != nil {
		s.outcome(cid, "refused:"+string(ReasonEmpty)) // opened and closed with nothing said: not a malformed header
		return
	}
	line, err := readLine(br, maxHeader)
	if err != nil {
		s.outcome(cid, "refused:"+string(ReasonHeader))
		return
	}
	g.SetReadDeadline(time.Time{})
	f := strings.Fields(line)
	if len(f) == 3 && (f[0] == webProto || f[0] == dnsProto) {
		s.handleWeb(ctx, cid, g, br, f)
		return
	}
	if len(f) != 3 || f[0] != protoVersion || f[2] != "443" {
		s.outcome(cid, "refused:"+string(ReasonHeader))
		io.WriteString(g, "refused\n")
		return
	}
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	up, release, err := s.Dialer.Dial(dctx, cid, f[1], 443)
	cancel()
	if err != nil {
		s.outcome(cid, "refused:"+string(ReasonOf(err)))
		io.WriteString(g, "refused\n")
		return
	}
	defer release()
	defer up.Close()
	s.outcome(cid, "open")
	if _, err := io.WriteString(g, "ok\n"); err != nil {
		return
	}
	splice(g, br, up, up) // br holds anything the guest sent after its header
}

// outcome is the server's ONLY log line. Its arguments are the CID and a code from a fixed set; there is no format
// string to pass a hostname or an error through.
func (s *Server) outcome(cid uint32, code string) {
	if s.Log != nil {
		s.Log.Printf("guest %d egress %s", cid, code)
	}
}

func readLine(br *bufio.Reader, max int) (string, error) {
	var b strings.Builder
	for b.Len() < max {
		c, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		if c == '\n' {
			return b.String(), nil
		}
		b.WriteByte(c)
	}
	return "", errors.New("header too long")
}

// splice copies both ways until either side ends. Each side has its own reader (ar reads a, br reads b), so bytes
// a bufio.Reader already buffered from one side are delivered to the OTHER side, never echoed back.
func splice(a net.Conn, ar io.Reader, b net.Conn, br io.Reader) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(b, ar); closeWrite(b); done <- struct{}{} }()
	go func() { io.Copy(a, br); closeWrite(a); done <- struct{}{} }()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}
