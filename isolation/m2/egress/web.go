package egress

// Public web egress: an owner's "egress": "public-web" in a NucBox Shield domain's MEASURED config opens the public
// internet to the domain over TCP, through the deployment's own route on the host. The guest still has no NIC:
//
//	app -> ENCLAVE_EGRESS socks5 127.0.0.2:1080 (this front) -> "egress-web-v1 <host|ip> <port>" -> host -> route
//	app's getaddrinfo -> /etc/resolv.conf 127.0.0.2:53 (TCP, use-vc) -> "egress-dns-v1 <name> 0" -> host DoH -> route
//
// On the same vsock stream as egress-v1 (forward.go): one header line, then "ok" (followed by raw bytes for a
// connection, or by the addresses for a lookup) or "refused". What stays enforced:
//   - only PUBLIC addresses, on both sides: an IP literal, every DNS answer and the address actually dialed are
//     judged by RefuseAddr (loopback, private, link-local and metadata, CGNAT, NAT64/6to4/Teredo, ... and the host's
//     own addresses);
//   - a plain DNS name (ParseOrigin's rules) or an IP literal, never anything else; TCP only (TUNA carries no UDP),
//     any port except 0 and 25 (SMTP, which the route's exits refuse anyway);
//   - the configured origins keep their egress-v1 forwarders and /etc/hosts entries, so a wasi:http app's configured
//     names behave exactly as before;
//   - the host's log records the guest and an outcome code, never a destination.

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const (
	PublicDNSAddress = "127.0.0.2:53"

	webProto = "egress-web-v1"
	dnsProto = "egress-dns-v1"

	publicSOCKSSlots = 64 // concurrent tenant connections through the SOCKS front
	publicDNSSlots   = 16 // concurrent DNS connections
	maxDNSAnswers    = 16
)

func validWebPort(port int) bool { return port >= 1 && port <= 65535 && port != 25 }

// validWebHost: a plain DNS name by ParseOrigin's rules, or (allowIP) a PUBLIC IP literal.
func validWebHost(host string, allowIP bool) bool {
	if a, err := netip.ParseAddr(host); err == nil {
		return allowIP && a.Zone() == "" && RefuseAddr(a, nil) == ""
	}
	o, err := ParseOrigin("https://" + host + "/")
	return err == nil && strings.EqualFold(o.Host, host)
}

// ---- guest side ----

// startPublicWeb binds the SOCKS front and the DNS stub. A bind failure is fatal to the domain's egress (Start).
func (f *Forwarder) startPublicWeb(ctx context.Context) error {
	socks, err := net.Listen("tcp", orDefault(f.PublicListen, PublicSOCKSAddress))
	if err != nil {
		return errors.New("public web SOCKS listener unavailable")
	}
	f.track(socks)
	dns, err := net.Listen("tcp", orDefault(f.DNSListen, PublicDNSAddress))
	if err != nil {
		return errors.New("public web DNS listener unavailable")
	}
	f.track(dns)
	go acceptBounded(ctx, socks, publicSOCKSSlots, f.publicWebConnect)
	go acceptBounded(ctx, dns, publicDNSSlots, f.serveDNS)
	return nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// acceptBounded serves each connection on its own goroutine, at most `slots` at once; one over that is closed.
func acceptBounded(ctx context.Context, l net.Listener, slots int, serve func(net.Conn)) {
	busy := make(chan struct{}, slots)
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		select {
		case busy <- struct{}{}:
			go func() {
				defer func() { <-busy }()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				serve(c)
			}()
		default:
			c.Close()
		}
	}
}

// SOCKS5 replies (RFC 1928 section 6).
const (
	socksOK          = 0
	socksNotAllowed  = 2
	socksUnreachable = 4
	socksBadCommand  = 7
	socksBadAddrType = 8
)

// publicWebConnect is one SOCKS5 session: no-auth or RFC 1929 user/password (any pair: it is framing, not
// authentication), then CONNECT to a name or a public IP on a web port. Every read before the upstream exists is
// bounded in size and time, and nothing reaches the host before the request has passed validWebHost/validWebPort.
func (f *Forwarder) publicWebConnect(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 5 || h[1] == 0 {
		return
	}
	methods := make([]byte, int(h[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	method := byte(255)
	for _, m := range methods {
		if m == 2 || (m == 0 && method != 2) {
			method = m
		}
	}
	if _, err := c.Write([]byte{5, method}); err != nil || method == 255 {
		return
	}
	if method == 2 {
		if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 1 {
			return
		}
		if _, err := io.CopyN(io.Discard, c, int64(h[1])); err != nil { // the user name
			return
		}
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return
		}
		if _, err := io.CopyN(io.Discard, c, int64(n[0])); err != nil { // the password
			return
		}
		if _, err := c.Write([]byte{1, 0}); err != nil {
			return
		}
	}
	reply := func(code byte) { c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}) }
	host, port, code := readSOCKSTarget(c)
	if code != socksOK {
		reply(code)
		return
	}
	up, err := dialPublicWeb(f.Upstream, host, port)
	if err != nil {
		f.logf("public web: %s", dialClass(err))
		reply(socksUnreachable)
		return
	}
	defer up.Close()
	reply(socksOK)
	c.SetDeadline(time.Time{})
	splice(c, c, up, up)
}

// readSOCKSTarget reads a CONNECT request: the target (lowercased name, or an IP in canonical text) and port, or the
// reply code that refuses it.
func readSOCKSTarget(c net.Conn) (string, int, byte) {
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 5 || h[2] != 0 {
		return "", 0, socksNotAllowed
	}
	if h[1] != 1 {
		return "", 0, socksBadCommand // CONNECT only: no BIND, no UDP ASSOCIATE
	}
	var host string
	switch h[3] {
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil || n[0] == 0 {
			return "", 0, socksNotAllowed
		}
		b := make([]byte, int(n[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, socksNotAllowed
		}
		host = strings.ToLower(string(b))
		if a, err := netip.ParseAddr(host); err == nil { // a literal sent as a name is judged as the literal
			host = a.Unmap().String()
		}
	case 1, 4:
		b := make([]byte, map[byte]int{1: 4, 4: 16}[h[3]])
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, socksNotAllowed
		}
		a, _ := netip.AddrFromSlice(b)
		host = a.Unmap().String()
	default:
		return "", 0, socksBadAddrType
	}
	var p [2]byte
	if _, err := io.ReadFull(c, p[:]); err != nil {
		return "", 0, socksNotAllowed
	}
	port := int(binary.BigEndian.Uint16(p[:]))
	if !validWebPort(port) || !validWebHost(host, true) {
		return "", 0, socksNotAllowed
	}
	return host, port, socksOK
}

// dialPublicWeb opens one connection through the host: the header, the host's "ok", then raw bytes.
func dialPublicWeb(upstream func() (net.Conn, error), host string, port int) (net.Conn, error) {
	if !validWebPort(port) || !validWebHost(host, true) {
		return nil, errRefused
	}
	up, err := upstream()
	if err != nil {
		return nil, errNoPath
	}
	up.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := fmt.Fprintf(up, "%s %s %d\n", webProto, host, port); err != nil {
		up.Close()
		return nil, errPathFailed
	}
	br := bufio.NewReaderSize(up, 64)
	line, err := readLine(br, 64)
	if err != nil || line != "ok" {
		up.Close()
		return nil, errRefused
	}
	up.SetDeadline(time.Time{})
	return &bufConn{Conn: up, r: br}, nil
}

// serveDNS answers DNS over TCP (RFC 7766 framing: a two-byte length before each message); glibc uses TCP because
// resolv.conf says use-vc. At most 16 queries per connection, each bounded in size and time.
func (f *Forwarder) serveDNS(c net.Conn) {
	defer c.Close()
	for i := 0; i < 16; i++ {
		c.SetDeadline(time.Now().Add(30 * time.Second))
		var n [2]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return
		}
		length := int(binary.BigEndian.Uint16(n[:]))
		if length < 12 || length > 4096 {
			return
		}
		q := make([]byte, length)
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		answer := answerPublicDNS(q, f.lookupPublic)
		if answer == nil {
			return
		}
		binary.BigEndian.PutUint16(n[:], uint16(len(answer)))
		if _, err := c.Write(append(n[:], answer...)); err != nil {
			return
		}
	}
}

// lookupPublic asks the host for a name's public addresses.
func (f *Forwarder) lookupPublic(name string) ([]netip.Addr, error) {
	up, err := f.Upstream()
	if err != nil {
		return nil, errNoPath
	}
	defer up.Close()
	up.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := fmt.Fprintf(up, "%s %s 0\n", dnsProto, name); err != nil {
		return nil, errPathFailed
	}
	line, err := readLine(bufio.NewReaderSize(up, 64), 1024)
	fields := strings.Fields(line)
	if err != nil || len(fields) < 2 || fields[0] != "ok" || len(fields) > maxDNSAnswers+1 {
		return nil, errRefused
	}
	var out []netip.Addr
	for _, s := range fields[1:] {
		a, err := netip.ParseAddr(s)
		if err != nil || RefuseAddr(a, nil) != "" { // the guest judges the host's answers too
			return nil, errRefused
		}
		out = append(out, a.Unmap())
	}
	return out, nil
}

// answerPublicDNS builds the reply to one query, or nil for a message that is not a plain one-question query (the
// connection is then closed). A and AAAA are answered from `lookup`; other types get an empty NOERROR; a name that is
// not a plain public DNS name gets NXDOMAIN; a failed lookup gets SERVFAIL.
func answerPublicDNS(q []byte, lookup func(string) ([]netip.Addr, error)) []byte {
	if len(q) < 12 || q[2]&0xf8 != 0 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return nil // a response, a non-QUERY opcode, or not exactly one question
	}
	i := 12
	var labels []string
	for {
		if i >= len(q) {
			return nil
		}
		n := int(q[i])
		i++
		if n == 0 {
			break
		}
		if n > 63 || i+n > len(q) {
			return nil // a compression pointer or a truncated label
		}
		labels = append(labels, string(q[i:i+n]))
		i += n
		if i > 12+255 {
			return nil
		}
	}
	if i+4 > len(q) {
		return nil
	}
	kind := binary.BigEndian.Uint16(q[i : i+2])
	class := binary.BigEndian.Uint16(q[i+2 : i+4])
	i += 4
	resp := append([]byte(nil), q[:i]...)
	resp[2] = 0x80 | (q[2] & 1) // QR, RD as asked
	resp[3] = 0x80              // RA
	for j := 6; j < 12; j++ {
		resp[j] = 0 // no answer, authority or additional records yet
	}
	name := strings.ToLower(strings.Join(labels, "."))
	if class != 1 || !validWebHost(name, false) {
		resp[3] |= 3 // NXDOMAIN
		return resp
	}
	if kind != 1 && kind != 28 {
		return resp // NOERROR, no data
	}
	addresses, err := lookup(name)
	if err != nil {
		resp[3] |= 2 // SERVFAIL
		return resp
	}
	var count uint16
	for _, a := range addresses {
		if (kind == 1) != a.Is4() {
			continue
		}
		count++
		resp = append(resp, 0xc0, 0x0c) // the question's name
		resp = binary.BigEndian.AppendUint16(resp, kind)
		resp = append(resp, 0, 1, 0, 0, 0, 30) // IN, TTL 30 s: the host caches for the record's own TTL
		b := a.AsSlice()
		resp = binary.BigEndian.AppendUint16(resp, uint16(len(b)))
		resp = append(resp, b...)
	}
	binary.BigEndian.PutUint16(resp[6:8], count)
	return resp
}

// ---- host side ----

// handleWeb serves one egress-web-v1 or egress-dns-v1 stream whose header is already read.
func (s *Server) handleWeb(ctx context.Context, cid uint32, g net.Conn, br *bufio.Reader, fields []string) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if fields[0] == dnsProto {
		if fields[2] != "0" {
			s.outcome(cid, "refused:"+string(ReasonHeader))
			io.WriteString(g, "refused\n")
			return
		}
		addresses, err := s.Dialer.ResolvePublic(ctx, cid, fields[1])
		if err != nil {
			s.outcome(cid, "refused:"+string(ReasonOf(err)))
			io.WriteString(g, "refused\n")
			return
		}
		names := make([]string, len(addresses))
		for i, a := range addresses {
			names[i] = a.Unmap().String()
		}
		s.outcome(cid, "resolved")
		io.WriteString(g, "ok "+strings.Join(names, " ")+"\n")
		return
	}
	port, err := strconv.Atoi(fields[2])
	if err != nil || strconv.Itoa(port) != fields[2] {
		s.outcome(cid, "refused:"+string(ReasonHeader))
		io.WriteString(g, "refused\n")
		return
	}
	up, release, err := s.Dialer.DialWeb(ctx, cid, fields[1], port)
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
	splice(g, br, up, up)
}

// DialWeb opens a TCP connection for guest `cid` to a public host:port, by name (resolved and judged as Dial does) or
// by a public IP literal. The release func MUST be called when the connection ends.
func (d *Dialer) DialWeb(ctx context.Context, cid uint32, host string, port int) (net.Conn, func(), error) {
	if !validWebPort(port) {
		return nil, nil, refused(ReasonPort)
	}
	ip, err := netip.ParseAddr(host)
	isIP := err == nil
	if isIP {
		ip = ip.Unmap()
		if ip.Zone() != "" {
			return nil, nil, refused(ReasonName)
		}
	} else if !validWebHost(host, false) {
		return nil, nil, refused(ReasonName)
	}
	host = strings.ToLower(host)
	if !isIP && host == BlobHost && port == 80 && d.BlobService != "" {
		return d.dialBlobService(ctx, cid)
	}
	if d.Allow != nil && (isIP || !d.Allow(host)) {
		return nil, nil, refused(ReasonNotAllowed) // a host given a list allows names on it, never a literal
	}
	if isIP {
		var own []netip.Addr
		if d.Own != nil {
			own = d.Own()
		}
		if RefuseAddr(ip, own) != "" {
			return nil, nil, refused(ReasonNonPublicAddress)
		}
	}
	release, err := d.take(cid)
	if err != nil {
		return nil, nil, err
	}
	var c net.Conn
	if isIP {
		c, err = d.dialAddrs(ctx, cid, []netip.Addr{ip}, port)
	} else {
		c, err = d.dialName(ctx, cid, host, port)
	}
	if err != nil {
		release()
		return nil, nil, err
	}
	return c, release, nil
}

// ResolvePublic is a name's addresses for guest `cid` (at most 16), resolved the way DialWeb would resolve it; a name
// with ANY non-public answer is refused outright, as in Dial.
func (d *Dialer) ResolvePublic(ctx context.Context, cid uint32, host string) ([]netip.Addr, error) {
	if !validWebHost(host, false) {
		return nil, refused(ReasonName)
	}
	host = strings.ToLower(host)
	if d.Allow != nil && !d.Allow(host) {
		return nil, refused(ReasonNotAllowed)
	}
	release, err := d.take(cid)
	if err != nil {
		return nil, err
	}
	defer release()
	var addresses []netip.Addr
	if d.RouteFor != nil {
		route, err := d.RouteFor(cid)
		if err != nil || len(route.Proxies) == 0 || len(route.DNS) == 0 {
			return nil, refused(ReasonAdmit)
		}
		for _, proxy := range route.Proxies {
			if ValidateSOCKSProxy(proxy) != nil {
				return nil, refused(ReasonAdmit)
			}
			attempt, cancel := context.WithTimeout(ctx, d.timeout())
			addresses, err = (appResolver{proxy: proxy, servers: route.DNS, scope: route.scope}).LookupNetIP(attempt, "ip", host)
			cancel()
			if err == nil && len(addresses) > 0 {
				break
			}
			if ctx.Err() != nil {
				break
			}
		}
	} else if d.Resolver != nil {
		addresses, err = d.Resolver.LookupNetIP(ctx, "ip", host)
	}
	if err != nil || len(addresses) == 0 {
		return nil, refused(ReasonResolve)
	}
	var own []netip.Addr
	if d.Own != nil {
		own = d.Own()
	}
	for _, a := range addresses {
		if RefuseAddr(a, own) != "" {
			return nil, refused(ReasonNonPublicAnswer)
		}
	}
	if len(addresses) > maxDNSAnswers {
		addresses = addresses[:maxDNSAnswers]
	}
	return addresses, nil
}

// BlobHost is the reserved name a public-web guest asks for public, pinned content by (docs/design/shield-blob-cache.md).
const BlobHost = "blobs.enclave.internal"

// dialBlobService connects a guest to the host's blob cache on loopback (Dialer.BlobService). The guest verifies the
// sha256 of every object it reads, so the host can delay or refuse a blob but never substitute one.
func (d *Dialer) dialBlobService(ctx context.Context, cid uint32) (net.Conn, func(), error) {
	release, err := d.take(cid)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, d.timeout())
	defer cancel()
	var c net.Conn
	if d.dial != nil {
		c, err = d.dial(ctx, d.BlobService)
	} else {
		var nd net.Dialer
		c, err = nd.DialContext(ctx, "tcp", d.BlobService)
	}
	if err != nil {
		release()
		return nil, nil, refused(ReasonResolve)
	}
	return c, release, nil
}
