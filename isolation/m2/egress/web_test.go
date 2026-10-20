package egress

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// newWebRig is newRig for a public-web guest: the configured origins' forwarders, plus the SOCKS front and the DNS
// stub on free loopback ports.
func newWebRig(t *testing.T, origins []string, route map[string]net.Listener, dns fakeResolver) *rig {
	t.Helper()
	r := newRig(t, nil, route, dns)
	r.fwd.Close()
	var os []Origin
	for _, h := range origins {
		os = append(os, Origin{Host: h})
	}
	r.fwd = &Forwarder{Policy: &Policy{Origins: os, PublicWeb: true}, Port: r.fwd.Port, Upstream: r.fwd.Upstream,
		PublicListen: "127.0.0.1:0", DNSListen: "127.0.0.1:0"}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := r.fwd.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return r
}

// socksAddr and dnsAddr: Start binds the SOCKS front and then the DNS stub after every origin forwarder.
func (r *rig) socksAddr() string { l := r.fwd.Listeners(); return l[len(l)-2].String() }
func (r *rig) dnsAddr() string   { l := r.fwd.Listeners(); return l[len(l)-1].String() }

// body is a local "internet" server answering every connection with a fixed body.
func body(t *testing.T, text string) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.WriteString(c, text) }()
		}
	}()
	return l
}

// socksConnect is a tenant's SOCKS5 session, the way risc-box's egress.rs speaks it (user/password only) or with no
// authentication; it returns the reply code and, on success, the connection.
func socksConnect(t *testing.T, addr string, userPass bool, atyp byte, host []byte, port uint16, cmd byte) (byte, net.Conn) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	method := byte(0)
	if userPass {
		method = 2
	}
	c.Write([]byte{5, 1, method})
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil || m != [2]byte{5, method} {
		t.Fatalf("greeting answered %v (%v)", m, err)
	}
	if userPass {
		c.Write([]byte{1, 5, 'g', 'u', 'e', 's', 't', 3, 'a', 'n', 'y'})
		if _, err := io.ReadFull(c, m[:]); err != nil || m != [2]byte{1, 0} {
			t.Fatalf("auth answered %v (%v)", m, err)
		}
	}
	req := []byte{5, cmd, 0, atyp}
	if atyp == 3 {
		req = append(req, byte(len(host)))
	}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, port)
	c.Write(req)
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		t.Fatalf("no CONNECT reply: %v", err)
	}
	if rep[1] != 0 {
		c.Close()
		return rep[1], nil
	}
	return 0, c
}

func readAll(t *testing.T, c net.Conn) string {
	t.Helper()
	defer c.Close()
	b, _ := io.ReadAll(c)
	return string(b)
}

func TestPublicWebReachesANameOrAPublicIPOnAnyPort(t *testing.T) {
	web, alt := body(t, "hello from 8080"), body(t, "hello from 443")
	r := newWebRig(t, nil, map[string]net.Listener{"93.184.216.34:8080": web, "93.184.216.34:443": alt},
		fakeResolver{"www.example.com": {"93.184.216.34"}})
	code, c := socksConnect(t, r.socksAddr(), true, 3, []byte("WWW.Example.com"), 8080, 1)
	if code != 0 || readAll(t, c) != "hello from 8080" {
		t.Fatalf("by name: reply %d", code)
	}
	code, c = socksConnect(t, r.socksAddr(), false, 1, []byte{93, 184, 216, 34}, 443, 1)
	if code != 0 || readAll(t, c) != "hello from 443" {
		t.Fatalf("by IPv4 literal: reply %d", code)
	}
	looked, dialed := r.observed()
	if strings.Join(looked, ",") != "www.example.com" || strings.Join(dialed, ",") != "93.184.216.34:8080,93.184.216.34:443" {
		t.Fatalf("looked %v dialed %v", looked, dialed)
	}
	if logs := r.logs(); strings.Count(logs, "guest 42 egress open") != 2 || strings.Contains(logs, "example") || strings.Contains(logs, "93.184") {
		t.Fatalf("host log %q", logs)
	}
}

func TestPublicWebRefusesWhatIsNotPublicTCP(t *testing.T) {
	never := body(t, "must not be reached")
	r := newWebRig(t, nil, map[string]net.Listener{"10.0.0.5:443": never, "93.184.216.34:25": never},
		fakeResolver{"rebind.example": {"93.184.216.34", "10.0.0.5"}})
	for _, tc := range []struct {
		name string
		atyp byte
		host []byte
		port uint16
		cmd  byte
		want byte
	}{
		{"private literal", 1, []byte{10, 0, 0, 5}, 443, 1, socksNotAllowed},
		{"loopback literal", 1, []byte{127, 0, 0, 1}, 443, 1, socksNotAllowed},
		{"metadata literal", 1, []byte{169, 254, 169, 254}, 80, 1, socksNotAllowed},
		{"private literal sent as a name", 3, []byte("10.0.0.5"), 443, 1, socksNotAllowed},
		{"IPv6 loopback", 4, netip.IPv6Loopback().AsSlice(), 443, 1, socksNotAllowed},
		{"SMTP", 1, []byte{93, 184, 216, 34}, 25, 1, socksNotAllowed},
		{"port 0", 3, []byte("www.example.com"), 0, 1, socksNotAllowed},
		{"single label", 3, []byte("intranet"), 443, 1, socksNotAllowed},
		{"BIND", 3, []byte("www.example.com"), 443, 2, socksBadCommand},
		{"UDP ASSOCIATE", 3, []byte("www.example.com"), 443, 3, socksBadCommand},
		{"a name with a private answer", 3, []byte("rebind.example"), 443, 1, socksUnreachable},
		{"a name that does not resolve", 3, []byte("nx.example"), 443, 1, socksUnreachable},
	} {
		if code, c := socksConnect(t, r.socksAddr(), true, tc.atyp, tc.host, tc.port, tc.cmd); code != tc.want {
			if c != nil {
				c.Close()
			}
			t.Errorf("%s: reply %d, want %d", tc.name, code, tc.want)
		}
	}
	if _, dialed := r.observed(); len(dialed) != 0 {
		t.Fatalf("the host dialed %v", dialed)
	}
	if logs := r.logs(); strings.Contains(logs, "rebind") || strings.Contains(logs, "10.0.0.5") {
		t.Fatalf("host log %q", logs)
	}
}

// dnsQuery builds a one-question query.
func dnsQuestion(id uint16, name string, kind uint16) []byte {
	q := binary.BigEndian.AppendUint16(nil, id)
	q = append(q, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) // RD; one question
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0)
	q = binary.BigEndian.AppendUint16(q, kind)
	return binary.BigEndian.AppendUint16(q, 1)
}

// askTCP sends one query over DNS-over-TCP framing and returns (rcode, answers), or ok=false if the stub hung up.
func askTCP(t *testing.T, addr string, q []byte) (rcode int, answers []string, ok bool) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...))
	var n [2]byte
	if _, err := io.ReadFull(c, n[:]); err != nil {
		return 0, nil, false
	}
	resp := make([]byte, binary.BigEndian.Uint16(n[:]))
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != q[0] || resp[1] != q[1] || resp[2]&0x80 == 0 {
		t.Fatalf("not a response to this query: % x", resp[:4])
	}
	rcode = int(resp[3] & 0xf)
	i := len(q) // the question is echoed whole; answers follow
	for k := 0; k < int(binary.BigEndian.Uint16(resp[6:8])); k++ {
		size := int(binary.BigEndian.Uint16(resp[i+10 : i+12]))
		a, _ := netip.AddrFromSlice(resp[i+12 : i+12+size])
		answers = append(answers, a.String())
		i += 12 + size
	}
	return rcode, answers, true
}

func TestPublicWebDNSStubAnswersOnlyPublicAddresses(t *testing.T) {
	r := newWebRig(t, nil, nil, fakeResolver{
		"www.example.com": {"93.184.216.34", "2606:2800:220:1::1"},
		"rebind.example":  {"93.184.216.34", "192.168.1.1"},
	})
	for _, tc := range []struct {
		name    string
		kind    uint16
		rcode   int
		answers string
	}{
		{"www.example.com", 1, 0, "93.184.216.34"},
		{"WWW.EXAMPLE.COM", 28, 0, "2606:2800:220:1::1"},
		{"www.example.com", 15, 0, ""},      // MX: NOERROR, no data
		{"rebind.example", 1, 2, ""},        // a private answer: SERVFAIL, never the public half
		{"nx.example", 1, 2, ""},            // the host could not resolve it
		{"intranet", 1, 3, ""},              // not a public DNS name: NXDOMAIN without asking the host
		{"1.2.3.4.in-addr.arpa", 12, 0, ""}, // PTR: NOERROR, no data
	} {
		rcode, answers, ok := askTCP(t, r.dnsAddr(), dnsQuestion(0x1234, tc.name, tc.kind))
		if !ok || rcode != tc.rcode || strings.Join(answers, ",") != tc.answers {
			t.Errorf("%s/%d: ok %v rcode %d answers %v", tc.name, tc.kind, ok, rcode, answers)
		}
	}
	looked, _ := r.observed()
	if strings.Contains(strings.Join(looked, ","), "intranet") {
		t.Fatalf("the host was asked for a name the guest must refuse itself: %v", looked)
	}
	if logs := r.logs(); strings.Contains(logs, "example") || strings.Contains(logs, "192.168") {
		t.Fatalf("host log %q", logs)
	}
}

func TestTheDNSStubHangsUpOnWhatIsNotAPlainQuery(t *testing.T) {
	r := newWebRig(t, nil, nil, fakeResolver{})
	response := dnsQuestion(1, "www.example.com", 1)
	response[2] |= 0x80
	two := dnsQuestion(2, "www.example.com", 1)
	two[5] = 2
	pointer := append(dnsQuestion(3, "a.example", 1)[:12], 0xc0, 0x0c, 0, 1, 0, 1)
	for name, q := range map[string][]byte{"a response": response, "two questions": two, "a compression pointer": pointer} {
		if _, _, ok := askTCP(t, r.dnsAddr(), q); ok {
			t.Errorf("%s was answered", name)
		}
	}
}

func TestTheHostRefusesMalformedWebHeaders(t *testing.T) {
	r := newWebRig(t, nil, nil, fakeResolver{"www.example.com": {"93.184.216.34"}})
	for _, header := range []string{
		"egress-web-v1 www.example.com +443", "egress-web-v1 www.example.com 0443", "egress-web-v1 www.example.com 65536",
		"egress-web-v1 www.example.com 25", "egress-web-v1 10.1.2.3 443", "egress-web-v1 fe80::1%eth0 443",
		"egress-dns-v1 www.example.com 1", "egress-dns-v1 10.1.2.3 0", "egress-web-v1 www.example.com",
	} {
		c, err := net.Dial("tcp", r.hostAddr)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(c, "%s\n", header)
		line, _ := bufio.NewReader(c).ReadString('\n')
		c.Close()
		if line != "refused\n" {
			t.Errorf("%q answered %q", header, line)
		}
	}
	if _, dialed := r.observed(); len(dialed) != 0 {
		t.Fatalf("the host dialed %v", dialed)
	}
}

func TestAGuestWithoutPublicWebHasNoSOCKSOrDNSListener(t *testing.T) {
	r := newRig(t, []string{"a.example"}, nil, fakeResolver{})
	if got := r.fwd.Listeners(); len(got) != 1 {
		t.Fatalf("listeners %v", got)
	}
	w := newWebRig(t, []string{"a.example"}, nil, fakeResolver{})
	if got := w.fwd.Listeners(); len(got) != 3 {
		t.Fatalf("public web listeners %v", got)
	}
	if !strings.Contains(w.fwd.HostsFile(), " a.example\n") {
		t.Fatal("a public-web guest lost its configured origin's forwarder")
	}
}

// fakeSOCKS is the route's loopback TUNA entry: it records each CONNECT target and splices it to `route`.
func fakeSOCKS(t *testing.T, route map[string]net.Listener) (string, func() []string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var targets = make(chan string, 16)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var b [4]byte
				io.ReadFull(c, b[:3])
				c.Write([]byte{5, 0})
				io.ReadFull(c, b[:4])
				ip := make([]byte, map[byte]int{1: 4, 4: 16}[b[3]])
				io.ReadFull(c, ip)
				var p [2]byte
				io.ReadFull(c, p[:])
				a, _ := netip.AddrFromSlice(ip)
				target := netip.AddrPortFrom(a, binary.BigEndian.Uint16(p[:])).String()
				targets <- target
				srv, ok := route[target]
				if !ok {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				up, err := net.Dial("tcp", srv.Addr().String())
				if err != nil {
					return
				}
				defer up.Close()
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				splice(c, c, up, up)
			}()
		}
	}()
	return l.Addr().String(), func() []string {
		var out []string
		for {
			select {
			case s := <-targets:
				out = append(out, s)
			default:
				return out
			}
		}
	}
}

func TestDialWebGoesThroughTheAppsRouteForNamesAndLiterals(t *testing.T) {
	fakeDoH(t, 300, false) // every name is 93.184.216.34 / 2606:2800:220:1::1
	srv := body(t, "via the route")
	proxy, seen := fakeSOCKS(t, map[string]net.Listener{"93.184.216.34:8443": srv, "[2606:4700::1111]:80": srv})
	id := "0x" + strings.Repeat("e", 64)
	d := &Dialer{Resolver: panicResolver{}, RouteFor: func(uint32) (AppRoute, error) {
		return AppRoute{Proxies: []string{proxy}, DNS: dohServers, scope: id}, nil
	}}
	c, release, err := d.DialWeb(context.Background(), 7, "www.example.com", 8443)
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, c); got != "via the route" {
		t.Fatalf("got %q", got)
	}
	release()
	c, release, err = d.DialWeb(context.Background(), 7, "2606:4700::1111", 80)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, c)
	release()
	if got := strings.Join(seen(), ","); got != "93.184.216.34:8443,[2606:4700::1111]:80" {
		t.Fatalf("the route was asked for %s", got)
	}
	addrs, err := d.ResolvePublic(context.Background(), 7, "www.example.com")
	if err != nil || len(addrs) != 2 {
		t.Fatalf("resolve: %v %v", addrs, err)
	}
	if _, _, err := d.DialWeb(context.Background(), 7, "192.168.0.1", 443); ReasonOf(err) != ReasonNonPublicAddress {
		t.Fatalf("a private literal: %v", err)
	}
	d.Allow = func(host string) bool { return host == "www.example.com" }
	if _, _, err := d.DialWeb(context.Background(), 7, "93.184.216.34", 443); ReasonOf(err) != ReasonNotAllowed {
		t.Fatalf("a literal under a host list: %v", err)
	}
	if _, err := d.ResolvePublic(context.Background(), 7, "other.example"); ReasonOf(err) != ReasonNotAllowed {
		t.Fatalf("a name off the host list: %v", err)
	}
}

func TestDialSOCKSStillRefusesNonPublicTargetsAndSMTP(t *testing.T) {
	for _, dest := range []string{"10.0.0.1:443", "93.184.216.34:25", "93.184.216.34:0", "[::1]:443"} {
		if _, err := dialSOCKS(context.Background(), "127.0.0.1:9", dest, time.Second); err == nil ||
			!strings.Contains(err.Error(), "judged public IP") {
			t.Errorf("%s: %v", dest, err)
		}
	}
	if _, err := dialSOCKS(context.Background(), "127.0.0.1:9", "93.184.216.34:8080", 100*time.Millisecond); err == nil ||
		strings.Contains(err.Error(), "judged public IP") {
		t.Errorf("a public target on 8080 was refused before dialing: %v", err)
	}
}
