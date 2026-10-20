package egress

// The HOST side of controlled egress: a guest's forwarder asks for one (hostname, 443) and the host dials it, or
// refuses. The host holds no allowlist of its own (that lives in the guest, derived from secrets it cannot see; Allow
// is an optional narrowing for a host that was told one); what the host enforces is that a guest can never reach the
// host's own network: the FINAL resolved address is judged at dial time, so a CNAME chain or a DNS change that lands on
// a private address is refused on the address itself. With SOCKSProxy set, the judged IP literal is what the proxy is
// asked for, and a proxy that is down is a failed dial, never a direct one (socks.go).

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

// refusedPrefixes: never a destination for a tenant, whatever DNS says.
var refusedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8",       // "this network", incl. 0.0.0.0
		"10.0.0.0/8",      // RFC1918
		"100.64.0.0/10",   // CGNAT
		"127.0.0.0/8",     // loopback
		"169.254.0.0/16",  // link-local, incl. the 169.254.169.254 metadata service
		"172.16.0.0/12",   // RFC1918
		"192.0.0.0/24",    // IETF protocol assignments
		"192.168.0.0/16",  // RFC1918
		"198.18.0.0/15",   // benchmarking
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // reserved, incl. 255.255.255.255
		"::/128",          // unspecified
		"::1/128",         // loopback
		"64:ff9b::/96",    // NAT64: an IPv4 in disguise
		"fc00::/7",        // ULA
		"fe80::/10",       // link-local
		"ff00::/8",        // multicast
		"2002::/16",       // 6to4: an IPv4 in disguise
		"2001::/32",       // Teredo: an IPv4 in disguise
		"64:ff9b:1::/48",  // local-use NAT64 (RFC 8215)
		"2001:db8::/32",   // documentation
		"192.0.2.0/24",    // TEST-NET-1
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// RefuseAddr says why an address may not be dialed for a tenant ("" = allowed). IPv4-mapped IPv6 is judged as the
// IPv4 it carries.
func RefuseAddr(a netip.Addr, own []netip.Addr) string {
	a = a.Unmap()
	if !a.IsValid() {
		return "not an address"
	}
	for _, p := range refusedPrefixes {
		if p.Contains(a) {
			return "a non-public address (" + p.String() + ")"
		}
	}
	for _, o := range own {
		if o.Unmap() == a {
			return "one of this host's own addresses"
		}
	}
	return ""
}

// Resolver is the part of net.Resolver the dialer needs (a fake in tests).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Dialer is the host's egress service for ALL guests; per-guest caps keep one guest from exhausting it.
type Dialer struct {
	Resolver      Resolver
	Own           func() []netip.Addr // this host's addresses, read at dial time
	DialTimeout   time.Duration
	MaxConcurrent int                                // per guest
	MaxPerMinute  int                                // per guest, dials started
	SOCKSProxy    string                             // optional trusted loopback TUNA entry; failure never falls back to direct
	RouteFor      func(cid uint32) (AppRoute, error) // when configured, no shared/default route may be used
	// Allow is an OPTIONAL host-side list (shield-egress -allow): when set, a name it does not allow is refused before
	// anything is resolved or dialed. It never widens anything: the guest's own allowlist, derived from the owner's
	// resolved config, still decides what the guest asks for, and every rule below still applies to what it allows.
	Allow func(host string) bool
	// BlobService is the loopback address of the host's cache for public, pinned content (windows/node/blob-cache.mjs,
	// docs/design/shield-blob-cache.md). When set, a public-web guest's by-name request for BlobHost:80 is dialed there
	// instead of through its route - under the same per-guest caps. "" = off: the name is then refused like any other
	// that does not resolve. Nothing else changes.
	BlobService string
	dial        func(ctx context.Context, addr string) (net.Conn, error)
	mu          sync.Mutex
	active      map[uint32]int
	window      map[uint32][]time.Time
}

var ErrRefused = errors.New("egress refused")

// Reason is why a dial was refused or failed: a code from a fixed set, never the destination, an address or the
// underlying network error. A destination can come from a secret (the owner's config resolves secret values into
// URLs), so the host's log records only the guest and this code (forward.go).
type Reason string

const (
	ReasonPort             Reason = "port"               // not 443 (egress-v1), or not a web port (0, 25) for egress-web-v1
	ReasonName             Reason = "name"               // not a plain DNS name: an IP literal, a single label, ...
	ReasonRate             Reason = "rate"               // the guest is over its dial rate
	ReasonConcurrency      Reason = "concurrency"        // the guest is at its connection limit
	ReasonResolve          Reason = "resolve"            // the name did not resolve
	ReasonNonPublicAnswer  Reason = "non-public-answer"  // an answer is loopback, private, link-local, this host, ...
	ReasonNonPublicPeer    Reason = "non-public-peer"    // the socket's actual peer is not public
	ReasonNonPublicAddress Reason = "non-public-address" // (egress-web-v1) the guest named a non-public IP literal
	ReasonConnect          Reason = "connect"            // no judged address accepted the connection
	ReasonNotAllowed       Reason = "not-allowed"        // the host was given a list for this guest (Dialer.Allow), and the name is not on it
	ReasonAdmit            Reason = "admit"              // (server) the stream is from a guest the host's manager did not launch
	ReasonEmpty            Reason = "empty"              // (server) the stream closed before any header byte
	ReasonHeader           Reason = "header"             // (server) a malformed or unfinished egress-v1 header
	ReasonInternal         Reason = "internal"           // anything else
)

// DialError is every error Dial returns. It holds a Reason and nothing else, so no caller can log a destination or
// a raw network error by printing it.
//
// ReasonOf is THE way to classify one. errors.Is(err, ErrRefused) covers policy refusals only: a connection that
// failed (ReasonConnect) is not a refusal, and is recognisable only through ReasonOf.
type DialError struct {
	Reason  Reason
	refused bool // a policy refusal (errors.Is ErrRefused), as opposed to a connection that failed
}

func (e *DialError) Error() string {
	if e.refused {
		return "egress refused: " + string(e.Reason)
	}
	return "egress failed: " + string(e.Reason)
}

func (e *DialError) Unwrap() error {
	if e.refused {
		return ErrRefused
	}
	return nil
}

func refused(r Reason) error { return &DialError{Reason: r, refused: true} }

// ReasonOf is the bounded code for any error Dial returned (ReasonInternal for anything else).
func ReasonOf(err error) Reason {
	var de *DialError
	if errors.As(err, &de) {
		return de.Reason
	}
	return ReasonInternal
}

// Dial opens a TCP connection for guest `cid` to host:443, or refuses. It returns the connection and a release func
// the caller MUST call when the connection ends (it frees the guest's concurrency slot).
func (d *Dialer) Dial(ctx context.Context, cid uint32, host string, port int) (net.Conn, func(), error) {
	if port != 443 {
		return nil, nil, refused(ReasonPort)
	}
	if _, err := ParseOrigin("https://" + host + "/"); err != nil {
		return nil, nil, refused(ReasonName) // an IP literal, a single label, …: never by name here
	}
	if d.Allow != nil && !d.Allow(host) {
		return nil, nil, refused(ReasonNotAllowed) // before the rate window: a name the host refuses costs the guest nothing
	}
	release, err := d.take(cid)
	if err != nil {
		return nil, nil, err
	}
	c, err := d.dialName(ctx, cid, host, port)
	if err != nil {
		release()
		return nil, nil, err
	}
	return c, release, nil
}

// dialName resolves a name (through the guest's own route when RouteFor is set) and dials a judged address of it.
func (d *Dialer) dialName(ctx context.Context, cid uint32, host string, port int) (net.Conn, error) {
	if d.RouteFor != nil {
		route, err := d.RouteFor(cid)
		if err != nil || len(route.Proxies) == 0 || len(route.DNS) == 0 {
			return nil, refused(ReasonAdmit)
		}
		return d.dialAppRoute(ctx, route, host, port)
	}
	if d.Resolver == nil {
		return nil, refused(ReasonResolve)
	}
	addrs, err := d.Resolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return nil, refused(ReasonResolve)
	}
	var own []netip.Addr
	if d.Own != nil {
		own = d.Own()
	}
	// every answer must be public: a name that resolves to ANY private address is refused outright, rather than
	// dialing its public sibling (a rebinding setup mixes the two)
	for _, a := range addrs {
		if RefuseAddr(a, own) != "" {
			return nil, refused(ReasonNonPublicAnswer)
		}
	}
	return d.dialAddrs(ctx, cid, addrs, port)
}

// dialAddrs dials the first of `addrs` (already judged public by the caller) that accepts: through the guest's route,
// the SOCKS entry, or directly, in that order of precedence; never a direct dial when a route or entry is configured.
func (d *Dialer) dialAddrs(ctx context.Context, cid uint32, addrs []netip.Addr, port int) (net.Conn, error) {
	if d.RouteFor != nil {
		route, err := d.RouteFor(cid)
		if err != nil || len(route.Proxies) == 0 {
			return nil, refused(ReasonAdmit)
		}
		return d.dialAppRouteAddrs(ctx, route, addrs, port)
	}
	var own []netip.Addr
	if d.Own != nil {
		own = d.Own()
	}
	dial := d.dial
	proxy := d.SOCKSProxy
	proxied := proxy != ""
	if proxied {
		dial = func(ctx context.Context, addr string) (net.Conn, error) {
			return dialSOCKS(ctx, proxy, addr, d.timeout())
		}
	}
	if dial == nil {
		nd := &net.Dialer{Timeout: d.timeout()}
		dial = func(ctx context.Context, addr string) (net.Conn, error) { return nd.DialContext(ctx, "tcp", addr) }
	}
	for _, a := range addrs {
		// dial the JUDGED address itself, never the name again (no second resolution between check and connect)
		c, err := dial(ctx, netip.AddrPortFrom(a.Unmap(), uint16(port)).String())
		if err != nil {
			continue // the raw error names the address; it is dropped, not logged (DialError)
		}
		// Direct sockets expose the destination peer. For SOCKS the peer is the
		// explicitly configured loopback entry; dialSOCKS sends only the already
		// judged IP literal, never a hostname that a provider could resolve again.
		if !proxied {
			if ra, err := netip.ParseAddrPort(c.RemoteAddr().String()); err != nil || RefuseAddr(ra.Addr(), own) != "" {
				c.Close()
				return nil, refused(ReasonNonPublicPeer)
			}
		}
		return c, nil
	}
	return nil, &DialError{Reason: ReasonConnect}
}

func (d *Dialer) timeout() time.Duration {
	if d.DialTimeout > 0 {
		return d.DialTimeout
	}
	return 10 * time.Second
}

func (d *Dialer) take(cid uint32) (func(), error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.active == nil {
		d.active, d.window = map[uint32]int{}, map[uint32][]time.Time{}
	}
	now := time.Now()
	w := d.window[cid][:0]
	for _, t := range d.window[cid] {
		if now.Sub(t) < time.Minute {
			w = append(w, t)
		}
	}
	d.window[cid] = w
	if d.MaxPerMinute > 0 && len(w) >= d.MaxPerMinute {
		return nil, refused(ReasonRate)
	}
	if d.MaxConcurrent > 0 && d.active[cid] >= d.MaxConcurrent {
		return nil, refused(ReasonConcurrency)
	}
	d.window[cid] = append(w, now)
	d.active[cid]++
	var once sync.Once
	return func() {
		once.Do(func() {
			d.mu.Lock()
			d.active[cid]--
			d.mu.Unlock()
		})
	}, nil
}

// fixedAnswers prevents a second resolution between policy checks and dialing.
type fixedAnswers []netip.Addr

func (a fixedAnswers) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr(a), nil
}
