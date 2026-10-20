package egress

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// RouteFor is resolved from the manager's authenticated guest CID, never a
// deployment identifier supplied in a guest request.
type AppRoute struct {
	Proxies []string      `json:"proxies"`
	DNS     []DNSEndpoint `json:"dns"`
	// scope is the app this route was read for (ReadAppRoute): its DNS cache.
	scope string
}
type DNSEndpoint struct {
	Address    string `json:"address"`
	ServerName string `json:"serverName"`
	Path       string `json:"path"`
}
type AppRouteFile struct {
	Version   int                 `json:"version"`
	ExpiresAt int64               `json:"expiresAt"`
	Apps      map[string]AppRoute `json:"apps"`
}

var appIDPattern = regexp.MustCompile(`^0x[0-9a-f]{64}$`)

func ReadAppRoute(file, deploymentID string) (AppRoute, error) {
	var zero AppRoute
	if !appIDPattern.MatchString(deploymentID) {
		return zero, errors.New("unbound guest")
	}
	f, e := os.Open(file)
	if e != nil {
		return zero, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if e != nil || len(b) > 1<<20 {
		return zero, errors.New("invalid app routes")
	}
	var doc AppRouteFile
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if e = dec.Decode(&doc); e != nil {
		return zero, e
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return zero, errors.New("trailing app route data")
	}
	now := time.Now().UnixMilli()
	if doc.Version != 1 || doc.ExpiresAt <= now || doc.ExpiresAt > now+120000 || len(doc.Apps) > 256 {
		return zero, errors.New("expired or invalid app routes")
	}
	// Reject shared circuit entries, including another app reusing one proxy.
	seen := map[string]bool{}
	for id, r := range doc.Apps {
		if !appIDPattern.MatchString(id) || len(r.Proxies) < 1 || len(r.Proxies) > 2 || len(r.DNS) < 1 || len(r.DNS) > 4 {
			return zero, errors.New("invalid app route")
		}
		for _, p := range r.Proxies {
			a, e := netip.ParseAddrPort(p)
			canonical := ""
			if e == nil {
				canonical = netip.AddrPortFrom(a.Addr().Unmap(), a.Port()).String()
			}
			if ValidateSOCKSProxy(p) != nil || seen[canonical] {
				return zero, errors.New("invalid or reused app proxy")
			}
			seen[canonical] = true
		}
		for _, d := range r.DNS {
			if d.Path != "/dns-query" && d.Path != "/resolve" {
				return zero, errors.New("unsupported DNS query path")
			}
			a, e := netip.ParseAddrPort(d.Address)
			if e != nil || a.Port() != 443 || RefuseAddr(a.Addr(), nil) != "" {
				return zero, errors.New("public DNS endpoint required")
			}
			if _, e = ParseOrigin("https://" + d.ServerName + "/"); e != nil {
				return zero, errors.New("invalid DNS TLS identity")
			}
		}
	}
	r, ok := doc.Apps[deploymentID]
	if !ok {
		return zero, errors.New("app has no authorized egress route")
	}
	r.scope = deploymentID
	return r, nil
}

// DNS is HTTPS over the SAME app proxy. The resolver is dialed by pinned IP
// and verified using its configured TLS name; host DNS is never consulted.
type appResolver struct {
	proxy   string
	servers []DNSEndpoint
	scope   string // the app the answers belong to; empty disables caching
}

// Every lookup is a TLS session through the app's guarded circuit (~0.4-1.3 s
// each), and a connection needs two (A and AAAA). Answers are therefore kept
// for their own TTL (at most dnsCacheMax), per app: one app's lookups never
// warm, and so never reveal, another's. A and AAAA are asked in parallel.
const (
	dnsCacheMax     = 10 * time.Minute
	dnsCacheEntries = 4096
)

type dnsKey struct{ scope, host string }
type dnsEntry struct {
	addrs []netip.Addr
	until time.Time
}

var (
	dnsMu    sync.Mutex
	dnsCache = map[dnsKey]dnsEntry{}
	dnsNow   = time.Now
	// dnsQuery asks one DoH server for one record type; tests replace it.
	dnsQuery = queryDoH
)

// forget drops a cached answer whose addresses all failed to connect, so the
// next attempt (the app's other circuit, or its next request) asks again.
func (r appResolver) forget(host string) {
	if r.scope == "" {
		return
	}
	dnsMu.Lock()
	delete(dnsCache, dnsKey{r.scope, strings.ToLower(host)})
	dnsMu.Unlock()
}

func (r appResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if network != "ip" {
		return nil, errors.New("unsupported address family")
	}
	key := dnsKey{r.scope, strings.ToLower(host)}
	if r.scope != "" {
		dnsMu.Lock()
		e, ok := dnsCache[key]
		dnsMu.Unlock()
		if ok && dnsNow().Before(e.until) {
			return append([]netip.Addr(nil), e.addrs...), nil
		}
	}
	type answer struct {
		addrs []netip.Addr
		ttl   uint32
		err   error
	}
	var answers [2]answer
	var wg sync.WaitGroup
	for i, kind := range []int{1, 28} {
		wg.Add(1)
		go func(i, kind int) {
			defer wg.Done()
			for _, server := range r.servers {
				addrs, ttl, err := dnsQuery(ctx, r.proxy, server, host, kind)
				if err == nil {
					answers[i] = answer{addrs: addrs, ttl: ttl}
					return
				}
			}
			answers[i] = answer{err: errors.New("guarded DNS unavailable")}
		}(i, kind)
	}
	wg.Wait()
	var result []netip.Addr
	ttl := ^uint32(0)
	for _, a := range answers {
		if a.err != nil {
			return nil, a.err
		}
		result = append(result, a.addrs...)
		if len(a.addrs) > 0 && a.ttl < ttl {
			ttl = a.ttl
		}
	}
	if len(result) == 0 {
		return nil, errors.New("DNS returned no addresses")
	}
	if r.scope != "" && ttl > 0 {
		life := time.Duration(ttl) * time.Second
		if life > dnsCacheMax {
			life = dnsCacheMax
		}
		now := dnsNow()
		dnsMu.Lock()
		if len(dnsCache) >= dnsCacheEntries {
			for k, e := range dnsCache {
				if !now.Before(e.until) {
					delete(dnsCache, k)
				}
			}
			if len(dnsCache) >= dnsCacheEntries {
				dnsCache = map[dnsKey]dnsEntry{}
			}
		}
		dnsCache[key] = dnsEntry{addrs: append([]netip.Addr(nil), result...), until: now.Add(life)}
		dnsMu.Unlock()
	}
	return result, nil
}

// queryDoH asks one server, through the app's proxy, for one record type. Any
// transport failure, refusal or malformed answer is an error (the caller tries
// the next server); the TTL is the smallest among the matching records.
func queryDoH(ctx context.Context, proxy string, server DNSEndpoint, host string, kind int) ([]netip.Addr, uint32, error) {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: server.ServerName},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialSOCKS(ctx, proxy, server.Address, 8*time.Second)
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("DNS redirect refused") }}
	u := "https://" + server.ServerName + server.Path + "?name=" + url.QueryEscape(host) + "&type=" + fmt.Sprint(kind)
	req, e := http.NewRequestWithContext(ctx, "GET", u, nil)
	if e != nil {
		return nil, 0, e
	}
	req.Header.Set("Accept", "application/dns-json")
	res, e := client.Do(req)
	if e != nil {
		return nil, 0, e
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, 65537))
	res.Body.Close()
	if e != nil || res.StatusCode != 200 || len(b) > 65536 {
		return nil, 0, errors.New("DNS answer refused")
	}
	var doc struct {
		Status int
		Answer []struct {
			Type int
			TTL  uint32
			Data string
		}
	}
	if json.Unmarshal(b, &doc) != nil || doc.Status != 0 {
		return nil, 0, errors.New("DNS answer refused")
	}
	var addrs []netip.Addr
	ttl := ^uint32(0)
	for _, a := range doc.Answer {
		if a.Type != kind {
			continue
		}
		ip, e := netip.ParseAddr(a.Data)
		if e != nil || (kind == 1 && !ip.Is4()) || (kind == 28 && !ip.Is6()) {
			return nil, 0, errors.New("malformed DNS answer")
		}
		addrs = append(addrs, ip)
		if a.TTL < ttl {
			ttl = a.TTL
		}
	}
	if len(addrs) == 0 {
		ttl = 0
	}
	return addrs, ttl, nil
}

// A failure after DNS resolution still tries the app's other authorized circuit.
// Every attempt is bounded and carries its own DNS through the same proxy.
func (d *Dialer) dialAppRoute(ctx context.Context, route AppRoute, host string, port int) (net.Conn, error) {
	var own []netip.Addr
	if d.Own != nil {
		own = d.Own()
	}
	reason := ReasonResolve
	for _, proxy := range route.Proxies {
		if ValidateSOCKSProxy(proxy) != nil {
			return nil, refused(ReasonAdmit)
		}
		attempt, cancel := context.WithTimeout(ctx, d.timeout())
		addresses, err := (appResolver{proxy: proxy, servers: route.DNS, scope: route.scope}).LookupNetIP(attempt, "ip", host)
		if err != nil || len(addresses) == 0 {
			cancel()
			continue
		}
		for _, address := range addresses {
			if RefuseAddr(address, own) != "" {
				cancel()
				return nil, refused(ReasonNonPublicAnswer)
			}
		}
		reason = ReasonConnect
		for _, address := range addresses {
			conn, err := dialSOCKS(attempt, proxy, netip.AddrPortFrom(address.Unmap(), uint16(port)).String(), d.timeout())
			if err == nil {
				cancel()
				return conn, nil
			}
			if attempt.Err() != nil {
				break
			}
		}
		appResolver{scope: route.scope}.forget(host)
		cancel()
		if ctx.Err() != nil {
			break
		}
	}
	return nil, &DialError{Reason: reason, refused: reason == ReasonResolve}
}

// dialAppRouteAddrs dials addresses the caller already judged (an egress-web-v1 IP literal) through the app's own
// circuits, trying its other circuit when one fails. No DNS is involved.
func (d *Dialer) dialAppRouteAddrs(ctx context.Context, route AppRoute, addrs []netip.Addr, port int) (net.Conn, error) {
	for _, proxy := range route.Proxies {
		if ValidateSOCKSProxy(proxy) != nil {
			return nil, refused(ReasonAdmit)
		}
		attempt, cancel := context.WithTimeout(ctx, d.timeout())
		for _, address := range addrs {
			conn, err := dialSOCKS(attempt, proxy, netip.AddrPortFrom(address.Unmap(), uint16(port)).String(), d.timeout())
			if err == nil {
				cancel()
				return conn, nil
			}
			if attempt.Err() != nil {
				break
			}
		}
		cancel()
		if ctx.Err() != nil {
			break
		}
	}
	return nil, &DialError{Reason: ReasonConnect}
}
