package egress

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDoH answers every query from a table and counts the queries per app
// proxy and type; it restores the real resolver and an empty cache after.
func fakeDoH(t *testing.T, ttl uint32, fail bool) (asked func(kind int) int, setNow func(time.Time)) {
	t.Helper()
	var mu sync.Mutex
	counts := map[int]int{}
	now := time.Unix(1_800_000_000, 0)
	oldQuery, oldNow := dnsQuery, dnsNow
	dnsMu.Lock()
	dnsCache = map[dnsKey]dnsEntry{}
	dnsMu.Unlock()
	dnsNow = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	dnsQuery = func(ctx context.Context, proxy string, server DNSEndpoint, host string, kind int) ([]netip.Addr, uint32, error) {
		mu.Lock()
		counts[kind]++
		mu.Unlock()
		if fail {
			return nil, 0, errors.New("unreachable")
		}
		if kind == 1 {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, ttl, nil
		}
		return []netip.Addr{netip.MustParseAddr("2606:2800:220:1::1")}, ttl, nil
	}
	t.Cleanup(func() {
		dnsQuery, dnsNow = oldQuery, oldNow
		dnsMu.Lock()
		dnsCache = map[dnsKey]dnsEntry{}
		dnsMu.Unlock()
	})
	return func(kind int) int { mu.Lock(); defer mu.Unlock(); return counts[kind] },
		func(t time.Time) { mu.Lock(); now = t; mu.Unlock() }
}

var dohServers = []DNSEndpoint{{Address: "1.1.1.1:443", ServerName: "cloudflare-dns.com", Path: "/dns-query"}}

func TestAppDNSIsCachedPerAppForItsTTL(t *testing.T) {
	asked, setNow := fakeDoH(t, 60, false)
	a := appResolver{proxy: "127.0.0.1:1", servers: dohServers, scope: "0x" + strings.Repeat("a", 64)}
	for i := 0; i < 3; i++ {
		got, err := a.LookupNetIP(context.Background(), "ip", "Store.example")
		if err != nil || len(got) != 2 || !got[0].Is4() || !got[1].Is6() {
			t.Fatalf("lookup %d: %v %v", i, got, err)
		}
	}
	if asked(1) != 1 || asked(28) != 1 {
		t.Fatalf("a cached answer was asked again: A=%d AAAA=%d", asked(1), asked(28))
	}
	// another app never sees this app's answer
	b := appResolver{proxy: "127.0.0.1:2", servers: dohServers, scope: "0x" + strings.Repeat("b", 64)}
	if _, err := b.LookupNetIP(context.Background(), "ip", "store.example"); err != nil || asked(1) != 2 {
		t.Fatalf("another app used a cached answer: A=%d %v", asked(1), err)
	}
	// the answer's own TTL ends the entry
	setNow(time.Unix(1_800_000_000+61, 0))
	if _, err := a.LookupNetIP(context.Background(), "ip", "store.example"); err != nil || asked(1) != 3 {
		t.Fatalf("an expired answer was served: A=%d %v", asked(1), err)
	}
	// forget (all addresses failed to connect) drops it at once
	a.forget("STORE.example")
	if _, err := a.LookupNetIP(context.Background(), "ip", "store.example"); err != nil || asked(1) != 4 {
		t.Fatalf("a forgotten answer was served: A=%d %v", asked(1), err)
	}
}

func TestAppDNSCapsTTLAndNeverCachesZeroTTLOrFailure(t *testing.T) {
	asked, setNow := fakeDoH(t, 86400, false)
	a := appResolver{proxy: "127.0.0.1:1", servers: dohServers, scope: "0x" + strings.Repeat("c", 64)}
	a.LookupNetIP(context.Background(), "ip", "long.example")
	setNow(time.Unix(1_800_000_000, 0).Add(dnsCacheMax + time.Second))
	a.LookupNetIP(context.Background(), "ip", "long.example")
	if asked(1) != 2 {
		t.Fatalf("a day-long TTL outlived the cap: A=%d", asked(1))
	}

	asked, _ = fakeDoH(t, 0, false)
	a.LookupNetIP(context.Background(), "ip", "zero.example")
	a.LookupNetIP(context.Background(), "ip", "zero.example")
	if asked(1) != 2 {
		t.Fatalf("a zero-TTL answer was cached: A=%d", asked(1))
	}

	asked, _ = fakeDoH(t, 60, true)
	for i := 0; i < 2; i++ {
		if _, err := a.LookupNetIP(context.Background(), "ip", "down.example"); err == nil {
			t.Fatal("a failed lookup answered")
		}
	}
	if asked(1) != 2 {
		t.Fatalf("a failure was cached: A=%d", asked(1))
	}
	// and an unscoped resolver (no app) never caches
	asked, _ = fakeDoH(t, 60, false)
	u := appResolver{proxy: "127.0.0.1:1", servers: dohServers}
	u.LookupNetIP(context.Background(), "ip", "x.example")
	u.LookupNetIP(context.Background(), "ip", "x.example")
	if asked(1) != 2 {
		t.Fatalf("an unscoped answer was cached: A=%d", asked(1))
	}
}

func TestAppDNSAsksAAndAAAAInParallel(t *testing.T) {
	fakeDoH(t, 60, false)
	started := make(chan int, 2)
	release := make(chan struct{})
	dnsQuery = func(ctx context.Context, proxy string, server DNSEndpoint, host string, kind int) ([]netip.Addr, uint32, error) {
		started <- kind
		<-release
		if kind == 1 {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, 60, nil
		}
		return nil, 0, nil
	}
	done := make(chan error, 1)
	go func() {
		_, err := appResolver{proxy: "127.0.0.1:1", servers: dohServers}.LookupNetIP(context.Background(), "ip", "p.example")
		done <- err
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			close(release)
			t.Fatal("AAAA waited for A: the two lookups ran one after the other")
		}
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAppDialForgetsAnAnswerWhoseAddressesAllFail(t *testing.T) {
	asked, _ := fakeDoH(t, 300, false)
	id := "0x" + strings.Repeat("d", 64)
	d := Dialer{Resolver: panicResolver{}, RouteFor: func(uint32) (AppRoute, error) {
		// port 1 refuses: every resolved address fails to connect
		return AppRoute{Proxies: []string{"127.0.0.1:1"}, DNS: dohServers, scope: id}, nil
	}}
	for i := 0; i < 2; i++ {
		if _, _, err := d.Dial(context.Background(), 12, "gone.example", 443); err == nil {
			t.Fatal("dial to a refusing proxy succeeded")
		}
	}
	if asked(1) != 2 {
		t.Fatalf("an answer whose addresses all failed was reused: A=%d", asked(1))
	}
}
