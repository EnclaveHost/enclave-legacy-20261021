package main

// Custom names are learned INSIDE the guest from the existing domain authority
// over verified TLS. A host-supplied name never authorizes a CSR or certificate.
// Successful snapshots replace the set; outages expire it after five minutes.
// A direct guest never runs this watcher: its names are the owner's committed
// set (setOwnerNames, names.go), bounded by the guest's own chain reads.
import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"enclave.host/isolation/m2/bootstrap"
	"enclave.host/isolation/m2/egress"
	"enclave.host/isolation/m2/release"
	"enclave.host/isolation/m2/vsock"
)

func (c *certState) forName(name string) *certState {
	if name == "" || name == c.name {
		return c
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !time.Now().Before(c.aliasesUntil) {
		return nil
	}
	return c.aliases[name]
}

func (c *certState) setDomains(domains map[string]string, id string, until time.Time) {
	next := make(map[string]*certState)
	c.mu.Lock()
	defer c.mu.Unlock()
	for name, owner := range domains {
		if owner != id || name != strings.ToLower(name) || name == c.name {
			continue
		}
		o, err := egress.ParseOrigin("https://" + name)
		if err != nil || o.Host != name || strings.HasSuffix(name, ".enclave.host") || name == "enclave.host" {
			continue
		}
		if len(next) >= 10 {
			break
		} // same per-deployment bound as the authority
		child := c.aliases[name]
		if child == nil {
			child = &certState{name: name, key: c.key, spki: c.spki, self: c.self}
		}
		next[name] = child
	}
	c.aliases, c.aliasesUntil = next, until
}

// setOwnerNames is the direct guest's alias set: exactly the hosts the owner's package committed (validated by
// bootstrap.Names), never a relay map. Each name's certificate must chain to roots. Children survive a refresh, so
// an installed certificate is kept while the grant renews; an empty set (revocation) drops every one at once.
func (c *certState) setOwnerNames(hosts []string, until time.Time, roots *x509.CertPool) {
	next := make(map[string]*certState, len(hosts))
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, name := range hosts {
		if name == c.name || len(next) >= bootstrap.MaxOwnerNames || !bootstrap.OwnerHost(name) {
			continue
		}
		child := c.aliases[name]
		if child == nil || child.roots != roots {
			child = &certState{name: name, key: c.key, spki: c.spki, self: c.self, roots: roots}
		}
		next[name] = child
	}
	if len(next) == 0 {
		next, until = nil, time.Time{}
	}
	c.aliases, c.aliasesUntil = next, until
}

func (c *certState) watchDomains(ctx context.Context, id string) {
	roots, err := release.RelayRoots()
	if err != nil {
		return
	}
	origin := egress.Origin{Host: release.RelayHost}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10,
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: origin.Host, MinVersion: tls.VersionTLS12},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return egress.DialOrigin(func() (net.Conn, error) { return vsock.Dial(vsock.CIDHost, EgressPort) }, origin)
		}}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+origin.Host+"/v1/domains/map", nil)
		if err != nil {
			return
		}
		resp, err := cl.Do(req)
		if err == nil {
			b, readErr := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
			resp.Body.Close()
			var doc struct {
				Domains map[string]string `json:"domains"`
			}
			if resp.StatusCode == 200 && readErr == nil && len(b) <= 4<<20 && json.Unmarshal(b, &doc) == nil && doc.Domains != nil {
				c.setDomains(doc.Domains, id, time.Now().Add(5*time.Minute))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}
