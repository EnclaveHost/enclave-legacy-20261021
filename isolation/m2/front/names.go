package main

// Owner-committed names for a DIRECT guest (bootstrap.Names): the custom DNS names its owner listed in the startup
// package the guest verified against its own chain quorum. No relay domain map, CA account, expected-guest
// prediction or platform DNS zone is involved in deciding them.
//
// What a listed name is worth: the guest will produce a CSR for it, for its own attested key, and install a
// certificate for it that chains to this image's measured WebPKI roots (certs.go). It is NOT proof that the owner
// controls the name; a CA's DNS validation is, through the owner's own _acme-challenge delegation. So a package that
// lists someone else's name yields a CSR nobody can get signed, never a trusted certificate.
//
// While the authorization lasts: names follow the guest's fresh chain reads (bootstrap.Authorization.Refresh). An
// owner, runner, operator, app or envelope change revokes them for good and the guest falls back to its self-signed
// carrier for those names at the next handshake; an RPC outage lets them lapse after bootstrap.NameGrace; they never
// outlive the lease.
//
//	GET /.well-known/enclave-names   public state: committed names, grant expiry, each name's certificate and
//	                                 issuance state, and the limits that apply. Nothing secret is in it.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"enclave.host/isolation/m2/bootstrap"
	"enclave.host/isolation/m2/egress"
)

const namesPath = "/.well-known/enclave-names"

// ownerStartup is what direct provisioning hands main for names: the authorization (kept for refreshes) and, when
// the owner selected an EAB-bound CA, the binding resolved from custody secrets. It stays in this process's memory.
type ownerStartup struct {
	auth   nameAuthority
	eabKID string
	eabKey []byte
	eabErr string
}

type nameAuthority interface {
	Refresh(context.Context) error
	NameGrant() (bootstrap.NameGrant, error)
}

// eabFrom resolves the named custody secrets. A CA's HMAC key is base64url (RFC 8555 section 7.3.4); a value that
// does not decode, or a missing secret, disables in-guest issuance and says why, but never stops the app.
func eabFrom(secrets map[string]string, eab *bootstrap.NameEAB) (string, []byte, string) {
	kid, mac := secrets[eab.KID], secrets[eab.HMAC]
	if kid == "" || mac == "" {
		return "", nil, "the committed EAB secrets are not in this deployment's custody release"
	}
	key, err := base64.RawURLEncoding.DecodeString(mac)
	if err != nil {
		key, err = base64.URLEncoding.DecodeString(mac)
	}
	if err != nil || len(key) < 16 || len(kid) > 256 {
		return "", nil, "the committed EAB HMAC secret is not a base64url key of at least 16 bytes"
	}
	return kid, key, ""
}

type ownerNames struct {
	auth    nameAuthority
	certs   *certState
	roots   *x509.CertPool
	now     func() time.Time
	mu      sync.Mutex
	grant   bootstrap.NameGrant
	revoked string
	issuer  *acmeIssuer // nil: issuance is external only (CSR/install endpoints)
	eabErr  string
}

// newOwnerNames applies the grant authorized at startup; nil when the package names no hosts.
func newOwnerNames(auth nameAuthority, certs *certState, roots *x509.CertPool) (*ownerNames, error) {
	if auth == nil || certs == nil || roots == nil {
		return nil, errors.New("owner names need an authorization, a certificate state and measured roots")
	}
	g, err := auth.NameGrant()
	if err != nil {
		return nil, err
	}
	if len(g.Hosts) == 0 {
		return nil, nil
	}
	o := &ownerNames{auth: auth, certs: certs, roots: roots, now: time.Now}
	o.apply(g)
	return o, nil
}

func (o *ownerNames) apply(g bootstrap.NameGrant) {
	o.mu.Lock()
	o.grant = g
	o.mu.Unlock()
	o.certs.setOwnerNames(g.Hosts, g.Until, o.roots)
}

func (o *ownerNames) revoke(why string) {
	o.mu.Lock()
	o.revoked = why
	o.mu.Unlock()
	o.certs.setOwnerNames(nil, time.Time{}, o.roots)
}

// refresh: one fresh chain read. Returns false once the names are revoked for good.
func (o *ownerNames) refresh(ctx context.Context) bool {
	err := o.auth.Refresh(ctx)
	switch {
	case errors.Is(err, bootstrap.ErrRevoked):
		o.revoke("the deployment's owner, runner, operator, app reference or startup commitment changed")
		fmt.Printf("DOM names: revoked; owner-committed names now get the self-signed carrier only\n")
		return false
	case err != nil:
		return true // lapses on its own at the grant's end
	}
	g, err := o.auth.NameGrant()
	if err == nil {
		o.apply(g)
	}
	return true
}

func (o *ownerNames) watch(ctx context.Context, every time.Duration) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
		if !o.refresh(ctx) {
			return
		}
	}
}

// authorized: the hosts certifiable right now (none once revoked or lapsed).
func (o *ownerNames) authorized() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.revoked != "" || !o.now().Before(o.grant.Until) {
		return nil
	}
	return append([]string(nil), o.grant.Hosts...)
}

func (o *ownerNames) authorizes(name string) bool {
	for _, h := range o.authorized() {
		if h == name {
			return true
		}
	}
	return false
}

type nameCert struct {
	Issuer    string `json:"issuer"`
	Serial    string `json:"serial"`
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
	RenewAt   string `json:"renewAt"`
}

type nameStatus struct {
	Name        string     `json:"name"`
	Authorized  bool       `json:"authorized"`
	Certificate *nameCert  `json:"certificate"`
	Issuance    *issueView `json:"issuance,omitempty"`
}

func renewAt(leaf *x509.Certificate) time.Time {
	return leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) * 2 / 3)
}

func (o *ownerNames) status() map[string]any {
	o.mu.Lock()
	g, revoked, eabErr := o.grant, o.revoked, o.eabErr
	o.mu.Unlock()
	now := o.now()
	live := revoked == "" && now.Before(g.Until)
	out := map[string]any{
		"version":    1,
		"source":     "owner-committed startup package",
		"deployment": "0x" + hex.EncodeToString(g.Deployment[:]),
		"owner":      g.Owner,
		"authorized": live,
		"proof":      "a listed name is the owner's word only; a certificate below chains to this image's measured WebPKI roots, so a CA validated that name through its DNS",
		"limits": []string{
			"the TLS key lives only in this guest's memory, so every relaunch needs new certificates; CAs cap duplicate certificates (Let's Encrypt: 5 per exact name set per week), so choose a CA without that cap or limit relaunches",
			"names lapse after a missed chain refresh window and never outlive the lease; an ownership change revokes them",
		},
	}
	if live {
		out["authorizedUntil"] = g.Until.UTC().Format(time.RFC3339)
	}
	if revoked != "" {
		out["revoked"] = revoked
	}
	issuance := "external: any party may fetch this guest's CSR and install a CA certificate for a listed name"
	if g.ACME != nil {
		alias, _ := bootstrap.ChallengeAlias(g.Deployment, g.Owner, g.ACME.Zone)
		out["acme"] = map[string]any{"directory": g.ACME.Directory, "challenge": g.ACME.Challenge, "zone": g.ACME.Zone,
			"challengeAlias": alias, "eab": g.ACME.EAB != nil}
		issuance = "in-guest ACME dns-01 through the owner-selected responder; each host needs _acme-challenge.<host> CNAME " + alias
		if eabErr != "" {
			out["acmeDisabled"] = eabErr
		}
	}
	out["issuance"] = issuance
	var names []nameStatus
	for _, h := range g.Hosts {
		s := nameStatus{Name: h, Authorized: live}
		if child := o.certs.forName(h); live && child != nil {
			if leaf := child.current(); leaf != nil {
				s.Certificate = &nameCert{Issuer: leaf.Issuer.CommonName, Serial: leaf.SerialNumber.Text(16),
					NotBefore: leaf.NotBefore.UTC().Format(time.RFC3339), NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339),
					RenewAt: renewAt(leaf).UTC().Format(time.RFC3339)}
			}
		}
		if o.issuer != nil {
			s.Issuance = o.issuer.view(h)
		}
		names = append(names, s)
	}
	out["names"] = names
	return out
}

func (o *ownerNames) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	if o == nil {
		http.Error(w, "this guest serves no owner-committed names", http.StatusNotFound)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(o.status())
}

// startOwnerNames applies a direct guest's committed names and, when the owner selected a CA, prepares the in-guest
// issuer (started once the app serves). Issuance problems are stated on the names endpoint; they never stop the app.
func (f *front) startOwnerNames(o *ownerStartup, dial func() (net.Conn, error), roots *x509.CertPool) (*ownerNames, error) {
	if o == nil || o.auth == nil || roots == nil {
		return nil, errors.New("owner names need the startup authorization and measured roots")
	}
	names, err := newOwnerNames(o.auth, f.certs, roots)
	if err != nil {
		// startup preparation outlasted the snapshot's freshness: one fresh read, else no names (the app still starts)
		if errors.Is(o.auth.Refresh(context.Background()), bootstrap.ErrRevoked) {
			return nil, nil
		}
		if names, err = newOwnerNames(o.auth, f.certs, roots); err != nil {
			fmt.Printf("DOM names: not applied (%v); owner-committed names get the self-signed carrier only\n", err)
			return nil, nil
		}
	}
	if names == nil {
		return nil, nil
	}
	names.eabErr = o.eabErr
	if names.grant.ACME != nil && o.eabErr == "" {
		iss, err := newACMEIssuer(names, f.certs, o.eabKID, o.eabKey, ownerHTTP(dial, roots), f.attestDocJSON, f.certs.key, f.spki)
		if err != nil {
			names.eabErr = err.Error()
		} else {
			names.issuer = iss
		}
	}
	o.eabKey = nil
	fmt.Printf("DOM names: %d owner-committed name(s) until %s; issuance %s\n", len(names.grant.Hosts),
		names.grant.Until.UTC().Format(time.RFC3339), map[bool]string{true: "in-guest ACME", false: "external only"}[names.issuer != nil])
	go names.watch(context.Background(), time.Minute)
	return names, nil
}

// ownerHTTP reaches the owner-selected CA and responder through the host's egress, verifying TLS against the roots
// measured into this image. The host chooses only whether to connect; it cannot read or alter what is sent.
func ownerHTTP(dial func() (net.Conn, error), roots *x509.CertPool) *http.Client {
	tr := &http.Transport{Proxy: nil, MaxResponseHeaderBytes: 16 << 10, TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil || port != "443" || ctx.Err() != nil {
				return nil, errors.New("owner-selected origins are HTTPS on 443 only")
			}
			return egress.DialOrigin(dial, egress.Origin{Host: host})
		}}
	return &http.Client{Transport: tr, Timeout: 60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
