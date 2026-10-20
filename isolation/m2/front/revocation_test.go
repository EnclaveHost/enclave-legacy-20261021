package main

// On the direct path, a lease the chain quorum AGREES has been cancelled, suspended or released ends the guest's
// owner-name certificates at the next refresh - not after the outage grace - while one lying RPC can neither end nor
// extend them, and an in-flight ACME order that completes after a revocation installs nothing.

import (
	"context"
	"crypto/x509"
	"net/http"
	"strings"
	"testing"
	"time"

	"enclave.host/isolation/m2/bootstrap"
)

func TestDirectAgreedCancellationEndsServedNamesAtOnce(t *testing.T) {
	for _, end := range []string{"inactive", "released"} {
		t.Run(end, func(t *testing.T) {
			w := newNamesWorld(t)
			prov, rows, info, _ := namesStartup(t, `{"hosts":["shop.example.com"]}`)
			f := namesFront(t, w)
			names, err := f.startOwnerNames(prov.owner, w.egress, w.pool)
			if err != nil || names == nil {
				t.Fatal(err)
			}
			f.names = names
			chain := w.root.issue(t, mustPub(t, f.spki), "shop.example.com", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
			if rec := get(t, f, "POST", certPath+"?name=shop.example.com", chain); rec.Code != 200 {
				t.Fatalf("install: %d %s", rec.Code, rec.Body)
			}
			if _, err := handshake(t, f, w.pool, "shop.example.com"); err != nil {
				t.Fatal(err)
			}

			// one lying RPC reporting the end: the honest pair's live lease stands
			rows.answer("three.example", info[end])
			if !names.refresh(context.Background()) {
				t.Fatal("one liar revoked an honest pair's live lease")
			}
			if _, err := handshake(t, f, w.pool, "shop.example.com"); err != nil {
				t.Fatal("a single liar stopped the certificate being served")
			}

			// no two RPCs agree (one ended, one live, one unusable): an outage, the grant stands to its bound
			rows.answer("two.example", "0x")
			if !names.refresh(context.Background()) || len(names.authorized()) != 1 {
				t.Fatal("an unavailable quorum revoked")
			}

			// two honest fresh RPCs agree the lease ended: revoked now, whatever the third says
			rows.answer("one.example", info[end])
			rows.answer("two.example", info[end])
			rows.answer("three.example", info["base"])
			if names.refresh(context.Background()) {
				t.Fatalf("an agreed %s lease did not revoke", end)
			}
			if _, err := handshake(t, f, w.pool, "shop.example.com"); err == nil {
				t.Fatal("the CA certificate is still served after an agreed cancellation")
			}
			if rec := get(t, f, "GET", csrPath+"?name=shop.example.com", nil); rec.Code != http.StatusForbidden {
				t.Fatalf("CSR after cancellation: %d", rec.Code)
			}
			if rec := get(t, f, "GET", namesPath, nil); !strings.Contains(rec.Body.String(), `"revoked"`) || strings.Contains(rec.Body.String(), `"authorizedUntil"`) {
				t.Fatalf("status: %s", rec.Body)
			}
			rows.set(info["base"])
			if names.refresh(context.Background()) || len(names.authorized()) != 0 {
				t.Fatal("a later live answer restored the names")
			}
		})
	}
}

// An ACME order in flight when the grant is revoked: the CA still signs, the guest installs nothing.
func TestInFlightACMEOrderDoesNotInstallAfterRevocation(t *testing.T) {
	w := newNamesWorld(t)
	sel := &bootstrap.NameACME{Directory: "https://" + caHost + "/dir", Challenge: "https://" + dnsBHost, Zone: zoneB}
	auth := &fakeAuthority{grant: grantFor("0x"+strings.Repeat("33", 20), sel, "shop.example.com")}
	f := namesFront(t, w)
	names, err := newOwnerNames(auth, f.certs, w.pool)
	if err != nil {
		t.Fatal(err)
	}
	names.issuer, err = newACMEIssuer(names, f.certs, "", nil, ownerHTTP(w.egress, w.pool), f.attestDocJSON, f.certs.key, f.spki)
	if err != nil {
		t.Fatal(err)
	}
	alias, _ := bootstrap.ChallengeAlias(auth.grant.Deployment, auth.grant.Owner, zoneB)
	w.cname["_acme-challenge.shop.example.com"] = alias
	// the quorum reports the lease cancelled while the CA is signing: the refresh lands mid-order
	w.onFinalize = func() {
		auth.mu.Lock()
		auth.err = bootstrap.ErrRevoked
		auth.mu.Unlock()
		if names.refresh(context.Background()) {
			t.Error("refresh did not revoke")
		}
	}
	if n := names.issuer.pass(context.Background()); n != 0 {
		t.Fatal("a certificate ordered before the revocation was installed after it")
	}
	if v := names.issuer.view("shop.example.com"); !strings.Contains(v.LastError, "revoked") {
		t.Fatalf("the issuer does not say why: %+v", v)
	}
	signed := false
	w.mu.Lock()
	for _, o := range w.orders {
		signed = signed || o.cert != nil
	}
	w.mu.Unlock()
	if !signed {
		t.Fatal("the scenario never reached the CA's signature")
	}
	if _, err := handshake(t, f, w.pool, "shop.example.com"); err == nil {
		t.Fatal("the revoked name is served with the late certificate")
	}
	var leaf *x509.Certificate
	if child := f.certs.forName("shop.example.com"); child != nil {
		leaf = child.current()
	}
	if leaf != nil {
		t.Fatal("a certificate state survived revocation")
	}
}
