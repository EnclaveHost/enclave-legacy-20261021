package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"enclave.host/isolation/m2/bootstrap"
)

// pushVector is one challenge push exactly as acmeIssuer.push sends it. relay/dns-challenge-attested.mjs must derive
// the same nonce and verify the same signature (test/dns-relay-attested.test.mjs reads this file).
type pushVector struct {
	Body, Sig, Nonce, Alias string
}

const pushVectorPath = "testdata/attested-push.json"

func TestAttestedPushWireFormatVector(t *testing.T) {
	if os.Getenv("UPDATE_PUSH_VECTOR") == "1" {
		var got pushVector
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			got.Body, got.Sig = string(b), r.Header.Get("x-attested-sig")
			w.Write([]byte(`{"ok":true}`))
		}))
		defer srv.Close()
		c := newCertState(t, "11111111.app.enclave.host")
		f := &front{spki: c.spki, appSha: make([]byte, 32), certs: c}
		f.appSha[0] = 0x44
		var id [32]byte
		for i := range id {
			id[i] = 0x11
		}
		g := bootstrap.NameGrant{Deployment: id, Owner: "0x" + strings.Repeat("33", 20), Hosts: []string{"shop.example.com"},
			ACME: &bootstrap.NameACME{Directory: "https://ca.example/dir", Challenge: srv.URL, Zone: "acme.example.net"}, Until: time.Now().Add(time.Hour)}
		names, _ := newOwnerNames(&fakeAuthority{grant: g}, c, x509.NewCertPool())
		iss, err := newACMEIssuer(names, c, "", nil, srv.Client(), f.attestDocJSON, c.key, c.spki)
		if err != nil {
			t.Fatal(err)
		}
		iss.cfg.Challenge = srv.URL
		if err := iss.push(context.Background(), "set", strings.Repeat("A", 43)); err != nil {
			t.Fatal(err)
		}
		var p challengePush
		json.Unmarshal([]byte(got.Body), &p)
		got.Nonce, got.Alias = hex.EncodeToString(pushNonce(p)), iss.alias
		b, _ := json.MarshalIndent(got, "", " ")
		if err := os.WriteFile(pushVectorPath, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(pushVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var v pushVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var p challengePush
	if err := json.Unmarshal([]byte(v.Body), &p); err != nil {
		t.Fatal(err)
	}
	if again, _ := json.Marshal(p); string(again) != v.Body {
		t.Fatal("the push's field order or encoding drifted from the vector")
	}
	var doc struct{ TransportKey, Nonce string }
	json.Unmarshal(p.Attestation, &doc)
	if hex.EncodeToString(pushNonce(p)) != v.Nonce || doc.Nonce != v.Nonce || doc.TransportKey != p.SPKI || p.Name != v.Alias {
		t.Fatal("the push nonce or attestation binding drifted")
	}
	spki, _ := base64.StdEncoding.DecodeString(p.SPKI)
	pub, err := x509.ParsePKIXPublicKey(spki)
	sig, _ := base64.StdEncoding.DecodeString(v.Sig)
	digest := sha256.Sum256(append([]byte(pushSigPrefix), v.Body...))
	if err != nil || !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("the vector's signature does not verify")
	}
	var id [32]byte
	b, _ := hex.DecodeString(strings.TrimPrefix(p.Deployment, "0x"))
	copy(id[:], b)
	if alias, _ := bootstrap.ChallengeAlias(id, p.Owner, "acme.example.net"); alias != p.Name {
		t.Fatal("the vector's alias is not the deployment and owner's")
	}
}
