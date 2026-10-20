package egress

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"enclave.host/isolation/m2/release"
)

// openedRelease seals {config, secrets} to a fresh seal key exactly as the relay does and opens it through the real
// SealKey.Verify and SealKey.Open, so the Release is one a guest front would hold after a verified Shield release.
func openedRelease(t *testing.T, config any, secrets map[string]string) *release.Release {
	t.Helper()
	idText := "0x" + strings.Repeat("a7", 32)
	id, _ := release.ID(idText)
	var nonce [32]byte
	rand.Read(nonce[:])
	sk, err := release.NewSealKey()
	if err != nil {
		t.Fatal(err)
	}
	pt, _ := json.Marshal(map[string]any{"id": idText, "config": config, "secrets": secrets, "issuedAt": time.Now().UTC().Format(time.RFC3339Nano)})
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sealed := sealTo(t, sk.Public(), id, nonce, pt)
	d, _ := release.ResponseDigest(id, nonce, sk.Public(), sealed)
	resp, err := sk.Verify([]ed25519.PublicKey{pub}, id, nonce, sealed, ed25519.Sign(priv, d[:]), "")
	if err != nil {
		t.Fatal(err)
	}
	rel, err := sk.Open(resp)
	if err != nil {
		t.Fatal(err)
	}
	return rel
}

func hosts(p *Policy) string {
	var got []string
	for _, o := range p.Origins {
		got = append(got, o.Host)
	}
	return strings.Join(got, ",")
}

// Jot's shape: the endpoint is ITSELF a secret ("$R2_ENDPOINT"), so the allowlist exists only once the measured config is
// resolved with the released secrets, in the guest. No relay origin is added: nothing outside the owner's config opens.
func TestForShieldResolvesTheMeasuredConfigWithTheReleasedSecretsAndAddsNoRelay(t *testing.T) {
	cfg := `{"bucket":"jot-notes","endpoint":"$R2_ENDPOINT","accessKeyId":"$R2_KEY","region":"auto",` +
		`"mirror":"https://${ACCOUNT}.r2.cloudflarestorage.com/jot","docs":"see https://docs.example for help"}`
	rel := openedRelease(t, nil, map[string]string{"R2_ENDPOINT": "https://0123abcd.r2.cloudflarestorage.com",
		"R2_KEY": "AKIA-synthetic", "ACCOUNT": "fedc9876"})
	p, err := ForShield(rel, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := hosts(p); got != "0123abcd.r2.cloudflarestorage.com,fedc9876.r2.cloudflarestorage.com" {
		t.Fatalf("origins %s", got)
	}
	if p.Allows("api.enclave.host") || p.Allows("docs.example") {
		t.Fatal("a Shield domain's allowlist opened something its config does not name as an https URL (the relay, or prose)")
	}
	// a placeholder that no secret resolves stays literal, and a literal placeholder in an authority is refused
	rel = openedRelease(t, nil, map[string]string{"R2_ENDPOINT": "https://0123abcd.r2.cloudflarestorage.com"})
	p, err = ForShield(rel, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if hosts(p) != "0123abcd.r2.cloudflarestorage.com" || len(p.Refused) != 1 || !strings.Contains(p.Refused[0], "placeholder") {
		t.Fatalf("origins %s refused %q", hosts(p), p.Refused)
	}
	for _, r := range p.Refused {
		if strings.Contains(r, "cloudflarestorage") || strings.Contains(r, "jot") {
			t.Fatalf("a refusal reason carries URL text (it may be secret): %q", r)
		}
	}
}

func TestForShieldExplicitListReplacesDerivation(t *testing.T) {
	rel := openedRelease(t, nil, map[string]string{"R2_ENDPOINT": "https://0123abcd.r2.cloudflarestorage.com", "ONLY": "https://only.example"})
	p, err := ForShield(rel, `{"egress":["$ONLY"],"endpoint":"$R2_ENDPOINT"}`)
	if err != nil {
		t.Fatal(err)
	}
	if hosts(p) != "only.example" {
		t.Fatalf("origins %s: an explicit list (resolved too) replaces derivation", hosts(p))
	}
	if p, err = ForShield(rel, `{"egress":[],"endpoint":"$R2_ENDPOINT"}`); err != nil || len(p.Origins) != 0 {
		t.Fatalf("an empty explicit list must open nothing: %v %v", err, p)
	}
	for _, bad := range []string{`{"egress":"https://x.example"}`, `{"egress":[1]}`, `not json $ONLY`} {
		if _, err := ForShield(rel, bad); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
	// no config at all: nothing to reach
	if p, err = ForShield(rel, ""); err != nil || len(p.Origins) != 0 {
		t.Fatalf("no config: %v %v", err, p)
	}
}

func TestForShieldTakesOnlyAnAttestedSecretsOnlyRelease(t *testing.T) {
	cfg := `{"endpoint":"$R2_ENDPOINT"}`
	forged := &release.Release{ID: "0x" + strings.Repeat("a7", 32), Secrets: map[string]string{"R2_ENDPOINT": "https://evil.example"}}
	if _, err := ForShield(forged, cfg); err == nil {
		t.Fatal("a Release that did not come through the attested channel built an allowlist")
	}
	if _, err := ForShield(nil, cfg); err == nil {
		t.Fatal("a nil release built an allowlist")
	}
	// a Shield release carries secrets only; one that also carries a config is refused, never merged or preferred
	withConfig := openedRelease(t, map[string]any{"endpoint": "https://other.example"}, map[string]string{"R2_ENDPOINT": "https://a.example"})
	if _, err := ForShield(withConfig, cfg); err == nil {
		t.Fatal("a release carrying its own config was accepted beside the measured one")
	}
}

// The optional host-side list refuses a name before anything is resolved or dialed, and before the rate window.
func TestTheHostSideListRefusesBeforeResolvingOrDialing(t *testing.T) {
	looked := 0
	d, dialed := testDialer(fakeResolver{"notes.example": {"93.184.216.34"}, "other.example": {"93.184.216.35"}}, nil)
	res := d.Resolver.(fakeResolver)
	d.Resolver = resolverFunc(func(ctx context.Context, n, h string) ([]netip.Addr, error) {
		looked++
		return res.LookupNetIP(ctx, n, h)
	})
	d.MaxPerMinute = 1
	d.Allow = (&Policy{Origins: []Origin{{Host: "notes.example"}}}).Allows
	for i := 0; i < 3; i++ {
		if _, _, err := d.Dial(context.Background(), 7, "other.example", 443); ReasonOf(err) != ReasonNotAllowed {
			t.Fatalf("a name off the host's list: %v", err)
		}
	}
	if looked != 0 || len(*dialed) != 0 {
		t.Fatalf("a refused name was resolved (%d) or dialed (%v)", looked, *dialed)
	}
	c, release, err := d.Dial(context.Background(), 7, "notes.example", 443)
	if err != nil {
		t.Fatalf("the listed name, after three refusals, must still be within the guest's one-per-minute window: %v", err)
	}
	c.Close()
	release()
}

// SOCKS mode keeps the host's address rules: a name with ANY non-public answer is refused before the proxy is asked.
func TestSOCKSModeRefusesNonPublicAnswersWithoutAskingTheProxy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	asked := make(chan struct{}, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			asked <- struct{}{}
			c.Close()
		}
	}()
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "169.254.169.254", "100.64.0.1", "::1", "fe80::1", "::ffff:192.168.1.1", "203.0.113.9"} {
		d, dialed := testDialer(fakeResolver{"svc.example": {"93.184.216.34", ip}}, nil)
		d.SOCKSProxy = ln.Addr().String()
		if _, _, err := d.Dial(context.Background(), 7, "svc.example", 443); ReasonOf(err) != ReasonNonPublicAnswer {
			t.Fatalf("%s: %v", ip, err)
		}
		if len(*dialed) != 0 {
			t.Fatalf("%s: dialed directly", ip)
		}
	}
	select {
	case <-asked:
		t.Fatal("the SOCKS entry was asked for a name with a non-public answer")
	case <-time.After(100 * time.Millisecond):
	}
	// and the SOCKS client itself refuses a non-public literal, whoever calls it
	if _, err := dialSOCKS(context.Background(), ln.Addr().String(), "10.0.0.1:443", time.Second); err == nil {
		t.Fatal("dialSOCKS sent a private literal")
	}
}

type resolverFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func TestForShieldPublicHTTPSModeUsesOnlyConfiguredOrigins(t *testing.T) {
	rel := openedRelease(t, nil, map[string]string{"R2_ENDPOINT": "https://0123abcd.r2.cloudflarestorage.com"})
	cfg := `{"egress":"public-https","storage":{"endpoint":"$R2_ENDPOINT"},"targets":{"eyesoff":{"url":"https://eyesoff.ai/chat"}},"bad":"https://127.0.0.1/"}`
	p, err := ForShield(rel, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if hosts(p) != "0123abcd.r2.cloudflarestorage.com,eyesoff.ai" || len(p.Refused) != 1 {
		t.Fatalf("origins %s refused %q", hosts(p), p.Refused)
	}
	if p, err = ForShield(rel, `{"egress":"public-https"}`); err != nil || len(p.Origins) != 0 {
		t.Fatalf("mode alone opens no origins: %v %v", p, err)
	}
	for _, mode := range []string{"public-http", "all", "PUBLIC-HTTPS"} {
		if _, err = ForShield(rel, `{"egress":"`+mode+`"}`); err == nil {
			t.Fatalf("unknown mode %s accepted", mode)
		}
	}
}

// public-web keeps its configured origins as forwarders AND opens the public web (web.go); only the MEASURED bytes
// decide the mode, so a secret that resolves to "public-web" does not.
func TestForShieldPublicWebModeKeepsConfiguredOriginsAndOpensThePublicWeb(t *testing.T) {
	rel := openedRelease(t, nil, map[string]string{"S3_ENDPOINT": "https://0123abcd.r2.cloudflarestorage.com", "MODE": "public-web"})
	p, err := ForShield(rel, `{"egress":"public-web","endpoint":"$S3_ENDPOINT","private":"https://127.0.0.1/","http":"http://example.com/"}`)
	if err != nil {
		t.Fatal(err)
	}
	if hosts(p) != "0123abcd.r2.cloudflarestorage.com" || len(p.Refused) != 1 || !p.PublicWeb {
		t.Fatalf("origins %s refused %q public web %v", hosts(p), p.Refused, p.PublicWeb)
	}
	p, err = ForShield(rel, `{"egress":"public-web"}`)
	if err != nil || len(p.Origins) != 0 || !p.PublicWeb {
		t.Fatalf("mode alone: %v %v", p, err)
	}
	for _, cfg := range []string{`{"egress":"$MODE"}`, `{"egress":"public-https"}`, `{"nested":{"egress":"public-web"}}`, `{}`, ``} {
		if p, err = ForShield(rel, cfg); err != nil || p.PublicWeb {
			t.Fatalf("%s: public web %v (%v)", cfg, p != nil && p.PublicWeb, err)
		}
	}
}
