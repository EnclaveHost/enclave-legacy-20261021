package main

// Owner-committed names on the DIRECT path, end to end: a startup package verified against a fake chain quorum
// (runDirect, with Enclave's release ticket refusing), the names it commits applied to the front's certificate
// state, in-guest ACME through the host egress protocol to an RFC 8555 CA, a DNS-01 push to the OWNER-selected
// responder (a second responder, standing in for a platform default, must never be contacted), the CA following
// the owner's CNAME delegation, and the certificate served on the guest's own attested key. Then: names the owner
// never delegated fail at the CA, a foreign name gets no CSR, a changed owner revokes everything and moves the alias,
// and a chain for another key or another root is refused.

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"enclave.host/isolation/m2/bootstrap"
)

const (
	caHost   = "ca.example"
	dnsAHost = "dns-a.example" // stands in for a platform default: never selected, so never contacted
	dnsBHost = "dns-b.example" // the owner's explicit choice
	zoneA    = "acme.zone-a.example"
	zoneB    = "acme.zone-b.example"
)

var b64 = base64.RawURLEncoding

// namesWorld is everything outside the guest: the host's egress service, one TLS server answering for the CA and
// both responders, the owner's DNS (CNAMEs) and each responder's TXT store.
type namesWorld struct {
	t       *testing.T
	root    *testCA
	pool    *x509.CertPool
	addr    string
	mu      sync.Mutex
	origins []string                  // every host the guest asked the host's egress to reach
	cname   map[string]string         // _acme-challenge.<host> -> alias, as the name's DNS controller published it
	txt     map[string]map[string]int // zone -> "name value" -> count, per responder
	hits    map[string]int
	eabKID  string
	eabKey  []byte
	acct    struct{ thumb string }
	orders  map[string]*fakeOrder
	nonce   atomic.Int64
	pushes  []challengePush
	spki    []byte // the guest key the responder accepts pushes for
	// onFinalize runs while the CA signs (under the world lock): a revocation landing mid-order
	onFinalize func()
}

type fakeOrder struct {
	name, token, status, authz string
	cert                       []byte
}

func newNamesWorld(t *testing.T) *namesWorld {
	w := &namesWorld{t: t, root: newTestCA(t), cname: map[string]string{}, txt: map[string]map[string]int{zoneA: {}, zoneB: {}},
		hits: map[string]int{}, orders: map[string]*fakeOrder{}}
	w.pool = x509.NewCertPool()
	w.pool.AddCert(w.root.cert)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "services"},
		DNSNames: []string{caHost, dnsAHost, dnsBHost}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, w.root.cert, &k.PublicKey, w.root.key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(w.serve))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der, w.root.cert.Raw}, PrivateKey: k}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	w.addr = srv.Listener.Addr().String()
	return w
}

// egress is the HOST's egress service as the guest sees it (egress-v1 framing): it reaches the test services by
// name and refuses everything else, recording every origin asked for.
func (w *namesWorld) egress() (net.Conn, error) {
	guest, host := net.Pipe()
	go func() {
		defer host.Close()
		br := bufio.NewReader(host)
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		f := strings.Fields(line)
		if len(f) != 3 || f[0] != "egress-v1" || f[2] != "443" {
			return
		}
		w.mu.Lock()
		w.origins = append(w.origins, f[1])
		w.mu.Unlock()
		if f[1] != caHost && f[1] != dnsAHost && f[1] != dnsBHost {
			io.WriteString(host, "refused\n")
			return
		}
		up, err := net.Dial("tcp", w.addr)
		if err != nil {
			return
		}
		defer up.Close()
		io.WriteString(host, "ok\n")
		go io.Copy(up, br)
		io.Copy(host, up)
	}()
	return guest, nil
}

func (w *namesWorld) serve(rw http.ResponseWriter, r *http.Request) {
	host := strings.Split(r.Host, ":")[0]
	w.mu.Lock()
	w.hits[host]++
	w.mu.Unlock()
	switch host {
	case caHost:
		w.ca(rw, r)
	case dnsBHost:
		w.responder(rw, r, zoneB)
	case dnsAHost:
		http.Error(rw, "this responder was never selected", http.StatusForbidden)
	default:
		http.Error(rw, "unknown host", http.StatusNotFound)
	}
}

// responder is a minimal stand-in for relay/dns-relay.js DNS_CHALLENGE_AUTH=attested (whose full judge is tested in
// test/dns-relay-attested.test.mjs): the push must be signed by the key it names, that key must be the attested
// guest key, the attestation must bind exactly this push, and the alias label must commit to deployment and owner.
func (w *namesWorld) responder(rw http.ResponseWriter, r *http.Request, zone string) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	var p challengePush
	if r.URL.Path != "/v1/txt" || json.Unmarshal(raw, &p) != nil {
		http.Error(rw, "bad push", 400)
		return
	}
	spki, _ := base64.StdEncoding.DecodeString(p.SPKI)
	pub, err := x509.ParsePKIXPublicKey(spki)
	sig, _ := base64.StdEncoding.DecodeString(r.Header.Get("x-attested-sig"))
	digest := sha256.Sum256(append([]byte(pushSigPrefix), raw...))
	if err != nil || !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), digest[:], sig) {
		http.Error(rw, "signature is not by the named key", 403)
		return
	}
	var doc struct{ TransportKey, Nonce string }
	json.Unmarshal(p.Attestation, &doc)
	if doc.TransportKey != p.SPKI || doc.Nonce != hex.EncodeToString(pushNonce(p)) || !bytes.Equal(spki, w.spki) {
		http.Error(rw, "the attestation does not bind this key and push", 403)
		return
	}
	var id [32]byte
	b, _ := hex.DecodeString(strings.TrimPrefix(p.Deployment, "0x"))
	copy(id[:], b)
	if alias, _ := bootstrap.ChallengeAlias(id, p.Owner, zone); alias != p.Name {
		http.Error(rw, "label does not commit to this deployment and owner", 403)
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pushes = append(w.pushes, p)
	if (p.Op == "set") != (r.Method == http.MethodPost) {
		http.Error(rw, "op/method", 400)
		return
	}
	k := p.Name + " " + p.Value
	if p.Op == "set" {
		w.txt[zone][k]++
	} else {
		delete(w.txt[zone], k)
	}
	rw.Write([]byte(`{"ok":true}`))
}

// lookupTXT is what a CA's resolver sees: follow the CNAME the name's DNS controller published, then read TXT there.
func (w *namesWorld) validated(name, value string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	alias, ok := w.cname["_acme-challenge."+name]
	if !ok {
		return false
	}
	for zone, store := range w.txt {
		if strings.HasSuffix(alias, "."+zone) && store[alias+" "+value] > 0 {
			return true
		}
	}
	return false
}

func thumbprint(jwk map[string]any) string {
	b, _ := json.Marshal(map[string]any{"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]})
	h := sha256.Sum256(b) // encoding/json sorts map keys: RFC 7638's lexicographic member order
	return b64.EncodeToString(h[:])
}

// ca is a minimal RFC 8555 server: directory, nonces, accounts (with EAB when configured), orders, dns-01 validation
// through the world's DNS, finalize and certificate download.
func (w *namesWorld) ca(rw http.ResponseWriter, r *http.Request) {
	base := "https://" + caHost
	rw.Header().Set("Replay-Nonce", fmt.Sprint("n", w.nonce.Add(1)))
	reply := func(code int, v any) {
		rw.Header().Set("content-type", "application/json")
		rw.WriteHeader(code)
		json.NewEncoder(rw).Encode(v)
	}
	if r.URL.Path == "/dir" {
		reply(200, map[string]any{"newNonce": base + "/nonce", "newAccount": base + "/acct", "newOrder": base + "/order",
			"revokeCert": base + "/revoke", "keyChange": base + "/key", "meta": map[string]any{"termsOfService": base + "/tos",
				"externalAccountRequired": w.eabKey != nil}})
		return
	}
	if r.URL.Path == "/nonce" {
		rw.WriteHeader(200)
		return
	}
	var j struct{ Protected, Payload, Signature string }
	if json.NewDecoder(r.Body).Decode(&j) != nil {
		reply(400, map[string]string{"type": "urn:ietf:params:acme:error:malformed"})
		return
	}
	var hdr map[string]any
	hb, _ := b64.DecodeString(j.Protected)
	json.Unmarshal(hb, &hdr)
	payload, _ := b64.DecodeString(j.Payload)
	w.mu.Lock()
	defer w.mu.Unlock()
	switch p := r.URL.Path; {
	case p == "/acct":
		jwk, _ := hdr["jwk"].(map[string]any)
		var req struct {
			TOS bool `json:"termsOfServiceAgreed"`
			EAB *struct{ Protected, Payload, Signature string }
		}
		json.Unmarshal(payload, &req)
		if !req.TOS || jwk == nil {
			reply(400, map[string]string{"type": "urn:ietf:params:acme:error:malformed"})
			return
		}
		if w.eabKey != nil {
			var raw struct {
				EAB *struct{ Protected, Payload, Signature string } `json:"externalAccountBinding"`
			}
			json.Unmarshal(payload, &raw)
			ok := raw.EAB != nil
			if ok {
				mac := hmac.New(sha256.New, w.eabKey)
				mac.Write([]byte(raw.EAB.Protected + "." + raw.EAB.Payload))
				sig, _ := b64.DecodeString(raw.EAB.Signature)
				ph, _ := b64.DecodeString(raw.EAB.Protected)
				var eh map[string]any
				json.Unmarshal(ph, &eh)
				ok = hmac.Equal(sig, mac.Sum(nil)) && eh["kid"] == w.eabKID
			}
			if !ok {
				reply(401, map[string]string{"type": "urn:ietf:params:acme:error:externalAccountRequired"})
				return
			}
		}
		w.acct.thumb = thumbprint(jwk)
		rw.Header().Set("Location", base+"/acct/1")
		reply(201, map[string]any{"status": "valid"})
	case p == "/order":
		var req struct {
			Identifiers []struct{ Type, Value string }
		}
		json.Unmarshal(payload, &req)
		if len(req.Identifiers) != 1 || w.acct.thumb == "" {
			reply(400, map[string]string{"type": "urn:ietf:params:acme:error:rejectedIdentifier"})
			return
		}
		id := fmt.Sprint(len(w.orders) + 1)
		o := &fakeOrder{name: req.Identifiers[0].Value, token: "tok" + id, status: "pending", authz: "pending"}
		w.orders[id] = o
		rw.Header().Set("Location", base+"/order/"+id)
		reply(201, w.orderView(id))
	case strings.HasPrefix(p, "/order/"):
		id := strings.TrimPrefix(p, "/order/")
		rw.Header().Set("Location", base+p)
		reply(200, w.orderView(id))
	case strings.HasPrefix(p, "/authz/"):
		id := strings.TrimPrefix(p, "/authz/")
		o := w.orders[id]
		reply(200, map[string]any{"status": o.authz, "identifier": map[string]string{"type": "dns", "value": o.name},
			"challenges": []map[string]any{{"type": "dns-01", "url": base + "/chal/" + id, "token": o.token, "status": o.authz}}})
	case strings.HasPrefix(p, "/chal/"):
		id := strings.TrimPrefix(p, "/chal/")
		o := w.orders[id]
		h := sha256.Sum256([]byte(o.token + "." + w.acct.thumb))
		w.mu.Unlock()
		ok := w.validated(o.name, b64.EncodeToString(h[:]))
		w.mu.Lock()
		if ok {
			o.authz, o.status = "valid", "ready"
		} else {
			o.authz, o.status = "invalid", "invalid"
		}
		reply(200, map[string]any{"type": "dns-01", "url": base + p, "token": o.token, "status": o.authz})
	case strings.HasPrefix(p, "/finalize/"):
		id := strings.TrimPrefix(p, "/finalize/")
		o := w.orders[id]
		var req struct{ CSR string }
		json.Unmarshal(payload, &req)
		der, _ := b64.DecodeString(req.CSR)
		csr, err := x509.ParseCertificateRequest(der)
		if o.status != "ready" || err != nil || csr.CheckSignature() != nil || len(csr.DNSNames) != 1 || csr.DNSNames[0] != o.name {
			reply(403, map[string]string{"type": "urn:ietf:params:acme:error:badCSR"})
			return
		}
		o.cert = w.root.issue(w.t, csr.PublicKey, o.name, time.Now().Add(-time.Minute), time.Now().Add(90*24*time.Hour))
		if w.onFinalize != nil {
			w.onFinalize()
		}
		o.status = "valid"
		rw.Header().Set("Location", base+"/order/"+id)
		reply(200, w.orderView(id))
	case strings.HasPrefix(p, "/cert/"):
		o := w.orders[strings.TrimPrefix(p, "/cert/")]
		rw.Header().Set("content-type", "application/pem-certificate-chain")
		rw.Write(o.cert)
	default:
		reply(404, map[string]string{"type": "urn:ietf:params:acme:error:malformed"})
	}
}

func (w *namesWorld) orderView(id string) map[string]any {
	base := "https://" + caHost
	o := w.orders[id]
	v := map[string]any{"status": o.status, "identifiers": []map[string]string{{"type": "dns", "value": o.name}},
		"authorizations": []string{base + "/authz/" + id}, "finalize": base + "/finalize/" + id}
	if o.status == "valid" {
		v["certificate"] = base + "/cert/" + id
	}
	return v
}

// ---- the direct startup, on a fake chain quorum ----

type chainRows struct {
	mu     sync.Mutex
	row    string
	byHost map[string]string // one RPC's own answer (a liar, or one of an agreeing pair)
}

func (c *chainRows) set(row string) { c.mu.Lock(); c.row, c.byHost = row, nil; c.mu.Unlock() }
func (c *chainRows) answer(host, row string) {
	c.mu.Lock()
	if c.byHost == nil {
		c.byHost = map[string]string{}
	}
	c.byHost[host] = row
	c.mu.Unlock()
}

// zeroWords is the ledger's release(): runner (14), runnerOperator (15) and leaseUntil (16) zeroed together.
func zeroWords(t *testing.T, row string) string {
	b := []byte(row)
	for _, i := range []int{14, 15, 16} {
		at := 2 + (32+i*32)*2
		copy(b[at:at+64], strings.Repeat("0", 64))
	}
	return string(b)
}

func namesStartup(t *testing.T, names string) (*provisioned, *chainRows, map[string]string, [32]byte) {
	t.Helper()
	var v struct {
		ID, Ledger, Owner, Manifest, Row, Schema string
		Variants                                 map[string]string
	}
	b, err := os.ReadFile("../bootstrap/testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(b, &v)
	raw := v.Manifest[:len(v.Manifest)-1] + `,"names":` + names + `}`
	var id [32]byte
	ib, _ := hex.DecodeString(v.ID[2:])
	copy(id[:], ib)
	rows := &chainRows{row: directCustodyRow(t, v.Row, id, []byte(raw))}
	ownerChanged := directCustodyRow(t, v.Variants["owner"], id, []byte(raw))
	now := uint64(time.Now().Unix())
	client := &http.Client{Transport: bootstrapTransport(func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Hostname(), "enclave.host") {
			return nil, errors.New("Enclave refuses")
		}
		var msg struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		json.NewDecoder(req.Body).Decode(&msg)
		var result any
		switch msg.Method {
		case "eth_chainId":
			result = "0x2105"
		case "eth_blockNumber":
			result = "0x64"
		case "eth_getBlockByNumber":
			var n string
			json.Unmarshal(msg.Params[0], &n)
			result = map[string]string{"number": n, "hash": "0x" + strings.Repeat("ab", 32), "timestamp": fmt.Sprintf("0x%x", now)}
		case "eth_call":
			var call struct{ Data string }
			json.Unmarshal(msg.Params[0], &call)
			if call.Data == "0x5d1b72b6" {
				result = v.Schema
			} else {
				rows.mu.Lock()
				result = rows.row
				if r, ok := rows.byHost[req.URL.Hostname()]; ok {
					result = r
				}
				rows.mu.Unlock()
			}
		}
		out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(out)), Header: make(http.Header)}, nil
	})}
	reader, err := bootstrap.NewReader(bootstrap.Config{ChainID: 8453, Ledger: v.Ledger, RPCs: []string{"https://one.example", "https://two.example", "https://three.example"},
		Confirmations: 2, MaxAge: time.Minute, Client: client})
	if err != nil {
		t.Fatal(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	var tickets atomic.Int64
	p := &provisioner{appFromCode: true, etc: t.TempDir(), fwdPort: port, logf: t.Logf,
		ticket: func() (net.Conn, error) { tickets.Add(1); return nil, errors.New("Enclave refuses release") },
		egress: func() (net.Conn, error) { return nil, errors.New("no application egress during preparation") },
		audit:  func([]netip.AddrPort) error { return nil }}
	var v2 struct{ AppID, RuntimeID string }
	json.Unmarshal(b, &v2)
	app, _ := hex.DecodeString(v2.AppID)
	rid, _ := hex.DecodeString(v2.RuntimeID)
	rt := &runtimeState{}
	copy(rt.RID[:], rid)
	got, err := p.runDirect(context.Background(), reader, []byte(raw), id[:], nil, rt, app)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { got.fwd.Close() })
	if tickets.Load() != 0 || got.owner == nil {
		t.Fatal("direct startup used the release ticket or lost the owner authorization")
	}
	return got, rows, map[string]string{"owner": v.Owner, "ownerChanged": ownerChanged, "base": rows.row,
		"inactive": directCustodyRow(t, v.Variants["inactive"], id, []byte(raw)), "released": zeroWords(t, rows.row)}, id
}

func namesFront(t *testing.T, w *namesWorld) *front {
	c := newCertState(t, "11111111.app.enclave.host")
	w.spki = c.spki
	return &front{spki: c.spki, appSha: bytes.Repeat([]byte{0x44}, 32), certs: c}
}

// handshake connects to the front's certificate selection as a browser would, trusting only the test roots.
func handshake(t *testing.T, f *front, roots *x509.CertPool, name string) (*x509.Certificate, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0") // buffered, unlike net.Pipe: a refused handshake must not deadlock
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		srv, err := l.Accept()
		if err != nil {
			return
		}
		s := tls.Server(srv, &tls.Config{GetCertificate: f.certs.getCertificate, MinVersion: tls.VersionTLS13})
		s.SetDeadline(time.Now().Add(10 * time.Second))
		s.Handshake()
		s.Close()
	}()
	cli, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cli.SetDeadline(time.Now().Add(10 * time.Second))
	c := tls.Client(cli, &tls.Config{ServerName: name, RootCAs: roots, MinVersion: tls.VersionTLS13})
	defer c.Close()
	if err := c.Handshake(); err != nil {
		return nil, err
	}
	return c.ConnectionState().PeerCertificates[0], nil
}

func get(t *testing.T, h http.Handler, method, target string, body []byte) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, bytes.NewReader(body)))
	return rec
}

func TestDirectOwnerNamesIssueThroughOwnerSelectedResponderWithoutEnclave(t *testing.T) {
	w := newNamesWorld(t)
	prov, rows, info, id := namesStartup(t, `{"hosts":["shop.example.com","undelegated.example.net"],"acme":{"directory":"https://`+
		caHost+`/dir","challenge":"https://`+dnsBHost+`/","zone":"`+zoneB+`"}}`)
	f := namesFront(t, w)
	names, err := f.startOwnerNames(prov.owner, w.egress, w.pool)
	if err != nil || names == nil || names.issuer == nil {
		t.Fatalf("names %v issuer %v: %v", names, names != nil && names.issuer != nil, err)
	}
	f.names = names
	alias, _ := bootstrap.ChallengeAlias(id, info["owner"], zoneB)
	// the owner (who controls example.com's DNS) delegates shop's challenge to the alias; nobody delegates the other
	w.cname["_acme-challenge.shop.example.com"] = alias

	if n := names.issuer.pass(context.Background()); n != 1 {
		t.Fatalf("installed %d certificates, want exactly the delegated one; status %+v", n, names.status())
	}
	leaf, err := handshake(t, f, w.pool, "shop.example.com")
	if err != nil {
		t.Fatalf("a browser trusting the CA cannot reach shop.example.com: %v", err)
	}
	if got, _ := x509.MarshalPKIXPublicKey(leaf.PublicKey); !bytes.Equal(got, f.spki) {
		t.Fatal("the served certificate is not for the attested key")
	}
	if _, err := handshake(t, f, w.pool, "undelegated.example.net"); err == nil {
		t.Fatal("a committed but undelegated name became browser-trusted: a package claim proved ownership")
	}
	if v := names.issuer.view("undelegated.example.net"); v.LastError == "" || !strings.Contains(v.LastError, alias) || v.NextAttempt == "" {
		t.Fatalf("an undelegated name must fail at the CA, say which CNAME is missing and back off: %+v", v)
	}
	if names.issuer.pass(context.Background()) != 0 {
		t.Fatal("a fresh certificate was re-issued or a backed-off name was retried at once")
	}

	// nothing reached Enclave; only the owner's CA and responder were contacted; the TXT value was cleaned up
	w.mu.Lock()
	for _, o := range w.origins {
		if strings.Contains(o, "enclave.host") || o == dnsAHost {
			t.Fatalf("the guest contacted %s", o)
		}
	}
	if w.hits[dnsAHost] != 0 || w.hits[dnsBHost] == 0 || len(w.txt[zoneB]) != 0 || len(w.txt[zoneA]) != 0 {
		t.Fatalf("responder use: hits %v txt %v", w.hits, w.txt)
	}
	w.mu.Unlock()

	// the public status states committed vs certified, the alias, and the limits
	rec := get(t, f, "GET", namesPath, nil)
	var st struct {
		Authorized bool
		Owner      string
		ACME       struct{ ChallengeAlias string } `json:"acme"`
		Names      []nameStatus
		Limits     []string
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &st) != nil || !st.Authorized || st.ACME.ChallengeAlias != alias ||
		len(st.Names) != 2 || st.Names[0].Certificate == nil || st.Names[1].Certificate != nil || len(st.Limits) == 0 {
		t.Fatalf("status %s", rec.Body)
	}
	if strings.Contains(rec.Body.String(), "PRIVATE") || strings.Contains(rec.Body.String(), "eabKey") {
		t.Fatal("status leaks key material")
	}

	// a foreign name: no CSR, no install, whatever the chain says
	if rec := get(t, f, "GET", csrPath+"?name=bank.example.org", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("CSR for a foreign name: %d", rec.Code)
	}
	foreign := w.root.issue(t, mustPub(t, f.spki), "bank.example.org", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if rec := get(t, f, "POST", certPath+"?name=bank.example.org", foreign); rec.Code != http.StatusForbidden {
		t.Fatalf("install for a foreign name: %d", rec.Code)
	}

	// TLS-key mismatch: a trusted chain for a committed name but another key; and the right key under an untrusted root
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if rec := get(t, f, "POST", certPath+"?name=shop.example.com",
		w.root.issue(t, &other.PublicKey, "shop.example.com", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))); rec.Code != 422 ||
		!strings.Contains(rec.Body.String(), "not this domain's key") {
		t.Fatalf("a chain for another key: %d %s", rec.Code, rec.Body)
	}
	rogue := newTestCA(t)
	if rec := get(t, f, "POST", certPath+"?name=shop.example.com",
		rogue.issue(t, mustPub(t, f.spki), "shop.example.com", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))); rec.Code != 422 ||
		!strings.Contains(rec.Body.String(), "measured WebPKI roots") {
		t.Fatalf("a chain from an unmeasured root: %d %s", rec.Code, rec.Body)
	}
	if leaf2, err := handshake(t, f, w.pool, "shop.example.com"); err != nil || !leaf2.Equal(leaf) {
		t.Fatal("a refused install replaced the served certificate")
	}

	// an external (operator-selected) issuer may still install a trusted certificate for the guest's own key
	ext := w.root.issue(t, mustPub(t, f.spki), "undelegated.example.net", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if rec := get(t, f, "POST", certPath+"?name=undelegated.example.net", ext); rec.Code != 200 {
		t.Fatalf("external issuance for a committed name: %d %s", rec.Code, rec.Body)
	}

	// the owner changes on chain: names are revoked for good, the CA certificates are no longer served, and the
	// guest asks for nothing more
	rows.set(info["ownerChanged"])
	if names.refresh(context.Background()) {
		t.Fatal("an owner change did not revoke")
	}
	if _, err := handshake(t, f, w.pool, "shop.example.com"); err == nil {
		t.Fatal("a revoked name is still served with its CA certificate")
	}
	if rec := get(t, f, "GET", csrPath+"?name=shop.example.com", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("CSR after revocation: %d", rec.Code)
	}
	rows.set(info["base"])
	if names.refresh(context.Background()) || len(names.authorized()) != 0 {
		t.Fatal("revocation was undone by a later read")
	}
	if names.issuer.pass(context.Background()) != 0 {
		t.Fatal("a revoked guest issued")
	}
	if rec := get(t, f, "GET", namesPath, nil); !strings.Contains(rec.Body.String(), `"revoked"`) {
		t.Fatalf("status does not state the revocation: %s", rec.Body)
	}
}

func mustPub(t *testing.T, spki []byte) crypto.PublicKey {
	p, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeAuthority drives ownerNames without a chain, for the cases the direct path above does not reach.
type fakeAuthority struct {
	mu    sync.Mutex
	grant bootstrap.NameGrant
	err   error
}

func (a *fakeAuthority) Refresh(context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}
func (a *fakeAuthority) NameGrant() (bootstrap.NameGrant, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if errors.Is(a.err, bootstrap.ErrRevoked) {
		return bootstrap.NameGrant{}, a.err
	}
	return a.grant, nil
}

func grantFor(owner string, acme *bootstrap.NameACME, hosts ...string) bootstrap.NameGrant {
	var id [32]byte
	for i := range id {
		id[i] = 0x11
	}
	return bootstrap.NameGrant{Deployment: id, Owner: owner, Hosts: hosts, ACME: acme, Until: time.Now().Add(time.Hour)}
}

// A changed owner moves the alias: the delegation the previous owner published no longer validates for a guest
// running under the new owner, even for the same deployment and the same responder.
func TestChangedOwnerCannotUseThePreviousOwnersDelegation(t *testing.T) {
	w := newNamesWorld(t)
	sel := &bootstrap.NameACME{Directory: "https://" + caHost + "/dir", Challenge: "https://" + dnsBHost, Zone: zoneB}
	oldOwner, newOwner := "0x"+strings.Repeat("33", 20), "0x"+strings.Repeat("aa", 20)
	oldGrant := grantFor(oldOwner, sel, "shop.example.com")
	oldAlias, _ := bootstrap.ChallengeAlias(oldGrant.Deployment, oldOwner, zoneB)
	w.cname["_acme-challenge.shop.example.com"] = oldAlias

	f := namesFront(t, w)
	names, err := newOwnerNames(&fakeAuthority{grant: grantFor(newOwner, sel, "shop.example.com")}, f.certs, w.pool)
	if err != nil {
		t.Fatal(err)
	}
	names.issuer, err = newACMEIssuer(names, f.certs, "", nil, ownerHTTP(w.egress, w.pool), f.attestDocJSON, f.certs.key, f.spki)
	if err != nil {
		t.Fatal(err)
	}
	if names.issuer.alias == oldAlias {
		t.Fatal("the alias does not commit to the owner")
	}
	if names.issuer.pass(context.Background()) != 0 {
		t.Fatal("the new owner's guest validated through the previous owner's delegation")
	}
	if _, err := handshake(t, f, w.pool, "shop.example.com"); err == nil {
		t.Fatal("served a trusted certificate under a stale delegation")
	}
}

// An outage lets names lapse at the grant's end, not before; a CA that requires EAB gets the binding resolved from
// the owner's custody secrets, never from the package.
func TestOwnerNamesLapseOnOutageAndUseCustodyEAB(t *testing.T) {
	w := newNamesWorld(t)
	w.eabKID, w.eabKey = "kid-1", bytes.Repeat([]byte{0x5a}, 32)
	sel := &bootstrap.NameACME{Directory: "https://" + caHost + "/dir", Challenge: "https://" + dnsBHost, Zone: zoneB,
		EAB: &bootstrap.NameEAB{KID: "ACME_EAB_KID", HMAC: "ACME_EAB_HMAC"}}
	auth := &fakeAuthority{grant: grantFor("0x"+strings.Repeat("33", 20), sel, "shop.example.com")}
	f := namesFront(t, w)
	names, err := newOwnerNames(auth, f.certs, w.pool)
	if err != nil {
		t.Fatal(err)
	}
	alias, _ := bootstrap.ChallengeAlias(auth.grant.Deployment, auth.grant.Owner, zoneB)
	w.cname["_acme-challenge.shop.example.com"] = alias

	if _, _, why := eabFrom(map[string]string{"ACME_EAB_KID": "kid-1"}, sel.EAB); why == "" {
		t.Fatal("a missing EAB secret was not reported")
	}
	if _, _, why := eabFrom(map[string]string{"ACME_EAB_KID": "kid-1", "ACME_EAB_HMAC": "not base64!"}, sel.EAB); why == "" {
		t.Fatal("an undecodable EAB key was accepted")
	}
	kid, key, why := eabFrom(map[string]string{"ACME_EAB_KID": "kid-1", "ACME_EAB_HMAC": b64.EncodeToString(w.eabKey)}, sel.EAB)
	if why != "" {
		t.Fatal(why)
	}
	if _, err := newACMEIssuer(names, f.certs, "", nil, ownerHTTP(w.egress, w.pool), f.attestDocJSON, f.certs.key, f.spki); err == nil {
		t.Fatal("an EAB-bound CA was used without its binding")
	}
	names.issuer, err = newACMEIssuer(names, f.certs, kid, key, ownerHTTP(w.egress, w.pool), f.attestDocJSON, f.certs.key, f.spki)
	if err != nil {
		t.Fatal(err)
	}
	if names.issuer.pass(context.Background()) != 1 {
		t.Fatalf("EAB issuance failed: %+v", names.issuer.view("shop.example.com"))
	}

	auth.mu.Lock()
	auth.err = errors.New("bootstrap chain quorum unavailable")
	auth.mu.Unlock()
	if !names.refresh(context.Background()) || len(names.authorized()) != 1 {
		t.Fatal("an outage revoked names before the grant ended")
	}
	names.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if len(names.authorized()) != 0 {
		t.Fatal("names outlived their grant")
	}
	f.certs.mu.Lock()
	f.certs.aliasesUntil = time.Now().Add(-time.Second) // what the clock does to the alias set at the same moment
	f.certs.mu.Unlock()
	if _, err := handshake(t, f, w.pool, "shop.example.com"); err == nil {
		t.Fatal("a lapsed name is still served with its CA certificate")
	}
}

// The legacy path is unchanged: a relay-mapped alias has no root requirement and the platform label keeps its own.
func TestLegacyAliasesKeepTheirInstallRule(t *testing.T) {
	c := newCertState(t, "4e62e60d.app.enclave.host")
	c.setDomains(map[string]string{"shop.example.com": "0xid"}, "0xid", time.Now().Add(time.Minute))
	alias := c.forName("shop.example.com")
	if alias == nil || alias.roots != nil {
		t.Fatal("a relay-mapped alias changed shape")
	}
	ca := newTestCA(t)
	if _, err := alias.install(ca.issue(t, mustPub(t, c.spki), "shop.example.com", time.Now().Add(-time.Minute), time.Now().Add(time.Hour)), time.Now()); err != nil {
		t.Fatalf("legacy install rule changed: %v", err)
	}
	c.setOwnerNames([]string{"shop.example.com", "x.app.enclave.host", "4e62e60d.app.enclave.host"}, time.Now().Add(time.Minute), x509.NewCertPool())
	if c.forName("x.app.enclave.host") != nil || len(c.aliases) != 1 || c.forName("shop.example.com").roots == nil {
		t.Fatal("owner names accepted a platform name or kept the relay alias")
	}
}

// staleAuthority's first grant is no longer fresh (startup preparation outlasted the snapshot); a refresh renews it.
type staleAuthority struct {
	fakeAuthority
	refreshed, refuse bool
}

func (a *staleAuthority) Refresh(ctx context.Context) error {
	a.refreshed = true
	return a.fakeAuthority.Refresh(ctx)
}
func (a *staleAuthority) NameGrant() (bootstrap.NameGrant, error) {
	if !a.refreshed || a.refuse {
		return bootstrap.NameGrant{}, errors.New("startup authorization expired or unverified")
	}
	return a.fakeAuthority.NameGrant()
}

// Names never stop the app: a stale grant at startup is refreshed once, and a grant that still cannot be had (or a
// revocation) leaves the guest serving without owner names instead of dying.
func TestOwnerNamesNeverBlockStartup(t *testing.T) {
	w := newNamesWorld(t)
	f := namesFront(t, w)
	stale := &staleAuthority{fakeAuthority: fakeAuthority{grant: grantFor("0x"+strings.Repeat("33", 20), nil, "shop.example.com")}}
	names, err := f.startOwnerNames(&ownerStartup{auth: stale}, w.egress, w.pool)
	if err != nil || names == nil || !stale.refreshed || len(names.authorized()) != 1 || names.issuer != nil {
		t.Fatalf("a stale startup grant was not refreshed: %v %v", names, err)
	}
	for _, a := range []*staleAuthority{{refuse: true}, {fakeAuthority: fakeAuthority{err: bootstrap.ErrRevoked}}} {
		names, err := f.startOwnerNames(&ownerStartup{auth: a}, w.egress, w.pool)
		if err != nil || names != nil {
			t.Fatalf("names blocked or survived startup: %v %v", names, err)
		}
	}
}
