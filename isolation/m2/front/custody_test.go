package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"enclave.host/isolation/contract"
	"enclave.host/isolation/m2/custody"
	"enclave.host/isolation/m2/custody/seats"
	"enclave.host/isolation/m2/custody/v2member"
	"enclave.host/isolation/m2/release"
)

// ---- loadedAppID: the AppID comes from the bytes init runs ----

func TestLoadedAppIDIsTakenFromTheLoadedCode(t *testing.T) {
	dir := t.TempDir()
	wasm := []byte("\x00asm\x01\x00\x00\x00 the component")
	b, err := contract.Build(contract.Manifest{Policy: contract.Policy{CPUPercent: 100, MemMiB: 256, Vcpus: 1}}, wasm)
	if err != nil {
		t.Fatal(err)
	}
	want := contract.AppID(b)
	put := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, data, 0o644)
		return p
	}
	bundle, wasmP := put("app.bundle", b), put("app.wasm", wasm)
	stated := put("app.sha256", []byte(hex.EncodeToString(want[:])+"\n"))
	id, how, err := loadedAppID(bundle, wasmP, stated)
	if err != nil || !bytes.Equal(id, want[:]) || !strings.Contains(how, "bundle") {
		t.Fatalf("bundle path: %x %q %v", id, how, err)
	}
	// /app.wasm differs from the bundle's artifact: the identity would not cover what runs
	other := put("other.wasm", []byte("\x00asm\x01\x00\x00\x00 another component"))
	if _, _, err := loadedAppID(bundle, other, stated); err == nil || !strings.Contains(err.Error(), "not the artifact") {
		t.Fatalf("a mismatched component was accepted: %v", err)
	}
	// the build's statement disagrees with the loaded code
	lie := put("lie.sha256", []byte(strings.Repeat("ab", 32)))
	if _, _, err := loadedAppID(bundle, wasmP, lie); err == nil || !strings.Contains(err.Error(), "broken image") {
		t.Fatalf("a lying app.sha256 was accepted: %v", err)
	}
	// a tampered bundle (artifact hash no longer matches) is refused by contract.Parse
	bad := append([]byte(nil), b...)
	bad[len(bad)-1] ^= 1
	if _, _, err := loadedAppID(put("bad.bundle", bad), wasmP, filepath.Join(dir, "none")); err == nil {
		t.Fatal("a tampered bundle was accepted")
	}
	// no bundle: the bare-artifact identity, from the same bytes
	id, _, err = loadedAppID(filepath.Join(dir, "absent.bundle"), wasmP, filepath.Join(dir, "none"))
	if sum := sha256.Sum256(wasm); err != nil || !bytes.Equal(id, sum[:]) {
		t.Fatalf("bare path: %v", err)
	}
}

// ---- the custody step in provisioning ----

type custodyWorld struct {
	*provWorld
	members []*ecdh.PrivateKey
	ys      []*big.Int
	down    map[int]bool
	seen    atomic.Int32 // custodian release requests whose evidence matched what a custodian checks
	authN   atomic.Int32
	st      custody.State
}

var secpOrder, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

func newCustodyWorld(t *testing.T, env map[string]string) *custodyWorld {
	w := &custodyWorld{provWorld: newProvWorld(t), down: map[int]bool{}}
	w.secrets = map[string]string{} // a custody deployment's relay release carries no values
	w.p.appFromCode = true
	// the owner's bundle: s split 3-of-5 over the secp256k1 order, the env sealed under the data key
	rnd := func() *big.Int {
		b := make([]byte, 32)
		rand.Read(b)
		return new(big.Int).Mod(new(big.Int).SetBytes(b), secpOrder)
	}
	s, a1, a2 := rnd(), rnd(), rnd()
	ctx := custody.Context{ChainID: 8453}
	copy(ctx.Vault[:], bytes.Repeat([]byte{0x5e}, 20))
	c0 := append([]byte{0x02}, bytes.Repeat([]byte{0xc0}, 32)...) // opaque here: only the AAD uses it
	dek, _ := custody.DeriveDEK(s, ctx, w.id, 4)
	aad, _ := custody.BundleAAD(ctx, w.id, 4, c0)
	blk, _ := aes.NewCipher(dek)
	g, _ := cipher.NewGCM(blk)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	// the owner commits the config its values may go into: exactly the text the relay delivers (its JSON value)
	cfgText, _ := json.Marshal(w.config)
	cfgSum := sha256.Sum256(cfgText)
	pt, _ := json.Marshal(map[string]any{"v": 1, "env": env, "configSha256": hex.EncodeToString(cfgSum[:])})
	ct := append(nonce, g.Seal(nil, nonce, pt, aad)...)
	w.st = custody.State{Ctx: ctx, ID: w.id, PolicyRev: 9, SecretRev: 4, Epoch: 1, Threshold: 3, C0: c0, Ciphertext: ct}
	var members []release.CustodyMember
	for i := 0; i < 5; i++ {
		k, _ := custody.NewRecipientKey()
		w.members = append(w.members, k)
		x := big.NewInt(int64(i + 1))
		y := new(big.Int).Add(s, new(big.Int).Mul(a1, x))
		y.Add(y, new(big.Int).Mul(a2, new(big.Int).Mul(x, x)))
		w.ys = append(w.ys, y.Mod(y, secpOrder))
		name := fmt.Sprintf("custodian-%d.example", i)
		l := w.ca.tlsListener(t, name)
		srv := &http.Server{Handler: w.custodian(i)}
		go srv.Serve(l)
		t.Cleanup(func() { srv.Close() })
		w.routes[name] = l.Addr().String()
		members = append(members, release.CustodyMember{EncKey: hex.EncodeToString(k.PublicKey().Bytes()), Endpoint: "https://" + name})
	}
	w.custody = release.Custody{ChainID: 8453, Vault: "0x" + strings.Repeat("5e", 20), PolicyRev: "9", SecretRev: "4", Epoch: 1, Threshold: 3,
		Members: members, C0: hex.EncodeToString(c0), Ciphertext: base64.StdEncoding.EncodeToString(ct)}
	// guestd's custody-auth service (TCP stands in for vsock): the lease holder's operator signs
	al, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { al.Close() })
	go func() {
		for {
			c, err := al.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				id, _, err := release.ReadAuthRequest(c)
				if err != nil || id != w.id {
					return
				}
				w.authN.Add(1)
				release.WriteAuth(c, release.CustodyAuth{Endpoint: "https://api.enclave.host/t/host-a", Sig: "0x" + strings.Repeat("5a", 65), Expiry: 1800000000})
			}()
		}
	}()
	w.p.custodyAuth = func() (net.Conn, error) { return net.Dial("tcp", al.Addr().String()) }
	return w
}

// a custodian that checks what custody/custodian.mjs checks about the guest's composition: the binding over the request's
// own fields, report_data = binding ‖ the loaded code's AppID, HOST_DATA = the deployment, the operator's authorization
func (w *custodyWorld) custodian(i int) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if w.down[i] {
			rw.WriteHeader(503)
			return
		}
		enc := hex.EncodeToString(w.members[i].PublicKey().Bytes())
		if r.URL.Path == "/v1/custody/challenge" {
			n := sha256.Sum256([]byte(fmt.Sprint("nonce-", i)))
			json.NewEncoder(rw).Encode(map[string]string{"encKey": enc, "nonce": hex.EncodeToString(n[:])})
			return
		}
		var req struct {
			ID, Endpoint, PolicyRev, SecretRev, RecipientKey string
			Epoch                                            uint32
			Challenges                                       []struct{ EncKey, Nonce string }
			Evidence                                         struct {
				Format, Abi, TransportKey, Report string
				Runtime                           json.RawMessage
			}
			Operator struct {
				Sig    string
				Expiry int64
			}
		}
		b, _ := io.ReadAll(r.Body)
		if json.Unmarshal(b, &req) != nil {
			rw.WriteHeader(422)
			return
		}
		var chs []custody.Challenge
		for _, c := range req.Challenges {
			var ch custody.Challenge
			k, _ := hex.DecodeString(c.EncKey)
			n, _ := hex.DecodeString(c.Nonce)
			copy(ch.EncKey[:], k)
			copy(ch.Nonce[:], n)
			chs = append(chs, ch)
		}
		var rid contract.RuntimeIdentity
		json.Unmarshal(req.Evidence.Runtime, &rid)
		runtimeID, _ := contract.RuntimeID(rid)
		spki, _ := base64.StdEncoding.DecodeString(req.Evidence.TransportKey)
		rk, _ := hex.DecodeString(req.RecipientKey)
		var rk32 [32]byte
		copy(rk32[:], rk)
		bind, err := custody.Binding(custody.BindingInput{Ctx: w.st.Ctx, ID: w.id, PolicyRev: 9, SecretRev: 4, Epoch: 1, Challenges: chs,
			RuntimeID: runtimeID, TransportSPKI: spki, RecipientKey: rk32})
		rep, _ := base64.StdEncoding.DecodeString(req.Evidence.Report)
		if err != nil || len(rep) < 0xe0 || !bytes.Equal(rep[0x50:0x70], bind[:]) || !bytes.Equal(rep[0x70:0x90], w.appSha) ||
			!bytes.Equal(rep[0xc0:0xe0], w.id[:]) || req.Evidence.Format != contract.FormatSNP || req.Evidence.Abi != contract.ABI2 ||
			req.Endpoint != "https://api.enclave.host/t/host-a" || req.Operator.Sig != "0x"+strings.Repeat("5a", 65) {
			rw.WriteHeader(403)
			io.WriteString(rw, `{"error":"evidence_refused","message":"composition"}`)
			return
		}
		w.seen.Add(1)
		pk, _ := ecdh.X25519().NewPublicKey(rk)
		var ek [32]byte
		copy(ek[:], w.members[i].PublicKey().Bytes())
		aad := sha256.Sum256(append(append(append([]byte("enclave-custody-v1 response\n"), bind[:]...), ek[:]...), byte(i)))
		yb := make([]byte, 32)
		w.ys[i].FillBytes(yb)
		sealed, err := custody.Seal(pk, []byte("enclave-custody-v1 share-release"), aad[:], yb, nil)
		if err != nil {
			rw.WriteHeader(500)
			return
		}
		json.NewEncoder(rw).Encode(map[string]any{"v": 1, "encKey": enc, "index": i, "sealed": base64.StdEncoding.EncodeToString(sealed)})
	})
}

func TestProvisionTakesCustodySecretsFromAThresholdOfCustodians(t *testing.T) {
	w := newCustodyWorld(t, map[string]string{"MCP_ADAPTER_API_KEY": "custody-k", "IMAGE_ENDPOINT": "https://images.example"})
	w.down[1], w.down[3] = true, true // two of five down: three suffice
	p, err := w.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"api_key":"custody-k","http":[{"url":"https://images.example/v1/images"}]}`; p.config != want {
		t.Fatalf("config %q, want %q", p.config, want)
	}
	if w.seen.Load() != 3 || w.authN.Load() != 1 {
		t.Fatalf("custodians judged %d requests, the host authorized %d", w.seen.Load(), w.authN.Load())
	}
	// the allowlist is derived from the config resolved WITH the custody values: images.example, named only through
	// ${IMAGE_ENDPOINT}, is allowed
	if _, ok := p.fwd.Addr("images.example"); !ok {
		t.Fatalf("the origin named through a custody placeholder is not allowed: %+v", p.fwd.Policy.Origins)
	}
}

// review H2: the relay delivers a config other than the one the owner committed (sending the key to its own URL): the
// values are refused, never substituted
func TestProvisionCustodyRefusesAConfigTheOwnerDidNotCommit(t *testing.T) {
	w := newCustodyWorld(t, map[string]string{"MCP_ADAPTER_API_KEY": "custody-k", "IMAGE_ENDPOINT": "https://images.example"})
	w.config = map[string]any{"api_key": "$MCP_ADAPTER_API_KEY", "http": []any{map[string]any{"url": "https://evil.example/collect"}}}
	if _, err := w.run(t); err == nil || !strings.Contains(err.Error(), "not the one the owner committed") {
		t.Fatalf("a relay-chosen config was accepted: %v", err)
	}
}

func TestProvisionCustodyFailsClosed(t *testing.T) {
	env := map[string]string{"MCP_ADAPTER_API_KEY": "custody-k", "IMAGE_ENDPOINT": "https://images.example"}
	// three of five down: no quorum, no app
	w := newCustodyWorld(t, env)
	w.down[0], w.down[2], w.down[4] = true, true, true
	if _, err := w.run(t); err == nil || !strings.Contains(err.Error(), "quorum") {
		t.Fatalf("no quorum: %v", err)
	}
	// a release that names custody AND carries relay-held values is refused before any custodian is asked
	w = newCustodyWorld(t, env)
	w.secrets = map[string]string{"MCP_ADAPTER_API_KEY": "relay-held"}
	if _, err := w.run(t); err == nil || !strings.Contains(err.Error(), "relay-held secrets") || w.seen.Load() != 0 {
		t.Fatalf("custody + relay values: %v", err)
	}
	// an image whose AppID was not derived from its loaded code
	w = newCustodyWorld(t, env)
	w.p.appFromCode = false
	if _, err := w.run(t); err == nil || !strings.Contains(err.Error(), "loaded code") {
		t.Fatalf("stated AppID: %v", err)
	}
	// a custodian endpoint that is not an https origin on 443 never parses
	w = newCustodyWorld(t, env)
	c := w.custody.(release.Custody)
	c.Members[0].Endpoint = "http://custodian-0.example:8080"
	w.custody = c
	if _, err := w.run(t); err == nil || !strings.Contains(err.Error(), "endpoint") {
		t.Fatalf("bad endpoint: %v", err)
	}
	// the host's authorization service is gone
	w = newCustodyWorld(t, env)
	w.p.custodyAuth = func() (net.Conn, error) { return nil, io.ErrClosedPipe }
	if _, err := w.run(t); err == nil || !strings.Contains(err.Error(), "authorization") {
		t.Fatalf("no authorization: %v", err)
	}
}

// ---- custody v2: a committee of custodian machines, the Enclave seat, verified partials ----

type v2Behaviour int

const (
	v2OK         v2Behaviour = iota
	v2Down                   // no challenge (and nothing else)
	v2Refuse                 // a challenge, then refuses the release
	v2Lie                    // releases a partial whose proof does not verify
	v2WrongIndex             // releases a VALID partial for an index it does not hold
)

type custodyWorldV2 struct {
	shieldOwner string // optional Shield evidence fixture; report bytes stand in for a monitor, never hardware proof
	*provWorld
	flags    []bool
	keys     []*ecdh.PrivateKey
	com      *v2member.Committee
	lay      *seats.Layout
	ctx      custody.Context
	cid      [32]byte
	behave   map[int]v2Behaviour
	released []atomic.Int32 // release requests each machine judged valid
	authN    atomic.Int32
	logMu    sync.Mutex
	logs     []string
}

func newCustodyWorldV2(t *testing.T, flags []bool, env map[string]string) *custodyWorldV2 {
	w := &custodyWorldV2{provWorld: newProvWorld(t), flags: flags, behave: map[int]v2Behaviour{}, released: make([]atomic.Int32, len(flags))}
	w.secrets = map[string]string{}
	w.p.appFromCode = true
	inner := w.p.logf
	w.p.logf = func(f string, a ...any) {
		w.logMu.Lock()
		w.logs = append(w.logs, fmt.Sprintf(f, a...))
		w.logMu.Unlock()
		inner(f, a...)
	}
	var err error
	if w.lay, err = seats.Of(flags); err != nil {
		t.Fatal(err)
	}
	w.com = v2member.NewCommittee(w.lay.T)
	w.ctx = custody.Context{ChainID: 8453}
	copy(w.ctx.Vault[:], bytes.Repeat([]byte{0x7a}, 20))
	w.cid = [32]byte{0xc0, 0x11}
	label := custody.LabelOf(custody.LabelInput{Ctx: w.ctx, ID: w.id, SecretRev: 6, CommitteeID: w.cid})
	cfgText, _ := json.Marshal(w.config)
	cfgSum := sha256.Sum256(cfgText)
	bundle, err := v2member.EncryptBundle(w.com.Y(), label, env, hex.EncodeToString(cfgSum[:]), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var machines []any
	for i := range flags {
		k, _ := custody.NewRecipientKey()
		w.keys = append(w.keys, k)
		name := fmt.Sprintf("cm-%d.example", i)
		prefix := ""
		if i == 0 {
			prefix = "/t/custody-m0" // reached through a path prefix, as behind the relay's fleet tunnel
		}
		l := w.ca.tlsListener(t, name)
		srv := &http.Server{Handler: w.custodianV2(i, prefix, bundle[:33])}
		go srv.Serve(l)
		t.Cleanup(func() { srv.Close() })
		w.routes[name] = l.Addr().String()
		machines = append(machines, map[string]any{"encKey": hex.EncodeToString(k.PublicKey().Bytes()), "endpoint": "https://" + name + prefix,
			"enclave": flags[i], "indices": w.lay.Indices[i]})
	}
	w.custody = map[string]any{"v": 2, "chainId": 8453, "vault": "0x" + strings.Repeat("7a", 20), "committeeId": "0x" + hex.EncodeToString(w.cid[:]),
		"epoch": 7, "t": w.lay.T, "policyRev": "11", "secretRev": "6", "bundle": hex.EncodeToString(bundle),
		"commitments": hex.EncodeToString(w.com.CommitmentBytes()), "machines": machines}
	// guestd's custody-auth service: a v2 line naming this vault and this deployment
	al, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { al.Close() })
	go func() {
		for {
			c, err := al.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				a, err := release.ReadAnyAuthRequest(c)
				if err != nil || a.V != 2 || a.Vault != "0x"+strings.Repeat("7a", 20) || a.ID != w.id {
					return
				}
				w.authN.Add(1)
				release.WriteAuth(c, release.CustodyAuth{Endpoint: "https://api.enclave.host/t/host-a", Sig: "0x" + strings.Repeat("5a", 65), Expiry: 1800000000})
			}()
		}
	}()
	w.p.custodyAuth = func() (net.Conn, error) { return net.Dial("tcp", al.Addr().String()) }
	return w
}

func (w *custodyWorldV2) pointer() map[string]any { return w.custody.(map[string]any) }

// a v2 custodian doing what custody/custodian.mjs checks about the guest's composition, then answering one partial per
// index it holds (or misbehaving as told)
func (w *custodyWorldV2) custodianV2(i int, prefix string, R []byte) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		b := w.behave[i]
		if b == v2Down {
			rw.WriteHeader(503)
			return
		}
		enc := hex.EncodeToString(w.keys[i].PublicKey().Bytes())
		nonce := sha256.Sum256([]byte(fmt.Sprint("v2-nonce-", i)))
		switch r.URL.Path {
		case prefix + "/v2/custody/challenge":
			json.NewEncoder(rw).Encode(map[string]any{"encKey": enc, "nonce": hex.EncodeToString(nonce[:]), "expiresAt": 1800000000})
			return
		case prefix + "/v2/custody/release":
		default:
			rw.WriteHeader(404)
			return
		}
		var req struct {
			V                                                             int
			ID, Endpoint, CommitteeID, PolicyRev, SecretRev, RecipientKey string
			Epoch                                                         uint32
			Challenges                                                    []struct{ EncKey, Nonce string }
			Evidence                                                      struct {
				Format, Abi, TransportKey, Report, Tier, AppSha256 string
				Nonce                                              *string
				Runtime                                            json.RawMessage
			}
			Operator struct {
				Sig    string
				Expiry int64
			}
		}
		body, _ := io.ReadAll(r.Body)
		if json.Unmarshal(body, &req) != nil {
			rw.WriteHeader(422)
			return
		}
		var chs []custody.Challenge
		mine := false
		for _, c := range req.Challenges {
			var ch custody.Challenge
			k, _ := hex.DecodeString(c.EncKey)
			n, _ := hex.DecodeString(c.Nonce)
			copy(ch.EncKey[:], k)
			copy(ch.Nonce[:], n)
			chs = append(chs, ch)
			mine = mine || (c.EncKey == enc && c.Nonce == hex.EncodeToString(nonce[:]))
		}
		var rid contract.RuntimeIdentity
		json.Unmarshal(req.Evidence.Runtime, &rid)
		runtimeID, _ := contract.RuntimeID(rid)
		spki, _ := base64.StdEncoding.DecodeString(req.Evidence.TransportKey)
		rk, _ := hex.DecodeString(req.RecipientKey)
		var rk32 [32]byte
		copy(rk32[:], rk)
		bind, err := custody.BindingV2(custody.BindingInputV2{Ctx: w.ctx, ID: w.id, PolicyRev: 11, SecretRev: 6, CommitteeID: w.cid, Epoch: 7,
			Challenges: chs, RuntimeID: runtimeID, TransportSPKI: spki, RecipientKey: rk32})
		rep, _ := base64.StdEncoding.DecodeString(req.Evidence.Report)
		evidenceOK := len(rep) >= 0xe0 && bytes.Equal(rep[0x50:0x70], bind[:]) && bytes.Equal(rep[0x70:0x90], w.appSha) && bytes.Equal(rep[0xc0:0xe0], w.id[:]) && req.Evidence.Format == contract.FormatSNP
		if w.shieldOwner != "" {
			input, e := custody.ShieldReleaseInput(bind, w.shieldOwner)
			evidenceOK = e == nil && len(rep) == 64 && bytes.Equal(rep[:32], input[:]) && bytes.Equal(rep[32:], w.appSha) && req.Evidence.Format == contract.FormatHyperV && req.Evidence.Tier == contract.TierHyperV && req.Evidence.AppSha256 == hex.EncodeToString(w.appSha) && req.Evidence.Nonce == nil
		}
		if err != nil || !mine || req.V != 2 || req.ID != "0x"+hex.EncodeToString(w.id[:]) || req.CommitteeID != "0x"+hex.EncodeToString(w.cid[:]) ||
			req.Epoch != 7 || req.PolicyRev != "11" || req.SecretRev != "6" ||
			!evidenceOK || req.Evidence.Abi != contract.ABI2 ||
			req.Endpoint != "https://api.enclave.host/t/host-a" || req.Operator.Sig != "0x"+strings.Repeat("5a", 65) {
			rw.WriteHeader(403)
			io.WriteString(rw, `{"error":"evidence_refused","message":"composition"}`)
			return
		}
		w.released[i].Add(1)
		if b == v2Refuse {
			rw.WriteHeader(403)
			io.WriteString(rw, `{"error":"refused","message":"this custodian says no"}`)
			return
		}
		var records [][]byte
		for _, k := range w.lay.Indices[i] {
			if b == v2WrongIndex {
				k = uint32(w.lay.W) // a real share of ANOTHER seat (the last index), validly proven
				if w.lay.Indices[i][0] == k {
					k = 1
				}
			}
			rec, err := v2member.Partial(k, w.com.Share(k), R, bind, w.com.Commitments, nil)
			if err != nil {
				rw.WriteHeader(500)
				return
			}
			if b == v2Lie {
				rec[100] ^= 1
			}
			records = append(records, rec)
		}
		pk, _ := ecdh.X25519().NewPublicKey(rk)
		var ek [32]byte
		copy(ek[:], w.keys[i].PublicKey().Bytes())
		sealed, err := v2member.Seal(pk, bind, ek, records, nil)
		if err != nil {
			rw.WriteHeader(500)
			return
		}
		json.NewEncoder(rw).Encode(map[string]any{"v": 2, "encKey": enc, "count": len(records), "sealed": base64.StdEncoding.EncodeToString(sealed)})
	})
}

// combined reports the machines the guest combined from (its log line), or nil
func (w *custodyWorldV2) combined(t *testing.T) []int {
	t.Helper()
	w.logMu.Lock()
	defer w.logMu.Unlock()
	for _, l := range w.logs {
		if i := strings.Index(l, "from machines ["); i >= 0 {
			var out []int
			for _, f := range strings.Fields(strings.TrimSuffix(l[i+len("from machines ["):], "]")) {
				var n int
				fmt.Sscan(f, &n)
				out = append(out, n)
			}
			return out
		}
	}
	return nil
}

var v2Env = map[string]string{"MCP_ADAPTER_API_KEY": "custody-v2-k", "IMAGE_ENDPOINT": "https://images.example"}

const v2Config = `{"api_key":"custody-v2-k","http":[{"url":"https://images.example/v1/images"}]}`

func TestProvisionCustodyV2IndependentQuorum(t *testing.T) {
	// two Enclave replicas (one seat, index 1) + three other hosts (2, 3, 4): n = 4, t = 3
	flags := []bool{true, true, false, false, false}
	enclaveUsed := func(t *testing.T, w *custodyWorldV2) int {
		n := 0
		for _, m := range w.combined(t) {
			if flags[m] {
				n++
			}
		}
		return n
	}
	ok := func(t *testing.T, w *custodyWorldV2) {
		t.Helper()
		p, err := w.run(t)
		if err != nil {
			t.Fatal(err)
		}
		if p.config != v2Config {
			t.Fatalf("config %q", p.config)
		}
		if w.authN.Load() != 1 {
			t.Fatalf("the host authorized %d releases", w.authN.Load())
		}
	}

	t.Run("all online: exactly one Enclave machine is combined", func(t *testing.T) {
		w := newCustodyWorldV2(t, flags, v2Env)
		ok(t, w)
		if got := w.combined(t); len(got) != 3 || enclaveUsed(t, w) != 1 {
			t.Fatalf("combined from machines %v", got)
		}
		if w.released[0].Load() != 1 || w.released[1].Load() != 1 {
			t.Fatal("both Enclave machines should have been asked (both issued a challenge)")
		}
	})
	t.Run("one Enclave machine refuses: the other Enclave machine is used", func(t *testing.T) {
		w := newCustodyWorldV2(t, flags, v2Env)
		w.behave[0] = v2Refuse
		ok(t, w)
		if got := w.combined(t); len(got) != 3 || got[0] != 1 {
			t.Fatalf("combined from machines %v", got)
		}
	})
	t.Run("Enclave online but refusing cannot veto an independent quorum", func(t *testing.T) {
		w := newCustodyWorldV2(t, flags, v2Env)
		w.behave[0], w.behave[1] = v2Refuse, v2Refuse
		ok(t, w)
		if got := w.combined(t); fmt.Sprint(got) != "[2 3 4]" {
			t.Fatalf("independent quorum combined from machines %v", got)
		}
		if w.released[2].Load() != 1 || w.released[3].Load() != 1 || w.released[4].Load() != 1 {
			t.Fatal("the other seats should have answered")
		}
	})
	t.Run("Enclave online but lying cannot veto an independent quorum", func(t *testing.T) {
		w := newCustodyWorldV2(t, flags, v2Env)
		w.behave[0], w.behave[1] = v2Lie, v2Down
		ok(t, w)
		if got := w.combined(t); fmt.Sprint(got) != "[2 3 4]" {
			t.Fatalf("independent quorum combined from machines %v", got)
		}
	})
	t.Run("no Enclave machine online: the other seats suffice", func(t *testing.T) {
		w := newCustodyWorldV2(t, flags, v2Env)
		w.behave[0], w.behave[1] = v2Down, v2Down
		ok(t, w)
		if got := w.combined(t); fmt.Sprint(got) != "[2 3 4]" {
			t.Fatalf("combined from machines %v", got)
		}
	})
	t.Run("a lying member is dropped", func(t *testing.T) {
		w := newCustodyWorldV2(t, flags, v2Env)
		w.behave[2] = v2Lie
		ok(t, w)
		if got := w.combined(t); fmt.Sprint(got) != "[0 3 4]" {
			t.Fatalf("combined from machines %v", got)
		}
	})
	t.Run("a member releasing another seat's (valid) partial is dropped", func(t *testing.T) {
		w := newCustodyWorldV2(t, flags, v2Env)
		w.behave[2] = v2WrongIndex
		ok(t, w)
		if got := w.combined(t); fmt.Sprint(got) != "[0 3 4]" {
			t.Fatalf("combined from machines %v", got)
		}
	})
	t.Run("too few: no Enclave and one other down; refused before the host is asked", func(t *testing.T) {
		w := newCustodyWorldV2(t, flags, v2Env)
		w.behave[0], w.behave[1], w.behave[3] = v2Down, v2Down, v2Down
		if _, err := w.run(t); err == nil || !strings.Contains(err.Error(), "quorum") || w.authN.Load() != 0 {
			t.Fatalf("too few: %v (authorizations %d)", err, w.authN.Load())
		}
	})
	t.Run("too few valid: Enclave + one other, the second other lies", func(t *testing.T) {
		w := newCustodyWorldV2(t, flags, v2Env)
		w.behave[1], w.behave[3], w.behave[4] = v2Down, v2Lie, v2Down
		if _, err := w.run(t); err == nil || !strings.Contains(err.Error(), "quorum") {
			t.Fatalf("too few valid: %v", err)
		}
	})
}

func TestProvisionCustodyV2SmallCommittees(t *testing.T) {
	// n < 3: the Enclave seat alone unlocks (Enclave + one other: Enclave holds indices 1,2 of t = 2)
	w := newCustodyWorldV2(t, []bool{true, false}, v2Env)
	if p, err := w.run(t); err != nil || p.config != v2Config {
		t.Fatalf("Enclave + one other: %v", err)
	}
	if got := w.combined(t); fmt.Sprint(got) != "[0]" {
		t.Fatalf("combined from machines %v, want the Enclave machine alone", got)
	}
	// ... and the other host alone does not
	w = newCustodyWorldV2(t, []bool{true, false}, v2Env)
	w.behave[0] = v2Down
	if _, err := w.run(t); err == nil || !strings.Contains(err.Error(), "quorum") {
		t.Fatalf("the other host alone unlocked: %v", err)
	}
	// Enclave online and refusing, the other answering: refused
	w = newCustodyWorldV2(t, []bool{true, false}, v2Env)
	w.behave[0] = v2Refuse
	if _, err := w.run(t); err == nil {
		t.Fatal("unlocked without the Enclave seat")
	}
	// the genesis committee: one Enclave machine, t = 1
	w = newCustodyWorldV2(t, []bool{true}, v2Env)
	if p, err := w.run(t); err != nil || p.config != v2Config {
		t.Fatalf("genesis: %v", err)
	}
}

func TestProvisionCustodyV2FailsClosed(t *testing.T) {
	flags := []bool{true, false, false, false}
	// the relay delivers a config other than the one the owner committed
	w := newCustodyWorldV2(t, flags, v2Env)
	w.config = map[string]any{"api_key": "$MCP_ADAPTER_API_KEY", "http": []any{map[string]any{"url": "https://evil.example/collect"}}}
	if _, err := w.run(t); err == nil || !strings.Contains(err.Error(), "not the one the owner committed") {
		t.Fatalf("a relay-chosen config was accepted: %v", err)
	}
	// relay-held values alongside a v2 pointer
	w = newCustodyWorldV2(t, flags, v2Env)
	w.secrets = map[string]string{"MCP_ADAPTER_API_KEY": "relay-held"}
	if _, err := w.run(t); err == nil || !strings.Contains(err.Error(), "relay-held secrets") {
		t.Fatalf("custody + relay values: %v", err)
	}
	// pointers that do not check out are refused before any custodian is asked
	for name, mutate := range map[string]func(p map[string]any){
		"a threshold that is not the seat layout's": func(p map[string]any) { p["t"] = 2 },
		"an endpoint with a query": func(p map[string]any) {
			p["machines"].([]any)[1].(map[string]any)["endpoint"] = "https://cm-1.example/x?y"
		},
		"an endpoint with a dot segment": func(p map[string]any) {
			p["machines"].([]any)[1].(map[string]any)["endpoint"] = "https://cm-1.example/t/../x"
		},
		"an endpoint on another port": func(p map[string]any) {
			p["machines"].([]any)[1].(map[string]any)["endpoint"] = "https://cm-1.example:8443"
		},
		"a commitment that is not a point":        func(p map[string]any) { p["commitments"] = "04" + p["commitments"].(string)[2:] },
		"a bundle for another deployment's label": func(p map[string]any) { p["secretRev"] = "7" },
		"v1 fields in a v2 pointer":               func(p map[string]any) { p["threshold"] = 3 },
	} {
		w := newCustodyWorldV2(t, flags, v2Env)
		mutate(w.pointer())
		_, err := w.run(t)
		asked := int32(0)
		for i := range w.released {
			asked += w.released[i].Load()
		}
		if err == nil || asked != 0 || w.authN.Load() != 0 {
			t.Fatalf("%s: %v (custodians judged %d, host authorized %d)", name, err, asked, w.authN.Load())
		}
		t.Logf("%s: refused: %v", name, err)
	}
}

func TestCustodianEndpointV2(t *testing.T) {
	for raw, want := range map[string]string{
		"https://cm.example":                         "https://cm.example",
		"https://cm.example/":                        "https://cm.example",
		"https://api.enclave.host/t/custody-metal0":  "https://api.enclave.host/t/custody-metal0",
		"https://api.enclave.host/t/custody-metal0/": "https://api.enclave.host/t/custody-metal0",
		"https://CM.example:443/a/b.c/d~e/f-g_h":     "https://cm.example/a/b.c/d~e/f-g_h",
	} {
		got, host, err := custodianEndpointV2(raw)
		if err != nil || got != want || !strings.HasPrefix(want, "https://"+host) {
			t.Fatalf("%s: %q %q %v", raw, got, host, err)
		}
	}
	for _, bad := range []string{
		"http://cm.example", "https://cm.example:8443", "https://u@cm.example", "https://cm.example/a?b", "https://cm.example/a#b",
		"https://cm.example/a/../b", "https://cm.example/..", "https://cm.example/./a", "https://cm.example/a%2fb", "https://cm.example/a/b/c/d/e",
		"https://cm.example//a", "https://cm.example\\a", "https://10.0.0.1/a", "https://localhost/a", "https://cm.example/a b", "https://cm.example/é",
		"https://cm.example/a//", "",
	} {
		if got, _, err := custodianEndpointV2(bad); err == nil {
			t.Fatalf("%q accepted as %q", bad, got)
		}
	}
}
