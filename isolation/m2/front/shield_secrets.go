package main

import (
	"crypto/ed25519"
	"enclave.host/isolation/contract"
	"enclave.host/isolation/m2/egress"
	"enclave.host/isolation/m2/release"
	"enclave.host/isolation/m2/shieldconfig"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"
)

const shieldSecretsPath = "/.well-known/enclave-secrets"
const shieldSecretPurpose = "enclave-shield-secrets/1"

type shieldSecrets struct {
	mu     sync.Mutex
	id     [32]byte
	text   string
	pipe   io.WriteCloser
	pins   []ed25519.PublicKey
	key    *release.SealKey
	nonce  [32]byte
	until  time.Time
	done   bool
	egress *shieldEgress     // the domain's outbound path, set up from the release before the pipe is written (shield_egress.go)
	fwd    *egress.Forwarder // its forwarders, held for the domain's life
}

func newShieldSecrets(pipe io.WriteCloser, file string, eg *shieldEgress) (*shieldSecrets, error) {
	if eg == nil {
		return nil, errors.New("a secret domain needs its egress path: the runtime must never get secrets without its allowlist")
	}
	b, e := os.ReadFile(file)
	if e != nil {
		return nil, e
	}
	if !regexp.MustCompile(`^0x[0-9a-f]{64}$`).Match(b) {
		return nil, errors.New("invalid secret deployment")
	}
	id, e := release.ID(string(b))
	if e != nil {
		return nil, e
	}
	pins, e := release.PinnedRelayKeys()
	if e != nil {
		return nil, e
	}
	return &shieldSecrets{id: id, text: string(b), pipe: pipe, pins: pins, egress: eg}, nil
}
func (f *front) serveShieldSecrets(w http.ResponseWriter, r *http.Request) {
	s := f.secrets
	if s == nil {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		http.Error(w, "already provisioned", http.StatusConflict)
		return
	}
	if r.Method == http.MethodGet {
		n, e := hex.DecodeString(r.URL.Query().Get("nonce"))
		if e != nil || len(n) != 32 {
			http.Error(w, "nonce required", 400)
			return
		}
		var nonce [32]byte
		copy(nonce[:], n)
		if s.key == nil || s.nonce != nonce || time.Now().After(s.until) {
			s.key, e = release.NewSealKey()
			if e != nil {
				http.Error(w, "key unavailable", 503)
				return
			}
			s.nonce = nonce
			s.until = time.Now().Add(120 * time.Second)
		}
		rid, e := contract.RuntimeID(f.rt.ID)
		if e != nil {
			http.Error(w, "runtime unavailable", 503)
			return
		}
		bind, e := release.Binding(s.id, f.spki, s.nonce, rid, s.key.Public())
		if e != nil {
			http.Error(w, "binding unavailable", 503)
			return
		}
		rep, certs, boundary, tier, format, wx, e := f.askMonitor(bind[:])
		if e != nil {
			http.Error(w, "report unavailable", 503)
			return
		}
		self, e := f.selfTest(wx)
		if e != nil {
			http.Error(w, "self-test unavailable", 503)
			return
		}
		d := doc{Tier: tier, Format: format, Report: base64.StdEncoding.EncodeToString(rep), TransportKey: base64.StdEncoding.EncodeToString(f.spki), AppSha256: hex.EncodeToString(f.appSha), Nonce: hex.EncodeToString(nonce[:]), Boundary: boundary, Abi: contract.ABI2, Runtime: &f.rt.ID, RuntimeSelfTest: self}
		if len(certs) > 0 {
			d.Certs = base64.StdEncoding.EncodeToString(certs)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			Doc     doc    `json:"doc"`
			SealKey string `json:"sealKey"`
			Purpose string `json:"purpose"`
			ID      string `json:"id"`
		}{d, base64.StdEncoding.EncodeToString(s.key.Public()), shieldSecretPurpose, s.text})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method refused", 405)
		return
	}
	if s.key == nil || time.Now().After(s.until) {
		http.Error(w, "no live challenge", 409)
		return
	}
	var b struct {
		Nonce  string `json:"nonce"`
		Sealed string `json:"sealed"`
		Sig    string `json:"sig"`
		KeyID  string `json:"keyId"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536))
	dec.DisallowUnknownFields()
	if dec.Decode(&b) != nil || b.Nonce != hex.EncodeToString(s.nonce[:]) {
		http.Error(w, "invalid release", 400)
		return
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		http.Error(w, "invalid release", 400)
		return
	}
	sealed, e := base64.StdEncoding.Strict().DecodeString(b.Sealed)
	if e != nil {
		http.Error(w, "invalid release", 400)
		return
	}
	sig, e := base64.StdEncoding.Strict().DecodeString(b.Sig)
	if e != nil {
		http.Error(w, "invalid release", 400)
		return
	}
	resp, e := s.key.Verify(s.pins, s.id, s.nonce, sealed, sig, b.KeyID)
	if e != nil {
		http.Error(w, "release refused", 403)
		return
	}
	plain, e := s.key.Open(resp)
	if e != nil {
		http.Error(w, "release refused", 403)
		return
	}
	issued, e := time.Parse(time.RFC3339Nano, plain.IssuedAt)
	if e != nil || time.Since(issued) > 120*time.Second || time.Until(issued) > 30*time.Second || shieldconfig.Validate(plain.Secrets) != nil || string(plain.Config) != "null" {
		http.Error(w, "release refused", 403)
		return
	}
	// Only this private pipe reaches the waiting runtime. Nothing is persisted or logged.
	payload, e := json.Marshal(plain.Secrets)
	if e != nil {
		http.Error(w, "release refused", 403)
		return
	}
	s.done = true
	s.key = nil
	// EGRESS BEFORE THE RUNTIME (shield_egress.go): the allowlist from the measured config resolved with THESE secrets,
	// a forwarder per allowed origin listening, /etc/hosts naming only them, and the listener audit clean - all before
	// one byte reaches the runtime. On any failure the pipe is closed EMPTY: secretrun reads EOF, refuses, and the
	// domain ends, so the app never runs without the allowlist its owner's config states. The release is spent either
	// way. The console gets the failing step's name only.
	if s.egress == nil {
		e = egressStepError{"setup"}
	} else {
		s.fwd, e = s.egress.start(plain)
	}
	if e != nil {
		for i := range payload {
			payload[i] = 0
		}
		plain.Secrets = nil
		s.pipe.Close()
		if es, ok := e.(egressStepError); ok {
			fmt.Printf("DOM egress: %s; the runtime gets nothing and the domain ends\n", es.Error())
		}
		http.Error(w, "egress unavailable", 503)
		return
	}
	_, e = s.pipe.Write(payload)
	s.pipe.Close()
	for i := range payload {
		payload[i] = 0
	}
	plain.Secrets = nil
	if e != nil {
		http.Error(w, "launch channel unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}
