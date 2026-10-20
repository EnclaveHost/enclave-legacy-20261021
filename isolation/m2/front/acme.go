package main

// In-guest ACME for owner-committed names (names.go), when the owner's package selects a CA and a DNS-01 challenge
// responder (bootstrap.NameACME). Nothing here is a platform service: the CA directory, the responder and its zone
// are the owner's explicit choice, and there is no default or fallback for any of them.
//
//   - The ACME account key is minted here, in guest memory, and is never the TLS key (a CA refuses that). With an
//     EAB the binding comes from the owner's custody secrets, resolved inside this guest.
//   - The CSR is for this domain's own attested key; the issued chain is installed only if it carries that key, is
//     for that name and chains to the measured roots (certs.go install).
//   - The dns-01 value is pushed to the responder signed by the attested TLS key, with an attestation document whose
//     report binds that key and a nonce derived from the push. A responder that checks both (relay/dns-relay.js,
//     DNS_CHALLENGE_AUTH=attested) writes only for a measured guest launched for this deployment, and only at the
//     alias label that commits to this deployment AND its current owner (bootstrap.ChallengeLabel).
//   - What proves the name is the CA following the owner's own _acme-challenge.<host> CNAME to that alias. A host
//     the owner never delegated fails validation; no package claim can change that.
//
// Duplicate-certificate limits: a relaunch mints a new key and so needs a new certificate. Each name is ordered
// alone (its own duplicate set), a fresh certificate is reused until 2/3 of its life, and failures back off
// exponentially from 15 minutes to a day. The status endpoint states the remaining exposure; the owner chooses a
// CA whose limits fit how often the host relaunches the guest.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"enclave.host/isolation/m2/bootstrap"
)

const (
	pushNoncePrefix = "enclave-acme-push-v1\n"
	pushSigPrefix   = "enclave-acme-push-sig-v1\n"
	acmeBackoffMin  = 15 * time.Minute
	acmeBackoffMax  = 24 * time.Hour
)

// challengePush is the body a responder authorizes. Field order is fixed by this struct; the signature covers the
// exact bytes sent.
type challengePush struct {
	V           int             `json:"v"`
	Op          string          `json:"op"`
	Name        string          `json:"name"`
	Value       string          `json:"value"`
	Deployment  string          `json:"deploymentId"`
	Owner       string          `json:"owner"`
	TS          int64           `json:"ts"`
	SPKI        string          `json:"spki"`
	Attestation json.RawMessage `json:"attestation"`
}

// pushNonce binds an attestation to exactly this push (relay/dns-challenge-attested.mjs computes the same).
func pushNonce(p challengePush) []byte {
	s := strings.Join([]string{strconv.Itoa(p.V), p.Op, p.Name, p.Value, p.Deployment, p.Owner,
		strconv.FormatInt(p.TS, 10), p.SPKI}, "\n")
	h := sha256.Sum256([]byte(pushNoncePrefix + s))
	return h[:]
}

type issueState struct {
	lastAttempt, nextAttempt time.Time
	lastError                string
	failures, issued         int
}

type issueView struct {
	Mode        string `json:"mode"`
	LastAttempt string `json:"lastAttempt,omitempty"`
	LastError   string `json:"lastError,omitempty"`
	NextAttempt string `json:"nextAttempt,omitempty"`
	Issued      int    `json:"issuedThisBoot"`
}

type acmeIssuer struct {
	names      *ownerNames
	certs      *certState
	cfg        bootstrap.NameACME
	alias      string
	deployment string
	owner      string
	eab        *acme.ExternalAccountBinding
	httpc      *http.Client // egress through the host, verified against the measured roots
	attest     func(nonce []byte) ([]byte, error)
	signer     crypto.Signer
	spki       []byte
	now        func() time.Time
	account    *acme.Client
	registered bool
	mu         sync.Mutex
	state      map[string]*issueState
}

func newACMEIssuer(names *ownerNames, certs *certState, eabKID string, eabKey []byte, httpc *http.Client,
	attest func([]byte) ([]byte, error), signer crypto.Signer, spki []byte) (*acmeIssuer, error) {
	names.mu.Lock()
	g := names.grant
	names.mu.Unlock()
	if g.ACME == nil {
		return nil, errors.New("the owner selected no ACME directory")
	}
	if g.ACME.EAB != nil && (eabKID == "" || len(eabKey) == 0) {
		return nil, errors.New("the owner's CA needs an EAB this guest could not resolve")
	}
	alias, err := bootstrap.ChallengeAlias(g.Deployment, g.Owner, g.ACME.Zone)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	i := &acmeIssuer{names: names, certs: certs, cfg: *g.ACME, alias: alias, deployment: "0x" + hex.EncodeToString(g.Deployment[:]),
		owner: g.Owner, httpc: httpc, attest: attest, signer: signer, spki: spki, now: time.Now, state: map[string]*issueState{},
		account: &acme.Client{Key: key, DirectoryURL: g.ACME.Directory, HTTPClient: httpc, UserAgent: "enclave-front"}}
	if g.ACME.EAB != nil {
		i.eab = &acme.ExternalAccountBinding{KID: eabKID, Key: append([]byte(nil), eabKey...)}
	}
	return i, nil
}

func (i *acmeIssuer) view(name string) *issueView {
	i.mu.Lock()
	defer i.mu.Unlock()
	v := &issueView{Mode: "acme-dns-01"}
	if s := i.state[name]; s != nil {
		v.Issued, v.LastError = s.issued, s.lastError
		if !s.lastAttempt.IsZero() {
			v.LastAttempt = s.lastAttempt.UTC().Format(time.RFC3339)
		}
		if !s.nextAttempt.IsZero() {
			v.NextAttempt = s.nextAttempt.UTC().Format(time.RFC3339)
		}
	}
	return v
}

// due: an authorized name with no certificate, or one past 2/3 of its life, whose backoff has passed.
func (i *acmeIssuer) due(name string, now time.Time) bool {
	child := i.certs.forName(name)
	if child == nil || child == i.certs {
		return false
	}
	if leaf := child.current(); leaf != nil && now.Before(renewAt(leaf)) {
		return false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	s := i.state[name]
	return s == nil || !now.Before(s.nextAttempt)
}

// pass issues for every due name once; returns how many were installed.
func (i *acmeIssuer) pass(ctx context.Context) int {
	n := 0
	for _, name := range i.names.authorized() {
		now := i.now()
		if !i.due(name, now) {
			continue
		}
		err := i.issue(ctx, name)
		i.mu.Lock()
		s := i.state[name]
		if s == nil {
			s = &issueState{}
			i.state[name] = s
		}
		s.lastAttempt = now
		if err != nil {
			s.failures++
			back := acmeBackoffMin << min(s.failures-1, 7)
			if back > acmeBackoffMax {
				back = acmeBackoffMax
			}
			s.lastError, s.nextAttempt = bounded(err.Error(), 200), now.Add(back)
			fmt.Printf("DOM names: certificate for %s not issued (%s); next attempt in %s\n", name, s.lastError, back)
		} else {
			s.failures, s.lastError, s.nextAttempt = 0, "", time.Time{}
			s.issued++
			n++
		}
		i.mu.Unlock()
	}
	return n
}

func (i *acmeIssuer) run(ctx context.Context, every time.Duration) {
	for {
		i.pass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

func bounded(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (i *acmeIssuer) issue(ctx context.Context, name string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if !i.names.authorizes(name) {
		return errors.New("the name is no longer authorized")
	}
	if !i.registered {
		_, err := i.account.Register(ctx, &acme.Account{ExternalAccountBinding: i.eab}, acme.AcceptTOS)
		if err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
			return fmt.Errorf("ACME account: %w", err)
		}
		i.registered = true
	}
	order, err := i.account.AuthorizeOrder(ctx, acme.DomainIDs(name))
	if err != nil {
		return fmt.Errorf("ACME order: %w", err)
	}
	for _, u := range order.AuthzURLs {
		z, err := i.account.GetAuthorization(ctx, u)
		if err != nil {
			return fmt.Errorf("ACME authorization: %w", err)
		}
		if z.Status == acme.StatusValid {
			continue
		}
		if z.Identifier.Value != name {
			return errors.New("the CA asked to authorize another name")
		}
		var ch *acme.Challenge
		for _, c := range z.Challenges {
			if c.Type == "dns-01" {
				ch = c
			}
		}
		if ch == nil {
			return errors.New("the CA offered no dns-01 challenge")
		}
		value, err := i.account.DNS01ChallengeRecord(ch.Token)
		if err != nil {
			return err
		}
		if err := i.push(ctx, "set", value); err != nil {
			return fmt.Errorf("challenge responder: %w", err)
		}
		defer i.push(context.Background(), "delete", value)
		if _, err := i.account.Accept(ctx, ch); err != nil {
			return fmt.Errorf("ACME challenge: %w", err)
		}
		if _, err := i.account.WaitAuthorization(ctx, z.URI); err != nil {
			return fmt.Errorf("ACME validation (is _acme-challenge.%s a CNAME to %s?): %w", name, i.alias, err)
		}
	}
	if order, err = i.account.WaitOrder(ctx, order.URI); err != nil {
		return fmt.Errorf("ACME order: %w", err)
	}
	child := i.certs.forName(name)
	if child == nil || child == i.certs {
		return errors.New("the name is no longer authorized")
	}
	csr, err := child.csrDER()
	if err != nil {
		return err
	}
	ders, _, err := i.account.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("ACME finalize: %w", err)
	}
	var chain bytes.Buffer
	for _, d := range ders {
		pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: d})
	}
	// revocation can land while the CA works: install only into the CURRENT authorized child
	if child = i.certs.forName(name); child == nil || child == i.certs || !i.names.authorizes(name) {
		return errors.New("the name was revoked during issuance; the certificate is not installed")
	}
	leaf, err := child.install(chain.Bytes(), i.now())
	if err != nil {
		return err
	}
	fmt.Printf("DOM names: certificate installed for %s: issuer %q, valid until %s\n", name, leaf.Issuer.CommonName,
		leaf.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

// push asks the owner-selected responder to set or delete the dns-01 value at this deployment's alias.
func (i *acmeIssuer) push(ctx context.Context, op, value string) error {
	p := challengePush{V: 1, Op: op, Name: i.alias, Value: value, Deployment: i.deployment, Owner: i.owner,
		TS: i.now().Unix(), SPKI: base64.StdEncoding.EncodeToString(i.spki)}
	doc, err := i.attest(pushNonce(p))
	if err != nil {
		return fmt.Errorf("attestation for the push: %w", err)
	}
	p.Attestation = doc
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(append([]byte(pushSigPrefix), body...))
	sig, err := i.signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return err
	}
	method := http.MethodPost
	if op == "delete" {
		method = http.MethodDelete
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(i.cfg.Challenge, "/")+"/v1/txt", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-attested-sig", base64.StdEncoding.EncodeToString(sig))
	res, err := i.httpc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", res.StatusCode, bounded(strings.TrimSpace(string(b)), 160))
	}
	return nil
}
