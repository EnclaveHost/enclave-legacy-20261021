package custody

// The v2 release, as the measured front runs it (docs/security/secret-custody-v2-spec.md §4):
//
//  1. ask EVERY machine of the committee's epoch for a challenge; E = the Enclave machines that answered;
//  2. a fresh recipient key, the v2 binding over the challenges that answered, hardware evidence over it (report_data =
//     binding ‖ AppID, the front's half) and the lease holder's operator authorization (custody-auth-v2);
//  3. the release to every machine that issued a challenge; each answer opens only under the recipient key and this
//     binding, and EVERY partial record in it must verify (DLEQ against Y_k from the commitments) and be for exactly the
//     indices that machine holds: a machine with one bad record is dropped whole;
//  4. combine at most one Enclave machine's valid partials (its replicas share one seat), then independent seats.
//     An Enclave machine answering a challenge does not gain a veto over an independently sufficient quorum.
//     Host-owner refusal belongs in that host's admission policy, not in the network-wide custody combiner;
//  5. combine exactly t partials, open the bundle under its label. Fewer than t: refuse; the app does not start.
//
// Because every partial is verified before it is used, a lying custodian is identified and dropped; it cannot make the
// guest combine a wrong key, so no subset search is needed (v1's MaxSubsets does not apply).

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"

	"enclave.host/isolation/m2/custody/seats"
)

// MachineV2 is one custodian machine of the committee's epoch, in machine order.
type MachineV2 struct {
	EncKey   [32]byte
	Endpoint string // https base URL (may carry a path prefix); the API paths are appended
	Enclave  bool
	Indices  []uint32
}

// StateV2 is what a v2 release needs to know about the deployment's custody (the relay-signed v2 pointer).
type StateV2 struct {
	Ctx         Context
	ID          [32]byte
	CommitteeID [32]byte
	PolicyRev   uint64
	SecretRev   uint64
	Epoch       uint32
	Threshold   int
	Commitments [][]byte // t x 33
	Bundle      []byte   // R ‖ proof ‖ nonce ‖ ct
	Machines    []MachineV2
}

// check checks the state's shape against the seat layout, and the bundle's label proof against this deployment.
func (s *StateV2) check() (label [32]byte, l *seats.Layout, err error) {
	if s.PolicyRev == 0 || s.SecretRev == 0 || s.Epoch == 0 || s.Ctx.ChainID == 0 {
		return label, nil, errors.New("the custody state is incomplete")
	}
	flags := make([]bool, len(s.Machines))
	keys := map[[32]byte]bool{}
	for i, m := range s.Machines {
		flags[i] = m.Enclave
		if keys[m.EncKey] {
			return label, nil, fmt.Errorf("machine %d repeats another machine's key", i)
		}
		keys[m.EncKey] = true
	}
	if l, err = SeatLayout(flags); err != nil {
		return label, nil, err
	}
	if l.T != s.Threshold {
		return label, nil, fmt.Errorf("the pointer's threshold %d is not its seat layout's %d", s.Threshold, l.T)
	}
	for i, m := range s.Machines {
		if !equalIndices(m.Indices, l.Indices[i]) {
			return label, nil, fmt.Errorf("machine %d's share indices are not its seat's", i)
		}
	}
	if len(s.Commitments) != s.Threshold {
		return label, nil, fmt.Errorf("%d commitments for threshold %d", len(s.Commitments), s.Threshold)
	}
	for j, c := range s.Commitments {
		if _, err := PointOf(c, fmt.Sprintf("commitment %d", j)); err != nil {
			return label, nil, err
		}
	}
	label = LabelOf(LabelInput{Ctx: s.Ctx, ID: s.ID, SecretRev: s.SecretRev, CommitteeID: s.CommitteeID})
	if !VerifyLabelProof(s.Bundle, label) {
		return label, nil, errors.New("the bundle's label proof does not name this deployment")
	}
	return label, l, nil
}

func equalIndices(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type wireChallengeV2 struct {
	EncKey    string `json:"encKey"`
	Nonce     string `json:"nonce"`
	ExpiresAt int64  `json:"expiresAt,omitempty"`
}

type wireReleaseV2 struct {
	V            int             `json:"v"`
	ID           string          `json:"id"`
	Endpoint     string          `json:"endpoint"`
	CommitteeID  string          `json:"committeeId"`
	Epoch        uint32          `json:"epoch"`
	PolicyRev    string          `json:"policyRev"`
	SecretRev    string          `json:"secretRev"`
	RecipientKey string          `json:"recipientKey"`
	Challenges   []wireChallenge `json:"challenges"`
	Operator     wireOperator    `json:"operator"`
	Evidence     json.RawMessage `json:"evidence"`
}

type wirePartialsV2 struct {
	V      int    `json:"v"`
	EncKey string `json:"encKey"`
	Count  int    `json:"count"`
	Sealed string `json:"sealed"`
}

// ObtainV2 returns the deployment's opened v2 bundle, or an error naming why not. The recipient key lives only in this
// call. The CALLER must refuse to substitute the values into any config whose sha256 is not Bundle.ConfigSha256.
func (c *Client) ObtainV2(ctx context.Context, st StateV2) (*Bundle, error) {
	if c.AuthorizeV2 == nil {
		return nil, errors.New("no custody-auth-v2 channel")
	}
	label, lay, err := st.check()
	if err != nil {
		return nil, err
	}
	R, err := PointOf(st.Bundle[:33], "bundle R")
	if err != nil {
		return nil, err
	}

	// 1. challenges from every machine
	type got struct {
		i  int
		ch Challenge
	}
	var mu sync.Mutex
	var chs []got
	var wg sync.WaitGroup
	for i, m := range st.Machines {
		wg.Add(1)
		go func(i int, m MachineV2) {
			defer wg.Done()
			var r wireChallengeV2
			if err := c.Post(ctx, m.Endpoint+"/v2/custody/challenge", struct{}{}, &r); err != nil {
				c.logf("DOM custody: machine %d gave no challenge: %v", i, err)
				return
			}
			if r.EncKey != hex.EncodeToString(m.EncKey[:]) {
				c.logf("DOM custody: machine %d answered under another key", i)
				return
			}
			n, err := hex.DecodeString(r.Nonce)
			if err != nil || len(n) != 32 {
				c.logf("DOM custody: machine %d's challenge has no 32-byte nonce", i)
				return
			}
			g := got{i: i, ch: Challenge{EncKey: m.EncKey}}
			copy(g.ch.Nonce[:], n)
			mu.Lock()
			chs = append(chs, g)
			mu.Unlock()
		}(i, m)
	}
	wg.Wait()
	sort.Slice(chs, func(a, b int) bool { return chs[a].i < chs[b].i })
	enclaveOnline, others := false, 0
	for _, g := range chs {
		if st.Machines[g.i].Enclave {
			enclaveOnline = true
		} else {
			others++
		}
	}
	reach := others
	if enclaveOnline {
		reach += lay.EnclaveWeight
	}
	if reach < st.Threshold {
		return nil, fmt.Errorf("%w: the %d of %d machines that issued a challenge hold %d share indices (need %d)", ErrQuorum, len(chs), len(st.Machines), reach, st.Threshold)
	}
	challenges := make([]Challenge, len(chs))
	for i, g := range chs {
		challenges[i] = g.ch
	}

	// 2. recipient key, binding, evidence, the operator's authorization
	sk, err := NewRecipientKey()
	if err != nil {
		return nil, err
	}
	var rk [32]byte
	copy(rk[:], sk.PublicKey().Bytes())
	binding, err := BindingV2(BindingInputV2{Ctx: st.Ctx, ID: st.ID, PolicyRev: st.PolicyRev, SecretRev: st.SecretRev, CommitteeID: st.CommitteeID,
		Epoch: st.Epoch, Challenges: challenges, RuntimeID: c.RuntimeID, TransportSPKI: c.TransportSPKI, RecipientKey: rk})
	if err != nil {
		return nil, err
	}
	ev, err := c.Evidence(binding)
	if err != nil {
		return nil, fmt.Errorf("the custody report: %w", err)
	}
	endpoint, sig, expiry, err := c.AuthorizeV2(ctx, st.Ctx.Vault, st.ID, binding)
	if err != nil {
		return nil, fmt.Errorf("the operator's authorization: %w", err)
	}
	req := wireReleaseV2{V: 2, ID: "0x" + hex.EncodeToString(st.ID[:]), Endpoint: endpoint, CommitteeID: "0x" + hex.EncodeToString(st.CommitteeID[:]),
		Epoch: st.Epoch, PolicyRev: strconv.FormatUint(st.PolicyRev, 10), SecretRev: strconv.FormatUint(st.SecretRev, 10),
		RecipientKey: hex.EncodeToString(rk[:]), Operator: wireOperator{Sig: sig, Expiry: expiry}, Evidence: ev}
	for _, ch := range challenges {
		req.Challenges = append(req.Challenges, wireChallenge{EncKey: hex.EncodeToString(ch.EncKey[:]), Nonce: hex.EncodeToString(ch.Nonce[:])})
	}

	// 3. partials from every machine that issued a challenge; a machine with any bad record is dropped whole
	valid := map[int][]Partial{}
	for _, g := range chs {
		wg.Add(1)
		go func(g got) {
			defer wg.Done()
			m := st.Machines[g.i]
			var r wirePartialsV2
			if err := c.Post(ctx, m.Endpoint+"/v2/custody/release", req, &r); err != nil {
				c.logf("DOM custody: machine %d released nothing: %v", g.i, err)
				return
			}
			ps, err := c.machinePartials(sk, binding, R, st.Commitments, m, r)
			if err != nil {
				c.logf("DOM custody: machine %d dropped: %v", g.i, err)
				return
			}
			mu.Lock()
			valid[g.i] = ps
			mu.Unlock()
		}(g)
	}
	wg.Wait()

	// 4. choose exactly t valid indices, counting Enclave replicas as one seat
	var use []Partial
	var used []int // machine positions combined
	if enclaveOnline {
		chosen := -1
		for _, g := range chs {
			if st.Machines[g.i].Enclave && valid[g.i] != nil {
				chosen = g.i
				break
			}
		}
		if chosen >= 0 {
			use = append(use, valid[chosen]...)
			used = append(used, chosen)
		}
	}
	for _, g := range chs {
		if len(use) >= st.Threshold {
			break
		}
		if !st.Machines[g.i].Enclave && valid[g.i] != nil {
			use = append(use, valid[g.i]...)
			used = append(used, g.i)
		}
	}
	if len(use) < st.Threshold {
		return nil, fmt.Errorf("%w: %d valid share indices released (need %d)", ErrQuorum, len(use), st.Threshold)
	}
	if len(use) > st.Threshold { // only possible if a seat's weight exceeded what remained; never with this layout
		return nil, errors.New("the released indices do not make up exactly the threshold")
	}

	// 5. combine and open
	ks := make([]uint32, len(use))
	for i, p := range use {
		ks[i] = p.K
	}
	c.logf("DOM custody: %d of %d machines released valid partials; combining indices %v from machines %v", len(valid), len(chs), ks, used)
	S, err := Combine(use, st.Threshold)
	if err != nil {
		return nil, err
	}
	b, err := DecryptBundleV2(S, label, st.Bundle)
	if err != nil {
		return nil, fmt.Errorf("the combined key: %w", err)
	}
	return b, nil
}

// machinePartials opens one machine's answer and verifies that it holds exactly one valid partial for each of that
// machine's share indices, and nothing else.
func (c *Client) machinePartials(sk *ecdh.PrivateKey, binding [32]byte, R *Point, commitments [][]byte, m MachineV2, r wirePartialsV2) ([]Partial, error) {
	if r.V != 2 || r.EncKey != hex.EncodeToString(m.EncKey[:]) {
		return nil, errors.New("it answered for another version or key")
	}
	if r.Count != len(m.Indices) {
		return nil, fmt.Errorf("it answered %d partials for %d share indices", r.Count, len(m.Indices))
	}
	blob, err := base64.StdEncoding.DecodeString(r.Sealed)
	if err != nil {
		return nil, errors.New("its answer is not base64")
	}
	recs, err := OpenPartials(sk, binding, m.EncKey, r.Count, blob)
	if err != nil {
		return nil, errors.New("its answer does not open under this release")
	}
	want := map[uint32]bool{}
	for _, k := range m.Indices {
		want[k] = true
	}
	out := make([]Partial, 0, len(recs))
	for _, rec := range recs {
		p, err := VerifyPartial(rec, R, binding, commitments)
		if err != nil {
			return nil, err
		}
		if !want[p.K] {
			return nil, fmt.Errorf("a partial for index %d, which it does not hold (or repeats)", p.K)
		}
		delete(want, p.K)
		out = append(out, p)
	}
	return out, nil
}
