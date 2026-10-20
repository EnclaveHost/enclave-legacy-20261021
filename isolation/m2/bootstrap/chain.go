// Package bootstrap authenticates owner-committed guest startup packages using
// a fixed ledger and agreeing, fresh chain reads. It never asks a release relay.
package bootstrap

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const maxReply = 512 * 1024
const getSelector = "0x8eaa6ac0"    // get(bytes32), checked against the JS ABI fixture
const schemaSelector = "0x5d1b72b6" // deploymentsSchema()

type rpcCall func(context.Context, string, any, any) error
type endpoint struct {
	name string
	call rpcCall
}
type Reader struct {
	chainID       uint64
	ledger        string
	peers         []endpoint
	confirmations uint64
	maxAge        time.Duration
	now           func() time.Time
	highWater     atomic.Uint64
}

type Config struct {
	ChainID       uint64
	Ledger        string
	RPCs          []string
	Confirmations uint64
	MaxAge        time.Duration
	// Client must retain certificate validation. A measured guest supplies its
	// vsock egress transport and compiled root set, never host-controlled roots.
	Client *http.Client
}

func address(s string) bool {
	b, e := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	return e == nil && strings.HasPrefix(s, "0x") && len(b) == 20 && !zero(b)
}
func zero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
func NewReader(c Config) (*Reader, error) {
	if c.ChainID == 0 || !address(c.Ledger) || c.Confirmations < 1 || c.Confirmations > 64 || c.MaxAge < time.Second || c.MaxAge > 2*time.Minute || len(c.RPCs) < 2 || len(c.RPCs) > 8 {
		return nil, errors.New("invalid measured bootstrap chain policy")
	}
	r := &Reader{chainID: c.ChainID, ledger: strings.ToLower(c.Ledger), confirmations: c.Confirmations, maxAge: c.MaxAge, now: time.Now}
	seen := map[string]bool{}
	base := http.Client{Timeout: 15 * time.Second}
	if c.Client != nil {
		base = *c.Client
	}
	base.Timeout = 15 * time.Second
	base.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, raw := range c.RPCs {
		u, e := url.Parse(raw)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") {
			return nil, errors.New("distinct HTTPS RPC hosts required")
		}
		host, ok := rpcHost(u.Hostname())
		if !ok || seen[host] {
			return nil, errors.New("distinct HTTPS RPC hosts required")
		}
		seen[host] = true
		origin := raw
		r.peers = append(r.peers, endpoint{name: host, call: func(ctx context.Context, method string, params any, out any) error {
			body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
			req, e := http.NewRequestWithContext(ctx, "POST", origin, bytes.NewReader(body))
			if e != nil {
				return e
			}
			req.Header.Set("Content-Type", "application/json")
			res, e := base.Do(req)
			if e != nil {
				return errors.New("bootstrap RPC transport failed")
			}
			defer res.Body.Close()
			if res.StatusCode != 200 {
				return fmt.Errorf("bootstrap RPC HTTP %d", res.StatusCode)
			}
			b, e := io.ReadAll(io.LimitReader(res.Body, maxReply+1))
			if e != nil || len(b) > maxReply {
				return errors.New("bootstrap RPC response exceeds limit")
			}
			var msg struct {
				JSONRPC string          `json:"jsonrpc"`
				ID      int             `json:"id"`
				Result  json.RawMessage `json:"result"`
				Error   json.RawMessage `json:"error"`
			}
			if e = json.Unmarshal(b, &msg); e != nil || msg.JSONRPC != "2.0" || msg.ID != 1 || len(msg.Error) > 0 && string(msg.Error) != "null" || len(msg.Result) == 0 || string(msg.Result) == "null" {
				return errors.New("invalid bootstrap RPC response")
			}
			if e := json.Unmarshal(msg.Result, out); e != nil {
				return errors.New("invalid bootstrap RPC result")
			}
			return nil
		}})
	}
	return r, nil
}

// rpcHost is an RPC's identity for counting distinct peers: one host is one vote however it is spelled. Case and a
// single trailing root dot are canonicalized (RPC.example and rpc.example. are the same host); an IP literal is
// canonicalized by its address; anything else must be a well-formed DNS name.
func rpcHost(h string) (string, bool) {
	if a, e := netip.ParseAddr(h); e == nil {
		return a.Unmap().String(), true
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if len(h) < 1 || len(h) > 253 {
		return "", false
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if !dnsLabelRE.MatchString(l) {
			return "", false
		}
	}
	if len(labels) < 2 || !letterRE.MatchString(labels[len(labels)-1]) {
		return "", false
	}
	return h, true
}

func quantity(s string) (uint64, error) {
	if !strings.HasPrefix(s, "0x") || len(s) < 3 || len(s) > 3 && s[2] == '0' {
		return 0, errors.New("invalid RPC quantity")
	}
	return strconv.ParseUint(s[2:], 16, 64)
}
func wordUint(b []byte, bits int) (uint64, error) {
	if len(b) != 32 || bits > 64 || bits < 1 || !zero(b[:24]) {
		return 0, errors.New("invalid ABI integer")
	}
	var n uint64
	for _, x := range b[24:] {
		n = n<<8 | uint64(x)
	}
	if bits < 64 && n >= (uint64(1)<<bits) {
		return 0, errors.New("ABI integer overflow")
	}
	return n, nil
}
func wordAddr(b []byte) (string, error) {
	if len(b) != 32 || !zero(b[:12]) || zero(b[12:]) {
		return "", errors.New("invalid ABI address")
	}
	return "0x" + hex.EncodeToString(b[12:]), nil
}

type ledgerRow struct {
	id                                [32]byte
	owner, appRef, envelope, operator string
	runner                            [32]byte
	leaseUntil                        uint64
	active                            bool
}

// Ledger schema 16 returns one dynamic tuple with 17 fields. Dynamic tails are
// required to be canonical, contiguous and padded; host/RPC supplied offsets
// never become unchecked slices or allocations.
func decodeRow(raw string, id [32]byte) (ledgerRow, error) {
	var row ledgerRow
	if len(raw) > maxReply*2+2 {
		return row, errors.New("ledger ABI exceeds limit")
	}
	b, e := hex.DecodeString(strings.TrimPrefix(raw, "0x"))
	if e != nil || !strings.HasPrefix(raw, "0x") || len(b) > maxReply || len(b) < 32+17*32 {
		return row, errors.New("invalid ledger ABI")
	}
	off, e := wordUint(b[:32], 64)
	if e != nil || off != 32 {
		return row, errors.New("invalid ledger tuple offset")
	}
	b = b[32:]
	w := func(i int) []byte { return b[i*32 : (i+1)*32] }
	copy(row.id[:], w(0))
	if row.id != id {
		return row, errors.New("ledger returned another deployment")
	}
	if row.owner, e = wordAddr(w(1)); e != nil {
		return row, e
	}
	next := 17 * 32
	for _, field := range []int{2, 3, 4} {
		o, err := wordUint(w(field), 64)
		if err != nil || o != uint64(next) || next+32 > len(b) {
			return row, errors.New("invalid dynamic ledger offset")
		}
		n, err := wordUint(b[next:next+32], 64)
		if err != nil || n > 128*1024 {
			return row, errors.New("ledger string exceeds limit")
		}
		end := next + 32 + int(n)
		padded := next + 32 + (int(n)+31)/32*32
		if padded > len(b) || !zero(b[end:padded]) || !utf8.Valid(b[next+32:end]) {
			return row, errors.New("invalid ledger string")
		}
		value := string(b[next+32 : end])
		if field == 2 {
			row.appRef = value
		}
		if field == 4 {
			row.envelope = value
		}
		next = padded
	}
	if next != len(b) {
		return row, errors.New("trailing ledger ABI data")
	}
	for _, f := range [][2]int{{5, 16}, {6, 16}, {7, 32}, {8, 1}, {9, 1}, {10, 64}, {16, 64}} {
		if _, e = wordUint(w(f[0]), f[1]); e != nil {
			return row, e
		}
	}
	row.active = w(9)[31] == 1
	copy(row.runner[:], w(14))
	row.leaseUntil, _ = wordUint(w(16), 64)
	// A released or never-claimed lease has no operator (the ledger zeroes runner, operator and leaseUntil together):
	// that is a fact to agree on, not malformed ABI. leaseCurrent refuses it.
	if zero(w(15)) {
		row.operator = ""
	} else if row.operator, e = wordAddr(w(15)); e != nil {
		return row, e
	}
	return row, nil
}

// errLeaseNotCurrent: a fresh snapshot the quorum AGREED on whose row is not a current lease - cancelled or
// suspended (inactive), released (no runner or operator), or ended. Unlike an unavailable quorum, this is the chain's
// answer. Startup still waits for it to change (a just-claimed lease may not be confirmed yet); a running
// authorization treats it as revocation.
var errLeaseNotCurrent = errors.New("deployment has no active current lease")

// leaseCurrent judges an agreed snapshot's row. It never runs on a single peer's answer: read() returns only raw facts
// at least two peers reported identically for the same block, so one peer cannot make a lease look ended or live.
func (r *Reader) leaseCurrent(s snapshot) error {
	if !s.row.active || zero(s.row.runner[:]) || s.row.operator == "" || s.row.leaseUntil <= s.timestamp || int64(s.row.leaseUntil) <= r.now().Unix() {
		return errLeaseNotCurrent
	}
	return nil
}

type block struct {
	Number    string `json:"number"`
	Hash      string `json:"hash"`
	Timestamp string `json:"timestamp"`
}
type snapshot struct {
	row               ledgerRow
	number, timestamp uint64
	hash, raw         string
}

func (r *Reader) readAt(ctx context.Context, p endpoint, n uint64, id [32]byte) (snapshot, error) {
	var out snapshot
	tag := fmt.Sprintf("0x%x", n)
	var before, after block
	// once the read's deadline passes or its target block is superseded, no further request leaves for this read
	rpc := func(method string, params any, result any) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		return p.call(ctx, method, params, result)
	}
	if e := rpc("eth_getBlockByNumber", []any{tag, false}, &before); e != nil {
		return out, e
	}
	bn, e := quantity(before.Number)
	if e != nil || bn != n {
		return out, errors.New("wrong block")
	}
	ts, e := quantity(before.Timestamp)
	if e != nil || ts > uint64(r.now().Unix()+5) || int64(ts) < r.now().Add(-r.maxAge).Unix() {
		return out, fmt.Errorf("stale or future chain block (clock delta %ds)", r.now().Unix()-int64(ts))
	}
	// a block hash is exactly 0x + 32 bytes of hex, as JSON-RPC defines it; a bare or short hash is not a header fact
	if !strings.HasPrefix(before.Hash, "0x") || len(before.Hash) != 66 {
		return out, errors.New("invalid block hash")
	}
	h, e := hex.DecodeString(before.Hash[2:])
	if e != nil || len(h) != 32 || zero(h) {
		return out, errors.New("invalid block hash")
	}
	call := func(data string) (string, error) {
		var out string
		e := rpc("eth_call", []any{map[string]string{"to": r.ledger, "data": data}, tag}, &out)
		return out, e
	}
	schema, e := call(schemaSelector)
	if e != nil {
		return out, e
	}
	sb, e := hex.DecodeString(strings.TrimPrefix(schema, "0x"))
	if e != nil {
		return out, e
	}
	sn, e := wordUint(sb, 64)
	if e != nil || sn != 16 {
		return out, errors.New("unsupported ledger schema")
	}
	raw, e := call(getSelector + hex.EncodeToString(id[:]))
	if e != nil {
		return out, e
	}
	// raw facts only: whether they authorize anything is decided after the quorum agrees on them (leaseCurrent)
	row, e := decodeRow(raw, id)
	if e != nil {
		return out, e
	}
	if e = rpc("eth_getBlockByNumber", []any{tag, false}, &after); e != nil {
		return out, e
	}
	if before != after {
		return out, errors.New("chain changed during bootstrap read")
	}
	return snapshot{row: row, number: n, timestamp: ts, hash: strings.ToLower(before.Hash), raw: strings.ToLower(raw)}, nil
}

// fresh: the agreed block is neither from the future nor older than maxAge, judged NOW (at acceptance), not only when
// each peer began its read.
func (r *Reader) fresh(s snapshot) error {
	now := r.now()
	if s.timestamp > uint64(now.Unix()+5) || int64(s.timestamp) < now.Add(-r.maxAge).Unix() {
		return fmt.Errorf("agreed chain block is stale or future at acceptance (clock delta %ds)", now.Unix()-int64(s.timestamp))
	}
	return nil
}

// accept: a snapshot two peers agreed on becomes the answer only if it is fresh now, does not fall below the highest
// block this reader has accepted (rollback floor), and is still fresh once the floor has moved.
func (r *Reader) accept(s snapshot) error {
	if e := r.fresh(s); e != nil {
		return e
	}
	for {
		old := r.highWater.Load()
		if s.number < old {
			return errors.New("bootstrap chain rollback")
		}
		if old == s.number || r.highWater.CompareAndSwap(old, s.number) {
			break
		}
	}
	return r.fresh(s)
}

// read returns raw facts at least two fresh peers reported identically for one block. It never judges them (that is
// leaseCurrent's job) and never falls back to a single peer's answer.
//
// Within one 20-second deadline:
//   - every peer's head is waited for; a head that arrives late (a slow honest RPC) still joins the read at the chosen
//     block, so a fast liar cannot exclude it;
//   - the block is the second-highest head less the confirmations, so one peer alone can neither raise it nor, once a
//     second honest head is in, hold it down: when later heads support a strictly newer block, every peer with a head
//     reads that block too. The block never moves down and is never chosen below the accepted floor (highWater);
//   - the first identical pair of fresh snapshots that passes accept() returns at once, without waiting for a hung peer.
//
// Bounded: at most one choice per arriving head, so at most len(peers)^2 block reads; every send is buffered and every
// reader ends with the deadline's cancellation.
func (r *Reader) read(ctx context.Context, id [32]byte) (snapshot, error) {
	var empty snapshot
	if r == nil || len(r.peers) < 2 || zero(id[:]) {
		return empty, errors.New("measured reader and deployment required")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	type head struct {
		peer endpoint
		n    uint64
		err  error
	}
	type result struct {
		s     snapshot
		e     error
		peer  string
		block uint64 // the target block this read was started for
	}
	heads := make(chan head, len(r.peers))
	results := make(chan result, len(r.peers)*len(r.peers))
	for _, p := range r.peers {
		go func(p endpoint) {
			var chain, num string
			e := p.call(ctx, "eth_chainId", []any{}, &chain)
			if e == nil {
				var cid uint64
				cid, e = quantity(chain)
				if cid != r.chainID {
					e = errors.New("wrong chain")
				}
			}
			if e == nil {
				e = p.call(ctx, "eth_blockNumber", []any{}, &num)
			}
			n, err := quantity(num)
			if e == nil {
				e = err
			}
			heads <- head{p, n, e}
		}(p)
	}
	var refusals []string
	noted := map[string]bool{}
	refuse := func(who, why string) {
		// Public measured peer names and bounded diagnostics only. Never
		// include RPC bodies, configuration, custody values or signatures.
		if len(why) > 160 {
			why = "invalid RPC response"
		}
		if m := who + ": " + why; !noted[m] {
			noted[m] = true
			refusals = append(refusals, m)
		}
	}
	var known []head
	var block uint64
	chosen := false
	reading := map[string]bool{}
	readers, headsLeft := 0, len(r.peers)
	// each target block is a round with its own context: superseding it cancels its reads' remaining requests
	round, endRound := ctx, context.CancelFunc(func() {})
	defer func() { endRound() }()
	readAt := func(p endpoint, n uint64) {
		if k := fmt.Sprintf("%s@%d", p.name, n); !reading[k] {
			reading[k] = true
			readers++
			rc := round
			go func() { s, e := r.readAt(rc, p, n, id); results <- result{s, e, p.name, n} }()
		}
	}
	choose := func() {
		if len(known) < 2 {
			return
		}
		ns := make([]uint64, 0, len(known))
		for _, h := range known {
			ns = append(ns, h.n)
		}
		sort.Slice(ns, func(i, j int) bool { return ns[i] > ns[j] })
		if ns[1] < r.confirmations {
			refuse("quorum", "insufficient confirmed blocks")
			return
		}
		n := ns[1] - r.confirmations
		if n < r.highWater.Load() {
			refuse("quorum", "supported block is below the accepted floor (rollback)")
			return
		}
		if chosen && n <= block {
			return
		}
		endRound()
		round, endRound = context.WithCancel(ctx)
		block, chosen = n, true
		for _, h := range known {
			readAt(h.peer, n)
		}
	}
	agree := map[string]map[string]bool{} // full snapshot -> the distinct peers that reported it
	for headsLeft > 0 || readers > 0 {
		select {
		case h := <-heads:
			headsLeft--
			if h.err != nil {
				refuse(h.peer.name, h.err.Error())
				continue
			}
			known = append(known, h)
			choose()
			if chosen {
				readAt(h.peer, block) // a late head joins the chosen block (a no-op if choose just started it there)
			}
		case v := <-results:
			readers--
			if v.block != block {
				// an older round's answer, even an agreeing one, never returns once a newer target is chosen
				refuse(v.peer, fmt.Sprintf("answer for superseded block %d", v.block))
				continue
			}
			if v.e != nil {
				refuse(v.peer, v.e.Error())
				continue
			}
			k := fmt.Sprintf("%d/%d/%s/%s", v.s.number, v.s.timestamp, v.s.hash, v.s.raw)
			if agree[k] == nil {
				agree[k] = map[string]bool{}
			}
			if agree[k][v.peer] = true; len(agree[k]) < 2 {
				continue
			}
			if e := r.accept(v.s); e != nil {
				refuse("quorum", e.Error())
				continue
			}
			return v.s, nil
		case <-ctx.Done():
			if len(known) < 2 {
				return empty, errors.New("bootstrap chain head deadline")
			}
			return empty, errors.New("bootstrap chain snapshot deadline")
		}
	}
	if len(known) < 2 {
		return empty, fmt.Errorf("bootstrap chain quorum unavailable (%s)", strings.Join(refusals, "; "))
	}
	return empty, fmt.Errorf("no fresh agreeing bootstrap chain snapshot (%s)", strings.Join(refusals, "; "))
}
