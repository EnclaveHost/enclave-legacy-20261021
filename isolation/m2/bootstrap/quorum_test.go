package bootstrap

// The reader's quorum under slow and lying peers (chain.go read/accept):
//   - a slow honest head is never excluded by a fast pair that cannot agree;
//   - two fast honest peers return without waiting for a hung third;
//   - one fast peer with a spoofed old head cannot pin the read to a stale block: later honest heads move it to a
//     strictly newer supported block, never below the accepted floor, and never to a single peer's answer;
//   - freshness is judged again when a pair is accepted, not only when each read began;
//   - every reader goroutine ends with the read.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// sim is one RPC over a modelled chain: block n has timestamp now-(head-n)*2s and a hash fixed by n, so honest peers
// agree; blocks above the peer's head do not exist.
type sim struct {
	head       uint64
	row        string
	schema     string
	headDelay  time.Duration
	hang       bool // the head never arrives
	hangBelow  uint64
	spoofFresh bool                          // a liar: any block it serves claims to be fresh
	after      func()                        // runs before the second block fetch of each read is answered
	now        func() int64                  // the shared clock
	base       int64                         // the chain's own time at head: a block's timestamp never changes
	hook       func(method string, n uint64) // runs before any block-scoped request is answered (ignores cancellation, like a slow server)
	hash       func(n uint64) string         // overrides the block hash encoding
	fetches    atomic.Int64
}

func (s *sim) call(ctx context.Context, method string, params any, out any) error {
	var result any
	switch method {
	case "eth_chainId":
		result = "0x2105"
	case "eth_blockNumber":
		if s.hang {
			<-ctx.Done()
			return ctx.Err()
		}
		select {
		case <-time.After(s.headDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
		result = fmt.Sprintf("0x%x", s.head)
	case "eth_getBlockByNumber":
		var n uint64
		fmt.Sscanf(params.([]any)[0].(string), "0x%x", &n)
		if n < s.hangBelow {
			<-ctx.Done()
			return ctx.Err()
		}
		if n > s.head {
			return errors.New("unknown block")
		}
		if s.hook != nil {
			s.hook(method, n)
		}
		if s.fetches.Add(1)%2 == 0 && s.after != nil {
			s.after()
		}
		ts := s.base - int64(s.head-n)*2
		if s.spoofFresh {
			ts = s.now()
		}
		h := fmt.Sprintf("0x%064x", n+1)
		if s.hash != nil {
			h = s.hash(n)
		}
		result = block{Number: fmt.Sprintf("0x%x", n), Hash: h, Timestamp: fmt.Sprintf("0x%x", ts)}
	case "eth_call":
		data := params.([]any)[0].(map[string]string)["data"]
		if s.hook != nil {
			var n uint64
			fmt.Sscanf(params.([]any)[1].(string), "0x%x", &n)
			s.hook(method+":"+data[:10], n)
		}
		if data == schemaSelector {
			result = s.schema
		} else {
			result = s.row
		}
	default:
		return errors.New("unexpected RPC method")
	}
	b, _ := json.Marshal(result)
	return json.Unmarshal(b, out)
}

type world struct {
	r     *Reader
	sims  []*sim
	id    [32]byte
	v     vectors
	clock *atomic.Int64
}

// newWorld: n honest peers at head 100 (block 98 after confirmations), on one clock.
func newWorld(t *testing.T, n int) *world {
	t.Helper()
	v := load(t)
	var id [32]byte
	b, _ := hex.DecodeString(v.ID[2:])
	copy(id[:], b)
	clock := new(atomic.Int64)
	clock.Store(v.Now)
	w := &world{id: id, v: v, clock: clock,
		r: &Reader{chainID: 8453, ledger: v.Ledger, confirmations: 2, maxAge: 120 * time.Second, now: func() time.Time { return time.Unix(clock.Load(), 0) }}}
	for i := 0; i < n; i++ {
		s := &sim{head: 100, row: v.Row, schema: v.Schema, now: clock.Load, base: v.Now}
		w.sims = append(w.sims, s)
		w.r.peers = append(w.r.peers, endpoint{name: fmt.Sprint("rpc", i), call: s.call})
	}
	return w
}

func TestLateHonestHeadIsNotExcludedByAFastLiar(t *testing.T) {
	w := newWorld(t, 3)
	w.sims[1].row = w.v.Variants["owner"] // fast liar: same block, other facts
	w.sims[2].headDelay = 600 * time.Millisecond
	start := time.Now()
	s, err := w.r.read(context.Background(), w.id)
	if err != nil {
		t.Fatalf("a slow honest head was excluded: %v", err)
	}
	if s.raw != strings.ToLower(w.v.Row) || s.number != 98 {
		t.Fatalf("accepted %d %.20s", s.number, s.raw)
	}
	if time.Since(start) < 500*time.Millisecond {
		t.Fatal("returned before the honest pair existed")
	}
}

func TestTwoEarlyHonestReturnWithoutAHungThird(t *testing.T) {
	w := newWorld(t, 3)
	w.sims[2].hang = true
	start := time.Now()
	if _, err := w.r.read(context.Background(), w.id); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("a hung peer held up an agreeing pair")
	}
}

func TestSpoofedOldHeadCannotHoldTheBlockDown(t *testing.T) {
	for _, hangs := range []bool{false, true} {
		t.Run(fmt.Sprint("liar-read-hangs=", hangs), func(t *testing.T) {
			w := newWorld(t, 3)
			liar := w.sims[1]
			liar.head, liar.spoofFresh = 5, true // a fast head naming an old block, served as if fresh
			if hangs {
				liar.hangBelow = 4 // and its read of that block never returns
			}
			w.sims[2].headDelay = 600 * time.Millisecond
			s, err := w.r.read(context.Background(), w.id)
			if err != nil {
				t.Fatalf("one bad fast head censored a late honest pair: %v", err)
			}
			if s.number != 98 {
				t.Fatalf("accepted block %d, not the honest pair's 98", s.number)
			}
		})
	}
}

func TestNeverBelowTheAcceptedFloorNorASingleAnswer(t *testing.T) {
	w := newWorld(t, 4)
	if s, err := w.r.read(context.Background(), w.id); err != nil || s.number != 98 {
		t.Fatalf("first read: %v", err)
	}
	// fresh peers on the SAME reader (its floor is 98): a lingering read of the last round must not see them change
	peers := func(cfg ...sim) {
		w.r.peers, w.sims = nil, nil
		for i := range cfg {
			s := &cfg[i]
			s.row, s.schema, s.now, s.base = w.v.Row, w.v.Schema, w.clock.Load, w.v.Now
			w.sims = append(w.sims, s)
			w.r.peers = append(w.r.peers, endpoint{name: fmt.Sprint("rpc", i), call: s.call})
		}
	}
	// two fast peers now support only block 97 (below the floor); one late peer alone names a newer block
	peers(sim{head: 99}, sim{head: 99}, sim{head: 102, headDelay: 300 * time.Millisecond}, sim{hang: true})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := w.r.read(ctx, w.id)
	if err == nil {
		t.Fatal("accepted a block below the floor or a single peer's newer block")
	}
	if w.r.highWater.Load() != 98 {
		t.Fatal("the floor moved")
	}
	// a second late peer supports the newer block: the read moves up to it
	peers(sim{head: 99}, sim{head: 99}, sim{head: 102, headDelay: 300 * time.Millisecond}, sim{head: 102, headDelay: 400 * time.Millisecond})
	s, err := w.r.read(context.Background(), w.id)
	if err != nil || s.number != 100 {
		t.Fatalf("a supported newer block was not selected: %d %v", s.number, err)
	}
	if w.r.highWater.Load() != 100 {
		t.Fatal("floor not advanced to the accepted block")
	}
}

func TestFreshnessIsJudgedAtAcceptance(t *testing.T) {
	w := newWorld(t, 2)
	// each read starts fresh, but the block is 200 s old by the time the pair agrees
	for _, s := range w.sims {
		s.after = func() { w.clock.Add(100) }
	}
	_, err := w.r.read(context.Background(), w.id)
	if err == nil || !strings.Contains(err.Error(), "at acceptance") {
		t.Fatalf("a pair that went stale while reading was accepted: %v", err)
	}
	if w.r.highWater.Load() != 0 {
		t.Fatal("a stale pair moved the floor")
	}
}

func TestReaderEndsEveryGoroutineAndKeepsItsDeadline(t *testing.T) {
	base := runtime.NumGoroutine()
	w := newWorld(t, 3)
	w.sims[2].hang = true
	if _, err := w.r.read(context.Background(), w.id); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(2 * time.Second); runtime.NumGoroutine() > base; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines outlive the read (base %d)", runtime.NumGoroutine(), base)
		}
	}
	// a caller's shorter deadline ends the read promptly; nothing waits past it
	w2 := newWorld(t, 3)
	for _, s := range w2.sims {
		s.hang = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := w2.r.read(ctx, w2.id); err == nil || !strings.Contains(err.Error(), "deadline") || time.Since(start) > time.Second {
		t.Fatalf("deadline: %v after %v", err, time.Since(start))
	}
}

func TestOneRPCHostCountsOnceHoweverItIsSpelled(t *testing.T) {
	v := load(t)
	cfg := func(rpcs ...string) Config {
		return Config{ChainID: 8453, Ledger: v.Ledger, RPCs: rpcs, Confirmations: 2, MaxAge: time.Minute}
	}
	for _, pair := range [][]string{
		{"https://RPC.example", "https://rpc.example."},
		{"https://rpc.example/a", "https://rpc.example:443/b"},
		{"https://Rpc.Example./v1", "https://rpc.example"},
		{"https://1.2.3.4", "https://[::ffff:1.2.3.4]"},
		{"https://[2001:db8::1]", "https://[2001:0db8:0:0:0:0:0:1]"},
	} {
		if _, err := NewReader(cfg(pair...)); err == nil {
			t.Fatalf("%v counted as two hosts", pair)
		}
	}
	for _, bad := range []string{"https://rpc..example", "https://-rpc.example", "https://rpc_1.example", "https://example", "https://rpc.123", "https://rpc.example.."} {
		if _, err := NewReader(cfg(bad, "https://other.example")); err == nil {
			t.Fatalf("malformed host %q accepted", bad)
		}
	}
	r, err := NewReader(cfg("https://RPC.Example.", "https://other.example", "https://[2001:db8::1]"))
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{r.peers[0].name, r.peers[1].name, r.peers[2].name}; got[0] != "rpc.example" || got[1] != "other.example" || got[2] != "2001:db8::1" {
		t.Fatalf("names are not canonical: %v", got)
	}
}

func TestBlockHashMustBe0xAnd32Bytes(t *testing.T) {
	for name, f := range map[string]func(uint64) string{
		"bare":  func(n uint64) string { return fmt.Sprintf("%064x", n+1) },
		"0X":    func(n uint64) string { return fmt.Sprintf("0X%064x", n+1) },
		"short": func(n uint64) string { return fmt.Sprintf("0x%062x", n+1) },
		"long":  func(n uint64) string { return fmt.Sprintf("0x%066x", n+1) },
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, 2)
			for _, s := range w.sims {
				s.hash = f
			}
			if _, err := w.r.read(context.Background(), w.id); err == nil || !strings.Contains(err.Error(), "invalid block hash") {
				t.Fatalf("a %s hash was accepted: %v", name, err)
			}
		})
	}
}

// Two colluding fast peers name an old block (3) and would agree there; two honest heads arrive and move the target
// to 98. The old round's reads are held at one request until the new round has begun:
//   - held in an EARLY request: cancellation of the superseded round stops every later request of those reads;
//   - held in the LAST request: the reads complete and agree, and the agreeing old pair is still refused.
//
// With the honest pair disagreeing nothing may be accepted; with it agreeing, only block 98.
func TestSupersededRoundNeverReturnsAndStopsItsRequests(t *testing.T) {
	for _, held := range []string{"eth_call:" + schemaSelector, "eth_getBlockByNumber"} {
		for _, honestAgree := range []bool{false, true} {
			t.Run(fmt.Sprintf("held=%s/honest-agree=%v", held[:8], honestAgree), func(t *testing.T) {
				w := newWorld(t, 4)
				gate := make(chan struct{})
				var released, late atomic.Bool
				var lateCalls atomic.Int64
				for _, l := range w.sims[:2] {
					fetchesAt3 := new(atomic.Int64) // this liar's own block-3 fetches
					l.head, l.spoofFresh, l.row = 5, true, w.v.Variants["owner"]
					l.hook = func(method string, n uint64) {
						if n != 3 {
							return
						}
						if late.Load() {
							lateCalls.Add(1)
						}
						hold := method == held
						if held == "eth_getBlockByNumber" {
							hold = method == held && fetchesAt3.Add(1) == 2 // this read's second (last) fetch
						}
						if hold {
							<-gate
							late.Store(true)
						}
					}
				}
				for i, h := range w.sims[2:] {
					h.headDelay = 50 * time.Millisecond
					if i == 1 && !honestAgree {
						h.row = w.v.Variants["appRef"]
					}
					h.hook = func(method string, n uint64) {
						if n == 98 && released.CompareAndSwap(false, true) {
							close(gate) // the newer round has begun
						}
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				s, err := w.r.read(ctx, w.id)
				if honestAgree {
					if err != nil || s.number != 98 {
						t.Fatalf("got block %d, %v; want the newer supported block 98", s.number, err)
					}
				} else if err == nil {
					t.Fatalf("an old round's agreeing pair returned block %d after a newer target was chosen", s.number)
				} else if !strings.Contains(err.Error(), "superseded block 3") {
					t.Fatalf("refusal does not say why: %v", err)
				}
				if held != "eth_getBlockByNumber" {
					time.Sleep(50 * time.Millisecond)
					if n := lateCalls.Load(); n != 0 {
						t.Fatalf("%d request(s) left for the superseded block after cancellation", n)
					}
				}
			})
		}
	}
}

func TestDeadlineStopsFurtherRequestsOfAnInFlightRead(t *testing.T) {
	w := newWorld(t, 2)
	var after atomic.Int64
	var expired atomic.Bool
	for _, s := range w.sims {
		s.hook = func(method string, n uint64) {
			if expired.Load() {
				after.Add(1)
			}
			if method == "eth_call:"+schemaSelector {
				time.Sleep(300 * time.Millisecond) // a slow server answers after the caller's deadline
				expired.Store(true)
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := w.r.read(ctx, w.id); err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("read outlived its deadline: %v", err)
	}
	time.Sleep(400 * time.Millisecond)
	if n := after.Load(); n != 0 {
		t.Fatalf("%d request(s) sent after the deadline", n)
	}
}
