package bootstrap

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type vectors struct {
	ID, Ledger, Owner, Manifest, CustodyManifest, AppID, RuntimeID, GetSelector, SchemaSelector, Schema, Row string
	Now                                                                                                      int64
	Variants                                                                                                 map[string]string
}

func load(t testing.TB) vectors {
	t.Helper()
	b, e := os.ReadFile("testdata/vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var v vectors
	if e = json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	return v
}

type peerFixture struct {
	row               atomic.Value
	schema, chain     string
	head, ts          uint64
	fail, hang, reorg bool
	blocks            atomic.Int64
}

func (p *peerFixture) call(ctx context.Context, method string, params any, out any) error {
	if p.hang {
		<-ctx.Done()
		return ctx.Err()
	}
	if p.fail {
		return errors.New("unavailable")
	}
	var result any
	switch method {
	case "eth_chainId":
		result = p.chain
	case "eth_blockNumber":
		result = fmt.Sprintf("0x%x", p.head)
	case "eth_getBlockByNumber":
		tag := params.([]any)[0].(string)
		h := strings.Repeat("ab", 32)
		if p.reorg && p.blocks.Add(1)%2 == 0 {
			h = strings.Repeat("cd", 32)
		}
		result = block{Number: tag, Hash: "0x" + h, Timestamp: fmt.Sprintf("0x%x", p.ts)}
	case "eth_call":
		data := params.([]any)[0].(map[string]string)["data"]
		if data == schemaSelector {
			result = p.schema
		} else if strings.HasPrefix(data, getSelector) {
			result = p.row.Load().(string)
		} else {
			return errors.New("unexpected selector")
		}
	default:
		return errors.New("unexpected RPC method")
	}
	b, _ := json.Marshal(result)
	return json.Unmarshal(b, out)
}
func rig(t testing.TB) (*Reader, []*peerFixture, vectors, [32]byte, Identity) {
	t.Helper()
	v := load(t)
	var id [32]byte
	ib, _ := hex.DecodeString(v.ID[2:])
	copy(id[:], ib)
	var loaded Identity
	b, _ := hex.DecodeString(v.AppID)
	copy(loaded.AppID[:], b)
	b, _ = hex.DecodeString(v.RuntimeID)
	copy(loaded.RuntimeID[:], b)
	r := &Reader{chainID: 8453, ledger: v.Ledger, confirmations: 2, maxAge: 120 * time.Second, now: func() time.Time { return time.Unix(v.Now, 0) }}
	var peers []*peerFixture
	for i := 0; i < 3; i++ {
		p := &peerFixture{schema: v.Schema, chain: "0x2105", head: 100, ts: uint64(v.Now)}
		p.row.Store(v.Row)
		peers = append(peers, p)
		r.peers = append(r.peers, endpoint{name: fmt.Sprint(i), call: p.call})
	}
	return r, peers, v, id, loaded
}
func TestOwnerCommitmentWithoutReleaseService(t *testing.T) {
	r, _, v, id, loaded := rig(t)
	a, e := r.Authorize(context.Background(), id, []byte(v.Manifest), loaded)
	if e != nil {
		t.Fatal(e)
	}
	c, e := a.ConfigText()
	if e != nil || c != "{ \"endpoint\": \"https://independent.example\" }" {
		t.Fatalf("exact config lost: %q %v", c, e)
	}
	if mode, _ := a.SecretsMode(); mode != "public" {
		t.Fatal(mode)
	}
	if e = a.Revalidate(context.Background()); e != nil {
		t.Fatal(e)
	}
	if getSelector != v.GetSelector || schemaSelector != v.SchemaSelector {
		t.Fatal("ABI selector drift")
	}
}
func TestNoQuorumOrHostPackageFallback(t *testing.T) {
	cases := []string{"one missing", "one hangs", "one disagrees", "two missing", "two stale", "two future", "two wrong chain", "two wrong schema", "two reorg"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			r, p, v, id, loaded := rig(t)
			switch name {
			case "one missing":
				p[0].fail = true
			case "one hangs":
				p[0].hang = true
			case "one disagrees":
				p[0].row.Store(v.Variants["owner"])
			case "two missing":
				p[0].fail = true
				p[1].fail = true
			case "two stale":
				p[0].ts -= 121
				p[1].ts -= 121
			case "two future":
				p[0].ts += 60
				p[1].ts += 60
			case "two wrong chain":
				p[0].chain = "0x1"
				p[1].chain = "0x1"
			case "two wrong schema":
				p[0].schema = "0x" + strings.Repeat("00", 31) + "11"
				p[1].schema = p[0].schema
			case "two reorg":
				p[0].reorg = true
				p[1].reorg = true
			}
			start := time.Now()
			_, e := r.Authorize(context.Background(), id, []byte(v.Manifest), loaded)
			if strings.HasPrefix(name, "one ") {
				if e != nil {
					t.Fatal(e)
				}
				if time.Since(start) > 2*time.Second {
					t.Fatal("one RPC blocked a healthy quorum")
				}
			} else if e == nil {
				t.Fatal("accepted without a fresh quorum")
			}
		})
	}
}
func TestWrongOwnerAppInactiveExpiredAndNoOptIn(t *testing.T) {
	for _, variant := range []string{"owner", "appRef", "inactive", "expired", "noCommitment", "duplicate", "mixedConfig", "mixedConfigCid"} {
		t.Run(variant, func(t *testing.T) {
			r, p, v, id, loaded := rig(t)
			for _, q := range p {
				q.row.Store(v.Variants[variant])
			}
			if _, e := r.Authorize(context.Background(), id, []byte(v.Manifest), loaded); e == nil {
				t.Fatal("accepted " + variant)
			}
		})
	}
}
func TestPackageSubstitutionAndScope(t *testing.T) {
	for _, name := range []string{"config", "runtime", "app", "deployment", "ledger", "chain", "mode", "downgrade", "unknown", "duplicate", "trailing", "large"} {
		t.Run(name, func(t *testing.T) {
			r, _, v, id, loaded := rig(t)
			var m map[string]any
			json.Unmarshal([]byte(v.Manifest), &m)
			switch name {
			case "config":
				m["configText"] = `{"endpoint":"https://attacker.example"}`
			case "runtime":
				m["runtimeId"] = strings.Repeat("aa", 32)
			case "app":
				m["appId"] = strings.Repeat("aa", 32)
			case "deployment":
				m["deployment"] = "0x" + strings.Repeat("aa", 32)
			case "ledger":
				m["ledger"] = "0x" + strings.Repeat("aa", 20)
			case "chain":
				m["chainId"] = 1
			case "mode":
				m["secretsMode"] = ""
			case "downgrade":
				m["secretsMode"] = "custody-v2"
			case "unknown":
				m["secrets"] = map[string]string{"key": "host injection"}
			}
			raw, _ := json.Marshal(m)
			switch name {
			case "duplicate":
				raw = []byte(strings.Replace(v.Manifest, `"version":1`, `"version":2,"version":1`, 1))
			case "trailing":
				raw = append([]byte(v.Manifest), []byte("{}")...)
			case "large":
				raw = make([]byte, MaxManifestBytes+1)
			}
			if _, e := r.Authorize(context.Background(), id, raw, loaded); e == nil {
				t.Fatal("accepted " + name)
			}
		})
	}
}
func TestRevalidationRevokesPreviouslyValidAuthorization(t *testing.T) {
	for _, variant := range []string{"owner", "runner", "operator", "appRef", "noCommitment", "inactive", "expired", "renewed", "quorum loss"} {
		t.Run(variant, func(t *testing.T) {
			r, p, v, id, loaded := rig(t)
			a, e := r.Authorize(context.Background(), id, []byte(v.Manifest), loaded)
			if e != nil {
				t.Fatal(e)
			}
			for _, q := range p {
				if variant == "quorum loss" {
					q.row.Store("0x")
				} else {
					q.row.Store(v.Variants[variant])
				}
			}
			e = a.Revalidate(context.Background())
			if variant == "renewed" {
				if e != nil {
					t.Fatal(e)
				}
				return
			}
			if e == nil {
				t.Fatal("authorization survived " + variant)
			}
			if _, e = a.ConfigText(); e == nil {
				t.Fatal("invalidated config still usable")
			}
		})
	}
}
func TestCustodyPointerCannotBeDowngradedOrMutated(t *testing.T) {
	r, p, v, id, loaded := rig(t)
	for _, q := range p {
		q.row.Store(v.Variants["custody"])
	}
	a, e := r.Authorize(context.Background(), id, []byte(v.CustodyManifest), loaded)
	if e != nil {
		t.Fatal(e)
	}
	ptr, e := a.Custody()
	if e != nil {
		t.Fatal(e)
	}
	ptr.Machines[0].EncKey = "tampered"
	again, _ := a.Custody()
	if again.Machines[0].EncKey == "tampered" {
		t.Fatal("authorization mutated externally")
	}
	if _, e = r.Authorize(context.Background(), id, []byte(v.Manifest), loaded); e == nil {
		t.Fatal("public downgrade accepted")
	}
}
func TestExpiredAndForgedAuthorizationCannotYieldConfig(t *testing.T) {
	if _, e := new(Authorization).ConfigText(); e == nil {
		t.Fatal("forged auth accepted")
	}
	r, _, v, id, loaded := rig(t)
	var clock atomic.Int64
	clock.Store(v.Now)
	r.now = func() time.Time { return time.Unix(clock.Load(), 0) }
	a, e := r.Authorize(context.Background(), id, []byte(v.Manifest), loaded)
	if e != nil {
		t.Fatal(e)
	}
	clock.Store(v.Now + 121)
	if _, e = a.ConfigText(); e == nil {
		t.Fatal("stale auth accepted")
	}
}
func TestMeasuredRPCPolicy(t *testing.T) {
	for _, urls := range [][]string{{"http://one.example", "https://two.example"}, {"https://one.example", "https://one.example/path"}, {"https://user@one.example", "https://two.example"}, {"https://one.example:444", "https://two.example"}} {
		if _, e := NewReader(Config{ChainID: 8453, Ledger: "0x" + strings.Repeat("22", 20), RPCs: urls, Confirmations: 2, MaxAge: time.Minute}); e == nil {
			t.Fatal("untrusted RPC policy accepted")
		}
	}
}
func FuzzLedgerABI(f *testing.F) {
	v := load(f)
	f.Add(v.Row)
	f.Add("0x")
	f.Fuzz(func(t *testing.T, s string) {
		var id [32]byte
		ib, _ := hex.DecodeString(v.ID[2:])
		copy(id[:], ib)
		decodeRow(s, id)
	})
}

func TestReaderNeverAcceptsEarlierStateAfterSuccessfulAuthorization(t *testing.T) {
	r, p, v, id, loaded := rig(t)
	if _, e := r.Authorize(context.Background(), id, []byte(v.Manifest), loaded); e != nil {
		t.Fatal(e)
	}
	for _, q := range p {
		q.head = 99
	}
	if _, e := r.Authorize(context.Background(), id, []byte(v.Manifest), loaded); e == nil {
		t.Fatal("rollback accepted for a new authorization")
	}
}

func TestStrictOwnerJSONRejectsCaseAliases(t *testing.T) {
	for _, raw := range []string{`{"Version":1}`, `{"version":2,"Version":1}`, `{"custody":{"V":2}}`} {
		var m Manifest
		if e := strictJSON([]byte(raw), &m); e == nil {
			t.Fatal("case alias accepted", raw)
		}
	}
}
