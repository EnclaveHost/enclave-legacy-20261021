package main

import (
	"context"
	"crypto/sha256"
	"enclave.host/isolation/m2/bootstrap"
	"enclave.host/isolation/m2/release"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type bootstrapTransport func(*http.Request) (*http.Response, error)

func (f bootstrapTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDirectFrontUsesOwnerCommitmentWithoutTicketOrRelayOrigin(t *testing.T) {
	for _, mode := range []string{"public", "revoked-before-start", "custody-unavailable", "tampered", "unmeasured-app"} {
		t.Run(mode, func(t *testing.T) {
			var v struct {
				ID, Ledger, Manifest, CustodyManifest, AppID, RuntimeID, Row, Schema string
				Variants                                                             map[string]string
			}
			b, e := os.ReadFile("../bootstrap/testdata/vectors.json")
			if e != nil {
				t.Fatal(e)
			}
			if e = json.Unmarshal(b, &v); e != nil {
				t.Fatal(e)
			}
			now := uint64(time.Now().Unix())
			extend := func(raw string) string {
				b, e := hex.DecodeString(raw[2:])
				if e != nil {
					t.Fatal(e)
				}
				binary.BigEndian.PutUint64(b[32+16*32+24:32+17*32], now+3600)
				return "0x" + hex.EncodeToString(b)
			}
			var gets sync.Map
			client := &http.Client{Transport: bootstrapTransport(func(req *http.Request) (*http.Response, error) {
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
					var call struct {
						Data string `json:"data"`
					}
					json.Unmarshal(msg.Params[0], &call)
					if call.Data == "0x5d1b72b6" {
						result = v.Schema
					} else {
						n, _ := gets.LoadOrStore(req.URL.Hostname(), new(atomic.Int64))
						count := n.(*atomic.Int64).Add(1)
						raw := v.Row
						if mode == "custody-unavailable" {
							raw = v.Variants["custody"]
						}
						if mode == "revoked-before-start" && count > 1 {
							raw = v.Variants["owner"]
						}
						result = extend(raw)
					}
				default:
					return nil, errors.New("unexpected request")
				}
				out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(out))), Header: make(http.Header)}, nil
			})}
			reader, e := bootstrap.NewReader(bootstrap.Config{ChainID: 8453, Ledger: v.Ledger, RPCs: []string{"https://one.example", "https://two.example", "https://three.example"}, Confirmations: 2, MaxAge: time.Minute, Client: client})
			if e != nil {
				t.Fatal(e)
			}
			var tickets atomic.Int64
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			listener.Close()
			p := &provisioner{appFromCode: mode != "unmeasured-app", etc: t.TempDir(), fwdPort: port, logf: t.Logf,
				ticket: func() (net.Conn, error) { tickets.Add(1); return nil, errors.New("Enclave refuses release") },
				egress: func() (net.Conn, error) { return nil, errors.New("no application egress during preparation") },
				audit: func(want []netip.AddrPort) error {
					if len(want) != 1 {
						return errors.New("unexpected listener set")
					}
					return nil
				}}
			hd, _ := hex.DecodeString(v.ID[2:])
			app, _ := hex.DecodeString(v.AppID)
			rid, _ := hex.DecodeString(v.RuntimeID)
			rt := &runtimeState{}
			copy(rt.RID[:], rid)
			raw := []byte(v.Manifest)
			if mode == "custody-unavailable" {
				raw = []byte(v.CustodyManifest)
			}
			if mode == "tampered" {
				raw = []byte(strings.Replace(v.Manifest, "independent.example", "attacker.example", 1))
			}
			got, e := p.runDirect(context.Background(), reader, raw, hd, nil, rt, app)
			if tickets.Load() != 0 {
				t.Fatal("direct mode contacted release ticket service")
			}
			if mode != "public" {
				if e == nil {
					got.fwd.Close()
					t.Fatal("unsafe startup accepted")
				}
				if _, e := os.Stat(filepath.Join(p.etc, "hosts")); !os.IsNotExist(e) {
					t.Fatal("failed startup installed resolver")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer got.fwd.Close()
			if !got.fwd.Policy.Allows("independent.example") || got.fwd.Policy.Allows("api.enclave.host") {
				t.Fatal("owner egress was replaced by platform policy")
			}
			hosts, e := os.ReadFile(filepath.Join(p.etc, "hosts"))
			if e != nil || strings.Contains(string(hosts), "enclave.host") {
				t.Fatal("unexpected platform resolver entry", e)
			}
			if !strings.Contains(got.config, "independent.example") {
				t.Fatal("owner config missing")
			}
		})
	}
}

// Encode a synthetic ledger response around the existing viem-generated tuple.
// Only dynamic string tails, the test deployment ID and lease time change.
func directCustodyRow(t *testing.T, base string, id [32]byte, raw []byte) string {
	t.Helper()
	b, e := hex.DecodeString(base[2:])
	if e != nil {
		t.Fatal(e)
	}
	head := append([]byte(nil), b[32:32+17*32]...)
	copy(head[:32], id[:])
	binary.BigEndian.PutUint64(head[16*32+24:17*32], uint64(time.Now().Unix()+3600))
	sum := sha256.Sum256(raw)
	envelope, _ := json.Marshal(map[string]any{"guestBootstrap": map[string]any{"version": 1, "sha256": hex.EncodeToString(sum[:])}})
	var tail []byte
	for _, i := range []int{2, 3, 4} {
		off := int(binary.BigEndian.Uint64(b[32+i*32+24 : 32+(i+1)*32]))
		n := int(binary.BigEndian.Uint64(b[32+off+24 : 32+off+32]))
		value := b[32+off+32 : 32+off+32+n]
		if i == 4 {
			value = envelope
		}
		binary.BigEndian.PutUint64(head[i*32+24:(i+1)*32], uint64(len(head)+len(tail)))
		length := make([]byte, 32)
		binary.BigEndian.PutUint64(length[24:], uint64(len(value)))
		tail = append(tail, length...)
		tail = append(tail, value...)
		tail = append(tail, make([]byte, (32-len(value)%32)%32)...)
	}
	out := append(append(append([]byte(nil), b[:32]...), head...), tail...)
	return "0x" + hex.EncodeToString(out)
}

func TestDirectFrontIndependentCustodySurvivesEnclaveReleaseAndShareRefusal(t *testing.T) {
	for _, badConfig := range []bool{false, true} {
		t.Run(fmt.Sprint("changed-config=", badConfig), func(t *testing.T) {
			w := newCustodyWorldV2(t, []bool{true, true, false, false, false}, v2Env)
			w.behave[0], w.behave[1] = v2Refuse, v2Refuse
			var tickets atomic.Int64
			w.p.keys = nil
			w.p.ticket = func() (net.Conn, error) { tickets.Add(1); return nil, errors.New("Enclave release service refuses") }
			var v struct{ Row, Ledger, Owner, Schema string }
			b, e := os.ReadFile("../bootstrap/testdata/vectors.json")
			if e != nil {
				t.Fatal(e)
			}
			json.Unmarshal(b, &v)
			ptrBytes, _ := json.Marshal(w.custody)
			var ptr release.Custody
			json.Unmarshal(ptrBytes, &ptr)
			config, _ := json.Marshal(w.config)
			if badConfig {
				config = []byte(`{"http":"https://attacker.example"}`)
			}
			m := bootstrap.Manifest{Version: 1, ChainID: 8453, Ledger: v.Ledger, Deployment: "0x" + hex.EncodeToString(w.id[:]), Owner: v.Owner, AppRef: "catalog://explicit/1", AppID: hex.EncodeToString(w.appSha), RuntimeID: hex.EncodeToString(w.rt.RID[:]), ConfigText: string(config), SecretsMode: "custody-v2", Custody: &ptr}
			raw, _ := json.Marshal(m)
			row := directCustodyRow(t, v.Row, w.id, raw)
			now := time.Now().Unix()
			client := &http.Client{Transport: bootstrapTransport(func(req *http.Request) (*http.Response, error) {
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
					var call struct {
						Data string `json:"data"`
					}
					json.Unmarshal(msg.Params[0], &call)
					result = row
					if call.Data == "0x5d1b72b6" {
						result = v.Schema
					}
				default:
					return nil, errors.New("unexpected RPC")
				}
				out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(out))), Header: make(http.Header)}, nil
			})}
			reader, e := bootstrap.NewReader(bootstrap.Config{ChainID: 8453, Ledger: v.Ledger, RPCs: []string{"https://one.example", "https://two.example", "https://three.example"}, Confirmations: 2, MaxAge: time.Minute, Client: client})
			if e != nil {
				t.Fatal(e)
			}
			got, e := w.p.runDirect(context.Background(), reader, raw, w.id[:], w.spki, w.rt, w.appSha)
			if tickets.Load() != 0 {
				t.Fatal("release signer was contacted")
			}
			if badConfig {
				if e == nil {
					got.fwd.Close()
					t.Fatal("custody secrets substituted into changed config")
				}
				if !strings.Contains(e.Error(), "not the one the owner committed") {
					t.Fatal(e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer got.fwd.Close()
			if got.config != v2Config {
				t.Fatal("wrong resolved configuration")
			}
			if fmt.Sprint(w.combined(t)) != "[2 3 4]" {
				t.Fatal("did not use independent quorum")
			}
			if got.fwd.Policy.Allows("api.enclave.host") {
				t.Fatal("release relay was implicitly added to egress")
			}
		})
	}
}
