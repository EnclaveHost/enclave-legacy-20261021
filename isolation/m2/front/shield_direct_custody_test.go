//go:build shielddirect && bootstrapdirect && !releaselab

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"enclave.host/isolation/contract"
	"enclave.host/isolation/m2/bootstrap"
	"enclave.host/isolation/m2/release"
)

// Real bootstrap authorization and real encrypted threshold partials; RPC and
// monitor signatures are fixtures. This tests composition, not hardware trust.
func TestShieldDirectCustodyStartsWithoutEnclaveRelease(t *testing.T) {
	for _, scenario := range []string{"independent-quorum", "measured-config-changed", "custody-config-changed", "owner-changed-during-egress", "wrong-monitor-tier", "missing-runtime-scan", "custodians-refuse"} {
		t.Run(scenario, func(t *testing.T) {
			w := newCustodyWorldV2(t, []bool{true, true, false, false, false}, v2Env)
			w.behave[0], w.behave[1] = v2Refuse, v2Refuse
			if scenario == "custodians-refuse" {
				w.behave[2], w.behave[3], w.behave[4] = v2Refuse, v2Refuse, v2Refuse
			}
			var v struct{ Row, Ledger, Owner, Schema string }
			b, err := os.ReadFile("../bootstrap/testdata/vectors.json")
			if err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(b, &v); err != nil {
				t.Fatal(err)
			}
			w.shieldOwner = v.Owner
			config, _ := json.Marshal(w.config)
			if scenario == "custody-config-changed" {
				config = []byte(`{"endpoint":"https://attacker.example"}`)
			}
			var ptr release.Custody
			b, _ = json.Marshal(w.custody)
			json.Unmarshal(b, &ptr)
			manifest := bootstrap.Manifest{Version: 1, ChainID: 8453, Ledger: v.Ledger, Deployment: "0x" + hex.EncodeToString(w.id[:]), Owner: v.Owner, AppRef: "catalog://explicit/1", AppID: hex.EncodeToString(w.appSha), RuntimeID: hex.EncodeToString(w.rt.RID[:]), ConfigText: string(config), SecretsMode: "custody-v2", Custody: &ptr}
			raw, _ := json.Marshal(manifest)
			row := directCustodyRow(t, v.Row, w.id, raw)
			var revoked atomic.Bool
			now := time.Now().Unix()
			hc := &http.Client{Transport: bootstrapTransport(func(req *http.Request) (*http.Response, error) {
				var q struct {
					Method string
					Params []json.RawMessage
				}
				json.NewDecoder(req.Body).Decode(&q)
				var result any
				switch q.Method {
				case "eth_chainId":
					result = "0x2105"
				case "eth_blockNumber":
					result = "0x64"
				case "eth_getBlockByNumber":
					var n string
					json.Unmarshal(q.Params[0], &n)
					result = map[string]string{"number": n, "hash": "0x" + strings.Repeat("ab", 32), "timestamp": fmt.Sprintf("0x%x", now)}
				case "eth_call":
					var call struct{ Data string }
					json.Unmarshal(q.Params[0], &call)
					result = row
					if revoked.Load() {
						bb, _ := hex.DecodeString(row[2:]) // change the ABI tuple's owner, retaining the exact old envelope
						bb[32+32+31] ^= 1
						result = "0x" + hex.EncodeToString(bb)
					}
					if call.Data == "0x5d1b72b6" {
						result = v.Schema
					}
				default:
					t.Errorf("unexpected RPC %s", q.Method)
				}
				out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(out))}, nil
			})}
			reader, err := bootstrap.NewReader(bootstrap.Config{ChainID: 8453, Ledger: v.Ledger, RPCs: []string{"https://one.example", "https://two.example", "https://three.example"}, Confirmations: 2, MaxAge: time.Minute, Client: hc})
			if err != nil {
				t.Fatal(err)
			}
			loaded := bootstrap.Identity{RuntimeID: w.rt.RID}
			copy(loaded.AppID[:], w.appSha)
			auth, err := reader.Authorize(context.Background(), w.id, raw, loaded)
			if err != nil {
				t.Fatal(err)
			}
			ew := newEgressWorld(t, string(config))
			ew.eg.deployment = filepath.Join(filepath.Dir(ew.eg.config), "secret.id")
			if err = os.WriteFile(ew.eg.deployment, []byte(manifest.Deployment), 0444); err != nil {
				t.Fatal(err)
			}
			if scenario == "measured-config-changed" {
				os.Chmod(ew.eg.config, 0600)
				os.WriteFile(ew.eg.config, []byte(`{"endpoint":"https://attacker.example"}`), 0444)
				os.Chmod(ew.eg.config, 0444)
			}
			originalAudit := ew.eg.audit
			audited := false
			ew.eg.audit = func(want []netip.AddrPort) error {
				audited = true
				if scenario == "owner-changed-during-egress" {
					revoked.Store(true)
				}
				return originalAudit(want)
			}
			sock := filepath.Join(t.TempDir(), "monitor.sock")
			ln, err := net.Listen("unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ln.Close() })
			go func() {
				for {
					c, e := ln.Accept()
					if e != nil {
						return
					}
					var q map[string]string
					json.NewDecoder(c).Decode(&q)
					input, _ := hex.DecodeString(q["bind"])
					rep := append(append([]byte{}, input...), w.appSha...)
					format := contract.FormatHyperV
					if scenario == "wrong-monitor-tier" {
						format = contract.FormatSNP
					}
					wx := "wx=clean maps=3 runtime=1 front=1 init=1 scope=cgroup:/dom1"
					if scenario == "missing-runtime-scan" {
						wx = ""
					}
					json.NewEncoder(c).Encode(map[string]string{"report": base64.StdEncoding.EncodeToString(rep), "tier": contract.TierHyperV, "format": format, "wx": wx})
					c.Close()
				}
			}()
			f := &front{spki: w.spki, appSha: w.appSha, rt: w.rt, monitor: sock}
			t.Cleanup(func() {
				if f.shieldFwd != nil {
					f.shieldFwd.Close()
				}
			})
			sink := &secretSink{onWrite: func() {
				if !audited {
					t.Error("runtime received secrets before egress audit")
				}
			}}
			_, err = f.prepareShieldDirect(context.Background(), auth, w.id, sink, ew.eg, w.p)
			if scenario != "independent-quorum" {
				if err == nil || sink.Len() != 0 || !sink.closed {
					t.Fatalf("unsafe startup: err=%v bytes=%d", err, sink.Len())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]string
			if err = json.Unmarshal(sink.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got["MCP_ADAPTER_API_KEY"] != v2Env["MCP_ADAPTER_API_KEY"] || !sink.closed || !audited {
				t.Fatal("secret runtime did not receive the authenticated bundle after egress setup")
			}
			if w.released[2].Load() != 1 || w.released[3].Load() != 1 || w.released[4].Load() != 1 {
				t.Fatal("independent quorum was not used")
			}
			if f.shieldFwd.Policy.Allows("api.enclave.host") {
				t.Fatal("relay origin was implicitly allowed")
			}
		})
	}
}

// Keep ABI offset assumptions used above explicit; a fixture layout change must
// fail rather than stop exercising an actual owner change.
func TestShieldOwnerFixtureWord(t *testing.T) {
	var v struct{ Row, Owner string }
	b, e := os.ReadFile("../bootstrap/testdata/vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	json.Unmarshal(b, &v)
	raw, e := hex.DecodeString(v.Row[2:])
	if e != nil {
		t.Fatal(e)
	}
	if binary.BigEndian.Uint64(raw[24:32]) != 32 || "0x"+hex.EncodeToString(raw[32+32+12:32+64]) != strings.ToLower(v.Owner) {
		t.Fatal("fixture owner word changed")
	}
}
