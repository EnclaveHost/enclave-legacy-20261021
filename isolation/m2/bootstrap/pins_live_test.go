package bootstrap

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"os"
	"testing"
)

// Explicitly opt-in: exercises the pinned TLS roots, real public RPC quorum and
// production schema without sending a wallet transaction or changing a guest.
func TestLiveMeasuredRPCQuorum(t *testing.T) {
	raw := os.Getenv("BOOTSTRAP_LIVE_DEPLOYMENT")
	if raw == "" {
		t.Skip("read-only live network check not requested")
	}
	b, err := hex.DecodeString(raw)
	if err != nil || len(b) != 32 {
		t.Fatal("expected 32-byte deployment hex")
	}
	var id [32]byte
	copy(id[:], b)
	roots, err := MeasuredRoots()
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	base := MeasuredConfig(&http.Client{Transport: tr})
	for missing := -1; missing < len(base.RPCs); missing++ {
		c := base
		c.RPCs = nil
		for i, raw := range base.RPCs {
			if i != missing {
				c.RPCs = append(c.RPCs, raw)
			}
		}
		r, err := NewReader(c)
		if err != nil {
			t.Fatal(err)
		}
		s, err := r.read(context.Background(), id)
		if err != nil {
			t.Fatalf("without peer %d: %v", missing, err)
		}
		t.Logf("fresh pinned ledger quorum at block %d; omitted peer %d", s.number, missing)
	}
}
