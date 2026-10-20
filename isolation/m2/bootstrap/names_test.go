package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type namesVectors struct {
	Cases []struct {
		Name, Manifest string
		Valid          bool
	}
	Aliases []struct{ Deployment, Owner, Zone, Label, Alias string }
}

func loadNames(t testing.TB) namesVectors {
	t.Helper()
	b, e := os.ReadFile("testdata/names-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var v namesVectors
	if e = json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	return v
}

// commit rewrites the row's envelope commitment (ASCII hex inside the ABI
// string, same length) to the hash of raw, so a refusal is the names check's
// and never a hash mismatch.
func commit(t testing.TB, row, oldManifest, raw string) string {
	t.Helper()
	o, n := sha256.Sum256([]byte(oldManifest)), sha256.Sum256([]byte(raw))
	from, to := hex.EncodeToString([]byte(hex.EncodeToString(o[:]))), hex.EncodeToString([]byte(hex.EncodeToString(n[:])))
	if !strings.Contains(row, from) {
		t.Fatal("row does not commit to the base manifest")
	}
	return strings.Replace(row, from, to, 1)
}

func TestOwnerNamesAgreeWithJavaScriptVectors(t *testing.T) {
	nv := loadNames(t)
	if len(nv.Cases) < 30 {
		t.Fatalf("only %d name vectors", len(nv.Cases))
	}
	for _, c := range nv.Cases {
		t.Run(c.Name, func(t *testing.T) {
			r, peers, v, id, loaded := rig(t)
			base, row := v.Manifest, v.Row
			if strings.Contains(c.Manifest, `"custody-v2"`) {
				base, row = v.CustodyManifest, v.Variants["custody"]
			}
			for _, p := range peers {
				p.row.Store(commit(t, row, base, c.Manifest))
			}
			a, e := r.Authorize(context.Background(), id, []byte(c.Manifest), loaded)
			if c.Valid != (e == nil) {
				t.Fatalf("valid=%v but Authorize: %v", c.Valid, e)
			}
			if !c.Valid {
				return
			}
			g, e := a.NameGrant()
			if e != nil || len(g.Hosts) == 0 || g.Owner != strings.ToLower(v.Owner) || g.Deployment != id {
				t.Fatalf("grant %+v %v", g, e)
			}
			lease := time.Unix(int64(a.snapshot.row.leaseUntil), 0)
			if g.Until.After(lease) || g.Until.After(time.Unix(v.Now, 0).Add(NameGrace)) {
				t.Fatalf("names outlive the lease or the grace: %v", g.Until)
			}
		})
	}
}

func TestChallengeAliasAgreesWithJavaScript(t *testing.T) {
	for _, a := range loadNames(t).Aliases {
		var id [32]byte
		b, _ := hex.DecodeString(a.Deployment[2:])
		copy(id[:], b)
		l, e := ChallengeLabel(id, a.Owner)
		alias, e2 := ChallengeAlias(id, a.Owner, a.Zone)
		if e != nil || e2 != nil || l != a.Label || alias != a.Alias {
			t.Fatalf("%s: got %s %s (%v %v), want %s %s", a.Owner, l, alias, e, e2, a.Label, a.Alias)
		}
	}
	var id [32]byte
	id[0] = 1
	for _, owner := range []string{"", "0x", "0x" + strings.Repeat("00", 20), strings.Repeat("ab", 20), "0x" + strings.Repeat("ab", 21)} {
		if _, e := ChallengeLabel(id, owner); e == nil {
			t.Fatalf("label for owner %q", owner)
		}
	}
	if _, e := ChallengeLabel([32]byte{}, "0x"+strings.Repeat("ab", 20)); e == nil {
		t.Fatal("label for the zero deployment")
	}
}

// Exact v1 bytes written before names existed keep their hash and meaning.
func TestLegacyPackageHasNoNames(t *testing.T) {
	r, _, v, id, loaded := rig(t)
	a, e := r.Authorize(context.Background(), id, []byte(v.Manifest), loaded)
	if e != nil {
		t.Fatal(e)
	}
	g, e := a.NameGrant()
	if e != nil || len(g.Hosts) != 0 || g.ACME != nil {
		t.Fatalf("a legacy package grew names: %+v %v", g, e)
	}
}

func namedAuthorization(t *testing.T) (*Authorization, []*peerFixture, vectors, *atomic.Int64) {
	t.Helper()
	r, peers, v, id, loaded := rig(t)
	clock := new(atomic.Int64) // a lingering third-peer read may consult the clock while a test moves it
	clock.Store(v.Now)
	r.now = func() time.Time { return time.Unix(clock.Load(), 0) }
	raw := v.Manifest[:len(v.Manifest)-1] + `,"names":{"hosts":["shop.example.com"]}}`
	for _, p := range peers {
		p.row.Store(commit(t, v.Row, v.Manifest, raw))
	}
	a, e := r.Authorize(context.Background(), id, []byte(raw), loaded)
	if e != nil {
		t.Fatal(e)
	}
	return a, peers, v, clock
}

func TestNameRefreshSurvivesOutageButNotOwnerChange(t *testing.T) {
	a, peers, v, _ := namedAuthorization(t)
	before, _ := a.NameGrant()
	for _, p := range peers {
		p.row.Store("0x") // every peer answers, none usably: an outage, not a change
	}
	var pending *snapshotUnavailable
	if e := a.Refresh(context.Background()); !errors.As(e, &pending) {
		t.Fatalf("an RPC outage must be transient, got %v", e)
	}
	if g, e := a.NameGrant(); e != nil || g.Until != before.Until {
		t.Fatalf("an outage changed the grant: %+v %v", g, e)
	}
	named := commit(t, v.Row, v.Manifest, v.Manifest[:len(v.Manifest)-1]+`,"names":{"hosts":["shop.example.com"]}}`)
	for _, p := range peers {
		p.row.Store(named)
	}
	if e := a.Refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	owner := commit(t, v.Variants["owner"], v.Manifest, v.Manifest[:len(v.Manifest)-1]+`,"names":{"hosts":["shop.example.com"]}}`)
	for _, p := range peers {
		p.row.Store(owner)
	}
	if e := a.Refresh(context.Background()); !errors.Is(e, ErrRevoked) {
		t.Fatalf("owner change must revoke, got %v", e)
	}
	if _, e := a.NameGrant(); e == nil {
		t.Fatal("revoked names are still granted")
	}
	for _, p := range peers {
		p.row.Store(v.Row)
	}
	if e := a.Refresh(context.Background()); !errors.Is(e, ErrRevoked) {
		t.Fatal("revocation is not permanent")
	}
}

func TestNameRefreshRevokesRunnerAndEnvelopeChanges(t *testing.T) {
	for _, variant := range []string{"runner", "operator", "appRef", "custody"} {
		t.Run(variant, func(t *testing.T) {
			a, peers, v, _ := namedAuthorization(t)
			for _, p := range peers {
				p.row.Store(v.Variants[variant])
			}
			if e := a.Refresh(context.Background()); !errors.Is(e, ErrRevoked) {
				t.Fatalf("%s change must revoke, got %v", variant, e)
			}
		})
	}
}

func TestNamesExpireWithTheirSnapshot(t *testing.T) {
	a, _, v, clock := namedAuthorization(t)
	g, _ := a.NameGrant()
	if !g.Until.Equal(time.Unix(v.Now, 0).Add(NameGrace)) {
		t.Fatalf("grant ends at %v", g.Until)
	}
	clock.Store(v.Now + 180)
	if _, e := a.NameGrant(); e == nil {
		t.Fatal("a stale snapshot still grants names")
	}
}
