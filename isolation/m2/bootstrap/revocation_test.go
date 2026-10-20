package bootstrap

// Revocation is a fact the quorum agrees on; an outage is the absence of agreement. The reader compares raw same-block
// facts across fresh peers BEFORE judging the lease (leaseCurrent), so:
//   - two honest fresh peers reporting a cancelled, released or ended lease revoke a running grant at once;
//   - one lying peer can neither revoke an honest pair's live lease nor keep alive what the pair reports ended;
//   - no agreement at all is an outage: the grant keeps its last bounded expiry;
//   - startup still waits (fail closed) for a just-claimed lease instead of failing on it.

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// patchWords returns row with head words (index -> 32-byte hex) replaced, the way the ledger's release() zeroes
// runner (14), runnerOperator (15) and leaseUntil (16) together.
func patchWords(t testing.TB, row string, words map[int]string) string {
	t.Helper()
	b := []byte(row)
	for i, w := range words {
		if len(w) != 64 {
			t.Fatal("word must be 32 bytes")
		}
		at := 2 + (32+i*32)*2
		copy(b[at:at+64], w)
	}
	return string(b)
}

func released(t testing.TB, row string) string {
	z := strings.Repeat("0", 64)
	return patchWords(t, row, map[int]string{14: z, 15: z, 16: z})
}

func TestDecodeAcceptsAReleasedRowAsAFact(t *testing.T) {
	v := load(t)
	var id [32]byte
	b, _ := hex.DecodeString(v.ID[2:])
	copy(id[:], b)
	row, err := decodeRow(released(t, v.Row), id)
	if err != nil {
		t.Fatalf("a released lease is the chain's answer, not malformed ABI: %v", err)
	}
	if !zero(row.runner[:]) || row.operator != "" || row.leaseUntil != 0 {
		t.Fatalf("decoded %+v", row)
	}
	r := &Reader{now: func() time.Time { return time.Unix(v.Now, 0) }}
	if err := r.leaseCurrent(snapshot{row: row, timestamp: uint64(v.Now)}); !errors.Is(err, errLeaseNotCurrent) {
		t.Fatal("a released lease judged current")
	}
	// a nonzero high byte in the operator word is still malformed
	bad := patchWords(t, v.Row, map[int]string{15: "01" + strings.Repeat("0", 62)})
	if _, err := decodeRow(bad, id); err == nil {
		t.Fatal("a malformed operator word decoded")
	}
}

func agreedEnd(t *testing.T, v vectors, name string) string {
	switch name {
	case "released":
		return released(t, v.Row)
	default:
		return v.Variants[name]
	}
}

func TestAgreedLeaseEndRevokesNamesImmediately(t *testing.T) {
	for _, end := range []string{"inactive", "expired", "released"} {
		for _, third := range []string{"agrees", "lies-active", "unavailable"} {
			t.Run(end+"/"+third, func(t *testing.T) {
				a, peers, v, _ := namedAuthorization(t)
				before, err := a.NameGrant()
				if err != nil || len(before.Hosts) == 0 {
					t.Fatal(err)
				}
				for i, p := range peers {
					switch {
					case i < 2 || third == "agrees":
						p.row.Store(agreedEnd(t, v, end))
					case third == "lies-active":
						// the liar keeps reporting the live, named lease
					case third == "unavailable":
						p.row.Store("0x") // answers, unusably: no fact to agree on
					}
				}
				err = a.Refresh(context.Background())
				if !errors.Is(err, ErrRevoked) {
					t.Fatalf("an agreed %s lease must revoke at once, got %v", end, err)
				}
				var pending *snapshotUnavailable
				if errors.As(err, &pending) {
					t.Fatal("revocation reported as an outage")
				}
				if _, err := a.NameGrant(); err == nil {
					t.Fatal("names survive an agreed lease end")
				}
				for _, p := range peers {
					p.row.Store(v.Row)
				}
				if err := a.Refresh(context.Background()); !errors.Is(err, ErrRevoked) {
					t.Fatal("a later live read restored a revoked grant")
				}
			})
		}
	}
}

func TestOneLiarCannotRevokeAnHonestPair(t *testing.T) {
	for _, lie := range []string{"inactive", "expired", "released", "owner", "runner"} {
		t.Run(lie, func(t *testing.T) {
			a, peers, v, _ := namedAuthorization(t)
			before, _ := a.NameGrant()
			peers[0].row.Store(agreedEnd(t, v, lie))
			if err := a.Refresh(context.Background()); err != nil {
				t.Fatalf("one peer reporting %s revoked the honest pair's live lease: %v", lie, err)
			}
			if g, err := a.NameGrant(); err != nil || len(g.Hosts) != len(before.Hosts) {
				t.Fatalf("names lost to a single liar: %+v %v", g, err)
			}
			// with only the liar and one honest peer answering there is no agreement: an outage, never a revocation
			peers[2].row.Store("0x")
			var pending *snapshotUnavailable
			if err := a.Refresh(context.Background()); !errors.As(err, &pending) || errors.Is(err, ErrRevoked) {
				t.Fatalf("a split pair must be an outage, got %v", err)
			}
			if g, err := a.NameGrant(); err != nil || len(g.Hosts) != len(before.Hosts) {
				t.Fatalf("an outage changed the grant: %+v %v", g, err)
			}
		})
	}
}

func TestUnavailableQuorumKeepsOnlyTheBoundedGrace(t *testing.T) {
	a, peers, v, clock := namedAuthorization(t)
	before, _ := a.NameGrant()
	for _, p := range peers {
		p.row.Store("0x") // a fixture's plain fail flag would race a lingering read; an unusable answer is an outage too
	}
	var pending *snapshotUnavailable
	if err := a.Refresh(context.Background()); !errors.As(err, &pending) || errors.Is(err, ErrRevoked) {
		t.Fatalf("an unavailable quorum is an outage, got %v", err)
	}
	if !before.Until.Equal(time.Unix(v.Now, 0).Add(NameGrace)) {
		t.Fatalf("grace is not bounded by the last agreed snapshot: %v", before.Until)
	}
	// the grant does not renew during the outage: once its snapshot is stale, no new grant is issued
	clock.Store(v.Now + int64(a.reader.maxAge/time.Second) + 1)
	if _, err := a.NameGrant(); err == nil {
		t.Fatal("an outage renewed the grant")
	}
}

func TestStartupStillWaitsForAJustClaimedLease(t *testing.T) {
	for _, end := range []string{"inactive", "expired", "released"} {
		t.Run(end, func(t *testing.T) {
			r, peers, v, id, loaded := rig(t)
			for _, p := range peers {
				p.row.Store(agreedEnd(t, v, end))
			}
			_, err := r.Authorize(context.Background(), id, []byte(v.Manifest), loaded)
			var pending *snapshotUnavailable
			if !errors.As(err, &pending) || !errors.Is(err, errLeaseNotCurrent) {
				t.Fatalf("startup must wait (retryable, fail closed) on an agreed %s lease, got %v", end, err)
			}
			if a, err := r.authorizeWhenConfirmed(context.Background(), id, []byte(v.Manifest), loaded, 50*time.Millisecond, time.Millisecond); err == nil || a != nil {
				t.Fatal("startup authorized a lease that is not current")
			}
		})
	}
}

func TestRevalidateRefusesAnAgreedReleasedLease(t *testing.T) {
	r, peers, v, id, loaded := rig(t)
	a, err := r.Authorize(context.Background(), id, []byte(v.Manifest), loaded)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range peers {
		p.row.Store(released(t, v.Row))
	}
	if err := a.Revalidate(context.Background()); err == nil {
		t.Fatal("app start allowed after the lease was released")
	}
	if _, err := a.ConfigText(); err == nil {
		t.Fatal("config usable after release")
	}
}
