package bootstrap

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestConfirmedStartupWaitsForNewLeaseWithoutWeakeningChecks(t *testing.T) {
	r, _, v, id, loaded := rig(t)
	for i := range r.peers {
		original := r.peers[i].call
		var reads atomic.Int64
		r.peers[i].call = func(ctx context.Context, method string, params any, out any) error {
			if method == "eth_call" && strings.HasPrefix(params.([]any)[0].(map[string]string)["data"], getSelector) && reads.Add(1) == 1 {
				*out.(*string) = v.Variants["inactive"]
				return nil
			}
			return original(ctx, method, params, out)
		}
	}
	a, err := r.authorizeWhenConfirmed(context.Background(), id, []byte(v.Manifest), loaded, time.Second, time.Millisecond)
	if err != nil || a == nil {
		t.Fatalf("confirmed claim did not recover: %v", err)
	}
	if err := a.Revalidate(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestConfirmedStartupNeverAcceptsUnavailableOrUnsafeState(t *testing.T) {
	for _, mode := range []string{"inactive", "expired", "stale", "no quorum", "owner", "noCommitment", "tampered"} {
		t.Run(mode, func(t *testing.T) {
			r, peers, v, id, loaded := rig(t)
			raw := []byte(v.Manifest)
			for _, p := range peers {
				switch mode {
				case "stale":
					p.ts -= 121
				case "no quorum":
					p.fail = true
				case "tampered":
					raw = []byte(strings.Replace(v.Manifest, "independent.example", "attacker.example", 1))
				default:
					p.row.Store(v.Variants[mode])
				}
			}
			start := time.Now()
			a, err := r.authorizeWhenConfirmed(context.Background(), id, raw, loaded, 60*time.Millisecond, time.Millisecond)
			if err == nil || a != nil {
				t.Fatal("unsafe startup authorized")
			}
			if time.Since(start) > time.Second {
				t.Fatal("startup deadline not bounded")
			}
			retry := mode == "inactive" || mode == "expired" || mode == "stale" || mode == "no quorum"
			if errors.Is(err, context.DeadlineExceeded) != retry {
				t.Fatalf("wrong retry classification: %v", err)
			}
		})
	}
}

func TestConfirmedStartupCancellationStopsHungPeers(t *testing.T) {
	r, peers, v, id, loaded := rig(t)
	for _, p := range peers {
		p.hang = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	a, err := r.AuthorizeWhenConfirmed(ctx, id, []byte(v.Manifest), loaded)
	if a != nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("caller cancellation not respected: %v", err)
	}
}
