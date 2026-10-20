package bootstrap

import (
	"context"
	"testing"
	"time"
)

func TestIsolationRequireReadsTheAgreedEnvelope(t *testing.T) {
	r, _, v, id, loaded := rig(t)
	a, e := r.Authorize(context.Background(), id, []byte(v.Manifest), loaded)
	if e != nil {
		t.Fatal(e)
	}
	got, e := a.IsolationRequire()
	if e != nil || got != "" {
		t.Fatalf("the vector envelope names no backend: %q %v", got, e)
	}
	live := func(envelope string) *Authorization {
		return &Authorization{reader: r, valid: true, snapshot: snapshot{timestamp: uint64(v.Now), row: ledgerRow{envelope: envelope, leaseUntil: uint64(v.Now) + 3600}}}
	}
	for envelope, want := range map[string]string{
		`{"isolation":{"require":"hyperv-partition-per-app"},"guestBootstrap":{}}`: "hyperv-partition-per-app",
		`{"guestBootstrap":{}}`:                "",
		`{"isolation":{},"guestBootstrap":{}}`: "",
		`{"isolation":{"cpuTee":false},"x":1}`: "",
	} {
		if got, e := live(envelope).IsolationRequire(); e != nil || got != want {
			t.Fatalf("%s: %q %v", envelope, got, e)
		}
	}
	for _, bad := range []string{`{"isolation":{"require":5}}`, `{"isolation":"hyperv-partition-per-app"}`, `[]`, `x`} {
		if _, e := live(bad).IsolationRequire(); e == nil {
			t.Fatalf("%s was read as a backend", bad)
		}
	}
	expired := live(`{"isolation":{"require":"hyperv-partition-per-app"}}`)
	expired.snapshot.timestamp = uint64(v.Now) - uint64((r.maxAge + time.Second).Seconds())
	if _, e := expired.IsolationRequire(); e == nil {
		t.Fatal("a stale authorization stated a backend")
	}
	if _, e := (&Authorization{}).IsolationRequire(); e == nil {
		t.Fatal("an unverified authorization stated a backend")
	}
}
