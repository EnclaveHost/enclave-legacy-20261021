package egress

import (
	"context"
	"io"
	"net"
	"testing"
)

// The host's blob cache (docs/design/shield-blob-cache.md): blobs.enclave.internal:80 goes to Dialer.BlobService on
// loopback, never through the app's route, under the same per-guest caps; with no service it is refused like any name.
func TestBlobHostDialsTheLoopbackService(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			io.WriteString(c, "blob-service\n")
			c.Close()
		}
	}()
	d := &Dialer{MaxConcurrent: 1, MaxPerMinute: 10, BlobService: l.Addr().String(),
		RouteFor: func(uint32) (AppRoute, error) { t.Fatal("the blob name must not use the app's route"); return AppRoute{}, nil }}
	c, release, err := d.DialWeb(context.Background(), 7, "BLOBS.enclave.internal", 80)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	b, _ := io.ReadAll(c)
	if string(b) != "blob-service\n" {
		t.Fatalf("reached %q, not the blob service", b)
	}
	// the per-guest cap still applies while that connection is held
	if _, _, err := d.DialWeb(context.Background(), 7, BlobHost, 80); ReasonOf(err) != ReasonRate && ReasonOf(err) != ReasonConcurrency {
		if err == nil {
			t.Fatal("a second concurrent blob connection got past MaxConcurrent 1")
		}
	}
	c.Close()
	release()

	// any other port or name keeps its normal path (here: the route, which refuses)
	d2 := &Dialer{MaxConcurrent: 4, MaxPerMinute: 10, BlobService: l.Addr().String(),
		RouteFor: func(uint32) (AppRoute, error) { return AppRoute{}, nil }}
	if _, _, err := d2.DialWeb(context.Background(), 8, BlobHost, 443); err == nil {
		t.Fatal("only port 80 is the blob service")
	}
	// off: refused like any name that does not resolve
	d3 := &Dialer{MaxConcurrent: 4, MaxPerMinute: 10}
	if _, _, err := d3.DialWeb(context.Background(), 9, BlobHost, 80); err == nil {
		t.Fatal("with no -blob-service the reserved name must not connect anywhere")
	}
}
