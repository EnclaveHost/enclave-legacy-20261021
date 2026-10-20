package egress

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestSOCKSDialsJudgedLiteralAndCarriesBytes(t *testing.T) {
	for _, ip := range []string{"93.184.216.34", "2606:4700:4700::1111"} {
		t.Run(ip, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			request := make(chan []byte, 1)
			go func() {
				c, e := ln.Accept()
				if e != nil {
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(2 * time.Second))
				b := make([]byte, 3)
				if _, e = io.ReadFull(c, b); e != nil {
					return
				}
				if !bytes.Equal(b, []byte{5, 1, 0}) {
					return
				}
				c.Write([]byte{5, 0})
				n := 10
				if netip.MustParseAddr(ip).Is6() {
					n = 22
				}
				b = make([]byte, n)
				if _, e = io.ReadFull(c, b); e != nil {
					return
				}
				request <- b
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				io.Copy(c, c)
			}()
			d := &Dialer{Resolver: fakeResolver{"service.example": {ip}}, SOCKSProxy: ln.Addr().String()}
			c, release, err := d.Dial(context.Background(), 7, "service.example", 443)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			defer release()
			want := []byte{5, 1, 0, 1}
			if netip.MustParseAddr(ip).Is6() {
				want[3] = 4
			}
			want = append(want, netip.MustParseAddr(ip).AsSlice()...)
			want = append(want, 1, 187)
			if got := <-request; !bytes.Equal(got, want) {
				t.Fatalf("proxy request %x, want literal %x", got, want)
			}
			c.SetDeadline(time.Now().Add(time.Second))
			c.Write([]byte("guest TLS bytes"))
			got := make([]byte, 15)
			if _, err = io.ReadFull(c, got); err != nil {
				t.Fatal(err)
			}
			if string(got) != "guest TLS bytes" {
				t.Fatal(string(got))
			}
		})
	}
}

func TestSOCKSDoesNotFallBackAndPreservesDestinationPolicy(t *testing.T) {
	d, dialed := testDialer(fakeResolver{"service.example": {"93.184.216.34"}, "private.example": {"127.0.0.1"}}, nil)
	d.SOCKSProxy = "127.0.0.1:1"
	if _, _, err := d.Dial(context.Background(), 7, "service.example", 443); ReasonOf(err) != ReasonConnect {
		t.Fatal(err)
	}
	if len(*dialed) != 0 {
		t.Fatal("fell back to direct dial")
	}
	if _, _, err := d.Dial(context.Background(), 7, "private.example", 443); ReasonOf(err) != ReasonNonPublicAnswer {
		t.Fatal(err)
	}
	if d.active[7] != 0 {
		t.Fatal("failed connection leaked a concurrency slot")
	}
	for _, address := range []string{"example.org:1234", "10.0.0.1:1234", "127.0.0.1:0", "socks5://127.0.0.1:1234"} {
		if ValidateSOCKSProxy(address) == nil {
			t.Fatal(address)
		}
	}
}

func TestSOCKSCancellationInterruptsHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := ln.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, e := dialSOCKS(ctx, ln.Addr().String(), "93.184.216.34:443", time.Minute)
		if c != nil {
			c.Close()
		}
		done <- e
	}()
	c := <-accepted
	defer c.Close()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt handshake")
	}
}
