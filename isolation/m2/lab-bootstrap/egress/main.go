// Hardware-test egress: only measured chain peers are reachable. This host-side
// transport cannot authorize startup; TLS and the owner commitment are checked
// inside the unchanged direct guest. Never use this broker for production apps.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	"enclave.host/isolation/m2/bootstrap"
	"enclave.host/isolation/m2/egress"
	"enclave.host/isolation/m2/vsock"
)

type chainOnly struct{ allowed map[string]bool }

func (r chainOnly) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if !r.allowed[host] {
		return nil, errors.New("hardware test refuses non-chain service")
	}
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

func main() {
	cidFile := flag.String("cid-file", "", "file containing the test guest's assigned vsock CID; absent means refuse every guest")
	port := flag.Uint("port", 19443, "isolated test vsock port")
	flag.Parse()
	if *cidFile == "" {
		log.Fatal("cid-file required")
	}
	allowed := map[string]bool{}
	for _, raw := range bootstrap.MeasuredConfig(nil).RPCs {
		u, err := url.Parse(raw)
		if err != nil {
			log.Fatal(err)
		}
		allowed[u.Hostname()] = true
	}
	d := &egress.Dialer{Resolver: chainOnly{allowed}, MaxConcurrent: 16, MaxPerMinute: 300}
	// Exercise the actual dial path before accepting a guest. Any successful
	// connection to these service names is a failed outage test.
	for _, host := range []string{"api.enclave.host", "ipfs.enclave.host", "s3.enclave.host", "nan.enclave.host"} {
		c, release, err := d.Dial(context.Background(), 2, host, 443)
		if err == nil {
			c.Close()
			release()
			log.Fatal("control refusal probe unexpectedly connected")
		}
		if egress.ReasonOf(err) != egress.ReasonResolve {
			log.Fatal("unexpected refusal probe result")
		}
	}
	log.Print("control refusal probes passed; only measured chain peers can resolve")
	l, err := vsock.Listen(uint32(*port))
	if err != nil {
		log.Fatal(err)
	}
	s := &egress.Server{Dialer: d, CIDOf: func(c net.Conn) uint32 {
		a, ok := c.RemoteAddr().(vsock.Addr)
		if !ok {
			return 0
		}
		return a.CID
	},
		Admit: func(cid uint32) bool {
			b, e := os.ReadFile(*cidFile)
			if e != nil {
				return false
			}
			n, e := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
			return e == nil && n >= 131072 && n < 196608 && uint32(n) == cid
		},
		Log: log.New(os.Stderr, "chain-only egress: ", log.LstdFlags)}
	log.Fatal(s.Serve(context.Background(), l))
}
