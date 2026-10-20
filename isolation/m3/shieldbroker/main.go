// A measured, per-domain, single-card byte broker. No plaintext inference API.
package main

import (
	"context"
	"enclave.host/isolation/m2/shieldbridge"
	"enclave.host/isolation/m2/vsock"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	uid, err := strconv.ParseUint(os.Args[1], 10, 31)
	if err != nil || uid == 0 {
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	b := shieldbridge.Bridge{Path: "/run/enclave-shield/gpu0", UID: int(uid), KeepIdleConnections: true, Limit: 8,
		Dial: func(ctx context.Context) (net.Conn, error) {
			ctx, c := context.WithTimeout(ctx, 5*time.Second)
			defer c()
			return vsock.DialContext(ctx, vsock.CIDHost, 19595)
		}}
	if b.Serve(ctx, make(chan error, 1)) != nil {
		os.Exit(1)
	}
}
