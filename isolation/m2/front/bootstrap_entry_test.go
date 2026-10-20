//go:build bootstrapdirect

package main

import (
	"context"
	"errors"
	"net"
	"testing"

	"enclave.host/isolation/m2/bootstrap"
)

func TestMeasuredDirectEntryNeverFallsBackToTicket(t *testing.T) {
	if !directBootstrap {
		t.Fatal("wrong measured mode")
	}
	for _, name := range []string{"missing", "wrong-deployment", "invalid-frame"} {
		t.Run(name, func(t *testing.T) {
			p := &provisioner{ticket: func() (net.Conn, error) {
				t.Error("direct startup requested a relay ticket")
				return nil, errors.New("refused")
			},
				egress: func() (net.Conn, error) { t.Error("invalid frame reached network"); return nil, errors.New("refused") }}
			id := [32]byte{1}
			dial := func() (net.Conn, error) {
				if name == "missing" {
					return nil, errors.New("host unavailable")
				}
				a, b := net.Pipe()
				go func() {
					defer b.Close()
					if name == "wrong-deployment" {
						bootstrap.WritePackage(b, [32]byte{2}, []byte("untrusted"))
					} else {
						b.Write([]byte("garbage"))
					}
				}()
				return a, nil
			}
			if _, err := p.runStartup(context.Background(), dial, id[:], nil, nil, nil); err == nil {
				t.Fatal("invalid package started guest")
			}
			if len(p.keys) != 0 {
				t.Fatal("loaded relay signing keys")
			}
		})
	}
}
