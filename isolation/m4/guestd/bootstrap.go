package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"time"

	"enclave.host/isolation/m2/bootstrap"
)

func decodeBootstrap(s string) ([]byte, error) {
	if s == "" || len(s) > base64.StdEncoding.EncodedLen(bootstrap.MaxManifestBytes) {
		return nil, errors.New("missing or oversized startup package")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) == 0 || len(b) > bootstrap.MaxManifestBytes || base64.StdEncoding.EncodeToString(b) != s {
		return nil, errors.New("startup package must be canonical base64 within limit")
	}
	return b, nil
}

// No package is an authorization here. Only the measured guest verifies the
// ledger commitment. CID routing prevents accidental cross-deployment delivery.
func (s *server) bootstrapForCID(cid uint32) ([32]byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var id [32]byte
	for _, v := range s.vms {
		if cid == 0 || v.cid != cid || !v.directBootstrap || v.Status != "starting" || !releaseLive(v) {
			continue
		}
		b, err := hex.DecodeString(v.HostData)
		if err != nil || len(b) != 32 || len(v.bootstrap) == 0 {
			break
		}
		copy(id[:], b)
		return id, append([]byte(nil), v.bootstrap...), nil
	}
	return id, nil, errors.New("no starting direct deployment has this CID")
}

func (s *server) serveBootstrap(ctx context.Context, l net.Listener, cidOf func(net.Conn) uint32) error {
	if cidOf == nil {
		return errors.New("bootstrap service requires peer CID")
	}
	go func() { <-ctx.Done(); l.Close() }()
	slots := make(chan struct{}, maxHeld)
	backoff := 5 * time.Millisecond
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			time.Sleep(backoff)
			if backoff < time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 5 * time.Millisecond
		select {
		case slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() {
			defer func() { c.Close(); <-slots }()
			c.SetDeadline(time.Now().Add(15 * time.Second))
			id, raw, err := s.bootstrapForCID(cidOf(c))
			if err != nil {
				return
			}
			_ = bootstrap.WritePackage(c, id, raw)
		}()
	}
}
