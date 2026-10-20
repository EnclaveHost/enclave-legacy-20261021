package egress

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"
)

// ValidateSOCKSProxy permits only an explicit local entry, with no DNS or userinfo.
func ValidateSOCKSProxy(address string) error {
	a, err := netip.ParseAddrPort(address)
	if err != nil || !a.Addr().IsLoopback() || a.Port() == 0 {
		return errors.New("SOCKS entry must be a loopback IP and nonzero port")
	}
	return nil
}

func dialSOCKS(ctx context.Context, proxy, destination string, timeout time.Duration) (net.Conn, error) {
	if err := ValidateSOCKSProxy(proxy); err != nil {
		return nil, err
	}
	target, err := netip.ParseAddrPort(destination)
	if err != nil || !validWebPort(int(target.Port())) || RefuseAddr(target.Addr(), nil) != "" {
		return nil, errors.New("SOCKS destination must be a judged public IP on a web port")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			c.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err = c.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err = c.Write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	var answer [4]byte
	if _, err = io.ReadFull(c, answer[:2]); err != nil {
		return nil, err
	}
	if answer[0] != 5 || answer[1] != 0 {
		return nil, errors.New("SOCKS entry rejected authentication method")
	}
	request := []byte{5, 1, 0}
	ip := target.Addr().Unmap()
	if ip.Is4() {
		request = append(request, 1)
	} else {
		request = append(request, 4)
	}
	request = append(request, ip.AsSlice()...)
	request = binary.BigEndian.AppendUint16(request, target.Port())
	if _, err = c.Write(request); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(c, answer[:]); err != nil {
		return nil, err
	}
	if answer[0] != 5 || answer[1] != 0 || answer[2] != 0 {
		return nil, errors.New("SOCKS entry refused connection")
	}
	size := 0
	switch answer[3] {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		var n [1]byte
		if _, err = io.ReadFull(c, n[:]); err != nil {
			return nil, err
		}
		size = int(n[0])
	default:
		return nil, errors.New("invalid SOCKS response address")
	}
	if _, err = io.CopyN(io.Discard, c, int64(size+2)); err != nil {
		return nil, err
	}
	if !stop() {
		return nil, ctx.Err()
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = c.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	success = true
	return c, nil
}
