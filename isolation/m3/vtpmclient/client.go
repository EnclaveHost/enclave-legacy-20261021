// Package vtpmclient obtains OpenHCL VBS reports through the guest Linux TPM.
// Only the measured monitor may access /dev/tpm0. App identities must come from
// its own domain table, never from an untrusted request or the Windows host.
package vtpmclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
)

const reportIndex uint32 = 0x01400001
const inputIndex uint32 = 0x01400002
const owner uint32 = 0x40000001
const refreshDelay = 2100 * time.Millisecond

var ErrBusy = errors.New("guest TPM attestation busy; retry")

type Exchange func([]byte) ([]byte, error)
type Client struct {
	mu          sync.Mutex
	exchange    Exchange
	wait        func(time.Duration)
	initialized bool
}

func New(exchange Exchange) *Client { return &Client{exchange: exchange, wait: time.Sleep} }
func Open(path string) (*Client, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	// TPM character devices implement command/response transactions. Go may put
	// pollable files in nonblocking mode; then a read can return zero before the
	// TPM's queued command finishes, leaving the next write EBUSY. Force blocking
	// mode before the first command, as required by the TPM char-device protocol.
	if err := syscall.SetNonblock(int(f.Fd()), false); err != nil {
		f.Close()
		return nil, err
	}
	// The monitor retains this descriptor for its lifetime; no child inherits it.
	return New(func(cmd []byte) ([]byte, error) {
		n, e := f.Write(cmd)
		if e != nil {
			return nil, e
		}
		if n != len(cmd) {
			return nil, io.ErrShortWrite
		}
		out := make([]byte, 4096)
		n, e = f.Read(out)
		return out[:n], e
	}), nil
}

type tpmError uint32

func (e tpmError) Error() string { return fmt.Sprintf("guest TPM rc=0x%08x", uint32(e)) }
func be16(v uint16) []byte       { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
func be32(v uint32) []byte       { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
func packet(tag uint16, cmd uint32, parts ...[]byte) []byte {
	b := append(be16(tag), make([]byte, 4)...)
	b = append(b, be32(cmd)...)
	for _, p := range parts {
		b = append(b, p...)
	}
	binary.BigEndian.PutUint32(b[2:6], uint32(len(b)))
	return b
}

var password = []byte{0, 0, 0, 9, 0x40, 0, 0, 9, 0, 0, 0, 0, 0}

func (c *Client) command(cmd []byte) ([]byte, error) {
	r, e := c.exchange(cmd)
	if e != nil {
		return nil, e
	}
	if len(r) < 10 || len(r) > 4096 || int(binary.BigEndian.Uint32(r[2:6])) != len(r) {
		return nil, errors.New("invalid TPM response size")
	}
	if rc := binary.BigEndian.Uint32(r[6:10]); rc != 0 {
		return nil, tpmError(rc)
	}
	if binary.BigEndian.Uint16(r[:2]) != binary.BigEndian.Uint16(cmd[:2]) {
		return nil, errors.New("TPM response tag mismatch")
	}
	return r, nil
}
func (c *Client) public(index uint32) (uint16, error) {
	r, e := c.command(packet(0x8001, 0x169, be32(index)))
	if e != nil {
		return 0, e
	}
	if len(r) < 26 || binary.BigEndian.Uint32(r[12:16]) != index {
		return 0, errors.New("invalid NV public response")
	}
	policy := int(binary.BigEndian.Uint16(r[22:24]))
	pubsize := int(binary.BigEndian.Uint16(r[10:12]))
	if pubsize != 14+policy || len(r) < 26+policy {
		return 0, errors.New("invalid NV public size")
	}
	return binary.BigEndian.Uint16(r[24+policy : 26+policy]), nil
}
func (c *Client) initialize() error {
	size, e := c.public(inputIndex)
	if e != nil {
		var rc tpmError
		if !errors.As(e, &rc) || rc != 0x18b {
			return e
		}
		pub := bytes.Join([][]byte{be32(inputIndex), be16(0x0b), be32(0x60006), be16(0), be16(64)}, nil)
		_, e = c.command(packet(0x8002, 0x12a, be32(owner), password, be16(0), be16(uint16(len(pub))), pub))
		if e != nil {
			return e
		}
		size, e = c.public(inputIndex)
	}
	if e != nil {
		return e
	}
	if size != 64 {
		return errors.New("guest input NV index is not 64 bytes")
	}
	c.initialized = true
	return nil
}
func (c *Client) Report(input []byte) ([]byte, error) {
	if len(input) != 64 {
		return nil, errors.New("attestation binding must be 64 bytes")
	}
	if !c.mu.TryLock() {
		return nil, ErrBusy
	}
	defer c.mu.Unlock()
	if !c.initialized {
		if e := c.initialize(); e != nil {
			return nil, e
		}
	}
	_, e := c.command(packet(0x8002, 0x137, be32(owner), be32(inputIndex), password, be16(64), input, be16(0)))
	if e != nil {
		return nil, e
	}
	// OpenHCL rate-limits reports. Wait after writing, and check the returned
	// binding: a cached or mismatched report must never pass as this request.
	c.wait(refreshDelay)
	size, e := c.public(reportIndex)
	if e != nil {
		return nil, e
	}
	if size < 1236 || size > 8192 {
		return nil, errors.New("invalid report NV size")
	}
	report := make([]byte, 0, int(size))
	for offset := 0; offset < int(size); {
		count := int(size) - offset
		if count > 512 {
			count = 512
		}
		r, e := c.command(packet(0x8002, 0x14e, be32(owner), be32(reportIndex), password, be16(uint16(count)), be16(uint16(offset))))
		if e != nil {
			return nil, e
		}
		if len(r) < 16+count || binary.BigEndian.Uint32(r[10:14]) != uint32(count+2) || binary.BigEndian.Uint16(r[14:16]) != uint16(count) {
			return nil, errors.New("invalid NV read response")
		}
		report = append(report, r[16:16+count]...)
		offset += count
	}
	if e := checkBinding(report, input); e != nil {
		return nil, e
	}
	return report, nil
}
func checkBinding(r, input []byte) error {
	if len(r) < 1236 {
		return errors.New("truncated HCLA report")
	}
	u := func(o int) uint32 { return binary.LittleEndian.Uint32(r[o : o+4]) }
	size, claimsSize := uint64(u(8)), uint64(u(1232))
	if u(0) != 0x414c4348 || u(4) != 2 || u(12) != 2 || u(16) != 0 || u(1220) != 1 || u(1224) != 1 || u(1228) != 1 ||
		size != 1236+claimsSize || size > uint64(len(r)) || uint64(u(1216)) != 20+claimsSize {
		return errors.New("invalid HCLA envelope")
	}
	claimsBytes := r[1236:int(size)]
	digest := sha256.Sum256(claimsBytes)
	if !bytes.Equal(r[56:88], digest[:]) {
		return errors.New("claims differ from VBS report data")
	}
	var claims struct {
		UserData string `json:"user-data"`
	}
	if json.Unmarshal(claimsBytes, &claims) != nil || claims.UserData != hex.EncodeToString(input) {
		return errors.New("VBS report does not bind this request")
	}
	return nil
}
