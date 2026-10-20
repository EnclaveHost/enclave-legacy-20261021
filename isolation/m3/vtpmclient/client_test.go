package vtpmclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func envelope(input []byte) []byte {
	claims, _ := json.Marshal(map[string]string{"user-data": hex.EncodeToString(input)})
	r := make([]byte, 2900)
	w := func(o int, n uint32) { binary.LittleEndian.PutUint32(r[o:o+4], n) }
	w(0, 0x414c4348)
	w(4, 2)
	w(8, uint32(1236+len(claims)))
	w(12, 2)
	w(1216, uint32(20+len(claims)))
	w(1220, 1)
	w(1224, 1)
	w(1228, 1)
	w(1232, uint32(len(claims)))
	copy(r[1236:], claims)
	h := sha256.Sum256(claims)
	copy(r[56:88], h[:])
	return r
}
func response(tag uint16, body ...[]byte) []byte { return packet(tag, 0, body...) }
func fakeTPM(t *testing.T, mutate func([]byte)) Exchange {
	t.Helper()
	var input []byte
	defined := false
	nextOffset := 0
	return func(cmd []byte) ([]byte, error) {
		if int(binary.BigEndian.Uint32(cmd[2:6])) != len(cmd) {
			t.Fatal("bad request size")
		}
		code := binary.BigEndian.Uint32(cmd[6:10])
		switch code {
		case 0x169:
			index := binary.BigEndian.Uint32(cmd[10:14])
			size := uint16(2900)
			if index == inputIndex {
				if !defined {
					return packet(0x8001, 0x18b), nil
				}
				size = 64
			}
			pub := bytes.Join([][]byte{be32(index), be16(0x0b), be32(0x60006), be16(0), be16(size)}, nil)
			return response(0x8001, be16(uint16(len(pub))), pub, be16(0)), nil
		case 0x12a:
			if binary.BigEndian.Uint32(cmd[31:35]) != inputIndex {
				t.Fatal("created wrong NV index")
			}
			defined = true
			return response(0x8002), nil
		case 0x137:
			if binary.BigEndian.Uint32(cmd[14:18]) != inputIndex || len(cmd) != 99 {
				t.Fatal("wrote wrong index or size")
			}
			input = append([]byte(nil), cmd[33:97]...)
			nextOffset = 0
			return response(0x8002), nil
		case 0x14e:
			if binary.BigEndian.Uint32(cmd[14:18]) != reportIndex {
				t.Fatal("read wrong index")
			}
			count, offset := int(binary.BigEndian.Uint16(cmd[31:33])), int(binary.BigEndian.Uint16(cmd[33:35]))
			if count > 512 || offset != nextOffset {
				t.Fatal("unbounded or nonsequential read")
			}
			nextOffset += count
			r := envelope(input)
			if mutate != nil {
				mutate(r)
			}
			return response(0x8002, be32(uint32(count+2)), be16(uint16(count)), r[offset:offset+count]), nil
		default:
			t.Fatalf("unexpected command %x", code)
			return nil, nil
		}
	}
}
func TestReportCreatesInputThenReadsFreshBoundedReport(t *testing.T) {
	c := New(fakeTPM(t, nil))
	var waits int
	c.wait = func(d time.Duration) {
		if d <= 2*time.Second {
			t.Fatal("refresh wait too short")
		}
		waits++
	}
	for _, value := range []byte{3, 7} {
		input := bytes.Repeat([]byte{value}, 64)
		r, e := c.Report(input)
		if e != nil {
			t.Fatal(e)
		}
		if e = checkBinding(r, input); e != nil {
			t.Fatal(e)
		}
	}
	if waits != 2 {
		t.Fatal("each request needs its own refresh")
	}
}
func TestStaleOrAlteredClaimsAreRefused(t *testing.T) {
	for _, mutate := range []func([]byte){func(r []byte) { copy(r, envelope(make([]byte, 64))) }, func(r []byte) { r[56] ^= 1 }, func(r []byte) { binary.LittleEndian.PutUint32(r[8:12], 99999) }} {
		c := New(fakeTPM(t, mutate))
		c.wait = func(time.Duration) {}
		if _, e := c.Report(bytes.Repeat([]byte{1}, 64)); e == nil {
			t.Fatal("accepted stale or altered report")
		}
	}
}
func TestBusyDoesNotMixAttestationInputs(t *testing.T) {
	c := New(fakeTPM(t, nil))
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	c.wait = func(time.Duration) { calls.Add(1); close(entered); <-release }
	done := make(chan error, 1)
	go func() { _, e := c.Report(make([]byte, 64)); done <- e }()
	<-entered
	if _, e := c.Report(bytes.Repeat([]byte{1}, 64)); !errors.Is(e, ErrBusy) {
		t.Fatalf("busy: %v", e)
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if calls.Load() != 1 {
		t.Fatal("second request entered TPM")
	}
}
func TestMalformedResponsesAndWrongInputLengthsFail(t *testing.T) {
	for _, bad := range [][]byte{nil, make([]byte, 10), packet(0x8001, 0x101), response(0x8002)} {
		c := New(func([]byte) ([]byte, error) { return bad, nil })
		if _, e := c.Report(make([]byte, 64)); e == nil {
			t.Fatal("accepted malformed TPM reply")
		}
	}
	c := New(func([]byte) ([]byte, error) { t.Fatal("wrong-size input touched TPM"); return nil, nil })
	for _, n := range []int{0, 32, 63, 65} {
		if _, e := c.Report(make([]byte, n)); e == nil {
			t.Fatal("accepted wrong input size")
		}
	}
}
