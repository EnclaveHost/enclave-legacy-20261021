package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"testing"
)

func TestPackageFramingFailsClosed(t *testing.T) {
	id := [32]byte{1}
	var b bytes.Buffer
	if err := WritePackage(&b, id, []byte(`{"version":1}`)); err != nil {
		t.Fatal(err)
	}
	good := append([]byte(nil), b.Bytes()...)
	if raw, err := ReadPackage(bytes.NewReader(good), id); err != nil || string(raw) != `{"version":1}` {
		t.Fatalf("%s %v", raw, err)
	}
	for _, name := range []string{"wrong-id", "zero-id", "truncated-header", "truncated-body", "oversized", "empty", "trailing", "wrong-version"} {
		t.Run(name, func(t *testing.T) {
			raw := append([]byte(nil), good...)
			want := id
			switch name {
			case "wrong-id":
				want[1] = 1
			case "zero-id":
				want = [32]byte{}
			case "truncated-header":
				raw = raw[:10]
			case "truncated-body":
				raw = raw[:len(raw)-1]
			case "oversized":
				binary.BigEndian.PutUint32(raw[len(packageMagic)+32:], MaxManifestBytes+1)
			case "empty":
				binary.BigEndian.PutUint32(raw[len(packageMagic)+32:], 0)
			case "trailing":
				raw = append(raw, 'x')
			case "wrong-version":
				raw[5] = '9'
			}
			if _, err := ReadPackage(bytes.NewReader(raw), want); err == nil {
				t.Fatal("accepted invalid frame")
			}
		})
	}
}

func TestMeasuredRootFingerprints(t *testing.T) {
	for _, v := range []struct {
		raw  []byte
		hash string
	}{
		{gtsRootR4, "349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d"},
		{digicertGlobalRootG2, "cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f"},
	} {
		b, rest := pem.Decode(v.raw)
		if b == nil || len(bytes.TrimSpace(rest)) != 0 {
			t.Fatal("root PEM")
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil || !c.IsCA {
			t.Fatal("not a root CA")
		}
		h := sha256.Sum256(b.Bytes)
		if hex.EncodeToString(h[:]) != v.hash {
			t.Fatal("measured root changed")
		}
	}
	if _, err := MeasuredRoots(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewReader(MeasuredConfig(nil)); err != nil {
		t.Fatal(err)
	}
}
