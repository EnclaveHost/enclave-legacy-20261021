//go:build shielddirect && bootstrapdirect && !releaselab

package main

// The Shield-direct front's own decisions, with the chain faked behind the authority interface (bootstrap.Authorize and
// its quorum are bootstrap's, tested there; names.go/acme.go/certs.go are tested by names_test.go and acme_test.go, and
// run unchanged here). run: go test -tags 'bootstrapdirect shielddirect' -run Shield ./front/
import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"

	"enclave.host/isolation/m2/bootstrap"
)

type shieldFake struct {
	fakeAuthority
	require, mode string
	reqErr        error
}

func (a *shieldFake) IsolationRequire() (string, error) { return a.require, a.reqErr }
func (a *shieldFake) SecretsMode() (string, error)      { return a.mode, nil }

func shieldID(label byte) [32]byte {
	var id [32]byte
	for i := range id {
		id[i] = label
	}
	return id
}

// a host serving one frame (bootstrap.WritePackage, the Linux guestd's own writer), then closing
func framed(t *testing.T, id [32]byte, raw []byte, extra []byte) func() (net.Conn, error) {
	t.Helper()
	var b bytes.Buffer
	if err := bootstrap.WritePackage(&b, id, raw); err != nil {
		t.Fatal(err)
	}
	b.Write(extra)
	frame := b.Bytes()
	return func() (net.Conn, error) {
		host, guest := net.Pipe()
		go func() { host.Write(frame); host.Close() }()
		return guest, nil
	}
}

func shieldFront(t *testing.T, name string) *front {
	c := newCertState(t, name)
	return &front{spki: c.spki, appSha: bytes.Repeat([]byte{0x44}, 32), certs: c, rt: &runtimeState{RID: shieldID(0x55)}}
}

func shieldRun(t *testing.T, f *front, packages func() (net.Conn, error), auth *shieldFake, authErr error) (error, [32]byte, bootstrap.Identity) {
	var gotID [32]byte
	var gotLoaded bootstrap.Identity
	err := f.shieldOwner(context.Background(), shieldDeps{packages: packages,
		egress: func() (net.Conn, error) { return nil, errors.New("no egress in this test") },
		roots:  func() (*x509.CertPool, error) { return x509.NewCertPool(), nil },
		authorize: func(_ context.Context, _ *x509.CertPool, id [32]byte, raw []byte, loaded bootstrap.Identity) (shieldAuthority, error) {
			gotID, gotLoaded = id, loaded
			if !bytes.Equal(raw, []byte(`{"version":1}`)) {
				t.Fatalf("the exact framed bytes were not authorized: %q", raw)
			}
			if authErr != nil {
				return nil, authErr
			}
			return auth, nil
		}})
	return err, gotID, gotLoaded
}

func TestShieldDirectAuthorizesTheExactPackageAndStartsCommittedNames(t *testing.T) {
	id := shieldID(0x11)
	f := shieldFront(t, "11111111.app.enclave.host")
	auth := &shieldFake{fakeAuthority: fakeAuthority{grant: grantFor("0x"+strings.Repeat("33", 20), nil, "shop.example.com")},
		require: shieldBackend, mode: "public"}
	err, gotID, loaded := shieldRun(t, f, framed(t, id, []byte(`{"version":1}`), nil), auth, nil)
	if err != nil {
		t.Fatal(err)
	}
	if gotID != id || !bytes.Equal(loaded.AppID[:], f.appSha) || loaded.RuntimeID != f.rt.RID {
		t.Fatal("the authorization was not asked for this deployment, this AppID and this RuntimeID")
	}
	if f.names == nil || !f.names.authorizes("shop.example.com") || f.names.authorizes("other.example.com") {
		t.Fatal("the committed name is not exactly what the front may certify")
	}
}

func TestShieldDirectNeverStandsInForAnotherTier(t *testing.T) {
	id := shieldID(0x11)
	for _, req := range []string{"snp-guest-per-app", "", "hyperv-partition-per-app ", "HYPERV-PARTITION-PER-APP"} {
		f := shieldFront(t, "11111111.app.enclave.host")
		auth := &shieldFake{fakeAuthority: fakeAuthority{grant: grantFor("0x"+strings.Repeat("33", 20), nil, "shop.example.com")},
			require: req, mode: "public"}
		err, _, _ := shieldRun(t, f, framed(t, id, []byte(`{"version":1}`), nil), auth, nil)
		if err == nil || !strings.Contains(err.Error(), "never stands in for another tier") {
			t.Fatalf("require %q: %v", req, err)
		}
		if f.names != nil {
			t.Fatalf("require %q: names applied for a package committed to another tier", req)
		}
	}
	f := shieldFront(t, "11111111.app.enclave.host")
	if err, _, _ := shieldRun(t, f, framed(t, id, []byte(`{"version":1}`), nil), &shieldFake{reqErr: errors.New("startup authorization expired or unverified")}, nil); err == nil {
		t.Fatal("an unreadable tier was accepted")
	}
}

func TestShieldDirectRefusesAnotherDeploymentAMalformedFrameAndAnyRefusal(t *testing.T) {
	ok := &shieldFake{fakeAuthority: fakeAuthority{grant: grantFor("0x"+strings.Repeat("33", 20), nil)}, require: shieldBackend, mode: "public"}
	// the launcher named this domain for deployment 0x11111111..., the transport serves another one's package
	f := shieldFront(t, "11111111.app.enclave.host")
	if err, _, _ := shieldRun(t, f, framed(t, shieldID(0x22), []byte(`{"version":1}`), nil), ok, nil); err == nil || !strings.Contains(err.Error(), "launcher named this domain") {
		t.Fatalf("a package for another deployment: %v", err)
	}
	// trailing bytes, judged by bootstrap.ReadPackage
	if err, _, _ := shieldRun(t, f, framed(t, shieldID(0x11), []byte(`{"version":1}`), []byte("x")), ok, nil); err == nil {
		t.Fatal("a frame with trailing bytes was accepted")
	}
	// no launcher name, no runtime identity, no transport
	if err, _, _ := shieldRun(t, shieldFront(t, ""), framed(t, shieldID(0x11), []byte(`{"version":1}`), nil), ok, nil); err == nil {
		t.Fatal("a domain the launcher never named was authorized")
	}
	nort := shieldFront(t, "11111111.app.enclave.host")
	nort.rt = nil
	if err, _, _ := shieldRun(t, nort, framed(t, shieldID(0x11), []byte(`{"version":1}`), nil), ok, nil); err == nil {
		t.Fatal("ABI/1 domain was authorized")
	}
	if err, _, _ := shieldRun(t, f, func() (net.Conn, error) { return nil, errors.New("down") }, ok, nil); err == nil {
		t.Fatal("no transport was not refused")
	}
	// the chain's refusal (owner, app, runtime, commitment, lease) ends the domain
	if err, _, _ := shieldRun(t, f, framed(t, shieldID(0x11), []byte(`{"version":1}`), nil), ok, errors.New("startup package does not authorize the loaded app and runtime")); err == nil || !strings.Contains(err.Error(), "loaded app and runtime") {
		t.Fatalf("the chain's refusal was not final: %v", err)
	}
	// custody-v2: never run without its values on this tier
	cust := &shieldFake{fakeAuthority: fakeAuthority{grant: grantFor("0x"+strings.Repeat("33", 20), nil)}, require: shieldBackend, mode: "custody-v2"}
	if err, _, _ := shieldRun(t, shieldFront(t, "11111111.app.enclave.host"), framed(t, shieldID(0x11), []byte(`{"version":1}`), nil), cust, nil); err == nil || !strings.Contains(err.Error(), "no custody startup channel") {
		t.Fatalf("custody-v2: %v", err)
	}
}

// The Windows manager's frame writer (windows/vbslike/manager/package-transport.mjs packageFrame) and this guest's reader
// agree byte for byte: test/windows-shield-package-transport.test.mjs pins the same hex.
const shieldFrameVector = "656e636c6230310aabababababababababababababababababababababababababababababababab0000000d7b2276657273696f6e223a317d"

func TestShieldPackageFrameMatchesTheWindowsManager(t *testing.T) {
	var b bytes.Buffer
	if err := bootstrap.WritePackage(&b, shieldID(0xab), []byte(`{"version":1}`)); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(b.Bytes()); got != shieldFrameVector {
		t.Fatalf("frame drift:\n got %s\nwant %s", got, shieldFrameVector)
	}
	raw, _ := hex.DecodeString(shieldFrameVector)
	id, pkg, err := readShieldPackage(func() (net.Conn, error) {
		host, guest := net.Pipe()
		go func() { host.Write(raw); host.Close() }()
		return guest, nil
	}, "abababab.app.enclave.host")
	if err != nil || id != shieldID(0xab) || string(pkg) != `{"version":1}` {
		t.Fatalf("the manager's frame does not read back: %v", err)
	}
}
