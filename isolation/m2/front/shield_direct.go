//go:build shielddirect && bootstrapdirect && !releaselab

package main

// Owner-committed startup authority on an Enclave Shield partition (tier T0-hv, windows/vbslike): a distinct measured
// build of the DIRECT front (bootstrapdirect) for the m3 monitor under a Hyper-V launcher. No flag, request or file can
// switch another build onto it.
//
// What is the same as the SNP direct guest, by construction - it is the same code: bootstrap.Reader with the measured RPC
// set through the host's egress, Reader.AuthorizeWhenConfirmed on the exact package bytes, the exact AppID and RuntimeID
// this domain runs, then names.go/acme.go/certs.go unchanged (CSRs for the guest-held key, in-guest ACME through the
// owner-selected responder, install only for chains to the measured roots, Refresh every minute: revoked on any agreed
// owner/runner/operator/appRef/envelope change or ended lease, lapsing NameGrace after an outage).
//
// What differs, and why it is no weaker on THIS tier:
//   - The deployment id. A Hyper-V partition has no PSP-signed HOST_DATA. The id arrives in the package transport frame
//     the host's launcher serves (vsock 9446), and must agree with the <8 hex>.<zone> name the launcher gave this domain
//     at load (/cert.name). On SNP, HOST_DATA is also the host's choice at launch; in both cases a host can only point a
//     guest at a deployment whose owner committed THIS exact app and runtime, which Authorize checks against the chain.
//   - The tier. The AppID and RuntimeID can be the same as an SNP guest's (one catalog bundle, one wasmtime identity), so
//     they cannot keep an SNP-committed package off this weaker tier. The owner's envelope must name this backend
//     explicitly: isolation.require = "hyperv-partition-per-app". An envelope naming another backend, or none, is refused.
//   - App start. The bundle the monitor loaded measures the package's config into the AppID, so the runtime does not wait
//     for this front; what this front gates is the names (and nothing is certified before Authorize succeeds).
//   - custody-v2. Released directly by the owner-selected committee under explicit Shield rules; the runtime waits
//     until the package, bundle config, egress and fresh lease agree. No relay release is accepted.
// The attestation every ACME push carries is the m3 monitor's: the launcher's signed document plus the guest's own
// OpenHCL VBS report (vtpmclient) over Bind2(this key, the push hash, RuntimeID) || AppID. A responder accepts it only
// under a Shield policy its operator pinned, with a host TPM session it challenged itself (relay/dns-challenge-shield.mjs).
import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"enclave.host/isolation/m2/bootstrap"
	"enclave.host/isolation/m2/egress"
	"enclave.host/isolation/m2/vsock"
)

const shieldBackend = "hyperv-partition-per-app"

// shieldAuthority is what this path needs of a bootstrap.Authorization (an interface, so the decisions are tested with
// the chain faked; the real one is bootstrap's own, tested there).
type shieldAuthority interface {
	nameAuthority
	IsolationRequire() (string, error)
	SecretsMode() (string, error)
}

type shieldDeps struct {
	packages  func() (net.Conn, error)
	egress    func() (net.Conn, error)
	roots     func() (*x509.CertPool, error)
	authorize func(ctx context.Context, roots *x509.CertPool, id [32]byte, raw []byte, loaded bootstrap.Identity) (shieldAuthority, error)
	prepare   func(context.Context, shieldAuthority, [32]byte, *x509.CertPool) (*ownerStartup, error)
}

// shieldDirectOwner: main's one call on an m3 domain with no HOST_DATA (a Hyper-V partition).
func (f *front) shieldDirectOwner(ctx context.Context, pipe io.WriteCloser, egConfig *shieldEgress) error {
	if pipe != nil {
		defer pipe.Close()
	}
	egressPort, custodyPort, packagePort := directPorts()
	dial := func(port uint32) func() (net.Conn, error) {
		return func() (net.Conn, error) { return vsock.Dial(vsock.CIDHost, port) }
	}
	eg := dial(egressPort)
	return f.shieldOwner(ctx, shieldDeps{packages: dial(packagePort), egress: eg, roots: bootstrap.MeasuredRoots,
		prepare: func(ctx context.Context, a shieldAuthority, id [32]byte, roots *x509.CertPool) (*ownerStartup, error) {
			auth, ok := a.(*bootstrap.Authorization)
			if !ok {
				return nil, errors.New("Shield startup requires verified bootstrap authority")
			}
			p := &provisioner{egress: eg, custodyAuth: dial(custodyPort), roots: roots, logf: func(format string, args ...any) { fmt.Printf(format+"\n", args...) }}
			return f.prepareShieldDirect(ctx, auth, id, pipe, egConfig, p)
		},
		authorize: func(ctx context.Context, roots *x509.CertPool, id [32]byte, raw []byte, loaded bootstrap.Identity) (shieldAuthority, error) {
			r, err := shieldReader(roots, eg)
			if err != nil {
				return nil, err
			}
			return r.AuthorizeWhenConfirmed(ctx, id, raw, loaded)
		}})
}

func (f *front) shieldOwner(ctx context.Context, d shieldDeps) error {
	if f.certs == nil || f.certs.name == "" {
		return errors.New("the launcher named no deployment for this domain (no /cert.name): owner-committed startup needs one")
	}
	if f.rt == nil || len(f.appSha) != 32 {
		return errors.New("owner-committed startup needs this domain's runtime identity (ABI/2) and AppID")
	}
	roots, err := d.roots()
	if err != nil {
		return err
	}
	id, raw, err := readShieldPackage(d.packages, f.certs.name)
	if err != nil {
		return err
	}
	loaded := bootstrap.Identity{RuntimeID: f.rt.RID}
	copy(loaded.AppID[:], f.appSha)
	auth, err := d.authorize(ctx, roots, id, raw, loaded)
	if err != nil {
		return fmt.Errorf("owner-committed startup refused: %w", err)
	}
	if err = shieldTier(auth); err != nil {
		return err
	}
	mode, err := auth.SecretsMode()
	if err != nil {
		return err
	}
	startup := &ownerStartup{auth: auth}
	if d.prepare != nil {
		startup, err = d.prepare(ctx, auth, id, roots)
		if err != nil {
			return err
		}
	} else if mode != "public" {
		return fmt.Errorf("its package keeps secrets in %s, but no custody startup channel was configured", mode)
	}
	if f.names, err = f.startOwnerNames(startup, d.egress, roots); err != nil {
		return err
	}
	fmt.Printf("DOM shield direct: deployment 0x%x authorized by its owner-committed package (tier T0-hv, hostExcluded=false)\n", id[:4])
	return nil
}

// shieldTier refuses a package whose owner did not commit the deployment to THIS backend by name.
func shieldTier(a shieldAuthority) error {
	req, err := a.IsolationRequire()
	if err != nil {
		return err
	}
	if req != shieldBackend {
		return fmt.Errorf("the owner committed this deployment to isolation backend %q, not %q: a Shield partition never stands in for another tier", req, shieldBackend)
	}
	return nil
}

// readShieldPackage reads one framed package (bootstrap.WritePackage) and takes the deployment id from its header. The
// frame is then re-read through bootstrap.ReadPackage, the SNP guest's own reader, so magic, length, binding and end of
// stream are judged by the same code. The id must be the one the launcher named this domain for.
func readShieldPackage(packages func() (net.Conn, error), launcherName string) ([32]byte, []byte, error) {
	var id [32]byte
	label, _, ok := strings.Cut(launcherName, ".")
	if !ok || len(label) != 8 {
		return id, nil, errors.New("the launcher's name for this domain is not <8 hex>.<zone>")
	}
	if packages == nil {
		return id, nil, errors.New("startup package transport unavailable")
	}
	c, err := packages()
	if err != nil {
		return id, nil, errors.New("startup package transport unavailable")
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	header := make([]byte, 8+32+4)
	if _, err := io.ReadFull(c, header); err != nil {
		return id, nil, errors.New("truncated startup package header")
	}
	copy(id[:], header[8:40])
	if hex.EncodeToString(id[:4]) != label {
		return id, nil, fmt.Errorf("the startup package is for deployment 0x%x..., and the launcher named this domain %s", id[:4], launcherName)
	}
	raw, err := bootstrap.ReadPackage(io.MultiReader(bytes.NewReader(header), c), id)
	return id, raw, err
}

// shieldReader is runStartup's measured chain client (bootstrap.go), unchanged: only the measured RPC origins, reached
// through the host's egress, with TLS verified against the measured roots.
func shieldReader(roots *x509.CertPool, eg func() (net.Conn, error)) (*bootstrap.Reader, error) {
	conf := bootstrap.MeasuredConfig(nil)
	allowed := make(map[string]bool)
	for _, raw := range conf.RPCs {
		u, e := url.Parse(raw)
		if e != nil {
			return nil, e
		}
		allowed[net.JoinHostPort(u.Hostname(), "443")] = true
	}
	tr := &http.Transport{Proxy: nil, DisableCompression: true,
		TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if !allowed[addr] || ctx.Err() != nil {
				return nil, errors.New("unmeasured bootstrap RPC origin")
			}
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return egress.DialOrigin(eg, egress.Origin{Host: host})
		}}
	conf.Client = &http.Client{Transport: tr}
	return bootstrap.NewReader(conf)
}
