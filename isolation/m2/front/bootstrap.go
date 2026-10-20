package main

// Direct startup has a distinct entry point; it never consumes a relay ticket
// or falls back to a signed release. The measured entry point/transport still
// needs activation as a new runtime before any production deployment uses it.
import (
	"context"
	"crypto/tls"
	"enclave.host/isolation/m2/appconfig"
	"enclave.host/isolation/m2/bootstrap"
	"enclave.host/isolation/m2/egress"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"

	"enclave.host/isolation/m2/release"
)

// runStartup is the actual measured entry point used by main. Its selection is
// compiled into the front, not negotiated with an untrusted launcher.
func (p *provisioner) runStartup(ctx context.Context, packages func() (net.Conn, error), hostData, spki []byte, rt *runtimeState, appID []byte) (*provisioned, error) {
	if !directBootstrap {
		var err error
		p.roots, err = release.RelayRoots()
		if err != nil {
			return nil, err
		}
		p.keys, err = release.PinnedRelayKeys()
		if err != nil {
			return nil, err
		}
		return p.run(ctx, hostData, spki, rt, appID)
	}
	var err error
	p.roots, err = bootstrap.MeasuredRoots()
	if err != nil {
		return nil, err
	}
	if len(hostData) != 32 || isZero(hostData) || packages == nil {
		return nil, errors.New("direct startup requires deployment and package transport")
	}
	var id [32]byte
	copy(id[:], hostData)
	c, err := packages()
	if err != nil {
		return nil, errors.New("startup package transport unavailable")
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	c.SetDeadline(time.Now().Add(15 * time.Second))
	raw, err := bootstrap.ReadPackage(c, id)
	c.Close()
	stop()
	if err != nil {
		return nil, err
	}
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
		TLSClientConfig:     &tls.Config{RootCAs: p.roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if !allowed[addr] || ctx.Err() != nil {
				return nil, errors.New("unmeasured bootstrap RPC origin")
			}
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return egress.DialOrigin(p.egress, egress.Origin{Host: host})
		}}
	defer tr.CloseIdleConnections()
	conf.Client = &http.Client{Transport: tr}
	reader, err := bootstrap.NewReader(conf)
	if err != nil {
		return nil, err
	}
	return p.runDirect(ctx, reader, raw, hostData, spki, rt, appID)
}

func (p *provisioner) runDirect(ctx context.Context, reader *bootstrap.Reader, manifest, hostData, spki []byte, rt *runtimeState, appID []byte) (*provisioned, error) {
	if !p.appFromCode || rt == nil || len(appID) != 32 || len(hostData) != 32 || isZero(hostData) {
		return nil, errors.New("direct startup requires deployment HOST_DATA and loaded code/runtime identity")
	}
	var id [32]byte
	copy(id[:], hostData)
	loaded := bootstrap.Identity{RuntimeID: rt.RID}
	copy(loaded.AppID[:], appID)
	auth, err := reader.AuthorizeWhenConfirmed(ctx, id, manifest, loaded)
	if err != nil {
		return nil, err
	}
	text, err := auth.ConfigText()
	if err != nil {
		return nil, err
	}
	ptr, err := auth.Custody()
	if err != nil {
		return nil, err
	}
	var secrets map[string]string
	if ptr != nil {
		secrets, err = p.custodySecrets(ctx, ptr, id, spki, rt, appID, text)
		if err != nil {
			return nil, err
		}
	}
	// Quorum retrieval may take minutes. Owner/lease/config changes during it
	// must prevent app start even if a previous custody operation succeeded.
	if err = auth.Revalidate(ctx); err != nil {
		return nil, err
	}
	pol, err := egress.FromBootstrap(auth, secrets)
	if err != nil {
		return nil, err
	}
	tag, err := auth.EnvelopeTag()
	if err != nil {
		return nil, err
	}
	out := &provisioned{envelope: tag, owner: &ownerStartup{auth: auth}}
	// An owner-selected CA with an EAB: the binding is resolved here, from custody secrets, and kept in this process.
	if g, e := auth.NameGrant(); e == nil && g.ACME != nil && g.ACME.EAB != nil {
		out.owner.eabKID, out.owner.eabKey, out.owner.eabErr = eabFrom(secrets, g.ACME.EAB)
	}
	if text != "" {
		resolved, e := appconfig.Resolve(text, secrets)
		if e != nil {
			return nil, e
		}
		value, ok := appconfig.EnvValue(resolved)
		if !ok {
			return nil, errors.New("direct startup config exceeds ENCLAVE_CONFIG ceiling")
		}
		out.config = value
	}
	secrets = nil
	return p.startForwarders(ctx, id, out, pol)
}
