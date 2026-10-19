package main

// Direct startup has a distinct entry point; it never consumes a relay ticket
// or falls back to a signed release. The measured entry point/transport still
// needs activation as a new runtime before any production deployment uses it.
import (
	"context"
	"enclave.host/isolation/m2/appconfig"
	"enclave.host/isolation/m2/bootstrap"
	"enclave.host/isolation/m2/egress"
	"errors"
)

func (p *provisioner) runDirect(ctx context.Context, reader *bootstrap.Reader, manifest, hostData, spki []byte, rt *runtimeState, appID []byte) (*provisioned, error) {
	if !p.appFromCode || rt == nil || len(appID) != 32 || len(hostData) != 32 || isZero(hostData) {
		return nil, errors.New("direct startup requires deployment HOST_DATA and loaded code/runtime identity")
	}
	var id [32]byte
	copy(id[:], hostData)
	loaded := bootstrap.Identity{RuntimeID: rt.RID}
	copy(loaded.AppID[:], appID)
	auth, err := reader.Authorize(ctx, id, manifest, loaded)
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
	out := &provisioned{envelope: tag}
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
