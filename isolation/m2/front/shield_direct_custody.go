//go:build shielddirect && bootstrapdirect && !releaselab

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"enclave.host/isolation/contract"
	"enclave.host/isolation/m2/bootstrap"
	"enclave.host/isolation/m2/custody"
	"enclave.host/isolation/m2/shieldconfig"
)

// prepareShieldDirect starts a Shield domain using only its verified owner package.
// The monitor owns the measured config and deployment files; the runtime waits on
// the inherited pipe. Neither a relay signature nor a launcher-supplied secret is
// accepted by this build. The stronger SNP path keeps its own evidence unchanged.
func (f *front) prepareShieldDirect(ctx context.Context, auth *bootstrap.Authorization, id [32]byte, pipe io.WriteCloser, eg *shieldEgress, p *provisioner) (*ownerStartup, error) {
	if pipe != nil {
		defer pipe.Close()
	}
	text, err := auth.ConfigText()
	if err != nil {
		return nil, err
	}
	measured, err := readMeasuredConfig("/app.config", 0)
	if eg != nil {
		measured, err = readMeasuredConfig(eg.config, eg.configUID)
	}
	if err != nil || measured != text {
		return nil, errors.New("Shield measured config differs from owner commitment")
	}
	mode, err := auth.SecretsMode()
	if err != nil {
		return nil, err
	}
	startup := &ownerStartup{auth: auth}
	if pipe == nil {
		if mode != "public" {
			return nil, errors.New("Shield custody requires a waiting secret-aware runtime")
		}
		return startup, auth.Revalidate(ctx)
	}
	if eg == nil {
		return nil, errors.New("Shield secret startup requires measured egress")
	}
	deployment, err := readMeasuredConfig(eg.deployment, eg.configUID)
	if err != nil || deployment != "0x"+hex.EncodeToString(id[:]) {
		return nil, errors.New("Shield secret runtime names another deployment")
	}
	values := map[string]string{}
	if mode == "custody-v2" {
		if p == nil || p.custodyAuth == nil || p.egress == nil || f.rt == nil {
			return nil, errors.New("Shield custody channels or runtime unavailable")
		}
		ptr, err := auth.Custody()
		if err != nil || ptr == nil {
			return nil, errors.New("Shield custody pointer unavailable")
		}
		st, err := custodyStateV2(id, ptr)
		if err != nil {
			return nil, err
		}
		grant, err := auth.NameGrant()
		if err != nil {
			return nil, err
		}
		cl := &custody.Client{Post: p.custodyPost, AuthorizeV2: p.authorizeV2, RuntimeID: f.rt.RID, TransportSPKI: f.spki,
			Evidence: func(binding [32]byte) (json.RawMessage, error) { return f.shieldCustodyEvidence(binding, grant.Owner) }}
		cctx, cancel := context.WithTimeout(ctx, custodyWindow)
		bundle, err := cl.ObtainV2(cctx, st)
		cancel()
		if err != nil {
			return nil, errors.New("Shield custody quorum release failed")
		}
		digest := sha256.Sum256([]byte(text))
		if bundle.ConfigSha256 != hex.EncodeToString(digest[:]) {
			return nil, errors.New("Shield custody bundle names another config")
		}
		values = bundle.Env
	} else if mode != "public" {
		return nil, errors.New("unsupported Shield secret mode")
	}
	if err = shieldconfig.Validate(values); err != nil {
		return nil, err
	}
	if err = auth.Revalidate(ctx); err != nil {
		return nil, err
	}
	// Names can use an owner-selected CA's EAB, recovered from the same custody bundle.
	if grant, e := auth.NameGrant(); e == nil && grant.ACME != nil && grant.ACME.EAB != nil {
		startup.eabKID, startup.eabKey, startup.eabErr = eabFrom(values, grant.ACME.EAB)
	}
	fwd, err := eg.startDirect(auth, values)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			fwd.Close()
		}
	}()
	payload, err := json.Marshal(values)
	if err != nil || len(payload) > 65536 {
		return nil, errors.New("Shield secret launch payload exceeds limit")
	}
	defer func() {
		for i := range payload {
			payload[i] = 0
		}
	}()
	// Egress setup and custody may be slow. Re-check ownership and the current lease
	// after both, immediately before the runtime receives its first secret byte.
	if err = auth.Revalidate(ctx); err != nil {
		return nil, err
	}
	n, err := pipe.Write(payload)
	if err != nil || n != len(payload) {
		return nil, errors.New("Shield secret launch pipe failed")
	}
	if err = pipe.Close(); err != nil {
		return nil, errors.New("Shield secret launch pipe failed")
	}
	f.shieldFwd = fwd
	keep = true
	return startup, nil
}

// shieldCustodyEvidence binds the recipient key and challenges to the ledger owner
// using the Shield-specific domain. The monitor supplies the AppID from loaded code.
// No nonce field is present: this is custody evidence, not a browser attestation.
func (f *front) shieldCustodyEvidence(binding [32]byte, owner string) (json.RawMessage, error) {
	if f.rt == nil || f.monitor == "" || len(f.spki) == 0 || len(f.appSha) != 32 {
		return nil, errors.New("Shield custody requires measured runtime and monitor")
	}
	input, err := custody.ShieldReleaseInput(binding, owner)
	if err != nil {
		return nil, err
	}
	rep, certs, boundary, tier, format, wx, err := f.askMonitor(input[:])
	if err != nil {
		return nil, errors.New("Shield custody report unavailable")
	}
	if tier != contract.TierHyperV || format != contract.FormatHyperV || len(rep) == 0 {
		return nil, errors.New("Shield custody report has wrong tier")
	}
	if !strings.HasPrefix(wx, "wx=clean ") {
		return nil, errors.New("Shield custody requires a fresh clean runtime scan")
	}
	self, err := f.selfTest(wx)
	if err != nil {
		return nil, errors.New("Shield custody runtime self-test failed")
	}
	d := map[string]any{"tier": tier, "format": format, "report": base64.StdEncoding.EncodeToString(rep),
		"transportKey": base64.StdEncoding.EncodeToString(f.spki), "appSha256": hex.EncodeToString(f.appSha),
		"boundary": boundary, "abi": contract.ABI2, "runtime": f.rt.ID, "runtimeSelfTest": self}
	if len(certs) > 0 {
		d["certs"] = base64.StdEncoding.EncodeToString(certs)
	}
	return json.Marshal(d)
}
