package custody

// Enclave Shield recipient evidence (custody/v2/shield-evidence.mjs is the reference; test/shield-custody.test.mjs pins the
// same vector). A Shield partition has no SEV-SNP report: its evidence is the OpenHCL VBS report the m3 monitor obtains
// over 64 bytes of guest input, the first 32 this front's, the last 32 the AppID the monitor loaded. For a custody release
// the front's half is ShieldReleaseInput: the v2 release binding (vault, deployment, revisions, committee, epoch,
// challenges, RuntimeID, transport key, recipient key R) folded with the ledger owner the custodian reads, under a domain
// no other report path uses. Custodians accept it only under owner-committed Shield rules (custody/v2/shield-rules.mjs).

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

const ShieldCustodyDomain = "enclave-custody-shield-v1\n"

// ShieldReleaseInput -> report input[0:32] for a Shield custody release.
func ShieldReleaseInput(binding [32]byte, owner string) ([32]byte, error) {
	o := strings.ToLower(owner)
	if len(o) != 42 || !strings.HasPrefix(o, "0x") {
		return [32]byte{}, errors.New("the owner is a 20-byte address")
	}
	addr, err := hex.DecodeString(o[2:])
	if err != nil || len(addr) != 20 {
		return [32]byte{}, errors.New("the owner is a 20-byte address")
	}
	zero := true
	for _, b := range addr {
		zero = zero && b == 0
	}
	if zero {
		return [32]byte{}, errors.New("the owner is a nonzero address")
	}
	h := sha256.New()
	h.Write([]byte(ShieldCustodyDomain))
	h.Write(binding[:])
	h.Write(addr)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}
