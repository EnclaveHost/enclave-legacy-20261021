// The Shield market's evidence rules, shared by the relay's marketplace (shield-marketplace.mjs) and an independent
// verifier an operator selects (shield-independent-verifier.mjs), so both open capacity on exactly the same proof:
//   - the policy's pinned readiness witness (an app the policy names by AppID and RuntimeID, never one the node names);
//   - a bounded proof from the node: the guest's attestation document and the TLS key of the session it came over;
//   - the check itself: verifyShieldAppPolicy over that document, this verifier's own fresh nonce, the witness's identities
//     and the TPM-verified host session the same verifier authenticated (the hub's verifyShieldApp, or the independent
//     verifier's own session). Nothing the node states about itself is read for the decision.
export const MAX_HANDSHAKE_SPKI_B64 = 5500;
const HEX = /^[0-9a-f]{64}$/;

/** The policy's readiness witness, or null when it names none. Throws on a malformed or mismatched one. */
export function pinnedWitness(policy) {
  const witness = policy?.witness;
  if (witness && (!HEX.test(witness.appSha256 || '') || !HEX.test(witness.runtimeId || '') || witness.runtimeId !== policy.cpu?.runtimeId))
    throw Error('invalid pinned Shield readiness witness');
  return witness || null;
}

/** A node's proof, bounded before anything parses it: { doc, handshakeSpki: Buffer }. Throws `no bounded <what> proof`. */
export function boundedProof(proof, what = 'readiness') {
  if (!proof || typeof proof.handshakeSpki !== 'string' || proof.handshakeSpki.length > MAX_HANDSHAKE_SPKI_B64)
    throw Error(`no bounded ${what} proof`);
  return { doc: proof.doc, handshakeSpki: Buffer.from(proof.handshakeSpki, 'base64') };
}

/** The verifier input for a readiness proof over `nonce` (the verifier's own 32 random bytes). */
export function readinessInput(proof, nonce, witness) {
  const p = boundedProof(proof, 'readiness');
  return { doc: p.doc, handshakeSpki: p.handshakeSpki, nonce, expectedAppSha256: witness.appSha256, expectedRuntimeId: witness.runtimeId };
}
