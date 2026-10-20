// An independent Shield market verifier: what the Enclave relay checks before it opens a Shield host's market window
// (relay/tunnel.js hv-node attach + relay/shield-marketplace.mjs readiness), run by whoever an operator chooses to trust,
// over plain HTTPS instead of the fleet tunnel, and answered with a signed, expiring verdict bound to the host's own round
// (windows/node/shield-verdict.mjs has the format and the host's rules).
//
// The checks are the relay's own code, unchanged:
//   vbs-credential.mjs makeCredential     the credential round for the presented EK and AK name (tunnel.js vbs-keys)
//   hvnode-verify.mjs verifyHvNodeEvidence the attach: EK chain, credential, quote, log, boot policy, possession
//   shield-market-evidence.mjs + shield-app-policy.mjs verifyShieldAppPolicy  the pinned readiness witness, under the IDKS
//                                          of THAT authenticated boot, on admitted images and platforms
// plus the identity the tunnel gets from a name's on-chain owner: the registry entry for keccak256(endpoint) names this
// endpoint, and its registered operator signed this exchange (shield-verdict.mjs attachMessage).
//
// Sessions are single use: an attest consumes its session whatever the outcome, and a session lives 60 s. The verifier
// keeps no state a host can replay into a verdict, and a verdict lives at most five minutes.
import { createHash } from "node:crypto";
import { verifyShieldAppPolicy } from "./shield-app-policy.mjs";
import { pinnedWitness, readinessInput } from "./shield-market-evidence.mjs";
import { createHostSessions, fail } from "./shield-host-session.mjs";
import { signVerdict, keyIdOf, keySpecOf, MAX_VERDICT_TTL_MS } from "../windows/node/shield-verdict.mjs";

const sha256hex = (b) => createHash("sha256").update(b).digest("hex");

/**
 * createIndependentShieldVerifier({ policy, signingKey, registryEntry, recoverSigner, ... })
 *   policy         enclave-shield-app-policy/1 with marketEnabled, a witness, ekRoots (and ekRootPins), platforms and images:
 *                  this verifier operator's own pins, exactly the relay's market policy
 *   signingKey     this verifier's Ed25519 private KeyObject (its public key is what host operators pin)
 *   registryEntry  async (hostId) -> { endpoint, operator, active } from the chain (a quorum read the verifier trusts)
 *   recoverSigner  async (message, signature) -> address (viem recoverMessageAddress)
 * The attach and identity checks are shield-host-session.mjs (shared with the DNS-01 responder and custodians).
 */
export function createIndependentShieldVerifier({ policy, signingKey, registryEntry, recoverSigner, now = Date.now, ttlMs = MAX_VERDICT_TTL_MS,
                                                  sessionTtlMs = 60_000, maxSessions = 64, log = () => {} }) {
  if (policy?.schema !== "enclave-shield-app-policy/1" || policy.marketEnabled !== true || !policy.ekRoots || !policy.cpu?.runtimeId)
    throw new Error("an independent Shield verifier needs a market-enabled enclave-shield-app-policy/1 with pinned TPM roots");
  const witness = pinnedWitness(policy);
  if (!witness) throw new Error("an independent Shield verifier needs the policy's pinned readiness witness");
  if (typeof registryEntry !== "function" || typeof recoverSigner !== "function") throw new Error("an independent Shield verifier needs chain identity checks");
  if (!(ttlMs > 0 && ttlMs <= MAX_VERDICT_TTL_MS)) throw new Error(`a verdict lives at most ${MAX_VERDICT_TTL_MS} ms`);
  const key = keySpecOf(signingKey), keyId = keyIdOf(key);
  const policySha256 = sha256hex(Buffer.from(JSON.stringify(policy)));
  const sessions = createHostSessions({ party: keyId, ekRoots: policy.ekRoots, ekRootPins: policy.ekRootPins, registryEntry, recoverSigner,
                                        now, sessionTtlMs, maxSessions });
  const challenge = (body) => sessions.challenge(body).then((c) => ({ ...c, verifier: keyId }));

  async function attest(body = {}) {
    // (1) THE ATTACH and (2) WHOSE HOST: the relay's own verification and session object, then the registry and operator
    const s = await sessions.verify(body);
    const { hostSession, host, spki } = s;
    // (3) THE PINNED READINESS WITNESS on that boot (the relay marketplace's readiness rule)
    let input;
    try { input = readinessInput(body.readiness, s.appNonce, witness); } catch (e) { throw fail(422, e.message); }
    const app = verifyShieldAppPolicy({ ...input, hostSession }, policy);
    if (!app.ok) throw fail(403, `readiness witness refused: ${String(app.reason).slice(0, 300)}`);
    const issuedAt = now();
    const verdict = signVerdict({ hostId: s.hostId, endpoint: s.endpoint, transportKeySha256: sha256hex(spki), ekCertSha256: sha256hex(s.ekCert),
      hostChallenge: s.hostChallenge, nonce: s.nonce.toString("hex"), tier: "hv-node", technology: "windows-tpm-host", hostExcluded: false,
      market: "shield-capacity", omissions: [...(host.omissions || [])],
      readiness: { appSha256: witness.appSha256, runtimeId: witness.runtimeId, measurement: String(app.measurement || "") },
      boot: { pcr0: host.boot?.pcr0 || null, akName: host.boot?.akName || null, idksModulusSha256: host.boot?.idksModulusSha256 || null },
      policySha256, issuedAt, expiresAt: issuedAt + ttlMs }, signingKey);
    log(`[shield-verifier] ${s.endpoint}: verdict until ${new Date(issuedAt + ttlMs).toISOString()}`);
    return { verdict };
  }

  /** A node:http handler for POST /v1/shield-verifier/{challenge,attest}; bodies are bounded. */
  async function handle(req, res) {
    const send = (status, body) => { res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" }); res.end(JSON.stringify(body)); };
    const route = { "/v1/shield-verifier/challenge": challenge, "/v1/shield-verifier/attest": attest }[new URL(req.url, "http://x").pathname];
    if (req.method !== "POST" || !route) return send(404, { error: "not_found" });
    const chunks = []; let n = 0;
    for await (const c of req) { n += c.length; if (n > 16 * 1024 * 1024) return send(413, { error: "body too large" }); chunks.push(c); }
    let body; try { body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"); } catch { return send(400, { error: "body is not JSON" }); }
    try { send(200, await route(body)); }
    catch (e) { send(Number.isInteger(e.status) ? e.status : 500, { error: String(e.message).slice(0, 800) }); }
  }
  return { key, keyId, challenge, attest, handle };
}
