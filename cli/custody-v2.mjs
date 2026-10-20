// `enclave custody … --v2` (docs/security/secret-custody-v2.md): the owner's side of custody v2. The values are encrypted
// HERE to the host-run committee's KEY and written to EnclaveSecretVaultV2; the relay never holds them.
import { createChainReaderV2 } from "../custody/v2/chain.mjs";
import { buildBundleV2, makeUpdateV2, UPDATE_V2_ABI } from "../custody/v2/owner.mjs";
import { configTextOf, configTextFromEnvelope, configSha256 } from "../custody/protocol.mjs";
import { validateRules, parseRules, rulesFromPrediction } from "../custody/rules.mjs";

// the committee the Enclave seat created on Base at genesis (2026-10-14), used when nothing else names one
export const PLATFORM_COMMITTEE_V2 = "0x47742ae8c544ff66a4ad91cfbf5cecdd389013da362813ba3b55c4e247b0f7a3";

export async function cmdCustodyV2(sub, f, h) {
  const account = h.loadKey();
  const id = (await h.resolveId(f._[0], account)).toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(id)) throw new Error("custody needs an on-chain deployment (bytes32 id)");
  const vault = (await h.vaultV2Address()).toLowerCase();
  const clients = h.pubEachClients();
  const minAgree = Math.floor(clients.length / 2) + 1;
  if (minAgree < 2) h.warn("! one RPC configured: the committee key your secrets are encrypted to is only as trustworthy as it (pass --rpc a,b)");
  const reader = createChainReaderV2({ clients, vault, minAgree, chainId:h.chainId });
  const chainId = h.chainId;
  const st = await reader.readRelease({ id, endpoint: null });
  const pol = st.policy;

  if (sub === "status") {
    if (pol.policyRev === 0n) return h.say(`no v2 custody policy for ${h.short(id)} in ${vault}`);
    const c = st.committee;
    const out = { vault, id, owner: pol.owner, policyRev: String(pol.policyRev), secretRev: String(pol.secretRev), paused: pol.paused,
                  committee: pol.committeeId, epoch: c?.epoch ?? null, threshold: c ? `${c.t} of ${c.W} shares` : null, bundleBytes: st.bundle.data.length,
                  custodians: (c?.machines || []).map((m) => `${m.endpoint}${m.enclave ? " (Enclave)" : ""}`),
                  rules: (() => { try { return parseRules(pol.rules); } catch (e) { return `UNPARSEABLE: ${e.message}`; } })() };
    if (h.json) return h.jout(out);
    for (const [k, v] of Object.entries(out)) h.say(`${k.padEnd(12)} ${typeof v === "object" ? JSON.stringify(v) : v}`);
    return;
  }

  const committeeId = String(f.committee || (pol.policyRev ? pol.committeeId : "") || h.env.ENCLAVE_CUSTODY_COMMITTEE_V2 || PLATFORM_COMMITTEE_V2).toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(committeeId)) throw new Error("no committee: pass --committee 0x…");
  let rules;
  if (f.rules) rules = validateRules(JSON.parse(h.readFile(f.rules)));
  else if (f["rules-from-relay"]) {
    rules = rulesFromPrediction(await h.api("GET", `/v1/expected-guest?id=${id}`));
    h.say(`the relay predicts app ${rules.appId} and these images for this version (reproduce them before admitting):`);
    for (const im of rules.images) h.say(`  ${im.platform}  measurement ${im.measurement}  runtime ${im.runtimeId}`);
    if (!f.admit) throw new Error("not admitted: re-run with --admit once you have checked these images (or pass --rules with your own)");
  } else if (pol.policyRev) rules = parseRules(pol.rules);
  else throw new Error("no rules yet: pass --rules rules.json, or --rules-from-relay --admit");

  if (sub === "pause" || sub === "resume") {
    if (!pol.policyRev) throw new Error("no v2 custody policy to pause or resume");
    await h.sendTx(account, { address: vault, abi: UPDATE_V2_ABI, functionName: "update",
      args: [id, makeUpdateV2({ expectPolicyRev: pol.policyRev, policy: { committeeId: pol.committeeId, paused: sub === "pause", rules } })] });
    return h.say(sub === "pause" ? "paused: custodians release nothing for this deployment until you resume" : "resumed");
  }

  let env;
  if (sub === "set") {
    env = h.secretsKv(f._.slice(1), f.file);
    if (!Object.keys(env).length) throw new Error("nothing to set: pass KEY=VALUE arguments and/or --file .env (custody replaces the whole set)");
  } else {
    const r = await h.relayRead(id);
    env = r.env || {};
    if (!Object.keys(env).length) throw new Error("the relay holds no secrets for this deployment: nothing to migrate (use enclave custody set --v2)");
    h.say(`migrating ${Object.keys(env).length} secret(s) from the relay (rev ${r.rev}): ${Object.keys(env).sort().join(", ")}`);
  }
  const configText = f["config-file"] ? configTextOf(JSON.parse(h.readFile(f["config-file"])))
    : f["no-config"] ? "" : configTextFromEnvelope(st.lease ? st.lease.envelope : "");
  h.say(`the values may only be substituted into the config with sha256 ${configSha256(configText).slice(0, 16)}… (${configText ? configText.length + " bytes" : "no config"}); a different config makes the app refuse them`);
  const { committee } = await reader.readCommittee({ committeeId });
  if (!committee) throw new Error(`no committee ${committeeId} in ${vault}`);
  h.say(`encrypting to committee ${committeeId.slice(0, 10)}… (epoch ${committee.epoch}, ${committee.t} of ${committee.W} shares): ${committee.machines.map((m) => m.endpoint + (m.enclave ? " (Enclave)" : "")).join(", ")}`);
  const secretRev = pol.secretRev + 1n;
  const bundle = buildBundleV2({ chainId, vault, id, secretRev, committeeId, Y: committee.Y, env, configText });
  await h.sendTx(account, { address: vault, abi: UPDATE_V2_ABI, functionName: "update",
    args: [id, makeUpdateV2({ expectPolicyRev: pol.policyRev, policy: { committeeId, paused: false, rules }, bundle })] });
  let after;
  for (let i = 0; i < 20; i++) { after = await reader.readRelease({ id, endpoint: null }); if (after.policy.secretRev === secretRev) break; await new Promise((r) => setTimeout(r, 1500)); }
  if (after.policy.secretRev !== secretRev || Buffer.compare(Buffer.from(after.bundle.data), Buffer.from(bundle)) !== 0)
    throw new Error("the vault does not show the bundle just written; nothing else was changed (re-run status)");
  h.say(`custody v2: secrets revision ${after.policy.secretRev}, policy revision ${after.policy.policyRev}`);
  if (sub === "migrate") {
    const ex = await h.api("POST", "/v1/secrets/exists", { body: { id } }).catch(() => null);
    if (!ex || ex.custody !== true) {
      h.say("! the relay does not report this deployment as custody-held yet (its CUSTODY_VAULT_V2 is not this vault, or not set):");
      h.say("  its plaintext copy was NOT cleared. Re-run once it does, or clear it with `enclave secrets clear`.");
      return;
    }
    await h.relayClear(id);
    h.say("the relay's plaintext copy is deleted. ROTATE each credential at its issuer, then `enclave custody set --v2` the new values.");
  }
  h.say(`a running app picks them up on its next start: enclave restart ${h.short(id)}`);
}
