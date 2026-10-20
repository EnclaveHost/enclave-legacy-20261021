// windows/node/shield-startup.mjs - owner-committed startup for an Enclave Shield partition (hyperv-partition-per-app),
// with no Enclave relay in the path.
//
// THE LINUX RULE, APPLIED WHERE THIS TIER CAN APPLY IT. On the SEV-SNP tier the guest itself re-reads the owner's
// commitment on chain before it starts the app (isolation/m2/front bootstrap). A Shield partition has no such front: the
// partition image measures what it runs (the bundle's AppID binds the component, the policy, the runtime and the public
// config) but cannot read Base. So this node does the chain half itself, and only from authorities its operator pinned:
//   1. PINNED AUTHORITY. The ledger and catalog are the operator's contract pins (ENCLAVE_CONTRACT_PINS_FILE), never the
//      mutable address book and never a relay.
//   2. FRESH SAME-BLOCK QUORUM. The deployment row and its catalog version are read in ONE agreed read
//      (host-identity.mjs quorumReader): two RPCs on distinct hosts agree on both values and the block hash, at a recent
//      confirmed block. A stale, lone or disagreeing RPC decides nothing.
//   3. THE EXACT PACKAGE. The envelope's guestBootstrap hash names the bytes; any of the operator's storage replicas may
//      serve them (sdk/bootstrap/package.mjs: CID-addressed, size-bounded, hash-checked), and the scope check binds them to
//      this chain, this pinned ledger, this deployment, its CURRENT owner, its appRef and this host's pinned RuntimeID.
//   4. THE EXACT APP. The partition's AppID is derived here with the manager's own rule (windows/vbslike/manager/derive.mjs)
//      from the catalog component, fetched CID-verified, and the record node-bridge.mjs isolationPlan builds - the same
//      record the manager will derive from. It must equal the package's appId, or nothing is claimed or started.
//   5. CURRENT WALLET POLICY. The caller's host-wallet admission (host-admission.bundle.mjs) is asked at the same moment.
// The package's configText REPLACES the envelope's config and the version's config, exactly as on Linux (supervisor.js:
// a guestBootstrap envelope carries no config/configCid, and "" means none), and it is measured into the AppID (V5).
//
// CUSTODY-V2. A custody-v2 package starts only as a direct custody domain: V6/V7 on a manager whose /health states
// supports.custodyV2 (a stated custody image; windows/vbslike/manager/custody-transport.mjs). The guest opens its own shares
// (isolation/m2/front/shield_direct_custody.go); this host only signs its release binding (secrets.mjs custodyAuthorization,
// via shield-custody.mjs) and keeps TPM sessions with the package's custodians. Anywhere else such a package is refused by
// name: nothing is started without its values and no plaintext reaches this host. Relay-staged secrets are never
// consulted for an owner-committed deployment.
import fs from "node:fs";
import { bootstrapIntent, verifyPackage, fetchPackage, parseUniqueJSON } from "../../sdk/bootstrap/package.mjs";
import { validateStoragePlan } from "../../sdk/storage/replicas.mjs";
import { isolationPlan, BACKEND } from "../vbslike/datapath/node-bridge.mjs";
import { derive, canonical, sha256Hex } from "../vbslike/manager/derive.mjs";

export const SHIELD_BACKEND = BACKEND;
export const CHAIN_ID = 8453;
const CATALOG_REF = /^catalog:\/\/(0x[0-9a-fA-F]{64})\/(\d+)$/;
const ADDR = /^0x[0-9a-fA-F]{40}$/;
const unknown = (input, why) => ({ ok: false, input, why, unknown: true });
const refused = (input, why) => ({ ok: false, input, why, unknown: false });
const reason = (e) => String(e?.shortMessage || e?.message || e).slice(0, 300);

/**
 * shieldStartupEnvelope(raw) -> null for a legacy envelope (no guestBootstrap: every legacy path is unchanged), or
 * { intent, projected }: the owner's commitment, and the envelope WITHOUT it, for the node's existing option parser
 * (chain.mjs parseEnvelope / claimPolicy), which then judges placement, isolation, protection rules and GPU options as it
 * always has. Throws for a malformed commitment (bootstrapIntent: version 1, a nonzero sha256, and no legacy config or
 * configCid beside it) or one that does not name THIS backend: a package's RuntimeID is per backend, and the CLI's default
 * names the SNP tier.
 */
export function shieldStartupEnvelope(raw) {
  const s = String(raw || "").trim();
  if (!s.startsWith("{")) return null;
  let o;
  try { o = parseUniqueJSON(s); } catch { return null; }     // the legacy parser reports its own refusal
  if (!o || typeof o !== "object" || Array.isArray(o) || !Object.hasOwn(o, "guestBootstrap")) return null;
  const intent = bootstrapIntent(s);
  const { guestBootstrap, ...rest } = o;
  const require = rest.isolation && typeof rest.isolation === "object" ? rest.isolation.require : undefined;
  if (require !== BACKEND)
    throw new Error(`its owner-committed startup names isolation backend ${JSON.stringify(require ?? null)}; this host starts packages only for "${BACKEND}"`);
  return { intent, projected: JSON.stringify(rest) };
}

/** Storage replicas for startup packages: a storage plan file or an explicit list, never both and never a default. */
export function startupGateways(env = process.env, { readFile = (f) => fs.readFileSync(f) } = {}) {
  const file = env.ENCLAVE_STARTUP_STORAGE_PLAN_FILE, list = String(env.ENCLAVE_STARTUP_GATEWAYS || "").trim();
  if (file && list) throw new Error("choose ENCLAVE_STARTUP_STORAGE_PLAN_FILE or ENCLAVE_STARTUP_GATEWAYS, not both");
  if (file) {
    const bytes = readFile(file);
    if (bytes.length > 16384) throw new Error("startup storage plan too large");
    return validateStoragePlan(parseUniqueJSON(Buffer.from(bytes).toString("utf8"))).replicas.map((r) => r.gateway);
  }
  return list ? list.split(",").map((x) => x.trim()).filter(Boolean) : [];
}

/**
 * startupImages(env) -> { direct, legacyPublic } for createShieldStartup (F3), from this node's own environment:
 *   ENCLAVE_ISOLATION_DIRECT_RUNTIME_ID + ENCLAVE_ISOLATION_DIRECT_IMAGE_SHA256   the pinned Shield-direct image (both or neither)
 *   ENCLAVE_STARTUP_LEGACY_PUBLIC=1    explicit legacy-public operation: host-verified public packages, no guest authority.
 *                                      Refused beside the direct pins, and refused in ENCLAVE_IDENTITY_MODE=independent.
 * Throws, naming the problem, for anything half-set: owner-committed startup is then not configured at all.
 */
export function startupImages(env = process.env) {
  const rid = String(env.ENCLAVE_ISOLATION_DIRECT_RUNTIME_ID || "").trim().toLowerCase();
  const sha = String(env.ENCLAVE_ISOLATION_DIRECT_IMAGE_SHA256 || "").trim().toLowerCase();
  const legacy = String(env.ENCLAVE_STARTUP_LEGACY_PUBLIC || "").trim();
  if (!!rid !== !!sha) throw new Error("ENCLAVE_ISOLATION_DIRECT_RUNTIME_ID and ENCLAVE_ISOLATION_DIRECT_IMAGE_SHA256 pin the Shield-direct image together: set both or neither");
  if (legacy && legacy !== "1") throw new Error("ENCLAVE_STARTUP_LEGACY_PUBLIC is 1 or unset");
  if (legacy && rid) throw new Error("ENCLAVE_STARTUP_LEGACY_PUBLIC=1 cannot be combined with a pinned Shield-direct image: an owner-committed package never has a legacy fallback");
  if (legacy && String(env.ENCLAVE_IDENTITY_MODE || "").toLowerCase() === "independent")
    throw new Error("an independent host starts owner-committed packages only on a pinned Shield-direct image (ENCLAVE_STARTUP_LEGACY_PUBLIC=1 is refused)");
  return { direct: rid ? { runtimeId: rid, imageSha256: sha } : null, legacyPublic: legacy === "1" };
}

function rowOf(x) {
  return { id: String(x.id).toLowerCase(), owner: String(x.owner).toLowerCase(), appRef: String(x.appRef), configCid: String(x.configCid),
           gpuMilli: Number(x.gpuMilli), cpuMilli: Number(x.cpuMilli), appPort: Number(x.appPort), isPublic: x.isPublic === true,
           active: x.active === true, runner: String(x.runner).toLowerCase(), leaseUntil: Number(x.leaseUntil) };
}
function versionOf(m, v) {
  return { appId: m[1].toLowerCase(), index: Number(m[2]), cid: String(v.cid), version: String(v.version), memMb: Number(v.memMb),
           ports: String(v.ports), config: String(v.config), yanked: v.yanked === true, approval: Number(v.approval),
           // a package's configText replaces every other config source: the catalog's configCid is never read here
           configCid: "" };
}

/**
 * createShieldStartup({ reader, pins, gateways, fetchComponent, fetchImpl, abis, log }) -> the startup authority.
 *   reader          host-identity.mjs quorumReader (or anything with the same agreed(fn) contract)
 *   pins            { deployments, appCatalog }: the operator's pinned contracts (chainId is Base's)
 *   gateways        1-8 storage replica origins (package bytes; they decide availability only)
 *   fetchComponent  async (cid) -> Buffer, CID-verified (windows/vbslike/manager/fetchcid.mjs cidFetcher)
 *   abis            { DEP_ABI, CATALOG_ABI } (chain.mjs)
 */
export function createShieldStartup({ reader, pins, gateways, fetchComponent, fetchImpl = globalThis.fetch, abis, timeoutMs = 8000, log = () => {},
                                     direct = null, legacyPublic = false }) {
  // THIS NODE'S OWN PINS for the Shield-direct image (F3): its RuntimeID and its IGVM sha256, both or neither. RuntimeIDs
  // may equal the legacy image's, so the image hash is what tells the images apart; the manager's /health is compared
  // with these pins and never adopted as one.
  const directPin = direct ? { runtimeId: String(direct.runtimeId || "").toLowerCase(), imageSha256: String(direct.imageSha256 || "").toLowerCase() } : null;
  if (directPin && (!/^[0-9a-f]{64}$/.test(directPin.runtimeId) || !/^[0-9a-f]{64}$/.test(directPin.imageSha256)))
    throw new Error("the Shield-direct pins are a RuntimeID and an IGVM sha256 (64 hex each), both or neither");
  if (legacyPublic === true && directPin)
    throw new Error("explicit legacy-public operation and a pinned Shield-direct image are exclusive: an owner-committed package must never have a legacy fallback");
  legacyPublic = legacyPublic === true;
  if (!reader || typeof reader.agreed !== "function") throw new Error("owner-committed startup needs a chain quorum reader");
  if (!pins || !ADDR.test(String(pins.deployments || "")) || !ADDR.test(String(pins.appCatalog || "")))
    throw new Error("owner-committed startup needs pinned deployments and appCatalog contracts (ENCLAVE_CONTRACT_PINS_FILE)");
  if (!Array.isArray(gateways) || !gateways.length || gateways.length > 8)
    throw new Error("owner-committed startup needs 1-8 storage replicas (ENCLAVE_STARTUP_STORAGE_PLAN_FILE or ENCLAVE_STARTUP_GATEWAYS)");
  if (typeof fetchComponent !== "function") throw new Error("owner-committed startup needs a CID-verified component fetcher");
  if (!abis?.DEP_ABI || !abis?.CATALOG_ABI) throw new Error("owner-committed startup needs the ledger and catalog ABIs");
  const ledger = String(pins.deployments).toLowerCase(), catalog = String(pins.appCatalog).toLowerCase();
  const packages = new Map(), derived = new Map();
  const remember = (m, k, v, max) => { m.set(k, v); while (m.size > max) m.delete(m.keys().next().value); return v; };

  /** One agreed read, one block: the deployment row and the catalog version it names. */
  async function read(id) {
    return reader.agreed(async (c, blockNumber) => {
      const d = rowOf(await c.readContract({ address: ledger, abi: abis.DEP_ABI, functionName: "get", args: [id], blockNumber }));
      const m = CATALOG_REF.exec(d.appRef);
      const version = m ? versionOf(m, await c.readContract({ address: catalog, abi: abis.CATALOG_ABI, functionName: "getVersion",
                                                             args: [m[1], BigInt(m[2])], blockNumber })) : null;
      return { d, version, block: blockNumber.toString() };
    });
  }
  async function packageFor(intent, scope) {
    let bytes = packages.get(intent.sha256);
    if (!bytes) {
      // the hash only, here: a scope mismatch below is then a definite refusal, not one more unavailable gateway
      bytes = (await fetchPackage(intent, {}, { gateways, fetchImpl, timeoutMs, allowHttpIPs: true })).bytes;
      remember(packages, intent.sha256, bytes, 32);
    }
    return verifyPackage(bytes, intent, scope);
  }
  async function appIdOf(record) {
    const key = sha256Hex(canonical(record));
    if (derived.has(key)) return derived.get(key);
    const component = await fetchComponent(record.cid);
    return remember(derived, key, derive({ record, component }).appId, 64);
  }

  /**
   * materialize(id, opts) -> an isolationPlan-shaped verdict, plus `startup` when it passes:
   *   { ok: true, derivation, httpPort, policy, spawn, startup: { sha256, cid, appId, runtimeId, secretsMode, names, block,
   *     envelope, owner, appRef } }
   *   { ok: false, input, why, unknown }  (unknown: ask again; refused: a definite answer about these inputs)
   * opts: observed (the caller's own ledger read: a change between it and the quorum is a moving commitment), manager
   * (/health), runtimeId (this host's pin), waf (the projected envelope's rules), enclaveId and needLease (a launch needs
   * this host's live lease at the quorum block), walletRefusal (async (row) -> reason|null).
   */
  async function materialize(id, { observed = null, manager = null, runtimeId = "", waf = {}, enclaveId = "", needLease = false,
                                   walletRefusal = async () => null } = {}) {
    id = String(id || "").toLowerCase();
    let state;
    try { state = await read(id); } catch (e) { return unknown("chain", `no fresh agreeing chain quorum on the pinned ledger: ${reason(e)}`); }
    const { d, version, block } = state;
    if (!d.owner || /^0x0{40}$/.test(d.owner)) return refused("deployment", "no such deployment on the pinned ledger");
    if (!d.active) return refused("deployment.active", "the deployment is not active");
    if (observed && (String(observed.configCid || "") !== d.configCid || String(observed.owner || "").toLowerCase() !== d.owner
                     || String(observed.appRef || "") !== d.appRef))
      return unknown("deployment", "the startup commitment changed during verification; waiting for the ledger to settle");
    let env;
    try { env = shieldStartupEnvelope(d.configCid); } catch (e) { return refused("guestBootstrap", reason(e)); }
    if (!env) return refused("guestBootstrap", "the deployment no longer carries an owner-committed startup package");
    if (needLease && !(d.runner === String(enclaveId).toLowerCase() && d.leaseUntil * 1000 > Date.now()))
      return unknown("lease", `this host does not hold a live lease at block ${block} (it may not be visible yet)`);
    const wallet = await walletRefusal(d);
    if (wallet) return refused("walletPolicy", wallet);
    if (!version) return refused("version", "the appRef does not name a catalog version");
    let pkg;
    // the scope's runtimeId is the one the plan below pins; checked after it, through the same verifyPackage
    const scope = { chainId: CHAIN_ID, ledger, deployment: id, owner: d.owner, appRef: d.appRef };
    try { pkg = await packageFor(env.intent, scope); }
    catch (e) {
      return /no gateway returned/.test(reason(e)) ? unknown("package", `${reason(e)} (${gateways.length} replica(s) asked)`)
                                                   : refused("package", reason(e));
    }
    const m = pkg.manifest;
    const secrets = m.secretsMode !== "public";
    // WHICH PINNED IMAGE (F3; work/shield-image-selection-interface.txt). An owner-committed package is a DIRECT request:
    // it starts on this node's pinned Shield-direct image (its RuntimeID AND IGVM hash, both this node's own pins, compared
    // with what the manager states, never adopted from it), or it is refused. It is never silently started on the legacy
    // image. Only an operator who chose explicit legacy-public operation (legacyPublic, which excludes the direct pins and
    // independent mode) starts a names-free public package host-verified on the legacy image, with guestAuthority=false.
    const sd = manager?.images?.shieldDirect;
    let route;
    if (directPin) {
      if (!(manager?.supports?.directBootstrap === true && sd?.runtimeId === directPin.runtimeId && sd?.igvmSha256 === directPin.imageSha256))
        return refused("manager", `this host pins the Shield-direct image ${directPin.imageSha256} with RuntimeID ${directPin.runtimeId}, and the manager states ${sd ? `${String(sd.igvmSha256).slice(0, 64)} with ${String(sd.runtimeId).slice(0, 64)}` : "no Shield-direct image"}: an owner-committed package starts on no other image`);
      if (m.runtimeId !== directPin.runtimeId)
        return refused("package.runtimeId", `the package commits to RuntimeID ${m.runtimeId}, and this host's Shield-direct image runs ${directPin.runtimeId}`);
      route = "shield-direct";
    } else if (legacyPublic) {
      if (m.names?.hosts?.length)
        return refused("names", "its package commits owner names, which only a Shield-direct partition image certifies (the guest verifies the package itself), and this host runs owner-committed packages in explicit legacy-public operation only");
      if (secrets)
        return refused("secretsMode", "its package keeps secrets in custody-v2, which only a Shield-direct custody image opens, and this host runs owner-committed packages in explicit legacy-public operation only: nothing is started without its values");
      route = "legacy";
    } else {
      return refused("guestBootstrap", "owner-committed startup needs this host's pinned Shield-direct image (ENCLAVE_ISOLATION_DIRECT_RUNTIME_ID and ENCLAVE_ISOLATION_DIRECT_IMAGE_SHA256), or explicit legacy-public operation (ENCLAVE_STARTUP_LEGACY_PUBLIC=1); this host has neither, so nothing is started");
    }
    const direct = route === "shield-direct";
    if (secrets && manager?.supports?.custodyV2 !== true)
      return refused("secretsMode", "its package keeps secrets in custody-v2, and this manager states no direct custody (supports.custodyV2) on its Shield-direct image:"
        + " it is not started without its values, and no plaintext secret is fetched into this host");
    let volumes = [];
    try { const c = JSON.parse(version.config || "{}"); volumes = Array.isArray(c?.volumes) ? c.volumes.slice() : []; } catch { volumes = null; }
    // the plan is pinned to the SELECTED image's RuntimeID (equal RuntimeIDs across images are legal)
    const pin = direct ? directPin.runtimeId : runtimeId;
    const plan = isolationPlan({ deploymentId: id, deployment: d, version, appConfig: m.configText, hasSecrets: secrets,
      waf, volumes, runtimeId: pin, require: BACKEND, manager, appConfigCid: "", configSourceCid: "" });
    if (!plan.ok) return plan;
    try { verifyPackage(pkg.bytes, env.intent, { ...scope, runtimeId: plan.spawn.derive.runtimeId }); }
    catch (e) { return refused("package.runtimeId", `${reason(e)}: the package commits to RuntimeID ${m.runtimeId}, and this host's ${direct ? "Shield-direct" : "legacy"} partition runtime is ${plan.spawn.derive.runtimeId}`); }
    let appId;
    try { appId = await appIdOf(plan.spawn.derive); }
    catch (e) { return unknown("component", `the catalog component could not be CID-verified and derived: ${reason(e)}`); }
    if (appId !== m.appId)
      return refused("package.appId", `the package commits to AppID ${m.appId}, and this deployment's partition derives ${appId} (${plan.derivation})`);
    // What the Shield-direct image starts: a public CPU app (V1/V5), or a custody-v2 secret domain (V6/V7) on a manager
    // stating direct custody. The guest verifies the exact bytes itself against its own RPC quorum
    // (isolation/m2/front/shield_direct.go); that guest-side authority is what certifies owner names and opens custody.
    if (direct) {
      const custodyDirect = secrets && manager?.supports?.custodyV2 === true && m.secretsMode === "custody-v2"
        && ["enclave-catalog-bundle/6", "enclave-catalog-bundle/7"].includes(plan.spawn.derive.derivation);
      const eligible = !plan.spawn.derive.inference
        && (secrets ? custodyDirect : ["enclave-catalog-bundle/1", "enclave-catalog-bundle/5"].includes(plan.spawn.derive.derivation));
      if (!eligible)
        return refused(secrets ? "secretsMode" : "derivation", secrets
          ? "its package keeps secrets in custody-v2, which a Shield partition opens only as a direct custody domain (enclave-catalog-bundle/6 or /7 on a manager stating direct custody), and this one is not"
          : `the Shield-direct image starts a public CPU app (enclave-catalog-bundle/1 or /5), not ${plan.derivation}`);
      // A Shield-direct front starts only when its measured /app.config IS the committed configText, byte for byte
      // (isolation/m2/front shield_direct_custody.go, shield_egress.go startDirect): custody's configSha256 and the
      // runtime's ENCLAVE_CONFIG both stand on those bytes. The bundle measures the canonical rendering (none at all
      // for a public app with no effective config), so any other spelling would derive this AppID and then end the
      // partition after a claim: refused here, before one.
      const measuredConfig = typeof plan.spawn.derive.config === "string" ? plan.spawn.derive.config : "";
      if (m.configText !== measuredConfig)
        return refused("package.configText", `its configText is not the exact bytes the partition measures (${measuredConfig ? `the canonical ${JSON.stringify(measuredConfig).slice(0, 80)}` : "no config file: commit \"\""}); a Shield-direct front starts only when they are equal`);
    }
    const spawn = direct ? { ...plan.spawn, bootstrap: pkg.bytes.toString("base64") } : plan.spawn;
    log(`${id.slice(0, 10)} owner-committed startup ${pkg.sha256.slice(0, 12)} verified at block ${block}: AppID ${appId.slice(0, 12)}, ${m.secretsMode}${direct ? ", carried into a Shield-direct partition" : ", legacy-public (host-verified, no guest authority)"}`);
    return { ...plan, spawn, startup: { direct, guestAuthority: direct, imageRole: route, imageSha256: direct ? directPin.imageSha256 : null, sha256: pkg.sha256, cid: pkg.cid, appId, runtimeId: m.runtimeId, secretsMode: m.secretsMode,
                                 names: [...(m.names?.hosts || [])], block, envelope: d.configCid, owner: d.owner, appRef: d.appRef,
                                 deployment: id,
                                 // the owner-selected CA responder this partition's in-guest ACME pushes to (shield-sessions.mjs)
                                 acme: direct && m.names?.acme ? { challenge: m.names.acme.challenge, zone: m.names.acme.zone } : null,
                                 // the owner-committed pointer's PUBLIC part: its vault, and the machines whose TPM
                                 // sessions with this node let them judge the guest (shield-sessions.mjs custodianTargets)
                                 custody: m.custody ? { v: m.custody.v, chainId: m.custody.chainId, vault: String(m.custody.vault || "").toLowerCase(),
                                                        machines: (Array.isArray(m.custody.machines) ? m.custody.machines : []).slice(0, 96)
                                                          .map((x) => ({ endpoint: String(x?.endpoint || ""), encKey: String(x?.encKey || "") })) } : null } };
  }
  return { configured: true, gateways: [...gateways], read, materialize };
}

/**
 * startupAdoptionRefusal(view, startup) -> why a partition the manager holds for this deployment must not be served as its
 * owner-committed startup, or null. A partition adopted by name (a node or manager restart) runs WHATEVER it was spawned
 * with; it serves only if it is the committed app on the committed runtime.
 */
export function startupAdoptionRefusal(view, startup) {
  if (!startup) return null;
  if (!view || typeof view !== "object") return "no manager view of the partition";
  if (String(view.appId || "") !== startup.appId) return `the partition runs AppID ${String(view.appId || "unknown").slice(0, 64)}, not the committed ${startup.appId}`;
  if (view.runtimeId != null && String(view.runtimeId) !== startup.runtimeId) return `the partition runs RuntimeID ${String(view.runtimeId).slice(0, 64)}, not the committed ${startup.runtimeId}`;
  // a Shield-direct partition holds its own copy of the package (its names, its custody pointer): the SAME app under an
  // older package is not the committed startup either
  if (startup.direct && String(view.bootstrapSha256 || "") !== startup.sha256)
    return `the partition holds startup package ${String(view.bootstrapSha256 || "none").slice(0, 64)}, not the committed ${startup.sha256}`;
  // ITS IMAGE (F3): a direct startup only on the Shield-direct image whose IGVM is THIS node's pin; anything else never on it.
  // Nothing is adopted across images.
  const role = typeof view.imageRole === "string" ? view.imageRole : "legacy";
  if (startup.direct) {
    if (role !== "shield-direct") return `the partition runs on the ${role} image, not the Shield-direct image the package needs`;
    if (!startup.imageSha256 || view.igvmSha256 !== startup.imageSha256)
      return `the partition's IGVM is ${String(view.igvmSha256 || "unstated").slice(0, 64)}, not this host's pinned Shield-direct image ${startup.imageSha256}`;
  } else if (role === "shield-direct") return "the partition runs on the Shield-direct image, and this startup is legacy-public";
  return null;
}
