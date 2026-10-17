// windows/node/host.mjs -- the Windows consumer node's host half: it holds a lease on the ledger
// and runs that deployment's app, and it answers the platform's host surface over the tunnel.
//
// Scope (see chain.mjs claimPolicy for each refusal and its reason): PUBLIC deployments, on CORES,
// whose options this box actually enforces, that FIT in what it has left to sell. The scope is
// OWNER-ONLY - the operator's and its delegated owners' deployments (ownerSet) - unless the box meets
// the isolation contract AND CLAIM_SCOPE=market (scope()); the relay grants a bounded window only after verifying guest app evidence.
//
// It advertises `claimEnabled: true` (it takes work) with `fullService: false` (it sells a subset
// of the platform's features). The relay keeps a partial box out of the fleet-AND capability flags,
// the minimum-spec numbers and the default price, so being listed here cannot take a feature away
// from another customer or make this box the platform's price - see fullServiceEnclaves() in
// relay/api-relay.js and test/fleet-partial-capability.test.mjs.
//
// A LEASED app runs INSIDE the enclave: its artifact is compiled to Pulley bytecode in VTL0 and
// interpreted in VTL1 by the runtime linked into the enclave image (windows/enclave-rt). Its code,
// its memory and its model calls never leave the enclave, and the card underneath only ever sees
// masked activations. An artifact built for a world the enclave cannot serve is refused by name
// rather than run beside the enclave, which is the thing this box does not sell.
import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import http from "node:http";
import * as chain from "./chain.mjs";
import { App, EnclaveApp, fetchArtifact, wasmLayer, appEnv, missingHostInterfaces, precompile } from "./apprun.mjs";
import { worldOf } from "./appframe.mjs";
import { fetchSecrets, secretsExist } from "./secrets.mjs";
// enclave-e3's shared module, vendored BYTE FOR BYTE from relay/host-delegation.mjs (test/windows-node-host-delegation.test.mjs
// pins it and replays the relay's vectors), so the relay and this node judge a delegation the same way
import { verifyDelegation, MAX_DELEGATIONS } from "./host-delegation.mjs";
// A WALLET SESSION as the owner's credential (shared with supervisor.js): restartRequest and a private deployment's proxy
// accept it beside this box's own SIWE session; cfg.sessionApi is the verifier (createSessionApiAuth), null = refused.
import { isSessionHeader } from "./session-api-auth.mjs";

/** The delegations this box carries: NODE_DIR/delegations/*.json, each { message, signature }, read fresh, in name order. */
function readDelegationFiles(dir) {
  let names = [];
  try { names = fs.readdirSync(dir).filter((n) => n.endsWith(".json")).sort(); } catch { return []; }
  return names.slice(0, MAX_DELEGATIONS).map((file) => {
    try { const o = JSON.parse(fs.readFileSync(path.join(dir, file), "utf8")); return { file, message: o.message, signature: o.signature }; }
    catch (e) { return { file, error: `unreadable: ${e.message}` }; }
  });
}
import { ensureCert, appHostFor, selfSigned } from "./apptls.mjs";
import { fetchDomains } from "./domains.mjs";
import tls from "node:tls";
import * as waf from "./waf.mjs";
import { CAP_STEP, loadCaps, saveCaps } from "./hosting.mjs";
import { priceGuide, defaultPrice, rowTiers, perSec6Of, perHourOf } from "./price-guide.mjs";
import { gasRunway } from "./gas-runway.mjs";
import { recentHyperVEvents } from "./hyperv-events.mjs";
import { createAuditJobs, auditAppRefsOf } from "./audit-jobs.mjs";
import { PARTITION_OFFERS } from "../vbslike/datapath/partition-offers.mjs";

const HEARTBEAT_MS = 10 * 60_000;
const TICK_MS = 30_000;
const PROOF_MS = 5 * 60_000;         // the contract's window is 15 min; the platform proves every 5
// Renew this long before the lease ends. It was 5 minutes, which with a 5-minute tick left exactly
// ONE attempt: a single transaction lost to a flaky RPC and the lease lapsed, after which `renew`
// reverts "lease expired" and the app is stopped - for risc-box, a cold boot of the whole machine.
// 15 minutes gives three attempts inside a ~30-minute lease, for twice the renewals' gas (cents).
const RENEW_LEAD_MS = 15 * 60_000;

/**
 * Why an isolated instance's stated boundary is not this backend's, or null when it is. hyperv-partition-per-app is T0-hv
 * with the host NOT excluded (a launcher-signed statement tier). A view saying otherwise is refused, never recorded: a
 * self-asserted hostExcluded or a stronger tier from the manager (a host process) must not reach this node's record,
 * which the console and the relay read.
 */
// isolationRespawn (off by default): at most this many respawns of an ended domain per deployment per window
export const RESPAWN_BUDGET = 3;
export const RESPAWN_WINDOW_MS = 60 * 60 * 1000;

// A manager-stated value, as it appears in a refusal reason: at most 64 characters. The reason is recorded, shown on the
// console and persisted with a block (host-state.json), so a lying manager must not be able to grow any of them without
// bound (enclave-99). Consumers escape it anyway: the node is not trusted by the tenant.
const stated64 = (v) => { const t = JSON.stringify(v ?? null) ?? "null"; return t.length > 64 ? `${t.slice(0, 61)}...` : t; };

export function isolationBoundaryRefusal(inst) {
  if (!inst || typeof inst !== "object") return "the manager returned no instance view";
  const who = inst.id == null ? "the instance" : stated64(String(inst.id)).replace(/^"|"$/g, "");
  const stated = "hostExcludedAsStated" in inst ? inst.hostExcludedAsStated : inst.hostExcluded;
  if (inst.hostExcluded !== false || (stated !== undefined && stated !== false)) {
    return `the manager's view of ${who} states hostExcluded=${stated64(stated)}; `
         + "this backend is T0-hv with the host NOT excluded, and nothing here verifies more, so it is not served";
  }
  const tier = typeof inst.tier === "string" ? inst.tier.toUpperCase().replace(/^T0-HV$/, "T0-hv") : null;
  if (tier !== "T0-hv") {
    return `the manager's view of ${who} states tier ${stated64(inst.tier)}; `
         + "this backend's tier is T0-hv, and a view stating another is not served";
  }
  return null;
}

// gasRunway: how long the operator key's gas lasts (gas-runway.mjs, shared with the phone's host agent)
export { gasRunway };

export class Host {
  constructor(cfg) {
    this.cfg = cfg;                                  // { dir, endpoint, name, appsEnabled, ownerWallet, cpuPricePerSec6, vcpus, ramGb, wasmtime, python, gateway, portBase, inferenceUrl, log }
    this.log = cfg.log || (() => {});
    /// The card, as the worker last described it, asked of the agent rather than remembered here:
    /// the pool this box sells is only as real as the worker that answers for it. Null when this
    /// box has no card or its worker is down, which sells nothing.
    this.card = cfg.card || (() => null);
    this.apps = new Map();                           // id -> App
    this.records = new Map();                        // id -> { id, status, reason, appRef, cid, version, leaseUntil, claimedAt, provenAt }
    this.enclaveId = chain.enclaveIdOf(cfg.endpoint);
    this.registered = null;                          // the registry entry as last read
    this.chainReady = false; this.lastError = "";
    this.statePath = path.join(cfg.dir, "host-state.json");
    const st = this.#loadState();
    this.tracked = new Set(st.tracked || []);
    /// The last card-price transaction this box SENT ({ want, at, tx }), kept across restarts: a registry read can lag a
    /// sent transaction, and a node restarted inside that lag used to send the same one again (d1's live node, 00:55:04
    /// and 00:55:33 at 013deb51). ensurePriced does not resend the same price while it is fresh.
    this.priceSent = st.priceSent && typeof st.priceSent === "object" ? st.priceSent : null;
    // THE PER-APP ISOLATION BACKEND, off unless a manager is configured. One place decides, so no
    // other code path can half-enable it: the deployed build has no such config and is unaffected.
    this.cfg.isolationManager   = this.cfg.isolationManager   || process.env.ENCLAVE_ISOLATION_MANAGER || "";
    this.cfg.isolationRuntimeId = this.cfg.isolationRuntimeId || process.env.ENCLAVE_ISOLATION_RUNTIME_ID || "";
    // host:port of the manager's data plane. Without it the app zone has no splicer, so an
    // isolated deployment is refused at the route rather than served through this agent.
    this.cfg.isolationDataAddr  = this.cfg.isolationDataAddr  || process.env.ENCLAVE_ISOLATION_DATA_ADDR || "";
    /// Secrets this box fetched for a lease it holds, in memory only: never written beside the
    /// state file, never logged, and dropped when the lease goes.
    this.secrets = new Map();
    /// The app-zone certificate per deployment, its backoff after a refusal, and the one request
    /// in flight: a browser retrying a name this box cannot certify must not turn into a retry
    /// storm at the relay's issuer.
    this.appCerts = new Map();
    this.appCertFails = new Map();
    /// The hostnames a customer attached to each deployment, their certificates, and what
    /// issuance did. Kept with the lease, not in the domains client, so there is one copy of the
    /// truth: `domains` is the list the relay last told us, `hostCerts` the certificate per name,
    /// and `certReports` what to tell the customer about names that did NOT get one.
    this.domains = new Map();        // id -> [hostname]
    /// hostname -> the deployment id that owns it, GLOBAL and live. `contextFor` consults this
    /// rather than a list captured when the connection opened: certificates are keyed by hostname
    /// across the whole box, so a name that moves between deployments would otherwise let the old
    /// owner keep serving it - with the NEW owner's certificate - for as long as a captured array
    /// survived. The window is small and the consequence is another tenant's identity.
    this.domainOwner = new Map();
    /// hostname -> a counter bumped on every ownership change. An issuance that started before a
    /// change and finishes after it is discarded rather than stored: the name is not ours now.
    this.domainGen = new Map();
    this.hostCerts = new Map();      // hostname -> { cert, ctx }
    // Both carry their OWNER, for the same reason hostCerts does: they are keyed by hostname
    // across the whole box, but what they are ABOUT is a (deployment, hostname) pair. A name that
    // moves takes neither the previous owner's backoff nor their pending report with it.
    this.certReports = new Map();    // hostname -> { owner, ok, error?, message?, at }
    this.domainFails = new Map();    // hostname -> { owner, until } retry-after epoch ms
    this.appCertInflight = new Set();
    // Work this box GAVE BACK, and why. It survives a restart on purpose: a claim costs gas and a
    // lease takes a deployment off the market, so a box that has already found out it cannot run
    // an app must not rediscover that every 30 seconds for as long as the row is on the ledger.
    // An operator or the console can clear an entry by forcing the claim (/v1/claim-hint force).
    this.blocked = new Map(Object.entries(st.blocked || {}));
    /// WHOSE deployments this box serves in owner-only scope: its operator, and the owner of each VALID delegation it
    /// carries (host-delegation.mjs), as refreshOwners last found them. Re-read every tick and before every claim and
    /// restart, so deleting a delegation file (or its expiry) ends that owner's authority.
    this.owners = { operator: null, delegations: [], invalid: new Map() };
    /// Definite pre-claim refusals (#preclaimVerdict): id -> { key, reason, at }. In memory; a restart asks again once.
    this.preclaim = new Map();
    /// Rows the ledger scan handed consider() and it DECLINED without a claim transaction (refused, queued, held by the
    /// partition verdict): id -> { key, at }. The scan skips such a row while its inputs are unchanged (scanHoldKey),
    /// asking again after SCAN_HOLD_MS for what the key cannot see. In memory; a restart asks again once.
    this.scanHold = new Map();
    /// Claim transactions that FAILED for a row, in a row, under the same inputs: id -> { key, n }. The second such failure
    /// holds the row for SCAN_CLAIMFAIL_HOLD_MS (enclave-bf's note on 3d37709a, enclave-87's follow-up): a claim that
    /// reverts every pass would otherwise spend every pass's one claim, and the rows behind it would wait.
    this.claimFails = new Map();
    // THE OWNER'S HOSTING CAPS (hosting.mjs, set from the tray): the most of this machine's CPU and GPU the node offers.
    // No file means 1.0 on both, which is this node exactly as it was before they existed.
    this.capsFile = cfg.hostingCapsFile || path.join(cfg.dir, "hosting-caps.json");
    const caps = loadCaps(this.capsFile);
    this.caps = caps.caps; this.capsError = caps.error;
    if (caps.error) this.log(caps.error);
    // THE OWNER'S PRICES (the tray's Pricing): an override per axis in USDC per hour for the whole CPU / card, or null for
    // the default (price-guide.mjs: the cheapest per-(GB x FLOPS) unit of the other hosts of this tier). The guide is
    // fetched from the relay (agent.mjs); until it is, the configured price stands.
    this.pricingFile = path.join(cfg.dir, "pricing.json");
    this.pricing = Host.loadPricing(this.pricingFile);
    this.priceGuide = null; this.pricedBy = { cpu: "config", gpu: "config" };
  }
  static loadPricing(file) {
    try {
      const o = JSON.parse(fs.readFileSync(file, "utf8"));
      const ok = (v) => (Number.isFinite(v) && v > 0 && v <= Host.MAX_PRICE_PER_HOUR ? v : null);
      return { cpuPerHour: ok(o.cpuPerHour), gpuPerHour: ok(o.gpuPerHour) };
    } catch { return { cpuPerHour: null, gpuPerHour: null }; }
  }
  static MAX_PRICE_PER_HOUR = 1000;      // USDC an hour for a whole machine or card: anything above is a typo
  static PRICE_DRIFT = 0.10;             // a default that moved less than this keeps the posted price (each change is a transaction)
  #loadState() {
    try { return JSON.parse(fs.readFileSync(this.statePath, "utf8")) || {}; } catch { return {}; }
  }
  #saveTracked() {
    try {
      fs.writeFileSync(this.statePath, JSON.stringify({ tracked: [...this.tracked],
        blocked: Object.fromEntries(this.blocked), ...(this.priceSent ? { priceSent: this.priceSent } : {}) }, null, 1));
    } catch {}
  }

  async init() {
    try {
      await chain.resolveAddresses();
      chain.loadOperator(path.join(this.cfg.dir, "operator.key"));
      chain.loadProofKey(path.join(this.cfg.dir, "proof.key"));
      this.chainReady = true;
      const op = chain.operatorAddress();
      this.log(`chain: registry ${chain.addresses.registry} · deployments ${chain.addresses.deployments}`);
      if (op) {
        const wei = await chain.operatorBalance();
        this.log(`operator ${op} holds ${(Number(wei) / 1e18).toFixed(6)} ETH; enclave id ${this.enclaveId}`);
        if (wei === 0n) this.log("operator has no gas: it can read the ledger but cannot register, claim, renew or prove");
      } else this.log("no operator key on this box: it can run an app it is told about, but cannot hold a lease");
      await this.refreshRegistration();
      await this.ensureRegistered();
    } catch (e) { this.lastError = e.message; this.log(`chain unavailable: ${e.message}`); }
    setInterval(() => this.tick().catch((e) => this.log(`tick: ${e.message}`)), TICK_MS);
    setInterval(() => this.heartbeat().catch(() => {}), HEARTBEAT_MS);
    setInterval(() => this.proveAll().catch((e) => this.log(`proof: ${e.message}`)), PROOF_MS);
    this.tick().catch(() => {});
  }
  async refreshRegistration() {
    try {
      const e = await chain.readEnclave(this.enclaveId);
      this.registered = e && e.endpoint ? e : null;
      // The card half says what this box ASKS (cardPrice) and, when the registry still lists something else, both.
      const listed = Number(e?.gpuPricePerSec6 || 0), ask = this.cardPrice();
      if (this.registered) this.log(`registry: listed as ${e.endpoint} price ${e.cpuPricePerSec6}/sec cpu`
        + `${ask > 0 ? ` + ${ask}/sec card` : ""}${listed !== ask ? `; the registry lists ${listed}/sec for the card, and this box asks ${ask}` : ""}`
        + `, payout ${e.payoutWallet}`);
    } catch (e) { this.lastError = e.message; }
  }
  /** Is this box running apps as isolated domains? False unless a manager is configured. */
  get isolation() { return !!this.cfg.isolationManager; }

  /** The isolation backend this box runs, by name, or null. What a tenant's `require` must match. */
  get isolationBackend() { return this.cfg.isolationManager ? "hyperv-partition-per-app" : null; }

  /** The wallet whose deployments this box will run: the on-chain declaration, else the config. */
  /**
   * ownerSet() -> the lowercase addresses whose deployments this box serves in owner-only scope: its OPERATOR (the key
   * that signs its attach and its claims) and the owner of each valid, unexpired delegation (host-delegation.mjs).
   * Coordinator enclave-87's rule (2026-09-26). The registry's payoutWallet and OWNER_WALLET used to be this box's
   * "owner" and authorize NOTHING now: each is the operator's own statement, with no owner's consent in it, so a
   * payoutWallet naming a victim made the box claim, bill and restart the victim's deployments (enclave-5d). Every
   * owner check - claimPolicy, the ledger scan, the restart gate, the sweep's hold - asks this one set.
   */
  /** The owners an attach carrying `sent` (attachDelegations' list) makes the relay serve: the operator and each sent
   *  delegation's owner, as this host verified it - what a re-attach compares to tell an added owner from a removed one
   *  (hvnode-attach.mjs reattachMode). */
  servedBy(sent = this.attachDelegations()) {
    const bySig = new Map(this.owners.delegations.map((d) => [String(d.signature).toLowerCase(), d.owner]));
    const out = new Set();
    if (this.owners.operator) out.add(this.owners.operator);
    for (const d of sent) { const o = bySig.get(String(d.signature).toLowerCase()); if (o) out.add(o); }
    return [...out].sort();
  }

  ownerSet(now = Math.floor(Date.now() / 1000)) {
    const set = new Set();
    if (this.owners.operator) set.add(this.owners.operator);
    for (const d of this.owners.delegations) if (d.expires > now) set.add(d.owner);
    return set;
  }

  /** The VALID, unexpired delegations this box carries, as the files hold them: what its hv-node attach sends (hvnode-attach.mjs). */
  attachDelegations(now = Math.floor(Date.now() / 1000)) {
    return this.owners.delegations.filter((d) => d.expires > now).slice(0, MAX_DELEGATIONS)
      .map((d) => ({ message: d.message, signature: d.signature }));
  }
  /** A digest of whom this box serves (the operator and the delegations it would send): an attach made under a different
   *  value no longer tells the relay the truth, so the agent attaches again (hvnode-attach.mjs shouldReattach). `sent`
   *  digests a given list instead - the one an attach ACTUALLY carried, so a refresh during the attach's own await
   *  cannot make the recorded version describe a set the relay never got (enclave-5d's review of ab7cdbb0). */
  ownersVersion(now = Math.floor(Date.now() / 1000), sent = null) {
    const sigs = (sent || this.attachDelegations(now)).map((d) => String(d.signature).toLowerCase()).sort();
    return crypto.createHash("sha256").update(JSON.stringify([this.owners.operator || null, sigs])).digest("hex");
  }

  /** Re-read the operator and the delegation files, verifying each (host-delegation.mjs). An invalid one is logged once per reason. */
  async refreshOwners({ recover } = {}) {
    const op = chain.operatorAddress();
    const operator = op ? String(op).toLowerCase() : null;
    const dir = this.cfg.delegationsDir || path.join(this.cfg.dir, "delegations");
    const valid = [], invalid = new Map();
    for (const f of readDelegationFiles(dir)) {
      const v = f.error ? { ok: false, reason: f.error }
        : await verifyDelegation({ message: f.message, signature: f.signature },
            // chain 8453: Base, the chain this node's ledger is on (chain.mjs uses viem's `base`)
            { operator, box: this.cfg.name, chain: 8453, registry: chain.addresses.registry, ...(recover ? { recover } : {}) });
      if (v.ok) valid.push({ file: f.file, owner: v.owner, expires: v.expires, message: f.message, signature: f.signature });
      else {
        invalid.set(f.file, v.reason);
        if (this.owners.invalid.get(f.file) !== v.reason) this.log(`delegation ${f.file} ignored: ${v.reason}`);
      }
    }
    this.owners = { operator, delegations: valid, invalid };
    return this.ownerSet();
  }
  /**
   * Put this box on the registry, or keep its entry current. The entry is what gives the box an
   * id (keccak of the endpoint) for a lease to name, and claim() refuses an entry with no price or
   * no proof key. The measurement published here is the VBS enclave's own identity key, so anyone
   * can compare the row against what the relay verified at attach.
   */
  async ensureRegistered() {
    if (!this.chainReady || !this.cfg.appsEnabled || !chain.operatorAddress()) return;
    const proofKey = chain.proofAddress() || "0x0000000000000000000000000000000000000000";
    const priced = this.registered && Number(this.registered.cpuPricePerSec6) > 0;
    const current = priced && this.registered.active
      && String(this.registered.proofKey).toLowerCase() === proofKey.toLowerCase()
      && String(this.registered.operator).toLowerCase() === String(chain.operatorAddress()).toLowerCase();
    if (current) return;
    if (this.registered && String(this.registered.operator).toLowerCase() !== String(chain.operatorAddress()).toLowerCase()
        && String(this.registered.operator) !== "0x0000000000000000000000000000000000000000") {
      this.log(`registry: ${this.cfg.endpoint} belongs to operator ${this.registered.operator}, not this box's key; refusing to re-register`);
      return;
    }
    const args = { endpoint: this.cfg.endpoint, repo: this.cfg.repo || "EnclaveHost/enclave",
      measurement: this.cfg.measurement || "0x0000000000000000000000000000000000000000000000000000000000000000",
      cpuPricePerSec6: this.cfg.cpuPricePerSec6, gpuPricePerSec6: this.cardPrice(), proofKey };
    const wei = await chain.operatorBalance();
    // A NEW box with no gas: EnclaveHostPaymaster pays its first register() once the relay has seen its hardware
    // (sponsor.mjs; set by the agent for an attested hv-node). Only the first registration, and only while the key
    // cannot pay for it itself.
    if (!this.registered && wei < Host.SELF_REGISTER_WEI && typeof this.sponsorRegister === "function") {
      if (Date.now() < (this._sponsorRetryAt || 0)) return;
      try {
        const r = await this.sponsorRegister(args);
        this.log(`registry: registered ${this.cfg.endpoint} with the host paymaster paying (no gas needed; tx ${r.tx})`);
        await this.refreshRegistration();
      } catch (e) {
        // the relay has not seen this box's attach yet (it attaches seconds after start-up): ask again within the minute,
        // not in 10 - a new host waited 10 minutes to register over a 5-second race (nucbox-k11-2, 2026-10-12)
        const early = /no attested tunnel|unknown_tunnel|no_claimant|without naming its operator key/.test(e.message);
        this._sponsorRetryAt = Date.now() + (early ? 30_000 : 600_000);
        this.log(`registry: ${e.message}; asking again in ${early ? "30 seconds (once this box's attach is accepted)" : "10 minutes"}`
          + `${!early && wei === 0n ? ", or send the operator key a little Base ETH" : ""}`);
      }
      return;
    }
    if (wei === 0n) { if (!this._gasNagged) { this._gasNagged = true; this.log(`registry: ${chain.operatorAddress()} has no gas; send it a little Base ETH and this box registers itself`); } return; }
    try {
      const { id, hash } = await chain.registerBox(args);
      this.log(`registry: registered ${this.cfg.endpoint} id=${id} price=${this.cfg.cpuPricePerSec6}/sec proofKey=${proofKey} tx=${hash}`);
      await this.refreshRegistration();
    } catch (e) { this.log(`registry: register failed: ${e.shortMessage || e.message}`); }
  }
  /**
   * What this box asks for its whole card, per second, in USDC 6dp - and zero unless there IS a
   * card answering right now. A price posted for silicon whose worker is down would have the
   * ledger sell a share this box cannot deliver.
   */
  /** Does this node sell a card at all? Not with the engine retired (gpu:false): the card was reached only through the
   *  enclave's model, so its desired card price is 0. */
  sellsCard() { return this.cfg.engineRetired !== true || (this.partitionOffers("gpu") && this.managerInference?.ready === true); }
  cardPrice() {
    if (!this.sellsCard()) return 0;
    const card = this.card();
    return card && Number(card.vramBudgetGb) > 0 ? Number(this.cfg.gpuPricePerSec6) || 0 : 0;
  }
  /**
   * Keep the REGISTRY's asks in step with what this box actually offers. The entry is what the
   * ledger charges, so the card became sellable here only when this transaction landed: publishing
   * a pool in /availability while the registry says the card costs nothing would have the platform
   * hand it out for free.
   */
  // A sent price transaction is not sent again for this long while the registry read still shows the old value.
  static PRICE_SETTLE_MS = 10 * 60_000;
  /**
   * NO transaction when the chain already equals what this box asks; ONE when it does not, remembered across restarts
   * (priceSent in host-state.json) so a restart inside a lagging read does not repeat it. `setPrices` and `now` are
   * parameters so a test can count transactions (test/windows-node-price-once.test.mjs).
   */
  async ensurePriced({ setPrices = (...a) => chain.setPrices(...a), now = Date.now() } = {}) {
    if (!this.chainReady || !this.registered || !chain.operatorAddress()) return;
    // both asks: the CPU's (the owner's override, or the default from the network's prices) and the card's
    // The CPU price: not the configured fallback before the network's prices are known (setPriceRows). Right after a
    // start cfg holds that fallback, and posting it overwrote the market price on the registry only for the default
    // read a minute later to post it back - two transactions per restart (2026-10-12). Until then the price already on
    // the registry stands (an owner's override, and a box with none posted yet, go ahead). The card's price is posted
    // as before: a worker that stops must take it off at once.
    const onChainCpu = Number(this.registered.cpuPricePerSec6 || 0);
    const keepCpu = !this.priceGuide && !this.pricing?.cpuPerHour && onChainCpu > 0;
    // The card's the same way while it is for sale: before the guide is known, the price on the registry stands (the
    // configured fallback was posted at every start and the default posted back a minute later, two transactions per
    // restart: 2026-10-14 06:21 and 06:23 on k11-4). A card that is not for sale is still taken off at once (0).
    const ask = this.cardPrice(), onChainGpu = Number(this.registered.gpuPricePerSec6 || 0);
    const keepGpu = ask > 0 && !this.priceGuide && !this.pricing?.gpuPerHour && onChainGpu > 0;
    const cpu = keepCpu ? onChainCpu : Number(this.cfg.cpuPricePerSec6) || 0, want = keepGpu ? onChainGpu : ask, key = `${cpu}/${want}`;
    if (cpu <= 0) return;
    if (Number(this.registered.cpuPricePerSec6 || 0) === cpu && Number(this.registered.gpuPricePerSec6 || 0) === want) {
      if (this.priceSent) { this.priceSent = null; this.#saveTracked(); }
      return;
    }
    const sent = this.priceSent;
    if (sent && String(sent.want) === key && now - Number(sent.at) < Host.PRICE_SETTLE_MS) return;   // in flight: the read lags it
    if ((this.gasRenewals ?? 1) <= 0) return;
    try {
      const hash = await setPrices(this.enclaveId, cpu, want);
      this.priceSent = { want: key, at: now, tx: String(hash) }; this.#saveTracked();
      this.log(`registry: prices now ${cpu}/sec cpu, ${want}/sec card (were ${this.registered.cpuPricePerSec6 || 0}, ${this.registered.gpuPricePerSec6 || 0}) tx=${hash}`);
      await this.refreshRegistration();
    } catch (e) { this.log(`registry: setPrices failed: ${e.shortMessage || e.message}`); }
  }

  // ---- prices: the owner's override or the network's default (price-guide.mjs) -----------------------------------------
  /** This box's priced capacity: the CPU (app memory budget GB x measured GFLOPS) and the card it sells, if any. */
  pricedCapacity() {
    const cpu = { gb: Number(this.capacity({ capped: false }).ramMbPool || 0) / 1024, flops: Number(this.cfg.gflops) || 0 };
    const c = this.sellsCard() ? this.card() : null;
    const gb = Number(c?.vramBudgetGb || c?.vramGb || 0), tflops = Number(c?.cardTflops || 0);
    return { cpu, gpu: gb > 0 && tflops > 0 ? { gb, flops: tflops } : null };
  }
  /** The relay's /enclaves rows -> the guide this box prices from (itself left out), and the prices re-applied. */
  setPriceRows(rows) {
    this.priceGuide = priceGuide(rows, { exclude: this.cfg.name });
    this.applyPrices();
  }
  /** The tiers this box sells in: a Shield PC's CPU is "cpu" and its card "gpu" (no CPU TEE on this host). */
  priceTiers() { return rowTiers({ mode: "hv-node", availability: { shielded: this.pricedCapacity().gpu ? { vramGb: 1 } : null } }); }
  /** Set cfg's asks from the override or the default; a default that drifted less than PRICE_DRIFT keeps the posted one. */
  applyPrices() {
    const cap = this.pricedCapacity(), tiers = this.priceTiers();
    for (const [axis, key] of [["cpu", "cpuPricePerSec6"], ["gpu", "gpuPricePerSec6"]]) {
      const over = this.pricing[`${axis}PerHour`];
      const def = this.priceGuide && cap[axis] && tiers[axis] ? defaultPrice(this.priceGuide, tiers[axis], cap[axis].gb, cap[axis].flops) : null;
      const cur = Number(this.cfg[key]) || 0;
      let next = cur, by = this.pricedBy[axis];
      if (over) { next = perSec6Of(over); by = "owner"; }
      else if (def) {
        // the drift is measured against what the market already sees: the default this node set, or (first time after a
        // start, an update, a re-measured GFLOPS) the price on the registry - so a restart sends no price transaction
        const ref = by === "default" ? cur : Number(this.registered?.[key] || 0);
        next = !ref || Math.abs(def.perSec6 - ref) / ref >= Host.PRICE_DRIFT ? def.perSec6 : ref;
        by = "default";
      }
      if (next !== cur) this.log(`price: ${axis} ${(by === "owner" ? over : perHourOf(next)).toFixed(4)} USDC/hr (${by === "owner" ? "set by the owner" : def?.from ? `the cheapest ${def.tier} unit is ${def.from}'s` : `the network default for ${def?.tier}`}; was ${perHourOf(cur).toFixed(4)})`);
      this.cfg[key] = next; this.pricedBy[axis] = by;
    }
  }
  /** GET /v1/local/hosting's `pricing`: each axis's posted price, its default and where it came from, the override. */
  pricingView() {
    const cap = this.pricedCapacity(), tiers = this.priceTiers(), out = {};
    for (const [axis, key] of [["cpu", "cpuPricePerSec6"], ["gpu", "gpuPricePerSec6"]]) {
      if (!cap[axis]) { out[axis] = null; continue; }
      const def = this.priceGuide ? defaultPrice(this.priceGuide, tiers[axis], cap[axis].gb, cap[axis].flops) : null;
      out[axis] = { perHour: perHourOf(this.cfg[key]), tier: tiers[axis], gb: cap[axis].gb, flops: cap[axis].flops,
                    override: this.pricing[`${axis}PerHour`],
                    default: def ? { perHour: def.perHour, from: def.from, unitPerHour: def.unit } : null };
    }
    return out;
  }
  /** The owner's prices (null: the default). Persisted, then applied; the registry follows on the next tick. */
  setPriceOverride(next) {
    const bad = (m) => Object.assign(new Error(m), { status: 400, code: "bad_price" });
    if (!next || typeof next !== "object" || Array.isArray(next)) throw bad("the body is { cpuPerHour, gpuPerHour }");
    const extra = Object.keys(next).filter((k) => !["cpuPerHour", "gpuPerHour"].includes(k));
    if (extra.length) throw bad(`unknown field ${JSON.stringify(extra[0]).slice(0, 40)}: only cpuPerHour and gpuPerHour can be set`);
    const pricing = { ...this.pricing };
    for (const k of ["cpuPerHour", "gpuPerHour"]) {
      if (!(k in next)) continue;
      const v = next[k];
      if (v === null) { pricing[k] = null; continue; }
      if (typeof v !== "number" || !Number.isFinite(v) || v <= 0 || v > Host.MAX_PRICE_PER_HOUR)
        throw bad(`${k} is a price in USDC per hour, above 0 and at most ${Host.MAX_PRICE_PER_HOUR}, or null for the default`);
      pricing[k] = v;
    }
    fs.mkdirSync(path.dirname(this.pricingFile), { recursive: true });
    fs.writeFileSync(this.pricingFile + ".tmp", JSON.stringify(pricing, null, 1) + "\n"); fs.renameSync(this.pricingFile + ".tmp", this.pricingFile);
    this.pricing = pricing;
    this.applyPrices();
    return this.pricingView();
  }
  async heartbeat() {
    if (!this.chainReady || !chain.operatorAddress() || !this.registered) return;
    // A box reached through a relay tunnel (its endpoint is <relay>/t/<name>) is NOT heartbeated on chain: the relay holds
    // its liveness (the tunnel row's lastSeen), the dialed-discovery staleness filter never applies to a tunnel row, and no
    // contract reads lastSeen. The transaction was gas burnt every 10 minutes by an idle box, 144 a day, and the one gas
    // cost a new host had before earning anything (nucbox-k11-2, 2026-10-12).
    if (!Host.isTunnelEndpoint(this.cfg.endpoint))
      try { await chain.heartbeatBox(this.enclaveId); } catch (e) { this.log(`heartbeat failed: ${e.shortMessage || e.message}`); }
    await this.warnLowGas();
  }
  static isTunnelEndpoint(endpoint) { return /^https:\/\/[a-z0-9.-]+\/t\/[a-z0-9][a-z0-9-]*$/i.test(String(endpoint || "")); }
  /**
   * Gas runs the lease. A renewal costs about 60k gas (measured: 0.00000036 ETH on Base), a
   * heartbeat and a claim more, so an empty tank does not fail loudly, it just stops renewing and
   * the app quietly goes away at the end of the quantum. Warn while there is still time to top up.
   */
  async warnLowGas() {
    const wei = await chain.operatorBalance().catch(() => null);
    if (wei === null) return;
    const now = Date.now(), { renews, burnPerHour, hoursLeft, low } = gasRunway((this._gasSamples ||= []), wei, now);
    if (low && now - (this._gasWarnedAt || 0) > 3600_000) {
      this._gasWarnedAt = now;
      this.log(`operator gas is low: ${(Number(wei) / 1e18).toFixed(6)} ETH`
        + (hoursLeft !== null ? `, about ${Math.round(hoursLeft)} hours at the measured ${(burnPerHour / 1e18).toFixed(6)} ETH/h` : `, about ${renews} renewals left`)
        + `. Top up ${chain.operatorAddress()} or apps stop renewing and go away`);
    }
    this.gasRenewals = Number(renews);
    this.gasHoursLeft = hoursLeft === null ? null : Math.round(hoursLeft);
    this.gasLow = low;
  }

  /** The loopback port a server-shaped app binds inside the enclave. Stable per deployment id so
   * a restart lands on the same one, and clear of the ephemeral range. */
  #portFor(id) {
    const base = this.cfg.portBase + 64;
    const n = parseInt(id.slice(2, 10), 16) % 64;
    return base + n;
  }

  /** When this box's registry entry was created: the date its disclosure became visible. */
  listedAt() { return Number(this.registered?.registeredAt || 0); }

  /**
   * Consider a deployment: the policy first, then the chain, then the app.
   * `invited` is the deploy console's target pick arriving as a claim hint that names this box -
   * the buyer choosing it, which is the consent the policy looks for on an older deployment.
   */
  async consider(id, { force = false, invited = false } = {}) {
    id = String(id).toLowerCase();
    if (!/^0x[0-9a-f]{64}$/.test(id)) return { accepted: false, reason: "id must be the bytes32 deployment id" };
    if (!this.chainReady) return { accepted: false, reason: `chain unavailable: ${this.lastError}` };
    await this.refreshOwners();
    if (this.blocked.has(id)) {
      if (!force) {
        const reason = this.blocked.get(id);
        this.#record(id, { status: "failed", reason });
        return { accepted: false, reason };
      }
      // Forced: the operator is saying try again (a new version, a fixed runtime, a wiped cache).
      this.blocked.delete(id); this.#saveTracked();
      this.log(`unblocking ${id.slice(0, 10)}: a forced claim overrides "${this.records.get(id)?.reason || "an earlier failure"}"`);
    }
    let d; try { d = await chain.readDeployment(id); } catch (e) { return { accepted: false, reason: `ledger read failed: ${e.shortMessage || e.message}` }; }
    // The catalog version is read BEFORE the policy, not after: two of the policy's answers live
    // in the version config and nowhere else - the publisher's `gpuOptional` (may a card-dialled
    // app run on cores) and their `cpuFallback` (how much node RAM it needs when it does). A
    // catalog read that fails leaves them undeclared, which fails closed in both cases.
    let v = null;
    try { v = await chain.resolveAppRef(d.appRef); } catch (e) { this.#record(id, { reason: `catalog: ${e.message}` }); }
    // Sized beside the OTHERS (exclude), and work that already OCCUPIES this box is not measured against the owner's
    // hosting cap: a hint for a deployment this box runs is not a new claim, and lowering a cap never takes a running
    // app away (hosting.mjs). Measured against itself, or against a cap below what runs, it would be marked refused.
    const here = Host.occupies(this.records.get(id) || {});
    const refuse = this.claimRefusal(d, { version: v, capacity: this.capacity({ exclude: id, capped: !here }),
                                          appsEnabled: this.cfg.appsEnabled, invited: invited || force });
    if (refuse) { this.#record(id, { status: "refused", reason: refuse, appRef: d?.appRef || "" }); return { accepted: false, reason: refuse, standing: "refused" }; }
    // A deployment for the ISOLATED backend that this box would still have to CLAIM is judged by the partition verdict
    // first: nothing is tracked and no chain call is made for one it would refuse or cannot judge (#preclaimVerdict).
    const heldHere = String(d.runner || "").toLowerCase() === this.enclaveId.toLowerCase() && Number(d.leaseUntil) * 1000 > Date.now();
    if (!heldHere && this.isolation) {
      let envOpts = {}, envRead = false;
      try { envOpts = chain.parseEnvelope(d.configCid, d.gpuMilli) || {}; envRead = true; } catch { envRead = false; }
      if (envRead && chain.isolationForBackend(envOpts, this.isolationBackend)) {
        const pre = await this.#preclaimVerdict(id, d, v, { envOpts, envRead, force });
        if (pre) return pre;
      }
    }
    this.tracked.add(id); this.#saveTracked();
    const ours = String(d.runner || "").toLowerCase() === this.enclaveId.toLowerCase();
    const live = Number(d.leaseUntil) * 1000 > Date.now();
    if (!(ours && live)) {
      if (!chain.operatorAddress()) { this.#record(id, { status: "queued", reason: "no operator key on this box: cannot claim", appRef: d.appRef }); return { accepted: false, reason: "no operator key on this box" }; }
      if (!this.registered) { this.#record(id, { status: "queued", reason: "this box is not registered on the ledger yet", appRef: d.appRef }); return { accepted: false, reason: "not registered" }; }
      // Ask the ledger whether IT would let this box claim, before spending gas finding out. It is
      // the authority on the two things this box cannot see in a record: whether the deployment's
      // rate cap covers what this box's registry entry charges, and whether the balance covers a
      // quantum at that rate. A reverted claim costs nothing but says nothing either, and a tenant
      // reading "Queued" deserves the reason.
      try {
        const ok = await chain.claimableBy(id, this.enclaveId);
        if (!ok) {
          const reason = "the ledger will not let this box claim it: its rate cap, its funded balance or a live lease says no"
            + ` (this box charges ${this.cfg.cpuPricePerSec6}/sec per whole node, ${Math.round(Number(d.cpuMilli) / 10)}% of it here)`;
          this.#record(id, { status: "queued", reason, appRef: d.appRef });
          return { accepted: false, reason, standing: "queued" };
        }
      } catch (e) { this.log(`claimableBy ${id.slice(0, 10)}: ${e.shortMessage || e.message}`); }
      // claimAttempted: this call went on to a claim TRANSACTION - what spends the ledger scan's one claim per pass. It is
      // carried through ANY later throw (the launch's relay read, its spawn cap, a giveUp's chain tx): a claim once sent
      // must count, or a throw after it lets a second claim go out in the same pass (enclave-bf's NO-GO on 3d37709a).
      let hash;
      try {
        const fresh = await chain.readDeployment(id);
        const pinRefusal = chain.placementRefusal(fresh.configCid, this.enclaveId);
        if (pinRefusal) return { accepted: false, reason: pinRefusal };
        this.#record(id, { status: "claiming", appRef: d.appRef });
        hash = await chain.claimDeployment(id, this.enclaveId);
      } catch (e) {
        const reason = `claim failed: ${e.shortMessage || e.message}`;
        this.#record(id, { status: "failed", reason, appRef: d.appRef }); return { accepted: false, reason, claimAttempted: true, claimFailed: true };
      }
      this.#record(id, { claimedAt: Date.now(), claimTx: hash });
      this.log(`claimed ${id.slice(0, 10)} (tx ${hash})`);
      // the ledger read AFTER a good claim is not the claim: a failure here is not a failed claim (no claimFailed, so the
      // scan's hold does not count it; enclave-bf's note on a1ae8567). The claim is tracked, so tick()'s lease loop resumes it
      try { d = await chain.readDeployment(id); }
      catch (e) {
        const reason = `claimed (tx ${hash}), but the ledger read after it failed: ${e.shortMessage || e.message}; the lease loop launches it`;
        this.#record(id, { reason });
        this.log(`${id.slice(0, 10)} ${reason}`);
        return { accepted: false, reason, claimAttempted: true };
      }
      try { await this.ensureApp(id, d, { force, version: v }); }
      catch (e) { throw Object.assign(e instanceof Error ? e : new Error(String(e)), { claimAttempted: true }); }
      return { accepted: true, status: this.records.get(id)?.status || "unknown", claimAttempted: true };
    }
    await this.ensureApp(id, d, { force, version: v });
    return { accepted: true, status: this.records.get(id)?.status || "unknown" };
  }

  /**
   * restartRefusal(id, d) -> why this box will not restart deployment `id`, or null. `d` is the LEDGER record.
   *
   * A restart re-runs a deployment this box already serves; it never claims one. So it needs this box's own LIVE
   * lease (the ledger's runner is this enclave and the lease has not ended) and, in owner-only scope, the box
   * owner's deployment. ensureApp checks neither: the route used to hand it ANY ledger id, and on the isolation
   * backend that spawned a stranger's opted-in deployment as a partition here, with no claim, no lease and no owner
   * (enclave-b4's N1). consider() is not the gate for this: it claims on chain, and a restart must not.
   */
  restartRefusal(id, d) {
    if (!/^0x[0-9a-f]{64}$/.test(String(id))) return "id must be the bytes32 deployment id";
    if (!d || typeof d !== "object") return "no such deployment on the ledger";
    // stopped on the ledger: nothing to run, whatever the lease says (the sweep would stop it next tick; enclave-bf)
    if (!d.active) return "the deployment is not active on the ledger";
    const ours = String(d.runner || "").toLowerCase() === String(this.enclaveId).toLowerCase();
    if (!ours || !(Number(d.leaseUntil) * 1000 > Date.now()))
      return "this box does not hold a live lease on it, so there is nothing here to restart";
    if (this.servingScope() === "owner-only" && !this.ownerSet().has(String(d.owner || "").toLowerCase()))
      return `this node is in owner-only scope and restarts only its operator's and its delegated owners' deployments (this one is owned by ${d.owner})`;
    return null;
  }

  /** Restart deployment `id` (ledger record `d`) if restartRefusal allows it: { refused: true, reason } or ensureApp's record. */
  async restart(id, d) {
    id = String(id).toLowerCase();
    const refuse = this.restartRefusal(id, d);
    if (refuse) { this.log(`restart ${id.slice(0, 10)} refused: ${refuse}`); return { refused: true, reason: refuse }; }
    return this.ensureApp(id, d, { force: true });
  }

  /**
   * POST /v1/deployments/<id>/restart, whole: WHO is asking, then WHAT may be restarted. -> { status, body }
   *
   * restartRefusal limits what; this limits who. Without it anyone who reached the route could force-restart the
   * owner's deployment again and again, and every forced relaunch of a partition mints a new domain key, ends its
   * sessions and asks the CA for a new certificate: a cheap availability and CA-rate attack (enclave-5d's review of
   * N1). The caller must hold this box's session (session.mjs, minted by its own SIWE login) for the deployment's
   * OWNER - the Linux runner's rule (supervisor.js: ownerAuth, then 404 unless rec.owner is the caller). No verifier
   * fails closed. `read` is the ledger read (chain.readDeployment), a parameter so the whole route can be tested.
   *
   * Or a WALLET SESSION (`Authorization: EnclaveSession v1 ...`, the Linux runner's rule too): verified on chain by
   * cfg.sessionApi with scope api.restart against `request` ({ method, path: the target as received, body: raw bytes }),
   * then the record rule - vault-held in the session's environments, or wallet-held with production + the owner's ledger
   * delegation - judged on the ledger's own owner. A session that may not act gets 403 with the reason.
   */
  async restartRequest(id, headers, { read = (x) => chain.readDeployment(x), request = null } = {}) {
    const j = (status, body) => ({ status, body });
    id = String(id || "").toLowerCase();
    if (!/^0x[0-9a-f]{64}$/.test(id)) return j(422, { error: "bad_id", message: "id must be the bytes32 deployment id" });
    const auth = (headers || {}).authorization;
    let who = null, session = null;
    if (isSessionHeader(auth)) {
      const api = this.cfg.sessionApi;
      if (!api) return j(401, { error: "unauthorized", message: "This box does not accept wallet sessions." });
      if (!request || typeof request.path !== "string")
        return j(401, { error: "unauthorized", message: "This request's target is unknown, so its session signature cannot be checked." });
      try {
        session = await api.verify({ header: auth, method: request.method || "POST", path: request.path, body: request.body,
          scope: "api.restart", fresh: true });
      } catch (e) {
        return j(Number.isInteger(e.status) ? e.status : 503, { error: e.code || "session_check_failed", message: e.message });
      }
    } else {
      who = typeof this.cfg.sessionVerify === "function" ? this.cfg.sessionVerify(headers || {}, id) : null;
      if (!who) return j(401, { error: "unauthorized", message: "Missing or invalid token: a restart needs the owner's session on this box." });
    }
    let d;
    try { d = await read(id); } catch (e) { return j(502, { error: "chain", message: e.shortMessage || e.message }); }
    if (!d || /^0x0{40}$/i.test(String(d.owner || "0x" + "0".repeat(40)))) return j(404, { error: "not_found", id });
    if (session) {
      let why;
      try { why = await this.cfg.sessionApi.refusal(session, { id, owner: d.owner }, { fresh: true }); }
      catch (e) { return j(Number.isInteger(e.status) ? e.status : 503, { error: e.code || "session_check_failed", message: e.message }); }
      if (why) return j(403, { error: "not_allowed", id, message: why });
    // not the owner: the same answer as a deployment that does not exist, as on Linux
    } else if (String(d.owner || "").toLowerCase() !== String(who).toLowerCase()) return j(404, { error: "not_found", id });
    await this.refreshOwners();
    const r = await this.restart(id, d);
    return r.refused ? j(409, { error: "refused", id, reason: r.reason }) : j(200, r);
  }

  /**
   * An owner resized the deployment on-chain (setShares). Honour it, or hand the lease back.
   *
   * The ledger starts billing the new shares at once, so the only two honest outcomes are to serve
   * them or to stop serving. What each axis means HERE:
   *
   *   cpu  an admission and billing figure. An app in this enclave is interpreted bytecode on the
   *        enclave's own threads - there is no cgroup to widen - so a CPU resize changes what the
   *        box has left to sell and what this tenant pays, not a slice anyone can feel. Said
   *        plainly rather than implied by silence.
   *   gpu  real, and it gates the model: the card share rides into VTL1 as ENCLAVE_GPU_MILLI and
   *        the runtime refuses `generate` without it. It is read when the app is opened, so a
   *        change means a restart in place.
   *
   * A resize this box cannot fit is not an error to retry: the lease goes back so a box that does
   * fit can take it.
   */
  async #applyShareResize(id, d, rec) {
    const cpu = this.cpuShareOf(id, d), gpu = Number(d.gpuMilli) / 1000;
    const wasCpu = Number(rec?.servedCpuShare), wasGpu = Number(rec?.servedGpuShare);
    if (!Number.isFinite(wasCpu) || !Number.isFinite(wasGpu)) {
      // First sight of this deployment under the watch: adopt what it is, without a restart.
      this.#record(id, { servedCpuShare: cpu, servedGpuShare: gpu });
      return;
    }
    if (cpu === wasCpu && gpu === wasGpu) return;
    // Does the new size still fit BESIDE the others? Its own old share is excluded, or a tenant
    // growing from 10% to 20% is measured against a box that still counts their first 10%.
    // The owner's hosting cap applies only to an axis that GROWS. Lowering a cap never takes a lease back, so a tenant
    // who shrinks or keeps a share is measured exactly as before the caps existed (capped: false).
    const capped = this.capacity({ exclude: id }), open = this.capacity({ exclude: id, capped: false });
    const cpuRoom = cpu > wasCpu ? capped.cpuShareFree : open.cpuShareFree;
    const gpuRoom = (gpu > wasGpu ? capped.gpuShareFree : open.gpuShareFree) ?? 0;
    const under = (c) => (c ? ` under the owner's ${Math.round(c.offered * 100)}% hosting cap` : "");
    if (cpu > cpuRoom + 1e-9) {
      return await this.#giveUp(id, `it was resized to ${Math.round(cpu * 100)}% of a node and this box has`
        + ` ${Math.round(cpuRoom * 100)}% left${under(cpu > wasCpu && capped.cpuCap)}; handing the lease back so a box that fits can take it`);
    }
    if (gpu > 0 && gpu > gpuRoom + 1e-9) {
      return await this.#giveUp(id, `it was resized to ${Math.round(gpu * 100)}% of this box's card and`
        + ` ${Math.round(gpuRoom * 100)}% of it is left${under(gpu > wasGpu && capped.gpuCap)}; handing the lease back`);
    }
    this.#record(id, { servedCpuShare: cpu, servedGpuShare: gpu });
    if (gpu !== wasGpu) {
      this.log(`resize ${id.slice(0, 10)}: card share ${Math.round(wasGpu * 100)}% -> ${Math.round(gpu * 100)}%,`
        + ` relaunching in place so the enclave sees it`);
      await this.ensureApp(id, d, { force: true });
      return;
    }
    this.log(`resize ${id.slice(0, 10)}: node share ${Math.round(wasCpu * 100)}% -> ${Math.round(cpu * 100)}%`
      + ` (an admission and billing figure here: an app in this enclave is interpreted, not cgroup-sliced)`);
  }

  /**
   * Act on the verdict: stamp, swap the rules live, or relaunch on the new configuration.
   *
   * The restart is IN PLACE and deliberate: the lease, the slot and the certificate are all kept,
   * so what the tenant sees is their app coming back on the configuration they just signed, not a
   * re-placement. An envelope that does not parse leaves the running app exactly as it is.
   */
  async #applyEnvelopeEdit(id, d) {
    const rec = this.records.get(id);
    const cur = String(d?.configCid || "");
    const verdict = this.envelopeVerdict(rec, cur);
    if (verdict === "skip") return;
    if (verdict === "stamp") { this.#record(id, { envelope: cur }); return; }
    if (verdict === "error") {
      let why = "it does not parse";
      try { chain.parseEnvelope(cur, d.gpuMilli); } catch (e) { why = e.message; }
      // Recorded once, not every 30 seconds: a bad edit is a standing fact about the row.
      if (rec.reason !== `the owner's last options edit was not applied: ${why}`)
        this.log(`config edit ${id.slice(0, 10)} NOT applied (the running app keeps its old configuration): ${why}`);
      this.#record(id, { reason: `the owner's last options edit was not applied: ${why}` });
      return;
    }
    let opts = {};
    try { opts = chain.parseEnvelope(cur, d.gpuMilli); } catch { return; }
    if (verdict === "waf") {
      // {} not null: the envelope parsed, so "no rules" is KNOWN. null means "could not read",
      // which isolationPlan holds on - so recording null after a live edit that REMOVED the rules
      // would re-hold an isolated deployment forever (enclave-99).
      this.#record(id, { envelope: cur, waf: opts.waf || {} });
      waf.forget(id);                          // new rules, new counters: an old bucket is not the owner's intent
      this.log(`config edit ${id.slice(0, 10)}: protection rules swapped live, no restart`);
      return;
    }
    // "restart": the app's own configuration changed.
    this.#record(id, { envelope: cur, waf: opts.waf || {} });
    waf.forget(id);
    this.log(`config edit ${id.slice(0, 10)}: the app's configuration changed, relaunching it in place`);
    await this.ensureApp(id, d, { force: true });
  }

  /**
   * An owner edited the deployment's options envelope on-chain (setConfig). Does the SERVING app
   * re-apply, and how?
   *
   * MIRRORED FROM THE PLATFORM RUNNER (supervisor.js envelopeEditVerdict) and checked against its
   * own self-test seam. The envelope is mutable on the ledger but was only ever read when the
   * lease was claimed; this is what makes an edit reach an app that is already running.
   *
   *   "skip"    nothing changed, or this is not a record we serve
   *   "stamp"   a record from before this watch existed: adopt the current value WITHOUT a
   *             restart, because rolling the feature out must not restart every tenant
   *   "waf"     only the protection rules changed: swap them live, no restart
   *   "restart" the app's configuration changed: relaunch it on the new ENCLAVE_CONFIG
   *   "error"   the new envelope does not parse under THIS build's rules: keep the old
   *             configuration serving and say why. The claim gate's fail-closed refusal cannot
   *             apply to something already running - tearing a tenant down because their NEXT
   *             edit was invalid would punish them for a typo.
   */
  envelopeVerdict(rec, chainCid) {
    if (!rec || rec.status !== "running") return "skip";
    const cur = String(chainCid || "");
    if (rec.envelope == null) return "stamp";
    if (rec.envelope === cur) return "skip";
    let oldO = {}, newO;
    try { oldO = chain.parseEnvelope(rec.envelope); } catch { /* a stale unparsable stamp reads as no options */ }
    try { newO = chain.parseEnvelope(cur); } catch { return "error"; }
    // "config absent" (use the version's) and "config: {}" (explicitly empty) are different owner
    // intents, so null and "{}" stay distinct. The CID rides the same key: repointing it at a
    // different pinned document is a config change even when the inline part is byte-identical.
    const cfg = (o) => (o.config !== undefined || o.configCid)
      ? JSON.stringify([o.configCid || "", o.config !== undefined ? o.config : null]) : null;
    return cfg(newO) === cfg(oldO) ? "waf" : "restart";
  }

  /**
   * The deployment's relay-stored secrets, fetched as its lease holder and kept in memory.
   *
   * This is the one thing on this box that the app gets and the operator does not: the values go
   * into the enclave with the app's environment and are never written down. A refusal is recorded
   * and NOT fatal by itself - an app whose config references a secret it did not get will say so
   * itself, and that reason is more useful than this box guessing.
   */
  async loadSecrets(id) {
    if (!this.cfg.secretsSign) return null;
    const r = await fetchSecrets({ id, endpoint: this.cfg.endpoint, sign: this.cfg.secretsSign,
                                   base: this.cfg.relayBase, log: (m) => this.log(m) });
    if (r.count > 0) {
      this.secrets.set(id, r.env);
      this.#record(id, { secrets: r.count });
      this.log(`secrets: ${r.count} for ${id.slice(0, 10)} (${Object.keys(r.env).join(", ")})`);
    } else { this.secrets.delete(id); }
    return r;
  }

  /**
   * true / false / null for "does this deployment have relay-stored secrets?", where null means
   * NOT KNOWABLE on this box rather than "no". The distinction is the whole point: a caller that
   * turns null into false has assumed exactly what it was asked to establish.
   */
  async #secretsState(id) {
    // WHETHER there are staged secrets - the only thing a partition's plan needs, since a partition is never handed
    // them - from the relay's unauthenticated, lease-free /v1/secrets/exists (secrets.mjs secretsExist). It used to FETCH
    // them as the lease holder, which (a) cannot be asked before a claim, (b) is refused for a lease holder the relay
    // does not hold eligible (403 since U7: d1's live test 1 was held on it), and (c) pulled plaintext into this host
    // (N4). Anything but a clear answer is null: UNKNOWN, which holds - and, before a claim, claims nothing.
    // Secrets this box already HOLDS for the lease are a known answer (the in-enclave path fetches them; an isolated
    // deployment never does, so for it this is only ever a test's "known: none").
    if (this.secrets.has(id)) return Object.keys(this.secrets.get(id) || {}).length > 0;
    // No relay configured = no one to ask: unknown. Never a default address - a Host built without relayBase (a test)
    // must not reach a live relay.
    if (!this.cfg.relayBase) return null;
    try { return await secretsExist({ id, base: this.cfg.relayBase }); }
    catch (e) { this.log(`${String(id).slice(0, 10)} ${e.message}`); return null; }
  }

  /**
   * isolationVerdict(id, d, v, { envOpts, envRead }) -> node-bridge.mjs isolationPlan's answer for this deployment: the
   * SAME verdict before a claim (consider) and at spawn (#isolationReconcile), from the same inputs - the ledger record,
   * the catalog version, the config the app would run with, whether secrets are staged (the relay's lease-free exists
   * probe), the envelope's protection rules and config override (envOpts, parsed ONCE by the caller; unknown when the
   * envelope could not be read), the model volumes the version needs, the manager's /health, and its pinned runtime.
   * Its rules and its refusals are node-bridge's (UNKNOWN is not NO: an input that cannot be established is unknown).
   */
  async isolationVerdict(id, d, v, { envOpts = {}, envRead = false } = {}) {
    const { IsolationManagerClient } = await import("./isolation-client.mjs");
    const { isolationPlan } = await import("../vbslike/datapath/node-bridge.mjs");
    const client = new IsolationManagerClient({ base: this.cfg.isolationManager });
    // The WHOLE /health object: the plan checks the manager's backend name and its derivations. null = could not ask.
    let managerHealth = null;
    try { managerHealth = (await client.health()) ?? null; } catch { managerHealth = null; }
    this.managerInference = managerHealth?.inference || null;
    if (!managerHealth) this.managerSupports = null;
    // what the manager says it can give a partition (/health supports), for features(): kept when it answered
    if (managerHealth && managerHealth.supports && typeof managerHealth.supports === "object") this.managerSupports = { ...managerHealth.supports };
    // Which model volumes this version needs, from its own config; null (unknown) when the config cannot be read.
    let volumes = null;
    try {
      const cfg = v && v.config ? (typeof v.config === "string" ? JSON.parse(v.config) : v.config) : {};
      volumes = Array.isArray(cfg.volumes) ? cfg.volumes.slice() : [];
    } catch { volumes = null; }
    let appConfig;
    try { appConfig = await this.appConfig(d, v, { strictCid: true }); }
    catch (e) { return { ok: false, input: "appConfig", why: `configuration could not be verified: ${e.message}`, unknown: true }; }
    return isolationPlan({
      deploymentId: id, deployment: d, version: v,
      appConfig,
      configSourceCid: envOpts.configCid || (envOpts.config !== undefined ? "" : String(v?.configCid || "")),
      hasSecrets: await this.#secretsState(id),
      // {} and [] only when known to be none; an unread envelope is unknown - exactly what ensureApp records as `waf`
      waf: envRead ? (envOpts.waf || {}) : null,
      volumes,
      runtimeId: this.cfg.isolationRuntimeId,
      require: envRead && chain.isolationForBackend(envOpts, this.isolationBackend) ? this.isolationBackend : (envOpts.isolationRequire ?? null),
      manager: managerHealth,
      appConfigCid: envRead ? String(envOpts.configCid || "") : null,
    });
  }

  /** Forward public app evidence over its existing partition route. No verdict
   * here can grant marketplace admission; the relay authenticates the report. */
  async shieldEvidence(id, nonce) {
    if (!/^0x[0-9a-f]{64}$/.test(String(id)) || !/^[0-9a-f]{64}$/.test(String(nonce)))
      throw new Error('exact deployment id and 32-byte nonce required');
    const rec = this.records.get(id);
    if (!rec || rec.status !== 'running' || rec.isPublic !== true || !rec.isolation?.instance || !rec.isolation.appId)
      throw new Error('no running public partition for this deployment');
    const { IsolationManagerClient } = await import('./isolation-client.mjs');
    const { viewTransport } = await import('./hvcert.mjs');
    const { readGuestAttestation } = await import('../../isolation/m4/guestd/supervisor-guestcert.mjs');
    return readGuestAttestation({ transport: viewTransport(new IsolationManagerClient({ base: this.cfg.isolationManager })),
      dataAddr: this.cfg.isolationDataAddr, instanceId: rec.isolation.instance,
      expectAppId: rec.isolation.appId, name: appHostFor(id, this.cfg.appZone), nonce: Buffer.from(nonce, 'hex') });
  }

  // A DEFINITE pre-claim refusal is reused for this long while the ledger's inputs are unchanged; whether secrets are
  // staged and what the manager serves are not on the ledger, so they are asked again after it.
  static PRECLAIM_RECHECK_MS = 10 * 60_000;
  /**
   * The partition verdict BEFORE a claim transaction (coordinator enclave-87, from d1's live test 1: 0x31136008 was
   * claimed at 01:00:29Z, tx 0x0340540e, and held 2 s later on "hasSecrets ... not known here"). A deployment this box
   * would refuse, or cannot yet judge, is never claimed: unknown -> queued, nothing spent, asked again next pass;
   * refused -> recorded and STICKY while its ledger inputs are unchanged (PRECLAIM_RECHECK_MS), so nothing re-asks in a
   * loop. `force` (an operator's claim hint) asks again. -> null to go on to the claim, or consider()'s refusal.
   */
  async #preclaimVerdict(id, d, v, { envOpts, envRead, force = false }) {
    const key = JSON.stringify([String(d.appRef || ""), String(d.configCid || ""), String(d.cpuMilli), String(d.gpuMilli), d.isPublic === true]);
    const was = this.preclaim.get(id);
    if (!force && was && was.key === key && Date.now() - was.at < Host.PRECLAIM_RECHECK_MS) {
      this.#record(id, { status: "refused", reason: was.reason, appRef: d.appRef });
      return { accepted: false, reason: was.reason, standing: "refused" };
    }
    const plan = await this.isolationVerdict(id, d, v, { envOpts, envRead });
    if (plan.ok) { this.preclaim.delete(id); return null; }
    const reason = `isolation, before any claim: ${plan.input}: ${plan.why}`;
    if (plan.unknown) {
      this.preclaim.delete(id);
      this.#record(id, { status: "queued", reason, appRef: d.appRef });
      this.log(`${id.slice(0, 10)} not claimed: ${reason}`);
      return { accepted: false, reason, standing: "queued" };
    }
    this.preclaim.set(id, { key, reason, at: Date.now() });
    this.#record(id, { status: "refused", reason, appRef: d.appRef });
    this.log(`${id.slice(0, 10)} not claimed: ${reason}`);
    return { accepted: false, reason, standing: "refused" };
  }

  /**
   * Run this deployment as an isolated domain through the manager, and translate the outcome into
   * this node's record vocabulary. Returns a record when it decided, or null to fall through to the
   * in-enclave path.
   *
   * The lease rule is the client's, not restated here: `held` means the outcome is UNKNOWN, so the
   * lease stays and nothing is retried; only a KNOWN failure frees it.
   */
  /**
   * The parameters this deliberately does NOT take: `memMb` and `port`. It used to be handed both,
   * and when the branch moved above their declarations ensureApp threw `memMb is not defined` on
   * every deployment - so the real ensureApp never reached the manager at all (enclave-5d, running
   * it for real). Neither was used: the policy's memMiB comes from the version's ON-CHAIN memMb
   * through isolationPlan, and the app port from the plan too. Removing them is the fix, not
   * hoisting the declarations, because taking a value you do not use is how it comes back.
   *
   * `envOpts` and `envRead` ARE taken, for the opposite reason: they are used here, they are
   * ensureApp's locals, and reading them as free variables was the SAME ReferenceError one line
   * apart (enclave-5d found it on the rerun after the memMb fix - I corrected one and did not look
   * for the others in the block I had just moved). Passing them makes the dependency a parameter
   * the reader can see instead of a scope accident.
   */
  async #isolationReconcile(id, d, v, { envOpts = {}, envRead = false, relaunch = false } = {}) {
    const { reconcile } = await import("./isolation-lifecycle.mjs");
    const { IsolationManagerClient } = await import("./isolation-client.mjs");
    const client = new IsolationManagerClient({ base: this.cfg.isolationManager });

    const req = this.records.get(id)?.isolationRequired;
    if (req !== true) {
      if (req === undefined || req === null) this.log(`${id.slice(0, 10)} isolation: the deployment's envelope was not read for an isolation requirement; not isolating`);
      return null;      // fall through: not an error, just not this backend
    }
    // A reboot recovery that did not end serving (#rebootHold) is not tried again by a routine pass: only an operator's
    // forced relaunch clears it (ensureApp).
    const rebootHeld = this.records.get(id)?.rebootHeld;
    if (rebootHeld) return this.#record(id, { status: "held", reason: rebootHeld });

    // THE SAME VERDICT consider() asked before the claim (isolationVerdict): one set of inputs, one answer.
    const plan = await this.isolationVerdict(id, d, v, { envOpts, envRead });
    if (!plan.ok) {
      const why = `isolation: ${plan.input}: ${plan.why}`;
      if (plan.unknown) {
        this.log(`${id.slice(0, 10)} ${why}`);
        // planHeld: this box will not provision it until the input is established, so the tick does not RENEW it (87)
        return this.#record(id, { status: "provisioning", reason: why, planHeld: true });
      }
      return await this.#giveUp(id, why);
    }
    if (this.records.get(id)?.planHeld) this.#record(id, { planHeld: null, noRenewSaid: null });

    // A lapsed hosting lease or readiness timeout may already have retired the
    // ended VM. Keep its service cooldown before reconcile can spawn an absent
    // instance. The host's normal lease policy still stops billing while held.
    const pendingRestart = this.#respawnAfter.get(id);
    if (pendingRestart && Date.now() < pendingRestart.until)
      return this.#record(id, { status: "provisioning", reason: pendingRestart.reason });

    const body = IsolationManagerClient.spawnBody(plan.spawn);
    // What this partition holds of the card is what it is spawned with, not what the lease bought: the accounting the
    // owner's GPU cap and the tray read (shareUse).
    this.#record(id, { partitionGpuShare: Number(body.gpuShare) || 0 });
    const capHeld = await this.#spawnCapHold(id, body, client, { relaunch });
    if (capHeld) return capHeld;
    if (this.records.get(id)?.capHeld) this.#record(id, { capHeld: null });
    // A DOMAIN RUNNING ANOTHER VERSION of this deployment is not adopted. When the owner switches the version on the
    // ledger (setAppRef: another catalog version or component), the domain the manager holds under this name still runs
    // the old one, and adopting it by name served the old version forever while the relay refused it as "not the
    // requested app" (2026-10-13 22:16Z: cron stayed on /1 after its switch to /2, down until retired by hand). It is
    // retired, confirmed gone, and the current version is spawned below. A manager that does not say which version it
    // runs is not second-guessed.
    const stale = await IsolationManagerClient.staleVersion(client, id, body.derive).catch(() => null);
    if (stale) {
      this.log(`${id.slice(0, 10)} isolation: version change: ${stale}; replacing the domain`);
      const gone = await this.#retireIsolated(id, `version change: ${stale}`);
      if (!gone) return this.#record(id, { status: "provisioning", reason: `isolation: version change (${stale}); the old domain `
        + "could not be confirmed removed, so nothing new is started" });
    }
    let r;
    try { r = await reconcile({ client, deployment: { id, body }, ledger: null }); }
    catch (e) { return this.#record(id, { status: "failed", reason: `isolation: ${e.message}` }); }

    // RECOVERY AFTER A MANAGER OR HOST RESTART (enclave-87's ruling (B) and its amendment from d1's live A8). A VM the
    // restarted manager lists `recovered` can never serve again: its relay and its launcher's per-process report key
    // belonged to the previous manager, so nothing can vouch for it, and RECOVERED's hold stranded the deployment until an
    // operator acted - after a host restart (the launcher's AutomaticStartAction Nothing leaves it Off, running nothing)
    // AND after a manager-only restart (still Running, but never judged or relayed again). So a recovered VM, in any state,
    // is RETIRED through the manager (confirmed gone), and ONE fresh partition is spawned inside the same lease: a new key
    // and a fresh measured boot, nothing released, never a second VM, and the recovered VM never served. Any failure on
    // this path HOLDS the deployment (rebootHeld: not retried, not renewed) until a forced re-ensure (an operator's
    // relaunch, or an owner's resize or config edit: ensureApp). This is
    // NOT the crash respawn below (ENCLAVE_ISOLATION_RESPAWN, off by default): a restart is not the app ending.
    if (r.action === "held" && r.instance && r.instance.recovered === true) {
      const dead = r.instance.id, state = r.instance.vmState || "state unknown";
      this.#record(id, { isolationHeld: dead });
      const gone = await this.#retireIsolated(id, `restart recovery: the recovered VM ${dead} (${state})`);
      if (!gone) return this.#rebootHold(id, `the recovered VM ${dead} (${state}) could not be confirmed removed`, dead);
      this.log(`${id.slice(0, 10)} restart recovery: the recovered VM ${dead} (${state}) was retired; starting ONE fresh partition`);
      try { r = await reconcile({ client, deployment: { id, body }, ledger: null }); }
      catch (e) { return this.#rebootHold(id, `the fresh partition could not be started: ${e.message}`); }
      if (r.action === "failed") return this.#rebootHold(id, `the fresh partition did not come up: ${r.reason}`, r.instance?.id ?? null);
      if (r.action === "held" && r.instance?.recovered === true)
        return this.#rebootHold(id, `the fresh partition is a recovered VM again (${r.instance.id}): ${r.reason}`, r.instance.id);
      // spawned/adopted: served below as any fresh domain; "held" (an unknown outcome) is recorded below as always
    }

    // RESPAWN, OFF BY DEFAULT (cfg.isolationRespawn, ENCLAVE_ISOLATION_RESPAWN=1): a lease policy, Steven's decision,
    // put to him by enclave-d1. Today a domain that ENDED (crashed, stopped by itself, failed the manager's sweeps, or
    // missed the readiness deadline) makes the node give the lease up: it is released on chain AND blocked on this box,
    // which for an owner-only NucBox deployment is effectively permanent. With the switch ON, the ended domain is instead
    // RETIRED, confirmed gone (so there is never a second VM, and nothing is released), and a fresh one is spawned, at
    // most RESPAWN_BUDGET times in RESPAWN_WINDOW_MS per deployment. Explicitly selected services cool down and retry;
    // the global switch retains the old give-up at its budget. A manager REFUSAL is never respawned.
    const serviceRecovery = this.cfg.isolationRespawnIds?.includes(id) === true;
    const respawnEnabled = this.cfg.isolationRespawn === true || serviceRecovery;
    if (r.action === "failed" && r.leaseFree && r.ended === true && respawnEnabled) {
      const spent = this.#respawnsWithin(id);
      const delay = Number(this.cfg.isolationRespawnDelayMs ?? 0);
      if (!Number.isSafeInteger(delay) || delay < 0 || delay > 600_000)
        return this.#record(id, { status: "held", reason: "isolation: invalid respawn delay (expected 0..600000 ms)" });
      if (spent >= RESPAWN_BUDGET) {
        // Explicit service recovery remains recoverable after a prolonged outage.
        // Keep the confirmed-ended instance until the budget opens again, so a
        // routine reconcile cannot spawn around the cooldown. Refusals never enter
        // this path, and retirement must still succeed before any replacement.
        if (serviceRecovery) {
          const until = Math.max(this.#respawns.get(id)[0] + RESPAWN_WINDOW_MS + 1, this.#respawnAfter.get(id)?.until || 0);
          const reason = `isolation: restart budget exhausted; automatic retry after ${new Date(until).toISOString()}`;
          this.#respawnAfter.set(id, { instance: r.instance?.id, until, reason });
          return this.#record(id, { status: "provisioning", reason,
            ...(r.instance?.id ? { isolationHeld: r.instance.id } : {}) });
        }
        r = { ...r, reason: `${r.reason}; it was respawned ${spent} time(s) in the last hour, so it is not respawned again` };
      } else {
        // A stateful service may have fenced itself after an ambiguous storage write.
        // Wait out its storage lease before starting a replacement; an immediate
        // restart can fail on that lease and exhaust the crash budget in seconds.
        if (delay) {
          let waiting = this.#respawnAfter.get(id);
          if (!waiting || waiting.instance !== r.instance?.id) {
            const until = Date.now() + delay;
            waiting = { instance: r.instance?.id, until,
              reason: `isolation: the domain ended; automatic restart after ${new Date(until).toISOString()} (waiting for the service's storage lease)` };
            this.#respawnAfter.set(id, waiting);
          }
          if (Date.now() < waiting.until)
            return this.#record(id, { status: "provisioning", reason: waiting.reason,
              ...(r.instance?.id ? { isolationHeld: r.instance.id } : {}) });
        }
        if (r.instance?.id) this.#record(id, { isolationHeld: r.instance.id });
        const gone = await this.#retireIsolated(id, "respawn after the domain ended", { ended: true });
        if (!gone) {
          return this.#record(id, { status: "provisioning", reason: `isolation: ${r.reason}; not respawned: the ended domain `
            + "could not be confirmed gone, so its lease is kept and nothing new is started" });
        }
        this.#respawnAfter.delete(id);
        this.#respawns.set(id, [...(this.#respawns.get(id) || []), Date.now()]);
        this.log(`${id.slice(0, 10)} isolation respawn ${spent + 1}/${RESPAWN_BUDGET} this hour: ${r.reason}`);
        try { r = await reconcile({ client, deployment: { id, body }, ledger: null }); }
        catch (e) { return this.#record(id, { status: "failed", reason: `isolation: ${e.message}` }); }
        // ended AGAIN at once: the next pass decides (it respawns while the budget lasts, then gives up), not this one
        if (r.action === "failed" && r.leaseFree && r.ended === true) {
          return this.#record(id, { status: "provisioning", reason: `isolation: respawned (${spent + 1}/${RESPAWN_BUDGET} this hour) `
            + `and it ended again: ${r.reason}`, ...(r.instance?.id ? { isolationHeld: r.instance.id } : {}) });
        }
      }
    }

    if (r.action === "held") {
      // NOT a failure and NOT a success: the lease is kept and this tick decided nothing. The instance it holds is
      // RECORDED (enclave-d1's review, finding 3) so a forced relaunch and the lease's end can retire it. It is kept
      // apart from rec.isolation, which is what routes traffic: a held domain is not serving.
      this.log(`${id.slice(0, 10)} isolation held: ${r.reason}`);
      return this.#record(id, { status: "provisioning", reason: r.reason, ...(r.instance?.id ? { isolationHeld: r.instance.id } : {}) });
    }
    // A HOST-WIDE LOSS IS NOT THIS APP FAILING (2026-10-14 14:29Z: Windows Update restarted nucbox-k11-4; while it shut
    // down, each partition in turn was "no longer on this host" and the node gave all eight up: released on chain and
    // blocked here, so after the boot nothing came back until an operator cleared them). A domain that ended ABSENT while
    // most of the domains this node saw serving are absent too (or the manager no longer answers) is a host shutdown or
    // restart: the lease is kept, nothing is released or blocked, and the next pass after the restart starts it again.
    if (r.action === "failed" && r.ended === true && /no longer on this host/.test(String(r.reason || ""))) {
      const wide = await this.#hostWideLoss(client);
      if (wide) {
        this.log(`${id.slice(0, 10)} isolation: its domain is gone with ${wide}: a host shutdown or restart, not this app; `
          + "the lease is kept and nothing is released");
        return this.#record(id, { status: "provisioning", reason: `isolation: host-wide loss (${wide}); waiting for the host` });
      }
    }
    if (r.action === "failed") {
      if (r.leaseFree) return await this.#giveUp(id, `isolation: ${r.reason}`);
      return this.#record(id, { status: "failed", reason: `isolation: ${r.reason}` });
    }
    // adopted or spawned, and serving
    const inst = r.instance || {};
    // If the old domain was already retired, reconcile spawned directly after
    // the wait. Count that replacement against the same crash budget.
    if (this.#respawnAfter.has(id)) this.#respawns.set(id, [...(this.#respawns.get(id) || []), Date.now()]);
    this.#respawnAfter.delete(id);
    // THIS BACKEND'S BOUNDARY, NEVER A STRONGER ONE READ FROM THE MANAGER. The manager is a host process, so the tier and
    // hostExcluded in its view are host statements. hyperv-partition-per-app is T0-hv with the host NOT excluded, and
    // nothing on this node can verify more. A view claiming host exclusion or another tier is a contract violation, from
    // a manager that is wrong or lying: nothing is routed to it, and the lease is HELD with the instance recorded so it
    // can be retired. The record never carries a boundary stronger than this tier's.
    // HELD, and NOT renewed (enclave-99's review of 9b79022c): a boundary refusal is a standing fact about a manager that is
    // wrong or lying, unlike a transient hold (a 503), so the tenant is not billed for a service this box will not give
    // (the tick reads boundaryHeld before it renews). isolation: null, because a record that served on an honest pass and
    // is now refused must not keep a serving block. Every tick re-asks, so an honest manager clears it.
    const boundaryWrong = isolationBoundaryRefusal(inst);
    if (boundaryWrong) {
      this.log(`${id.slice(0, 10)} isolation held, not renewed: ${boundaryWrong}`);
      return this.#record(id, { status: "held", boundaryHeld: true, isolation: null, reason: boundaryWrong,
                                ...(inst.id ? { isolationHeld: inst.id } : {}) });
    }
    // A domain this node saw serving that the manager no longer has (it stopped by itself, crashed, or was removed by
    // its own sweep) is replaced here silently otherwise: say so, with what was last known (2026-10-13 14:13Z: RISC Box's
    // partition turned itself off and a new one appeared with no line saying why). Read from #lastServing, NOT from
    // rec.isolation: any intermediate record may clear that (the respawn's cleanup retire, a boundary hold), and on the
    // 2026-10-14 03:52Z poweroff one did, so the line never fired. Only this node's own retire forgets a domain.
    this.#noteServing(id, inst, r.action);
    this.log(`${id.slice(0, 10)} isolation ${r.action}: ${inst.id} status=${inst.status} image=${inst.image || "?"}`);
    return this.#record(id, { status: "running", reason: null, isolationHeld: null, boundaryHeld: null,
                              // when this pass last saw it serving: what proveAll's checkpoint stands on
                              servingSeenAt: Date.now(),
                              isolation: { backend: "hyperv-partition-per-app", instance: inst.id,
                                           // appId is REQUIRED by isolatedTarget; without it the
                                           // app-zone route cannot name what it is splicing to
                                           appId: inst.appId ?? null,
                                           image: inst.image ?? null,
                                           // NORMALISED to the contract's spelling. The HCS backend's
                                           // BOUNDARY says "t0-hv" and start() hands it up verbatim, but
                                           // judge-hv and the splice's routeFor use "T0-hv" - so every
                                           // partition would have been read as an SNP guest and refused
                                           // for "not stating a whole verified identity" (enclave-5d).
                                           // They made routeFor case-insensitive; this makes the record
                                           // say the contract's word in the first place.
                                           tier: inst.tier ? String(inst.tier).toUpperCase().replace(/^T0-HV$/, "T0-hv") : null,
                                           // this tier's own word, never the manager's (isolationBoundaryRefusal
                                           // has refused any view claiming more); this is NOT verified capacity
                                           hostExcluded: false,
                                           transportKeySha256: inst.transportKeySha256 ?? null,
                                           // when the manager started this partition (its record's startedAt, ms)
                                           startedAt: Number.isFinite(inst.startedAt) ? inst.startedAt : null } });
  }

  /**
   * THE OWNER'S CAPS ON THE ISOLATED BACKEND, at the one step that adds a partition: a NEW spawn. The claim gate
   * (claimPolicy over capacity()) already holds new leases under the caps; this holds the partitions themselves, so a
   * NEW one starts only while the sum of cpuShare over running and starting partitions stays within what the owner offers.
   *
   * It never takes anything away. Not gated: a partition that is already there (reconcile adopts it; refusing to
   * adopt would not stop it, only stop serving it), and a RELAUNCH of work this box already runs - a forced relaunch of
   * a deployment that occupied the box (ensureApp decides), or a domain that vanished while it served (rec.isolation).
   * Forcing a held or never-started deployment is NOT a relaunch. Held work is recorded `capHeld`, is not renewed (the
   * tick) and starts on the first pass that it fits. -> the held record, or null to proceed.
   */
  async #spawnCapHold(id, body, client, { relaunch = false } = {}) {
    const rec = this.records.get(id) || {};
    if (relaunch || rec.isolation) return null;
    const why = this.capRefusal(id, { cpuShare: Number(body.cpuShare) || 0, gpuShare: Number(body.gpuShare) || 0 });
    if (!why) return null;
    // Only now, when the cap would refuse, ask whether a domain is already there: the default path costs no request.
    let existing;
    try { existing = await client.findByName(id); } catch { return null; }   // unknown: reconcile holds on its own
    if (existing) return null;
    const reason = `isolation: ${why}`;
    if (rec.reason !== reason) this.log(`${id.slice(0, 10)} ${reason}`);     // a change is worth a line, every 30 s is not
    return this.#record(id, { status: "held", capHeld: true, reason });
  }

  /** Fetch + verify + run the deployment's app, and keep the record honest about which stage failed. */
  async ensureApp(id, d, { force = false, version = null } = {}) {
    if (force) this.#respawnAfter.delete(id);
    // A FORCED ensure is what a reboot-recovery hold waits for (#rebootHold): it is tried again from here. That is the
    // operator's forced relaunch AND an owner's own action that re-ensures with force - a resize (#applyShareResize) or a
    // config edit (#applyEnvelopeEdit). Intended (enclave-b4's review, enclave-87): an owner acting on their deployment is
    // a reasonable moment to try again, and each such retry is still one attempt, held again if it fails.
    if (force && this.records.get(id)?.rebootHeld) this.#record(id, { rebootHeld: null });
    const rec = this.#record(id, { appRef: d.appRef, leaseUntil: Number(d.leaseUntil),
                                   cpuShare: this.cpuShareOf(id, d, version), gpuShare: Number(d.gpuMilli) / 1000,
                                   // What the data-path gate needs, from the ledger and nowhere else.
                                   isPublic: d.isPublic !== false, owner: String(d.owner || "").toLowerCase() });
    // HELD first, before the catalog read: a yanked version, like every later gate, would otherwise give the
    // lease back on chain (heldReason).
    const held = this.heldReason(d);
    if (held) return this.#record(id, { status: "held", reason: held });
    const pinRefusal = chain.placementRefusal(d.configCid, this.enclaveId);
    if (pinRefusal) return await this.#giveUp(id, pinRefusal, { retry: true });
    // THE ENVELOPE, parsed ONCE and BEFORE the catalog read and every gate that can give the lease back: #giveUp asks
    // #retireIsolated, which must know whether this deployment is isolated at all (unknown means it asks the manager).
    // And before the isolation branch, because the branch's opt-in gate reads what it records. It used to be parsed
    // after that gate, so `isolationRequired` was written after the gate had already read it as absent - and nothing
    // wrote it at all, which is the defect enclave-99 found: the gate could never be satisfied. Through the same parser
    // claimPolicy used, so "accepted at claim" and "applied here" cannot drift.
    let envOpts = {}, envRead = false;
    try { envOpts = chain.parseEnvelope(d.configCid, d.gpuMilli) || {}; envRead = true; }
    catch { envOpts = {}; envRead = false; }
    this.#record(id, {
      // {} = the envelope was read and carries no rules; null = it could not be read at all.
      // `envOpts.waf || null` conflated them, so an ordinary deployment with no WAF rules looked
      // UNKNOWN to isolationPlan and was held forever - every WAF-less deployment permanently
      // un-isolatable, from a line meant to be careful (enclave-99).
      waf: envRead ? (envOpts.waf || {}) : null,
      envelope: String(d?.configCid || ""),
      // true only when the tenant asked for THIS box's backend by name. claimPolicy already
      // refuses a deployment requiring a backend this box does not run, so a mismatch here means
      // the config changed under a live lease.
      // null when the envelope could not be read: UNKNOWN, which #isolationReconcile already treats as "not read" and
      // #retireIsolated as "may have been isolated" (it asks the manager by name rather than assume nothing is there).
      isolationRequired: envRead ? (chain.isolationForBackend(envOpts, this.isolationBackend)) : null,
    });
    let v = version;
    if (!v) try { v = await chain.resolveAppRef(d.appRef); } catch (e) { return this.#record(id, { status: "failed", reason: `catalog: ${e.message}` }); }
    if (v.yanked) return await this.#giveUp(id, "the catalog version is yanked");
    // The CORELESS floor, which is the only kind this box does: the version's own memMb, raised by
    // the publisher's cpuFallback when they declared one. Sizing a fallback off the card-case
    // figure is how a big model lands on a small slice and dies at weight-load with nothing having
    // said no, so the guest's memory cap is the larger number.
    const floor = chain.nodeFloorOf(v);
    this.#record(id, { cid: v.cid, version: v.version, memMb: floor.memMb, cpuFallbackSized: floor.fromFallback,
                       needCpuShare: this.cpuShareOf(id, { cpuMilli: 0 }, v), cpuShare: this.cpuShareOf(id, d, v) });

    // A FORCED re-ensure retires the existing domain first. Without this the reconcile below
    // ADOPTS the live one by name and the deployment keeps running its previous configuration
    // while the record says the new one was applied - a config edit or an artifact override that
    // silently did nothing (defect 15's third path).
    // It retires the instance this node knows of (serving or held), or BY NAME for a deployment known to be isolated
    // when it knows of none (a node that restarted beside a VM the manager recovered: probe H4 of enclave-d1's review).
    const forcedRec = this.records.get(id) || {};
    if (force && (forcedRec.isolation || forcedRec.isolationHeld || forcedRec.isolationRequired === true)) {
      const gone = await this.#retireIsolated(id, "forced relaunch");
      if (!gone) return this.#record(id, { status: "provisioning",
        reason: "the previous isolated domain could not be confirmed gone, so a new one is not started" });
    }

    // THE PER-APP ISOLATION BACKEND, decided HERE - before every gate that judges the IN-ENCLAVE
    // runtime, and before anything that can give the lease back.
    //
    // It used to sit further down, after the artifact-layer, host-interface, appsInTee, world and
    // engine-memory checks. Every one of those calls #giveUp, which RELEASES THE LEASE ON CHAIN
    // when this enclave is the runner - so on a box configured for isolation with no in-enclave
    // runtime, the first ensureApp handed back every isolated lease before the branch was ever
    // reached. enclave-5d measured it end to end: hello-world and hookbin both died at
    // appsInTee, then at the engine-memory check with the flags forced on, and hookbin's
    // wasi:cli world would have died at the world check too.
    //
    // None of those gates is meaningful for this backend: they ask what THIS enclave's runtime can
    // run, and an isolated deployment does not run in this enclave. The manager fetches the
    // component by CID and derives from it itself. What IS needed first is the catalog version,
    // the yanked check and the policy floor, which are above.
    //
    // The opt-in check lives inside the branch, so a deployment that did not ask for isolation
    // returns null here and falls through to the in-enclave path unharmed.
      //
      // Default OFF. Without ENCLAVE_ISOLATION_MANAGER nothing below runs and this node behaves
      // exactly as the deployed build does - which matters, because the bytes running on nucbox-k11
      // are NOT this branch's, and a change that altered the default would take six live apps with
      // it.
      //
      // When it IS set, the deployment's domain is a Hyper-V child partition managed by the
      // manager rather than a process in this enclave, and `reconcile` owns the decision: it adopts
      // a domain that is already there (so a node restart does not run a deployment twice), waits
      // for the manager's own readiness verdict, and HOLDS the lease whenever the outcome is
      // unknown. It never frees a lease on a guess.
      //
      // What it does NOT do: change what this box advertises. A T0-hv partition does not exclude
      // the host, attestedCapacity() is false for it, and nothing here touches meetsIsolationContract().
      if (this.isolation) {
        // A forced ensure is a RELAUNCH (not measured against the owner's cap) only for work that occupied this box
        // before it (forcedRec, read before the retire). Forcing a deployment the cap held, or one that never ran,
        // is a new spawn and is gated like one: the owner's restart must not push the box past its cap (enclave-5d).
        const outcome = await this.#isolationReconcile(id, d, v, { envOpts, envRead, relaunch: force && Host.occupies(forcedRec) });
        if (outcome) return outcome;
      }

    let art;
    // An OPERATOR ARTIFACT OVERRIDE, when one is set for this deployment (see #artifactPatch). It
    // replaces only WHICH BYTES run; the lease, the config, the secrets and the checks below are
    // the catalog version's, unchanged.
    const patched = this.#artifactPatch(id, v);
    if (patched && patched.error) return this.#record(id, { status: "failed", reason: `artifact override: ${patched.error}` });
    if (patched) art = { path: patched.path };
    else {
      try { art = await fetchArtifact({ cid: v.cid, dir: path.join(this.cfg.dir, "apps"), python: this.cfg.python, gateway: this.cfg.gateway, log: (m) => this.log(m) }); }
      catch (e) { return this.#record(id, { status: "failed", reason: `artifact: ${e.message}` }); }
    }
    try {
      const layer = wasmLayer(art.path);
      if (layer !== 1) return await this.#giveUp(id, `the artifact is a core wasm module (layer ${layer}), not a wasi:http component`);
      // What the artifact needs from its runtime, checked BEFORE it is launched: an app built
      // against the platform's patched wasmtime (wasi-nn inference, guest threads) cannot run
      // here, and finding that out by watching it restart while holding the lease is the worst
      // of the available orders.
      const needs = missingHostInterfaces(art.path);
      if (needs.length) return await this.#giveUp(id, `this box cannot run it: the artifact needs ${needs.join(" and ")}. It runs stock wasmtime 49 and carries no model volume; the enclave's own model is reachable at ENCLAVE_INFERENCE_URL instead, which is a different contract`);
    } catch (e) { return this.#record(id, { status: "failed", reason: `artifact: ${e.message}` }); }
    // WHICH WORLD the artifact was built for, read from the bytes rather than from a claim beside
    // them. Only the enclave:app world runs in VTL1: wasi:http needs a socket, a poll loop and a
    // host implementation of wasi:io, none of which exist in an enclave. A tenant whose app is
    // built for that world is told so, and their lease is handed back, rather than having their
    // app quietly run in the Windows session where this box's owner can read it.
    const world = worldOf(fs.readFileSync(art.path));
    if (!this.appsInTee())
      return await this.#giveUp(id, "this enclave image carries no app runtime, so this box cannot host an app inside the enclave and will not host one outside it");
    // Which worlds this enclave image actually serves (a bitmask from the runtime itself):
    // 1 = enclave:app, 2 = wasi:http. An ordinary platform app is world 2 and runs unchanged.
    const worlds = Number(this.cfg.enclaveAppWorlds || 1);
    const want = world === "enclave-app" ? 1 : world === "wasi-http" ? 2 : world === "wasi-cli" ? 4 : 0;
    if (!want || !(worlds & want))
      return await this.#giveUp(id, `this box runs an app INSIDE its VBS enclave. It serves`
        + ` ${worlds & 1 ? "enclave:app@0.1.0" : ""}${(worlds & 3) === 3 ? " and " : ""}${worlds & 2 ? "wasi:http" : ""},`
        + ` and this artifact is built for ${world === "wasi-cli" ? "wasi:cli with wasi:sockets, a server that binds its own"
            + " port: an enclave has no socket to bind and no reactor to poll, so that shape needs the brokered sockets"
            + " that are not built yet" : world}`);
    // Did anybody with the standing to say so declare the card optional? The same two voices
    // claimPolicy listens to: the owner's envelope and the publisher's version config. When they
    // did, a card-dialled deployment runs here on cores and nothing below applies.
    let gpuSoft = envOpts.gpuOptional === true;
    const wafRules = envOpts.waf || null;
    // The owner's protection rules, kept beside the lease so every request can be checked against
    // them without re-parsing the envelope. claimPolicy already refused anything unreadable.
    this.#record(id, { waf: wafRules, envelope: String(d?.configCid || "") });
    gpuSoft = gpuSoft || chain.gpuOptionalOfConfig(v && v.config);
    // TEMPORARY OPERATOR OVERRIDE (ENCLAVE_ALLOW_CARD_WITHOUT_MODEL), for the risc-box milestone.
    // The rule below is right in general - a card share here buys the MODEL, and an app that
    // cannot reach `generate` would be paying for silicon it cannot address - but risc-box bought
    // 1% of the card and wants the enclave for its own compute, not for inference. Until the
    // publisher declares `gpuOptional` on the version, this lets the operator say "I know, run it
    // anyway". Off unless set; windows/PARITY.md lists it with the other relaxations.
    gpuSoft = gpuSoft || this.cfg.allowCardWithoutModel === true;
    // Bought the card, but built for a world that cannot reach it. The model in this enclave is
    // offered through the enclave:app world's `generate` and nowhere else: a wasi:http or wasi:cli
    // artifact has no import that reaches it, so its card share would buy it nothing. Say so and
    // hand the lease back rather than take money for silicon the app cannot address.
    if (Number(d.gpuMilli) > 0 && want !== 1 && !gpuSoft)
      return await this.#giveUp(id, `it bought ${Math.round(Number(d.gpuMilli) / 10)}% of this box's card, and`
        + ` what a share buys here is the model inside the enclave, reached through the enclave:app@0.1.0`
        + ` world's generate. This artifact is built for ${world}, which has no import that reaches it`);
    let app = this.apps.get(id);
    if (app && force) { await app.stop(); this.apps.delete(id); app = null; }
    if (!app) {
      // WHAT THE APP'S OWN CONFIG ASKS FOR, when that is more than the catalog's declared floor.
      //
      // risc-box declares memMb 3072 in the catalog and `ramMiB: 21764` in its config - the guest
      // machine it boots. Given the floor it started, listened, and then died on a 72 KB
      // allocation, which reads as a corrupt app rather than a budget. The config is the app's own
      // statement of what it needs and the node already resolves it for everything else, so it is
      // honoured here too, bounded by what the enclave actually has left.
      let memMb = floor.memMb;
      try {
        const want = Number(JSON.parse(String(await this.appConfigResolved(d, v) || "{}")).ramMiB) || 0;
        // A little headroom: ramMiB is the GUEST's memory and the app needs its own on top.
        if (want > 0 && Math.round(want * 1.1) > memMb) memMb = Math.round(want * 1.1);
      } catch { /* a config that will not parse is the resolver's problem, not this one's */ }
      if (memMb !== floor.memMb)
        this.log(`${id.slice(0, 10)}: the version declares ${floor.memMb} MB but its config asks for`
          + ` a ${Math.round(memMb / 1.1)} MiB guest; giving it ${memMb} MB`);
      this.#record(id, { memMb });
      // Against the budget capacity() computed, not a config number: the enclave is a fixed size
      // and what is left of it is the enclave's size less what the engine holds less what the
      // other apps were promised. A version bigger than that cannot fit however the file is set.
      const cap = this.capacity({ exclude: id });
      if (!cap.ramMeasured)
        return await this.#giveUp(id, "this box has not yet measured what its engine holds of the enclave,"
          + " so it does not know how much memory it can honestly promise; it re-checks every 30 seconds");
      if (memMb > cap.ramMbFree)
        return await this.#giveUp(id, `the version asks for ${memMb} MB and this enclave has ${cap.ramMbFree} MB left`
          + ` of its ${Math.round((Number(this.cfg.enclaveGb) || 0) * 1024)} MB`);
      // Compile once per CID AND per runtime ABI, then keep it. The bytecode is a pure function
      // of the artifact and the compiler's tunables, and the runtime refuses bytecode built with
      // different ones ("compiled without epoch interruption but it is enabled for the host"), so
      // the ABI belongs in the name: a runtime change simply misses the cache instead of loading
      // something it will reject.
      // The cache key carries the runtime's ABI **and its feature mask**, both read from the
      // enclave itself. The ABI alone was not enough: turning a wasm feature on does not change
      // what wasmtime records in a cwasm, so an artifact compiled before the change would be
      // reused unchanged unless someone remembered to bump the ABI by hand. Naming the file after
      // the features removes that human step - any change on either side simply misses the cache.
      const abi = Number(this.cfg.enclaveAppAbi || 0);
      const feats = Number(this.cfg.enclaveAppFeatures || 0);
      const cwasm = path.join(this.cfg.dir, "apps", `${patched ? `local-${patched.sha.slice(0, 16)}` : `ipfs-${v.cid}`}.rt${abi}f${feats}.cwasm`);
      if (!fs.existsSync(cwasm) || fs.statSync(cwasm).size < 64) {
        this.#record(id, { status: "provisioning", reason: "compiling the app to enclave bytecode" });
        try { await precompile({ wasmPath: art.path, outPath: cwasm, exe: this.cfg.precompileExe,
                                 features: this.cfg.enclaveAppFeatures, log: (m) => this.log(m) }); }
        catch (e) {
          // A COMPILE FAILURE THAT NAMES A MISSING WASM FEATURE IS PERMANENT, and the lease must
          // go back. wasmtime says "<feature> must be enabled for <thing>" when an artifact uses
          // something this build does not have, and no amount of retrying changes that - while the
          // lease keeps running and the tenant keeps paying for an app that will never start.
          //
          // Found live: this box claimed risc-box 0.6.15, whose catalog config does NOT declare
          // set:true, and the artifact turned out to contain shared memories anyway. The claim gate
          // reads the declaration; only the compiler reads the bytes. So the gate let it through
          // and the box sat in "failed" holding the lease.
          const missing = /([a-z0-9_-]+) must be enabled/i.exec(String(e.message || ""));
          if (missing) {
            return await this.#giveUp(id, `its artifact uses ${missing[1]}, which this box's enclave runtime`
              + ` does not build for - whatever the catalog version declares. The bytes are the authority:`
              + ` ${String(e.message).split("\n").filter((l) => /must be enabled/i.test(l))[0]?.trim() || e.message}`);
          }
          return this.#record(id, { status: "failed", reason: `bytecode: ${e.message}` });
        }
      }
      // A server-shaped app binds a port INSIDE the enclave, so the node picks the actual port
      // (nothing else on this machine may already hold it) and tells the app through
      // ENCLAVE_PORTS, which is the platform's own convention: "<label>:<declared>=<actual>". An
      // app that hardcodes a port instead of reading this is the one thing that cannot work here.
      const port = want === 4 ? this.#portFor(id) : 0;
      const declared = Number(d.appPort) || 8080;
      // The secrets, fetched here rather than beside the claim: a node restart rebuilds the app
      // from a lease it already holds and never passes through consider(), and an app that comes
      // back WITHOUT its credentials starts unconfigured and answers 503 - which is exactly what
      // happened to the s3-ipfs-adapter on the first restart after it was claimed.
      if (!this.secrets.has(id)) {
        await this.loadSecrets(id).catch((e) => this.log(`secrets ${id.slice(0, 10)}: ${e.message}`));
      }
      // ...and the custom hostnames, HERE, before the environment is built. The platform runner
      // does the same thing in the same place (supervisor.js launchSpec calls fetchDepDomains
      // before launchSpecFrom), and for the same reason: ENCLAVE_HOSTS is a LAUNCH-TIME SNAPSHOT,
      // so a box that only learned the names on its next tick would hand every cold-started guest
      // a list missing the very domain its owner attached. The tick keeps certificates and SNI
      // serving current after that; the guest's own copy changes when it next starts, which is
      // also what happens on a platform box.
      await this.refreshDomains(id, { forLaunch: true })
        .catch((e) => this.log(`domains ${id.slice(0, 10)}: ${e.message}`));
      const env = this.appEnvFor(id, d, v, { memMb, port, world: want, declared,
                                             config: await this.appConfigResolved(d, v) });
      app = new EnclaveApp({ id, cwasmPath: cwasm, hostCmd: this.cfg.hostCmd, memMb, world: want, port, env,
                             log: (m) => this.log(`${id.slice(0, 10)} ${m}`) });
      this.apps.set(id, app);
    }
    if (app.state !== "running") {
      this.#record(id, { status: "provisioning", reason: null });
      try { await app.start(); }
      catch (e) {
        // Three goes, then the lease goes back. A start that keeps failing is not always this
        // box's fault (a port, a cold cache, a bad artifact), but holding a lease through it
        // keeps the deployment off every other enclave while its balance drains.
        const tries = (this.records.get(id)?.startTries || 0) + 1;
        this.#record(id, { status: "failed", reason: `app: ${e.message}`, startTries: tries });
        if (tries >= 3) return await this.#giveUp(id, `it would not start after ${tries} tries: ${e.message}`);
        return this.records.get(id);
      }
    }
    const rec2 = this.#record(id, { status: "running", reason: null, port: app.port, startTries: 0 });
    // Ask for the app's certificate NOW rather than when the first visitor arrives: issuance goes
    // through ACME and takes a moment, and the console's padlock stays amber (and a browser lands
    // on a warning) until a handshake actually succeeds. Fire and forget - appZoneTarget holds its
    // own backoff, and nothing about the app depends on the outcome.
    if (app.port) {
      this.appZoneTarget(id).then((t) => {
        if (t) this.log(`${id.slice(0, 10)} app-zone ready at https://${t.cert.name}/`);
      }).catch(() => {});
    }
    return rec2;
  }

  /**
   * The app's config: the catalog version's, replaced by the deployment's override when it carries
   * one. Through the same parser the claim policy used, so the config that reaches the guest is
   * the one the policy accepted and nothing else - a second, looser reading of the same field is
   * how a runner ends up honouring an option it told the tenant it had refused.
   */
  /**
   * Resolve `$NAME` / `${NAME}` in an app config from this deployment's secrets.
   *
   * MIRRORED FROM THE PLATFORM RUNNER (wasm/wasm_manager.py `_subst_secrets`), deliberately and
   * down to the escape rule, because a box that reads these differently from the rest of the fleet
   * is worse than one that does not read them at all: the same app would be configured here and
   * unconfigured there, with nothing having said no. The published apps depend on it - risc-box's
   * catalog config is `"endpoint": "$S3_ENDPOINT"` and four more like it.
   *
   * The substitution walks the PARSED JSON and replaces inside string values only, so a secret
   * holding a quote or a backslash is re-serialised safely rather than spliced into raw JSON text.
   * Only names that really are secrets substitute; anything else keeps its literal `$`, because a
   * config may legitimately contain dollar signs. `$$` is a literal `$`.
   *
   * The resolved text exists only in the environment handed to the enclave. What the node records
   * and what the owner reads back keeps the placeholder - same exposure class as the secrets.
   */
  #substituteSecrets(text, secrets) {
    if (!text || !secrets || !Object.keys(secrets).length || !text.includes("$")) return text;
    const RE = /\$(\$)|\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g;
    const rep = (m, dollar, braced, bare) => {
      if (dollar) return "$";
      const name = braced || bare;
      const v = secrets[name];
      return v === undefined ? m : String(v);
    };
    const walk = (x) => {
      if (typeof x === "string") return x.replace(RE, rep);
      if (Array.isArray(x)) return x.map(walk);
      if (x && typeof x === "object") {
        const o = {};
        for (const [k, val] of Object.entries(x)) o[k] = walk(val);
        return o;
      }
      return x;
    };
    // A config that is not JSON is passed through untouched rather than mangled: the app owns its
    // own format, and this box is not the place to discover it is not JSON.
    let parsed;
    try { parsed = JSON.parse(text); } catch { return text; }
    return JSON.stringify(walk(parsed));
  }

  /**
   * The environment a guest is started with: the same one the platform gives an app on a
   * confidential VM.
   *
   * Its own method so it can be READ. What a guest receives is a contract - an app reads its
   * config, its hostnames and its card share from here and has no other way to learn them - and a
   * contract that can only be observed by starting a real enclave is a contract nobody checks.
   */
  appEnvFor(id, d, v, { memMb, port = 0, world = 1, declared = 8080, config }) {
    return {
      // The same environment the platform gives an app on a confidential VM.
      // RESOLVED against this deployment's secrets, which is what the platform's runner hands a
      // guest. An app whose config says "$S3_ENDPOINT" must receive the endpoint, not the word.
      ENCLAVE_CONFIG: config,
      ENCLAVE_MEM_MB: String(memMb),
      // THE CARD SHARE THIS DEPLOYMENT BOUGHT, read off the ledger record and carried into VTL1,
      // where the runtime gates the model on it: `generate` answers a deployment that bought a
      // share of this box's card and refuses one that did not (windows/enclave-rt HostState).
      // The tenant never supplies this value; the only lie available to this side is giving its
      // own card away.
      ENCLAVE_GPU_MILLI: String(Number(d.gpuMilli) || 0),
      // Every hostname this deployment answers on: its own subdomain first, then whatever its
      // owner attached. An app that generates absolute URLs or checks the Host header needs to
      // know its customer's name, and this is how the platform tells it.
      ENCLAVE_HOSTS: this.hostsFor(id).join(","),
      ...(world === 4 ? { ENCLAVE_PORTS: `http:${declared}=${port}` } : {}),
      // ...plus this deployment's relay-stored secrets, which is how an app's credentials reach
      // it. They are fetched as the LEASE HOLDER (secrets.mjs) and injected into the enclave,
      // never written to disk and never given to the VTL0 side beyond this call.
      ...(this.secrets.get(id) || {}),
    };
  }

  async appConfig(d, v, { strictCid = false } = {}) {
    try {
      const opts = chain.parseEnvelope(d?.configCid, d?.gpuMilli);
      if (opts.config !== undefined && !(strictCid && opts.configCid)) return JSON.stringify(opts.config);
      if (opts.configCid) {
        // Fetched through the CID verifier, not trusted from the gateway: the bytes are re-hashed
        // against the CID the ledger names before they become an app's configuration.
        const file = path.join(this.cfg.dir, "apps", `cfg-${opts.configCid}.json`);
        if (!fs.existsSync(file)) {
          await fetchArtifact({ cid: opts.configCid, dir: path.join(this.cfg.dir, "apps"),
                                python: this.cfg.python, gateway: this.cfg.gateway,
                                maxBytes: 1 << 20, out: file, log: (m) => this.log(m) });
        }
        const text = fs.readFileSync(file, "utf8");
        JSON.parse(text);                              // it must BE JSON before an app sees it
        this.log(`config: ${opts.configCid} applied to ${String(d.id).slice(0, 10)} (${text.length} bytes, CID-verified)`);
        return text;
      }
    } catch (e) {
      if (strictCid) throw e;
      this.log(`config: ${e.message}; the version's own config stands`);
    }
    // THE PUBLISHER's split (catalog rev 7): when the version names a config CID, the inline field
    // is only the routing manifest (volumes, mem64, set...) and the fetched bytes are what the
    // guest gets. Handing it the manifest instead would look like a working app with a nonsense
    // configuration, so a fetch that FAILS refuses rather than falling back to the inline field.
    if (v?.configCid) {
      const file = path.join(this.cfg.dir, "apps", `cfg-${v.configCid}.json`);
      if (!fs.existsSync(file)) {
        await fetchArtifact({ cid: v.configCid, dir: path.join(this.cfg.dir, "apps"),
                              python: this.cfg.python, gateway: this.cfg.gateway,
                              maxBytes: 1 << 20, out: file, log: (m) => this.log(m) });
      }
      const text = fs.readFileSync(file, "utf8");
      JSON.parse(text);                                // it must BE JSON before an app sees it
      this.log(`config: the version's own ${v.configCid} applied (${text.length} bytes, CID-verified)`);
      return text;
    }
    return String(v?.config || "");
  }

  /** The app's config as the GUEST sees it: resolved against this deployment's secrets. */
  async appConfigResolved(d, v) {
    const text = await this.appConfig(d, v);
    const secrets = this.secrets.get(String(d?.id || "").toLowerCase()) || {};
    const out = this.#substituteSecrets(text, secrets);
    if (out !== text) {
      const names = Object.keys(secrets).filter((n) => text.includes(n));
      this.log(`config: resolved ${names.length} secret placeholder${names.length === 1 ? "" : "s"}`
        + ` for ${String(d.id).slice(0, 10)} (${names.join(", ")})`);
    }
    return this.#patchConfig(d, out);
  }
  /**
   * An OPERATOR-SET, per-deployment patch over a tenant's resolved app config, from
   * ENCLAVE_APP_CONFIG_PATCH ({"<deployment id>": {"key": value}}). It is a local override: it
   * changes nothing on chain and nothing for the same version anywhere else.
   *
   * It exists because a setting that is right on one box can be fatal on another. risc-box asks
   * for `realtime: true` - the guest's clock driven by the HOST's, which anything that paces
   * itself (a game, a video player) needs. That assumes the guest runs near real speed. In this
   * enclave there is no JIT: the emulator is Pulley bytecode and the guest manages ~0.5 MIPS, so
   * the 10 ms timer arrives every ~5,000 guest instructions while the kernel's timer ISR costs
   * ~31,000 - measured 65M vs 121M instructions to reach "Linux version" under Pulley with the
   * clock off and on. The guest never finishes one tick before the next is due, so it executes
   * flat out and never gets past OpenSBI, which is exactly what this box showed.
   *
   * A patch is a WORKAROUND and should name itself as one: it is logged on every apply, and the
   * standing list lives in windows/PARITY.md.
   */
  /**
   * An OPERATOR-SET artifact override: ENCLAVE_APP_ARTIFACT_PATCH = {"<deployment id>":
   * {"file": "<path>", "sha256": "<hex>"}}. The deployment runs that file instead of its catalog
   * version's CID.
   *
   * It exists for one case: a fix whose permanent form needs signatures this box does not hold.
   * risc-box's catalog app and the deployment both belong to the governance hardware wallet, so a
   * fixed build can only become the catalog's version, and the deployment's, through two signatures
   * on that device (publishVersion, then setAppRef). Until then the override is how the fix runs.
   *
   * The bytes are pinned by hash - a file that does not match is refused, never run - and the
   * compiled cache is keyed by that hash, so it cannot be confused with the catalog CID's. Every
   * apply is logged and recorded on the deployment, and the list lives in windows/PARITY.md. It is a
   * WORKAROUND and must be removed once the signed version exists.
   */
  #artifactPatch(id, v) {
    const raw = process.env.ENCLAVE_APP_ARTIFACT_PATCH;
    if (!raw) return null;
    let all;
    try { all = JSON.parse(raw); } catch (e) { return { error: `ENCLAVE_APP_ARTIFACT_PATCH is not JSON (${e.message})` }; }
    const key = String(id).toLowerCase();
    const p = all[key] || all[key.replace(/^0x/, "")];
    if (!p) return null;
    if (!p.file || !/^[0-9a-f]{64}$/i.test(String(p.sha256 || ""))) return { error: "needs {file, sha256}" };
    let bytes;
    try { bytes = fs.readFileSync(p.file); } catch (e) { return { error: `cannot read ${p.file}: ${e.message}` }; }
    const sha = crypto.createHash("sha256").update(bytes).digest("hex");
    if (sha !== String(p.sha256).toLowerCase()) return { error: `${p.file} is sha256 ${sha.slice(0, 16)}…, not the pinned ${String(p.sha256).slice(0, 16)}… - refusing to run it` };
    this.log(`ARTIFACT OVERRIDE (operator, NOT the catalog's bytes) for ${key.slice(0, 10)}: running ${path.basename(p.file)} `
      + `sha256 ${sha.slice(0, 16)}… in place of catalog ${v.version} (${v.cid})`);
    this.#record(key, { artifactOverride: { file: path.basename(p.file), sha256: sha, replaces: v.cid } });
    return { path: p.file, sha };
  }
  #patchConfig(d, text) {
    const raw = process.env.ENCLAVE_APP_CONFIG_PATCH;
    if (!raw) return text;
    let all;
    try { all = JSON.parse(raw); } catch (e) {
      this.log(`config patch: ENCLAVE_APP_CONFIG_PATCH is not JSON (${e.message}); ignoring it`);
      return text;
    }
    const id = String(d?.id || "").toLowerCase();
    const patch = all[id] || all[id.replace(/^0x/, "")] || null;
    if (!patch || typeof patch !== "object") return text;
    let cfg;
    try { cfg = JSON.parse(text || "{}"); } catch { return text; }
    const changed = Object.keys(patch).filter((k) => JSON.stringify(cfg[k]) !== JSON.stringify(patch[k]));
    if (!changed.length) return text;
    this.log(`config patch (operator override, NOT the tenant's published config) for ${id.slice(0, 10)}: `
      + changed.map((k) => `${k}=${JSON.stringify(patch[k])}`).join(" "));
    return JSON.stringify({ ...cfg, ...patch });
  }
  #record(id, patch) {
    const cur = this.records.get(id) || { id, status: "unknown", reason: null };
    const rec = { ...cur, ...patch, updatedAt: new Date().toISOString() };
    this.records.set(id, rec);
    return rec;
  }

  /**
   * Read the ledger and take the work this box may run.
   *
   * In "market" scope that is any wallet's public, coreless, option-compatible deployment that
   * fits in what this box has left; in "owner-only" it is the box owner's alone. An unclaimed row
   * is the platform's Queued state, so this scan IS how a deployment reaches this box - nobody
   * pushes work at a runner.
   *
   * ONE new claim per pass. A claim costs gas and a lease commits capacity, and a scan that took
   * every row it liked at once would spend both before the first app had proved it starts. The slot is
   * spent by a row that goes on to a claim TRANSACTION (consider()'s claimAttempted, set at send and carried
   * through any later throw): a row refused on policy (claimRefusal, the same predicate consider() asks), or
   * declined by consider() without a claim (queued, the partition verdict), leaves it for the next row - and
   * a row declined with a STANDING answer is not asked again while its inputs are unchanged (scanHold), so it
   * cannot starve the rows behind it (enclave-d1's TEST2). At most SCAN_DECLINED_PER_PASS declines a pass.
   */
  #audits = null;
  #auditAdmitted = new Set();
  #auditFee = new Set();
  #auditScanned = false;
  /**
   * An audit job an OWNER-ONLY box serves although its ledger owner is a keyless fee wallet (audit-jobs.mjs admitted: a job
   * created for this box by a payer policy of an owner it already serves). Until this process's first scan has decided,
   * a deployment running an audit workload is not swept on owner grounds - a node restart must not kill a running job.
   */
  servesAuditJob(d) {
    const id = String(d?.id || "").toLowerCase();
    if (this.#auditAdmitted.has(id)) return true;
    return !this.#auditScanned && auditAppRefsOf(this.cfg.auditAppRefs).includes(String(d?.appRef || "").toLowerCase());
  }
  #auditJobs() {
    if (this.#audits && this.#audits.fees === chain.addresses.verificationFees) return this.#audits.jobs;
    let floor = 0n; try { floor = BigInt(String(this.cfg.auditMinRatePerShareMilli6 ?? "0").trim() || "0"); } catch {}
    const jobs = createAuditJobs({ appRefs: auditAppRefsOf(this.cfg.auditAppRefs), minRatePerShareMilli6: floor < 0n ? 0n : floor,
      enclaveId: this.enclaveId, ledger: chain.addresses.deployments, fees: chain.addresses.verificationFees || null,
      publicClient: chain.publicClient(), send: chain.sendOperatorTx, log: this.log,
      servedOwners: () => this.ownerSet(), ownerOnly: () => this.servingScope() === "owner-only" });
    if (jobs.enabled) this.log(`paid capacity audits: accepting jobs for ${auditAppRefsOf(this.cfg.auditAppRefs).join(", ")} at >= ${floor} per milli`);
    this.#audits = { fees: chain.addresses.verificationFees, jobs };
    return jobs;
  }
  async scanLedger() {
    const owners = this.ownerSet();
    const scope = this.scope();
    if (!this.cfg.appsEnabled || !this.registered || !chain.operatorAddress()) return;
    if (scope === "owner-only" && !owners.size) return;
    let rows; try { rows = await chain.allDeployments(); } catch (e) { this.log(`ledger scan failed: ${e.shortMessage || e.message}`); return; }
    const isOwners = (d) => owners.has(String(d.owner || "").toLowerCase());
    // PAID CAPACITY AUDITS (audit-jobs.mjs): jobs the fee contract created for THIS host are accepted here (the operator
    // key never leaves the box) and join the pool whatever the scope; off unless ENCLAVE_AUDIT_APPREFS lists workloads
    const audits = await this.#auditJobs().pass(rows).catch((e) => { this.log(`audit jobs: ${e.message}`); return null; });
    if (audits) { this.#auditAdmitted = audits.admitted; this.#auditFee = audits.fee || new Set(); this.#auditScanned = true; }
    const pool = rows.filter((d) => d.active && ((scope === "market" ? d.isPublic : isOwners(d)) || !!audits?.pool.has(String(d.id).toLowerCase())));
    if (pool.length && !this._sawLedger) {
      this._sawLedger = true;
      this.log(`ledger: ${pool.length} active deployment(s) in scope (${scope})`);
    }
    // Ours first (a lease already held is work in progress), then this box owner's own, then the
    // market oldest-first: a queue, not a cherry-pick.
    const ourId = this.enclaveId.toLowerCase();
    const rank = (d) => (String(d.runner || "").toLowerCase() === ourId ? 0 : isOwners(d) ? 1 : 2);
    pool.sort((a, b) => rank(a) - rank(b) || Number(a.createdAt) - Number(b.createdAt));
    const ov = this.ownersVersion();
    let claimed = 0, declined = 0;
    for (const d of pool) {
      const id = String(d.id).toLowerCase();
      if (this.blocked.has(id)) continue;                  // already tried, already handed back
      const rec = this.records.get(id);
      if (rec && ["running", "provisioning", "claiming"].includes(rec.status)) continue;
      const ours = String(d.runner || "").toLowerCase() === ourId;
      const live = Number(d.leaseUntil) * 1000 > Date.now();
      // A LEASE THIS BOX ALREADY HOLDS is work in progress, not a candidate. The tick's own loop
      // resumes it; asking the claim gate about it here can only produce a wrong answer, because
      // the gate decides whether to TAKE work and this work is already taken.
      //
      // It showed up as a restart window: on a fresh boot the records have no status yet, so the
      // scan ran before the resume and stamped "refused" on an app that was seconds from serving -
      // visible to the tenant and to the console, and a lie either way. Caught by curling the app
      // during a restart and finding it marked refused while the lease was live.
      // ...UNLESS this box no longer tracks it: a give-up whose release never reached the chain (2026-10-14 14:30:46,
      // 0x7ae476a3: the node gave it up, the host restart came before the release transaction) leaves a lease held here
      // with no record, and the tick resumes only what it tracks, so it sat unserved until the lease lapsed. Tracking it
      // again hands it back to the tick, which resumes it as any lease this box holds.
      if (ours && live) {
        if (!this.tracked.has(id)) {
          this.tracked.add(id); this.#saveTracked();
          this.log(`${id.slice(0, 10)}: this box holds its lease on chain but no longer tracked it; resuming it`);
        }
        continue;
      }
      if (!ours && live && !/^0x0+$/.test(String(d.runner || ""))) continue;   // somebody else is running it
      if (!ours && (claimed >= 1 || declined >= Host.SCAN_DECLINED_PER_PASS)) continue;
      const holdKey = this.scanHoldKey(d, ov);
      const held = this.scanHold.get(id);
      if (held && held.key === holdKey && Date.now() - held.at < held.ms) continue;   // declined, and nothing it was judged on changed
      let v = null; try { v = await chain.resolveAppRef(d.appRef); } catch {}
      const refuse = this.claimRefusal(d, { version: v, capacity: this.capacity(), appsEnabled: true, ownerAllow: owners });
      if (refuse) {
        // Recorded, not logged every 30 seconds: a refusal is a standing fact about a row, and
        // the console reads it off /v1/deployments. Only a CHANGE is worth a line.
        if (!rec || rec.reason !== refuse) { this.#record(id, { status: "refused", reason: refuse, appRef: d.appRef }); this.log(`ledger: not taking ${id.slice(0, 10)}: ${refuse}`); }
        continue;
      }
      const takes = this.cpuShareOf(id, d, v);
      this.log(`ledger: considering ${id.slice(0, 10)} (${d.appRef}, owner ${d.owner}, ${Math.round(takes * 100)}% of this box`
        + `${takes > Number(d.cpuMilli) / 1000 + 1e-9 ? `, dialed ${Math.round(Number(d.cpuMilli) / 10)}%: its version needs that much here` : ""})`);
      // a throw still says whether a claim went out before it (consider()'s claimAttempted, set at send)
      const r = await this.consider(id).catch((e) => {
        this.log(`consider ${id.slice(0, 10)}: ${e.message}`);
        return { accepted: false, claimAttempted: e?.claimAttempted === true };
      });
      if (r.claimAttempted) {
        if (!ours) claimed++;
        this.scanHold.delete(id);
        if (r.claimFailed) {         // the claim transaction itself failed (reverted, or could not be sent)
          const was = this.claimFails.get(id);
          const n = was && was.key === holdKey ? was.n + 1 : 1;   // n keeps counting: every later failure re-holds (5d)
          this.claimFails.set(id, { key: holdKey, n });
          if (n >= 2) {
            this.scanHold.set(id, { key: holdKey, at: Date.now(), ms: Host.SCAN_CLAIMFAIL_HOLD_MS });
            this.log(`ledger: ${id.slice(0, 10)}'s claim failed ${n} passes running with nothing changed: not asked again for ${Host.SCAN_CLAIMFAIL_HOLD_MS / 1000} s, so the rows behind it are reached`);
          }
        } else this.claimFails.delete(id);   // a good claim (or a launch that threw after one) restarts the count
        continue;
      }
      if (!ours) declined++;
      // held only on an answer consider() says is STANDING - refused (policy, partition verdict) or queued (the ledger's
      // claimableBy, a verdict input not known yet) - never read off the record, which may be an OLDER answer; a transient
      // failure (chain unavailable, a read that failed, a throw) is asked the next pass (enclave-5d's should-fix)
      // ...and a queued row whose lease has EXPIRED with nothing left to fund it (balance6 0) is not coming back on its own:
      // only a top-up, or a new version, changes that, and either changes the key (balance6, spent6, appRef). Asked every
      // SCAN_QUEUED_HOLD_MS instead, such a row was re-tracked and retired again every ~2.5 min for as long as nobody
      // paid (customer 0x2215bad4 on k11-4, 2026-10-15: its lease ended 10-14 17:42Z with 1.25 USDC spent and 0 left).
      if (!r.accepted && (r.standing === "refused" || r.standing === "queued"))
        this.scanHold.set(id, { key: holdKey, at: Date.now(),
          ms: r.standing === "refused" ? Host.SCAN_HOLD_MS : Host.unfundedExpired(d) ? Host.SCAN_UNFUNDED_HOLD_MS : Host.SCAN_QUEUED_HOLD_MS });
      else this.scanHold.delete(id);
    }
  }
  // FOLLOW THE BOOK: a ledger cutover (15d -> 16d, 2026-10) moves `deployments` and the prover in the address book. The
  // node read the book only at start, so every host had to be restarted to follow one; an open-market host has nobody
  // to do that. Re-read it every BOOK_RECHECK_MS: a moved ledger is used from the next read on - the migration keeps
  // every id and clears every lease, so the tick finds this box's records unclaimed there and claims them again while
  // their partitions keep running (nothing here stops an app for the move).
  static BOOK_RECHECK_MS = 10 * 60_000;
  async followBook({ now = Date.now(), resolve = () => chain.resolveAddresses() } = {}) {
    if (now - (this.bookCheckedAt || 0) < Host.BOOK_RECHECK_MS) return [];
    this.bookCheckedAt = now;
    const before = { ...chain.addresses };
    try { await resolve(); } catch (e) { this.log(`address book: re-read failed (${e.shortMessage || e.message}); keeping ${before.deployments}`); return []; }
    const moved = ["deployments", "proofOfTime", "registry", "appCatalog"].filter((k) => String(before[k] || "").toLowerCase() !== String(chain.addresses[k] || "").toLowerCase());
    for (const k of moved) this.log(`address book: ${k} moved ${before[k]} -> ${chain.addresses[k]}`
      + (k === "deployments" ? ": this box's leases are claimed again on the new ledger; running partitions keep running" : ""));
    if (moved.includes("deployments")) { this.scanHold?.clear?.(); this.priceSent = null; this.#saveTracked(); }
    if (moved.includes("registry")) await this.refreshRegistration().catch(() => {});
    return moved;
  }
  async tick() {
    if (!this.chainReady) return;
    await this.followBook();
    await this.enforceOff();
    // whose deployments this box serves, re-read before the scan and the sweep ask (a deleted delegation ends here)
    await this.refreshOwners();
    if (!this.registered) await this.refreshRegistration();
    await this.ensureRegistered().catch((e) => this.log(`register: ${e.message}`));
    // The asks, every tick rather than once at start-up: the card price is a function of whether
    // a worker is answering, and a worker that dies mid-shift must take the card's price off the
    // registry with it.
    await this.ensurePriced().catch((e) => this.log(`prices: ${e.message}`));
    await this.scanLedger().catch(() => {});
    await this.retireForeignRecovered().catch((e) => this.log(`isolation: recovered-VM sweep: ${e.message}`));
    for (const id of [...this.tracked]) {
      let d; try { d = await chain.readDeployment(id); } catch { continue; }
      const rec = this.records.get(id) || this.#record(id, {});
      const runner = String(d.runner || "").toLowerCase();
      const unclaimed = /^0x0+$/.test(runner);
      const ours = runner === this.enclaveId.toLowerCase();
      const untilMs = Number(d.leaseUntil) * 1000;
      const leaseLive = untilMs > Date.now();
      if (!d.active) { await this.#stopApp(id, "the deployment was stopped on the ledger"); continue; }
      // Somebody else really does hold it: stand down. Only a LIVE lease held by a DIFFERENT,
      // non-zero runner counts, because the other two readings are not that.
      if (!ours && !unclaimed && leaseLive) { await this.#stopApp(id, `another enclave holds the lease (${runner.slice(0, 10)})`); continue; }
      // Not ours and nobody's: claim it (or re-claim a lapsed one) rather than tearing the app
      // down. A public RPC can be a block or two behind our own claim receipt, and reading that
      // as "another enclave holds the lease" stopped a freshly started app within a second of
      // claiming it. The receipt is the truth; give the reads two minutes to catch up.
      if (!ours) {
        if (rec.claimedAt && Date.now() - rec.claimedAt < 120_000) continue;
        await this.consider(id).catch((e) => this.log(`re-claim ${id.slice(0, 10)}: ${e.message}`));
        continue;
      }
      const pinRefusal = chain.placementRefusal(d.configCid, this.enclaveId);
      if (pinRefusal) { await this.#giveUp(id, pinRefusal, { retry: true }); continue; }
      // HELD (a retired-engine node, a deployment it cannot run): before the renewal, the envelope edit and
      // the resize, each of which can spend or give back the lease on chain. Recorded, and left alone.
      const held = this.heldReason(d);
      if (held) {
        // AN OWNER THIS BOX DOES NOT SERVE is not only left unrenewed: what it runs here is STOPPED (enclave-bf's
        // should-fix). At once after a TRANSFER - the ledger's owner is not the one this box ran it for (rec.owner,
        // recorded by ensureApp) - and at the latest when the held lease lapses, as a boundary hold is. A delegation
        // that is merely missing or unreadable (a transient file-system error looks the same) holds until the lease
        // ends rather than killing a delegated owner's app. #stopApp retires a partition and waits until it is confirmed
        // gone; nothing is released on chain.
        if (this.ownerNotServed(d)) {
          const ranFor = String(rec.owner || "").toLowerCase(), owner = String(d.owner || "").toLowerCase();
          if (ranFor && ranFor !== owner) { await this.#stopApp(id, `the deployment was transferred to ${d.owner}, whom this box does not serve`); continue; }
          if (untilMs < Date.now()) { await this.#stopApp(id, `its lease lapsed while held for an owner this box does not serve (${d.owner})`); continue; }
        }
        this.#record(id, { status: "held", reason: held, leaseUntil: Number(d.leaseUntil) });
        continue;
      }
      // A deployment whose manager stated a boundary this backend cannot have is HELD and NOT renewed: renewing would bill
      // the tenant for a service this box will not give (enclave-99). ensureApp below still re-asks every tick. But its
      // LEASE END is still honoured, and before ensureApp, so a lapsed lease is neither kept running nor served again for
      // one tick by a manager that turned honest: the held domain is RETIRED here. That is a local retirement (#stopApp),
      // never an on-chain release, so it stays inside heldReason's "never released automatically" (enclave-99's re-review).
      // And it is BLOCKED here (enclave-99's re-review of 99900b74): otherwise the next ledger scan re-claims the lapsed
      // lease, spawning the tenant's app again under the same manager, and every lease period the claim takes gas and a
      // quantum. That is the renew leak again, through the claim. blocked is exactly the needed state: scanLedger skips
      // it, an unforced consider refuses it, the operator's forced claim clears it, and it persists across a restart.
      // Nothing is released on chain: this is local state, as heldReason's doctrine requires.
      if (rec.boundaryHeld === true && untilMs < Date.now()) {
        this.blocked.set(id, `the manager stated a boundary this backend cannot have (${rec.reason || "boundary-held"}); the lease `
          + "lapsed unrenewed and the domain was retired here. It is not re-claimed until the operator forces it; nothing was released on chain");
        this.#saveTracked();
        await this.#stopApp(id, "the lease lapsed while the deployment was boundary-held (not renewed)");
        continue;
      }
      // HELD BY THE OWNER'S CAP (#spawnCapHold): its partition never started, so it is not renewed (nothing is served
      // to bill for), and when the lease lapses it is let go here. Nothing runs to retire and nothing is released on
      // chain; it comes back through the ledger scan, whose claim gate reads the same cap.
      if (rec.capHeld === true && untilMs < Date.now()) {
        await this.#stopApp(id, "the lease lapsed while it waited for room under the owner's hosting cap (not renewed)");
        if (this.records.get(id)?.status === "stopped") this.#record(id, { capHeld: null });   // else retried next tick
        continue;
      }
      // HELD BY THE PLAN (#isolationReconcile: an input it cannot establish, such as whether secrets are staged): this box
      // refuses to provision it, so it is NOT renewed - renewing drained the tenant's balance for time nobody was served
      // (coordinator enclave-87: d1's live node renewed test 1 at 01:15:58Z while it refused it). ensureApp below asks
      // again every tick, and a plan that passes clears the hold before the renewal window closes. A lease that lapses
      // while held is let go here, as a cap hold is; nothing is released on chain.
      // ...and a domain HELD rather than serving - one recovered from Hyper-V after a host or manager restart, or whose
      // outcome is unknown (rec.isolationHeld without a running record) - is the same case: billed, nothing served
      // (enclave-5d's G1; coordinator enclave-87). It is retired at lapse by the id it is held under (#stopApp ->
      // #retireIsolated), and stays tracked until the manager confirms it gone.
      // ...and a REBOOT RECOVERY that did not end serving (#rebootHold: held, with or without a VM left to name)
      const notServing = rec.planHeld === true || (!!rec.isolationHeld && rec.status !== "running") || !!rec.rebootHeld;
      if (notServing) {
        if (untilMs < Date.now()) {
          await this.#stopApp(id, `its lease lapsed while this box was not serving it (not renewed): ${rec.reason || "held"}`);
          if (this.records.get(id)?.status === "stopped") this.#record(id, { planHeld: null, isolationHeld: null, rebootHeld: null });
          continue;
        }
        if (untilMs - Date.now() < RENEW_LEAD_MS && rec.noRenewSaid !== untilMs) {
          this.#record(id, { noRenewSaid: untilMs });
          this.log(`${id.slice(0, 10)} NOT renewed: this box is not serving it (${rec.reason || "held"}); the lease ends ${new Date(untilMs).toISOString()}`);
        }
      }
      // Expired leases retain their old runner on chain, but renew() cannot extend them.
      // Retire locally and let scanLedger/consider enforce funding and policy before a new
      // claim. In particular, an exhausted deployment must not send failing renewals forever.
      if (!leaseLive) {
        await this.#stopApp(id, "the lease expired; a new claim must pass the current funding and hosting policy");
        continue;
      }
      // A FEE-CONTRACT AUDIT JOB is one quantum by design (audit-jobs.mjs fee): the coordinator stops it once its challenge
      // returns and stopAfter bounds it, so a renew can only revert ("unfunded") or extend time nobody pays for. Said once.
      const oneQuantum = this.#auditFee.has(id);
      if (oneQuantum && untilMs - Date.now() < RENEW_LEAD_MS && rec.noRenewSaid !== untilMs) {
        this.#record(id, { noRenewSaid: untilMs });
        this.log(`${id.slice(0, 10)} NOT renewed: a capacity-audit job is one quantum; the lease ends ${new Date(untilMs).toISOString()}`);
      }
      if (rec.boundaryHeld !== true && rec.capHeld !== true && !notServing && !oneQuantum && untilMs - Date.now() < RENEW_LEAD_MS) {
        try { await chain.renewDeployment(id); this.log(`renewed ${id.slice(0, 10)}`); d = await chain.readDeployment(id); }
        catch (e) {
          // rateCap doctrine (the platform runner's, mirrored): a renew the LEDGER refuses is not
          // an error to retry, it is the deployment's own rate cap or its balance saying "this is
          // the last quantum". Say when the app goes rather than retrying until it vanishes.
          const msg = e.shortMessage || e.message;
          const ends = new Date(untilMs).toISOString().replace("T", " ").slice(0, 19);
          const capped = /cap|balance|fund|rate/i.test(msg);
          this.#record(id, { reason: capped ? `the lease ends at ${ends} UTC and will not renew: ${msg}` : `renew failed: ${msg}` });
          this.log(`${id.slice(0, 10)} renew failed: ${msg}`);     // said, not only recorded: a later pass rewrites the reason
          if (untilMs < Date.now()) { await this.#stopApp(id, `the lease expired and renew failed: ${msg}`); continue; }
        }
      }
      this.#record(id, { leaseUntil: Number(d.leaseUntil), rate6: String(d.rate), balance6: String(d.balance6),
                         cpuShare: this.cpuShareOf(id, d), gpuShare: Number(d.gpuMilli) / 1000,
                         isPublic: d.isPublic !== false, owner: String(d.owner || "").toLowerCase() });
      // THE OWNER'S EDIT, reaching an app that is already running. The envelope is mutable on the
      // ledger (setConfig) and used to be read only at claim time, so an owner who changed their
      // app's configuration or its protection rules saw nothing happen until the lease turned over.
      await this.#applyEnvelopeEdit(id, d).catch((e) => this.log(`config edit ${id.slice(0, 10)}: ${e.message}`));
      // ...and the owner's RESIZE (setShares), which the ledger bills from immediately. A box that
      // billed the new share while serving the old one would be charging for something it is not
      // doing, which is why the fleet AND-folds this before a client will even send the tx.
      await this.#applyShareResize(id, d, rec).catch((e) => this.log(`resize ${id.slice(0, 10)}: ${e.message}`));
      const app = this.apps.get(id);
      if (!app || app.state !== "running") await this.ensureApp(id, d);
    }
    // The app's own origin: a certificate order at the relay answers 202 while ACME runs, so keep
    // asking on the tick rather than only when a visitor arrives. Until it is issued the console's
    // padlock stays amber and a browser gets a handshake failure, so nobody should have to trigger
    // this by hand. appZoneTarget holds the backoff; this only re-enters it.
    // An owner attaches a domain while the app is already RUNNING - that is the whole point - so
    // the list is re-read on the tick rather than only at claim time.
    for (const id of this.apps.keys())
      await this.refreshDomains(id).catch((e) => this.log(`domains ${id.slice(0, 10)}: ${e.message}`));
    for (const [id, app] of this.apps) {
      const cur = this.appCerts.get(id);
      if (app.state === "running" && app.port && (!cur || !cur.cert || cur.cert.selfSigned)) {
        this.appZoneTarget(id).then((t) => {
          // "Ready" has to mean a BROWSER WILL LOCK. appZoneTarget answers a target either way -
          // the self-signed fallback is still a servable target - so logging on `t` alone printed
          // "app-zone ready at https://..." every tick for an app whose padlock was amber, which
          // is how a missing certificate stayed invisible here while the log said it was fine.
          if (t && t.cert && !t.cert.selfSigned) this.log(`${id.slice(0, 10)} app-zone ready at https://${t.cert.name}/`);
        }).catch(() => {});
      }
    }
  }
  /**
   * Give the lease back. The ledger's release() is what puts the deployment in front of the rest
   * of the fleet again, and this box remembers not to take it a second time. Every caller is a
   * failure that will not fix itself by waiting, which makes holding the lease the wrong answer:
   * a tenant whose app cannot run here is better served by a row that reads Queued somewhere else
   * than by one that reads "running on nucbox-k11" over a restart loop.
   */
  /**
   * ONE give-up per deployment at a time: callers that arrive while one runs share it. The tick, the reconcile and the
   * manager's report can all decide to give up on the same domain in the same second, and each used to read "the runner
   * is still this box" and send its own release: one landed and the rest reverted on chain, gas spent (2026-10-12,
   * nucbox-k11-4: seven give-ups and ten releases for one partition that died starting).
   */
  #givingUp = new Map();
  #giveUp(id, why, opts = {}) {
    const busy = this.#givingUp.get(id);
    if (busy) return busy;
    const p = this.#giveUpOnce(id, why, opts).finally(() => this.#givingUp.delete(id));
    this.#givingUp.set(id, p);
    return p;
  }
  async #giveUpOnce(id, why, { retry = false } = {}) {
    this.#respawnAfter.delete(id);
    // An isolated domain first: handing the lease back while its partition still serves would
    // leave the deployment answering with no lease behind it (defect 15). And if it could NOT be confirmed gone, the
    // lease is not given back at all (enclave-d1's review, finding 4): no block, no release, still tracked, so the tick
    // keeps the lease renewed while the domain may run and retries this on its next pass.
    if (!(await this.#retireIsolated(id, why))) {
      const rec = this.records.get(id) || {};
      const held = `giving up (${why}) waits: the isolated domain could not be confirmed gone (${rec.isolationRetireFailed || "unconfirmed"}); `
        + "the lease is kept and the retire is retried";
      this.log(`${id.slice(0, 10)} ${held}`);
      return this.#record(id, { status: "held", reason: held });
    }
    // Everything that belonged to the lease goes with it. The rate buckets and concurrency
    // counters are keyed by deployment id, and an id CAN come back - a lease handed back for one
    // reason is re-claimable once that reason changes. Leaving the counters behind would meet the
    // returning tenant with a bucket their own traffic emptied an hour ago.
    waf.forget(id);
    this.secrets.delete(id);
    this.forgetDomains(id);
    const app = this.apps.get(id);
    if (app) { await app.stop(); this.apps.delete(id); }
    this.#record(id, { status: "failed", reason: why, port: null });
    if (retry) this.blocked.delete(id); else this.blocked.set(id, why);
    this.tracked.delete(id); this.#saveTracked();
    this.log(`giving up on ${id.slice(0, 10)}: ${why}`);
    try {
      const held = await chain.readDeployment(id).catch(() => null);
      if (held && String(held.runner || "").toLowerCase() === this.enclaveId.toLowerCase()) {
        const hash = await chain.releaseDeployment(id);
        this.log(`released ${id.slice(0, 10)} back to the fleet (tx ${hash})`);
        this.#record(id, { status: "released", reason: why });
      }
    } catch (e) { this.log(`release ${id.slice(0, 10)} failed: ${e.shortMessage || e.message}`); }
    return this.records.get(id);
  }
  /**
   * DEFECT 15 (enclave-99): nothing ever retired an isolated domain. #stopApp, #giveUp and the
   * forced restart all stop `this.apps` entries, and a partition has none - so no DELETE ever
   * reached the manager and a domain outlived its lease, still answering under a name whose lease
   * was gone. Worse than a leak: it is a deployment served without a lease.
   *
   * Returns true when the domain is KNOWN gone. False means the manager could not confirm it, and
   * the caller must not treat the deployment as finished - retire() already keeps the lease in
   * that case, and this reports it so the record says why.
   */
  /** Respawns of an ended isolated domain inside the budget window (cfg.isolationRespawn). In memory: a node restart
   *  starts the count again, which errs toward trying; the budget still bounds each run. */
  #respawns = new Map();
  #respawnAfter = new Map();
  #respawnsWithin(id) {
    const recent = (this.#respawns.get(id) || []).filter((t) => Date.now() - t < RESPAWN_WINDOW_MS);
    this.#respawns.set(id, recent);
    return recent.length;
  }

  /** A reboot recovery that did not end serving: HELD, not retried by ensureApp and not renewed, until a forced relaunch. */
  /**
   * Whether the domains this node saw serving in the last 10 minutes are mostly gone from the manager at once (or the
   * manager no longer answers): -> a short description of the loss, or null when it is this domain alone.
   */
  async #hostWideLoss(client) {
    const since = Date.now() - 10 * 60_000;
    const seen = [...this.#lastServing.values()].filter((l) => l?.instance && Number(l.lastSeenAt) >= since);
    if (seen.length < 2) return null;
    let listed;
    // present = still a live domain: the manager keeps an ended one listed, as failed, until the node retires it
    try { listed = new Set((await client.list()).filter((v) => v.status !== "failed" && v.status !== "stopped").map((v) => v.id)); }
    catch (e) { return `the manager not answering (${String(e.message).slice(0, 80)})`; }
    const present = seen.filter((l) => listed.has(l.instance)).length;
    return present * 2 < seen.length ? `${seen.length - present} of the ${seen.length} domains this host was serving` : null;
  }
  /**
   * A VM the manager RECOVERED after a host or manager restart can never serve again (its relay and report key belonged
   * to the previous manager), and the node retires it only on the reconcile of the deployment it names. One whose
   * deployment this box no longer holds - released (a host shutdown's give-ups, 2026-10-14 14:30Z) and maybe served
   * elsewhere since (0xc13d4b6a moved to the phone) - was never reconciled here, so it stayed, and the manager refused
   * every new partition ("RAM allocation is unknown until recovered partitions are reconciled"): k11-4 could start
   * nothing. Each tick, a recovered VM naming a deployment this box does not track is retired through the manager.
   * Only recovered VMs, only for deployments not held here; a held one is the reconcile's (restart recovery above).
   */
  async retireForeignRecovered(client = null) {
    if (!this.cfg.isolationManager && !client) return;
    if (!client) {
      const { IsolationManagerClient } = await import("./isolation-client.mjs");
      client = new IsolationManagerClient({ base: this.cfg.isolationManager });
    }
    for (const v of await client.list()) {
      const owner = String(v.name || "").toLowerCase();
      const rec = this.records.get(owner);
      if (v.recovered !== true || !/^0x[0-9a-f]{64}$/.test(owner) || this.tracked.has(owner)
          || ["running", "provisioning", "held"].includes(rec?.status)) continue;
      const r = await client.remove(v.id);
      this.log(`${owner.slice(0, 10)} isolation: the recovered VM ${v.id} (${v.vmState || "state unknown"}) names a deployment `
        + `this box no longer holds: ${r.removed ? "retired" : r.absent ? "already gone" : "NOT retired"}`);
    }
  }
  #rebootHold(id, why, instanceId = null) {
    const reason = `isolation: reboot recovery: ${why}; held (not retried, not renewed) until a forced relaunch, or the owner's resize or config edit`;
    this.log(`${id.slice(0, 10)} ${reason}`);
    return this.#record(id, { status: "held", rebootHeld: reason, reason, ...(instanceId ? { isolationHeld: instanceId } : {}) });
  }

  /**
   * THE LAST DOMAIN THIS NODE SAW SERVING, per deployment: { instance, startedAt, firstSeenAt, lastSeenAt }. Kept apart
   * from rec.isolation (which routes traffic, and which intermediate records clear), and forgotten ONLY by this node's
   * own retire of a domain (#retireIsolated without `ended`). So a later spawn of a DIFFERENT instance that this node did
   * not retire is a domain that vanished, and is said, with Hyper-V's own account of it (#vanishedEvidence).
   */
  #lastServing = new Map();
  /** The pending Hyper-V evidence read for the last vanished domain (tests await it; nothing else waits on it). */
  vanishedEvidence = null;
  #noteServing(id, inst, action) {
    const now = Date.now();
    const prev = this.#lastServing.get(id);
    if (prev && inst.id && prev.instance !== inst.id) {
      this.log(`${id.slice(0, 10)} isolation: the domain ${prev.instance} recorded as serving is gone from the manager `
               + `(it ended by itself or was removed outside this node); ${action === "spawned" ? "a new one was started" : `${inst.id} was found in its place`}`);
      this.vanishedEvidence = this.#vanishedEvidence(id, prev, now).catch(() => {});
    }
    if (!inst.id) return;
    const startedAt = Number.isFinite(inst.startedAt) ? inst.startedAt : null;
    this.#lastServing.set(id, prev && prev.instance === inst.id
      ? { ...prev, lastSeenAt: now, startedAt: prev.startedAt ?? startedAt }
      : { instance: inst.id, startedAt, firstSeenAt: now, lastSeenAt: now });
  }
  /** Under the vanished line: what was last known of it, then the Hyper-V Worker-Admin events naming its VM. Never throws;
   *  on a host that is not Windows, or when the query fails, nothing more is said. */
  async #vanishedEvidence(id, prev, now) {
    const tag = `${id.slice(0, 10)}   `;
    const iso = (t) => (Number.isFinite(t) ? new Date(t).toISOString() : "?");
    const up = (ms) => { const m = Math.max(0, Math.round(ms / 60_000)); return m >= 60 ? `${Math.floor(m / 60)}h${String(m % 60).padStart(2, "0")}m` : `${m}m`; };
    const since = prev.startedAt ?? prev.firstSeenAt;
    this.log(`${tag}last known: ${prev.startedAt ? `started ${iso(prev.startedAt)}` : `first seen serving ${iso(prev.firstSeenAt)}`}, `
             + `last seen serving ${iso(prev.lastSeenAt)}${Number.isFinite(since) ? ` (up at least ${up(prev.lastSeenAt - since)})` : ""}`);
    // from a minute before it was last seen serving (at most two hours back), and never less than the last ten minutes
    const from = Math.max(now - 2 * 3600_000, Math.min(now - 10 * 60_000, (prev.lastSeenAt ?? now) - 60_000));
    const events = await recentHyperVEvents({ instanceId: prev.instance, since: from, now, run: this.cfg.hyperVEventsRun || null });
    if (!Array.isArray(events)) return;
    if (!events.length) { this.log(`${tag}hyper-v: no Worker-Admin event names its VM since ${iso(from)}`); return; }
    for (const e of events) this.log(`${tag}hyper-v ${e.time ?? "?"} event ${e.id ?? "?"}: ${e.message}`);
  }

  /** `ended`: the manager already reported this domain ENDED (the respawn's cleanup), so retiring it is not this node's
   *  decision and it stays the last domain seen serving, for the vanished line on its replacement. */
  async #retireIsolated(id, why, { ended = false } = {}) {
    if (!this.cfg.isolationManager) return true;                                // no backend: nothing can be out there
    const rec = this.records.get(id) || {};
    // The instance this node KNOWS of: serving (rec.isolation) or held (rec.isolationHeld). With neither, it retires BY
    // NAME (enclave-d1's review, finding 3): a node that restarted, or that only ever held a recovered VM, does not
    // know the id, and "I know of none" is not "there is none". Skipped only for a deployment KNOWN not to be isolated.
    const instanceId = rec.isolation?.instance ?? rec.isolationHeld ?? null;
    if (!instanceId && rec.isolationRequired === false) return true;
    try {
      const { retire } = await import("./isolation-lifecycle.mjs");
      const { IsolationManagerClient } = await import("./isolation-client.mjs");
      const client = new IsolationManagerClient({ base: this.cfg.isolationManager });
      const r = await retire({ client, deployment: { id }, ledger: null, instanceId });
      if (r.removed) {
        // CLEARED ONLY ON A CONFIRMED REMOVAL (enclave-99). Dropping `isolation` on any other
        // outcome would erase the only record of which instance is still out there: the domain
        // would keep serving and nothing here would name it, so a later tick could neither retire
        // it nor even report it. Keeping it is what makes an unconfirmed retire visible.
        this.#record(id, { isolation: null, isolationHeld: null, isolationRetireFailed: null });
        if (!ended) this.#lastServing.delete(id);                                 // this node's own decision: not a vanish
        this.log(`${id.slice(0, 10)} isolated domain retired (${why})`);
        return true;
      }
      this.log(`${id.slice(0, 10)} isolated domain NOT retired: ${r.reason}`);
      this.#record(id, { isolationRetireFailed: r.reason });
      return false;
    } catch (e) {
      this.log(`${id.slice(0, 10)} isolated domain retire failed: ${e.message}`);
      this.#record(id, { isolationRetireFailed: e.message });
      return false;
    }
  }

  async #stopApp(id, why) {
    // BEFORE forgetting anything: a partition is not in this.apps, so without this the domain
    // simply keeps running under a lease that has ended. An unconfirmed retire keeps the deployment TRACKED, so the
    // next tick (which reads the same ledger state and comes back here) retries it rather than forgetting a VM that
    // may still run.
    const gone = await this.#retireIsolated(id, why);
    waf.forget(id);
    this.secrets.delete(id);                           // they belong to the lease, not to this box
    this.appCerts.delete(id); this.appCertFails.delete(id);
    this.forgetDomains(id);
    const app = this.apps.get(id);
    if (app) { await app.stop(); this.apps.delete(id); }
    if (!gone) {
      this.#record(id, { status: "held", reason: `stopping (${why}) waits: the isolated domain could not be confirmed gone; retried each tick` });
      this.log(`${id.slice(0, 10)} stop waits on the isolated domain's retire: ${why}`);
      return;
    }
    this.#record(id, { status: "stopped", reason: why });
    this.tracked.delete(id); this.#saveTracked();
    this.log(`stopped ${id.slice(0, 10)}: ${why}`);
  }
  /**
   * A checkpoint per live paid lease that is serving right now, all in one batch (chain.checkpointBatch: one checkpointMany,
   * plus one fee-routed call per deployment with a payer policy). Serving means: an engine app that answers, or an ISOLATED
   * partition the tick saw serving within the last two minutes (rec.servingSeenAt: every pass re-adopts a serving domain). Before
   * 2026-10-16 isolated partitions were never proven (only this.apps, the retired engine's), so past the ledger's
   * proofRequiredFrom every paid partition lease on a Windows host earned nothing, and a fee-contract source's budget
   * (capacity audits) never accrued.
   */
  async proveAll() {
    if (!this.chainReady || !chain.proofAddress() || !this.registered) return;
    const due = [];
    const free = (id, rec) => {
      // A checkpoint earns the runner its lease seconds. At rate 0 (a free self-hosted lease:
      // _hostRate returns 0 when the box's payout wallet owns the deployment) there is nothing to
      // earn and nothing to meter, so proving it would spend this box's gas, every five minutes,
      // to move a number that is multiplied by zero. It is skipped and said, not silently dropped.
      if (rec.rate6 !== undefined && BigInt(rec.rate6 || 0) === 0n) {
        if (!this._freeProofSaid) { this._freeProofSaid = true; this.log(`no checkpoints for ${id.slice(0, 10)}: a free lease (rate 0) has nothing to credit`); }
        return true;
      }
      return false;
    };
    const now = Date.now();
    for (const [id, rec] of this.records) {
      if (!rec || rec.status !== "running" || !rec.leaseUntil || free(id, rec)) continue;
      const app = this.apps.get(id);
      if (app) { if (!(await app.alive())) { this.log(`no checkpoint for ${id.slice(0, 10)}: the app did not answer`); continue; } }
      else {
        if (!rec.isolation?.instance || !(now - Number(rec.servingSeenAt || 0) <= 120_000)) continue;
      }
      due.push({ id, enclaveId: this.enclaveId, upto: Math.min(Math.floor(now / 1000), Number(rec.leaseUntil)) });
    }
    if (!due.length) return;
    let results;
    try { results = await (this.cfg.checkpointBatch || chain.checkpointBatch)(due); }
    catch (e) { this.log(`checkpoints failed: ${e.shortMessage || e.message}`); return; }
    for (const r of results) {
      if (r.error) { this.log(`checkpoint ${r.ids.map((i) => i.slice(0, 10)).join(",")} failed: ${r.error.shortMessage || r.error.message}`); continue; }
      for (const id of r.ids) this.#record(id, { provenAt: due.find((d) => d.id === id)?.upto });
    }
  }

  // ---- the surface the relay and the console call, over the tunnel -------------------------
  deployments() { return [...this.records.values()].map((r) => ({ ...r })); }
  /**
   * Does this record still occupy the box? A running app does; so does an isolated domain the node holds or could not
   * confirm gone, whatever the record's status says (held, provisioning, failed): its VM may still run, and selling
   * its share again would over-admit (enclave-d1's re-review, finding 5). So does an ISOLATED deployment that is
   * provisioning with no instance id yet (a hold on a manager 503): a VM for it may exist unnamed (d1's acceptance of
   * fb1db848, the residual).
   */
  /** Below this an operator key does not try to pay its own register() (about 200k gas at Base's usual fees, with room). */
  static SELF_REGISTER_WEI = 20_000_000_000_000n;        // 0.00002 ETH
  static occupies(r) {
    return r.status === "running" || !!r.isolation || !!r.isolationHeld || !!r.isolationRetireFailed
      || (r.status === "provisioning" && r.isolationRequired === true);
  }
  /**
   * The shares the units occupying this box stand for (Host.occupies: running, starting, or a partition that may still
   * run), summed. `cpu` and `gpu` are what their leases bought; `gpuInUse` is what they hold of the card, which for a
   * partition is what it was spawned with (partitionGpuShare: 0 on this backend today, node-bridge.mjs isolationPlan).
   */
  /**
   * The CPU share a deployment takes on this box (chain.effectiveCpuShare): its dialed share, or what its version needs
   * here if that is more. Recorded per deployment as `needCpuShare` once the version is known, so every later pass
   * (renewals, resizes, capacity) counts what the box actually gives, not only what the record dials.
   */
  cpuShareOf(id, d, version = null) {
    const dial = Number(d && d.cpuMilli) / 1000 || 0;
    const need = version ? chain.effectiveCpuShare({ cpuMilli: 0 }, version, Number(this.cfg.gflopsFloorBasis ?? this.cfg.gflops) || 0)
                         : Number(this.records.get(id)?.needCpuShare) || 0;
    return Math.max(dial, need);
  }
  shareUse({ exclude = null } = {}) {
    let cpu = 0, gpu = 0, gpuInUse = 0;
    for (const r of this.records.values()) {
      if (!Host.occupies(r) || (exclude && String(r.id).toLowerCase() === String(exclude).toLowerCase())) continue;
      cpu += r.cpuShare || 0; gpu += r.gpuShare || 0;
      gpuInUse += r.partitionGpuShare ?? (r.gpuShare || 0);
    }
    return { cpu, gpu, gpuInUse };
  }
  /**
   * The node pool this box has left, as a fraction: what the relay's placement reads. `capped: false` is the figure
   * without the owner's cap, for a resize that does not grow (the cap never takes a lease back).
   */
  cpuShareFree({ exclude = null, capped = true } = {}) {
    if (!this.cfg.appsEnabled) return 0;
    const used = this.shareUse({ exclude }).cpu;
    // The owner's cap (hosting.mjs) can only lower this; at the default 1.0 it never binds and the figure is exactly
    // the one before caps existed.
    const offered = capped ? this.#offered("cpuShare") - used : Infinity;
    return Math.max(0, Math.min(1, 1 - used - (this.cfg.reservedShare ?? 0.25), offered));   // a quarter stays for the enclave, the worker and the owner
  }
  /**
   * The CARD pool this box has left, as a fraction of the worker's budget.
   *
   * Two limits, and the smaller wins. What this box has SOLD is its own ledger: the card shares of
   * the leases it is running. What is actually FREE on the silicon is the worker's business, and
   * on a desktop it is not the same number - the owner of the PC may be playing a game on it. The
   * card facts arrive from the agent (shieldedcard.mjs asks the worker), so a box whose worker is
   * down sells nothing rather than selling from memory.
   */
  gpuShareFree({ exclude = null, capped = true } = {}) {
    if (!this.cfg.appsEnabled || !this.sellsCard()) return 0;
    const card = this.card && this.card();
    if (!card || !(Number(card.vramBudgetGb) > 0)) return 0;
    const sold = this.shareUse({ exclude }).gpu;
    const onCard = Number(card.vramFreeGb) / Number(card.vramBudgetGb);
    // ...and a third, the owner's cap, which can only lower it (1.0 by default, where it never binds).
    return Math.max(0, Math.min(1, 1 - sold, Number.isFinite(onCard) ? onCard : 0, capped ? this.#offered("gpuShare") - sold : Infinity, this.partitionsOnly() ? Number(this.managerInference?.freeGpuMilli || 0) / 1000 : Infinity));
  }
  /**
   * capRefusal(id, {cpuShare, gpuShare}) -> why a NEW unit with these shares does not fit under the owner's caps beside
   * everything else occupying this box, or null. The isolated backend's spawn gate (#spawnCapHold). A unit that uses
   * no GPU is never refused for the GPU cap.
   */
  capRefusal(id, { cpuShare = 0, gpuShare = 0 } = {}) {
    const use = this.shareUse({ exclude: id });
    const pct = (x) => Math.round(x * 100);
    if (this.caps.paused === true)
      return "not started: the owner of this box has turned hosting off";
    if (use.cpu + cpuShare > this.caps.cpuShare + 1e-9)
      return `not started: the owner offers ${pct(this.caps.cpuShare)}% of this box's CPU to hosting, ${pct(use.cpu)}% of it is in use`
        + ` by running and starting partitions, and this one needs ${pct(cpuShare)}%; it starts when it fits (nothing running was stopped)`;
    if (gpuShare > 0 && use.gpuInUse + gpuShare > this.caps.gpuShare + 1e-9)
      return `not started: the owner offers ${pct(this.caps.gpuShare)}% of this box's GPU to hosting, ${pct(use.gpuInUse)}% of it is in use`
        + ` by running and starting partitions, and this one needs ${pct(gpuShare)}%; it starts when it fits (nothing running was stopped)`;
    return null;
  }

  // ---- the owner's hosting controls (hosting.mjs's local API, the tray app) -----------------------------------------
  hostingCaps() { return { ...this.caps }; }
  /**
   * dropPlan(caps) -> the units occupying this box that these caps leave no room for, as [{id, appRef, cpuShare,
   * gpuShare}], in the order they would go: the NEWEST first (the most recently claimed, then the most recently
   * recorded), each only if it frees an axis that is over, until use fits under both caps. Empty when it already fits.
   * Turning hosting OFF (caps.paused) leaves room for nothing: the plan is every unit, so the owner's games get the whole
   * machine back - CPU, GPU and memory - not just a box that stops taking new work.
   */
  dropPlan(caps) {
    const at = new Map([...this.records.values()].map((r, i) => [r.id, i]));
    const units = [...this.records.values()].filter((r) => Host.occupies(r))
      .sort((a, b) => (b.claimedAt || 0) - (a.claimedAt || 0) || at.get(b.id) - at.get(a.id));
    const unit = (r) => ({ id: r.id, appRef: r.appRef || "", cpuShare: r.cpuShare || 0, gpuShare: r.partitionGpuShare ?? (r.gpuShare || 0) });
    if (caps && caps.paused === true) return units.map(unit);
    let { cpu, gpuInUse } = this.shareUse();
    const plan = [];
    for (const r of units) {
      const cpuOver = cpu > caps.cpuShare + 1e-9, gpuOver = gpuInUse > caps.gpuShare + 1e-9;
      if (!cpuOver && !gpuOver) break;
      const c = r.cpuShare || 0, g = r.partitionGpuShare ?? (r.gpuShare || 0);
      if (!((cpuOver && c > 0) || (gpuOver && g > 0))) continue;
      plan.push({ id: r.id, appRef: r.appRef || "", cpuShare: c, gpuShare: g });
      cpu -= c; gpuInUse -= g;
    }
    return plan;
  }
  /** Hand back what the owner confirmed dropping, one at a time (each retires its domain, then releases its lease). */
  async #dropForCaps(ids, why) {
    for (const id of ids) {
      try { await this.#giveUp(id, why); }
      catch (e) { this.log(`${String(id).slice(0, 10)} could not be dropped for the owner's caps: ${e.message}`); }
    }
  }
  /**
   * OFF means nothing runs here: anything still occupying the box while hosting is off (a claim that landed as the owner
   * switched off, a drop that failed) is stopped and handed back. Every tick (host.tick), until hosting is turned on again.
   * -> the ids it stopped.
   */
  async enforceOff() {
    if (this.caps.paused !== true) return [];
    const left = this.dropPlan(this.caps).map((u) => u.id).filter((id) => !(this.offDropping || new Set()).has(id));
    if (!left.length) return [];
    this.offDropping = new Set([...(this.offDropping || []), ...left]);
    this.log(`hosting is off: stopping ${left.length} deployment(s) still on this box`);
    try { await this.#dropForCaps(left, "the owner of this box turned hosting off; handing the lease back so another host can take it"); }
    finally { for (const id of left) this.offDropping.delete(id); }
    return left;
  }
  /** What the owner offers on an axis: their cap, or nothing while they have hosting paused. */
  #offered(axis) { return this.caps.paused === true ? 0 : this.caps[axis]; }
  servedCount() { return [...this.records.values()].filter((r) => r.status === "running").length; }
  /** Persist, THEN apply: a cap that could not be saved changes nothing, so the tray snaps back to the truth. */
  setHostingCaps(next, { drop = [] } = {}) {
    saveCaps(this.capsFile, next);
    const was = this.caps;
    this.caps = { cpuShare: next.cpuShare, gpuShare: next.gpuShare, paused: next.paused === true }; this.capsError = null;
    const use = this.shareUse(), pct = (x) => `${Math.round(x * 100)}%`;
    if (was.paused !== this.caps.paused)
      this.log(this.caps.paused
        ? `hosting turned OFF by the owner of this box: no new work is taken, and the ${drop.length} deployment(s) occupying it are stopped and handed back`
        : "hosting turned ON by the owner of this box: new work is taken again under the caps");
    this.log(`hosting caps set on this box: CPU ${pct(was.cpuShare)} -> ${pct(this.caps.cpuShare)}, GPU ${pct(was.gpuShare)} -> ${pct(this.caps.gpuShare)}`
      + (drop.length ? `; dropping ${drop.length} running deployment(s) the owner confirmed, newest first`
        : use.cpu > this.caps.cpuShare + 1e-9 ? `; ${pct(use.cpu)} of the CPU is already in use, which keeps running: new work waits until use drops below the cap` : ""));
    // Only what the owner confirmed (hosting.mjs's handler checks it against dropPlan); never anything chosen here.
    if (drop.length) {
      const why = this.caps.paused
        ? "the owner of this box turned hosting off; handing the lease back so another host can take it"
        : `the owner of this box lowered its hosting caps to CPU ${pct(this.caps.cpuShare)}, GPU ${pct(this.caps.gpuShare)}, below what`
          + " was in use; handing the lease back so a box with room can take it";
      // marked in flight, so the tick's own off-enforcement does not stop the same deployment a second time
      this.offDropping = new Set([...(this.offDropping || []), ...drop]);
      this.capDrops = this.#dropForCaps(drop, why).finally(() => { for (const id of drop) this.offDropping.delete(id); });
    }
    return this.hostingCaps();
  }
  /** Does anything on the ACTIVE backend use the GPU? The tray says so rather than imply GPU hosting that is not happening. */
  gpuConsumer() {
    if (this.cfg.engineRetired === true) {
      const held = this.shareUse().gpuInUse;
      return held > 0 ? { consumer: true, why: `partitions on the isolated backend hold ${Math.round(held * 100)}% of the GPU` }
        : { consumer: false, why: "no partition currently holds a masked GPU allocation" };
    }
    const card = this.card && this.card();
    return card && Number(card.vramBudgetGb) > 0
      ? { consumer: true, why: "the enclave's model offloads to this card through the shielded worker" }
      : { consumer: false, why: "no shielded worker is answering, so nothing on this node uses the GPU" };
  }
  /** GET /v1/local/hosting: the caps, what is sold, in use and free, and what this backend does with the GPU. */
  hostingView() {
    const use = this.shareUse(), cap = this.capacity(), r4 = (x) => Math.round(x * 1e4) / 1e4;
    const recs = [...this.records.values()];
    return {
      caps: this.hostingCaps(), step: CAP_STEP, capsError: this.capsError,
      pricing: this.pricingView(),
      // The same accounting the claim gate and the isolated backend's spawn gate use (shareUse).
      sold: { cpuShare: r4(use.cpu), gpuShare: r4(use.gpu) },
      inUse: { cpuShare: r4(use.cpu), gpuShare: r4(use.gpuInUse) },
      // What a new claim is measured against: the caps, less what is in use, less the node's reserve.
      free: { cpuShare: r4(cap.cpuShareFree), gpuShare: r4(cap.gpuShareFree ?? 0) },
      reservedShare: this.cfg.reservedShare ?? 0.25,
      deploymentsServed: this.servedCount(),
      waitingForCap: recs.filter((r) => r.capHeld === true && r.status === "held").length,
      backend: this.cfg.engineRetired === true ? "hv" : "legacy",
      gpu: this.gpuConsumer(),
      appsEnabled: !!this.cfg.appsEnabled,
      market: this.marketStatus(),
      // the operator key's gas, so the TRAY says it before the apps go (a log line alone let the NucBox run dry, 10-13)
      gas: { operator: chain.operatorAddress() || null, low: this.gasLow === true,
             hoursLeft: this.gasHoursLeft ?? null, renewalsLeft: this.gasRenewals ?? null },
      logsDir: this.cfg.dir,
      // for the hosting panel (host-ui, shared with the phone's Enclave app): what it calls this machine, and the apps here
      // (what occupies it, newest first, as dropPlan orders them)
      device: { kind: "pc", noun: "PC" },
      apps: recs.filter((r) => Host.occupies(r)).sort((a, b) => (b.claimedAt || 0) - (a.claimedAt || 0))
        .map((r) => ({ id: r.id, appRef: r.appRef || "", phase: r.status === "running" ? "serving" : "starting" })),
    };
  }
  /**
   * marketStatus() -> { taking, why }: is this box taking NEW work from the network right now, as the network sees it?
   * The owner's switch is only the first condition: the relay lists a Shield host (and opens its claim window, scope())
   * only while it is attached, registered, has gas and its readiness witness verifies - which takes a few minutes after
   * every start or update. The tray shows this, not the switch, as "taking new work".
   */
  marketStatus(now = Date.now()) {
    const no = (why) => ({ taking: false, why });
    if (this.caps.paused === true) return no("hosting is off");
    if (!this.cfg.appsEnabled) return no("hosting is disabled on this node (APPS)");
    if (this.cfg.claimScope !== "market") return no("this node serves only its owner's apps (CLAIM_SCOPE)");
    if (this.relayAttached !== true) return no("not connected to the network yet");
    if (!this.registered) return no("not registered on the network yet");
    if ((this.gasRenewals ?? 1) <= 0) return no("the operator key has no gas left for claims");
    if (this.scope() !== "market")
      return no("the network is verifying this PC (a few minutes after every start or update)");
    return { taking: true, why: "listed on enclave.host" };
  }

  /**
   * What this box has left to sell, in the numbers a refusal can be checked against. The reserve
   * is not slack: the enclave holds the model and its pads in VTL1, the shielded worker feeds the
   * card, and the owner of the PC is entitled to their own machine.
   */
  capacity({ exclude = null, capped = true } = {}) {
    const slots = this.cfg.appSlots ?? 4;
    // `exclude` is how a deployment is sized against the room it would leave BESIDE the others
    // rather than beside itself, and it applies to EVERY axis - memory, node share and card share.
    // Two things need it: a restart re-reads a record that already carries its own floor, and a
    // RESIZE measures a tenant growing from 10% to 20% against a box that would otherwise still be
    // counting their first 10%. Either way, counting a deployment against itself refuses it for
    // asking for what it already has.
    const running = [...this.records.values()].filter((r) => r.status === "provisioning" || Host.occupies(r))
      .filter((r) => !exclude || String(r.id).toLowerCase() !== String(exclude).toLowerCase());
    const committedMb = running.reduce((a, r) => a + (Number(r.memMb) || 0), 0);
    // AN APP INSIDE THE ENCLAVE LIVES IN ENCLAVE MEMORY, and the enclave is a FIXED, DEDICATED
    // size chosen at creation (ee-main.cpp EnclaveSize). So the pool is that size, and what is
    // taken out of it is two measured things and nothing else:
    //
    //   - what the ENGINE holds: the model, its KV cache and the pads, read from the enclave
    //     itself before any app was claimed (the host protocol's `mem`).
    //   - what each running app was PROMISED: its declared floor, because the box has to keep
    //     that promise whether or not the app has touched the pages yet.
    //
    // What it is NOT is a fraction of the share ledger. The RAM cell used to be cpuShareFree x the
    // node's RAM, so a box that had sold 5% of its cores and reserved a quarter for its owner
    // reported 14 GB of its enclave "used" while four apps between them held half a gigabyte.
    // Cores are sold as a share; this memory is a fixed allocation, and it reports as one.
    const enclaveMb = Math.round((Number(this.cfg.enclaveGb) || 0) * 1024);
    const physicalMb = Math.round((Number(this.cfg.ramGb) || 0) * 1024);
    // RAM is an independent hosting budget, not a CPU share. Invalid explicit
    // budgets admit nothing; absence preserves the older reserved-share policy.
    const configuredRam = this.cfg.appRamGb;
    const hostMb = configuredRam === undefined || configuredRam === null
      ? Math.round(physicalMb * (1 - (this.cfg.reservedShare ?? 0.25)))
      : (Number.isFinite(configuredRam) && configuredRam >= 0
        ? Math.min(physicalMb, Math.floor(configuredRam * 1024)) : 0);
    // UNKNOWN is not ZERO. `engineHeldMb` is null until the node has asked the enclave what the
    // model, its KV cache and the pads hold (the host protocol's `mem`), and treating that as "the
    // engine holds nothing" would offer a tenant the WHOLE enclave including the part the engine
    // is already sitting in - an app admitted on that figure does not fit and thrashes VTL1.
    //
    // So an unmeasured box admits NOTHING NEW. It keeps serving what it already runs, and the
    // agent re-probes every tick, so this is a startup window that closes itself rather than a
    // state a box can be stuck in silently.
    // `Number(null)` is 0, so the null check has to come FIRST or "not measured" silently becomes
    // "measured as nothing" - which is the exact over-admission this guard exists to prevent.
    const raw = this.cfg.engineHeldMb;
    const measured = raw === null || raw === undefined || !Number.isFinite(Number(raw)) || Number(raw) < 0
      ? null : Number(raw);
    const engineMb = measured ?? 0;
    // The optional cap: an owner may keep an app ceiling below the enclave's own size. Absent, the
    // whole enclave less what the engine holds is the budget.
    const capMb = Number(this.cfg.enclaveAppRamMb) || 0;
    const budgetMb = this.appsInTee()
      ? (measured === null ? 0 : Math.min(Math.max(0, enclaveMb - engineMb), capMb > 0 ? capMb : Infinity))
      : hostMb;
    const ramMb = Math.max(0, budgetMb - committedMb);
    const card = this.card && this.card();
    const cpuFree = this.cpuShareFree({ exclude, capped }), gpuFree = this.gpuShareFree({ exclude, capped });
    // THE OWNER'S CAP, named when it is what limits an axis (the capped figure is below the uncapped one), so a refusal
    // says so (chain.mjs claimPolicy) instead of reading as a full box.
    const use = this.shareUse({ exclude });
    const cpuCap = capped && cpuFree < this.cpuShareFree({ exclude, capped: false }) - 1e-9 ? { offered: this.#offered("cpuShare"), used: use.cpu } : null;
    const gpuCap = capped && gpuFree < this.gpuShareFree({ exclude, capped: false }) - 1e-9 ? { offered: this.#offered("gpuShare"), used: use.gpu } : null;
    const paused = capped && this.caps.paused === true ? { paused: true } : {};       // absent unless paused: the old shape
    return { ...paused, slots, slotsFree: Math.max(0, slots - running.length), cpuShareFree: cpuFree,
             ramMbFree: ramMb, ramMbPool: this.appsInTee() ? enclaveMb : hostMb, ramMbEngine: engineMb,
             // Has the engine's own hold been measured? A caller that sees false knows ramMbFree
             // is a refusal, not a capacity.
             ramMeasured: !this.appsInTee() || measured !== null,
             // what catalog cpuGflops floors are checked against: the nominal 62.5-a-vCPU figure they were written in
             // (agent.mjs gflopsFloorBasis), not the measured nodeGflops this box publishes
             cpuGflops: Number(this.cfg.gflopsFloorBasis ?? this.cfg.gflops) || 0,
             // The card, in the same shape: what a GPU-dialled deployment is checked against.
             gpuShareFree: gpuFree, cardGb: card ? Number(card.vramBudgetGb) || 0 : 0,
             ...(cpuCap ? { cpuCap } : {}), ...(gpuCap ? { gpuCap } : {}) };
  }
  /**
   * Does an app this box hosts run INSIDE the enclave?
   *
   * DETECTED, never configured: the answer is whether the loaded enclave image carries an app
   * runtime, which the enclave itself answers (EeAppAbi -> `appabi` on the host protocol, read at
   * startup). A switch in a config file could say yes while the image said nothing, and this
   * property is the whole basis on which the box sells app hosting at all.
   */
  appsInTee() { return Number(this.cfg.enclaveAppAbi || 0) >= 1; }
  /**
   * THE LEGACY BACKEND IS RETIRED on a node started without the VBS enclave engine (cfg.engineRetired;
   * Steven, 2026-09-25). Only a deployment that requires THIS box's isolation backend by name runs here.
   * isolatedForThisBox(d) -> true when the deployment's envelope asks for this.isolationBackend. An unreadable
   * envelope, or a node with no isolation manager, is not that.
   */
  isolatedForThisBox(d) {
    if (!this.isolationBackend) return false;
    try { return chain.isolationForBackend(chain.parseEnvelope(d?.configCid, d?.gpuMilli), this.isolationBackend); }
    catch { return false; }
  }
  /**
   * heldReason(d) -> the reason a deployment this node already holds is HELD, or null. A held deployment is
   * refused and recorded, never started, never renewed (a tenant is not billed for a service this box cannot
   * give), and NEVER released on chain automatically. Giving a lease back is an on-chain transaction and the
   * operator's decision (enclave-d1 F2). A held lease simply lapses at leaseUntil.
   */
  heldReason(d) {
    // AN OWNER THIS BOX DOES NOT SERVE: a lease it holds whose ledger owner is not its operator or a delegated owner -
    // a deployment transferred away (rev 11), or taken under an owner rule that no longer authorizes it. Without this
    // the sweep kept renewing it and re-spawned it whenever it was not running, and a share resize or envelope edit ran
    // ensureApp(force) for it: N1's harm through the sweep instead of the route (enclave-bf).
    if (this.ownerNotServed(d))
      return `this node is in owner-only scope and serves only its operator's and its delegated owners' deployments; this one is `
        + `owned by ${d?.owner}: held - not started, not renewed, not released - pending the operator's decision`;
    if (this.cfg.engineRetired !== true || this.isolatedForThisBox(d)) return null;
    return "this node runs only the isolated backend (the legacy VBS-enclave backend is retired) and this deployment "
      + "does not require it: held - not started, not renewed, not released - pending the operator's decision";
  }
  /** ownerNotServed(d) -> true when, in owner-only scope, the deployment's ledger owner is not in ownerSet(). */
  ownerNotServed(d) {
    return this.servingScope() === "owner-only" && !this.ownerSet().has(String(d?.owner || "").toLowerCase()) && !this.servesAuditJob(d);
  }
  /**
   * claimRefusal(d, ...) -> why this box will not CLAIM ledger row `d` on policy, or null: chain.claimPolicy AND the
   * retired-engine rule (a NucBox claims only deployments requiring its partition backend), as ONE predicate that the
   * ledger scan and consider() both ask, so the scan can never take a row that consider() then refuses on policy
   * (enclave-d1's TEST2: an owner's older row with no isolation envelope passed the scan's claimPolicy, took the pass's
   * one claim, was refused by consider() on the retired-engine rule, and again every 30 s, so the owner's newer
   * hyperv row was never reached).
   */
  claimRefusal(d, { version = null, capacity, appsEnabled, invited = false, ownerAllow = this.ownerSet() }) {
    // an admitted audit job (servesAuditJob) is claimed as its fee wallet's own: owner-only scope still holds, because only
    // a payer this box serves can have created it here
    if (this.#auditAdmitted.has(String(d?.id || "").toLowerCase())) ownerAllow = new Set([...ownerAllow, String(d.owner || "").toLowerCase()]);
    return chain.claimPolicy(d, { isolationBackend: this.isolationBackend, ownerAllow, enclaveId: this.enclaveId,
                                  appsEnabled, scope: this.scope(), version, capacity, listedAt: this.listedAt(), invited,
                                  legacy: this.cfg.claimLegacy === true, fetchesConfigCid: this.features().configCidOverride,
                                  privateOk: !!this.cfg.sessionKid && (!this.partitionsOnly() || this.features().devDeploy),
                                  features: this.features() })
      || this.retiredEngineClaimRefusal(d);
  }
  static MARKET_GRACE_MS = 15 * 60_000;    // servingScope(): the relay's owner-read grace is the same 15 min
  static SCAN_HOLD_MS = 10 * 60_000;       // a refused row
  static SCAN_QUEUED_HOLD_MS = 2 * 60_000; // a queued one: its input may come back soon (the preclaim's unknown, the ledger's cap)
  static SCAN_CLAIMFAIL_HOLD_MS = 2 * 60_000; // a row whose claim tx failed twice running under the same inputs
  static SCAN_UNFUNDED_HOLD_MS = 6 * 3600_000; // a queued row whose lease expired with a zero balance: waits for a top-up
  /** unfundedExpired(d) -> the lease has ended and the deployment holds nothing to pay for another quantum. */
  static unfundedExpired(d) {
    let bal; try { bal = BigInt(d.balance6 ?? 0); } catch { return false; }
    return bal === 0n && Number(d.leaseUntil) * 1000 <= Date.now();
  }
  // at most this many rows a pass hands consider() and it declines, so a pool full of refused rows cannot make one pass
  // ask the chain and the relay about every row (enclave-bf's should-fix, enclave-87's bound); the next pass moves on,
  // past the ones now held
  static SCAN_DECLINED_PER_PASS = 16;
  /**
   * scanHoldKey(d, ownersVersion) -> what a row consider() declined is judged on, as the scan can see it: the row
   * (envelope, app, size, visibility, owner, active, funding, rate cap, lease) and this box (whom it serves, what it
   * charges). A change in any of them asks again; SCAN_HOLD_MS (refused) and SCAN_QUEUED_HOLD_MS (queued) bound what it
   * cannot see (the relay's secrets answer, the manager's supports, capacity freed by an app that ended).
   */
  scanHoldKey(d, ownersVersion) {
    return JSON.stringify([String(d.appRef || ""), String(d.configCid || ""), String(d.cpuMilli), String(d.gpuMilli), d.isPublic === true,
      String(d.owner || "").toLowerCase(), d.active === true, String(d.balance6 ?? ""), String(d.spent6 ?? ""), String(d.rate ?? ""),
      String(d.runner || "").toLowerCase(), String(d.leaseUntil ?? ""), ownersVersion, String(this.cfg.cpuPricePerSec6), String(this.cardPrice())]);
  }
  /** retiredEngineClaimRefusal(d) -> why a retired-engine node will not CLAIM a deployment, or null (see heldReason). */
  retiredEngineClaimRefusal(d) {
    if (this.cfg.engineRetired !== true || this.isolatedForThisBox(d)) return null;
    return "this node runs only the isolated backend (the legacy VBS-enclave backend is retired): "
      + `it claims only deployments compatible with ${this.isolationBackend || "an isolation backend it does not have"}`;
  }
  /** Marketplace claims require a fresh relay decision. The relay checks the
   * pinned boot/image/runtime and actual guest TLS key. The host's manager
   * statements and this local flag cannot authorize routing or certificates.
   * Only the restricted public partition runtime is currently admitted. */
  appTrafficInsideEnclave() { return false; }
  meetsIsolationContract() {
    return this.cfg.engineRetired === true && this.isolationBackend === "hyperv-partition-per-app"
      && this.relayTier === "hv-node" && Number(this.shieldMarketUntil || 0) > Date.now();
  }
  /**
   * Which scope this box claims in. The market is only open when an app runs inside the enclave
   * (appsInTee): claiming a stranger's deployment onto a runtime the enclave does not cover would
   * sell them the one thing they came here for and not deliver it. Until then the box runs its
   * OWNER's apps only, which is the owner's own machine and the owner's own call.
   */
  scope() { return this.meetsIsolationContract() && this.cfg.claimScope === "market" ? "market" : "owner-only"; }
  /** The relay's market window (agent.mjs, the shield-market frame): open until `until`, remembered past it for the grace. */
  openShieldMarket(until) {
    this.shieldMarketUntil = Number(until) || 0;
    if (this.shieldMarketUntil > Date.now()) this.shieldMarketSeenUntil = Math.max(Number(this.shieldMarketSeenUntil || 0), this.shieldMarketUntil);
  }
  /**
   * The scope this box SERVES what it already runs in: scope(), or "market" for MARKET_GRACE_MS past the relay's last
   * market window. A relay restart, a re-attach or a missed refresh lapses the window for a minute or two; without the
   * grace, every buyer's app here was held (unrenewed, its certificate and route refused) until the next window. NEW
   * claims still need a live window (scope(): scanLedger), and the relay still routes each app only on its own fresh
   * evidence (relay/shield-marketplace.mjs servesUntil): the grace keeps nothing reachable the relay has not verified.
   */
  servingScope() {
    if (this.scope() === "market") return "market";
    return this.cfg.claimScope === "market" && this.cfg.engineRetired === true && this.isolationBackend === "hyperv-partition-per-app"
      && this.relayTier === "hv-node" && Number(this.shieldMarketSeenUntil || 0) + Host.MARKET_GRACE_MS > Date.now() ? "market" : "owner-only";
  }
  /**
   * What this box adds to /availability.
   *
   * claimEnabled is the relay's question "does this box take work", and the answer is yes only
   * when it actually can: apps enabled, an operator key with gas, a registry entry with a price
   * and a proof key, and somewhere to put the work. Saying yes while any of those is missing
   * publishes capacity the platform would then offer and this box would refuse.
   */
  availability() {
    const running = [...this.apps.values()].filter((a) => a.state === "running").length;
    // partitions this node serves: a record with an isolation block is a running domain the app zone splices to
    const partitions = [...this.records.values()].filter((r) => r && r.isolation && r.status === "running").length;
    const cap = this.capacity();
    const ready = !!(this.cfg.appsEnabled && this.registered && Number(this.registered.cpuPricePerSec6) > 0
                     && chain.operatorAddress() && (this.gasRenewals ?? 1) > 0);
    return {
      // Does this box take work from the market at all? That is a question about CAPABILITY, not
      // about whether it is busy: an app runtime in the enclave, apps enabled, an operator key
      // with gas and a priced registry entry. How much room is left is `cpuShareFree` and
      // `nodeSlotsFree` beside it. Folding "full" into this made the box drop out of the serving
      // set the moment its fourth app started, which took its capacity, its price and its card off
      // the fleet's books - the opposite of what a full box should report.
      // ...and, above all of those, the isolation contract: a box that does not meet it takes no
      // tenant work and says so, whatever its scope config asks for (meetsIsolationContract).
      claimEnabled: this.meetsIsolationContract() && ready,
      // The honest word for what this box is: a seller of SOME of the platform's features. The
      // relay reads it and keeps this box out of the fleet-wide capability ANDs, the sizing floors
      // and the default price, so the flags below can be the plain truth about this box instead of
      // a promise the whole fleet has to keep.
      fullService: false,
      ...this.features(),
      // THE ISOLATION BACKEND, by the name a tenant's isolation.require and `enclave deploy --isolation` match (metal-iso0
      // advertises "snp-guest-per-app" the same way), or null without a manager. Its boundary is stated beside it and is
      // this backend's own, never a stronger one: a Hyper-V partition per app is T0-hv, and the host is NOT excluded.
      isolation: this.isolationBackend,
      ...(this.isolationBackend ? { isolationBoundary: { tier: "T0-hv", hostExcluded: false } } : {}),
      // The relay's verdict on this node's attach, as it gave it (null until attached): tier "hv-node", hostExcluded false.
      attach: { tier: this.relayTier || null, hostExcluded: this.relayHostExcluded ?? null },
      apps: this.appsInTee() ? {
        // Where a leased app runs, in the one word that matters: INSIDE the enclave. The bytecode
        // is interpreted in VTL1 by the runtime linked into the measured image, so the app's code
        // and memory are covered by the same attestation as the model beside it. What is NOT
        // covered is the traffic: VTL0 owns the socket and carries the request and response
        // frames, exactly as the platform's relay does for every other box in the fleet.
        isolation: "vbs-enclave", inTee: true, runtime: "wasmtime-pulley", abi: Number(this.cfg.enclaveAppAbi || 0),
        worlds: [...(Number(this.cfg.enclaveAppWorlds || 1) & 1 ? ["enclave:app@0.1.0"] : []),
                 ...(Number(this.cfg.enclaveAppWorlds || 1) & 2 ? ["wasi:http@0.2"] : []),
                 ...(Number(this.cfg.enclaveAppWorlds || 1) & 4 ? ["wasi:cli@0.2 (its own socket, brokered)"] : [])],
        world: "enclave:app@0.1.0", traffic: "carried by the host",
        // The contract verdict this box gives about ITSELF, for the row and for the operator's own
        // eyes: false today, with the reason. The relay's verdict is the one that counts.
        isolationContract: this.meetsIsolationContract(),
        ...(this.meetsIsolationContract() ? {} : { contractGap: "app-zone TLS key and traffic run through the host OS; tier " + (this.relayTier || "unverified") }),
        scope: this.scope(), public: true, running, capacity: cap.slots,
        // The enclave's dedicated size, what the engine holds of it, and what is free - the three
        // numbers that make the pool checkable rather than asserted.
        ramMb: cap.ramMbPool, engineMb: cap.ramMbEngine, ramMbFree: cap.ramMbFree,
        note: "an app runs inside the VBS enclave, interpreted from bytecode; its host carries the request and response bytes",
      } : this.isolationBackend ? {
        // THE ISOLATED BACKEND (enclave-b4's N5): each deployment in its own Hyper-V partition. It used to fall into the
        // branch below and say isolation "none", capacity 0 and "sells no app hosting" while partitions served.
        isolation: this.isolationBackend, tier: this.meetsIsolationContract() ? "enclave-shield" : "T0-hv", hostExcluded: false, hostOsExcluded: this.meetsIsolationContract(), operatorExcluded: false, inTee: false,
        running: partitions, capacity: cap.slots, scope: this.scope(),
        note: this.meetsIsolationContract() ? "each app has a measured Shield partition and guest-held TLS key; the relay verifies app evidence; physical operator and hypervisor remain trusted" : "each deployment runs in its own Hyper-V partition; marketplace admission awaits the relay’s app-evidence check",
      } : {
        // No app runtime in this enclave image: the box hosts nothing for a tenant. The VTL0
        // wasmtime path still exists for the box owner's own bring-up, and is not an offer.
        isolation: "none", inTee: false, running, capacity: 0,
        note: "this enclave image carries no app runtime, so this box sells no app hosting",
      },
      // The app's own origin: whether this box can answer a TLS handshake for it, and WHERE the
      // key lives. On a confidential VM the key is minted inside the measured guest; here it is in
      // the agent's process in VTL0, which is the same place the /x/ path's plaintext already
      // passes through. Published rather than implied.
      // WHERE THE SESSION KEY LIVES, published for the same reason appTls.keyIn is. On a
      // confidential VM this key is minted inside the measured guest, so the operator cannot forge
      // a session for somebody else's wallet. Here it is in the agent's process in VTL0, so on
      // this box a session is worth what the machine owner's word is worth - which is the SAME bar
      // this box already publishes for app traffic, not a new one.
      session: this.cfg.sessionKid
        ? { kid: this.cfg.sessionKid, alg: "ES256", keyIn: "host-process", jwks: "/v1/session-jwks",
            note: "private deployments are served to their owner; the key that proves it is in the agent's process, not inside the enclave" }
        : null,
      appTls: !this.appsInTee() && this.isolationBackend ? {
        // a partition's hostname is spliced to it UNOPENED (node-bridge.mjs): the key and the handshake are the partition's
        served: partitions > 0, zone: this.cfg.appZone, keyIn: "partition", terminatesIn: "partition",
        note: "each isolated deployment's hostname is spliced to its partition unopened; the partition holds the key and ends TLS",
      } : {
        served: this.appsInTee() && Number(this.cfg.enclaveAppWorlds || 0) & 4 ? true : false,
        zone: this.cfg.appZone, keyIn: "host-process", terminatesIn: "host-process",
        issued: [...this.appCerts.values()].filter((c) => c.cert && !c.cert.selfSigned).length,
        selfSigned: [...this.appCerts.values()].filter((c) => c.cert && c.cert.selfSigned).length,
        note: "the app's own hostname is answered by this box; its TLS key is in the agent's process, not inside the enclave",
      },
      claimScope: this.scope(),
      // The REGISTRY's price, not the config's, when this box is listed: that entry is what the
      // ledger charges a lease and therefore what a buyer would actually pay. The config value is
      // only what a fresh box would register itself at.
      askCpuPricePerSec6: Number(this.registered?.cpuPricePerSec6) || this.cfg.cpuPricePerSec6,
      // The CARD's price, on the same rule: the registry entry when this box is listed, because
      // that is what the ledger would charge. Zero means this box sells no card share - either it
      // has none, or it has not registered a price for the one it has.
      // what this box ASKS: the registry's figure when it sells a card, 0 when it does not (engine retired, gpu:false)
      askGpuPricePerSec6: this.sellsCard() ? Number(this.registered?.gpuPricePerSec6) || 0 : 0,
      // ...and the same number under the name a SHIELDED pool's price is read by. The platform's
      // own boxes publish both from one on-chain figure (supervisor.js: askShieldedPricePerSec6 =
      // SELL_GPU_PRICE6), because the card is charged as the card whichever side of the enclave it
      // sits on; what differs is only which pool the fleet row draws it under. A box that posted
      // only askGpu rendered a shielded pool with no rate at all, which reads as "free".
      ...(Number(this.registered?.gpuPricePerSec6) > 0 && this.card()
            && this.sellsCard() ? { askShieldedPricePerSec6: Number(this.registered.gpuPricePerSec6) } : {}),
      nodeSlotsFree: cap.slotsFree, ramMbFree: cap.ramMbFree,
      // The enclave's memory as the fleet row reads it: a FIXED pool and what is really left of
      // it. ramGbFree is the field the row prefers over the share-derived figure, and publishing
      // it is what stops a box that sold 5% of its cores from reporting 14 GB of its enclave
      // "used" while its apps hold half a gigabyte between them.
      ramGbFree: Math.round((cap.ramMbFree / 1024) * 10) / 10,
      ramGbEngine: Math.round((cap.ramMbEngine / 1024) * 10) / 10,
      enclaveId: this.enclaveId,
      registered: !!this.registered,
      operator: chain.operatorAddress() || null,
      gasRenewalsLeft: this.gasRenewals ?? null,   // an operator key out of gas stops renewing, and the app goes at the end of its quantum
      gasHoursLeft: this.gasHoursLeft ?? null,     // the key's MEASURED runway (warnLowGas); null until half an hour of samples

      proofKey: chain.proofAddress() || null,
      // whose deployments this box serves (ownerSet): its operator and its delegated owners, never the payout wallet
      owners: [...this.ownerSet()],
    };
  }
  /**
   * Exactly which of the platform's deployment features this box implements. The relay AND-folds
   * these across the full-service fleet; this box is not in that fold (fullService: false), so
   * these describe THIS box and nothing else. A true here is a promise the claim policy keeps: if
   * a flag is false, a deployment that needs it is refused by name rather than run without it.
   */
  /** Does this node run ONLY the isolated backend (the engine retired, a manager configured)? Then what it offers a
   *  deployment is what a partition can be given, not what the enclave's runtime could do. */
  partitionsOnly() { return this.cfg.engineRetired === true && !!this.isolationBackend; }
  /** A partition capability: the node's own plan allows it (PARTITION_OFFERS) AND the manager's /health supports it. */
  partitionOffers(plan, supports = plan) {
    return PARTITION_OFFERS[plan] === true && !!this.managerSupports && this.managerSupports[supports] === true;
  }
  features() {
    // THE ISOLATED BACKEND offers what a partition can be given (enclave-87, from d1's live node at 013deb51, which
    // advertised secrets, secretsInConfig, configOverride and customDomains as true while its plan refuses every one).
    // Each is the node's plan AND the manager's word; today every one is false, and the claim gate refuses such a
    // deployment by name instead of claiming it.
    if (this.partitionsOnly()) {
      const config = this.partitionOffers("config"), configCid = this.partitionOffers("configCid");
      return {
        configOverride: config, gpuOptional: false, cpuFallback: true,
        networkOptions: this.partitionOffers("egress"), rateCap: true, proofOfTime: true,
        waf: this.partitionOffers("waf"),
        secrets: this.partitionOffers("secrets") && !!this.cfg.secretsSign,
        secretsInConfig: this.partitionOffers("secrets") && config && !!this.cfg.secretsSign,
        configCid, configCidOverride: configCid, configEdit: config,
        shareResize: true,
        customDomains: this.partitionOffers("customDomains"),
        devDeploy: this.partitionOffers("privateDeployments") && !!this.cfg.sessionKid,
        mem64: this.managerSupports?.mem64 === true, set: this.managerSupports?.set === true, p3: false, coopThreads: false,
        volumes: this.managerInference?.ready ? [this.managerInference.model] : [],
      };
    }
    return {
      // What it does implement.
      configOverride: true,   // the envelope's `config` namespace: the deployment's app-config replaces the version's (appConfig() below)
      gpuOptional: true,      // {"gpu":{"optional":true}}: a card-dialled deployment may run here on cores instead of queueing for a card
      cpuFallback: true,      // a version config's cpuFallback ({memMb, cpuGflops}) raises the node floor this box demands of a coreless placement (chain.nodeFloorOf)
      networkOptions: true,   // the envelope's `network` namespace is understood and not refused; the choice itself is consumed at the DNS layer, as it is on every runner
      rateCap: true,          // it prices a claim off its own registry entry, asks the ledger first (claimableBy) and treats a cap-blocked renew as "stop at lease end"
      proofOfTime: true,      // it signs EIP-712 checkpoints from the proof key in its registry entry; /v1/attestation says where that key lives, which on this box is the Windows host
      // What it does not, each one a refusal in chain.claimPolicy rather than a silent gap.
      // Per-deployment protection rules (rate, concurrency, body size, method/path/agent filters),
      // enforced at BOTH of this box's doors because they funnel through one proxy. Mirrored from
      // the platform runner down to the status codes: the envelope is fail-closed, so a box that
      // read these rules differently would leave the same deployment protected in one place and
      // open in another.
      //
      // ONE HONEST DIFFERENCE, published rather than implied. On the /x/<id> path the relay
      // forwards the caller's address and the limits are per-address, as on the fleet. On the
      // app's OWN hostname the relay splices TLS bytes without terminating them, so there is no
      // client address to read and the rate and concurrency limits there count the DEPLOYMENT as a
      // whole. The filters (method, path, agent, body size) are unaffected either way.
      waf: true,
      // Relay-stored secrets, fetched as the lease holder and injected INTO the enclave with the
      // app's environment (secrets.mjs, host.loadSecrets) - AND resolved inside the app's config,
      // which is what `secretsInConfig` means. An app that resolves its own placeholders (the
      // s3-ipfs-adapter does) worked either way; one that expects the runner to do it (risc-box's
      // config is "$S3_ENDPOINT" and four more) did not, and simply started unconfigured.
      secrets: !!this.cfg.secretsSign, secretsInConfig: !!this.cfg.secretsSign,
      // BOTH halves of the rev-7 split, because the envelope shares one ledger field with
      // everything else and an app config bigger than that has nowhere else to live.
      //   configCidOverride  the OWNER's: the envelope's `configCid` namespace.
      //   configCid          the PUBLISHER's: the catalog version's own configCid, read through
      //                      versionConfigCid when the catalog says it speaks rev 7.
      // Either way the bytes are fetched and RE-HASHED against the CID the chain names before they
      // become an app's configuration. A box that knew only the inline field would hand such an
      // app its ROUTING MANIFEST and call it configured.
      configCid: true, configCidOverride: true,
      // An owner's setConfig reaches a LIVE deployment: the protection rules swap in place and a
      // config change relaunches the app on the new value (envelopeVerdict, mirrored from the
      // platform runner and checked against its own self-test seam).
      configEdit: true,
      // ...and setShares does too: the card half really re-slices (it gates the model in VTL1), the
      // node half is an admission and billing figure on this box, and a resize that no longer fits
      // hands the lease back rather than billing for a size it is not serving.
      shareResize: true,
      // A hostname the deployment's owner attached and proved: this box reads the list from the
      // relay (operator-signed, scoped by the live lease), gets a certificate for each name from
      // the same service that certifies its own subdomain, answers TLS for them by SNI, and hands
      // the guest ENCLAVE_HOSTS. Reported false when the box has no operator key to sign the
      // fetch with, because then it cannot learn the names at all and a lease landing here would
      // leave the customer's domain dark with nothing on the dashboard to explain it.
      customDomains: !!this.cfg.secretsSign && this.cfg.customDomains !== false,
      // A PENDING catalog version may run on a PRIVATE deployment - a publisher testing their own
      // app before the catalog owner has approved it. Public deployments of a pending version stay
      // refused, here as on the fleet. Both depend on being able to verify who is asking.
      devDeploy: !!this.cfg.sessionKid,
      // The wasm features, READ OFF THE ENCLAVE (the runtime's own ee_rt_features, carried out
      // through `appabi`). Never a config value: these are compile-time engine features recorded
      // in every cwasm, so a box that advertised one its image does not build would take a lease
      // and then refuse the artifact.
      //
      // `set` is the one that costs real work: wasmtime refuses the threads proposal outright for
      // a Pulley target, and with that gate lifted the compiler stops at the first `atomic_rmw`
      // for want of a lowering - Pulley's ISA has no atomic instructions at all. Until they exist
      // this stays false and a version declaring set:true is refused by name.
      mem64: !!(Number(this.cfg.enclaveAppFeatures) & 1),
      set: !!(Number(this.cfg.enclaveAppFeatures) & 2),
      p3: !!(Number(this.cfg.enclaveAppFeatures) & 4),
      coopThreads: !!(Number(this.cfg.enclaveAppFeatures) & 8),
      volumes: [],            // no attested model volumes: the one model on this box is the enclave's own
    };
  }

  /**
   * Run an app by catalog reference or CID with NO lease behind it. This is a bring-up and proof
   * path for the box's owner, reachable only on the loopback surface (agent.mjs never routes it
   * from the tunnel), and every record it makes says `leased: false` so nothing here can be
   * mistaken for a deployment the ledger knows about.
   */
  async runUnleased({ appRef, cid, id }) {
    if (!this.cfg.appsEnabled) throw new Error("apps are not enabled on this node (APPS=1)");
    let v = null;
    if (appRef) { v = await chain.resolveAppRef(appRef); cid = v.cid; }
    if (!cid) throw new Error("give appRef (catalog://<appId>/<index>) or cid");
    const key = String(id || `local-${cid.slice(-12)}`).toLowerCase();
    const art = await fetchArtifact({ cid, dir: path.join(this.cfg.dir, "apps"), python: this.cfg.python, gateway: this.cfg.gateway, log: (m) => this.log(m) });
    const layer = wasmLayer(art.path);
    if (layer !== 1) throw new Error(`the artifact is a core wasm module (layer ${layer}), not a wasi:http component`);
    const needs = missingHostInterfaces(art.path);
    if (needs.length) throw new Error(`this box cannot run it: the artifact needs ${needs.join(" and ")}`);
    let app = this.apps.get(key);
    if (app) { await app.stop(); this.apps.delete(key); }
    const memMb = Number(v?.memMb) || 512;
    const port = this.cfg.portBase + 32 + (this.apps.size % 16);
    app = new App({ id: key, wasmtime: this.cfg.wasmtime, wasmPath: art.path, port, memMb, allowHttp: true,
                    dir: this.cfg.dir, log: (m) => this.log(m),
                    env: appEnv({ config: String(v?.config || ""), memMb, inferenceUrl: this.cfg.inferenceUrl }) });
    this.apps.set(key, app);
    this.#record(key, { status: "provisioning", leased: false, appRef: appRef || null, cid, version: v?.version || null, memMb });
    await app.start();
    return this.#record(key, { status: "running", reason: null, port: app.port, leased: false });
  }

  /**
   * What the app-zone half needs to answer a TLS handshake for this deployment: the app's own
   * loopback port and a certificate for its hostname. Null when this box does not serve it.
   *
   * The certificate is fetched ONCE and kept (apptls.mjs writes it beside the agent), and a
   * failure is remembered with its backoff so a browser hammering a name this box cannot certify
   * does not hammer the relay's issuer with it. A pending issuance answers null, which the caller
   * turns into a 503 rather than a broken handshake.
   */
  /**
   * Learn this deployment's custom hostnames, and get a certificate for each.
   *
   * Runs on the tick for every deployment this box is serving, because an owner attaches a domain
   * while the app is already running - that is the whole point of the feature - and a lease that
   * only read the list at claim time would leave the customer's name dark until the next turnover.
   *
   * The failure semantics are the platform runner's and they are not symmetrical (domains.mjs has
   * the reasoning): an authoritative "none" clears the list, but an unreachable relay KEEPS it,
   * because forgetting a hostname is an outage on a name the customer owns.
   */
  async refreshDomains(id, { forLaunch = false } = {}) {
    if (!this.cfg.secretsSign || !this.cfg.customDomains) return;
    const rec = this.records.get(id);
    // `forLaunch` is the cold-start call, made while the record is still "provisioning": the names
    // have to be known BEFORE the environment is built, or the guest starts without them.
    if (!rec || (!forLaunch && rec.status !== "running")) return;
    // Lower-cased once, as #certifyHost and forgetDomains already do: the index is written through
    // #setOwner, which normalises, so comparing a raw id against it is a bug waiting for the first
    // mixed-case deployment id to arrive.
    const key = String(id).toLowerCase();
    const previous = this.domains.get(id) || [];
    // What to tell the customer about names that did not get a certificate. This is the only way
    // somebody learns a CA refused their domain, so it rides on the next fetch and is cleared only
    // once the relay has taken it.
    const report = [];
    for (const h of previous) {
      const r = this.certReports.get(h);
      // OURS only. The map is keyed by hostname, so a report found under a name this deployment
      // now holds may still be the PREVIOUS owner's account of why their certificate was refused -
      // and that is their CA's message about their DNS, delivered to somebody else's customer.
      if (!r || r.owner !== key) continue;
      const { owner, ...rest } = r;
      report.push({ hostname: h, ...rest });
    }
    let r;
    try {
      r = await fetchDomains({ id, endpoint: this.cfg.endpoint, sign: this.cfg.secretsSign,
                               base: this.cfg.relayBase, previous, report, log: (m) => this.log(m) });
    } catch (e) { this.log(`domains ${id.slice(0, 10)}: ${e.message}`); return; }
    for (const h of r.delivered) if (this.certReports.get(h)?.owner === key) this.certReports.delete(h);
    if (r.source === "kept" && r.why && rec.domainWhy !== r.why) {
      this.log(`domains ${id.slice(0, 10)}: ${r.why}; keeping the ${previous.length} name(s) already known`);
      this.#record(id, { domainWhy: r.why });
    }
    const before = previous.join(",");
    this.domains.set(id, r.hosts);
    // ONLY AN AUTHORITATIVE ANSWER MAY MOVE OWNERSHIP. `source: "kept"` is this box's own stale
    // cache, returned because the relay could not be reached - it keeps the app answering, which
    // is the point, but it is not NEWS. Writing it into the index let a deployment RECLAIM a name
    // that had already moved to another one: A loses the name, B takes it, A's next fetch fails,
    // and A's stale list put A back in the index and started re-issuing a certificate for it.
    // A cache must never override newer knowledge.
    if (r.source === "relay" || r.source === "none") {
      for (const h of r.hosts) this.#setOwner(h, id);
      for (const h of previous) if (!r.hosts.includes(h) && this.domainOwner.get(h) === key) this.#setOwner(h, null);
    }
    if (before !== r.hosts.join(",")) {
      // A name that has gone away stops being served AND stops being certified: its key is dropped
      // here rather than left on disk answering for a domain this deployment no longer owns.
      for (const h of previous) {
        if (r.hosts.includes(h)) continue;
        // Same rule as forgetDomains: a detached name whose certificate now belongs to another
        // deployment is not ours to delete.
        if (this.hostCerts.get(h)?.owner === key) this.hostCerts.delete(h);
        // Ours to drop only if it IS ours: by now the name may already have been taken by another
        // deployment, whose first attempt must not inherit this one's silence.
        if (this.certReports.get(h)?.owner === key) this.certReports.delete(h);
        if (this.domainFails.get(h)?.owner === key) this.domainFails.delete(h);
      }
      this.log(`domains ${id.slice(0, 10)}: ${r.hosts.length ? r.hosts.join(", ") : "no custom domains"}`);
      this.#record(id, { domains: r.hosts, domainWhy: null });
    }
    // Certificates only for names this box currently believes are OURS. On a kept answer that is
    // whatever the index says, which may be nothing - and asking a CA to certify a name another
    // deployment now holds is the very thing the index exists to prevent.
    for (const h of r.hosts) if (this.domainOwner.get(h) === key) await this.#certifyHost(id, h);
  }

  /**
   * Record who owns a hostname, and bump its GENERATION.
   *
   * The generation is what makes a late answer safe to discard. Certificate issuance is an await
   * of unbounded length - an ACME order can take minutes - and a name can move underneath it. A
   * result that lands after the move must not be stored, however correct it was when it was asked
   * for.
   */
  #setOwner(hostname, id) {
    const cur = this.domainOwner.get(hostname) || null;
    const next = id ? String(id).toLowerCase() : null;
    if (cur === next) return;
    this.domainGen.set(hostname, (this.domainGen.get(hostname) || 0) + 1);
    if (next) this.domainOwner.set(hostname, next); else this.domainOwner.delete(hostname);
  }

  /** One custom hostname's certificate, with its own backoff and its own report to the customer. */
  async #certifyHost(id, hostname) {
    const key = String(id).toLowerCase();
    const have = this.hostCerts.get(hostname);
    // Reused only if it was minted FOR THIS DEPLOYMENT. A name that has moved between deployments
    // gets a fresh certificate for its new owner rather than inheriting the old one: the entry is
    // keyed by hostname across the whole box, and handing B a certificate obtained on A's behalf
    // would have this box assert an identity B never proved. Found by the test - the index said B
    // and the cached entry still said A, so nobody could serve the name at all.
    if (have?.cert && have.owner === key
        && new Date(have.cert.notAfter).getTime() - Date.now() > 7 * 24 * 3600 * 1000) return;
    if (have && have.owner !== key) this.log(`custom domain ${hostname}: moved to ${key.slice(0, 10)}; getting its own certificate`);
    // A backoff belongs to the deployment that EARNED it. Reading it by hostname alone let one
    // deployment's rate-limited order suppress another's first attempt ever - and because that
    // attempt never ran, the previous owner's failure report stayed under the name and went out
    // to the new owner's customer as though it were about them. Found by the test: B's domain sat
    // uncertified for the rest of A's hour while the CA would happily have said yes.
    const fail = this.domainFails.get(hostname);
    if (fail && fail.owner === key && Date.now() < fail.until) return;
    // Captured BEFORE the await. An ACME order can take minutes and a name can move underneath it.
    const gen = this.domainGen.get(hostname) || 0;
    const stillOurs = () => this.domainGen.get(hostname) === gen && this.domainOwner.get(hostname) === key;
    try {
      // `issueCert` is injectable so a test can drive the REAL bookkeeping below - the ownership
      // stamp, the index, the teardown - with the certificate authority stubbed out. A test that
      // wrote into hostCerts itself would be reimplementing the very thing it is checking.
      const issue = this.cfg.issueCert || ensureCert;
      const cert = await issue({ id, endpoint: this.cfg.endpoint, sign: this.cfg.secretsSign,
                                 base: this.cfg.relayBase, dir: this.cfg.dir,
                                 hostname, log: (m) => this.log(m) });
      // The entry carries its OWNER. The map is keyed by hostname across the whole box, so a
      // context found under a name is not by itself evidence that this deployment may present it:
      // belt and braces with the live index below, because between them is another tenant's
      // identity.
      if (!stillOurs()) {
        // The name moved while we were asking. Storing this would put a certificate obtained on
        // our behalf under a name somebody else now owns - and would set `owner` back to us.
        this.log(`custom domain ${hostname}: it moved while its certificate was being issued; discarding the result`);
        return;
      }
      this.hostCerts.set(hostname, { cert, ctx: tls.createSecureContext({ key: cert.key, cert: cert.cert }),
                                     owner: key });
      this.certReports.set(hostname, { owner: key, ok: true, notAfter: cert.notAfter, at: new Date().toISOString() });
      this.domainFails.delete(hostname);
      this.log(`${id.slice(0, 10)} custom domain ready: https://${hostname}/`);
    } catch (e) {
      if (!stillOurs()) return;          // a failure for a name that is no longer ours says nothing
      const wait = Math.max(60, Number(e.retryAfterSec) || 600) * 1000;
      this.domainFails.set(hostname, { owner: key, until: Date.now() + wait });
      // Reported to the CUSTOMER, not just logged here: a CA refusing their domain is something
      // only they can fix, and they cannot see this box's logs.
      this.certReports.set(hostname, { owner: key, ok: false, error: "issue_failed",
                                       message: String(e.message).slice(0, 200), at: new Date().toISOString() });
      this.log(`custom domain ${hostname}: ${e.message} (retrying in ${Math.round(wait / 1000)}s)`);
    }
  }

  /**
   * Drop every hostname this deployment answered on, with its key and its pending report.
   *
   * One function so that losing a lease, giving one up and a name being detached all converge -
   * and so a test can exercise the REAL cleanup instead of repeating it, which would go green
   * against a regression in the thing it is meant to guard.
   *
   * A hostname is only released from the global index if THIS deployment still owns it: a name
   * already reassigned belongs to somebody else, and taking it out on the old owner's teardown
   * would leave the new one unable to serve it.
   */
  forgetDomains(id) {
    const key = String(id).toLowerCase();
    for (const h of this.domains.get(key) || []) {
      // Only what this deployment STILL owns. A name already reassigned belongs to somebody else,
      // and taking its certificate out on the old owner's teardown would leave the new one unable
      // to serve a domain it legitimately holds - found by the test, not by reading.
      if (this.domainOwner.get(h) !== key) continue;
      this.domainOwner.delete(h);
      if (this.hostCerts.get(h)?.owner === key) this.hostCerts.delete(h);
      this.certReports.delete(h);
      this.domainFails.delete(h);
    }
    this.domains.delete(key);
  }

  /**
   * The wallet that may reach this deployment, if it is PRIVATE - otherwise null.
   *
   * Read from the ledger record this box already holds, so the answer cannot drift from the
   * deployment's own state. A record this box does not have returns null, which means "not
   * private here": the caller is about to get a 404 from the app path anyway, and pretending a
   * deployment we do not serve is private would leak that it exists somewhere.
   */
  privateOwner(id) {
    const rec = this.records.get(String(id).toLowerCase());
    if (!rec || rec.isPublic !== false) return null;
    return String(rec.owner || "").toLowerCase() || null;
  }

  /** Every hostname a deployment answers on: its own subdomain first, then the customer's. */
  hostsFor(id) {
    const names = [];
    const rec = this.records.get(String(id).toLowerCase());
    if (rec?.appHost) names.push(rec.appHost);
    else names.push(appHostFor(id, this.cfg.appZone));
    for (const h of this.domains.get(String(id).toLowerCase()) || []) names.push(h);
    return names;
  }

  /**
   * What the app zone needs to serve one deployment: its protection rules (so a request is parsed
   * rather than spliced), its body ceiling (so the READ stops at the limit instead of buffering
   * past it), and which certificate to present for a given SNI name.
   *
   * Public rather than private because the app zone is a separate module that consumes it, and
   * because a test that reimplements `contextFor` proves only that the reimplementation works -
   * which is exactly how a cross-tenant check would go green while the real one drifted.
   */
  zoneRules(id) {
    const key = String(id).toLowerCase();
    const w = this.records.get(key)?.waf || null;
    // contextFor: the certificate to present for a given SNI name. The app zone cannot know which
    // of a deployment's hostnames a browser asked for until the ClientHello arrives, so the choice
    // is a callback rather than a field. An unknown name answers null and the default is served,
    // which gives the browser a name mismatch it can explain rather than a reset.
    return {
      waf: w, bodyLimit: waf.bodyLimit(w),
      // A private deployment must be PARSED rather than spliced to its port: an opaque byte stream
      // carries no Authorization header and no cookie, so there is nothing to check. The app zone
      // reads this and takes the parsed path, which ends in `proxy` above.
      private: !!this.privateOwner(key),
      contextFor: (name) => {
        const h = String(name || "").toLowerCase().replace(/\.+$/, "");
        // Asked of the LIVE index at handshake time, not of a list captured when this object was
        // built. Certificates are keyed by hostname across the whole box, so a name that moves
        // between deployments would otherwise let the OLD owner keep serving it - presenting the
        // NEW owner's certificate - for as long as the captured array survived, and a connection
        // can sit between `resolve` and its ClientHello for as long as a client cares to take.
        if (this.domainOwner.get(h) !== key) return null;
        const e = this.hostCerts.get(h);
        // BOTH must agree. The index says who owns the name now; the entry says who the context
        // was minted for. A disagreement is a name mid-move, and mid-move nobody serves it.
        return e && e.owner === key ? e.ctx : null;
      },
    };
  }

  async appZoneTarget(ref) {
    // A label (the first 8 hex, which is what the hostname carries) or a full id: resolved against
    // the leases this box holds, so a prefix that matches nothing here is simply not ours.
    let id = String(ref).toLowerCase();
    if (!/^0x[0-9a-f]{64}$/.test(id)) {
      const pre = id.startsWith("0x") ? id : "0x" + id;
      const hit = [...this.records.keys()].filter((k) => k.startsWith(pre));
      if (hit.length !== 1) return null;
      id = hit[0];
    }
    const rec = this.records.get(id);
    // WHOSE app: in owner-only scope a deployment whose ledger owner this box no longer serves (a delegation removed,
    // expired or invalid) is never spliced, whatever list the relay still holds - the removal takes effect here at once
    // (enclave-bf's belt, enclave-87's revocation ruling on the make-before-break re-attach).
    if (rec && rec.owner && this.servingScope() === "owner-only" && !this.ownerSet().has(rec.owner) && !this.servesAuditJob({ id, appRef: rec.appRef })) return null;
    // AN ISOLATED DEPLOYMENT HAS NO `app` HERE, AND MUST NOT NEED ONE.
    //
    // Its process is a partition, not an entry in this.apps, so the checks below - which want a
    // port and a certificate this agent holds - are all wrong for it. Before this, an isolated
    // record fell through to `!app` and answered null, which the app zone turns into a 503: the
    // deployment would have been running and unreachable (enclave-5d, tracing the real route).
    //
    // Nothing here terminates TLS for it. The target says only WHICH domain to splice to; the
    // guest holds the key and does the handshake, which is the entire point of the tier.
    if (rec && rec.isolation) {
      const { isolatedTarget } = await import("../vbslike/datapath/node-bridge.mjs");
      return isolatedTarget(id, rec, this.cfg.appZone);
    }
    const app = this.apps.get(id);
    if (!rec || rec.status !== "running" || !app) return null;
    // A server-shaped app has a port to proxy into. A GATE-SERVED app (wasi:http, enclave:app)
    // does not, so its origin is served the other way: the TLS session is terminated here, the
    // request is parsed out of it and carried through the gate as a frame, exactly as the /x/
    // path does. Either way the app's own hostname works, which is what a browser needs before
    // it will show a closed padlock.
    const gate = !app.port;
    const have = this.appCerts.get(id);
    if (have && have.cert && !have.cert.selfSigned) return { id, port: app.port, gate, cert: have.cert, ...this.zoneRules(id) };
    // The FALLBACK pair, while the real certificate is being issued. Without it the connection
    // dies at the first byte and the failure reads as a broken box rather than a certificate that
    // has not arrived; with it the path is provable (a client told to skip verification gets the
    // app) and a browser sees exactly what the console's amber padlock is warning about. The
    // platform's own boxes do the same thing.
    const fallback = () => {
      let f = this.appCerts.get(id);
      if (!f || !f.cert) {
        f = { cert: selfSigned(appHostFor(id, this.cfg.appZone)) };
        this.appCerts.set(id, f);
        this.log(`${id.slice(0, 10)} app-zone: serving a self-signed pair for ${f.cert.name} until the real one is issued`);
      }
      return { id, port: app.port, gate, cert: f.cert, ...this.zoneRules(id) };
    };
    const fail = this.appCertFails.get(id);
    if (fail && Date.now() < fail) return fallback();
    if (this.appCertInflight.has(id)) return fallback();
    this.appCertInflight.add(id);
    try {
      const cert = await ensureCert({ id, endpoint: this.cfg.endpoint, sign: this.cfg.secretsSign,
                                      base: this.cfg.relayBase, dir: this.cfg.dir,
                                      zone: this.cfg.appZone, log: (m) => this.log(m) });
      this.appCerts.set(id, { cert });
      this.#record(id, { appHost: cert.name, certNotAfter: cert.notAfter });
      return { id, port: app.port, gate, cert, ...this.zoneRules(id) };
    } catch (e) {
      const wait = Math.max(30, Number(e.retryAfterSec) || 300) * 1000;
      this.appCertFails.set(id, Date.now() + wait);
      this.log(`certificate for ${appHostFor(id, this.cfg.appZone)} not ready: ${e.message} (retrying in ${Math.round(wait / 1000)}s)`);
      return fallback();
    } finally { this.appCertInflight.delete(id); }
  }

  /**
   * Carry an /x/:id/... request to that deployment's app: into the enclave, or to a local port.
   *
   * `target` is the request target AS THIS BOX RECEIVED IT (the relay frame's /x/<id>/... path; the app zone's own
   * request line, which is `pathRest` there and the default): a wallet session signs host + that target, so it is what a
   * session on a private deployment is checked against, with this deployment's own hostnames as extra bases.
   */
  async proxy(id, { method, pathRest, headers, body, ip = null, target = null }) {
    const key = String(id).toLowerCase();
    // THE DEPLOYMENT'S OWN PROTECTION RULES, before the app is consulted. Both of this box's doors
    // funnel through here - the relay's /x/<id> path and the app's own hostname - so the rules
    // hold on either, which is the property the envelope promises.
    // A PRIVATE DEPLOYMENT IS CHECKED HERE, in the one place every HTTP serving path funnels
    // through: the relay's /x/<id> and the app zone's own hostname both end up in this function.
    // The check used to live in the agent's /x/ handler alone, which left a private app reachable
    // anonymously on its own hostname - the hole this moved to close.
    //
    // AFTER the protection rules and before anything else, mirroring the platform runner: a flood
    // on a private deployment must not be able to grind token verification either.
    const priv = this.privateOwner(key);
    let fwd = headers;
    const deny = (status, error, message) => ({ status, headers: { "content-type": "application/json" },
                                                body: JSON.stringify({ error, message }) });
    const denyPrivate = async () => {
      // A WALLET SESSION (api.appAccess) for this deployment's owner: verified on chain (session-api-auth.mjs), then the
      // record rule (vault-held: its environments; wallet-held: production + the owner's ledger delegation). A header in
      // that scheme is judged as one - malformed or unverifiable is a 401, never a fall-through. Once it has served its
      // purpose it is dropped from what the app sees (a used signature, but the owner's credential all the same).
      const auth = (headers || {}).authorization;
      if (isSessionHeader(auth)) {
        const api = this.cfg.sessionApi;
        if (!api) return deny(401, "unauthorized", "This box does not accept wallet sessions.");
        let s, why;
        try {
          s = await api.verify({ header: auth, method: method || "GET", path: target || pathRest || "/", body,
            scope: "api.appAccess", bases: this.hostsFor(key) });
          why = await api.refusal(s, { id: key, owner: priv });
        } catch (e) {
          return deny(Number.isInteger(e.status) ? e.status : 503, e.code || "session_check_failed", e.message);
        }
        if (why) return deny(403, "forbidden", why);
        fwd = { ...headers };
        delete fwd.authorization;
        return null;
      }
      if (!this.cfg.sessionVerify) {
        // FAIL CLOSED. A box that cannot prove who is asking must not serve a deployment whose
        // whole contract is that only one wallet may reach it. This should be unreachable - the
        // claim gate refuses private deployments without a verifier - but "should be" is not a
        // reason to serve one.
        return { status: 503, headers: { "content-type": "application/json" },
                 body: JSON.stringify({ error: "no_session_key",
                                        message: "This box cannot verify who is asking, so it will not serve a private deployment." }) };
      }
      const who = this.cfg.sessionVerify(headers || {}, key);
      if (!who) return { status: 401, headers: { "content-type": "application/json" },
                         body: JSON.stringify({ error: "unauthorized", message: "Missing or invalid token." }) };
      if (who !== priv) return { status: 403, headers: { "content-type": "application/json" },
                                 body: JSON.stringify({ error: "forbidden", message: "Not your deployment." }) };
      return null;
    };
    const w = this.records.get(key)?.waf;
    if (w) {
      // The ACTUAL body length, not the declared one. By the time a request reaches here the body
      // is whole (the relay hands /x/ a complete frame; the app zone counts as it reads), so this
      // is the guard that holds when content-length is absent or lying.
      const bodyBytes = body == null ? 0 : (Buffer.isBuffer(body) ? body.length : Buffer.byteLength(body));
      const v = waf.check(key, w, { method, url: pathRest, headers: headers || {}, ip, bodyBytes });
      if (v && !v.allow) {
        return { status: v.status, headers: { "content-type": "application/json", ...(v.headers || {}) },
                 body: JSON.stringify({ error: v.error, message: v.message }) };
      }
      // An allowed request holds a concurrency slot until it is answered. try/finally rather than
      // a callback: every return below this point has to give the slot back, including the throws.
      try {
        if (priv) { const no = await denyPrivate(); if (no) return no; }
        return await this.#proxyApp(key, { method, pathRest, headers: fwd, body });
      } finally { v.release(); }
    }
    if (priv) { const no = await denyPrivate(); if (no) return no; }
    return await this.#proxyApp(key, { method, pathRest, headers: fwd, body });
  }

  async #proxyApp(id, { method, pathRest, headers, body }) {
    const app = this.apps.get(String(id).toLowerCase());
    if (!app || app.state !== "running") return { status: 503, headers: { "content-type": "application/json" }, body: JSON.stringify({ error: "not_running", id, state: app?.state || "unknown", reason: this.records.get(String(id).toLowerCase())?.reason || null }) };
    if (app instanceof EnclaveApp) {
      try {
        const r = await app.handle({ method, pathRest, headers, body });
        this.#record(String(id).toLowerCase(), { enclaveUs: r.enclaveUs });
        return { status: r.status, headers: r.headers, body: r.body };
      } catch (e) {
        // "no such app" means the enclave restarted under us and its memory went with it, which is
        // the honest failure mode for an app that lives in there. Mark it for reload rather than
        // pretending the app is still up.
        const gone = /no such app/i.test(e.message || "");
        if (gone) { app.state = "failed"; this.#record(String(id).toLowerCase(), { status: "failed", reason: "the enclave no longer carries this app (it restarted); reloading" }); }
        return { status: 502, headers: { "content-type": "application/json" },
                 body: JSON.stringify({ error: gone ? "app_gone" : "enclave_error", message: e.message }) };
      }
    }
    const hdrs = {};
    for (const [k, v] of Object.entries(headers || {})) if (!/^host$|^connection$|^x-metal-|^x-enclave-/i.test(k)) hdrs[k] = v;
    return await new Promise((resolve) => {
      // The app's RESPONSE is buffered whole here (both doors hand back a complete answer), so it
      // needs the same bound its request has. An app that streams without end - a bug, or a tenant
      // who does not care - would otherwise exhaust the agent's memory and take every OTHER tenant
      // on this box down with it. Same class as the request-body hole, the other direction.
      const cap = Math.round((Number(this.cfg.maxBodyMb) || 64) * 1048576);
      const req = http.request({ host: "127.0.0.1", port: app.port, method: method || "GET", path: pathRest || "/", headers: { ...hdrs, host: `127.0.0.1:${app.port}` } }, (r) => {
        const chunks = [];
        let seen = 0, over = false;
        r.on("data", (c) => {
          if (over) return;
          seen += c.length;
          if (seen > cap) {
            over = true;
            this.log(`${String(id).slice(0, 10)} answered with more than ${cap} bytes; cutting it off`);
            try { req.destroy(new Error("response too large")); } catch {}
            return resolve({ status: 502, headers: { "content-type": "application/json" },
                             body: JSON.stringify({ error: "app_response_too_large",
                                                    message: `The app answered with more than ${(cap / 1048576).toFixed(0)} MB.` }) });
          }
          chunks.push(c);
        });
        r.on("end", () => { if (!over) resolve({ status: r.statusCode || 502, headers: r.headers, body: Buffer.concat(chunks) }); });
      });
      req.setTimeout(120_000, () => { req.destroy(new Error("app timed out")); });
      req.on("error", (e) => resolve({ status: 502, headers: { "content-type": "application/json" }, body: JSON.stringify({ error: "app_unreachable", message: e.message }) }));
      if (body && body.length) req.write(body);
      req.end();
    });
  }
}
