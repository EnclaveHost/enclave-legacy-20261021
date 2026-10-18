// network-enroll.mjs -- an open-market Windows host keeps its own network agent enrolled on the Enclave network, with no
// operator SSH.
//
// Every app this box serves reaches the internet only through its own Enclave-network circuits (network/privacy-agent.mjs,
// the \Enclave\Network task; docs/design/enclave-network.md). This pass, run by the node agent every few minutes:
//   1. writes privacy-config.json with the first app (the agent refuses an empty list) - the \Enclave\Network task waits
//      for it; the box's own control traffic uses Enclave-network control circuits;
//   2. enrolls each public deployment leased to this box, running ready in a partition of its current version: its
//      expectation (network/shield-expectation.mjs) and its names (the relay's domain map). An expectation that changes
//      (an upgrade) is rewritten; the names follow the relay's map.
// The privacy agent re-reads its config when the file changes. Nothing is ever removed: a lease that ends ends its
// admission at the relay.
//
// A box whose config still carries settings of the retired TUNA transport (NKN wallets, its control guards, its runtime)
// has them dropped, and is switched once to the current enclaveNetwork section (its agent restarted). Paths follow the
// agent's directory: a box whose agent directory moved (ProgramData\Enclave\tuna -> network, release .35) has its
// state directory and expectations repointed, and its agent restarted once.
import fs from "node:fs/promises";
import path from "node:path";
import { createHash } from "node:crypto";
import { shieldExpectation, catalogRef } from "../../network/shield-expectation.mjs";

const ID = /^0x[0-9a-f]{64}$/;
// settings of the retired TUNA transport a box's config may still hold; the agent ignores them, the next pass drops them
export const RETIRED_KEYS = ["nknRpc", "inventory", "control", "runtime", "defaults", "tunaUSDC", "currencyManagement"];

/** The privacy agent's config for this box, apps empty (the NucBox's production shape). */
export function baseConfig({ agentDir, binDir, nodeBinary, operatorKeyFile, runner, endpoint, relayBase, policyFile, tpmBinary, tpmSha256,
                             addressBook, chainRpc, manager = "http://127.0.0.1:8091", dataAddr = "127.0.0.1:8092", upstream = "http://127.0.0.1:9600",
                             enclaveNetwork }) {
  return { version: 2, directory: path.join(agentDir, "state"), operatorKeyFile, runner, endpoint, apps: [],
    chain: { addressBook, rpc: chainRpc }, upstream,
    shield: { policyFile, tpmBinary, tpmSha256, ingress: { url: manager, dataAddr }, manager },
    dns: [{ address: "1.1.1.1:443", serverName: "cloudflare-dns.com", path: "/dns-query" }, { address: "8.8.8.8:443", serverName: "dns.google", path: "/resolve" }],
    mirror: relayBase, enclaveNetwork: networkConfig({ binDir, nodeBinary, relayBase, ...enclaveNetwork }) };
}

/** The privacy agent's enclaveNetwork section: every app, the box's own control circuits, the bundled binaries. */
export function networkConfig({ binDir, nodeBinary, relayBase, checkers, paid }) {
  const bin = (f) => path.join(binDir, f);
  if (!Array.isArray(checkers) || !checkers.length || checkers.some((c) => !/^0x[0-9a-f]{40}$/.test(c))) throw new Error("Enclave network: trusted checker addresses required");
  return { relay: relayBase, checkers, apps: "all", control: true, wgBinary: bin("enclave-wg.exe"), nodeBinary,
    workerModule: bin("windows-circuit-worker.mjs"), firewallBinary: bin("enclave-circuit-firewall.exe"),
    // paid providers (used only for apps whose owners authorized them on chain): this box's registry proof key signs
    // the bandwidth receipts, its operator key pays the settlement gas; up to 0.01 USDC per provider is settled in a batch
    ...(paid ? { paid: { proofKeyFile: paid.proofKeyFile, gasKeyFile: paid.gasKeyFile, rpc: paid.rpc || "https://base-rpc.publicnode.com", maxPending6: paid.maxPending6 || "10000" } } : {}) };
}

/** An operator's hostEgress block kept as it is when its shape is right (apps: deployment ids, own: IP addresses); else none. */
export function validHostEgress(h) {
  if (!h || typeof h !== "object" || Array.isArray(h)) return null;
  const own = Array.isArray(h.own) ? h.own : [];
  // apps: "all", or a list of deployment ids (network/enclave-network-host.mjs reads the same shape)
  if (h.apps !== "all") {
    const apps = Array.isArray(h.apps) ? h.apps : [];
    if (!apps.length || apps.length > 64 || apps.some((a) => !ID.test(String(a).toLowerCase()))) return null;
  }
  if (own.length > 8 || own.some((ip) => !/^[0-9a-fA-F:.]{2,45}$/.test(String(ip)))) return null;
  return structuredClone(h);
}

/** An operator's enclaveNetwork.paceMbps (this host's uplink in Mbps; circuits pace their UDP to it) kept when it is a number
 *  in (0, 100000]; else none (unpaced). */
export function validPaceMbps(v) {
  return typeof v === "number" && Number.isFinite(v) && v > 0 && v <= 100000 ? v : null;
}

/**
 * createNetworkEnroll(opts) -> { pass() }. opts: agentDir (ProgramData\Enclave\network), binDir (Program Files\Enclave\network),
 * runner, relayBase, config (baseConfig's inputs, with enclaveNetwork: {checkers}), rows() (the ledger),
 * version(appRef) (its catalog version record), vms() (the manager's /vms list), restartAgent(), and for tests: fetch, log.
 * name, endpoint and transportKey are accepted (and unused) so older callers keep working.
 */
export function createNetworkEnroll({ agentDir, binDir, runner, relayBase, config, rows, version, vms,
                                   fetch: fetchFn = globalThis.fetch, restartAgent = async () => {}, log = () => {} }) {
  if (!config?.enclaveNetwork) throw new Error("the Enclave network configuration (trusted checkers) is required: TUNA is retired");
  const file = (f) => path.join(agentDir, f);
  const readJSON = async (f, d) => { try { return JSON.parse(await fs.readFile(f, "utf8")); } catch (e) { if (e.code === "ENOENT") return d; throw e; } };
  const writeAtomic = async (f, text) => { const t = `${f}.tmp-${process.pid}`; await fs.writeFile(t, text); await fs.rename(t, f); };

  async function pass() {
    await fs.mkdir(file("state"), { recursive: true });
    // The config is written only once it names an app: the privacy agent refuses an empty app list.
    let cfg = await readJSON(file("privacy-config.json"), null), changed = false, waiting = 0;
    const fresh = !cfg;
    if (fresh) cfg = baseConfig(config);
    // HOST EGRESS (network/privacy-agent.mjs, main 7e27c1d0c) is the OPERATOR's opt-in, set by hand in privacy-config.json
    // ({apps:[deployment ids], own:[this box's public addresses]}): kept across passes, never computed here. Without this
    // the next pass replaced the whole section and dropped it (and restarted the agent).
    const hostEgress = validHostEgress(cfg?.enclaveNetwork?.hostEgress);
    // PACING (main d476cc0f9): the operator's uplink in Mbps, set by hand like hostEgress and kept the same way
    const paceMbps = validPaceMbps(cfg?.enclaveNetwork?.paceMbps);
    const want = { ...networkConfig({ binDir, nodeBinary: config.nodeBinary, relayBase, ...config.enclaveNetwork }), ...(hostEgress ? { hostEgress } : {}), ...(paceMbps ? { paceMbps } : {}) };
    // a box whose config predates the current enclaveNetwork section (or still runs TUNA): switched once, then restarted
    let switched = false;
    if (JSON.stringify(cfg.enclaveNetwork) !== JSON.stringify(want)) {
      cfg.enclaveNetwork = want; switched = !fresh; changed = true;
      log(fresh ? "Enclave network: new config" : "Enclave network: this box's network configuration changes");
    }
    // the chain RPCs follow the node's list (chain.mjs RPCS, or BASE_RPCS): a box kept the list it was set up with forever,
    // and on k11-4 two of its three public RPCs rate-limited, so 2 of 3 agreeing failed most rounds (2026-10-18). The agent
    // reads them at start, so a change restarts it once.
    const rpcs = Array.isArray(config.chainRpc) ? config.chainRpc.filter((u) => /^https:\/\//.test(String(u))) : [];
    if (!fresh && rpcs.length >= 2 && JSON.stringify(cfg.chain?.rpc || []) !== JSON.stringify(rpcs)) {
      cfg.chain = { ...(cfg.chain || {}), rpc: rpcs }; switched = true; changed = true;
      log(`chain RPCs now ${rpcs.map((u) => new URL(u).host).join(", ")}`);
    }
    // paths follow the agent's directory (it moved once, tuna -> network): the state directory needs a restart
    if (!fresh && cfg.directory !== file("state")) { cfg.directory = file("state"); switched = true; changed = true; log(`state directory now ${cfg.directory}`); }
    if (!fresh && cfg.shield && cfg.shield.policyFile !== config.policyFile) { cfg.shield.policyFile = config.policyFile; switched = true; changed = true; }
    for (const a of cfg.apps) {
      const want = path.join(file(String(a.deploymentId).toLowerCase()), "expected.json");
      if (a.expectedFile !== want) { a.expectedFile = want; changed = true; }
    }
    // retired TUNA settings are dropped (the agent ignores them; nothing restarts for this alone)
    const retired = RETIRED_KEYS.filter((k) => k in cfg);
    for (const k of retired) delete cfg[k];
    for (const a of cfg.apps) {
      if (a.internetMode !== "enclave-network") { a.internetMode = "enclave-network"; changed = true; }
      if ("walletsFile" in a) { delete a.walletsFile; changed = true; }
    }
    if (retired.length) { changed = true; log(`retired TUNA settings dropped from the config: ${retired.join(", ")}`); }
    const policy = await readJSON(config.policyFile, null);
    if (!policy?.cpu?.runtimeId) throw new Error(`no admitted Shield policy at ${config.policyFile}`);
    const now = Math.floor(Date.now() / 1000), me = String(runner).toLowerCase();
    const mine = (await rows()).filter((d) => String(d.runner).toLowerCase() === me && d.active === true && d.isPublic === true &&
      Number(d.leaseUntil) > now && ID.test(String(d.id).toLowerCase()));
    let domains = null;
    try { const r = await fetchFn(`${relayBase}/v1/domains/map`, { signal: AbortSignal.timeout(15000) }); if (r.ok) domains = (await r.json()).domains || {}; } catch {}
    const namesFor = (id) => { const n = [id.slice(2, 10) + ".app.enclave.host"]; for (const [h, d] of Object.entries(domains || {})) if (String(d).toLowerCase() === id && !n.includes(h)) n.push(h); return n; };
    const list = mine.length ? await vms() : [];
    for (const row of mine) {
      const id = String(row.id).toLowerCase(), short = id.slice(0, 10), dir = file(id);
      if (!catalogRef(row.appRef)) { log(`${short}: not a catalog app; skipped`); continue; }
      const expectedFile = path.join(dir, "expected.json");
      const previous = await readJSON(expectedFile, null);
      const v = shieldExpectation({ row, version: await version(row.appRef), vms: list, policy, previous });
      if (!v.expected) { if (v.wait) waiting++; log(`${short}: ${v.wait || v.skip}`); continue; }
      const existing = cfg.apps.find((a) => a.deploymentId === id);
      await fs.mkdir(dir, { recursive: true });
      if (JSON.stringify(previous) !== JSON.stringify(v.expected)) {
        await writeAtomic(expectedFile, JSON.stringify(v.expected)); changed = changed || !!existing;
        if (existing) log(`${short}: expectation now ${v.expected.appRef.split("/").pop()} app ${v.expected.appSha256.slice(0, 8)}`);
      }
      if (existing) {
        if (domains) { const n = namesFor(id); if (JSON.stringify(n) !== JSON.stringify(existing.names)) { existing.names = n; changed = true; } }
        continue;
      }
      if (!domains) { log(`${short}: new, but the relay's domain map is unavailable; enrolling next pass`); continue; }
      cfg.apps.push({ deploymentId: id, names: namesFor(id), expectedFile, internetMode: "enclave-network", publishToMirror: true });
      changed = true; log(`${short}: enrolled on the Enclave network (${namesFor(id).join(", ")})`);
    }
    if (changed && cfg.apps.length) {
      await writeAtomic(file("privacy-config.json"), JSON.stringify(cfg, null, 2));
      if (fresh) log("privacy-config.json written: the privacy agent starts");
      if (switched) { log("restarting the privacy agent on its new network configuration"); await restartAgent().catch((e) => log(`agent restart: ${e.message}`)); }
    }
    // waiting: apps whose new version's partition is not ready yet - the caller looks again soon instead of in 5 minutes
    return { ready: true, apps: cfg.apps.length, changed: changed && cfg.apps.length > 0, waiting };
  }
  return { pass };
}

/** sha256 of a file, hex (the TPM tool's pin in the privacy agent's config). */
export const fileSha256 = async (f) => createHash("sha256").update(await fs.readFile(f)).digest("hex");
