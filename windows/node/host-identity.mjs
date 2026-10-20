// windows/node/host-identity.mjs -- who this Windows host is, and which outside services it uses, decided ONCE from its
// configuration (node-config.cmd, written by install-host.ps1 from the identity recorded in node\host.json).
//
// Two modes, and the difference is defaults:
//   relay (legacy, the default)  exactly what every installed host does today: PUBLIC_URL is the relay route
//       https://api.enclave.host/t/<name>, the fleet tunnel is wss://api.enclave.host/v1/fleet-tunnel, secrets,
//       certificates, custom domains, prices and the sponsored first registration come from that relay, and artifacts
//       from ipfs.enclave.host. Nothing about such a host changes.
//   independent (ENCLAVE_IDENTITY_MODE=independent)  nothing defaults to an Enclave service. PUBLIC_URL (the string whose
//       keccak256 is this host's registry id) is the operator's own and required; artifact gateways are required; the
//       contract pins are required (no mutable address book); the fleet tunnel and RELAY_BASE are used only if the
//       operator names them. What an Enclave relay provided and nothing else provides yet is OFF, and says so
//       (`unavailable`), rather than quietly reaching for api.enclave.host.
//
// What independent mode does NOT do, and must not pretend to: open the Shield MARKET by itself. host.mjs
// meetsIsolationContract opens it on one of two verdicts on this host's hv-node evidence, never on a local flag:
//   * an attached relay's verdict;
//   * a threshold of verdicts from verifiers the OPERATOR selected (shield-verdict.mjs, host.mjs verifierMarketOpen).
// The second is implemented in source but switched on only by configuration: agent.mjs starts it only with
// ENCLAVE_SHIELD_VERIFIERS_FILE (there is no built-in verifier, Enclave's included) and the pinned readiness witness.
// Without either verdict, the host runs only its operator's and delegated owners' deployments (owner-only scope).
//
// CLI (install-host.ps1's relay-free name check):
//   node host-identity.mjs check-endpoint --endpoint <url> --operator <0x...> --pins <contract-pins.json> [--rpc <url>]...
//   exit 0: free or already this operator's; exit 2: registered to another operator; exit 1: could not tell.
//   At least two --rpc on distinct hosts (default: DEFAULT_RPCS); two fresh ones must agree (quorumReader).
import { rpcEndpoint, redactUrls } from "../../network/rpc-identity.mjs";
import os from "node:os";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const LEGACY_RELAY = "https://api.enclave.host";
export const LEGACY_GATEWAY = "https://ipfs.enclave.host";
export const DEFAULT_RPCS = Object.freeze(["https://base-rpc.publicnode.com", "https://base.gateway.tenderly.co",
  "https://base-public.nodies.app", "https://base.drpc.org", "https://mainnet.base.org"]);
const list = (v) => String(v || "").split(",").map((s) => s.trim()).filter(Boolean);
const loopback = (h) => h === "localhost" || h === "127.0.0.1" || h === "[::1]";

/** The node's tunnel name, as agent.mjs has always derived it. */
export const nodeName = (env = process.env, hostname = os.hostname()) =>
  (env.NODE_NAME || hostname).toLowerCase().replace(/[^a-z0-9_-]/g, "-").slice(0, 64);

/** An https origin-or-base URL with no credentials, query or fragment; http only on loopback. Trailing slashes off. */
export function httpsUrl(value, what) {
  let u;
  try { u = new URL(String(value)); } catch { throw new Error(`${what} ${JSON.stringify(value)} is not a URL`); }
  if (!(u.protocol === "https:" || (u.protocol === "http:" && loopback(u.hostname)))) throw new Error(`${what} ${u.href} must be https`);
  if (u.username || u.password || u.search || u.hash) throw new Error(`${what} ${u.href} must not carry credentials, a query or a fragment`);
  return u.href.replace(/\/+$/, "");
}
/** wss://relay/v1/fleet-tunnel -> https://relay (the relay's HTTP API), or "" for none. */
export function relayHttpBase(relayUrl) {
  if (!relayUrl || relayUrl === "none") return "";
  return String(relayUrl).replace(/^wss:/, "https:").replace(/^ws:/, "http:").replace(/\/v1\/fleet-tunnel\/?$/, "");
}
/** Is this endpoint a route on Enclave's own relay (so clients reach it only while that relay routes it)? */
export const isEnclaveRelayRoute = (endpoint) => /^https:\/\/api\.enclave\.host\/t\//i.test(String(endpoint || ""));

/**
 * The resolved identity -> { mode, name, publicUrl, relayUrl, relayBase, relayHttp, gateway, sessionApiHosts,
 * networkDirectories, sponsor, prices, warnings, unavailable }. Throws on an independent configuration that is missing
 * something it would otherwise have defaulted to Enclave for. `pins` is the loaded contract pin document (chain.mjs
 * CONTRACT_PINS) or null.
 */
export function resolveIdentity(env = process.env, { hostname = os.hostname(), pins = null } = {}) {
  const name = nodeName(env, hostname);
  const mode = String(env.ENCLAVE_IDENTITY_MODE || "relay").toLowerCase();
  if (mode !== "relay" && mode !== "independent") throw new Error(`ENCLAVE_IDENTITY_MODE must be relay or independent, not ${JSON.stringify(mode)}`);
  if (mode === "relay") {
    const relayUrl = env.RELAY_URL || "wss://api.enclave.host/v1/fleet-tunnel";
    return Object.freeze({ mode, name, publicUrl: env.PUBLIC_URL || `${LEGACY_RELAY}/t/${name}`,
      relayUrl, relayHttp: relayHttpBase(relayUrl), relayBase: env.RELAY_BASE || LEGACY_RELAY,
      gateway: env.IPFS_GATEWAYS || env.IPFS_GATEWAY || LEGACY_GATEWAY,
      sessionApiHosts: list(env.SESSION_API_HOSTS), networkDirectories: list(env.ENCLAVE_NETWORK_DIRECTORIES),
      sponsor: relayUrl !== "none", prices: relayUrl !== "none", warnings: [], unavailable: [] });
  }
  if (!env.PUBLIC_URL) throw new Error("independent mode needs PUBLIC_URL: this host's own public endpoint (its registry identity)");
  const publicUrl = httpsUrl(env.PUBLIC_URL, "PUBLIC_URL");
  if (publicUrl !== String(env.PUBLIC_URL)) throw new Error(`PUBLIC_URL must be written exactly as registered, without a trailing slash: ${publicUrl}`);
  if (!pins) throw new Error("independent mode needs ENCLAVE_CONTRACT_PINS_FILE: contracts are pinned, never read from the mutable address book");
  const gateways = list(env.IPFS_GATEWAYS || env.IPFS_GATEWAY).map((g) => httpsUrl(g, "IPFS gateway"));
  if (!gateways.length) throw new Error("independent mode needs IPFS_GATEWAYS: the artifact gateways this host fetches from (CID-verified)");
  const relayUrl = env.RELAY_URL && env.RELAY_URL !== "none" ? env.RELAY_URL : "none";
  if (relayUrl !== "none" && !/^wss:\/\//.test(relayUrl)) throw new Error("RELAY_URL must be wss:// or none");
  const relayBase = env.RELAY_BASE ? httpsUrl(env.RELAY_BASE, "RELAY_BASE") : "";
  const directories = list(env.ENCLAVE_NETWORK_DIRECTORIES).map((d) => {
    const u = new URL(httpsUrl(d, "network directory"));
    if (u.pathname !== "/") throw new Error(`network directory ${d} must be an origin`);
    return u.origin;
  });
  const warnings = [], unavailable = [];
  if (isEnclaveRelayRoute(publicUrl)) warnings.push(`PUBLIC_URL ${publicUrl} is a route on Enclave's relay: clients reach this host there only while that relay routes it`);
  if (!relayBase) unavailable.push("relay-staged secrets (deployments that have them are held, not started)", "relay-issued app certificates (partitions keep their own self-signed ones)", "relay custom-domain lists");
  if (relayUrl === "none" && !env.ENCLAVE_SHIELD_VERIFIERS_FILE) unavailable.push("the Shield market (needs an attached relay's verdict, or operator-selected verifiers in ENCLAVE_SHIELD_VERIFIERS_FILE: owner-only scope until then)");
  if (relayUrl === "none") unavailable.push("the sponsored first registration (the operator key pays its own gas)", "the relay's network price list (registry prices stand)");
  if (!directories.length) unavailable.push("Enclave network routes (no ENCLAVE_NETWORK_DIRECTORIES)");
  return Object.freeze({ mode, name, publicUrl, relayUrl, relayHttp: relayHttpBase(relayUrl), relayBase, gateway: gateways.join(","),
    sessionApiHosts: list(env.SESSION_API_HOSTS), networkDirectories: directories,
    sponsor: relayUrl !== "none", prices: !!relayBase, warnings, unavailable });
}

/** Sorted-key JSON (bigints as strings), so two RPCs' answers compare by value and not by key order. */
const stable = (v) => {
  if (typeof v === "bigint") return JSON.stringify(v.toString());
  if (Array.isArray(v)) return `[${v.map(stable).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${stable(v[k])}`).join(",")}}`;
  return JSON.stringify(v) ?? "null";
};
/**
 * reader.agreed(fn) -> the value fn(client, blockNumber, signal) that two DISTINCT RPC hosts agree on, at one fresh confirmed
 * block. It follows the rules of network/lease-reader.mjs LeaseReader.agreed, which every other chain decision in Enclave
 * goes through. The Windows node cannot import that module, because it resolves viem from the repository root, and the
 * admission bundle does not export it. test/windows-host-identity.test.mjs runs this reader and LeaseReader on the same
 * RPCs and expects the same verdicts.
 *
 * Two properties must both hold.
 *
 * AUTHORIZATION: no single RPC decides anything.
 *   * Each configured client is one peer, and it must name its RPC: a viem http transport URL (https, or http on
 *     loopback). Two clients on one host are refused. A host is compared in canonical form: lower case, without trailing
 *     dots, so rpc.example and RPC.example. are one host. The same client object twice is refused, and so is a client
 *     with no URL, a malformed URL, or one without getChainId, getBlockNumber and getBlock.
 *   * Configuration is bounded:
 *       - 2 to MAX_PEERS clients;
 *       - chainId and confirmations are positive integers;
 *       - maxBlockAgeMs and deadlineMs are finite and within range.
 *     Anything else is refused when the reader is made.
 *   * A vote is for one ROUND (one requested block). It counts only while that round is the current one, and once per peer.
 *     A peer that answers the same (forged) thing in two rounds never meets itself.
 *   * The agreement key is the whole snapshot:
 *       - the requested block number;
 *       - the block's returned number (it must equal the requested one), hash (32-byte hex) and timestamp, all
 *         re-read unchanged after `fn`;
 *       - the whole value `fn` returned.
 *   * The block must be recent (maxBlockAgeMs) before `fn`, after the whole snapshot is read, and at the decision.
 *   * The block never goes below one this reader has accepted (lastBlock), checked AT THE DECISION. An overlapping call
 *     that started on a lower block cannot roll an accepted block back. Its lower round is replaced by one at
 *     lastBlock.
 *
 * CENSORSHIP RESISTANCE: a later head is never shut out.
 *   * Heads are taken until deadlineMs. LeaseReader, as of this writing, waits headGraceMs (250 ms) after the second head
 *     before choosing its block, still reads later heads at that block, and moves to a newer block only after a round
 *     has failed. This reader moves up as soon as a head raises the target, as follows.
 *   * The target block is the second-highest head reported so far, minus `confirmations`, so one far-future head cannot
 *     pick it. A late head is read in the current round.
 *   * A head that raises the target starts a new round at the higher block, where every peer with a head is read again.
 *     A fast stale head cannot pin an old block.
 *   * So a fast liar plus one fast honest RPC cannot shut out a second honest RPC that answers later.
 *
 * FAIL CLOSED. The reader refuses when every head and read has settled without two distinct fresh agreeing peers in the
 * current round, or when deadlineMs passes first. After it has decided, refused or moved on to a higher round:
 *   * no step of an earlier read starts another request (each one checks first);
 *   * `signal` is aborted, for clients and `fn`s that can cancel.
 */
const BLOCK_HASH = /^0x[0-9a-fA-F]{64}$/;
export const MAX_PEERS = 16;
/**
 * The host an RPC URL reaches, in the one spelling used to tell peers apart: lower case, trailing dots removed (DNS treats
 * rpc.example. and rpc.example as one name). Only https, or http on loopback, and no empty labels.
 * `localFixture` keeps the port for LOOPBACK hosts only, so a test can run several local RPCs. It is an explicit argument
 * of quorumReader, never set from configuration or the CLI, and it changes nothing for a public host.
 */
export function rpcPeerHost(url, { localFixture = false } = {}) {
  let endpoint;
  try { endpoint = rpcEndpoint(url, { loopbackPorts: localFixture }); }
  catch (e) {
    const reason = {url: "RPC is not a URL", scheme: "RPC must be https (http only on loopback)", host: "RPC has a malformed host", secret: "RPC must not carry credentials or a fragment"};
    throw new Error(reason[e.code] || "invalid RPC URL");
  }
  return endpoint.loopback ? endpoint.identity : endpoint.host;
}

const PEER_METHODS = ["getChainId", "getBlockNumber", "getBlock"];
const inRange = (v, lo, hi) => Number.isSafeInteger(v) && v >= lo && v <= hi;
export function quorumReader({ clients, chainId = 8453, confirmations = 2, maxBlockAgeMs = 90_000, deadlineMs = 30_000, now = Date.now, localFixture = false }) {
  if (!Array.isArray(clients) || clients.length < 2) throw new Error("at least two RPCs are required: one RPC never decides what the chain says");
  if (clients.length > MAX_PEERS) throw new Error(`at most ${MAX_PEERS} RPCs`);
  if (!inRange(chainId, 1, Number.MAX_SAFE_INTEGER)) throw new Error("chainId must be a positive integer");
  if (!inRange(confirmations, 1, 1000)) throw new Error("confirmations must be a whole number from 1 to 1000");
  if (!inRange(maxBlockAgeMs, 1000, 3_600_000)) throw new Error("maxBlockAgeMs must be a whole number of ms from 1 s to 1 h");
  if (!inRange(deadlineMs, 100, 600_000)) throw new Error("deadlineMs must be a whole number of ms from 0.1 s to 10 min");
  if (typeof now !== "function" || typeof localFixture !== "boolean") throw new Error("now must be a function and localFixture a boolean");
  if (clients.some((c) => !c || typeof c !== "object" || PEER_METHODS.some((m) => typeof c[m] !== "function")))
    throw new Error(`each RPC client needs ${PEER_METHODS.join(", ")}`);
  if (new Set(clients).size !== clients.length) throw new Error("an RPC client is configured twice: each peer counts once");
  // every peer names its RPC, and no two name one host: one public host never casts two votes
  const hosts = clients.map((c) => {
    if (typeof c.transport?.url !== "string") throw new Error("each RPC client must name its RPC (a viem http transport URL)");
    return rpcPeerHost(c.transport.url, { localFixture });
  });
  if (new Set(hosts).size !== hosts.length) throw new Error("two RPC clients use one host: each peer counts once");
  const conf = BigInt(confirmations);
  let lastBlock = 0n;
  const why = (e) => redactUrls(String(e?.shortMessage || e?.message || e)).slice(0, 300);
  const fresh = (t) => Number.isSafeInteger(t) && t <= now() + 5000 && t + maxBlockAgeMs > now();
  /** The block a peer returned for `at`, validated: its number is `at`, its hash 32-byte hex, its timestamp a safe time. */
  const checkBlock = (b, at) => {
    let n, t;
    try { n = BigInt(b.number); t = Number(BigInt(b.timestamp)) * 1000; } catch { throw new Error("malformed chain block"); }
    if (n !== at) throw new Error(`asked for block ${at}, got block ${n}`);
    if (typeof b.hash !== "string" || !BLOCK_HASH.test(b.hash)) throw new Error("malformed chain block hash");
    if (!Number.isSafeInteger(t)) throw new Error("malformed chain block timestamp");
    return { hash: b.hash.toLowerCase(), t };
  };
  return {
    agreed(fn, failures = []) {
      return new Promise((resolve, reject) => {
        const heads = [];
        let headsPending = clients.length, readsPending = 0, round = null, settled = false;
        const live = (r) => !settled && r === round;
        const finish = (err, value) => {
          if (settled) return;
          settled = true; clearTimeout(timer); round?.stop.abort();
          if (err) reject(err); else resolve(value);
        };
        const timer = setTimeout(() => finish(new Error(`no fresh agreeing chain quorum within ${deadlineMs / 1000} s` +
          `${failures.length ? `: ${failures.join("; ")}` : ""}`)), deadlineMs);
        // nothing is still coming and nothing agreed: refuse (heads first, so "unavailable" names the real reason)
        const giveUp = () => {
          if (settled || headsPending || readsPending) return;
          finish(new Error(heads.length < 2 ? `chain quorum unavailable: ${heads.length} of ${clients.length} RPCs answered (${failures.join("; ")})`
            : `no fresh agreeing chain quorum at block ${round?.at}${failures.length ? `: ${failures.join("; ")}` : " (the RPCs disagree)"}`));
        };
        const startRound = (at) => {
          round?.stop.abort();   // the superseded round's reads stop at their next step and are never counted
          round = { at, votes: new Map(), stop: new AbortController() };
          for (const h of heads) read(round, h);
        };
        const read = (r, h) => {
          readsPending++;
          (async () => {
            const first = checkBlock(await h.c.getBlock({ blockNumber: r.at }), r.at);
            if (!live(r)) return null;
            if (!fresh(first.t)) throw new Error("stale chain block");
            const value = await fn(h.c, r.at, r.stop.signal);
            if (!live(r)) return null;
            const again = checkBlock(await h.c.getBlock({ blockNumber: r.at }), r.at);
            if (!live(r)) return null;
            if (again.hash !== first.hash || again.t !== first.t) throw new Error("chain reorganized during read");
            if (!fresh(first.t)) throw new Error("chain block went stale during the read");   // the whole snapshot, not only its start
            return { key: stable({ block: String(r.at), hash: first.hash, timestamp: String(first.t), value }), value, t: first.t };
          })().then((a) => {
            if (!a || !live(r)) return;   // superseded, decided or timed out: never counted
            let peers = r.votes.get(a.key);
            if (!peers) r.votes.set(a.key, (peers = new Set()));
            peers.add(h.peer);
            if (peers.size < 2) return;   // two DISTINCT configured peers, in THIS round
            if (!fresh(a.t)) { failures.push("two RPCs agreed on a block that is no longer fresh"); return; }
            if (r.at < lastBlock) {   // an overlapping call accepted a higher block meanwhile: never roll back to this one
              failures.push(`block ${r.at} is below the accepted block ${lastBlock}`);
              startRound(lastBlock);
              return;
            }
            lastBlock = r.at;
            finish(null, a.value);
          }, (e) => { if (live(r)) failures.push(why(e)); }).finally(() => { readsPending--; giveUp(); });
        };
        const arrived = (h) => {
          heads.push(h);
          if (heads.length < 2) return;
          const sorted = heads.map((x) => x.number).sort((x, y) => (x > y ? -1 : x < y ? 1 : 0));
          let at = sorted[1] - conf;
          if (at < 0n) return;
          if (at < lastBlock) at = lastBlock;
          if (!round || at > round.at) startRound(at);   // a new, higher target: a new round, everyone read again
          else read(round, h);                            // a late head: read it in the current round
        };
        clients.forEach((c, peer) => {
          Promise.all([c.getChainId(), c.getBlockNumber({ cacheTime: 0 })]).then(([id, number]) => {
            if (Number(id) !== chainId) throw new Error(`wrong chain ${id}`);
            const head = BigInt(number);
            if (head < 0n) throw new Error("malformed chain head");
            if (!settled) arrived({ c, peer, number: head });
          }).catch((e) => failures.push(why(e))).finally(() => { headsPending--; giveUp(); });
        });
      });
    },
  };
}
/** viem clients for two or more RPCs on distinct hosts (one operator's two URLs are one RPC). */
export async function rpcClients(rpcs) {
  if (!Array.isArray(rpcs) || rpcs.length > MAX_PEERS) throw new Error(`at most ${MAX_PEERS} RPCs`);
  const urls = rpcs.map((u) => httpsUrl(u, "RPC"));
  if (urls.length < 2 || new Set(urls.map((u) => rpcPeerHost(u))).size !== urls.length) throw new Error("at least two RPCs on distinct hosts are required");
  const { createPublicClient, http } = await import("viem");
  const { base } = await import("viem/chains");
  return urls.map((u) => createPublicClient({ chain: base, transport: http(u, { timeout: 15000, retryCount: 1 }) }));
}
const REGISTRY_GET = [{ type: "function", name: "get", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ type: "tuple", components:
  [["endpoint", "string"], ["repo", "string"], ["measurement", "bytes32"], ["operator", "address"], ["registeredAt", "uint64"], ["lastSeen", "uint64"],
   ["active", "bool"], ["cpuPricePerSec6", "uint64"], ["gpuPricePerSec6", "uint64"], ["proofKey", "address"], ["payoutWallet", "address"]].map(([name, type]) => ({ name, type })) }] }];

/**
 * Is this endpoint free for this operator on the PINNED registry? The registry id is keccak256(endpoint), so this is the
 * collision that actually matters to an independent host - the relay's /v1/hosts/name only ever reserved a relay route.
 * -> { status: "free" | "ours" | "taken", hostId, operator, active }
 */
export async function checkEndpointOnChain({ endpoint, operator, registry, reader }) {
  const { keccak256, toBytes } = await import("viem");
  if (!/^0x[0-9a-fA-F]{40}$/.test(String(operator || ""))) throw new Error("operator must be an address");
  if (!/^0x[0-9a-fA-F]{40}$/.test(String(registry || ""))) throw new Error("registry pin must be an address");
  const hostId = keccak256(toBytes(String(endpoint)));
  const e = await reader.agreed((c, blockNumber) => c.readContract({ address: registry, abi: REGISTRY_GET, functionName: "get", args: [hostId], blockNumber })
    .then((x) => ({ endpoint: x.endpoint, operator: String(x.operator).toLowerCase(), active: !!x.active })));
  const zero = /^0x0{40}$/;
  if (!e.endpoint && zero.test(e.operator)) return { status: "free", hostId, operator: null, active: false };
  return { status: e.operator === String(operator).toLowerCase() ? "ours" : "taken", hostId, operator: e.operator, active: e.active };
}

async function main(argv) {
  const [cmd, ...rest] = argv;
  const o = { rpc: [] };
  for (let i = 0; i < rest.length; i++) { const k = rest[i].replace(/^--/, ""), v = rest[++i]; if (k === "rpc") o.rpc.push(...list(v)); else o[k] = v; }
  if (cmd !== "check-endpoint") throw new Error("commands: check-endpoint --endpoint <url> --operator <0x...> --pins <file> [--rpc <url>]...");
  for (const k of ["endpoint", "operator", "pins"]) if (!o[k]) throw new Error(`--${k} is required`);
  const { validateContractPins } = await import("./host-admission.bundle.mjs");
  const pins = validateContractPins(JSON.parse(fs.readFileSync(o.pins, "utf8").replace(/^﻿/, "")));
  const reader = quorumReader({ clients: await rpcClients(o.rpc.length ? o.rpc : [...DEFAULT_RPCS]) });
  const r = await checkEndpointOnChain({ endpoint: httpsUrl(o.endpoint, "endpoint"), operator: o.operator, registry: pins.registry, reader });
  process.stdout.write(JSON.stringify(r) + "\n");
  return r.status === "taken" ? 2 : 0;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  main(process.argv.slice(2)).then((c) => process.exit(c), (e) => { process.stderr.write(`identity: ${e.shortMessage || e.message}\n`); process.exit(1); });
