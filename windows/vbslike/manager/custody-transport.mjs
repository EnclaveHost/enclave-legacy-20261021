/* ============================================================
   THE OPERATOR'S CUSTODY AUTHORIZATION, CARRIED TO ONE SHIELD PARTITION (vsock 9445).

   A Shield-direct custody guest (isolation/m2/front/shield_direct_custody.go) opens its owner's custody-v2 shares itself:
   it challenges the committee's machines, proves itself to them and decrypts their partials with a key that never leaves
   it. The ONE thing it needs from this host is what a Linux host gives it (guestd's custody-auth): the lease holder's
   operator signature over the guest's release binding, for the exact vault it was measured with. The guest asks once per
   release, on CID 2 port 9445, in release.WriteAuthRequestV2's line, and reads one release.ReadAuth line back:

     guest -> host  "custody-auth-v2 0x<vault 40 hex> 0x<deployment 64 hex> <binding 64 hex>\n"     (at most 256 bytes)
     host -> guest  "custody-sig-v1 <base64 endpoint> <expiry> 0x<130 hex>\n"                      (release.WriteAuth)

   This file is the carrier and nothing else: it holds no key and signs nothing. A request is held PENDING on its
   connection, and the manager lists it (awaitingCustodyAuth) for the node, which re-verifies the deployment's startup and
   lease itself and answers through the manager's authenticated callback (server.mjs). A request naming another deployment
   or another vault than this partition's is never listed: its connection is closed with no answer. The custodians judge
   the signature; this side checks only its shape.

   Through the SAME pinned shielded-bridge the egress, package and GPU paths use (it binds THIS partition's hv_sock service
   only and checks every peer's VmId); its bytes are hashed against the pin at every start, and closing stdin ends it.
   The loopback listener admits ONLY that bridge: each start mints a credential, hands it to the bridge on stdin
   (--worker-auth-stdin) and requires it at the head of every connection (bridge-auth.mjs). Another local process's
   connection consumes no request budget and no pending slot, and never reaches the node's signing. The
   partition lifecycle owns it (wmi-launcher.mjs). The hv_sock service for 9445 must be registered under
   GuestCommunicationServices by an explicit activation step; the launcher's preflight READS that and never writes it.
   ============================================================ */
import net from "node:net";
import crypto from "node:crypto";
import { spawn as nodeSpawn } from "node:child_process";
import { checkPin } from "./egress.mjs";
import { BRIDGE_AUTH_FLAG, bridgeAuthLine, createBridgeGate, mintBridgeCredential } from "./bridge-auth.mjs";

export const CUSTODY_VSOCK_PORT = 9445;
/** vsock 9445 -> its hv_sock service id (Linux hyperv_transport srv_id_template, as EGRESS_SERVICE_GUID for 9443). */
export const CUSTODY_SERVICE_GUID = "000024e5-facb-11e6-bd58-64006a7986d3";
export const MAX_REQUEST_LINE = 256;                          // release.ReadAnyAuthRequest's LimitReader
export const MAX_ANSWER_EXPIRY_SEC = 600;                     // an operator signature lives 300 s (secrets.mjs); never longer than this
const DEPLOYMENT = /^0x[0-9a-f]{64}$/;
const VAULT = /^0x[0-9a-f]{40}$/;
const HEX32 = /^[0-9a-f]{64}$/;
const SIG = /^0x[0-9a-f]{130}$/;
const ENDPOINT = /^https?:\/\/[!-~]{1,190}$/;
const REQUEST_ID = /^[0-9a-f]{32}$/;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const status = (code, msg) => Object.assign(new Error(msg), { status: code });

/* THE NODE'S CALLBACK (server.mjs POST /vms/:id/custody-auth): the node agent and this manager share one key
   (ENCLAVE_CUSTODY_CALLBACK_KEY_FILE); the manager's loopback /vms listing is readable by any local process, and only a
   holder of that key can answer a request. Single-use nonces and a 60 s window; the body is bound by its sha256. */
export const CUSTODY_CALLBACK_PROTOCOL = "hmac-sha256/v1";
export const CUSTODY_CALLBACK_HEADER = "x-enclave-custody-callback";
export const CUSTODY_CALLBACK_SKEW_MS = 60_000;
export const CUSTODY_CALLBACK_NONCES = 4096;
export const MAX_CALLBACK_BODY = 4096;
export function custodyCallbackMac(key, { method, path, ts, nonce, body }) {
  const digest = crypto.createHash("sha256").update(Buffer.from(body ?? "")).digest("hex");
  return crypto.createHmac("sha256", key).update(`enclave-custody-callback/v1\n${method}\n${path}\n${ts}\n${nonce}\n${digest}`).digest("hex");
}
/** The header value the node sends: "v1 <ts seconds> <nonce 32 hex> <mac 64 hex>". */
export function custodyCallbackHeader(key, { method = "POST", path, body, now = Date.now() }) {
  const ts = String(Math.floor(now / 1000)), nonce = crypto.randomBytes(16).toString("hex");
  return `v1 ${ts} ${nonce} ${custodyCallbackMac(key, { method, path, ts, nonce, body })}`;
}

/**
 * release.ReadAnyAuthRequest's v2 rules, and v2 ONLY: a custody-auth-v1 line is the relay-measured SNP flow, which a
 * Shield-direct guest never speaks. Lowercase only, exactly as the guest writes it (%x).
 */
export function parseCustodyRequest(line) {
  const s = Buffer.isBuffer(line) ? line.toString("latin1") : String(line ?? "");
  if (Buffer.byteLength(s, "latin1") > MAX_REQUEST_LINE || !s.endsWith("\n")) throw new Error("not one bounded custody-auth line");
  const f = s.split(/[\t\n\v\f\r ]+/).filter(Boolean);
  if (f.length !== 4 || f[0] !== "custody-auth-v2") throw new Error("not a custody-auth-v2 line");
  if (!VAULT.test(f[1])) throw new Error("the request names no vault (0x + 40 lowercase hex)");
  if (!DEPLOYMENT.test(f[2]) || /^0x0{64}$/.test(f[2])) throw new Error("the request names no deployment id");
  if (!HEX32.test(f[3])) throw new Error("the binding is not 32 bytes of lowercase hex");
  return { v: 2, vault: f[1], id: f[2], binding: f[3] };
}

/** release.WriteAuth, byte for byte; refuses anything ReadAuth would. */
export function custodyAnswerLine({ endpoint, sig, expiry } = {}) {
  const s = String(sig || "").toLowerCase();
  if (!ENDPOINT.test(String(endpoint || "")) || !SIG.test(s) || !Number.isSafeInteger(expiry) || expiry <= 0)
    throw new Error("a custody authorization needs an endpoint, a 65-byte signature and an expiry");
  return `custody-sig-v1 ${Buffer.from(endpoint).toString("base64")} ${expiry} ${s}\n`;
}

/**
 * serveCustodyRequests({ deploymentId, vault, credential, ... }) -> { port, pending(), answer(requestId, auth), close(), stats() }
 * A loopback server for ONE partition's requests, bound to the deployment and vault this partition was spawned with, and
 * admitting only connections that begin with this start's bridge credential (bridge-auth.mjs createBridgeGate). The
 * lifetime budget (maxRequests) and the pending slots count authenticated connections only.
 */
export function serveCustodyRequests({ deploymentId, vault, credential, maxRequests = 16, maxPending = 2, lineTimeoutMs = 10_000,
                                       answerTimeoutMs = 110_000, maxUnauthenticated = 16, authTimeoutMs = 2000, now = Date.now } = {}) {
  if (!DEPLOYMENT.test(String(deploymentId || "")) || /^0x0{64}$/.test(deploymentId)) throw new Error("a custody channel needs the deployment id (0x + 64 hex)");
  if (!VAULT.test(String(vault || ""))) throw new Error("a custody channel needs the committed vault (0x + 40 lowercase hex)");
  const gate = createBridgeGate({ credential, maxUnauthenticated, authTimeoutMs });     // throws without a credential
  const pending = new Map();                         // request id -> { conn, entry, timer }
  const conns = new Set();
  let requests = 0, refused = 0, answered = 0, closed = false;
  const drop = (c) => { c.destroy(); };
  const server = net.createServer((c) => {
    conns.add(c);
    c.on("error", () => {});
    c.on("close", () => { conns.delete(c); for (const [k, p] of pending) if (p.conn === c) { clearTimeout(p.timer); pending.delete(k); } });
    if (closed) return drop(c);
    gate.admit(c, (c, rest) => request(c, rest));
  });
  // an AUTHENTICATED connection: the bridge's, carrying one guest request line
  function request(c, rest) {
    if (closed || ++requests > maxRequests || pending.size >= maxPending) { refused++; return drop(c); }
    let buf = Buffer.alloc(0), done = false;
    const lineTimer = setTimeout(() => { if (!done) { done = true; refused++; drop(c); } }, lineTimeoutMs);
    lineTimer.unref?.();
    c.on("close", () => clearTimeout(lineTimer));
    const onData = (b) => {
      if (done) { drop(c); return; }                 // one request per connection; nothing after it
      buf = Buffer.concat([buf, b]);
      const nl = buf.indexOf(0x0a);
      if (nl < 0 && buf.length < MAX_REQUEST_LINE) return;
      done = true; clearTimeout(lineTimer);
      let req;
      try {
        if (nl < 0 || nl + 1 !== buf.length) throw new Error("one line, then nothing");
        req = parseCustodyRequest(buf);
      } catch { refused++; return drop(c); }
      // THIS partition's deployment and vault, or no answer at all
      if (req.id !== deploymentId || req.vault !== vault) { refused++; return drop(c); }
      if (closed || pending.size >= maxPending) { refused++; return drop(c); }
      const id = crypto.randomBytes(16).toString("hex");
      const entry = { request: id, ...req, since: new Date(now()).toISOString() };
      const timer = setTimeout(() => { if (pending.get(id)?.conn === c) { pending.delete(id); drop(c); } }, answerTimeoutMs);
      timer.unref?.();
      pending.set(id, { conn: c, entry, timer });
    };
    c.on("data", onData);
    c.on("end", () => { if (!done) { done = true; clearTimeout(lineTimer); refused++; drop(c); } });
    if (rest.length) onData(rest);
  }
  server.maxConnections = maxPending + 2 + maxUnauthenticated;
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve({
      port: server.address().port,
      pending: () => [...pending.values()].map((p) => ({ ...p.entry })),
      answer(requestId, auth = {}) {
        if (!REQUEST_ID.test(String(requestId || ""))) throw status(400, "the answer names no request");
        const p = pending.get(requestId);
        if (closed || !p) throw status(409, "that request is not pending on this partition");
        if (String(auth.binding || "") !== p.entry.binding) throw status(409, "the answer is for another binding than the pending request's");
        const sec = Math.floor(now() / 1000);
        if (!Number.isSafeInteger(auth.expiry) || auth.expiry <= sec || auth.expiry > sec + MAX_ANSWER_EXPIRY_SEC)
          throw status(400, `the authorization's expiry must be within ${MAX_ANSWER_EXPIRY_SEC} s from now`);
        let line;
        try { line = custodyAnswerLine(auth); } catch (e) { throw status(400, e.message); }
        clearTimeout(p.timer); pending.delete(requestId);
        p.conn.end(line);
        answered++;
        return { answered: true };
      },
      stats: () => ({ requests, refused, answered, pending: pending.size, closed, gate: gate.stats() }),
      close: () => {
        if (closed) return Promise.resolve();
        closed = true;
        for (const p of pending.values()) clearTimeout(p.timer);
        pending.clear();
        for (const c of conns) c.destroy();
        return new Promise((r) => server.close(() => r()));
      },
    }));
  });
}

/**
 * startCustodyTransport({ bridge: { exe, sha256 }, vmId, deploymentId, vault, spawn }) -> { port, exited, stop, pending,
 *   answer, stats }: the request server, then the pinned bridge for THIS partition's 9445 service to it. `exited` settles
 * when the bridge ends; `stop` ends the bridge, then the server (every pending request is dropped unanswered). Anything
 * that fails stops what was started before it rethrows.
 */
export async function startCustodyTransport({ bridge, vmId, deploymentId, vault, spawn = nodeSpawn, readyTimeoutMs = 10_000, limits = {} }) {
  if (!bridge?.exe || !/^[0-9a-f]{64}$/.test(String(bridge.sha256 || ""))) throw new Error("the custody transport needs the pinned shielded-bridge");
  if (!GUID.test(String(vmId || "")) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(vmId)) throw new Error(`not a partition id: ${vmId}`);
  checkPin(bridge.exe, bridge.sha256, "the shielded-bridge executable");
  // THIS start's credential: to the bridge on stdin only (never argv, environment or a log), and required of every connection
  const credential = mintBridgeCredential();
  const server = await serveCustodyRequests({ deploymentId, vault, credential, ...limits });
  let child = null;
  try {
    child = spawn(bridge.exe, [vmId, String(CUSTODY_VSOCK_PORT), String(server.port), "0", BRIDGE_AUTH_FLAG], { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
    child.stdin.on("error", () => {});
    child.stdin.write(bridgeAuthLine(credential));
    let resolveExit;
    const exited = new Promise((r) => { resolveExit = r; });
    child.once("exit", (code, signal) => resolveExit({ code, signal }));
    child.once("error", (e) => resolveExit({ error: e.message }));
    let out = "", err = "";
    child.stderr.on("data", (b) => { err = (err + b).slice(-1000); });
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("the custody bridge readiness timed out")), readyTimeoutMs);
      child.stdout.on("data", (b) => { out = (out + b).slice(-1000); if (out.includes("shielded bridge ready")) { clearTimeout(timer); resolve(); } });
      exited.then((x) => { clearTimeout(timer); reject(new Error(`the custody bridge exited (${x.code ?? x.signal ?? x.error}): ${err.trim().slice(-300)}`)); });
    });
    // the bridge ending closes the channel at once: nothing is left pending on a path the guest can no longer reach
    exited.then(() => server.close());
    let stopping = null;
    const stop = () => stopping ||= (async () => {
      child.stdin.destroy();
      const t = setTimeout(() => child.kill(), 2000); t.unref?.();
      await exited; clearTimeout(t);
      await server.close();
    })();
    return { port: server.port, exited, stop, pending: server.pending, answer: server.answer, stats: server.stats };
  } catch (e) {
    if (child) { child.stdin?.destroy(); child.kill(); }
    await server.close();
    throw e;
  }
}
