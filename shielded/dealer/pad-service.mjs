#!/usr/bin/env node
// The host pad service (shielded/dealer/HOST-BANK.md, phase H2): one per Shield host, banks per
// model, each pad issued to exactly one consumer, once.
//
// It serves the engine's existing bank client (wasm/ggml-shielded/shielded-bank.c), so a keyed
// consumer needs SHIELDED_PAD_SOURCE=http://<service>/v1/shipments and SHIELDED_PAD_KEYED=1:
//   POST /v1/consumers            {"delivery_id","pad_pk","model","ahead"}  register; issue `ahead` rows
//   GET  /v1/shipments?seed_id=X&need=N  {"shipments":[{name,bytes,index0,count}]} what X was
//                                 issued, after topping X up to `ahead` rows past its horizon N
//   GET  /v1/shipments/X/<name>   the shipment (format 4, boxed to X's pad key)
//   GET  /v1/health               bank cursors and consumers (counts only)
//
// Single issuance: the bank cursor is advanced and persisted BEFORE the rows are re-sealed, so a
// crash between the two burns those rows instead of ever issuing them twice. H3 replaces the
// local state file with the relay's signed per-bank ledger (rollback-proof).
//
// Phase H2 runs as an ordinary host process for tests: the service's own key comes from
// PADS_BANK_SK (H4: derived inside its TEE). Config: node pad-service.mjs CONFIG.json
//   {"listen":"127.0.0.1:7790","stateDir":"...","padsBank":".../pads-bank",
//    "models":{"<name>":{"bankDir":"...","bankId":"<32 hex>","digest":"<64 hex>","rowsPerShipment":8,"maxAhead":256}}}
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import { spawn } from "node:child_process";

const HEX = (n) => new RegExp(`^[0-9a-f]{${n}}$`);
const cfgPath = process.argv[2];
if (!cfgPath) { console.error("usage: pad-service.mjs CONFIG.json"); process.exit(2); }
const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
const bankSk = process.env.PADS_BANK_SK || "";
if (!HEX(64).test(bankSk)) { console.error("PADS_BANK_SK must be 64 lowercase hex"); process.exit(2); }
for (const [name, m] of Object.entries(cfg.models || {}))
  if (!HEX(32).test(m.bankId) || !HEX(64).test(m.digest) || !m.bankDir) { console.error(`model ${name}: bankDir, bankId (32 hex), digest (64 hex)`); process.exit(2); }

const stateFile = path.join(cfg.stateDir, "state.json");
const outDir = path.join(cfg.stateDir, "out");
fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });
let state = { banks: {}, consumers: {} };
try { state = JSON.parse(fs.readFileSync(stateFile, "utf8")); } catch {}
for (const name of Object.keys(cfg.models)) state.banks[name] ??= { cursor: 0 };

function persist() {                                    // atomic: temp, fsync, rename, fsync dir
  const tmp = `${stateFile}.tmp`;
  const fd = fs.openSync(tmp, "w", 0o600);
  fs.writeSync(fd, JSON.stringify(state));
  fs.fsyncSync(fd); fs.closeSync(fd);
  fs.renameSync(tmp, stateFile);
  const dfd = fs.openSync(cfg.stateDir, "r"); fs.fsyncSync(dfd); fs.closeSync(dfd);
}

let chain = Promise.resolve();                          // one issuance at a time, in order
const serial = (fn) => (chain = chain.then(fn, fn));

function run(args) {
  return new Promise((resolve) => {
    const p = spawn(cfg.padsBank, args, { env: { ...process.env, PADS_BANK_SK: bankSk }, stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d)); p.stderr.on("data", (d) => (err += d));
    p.on("close", (code) => resolve({ code, out: out.trim(), err: err.trim() }));
  });
}

// Issue `rows` more rows to consumer c, in shipments of rowsPerShipment.
async function issue(c, rows) {
  const m = cfg.models[c.model];
  const per = m.rowsPerShipment || 8;
  while (rows > 0) {
    const count = Math.min(per, rows);
    const bank = state.banks[c.model];
    const src0 = bank.cursor, dst0 = c.next;
    bank.cursor += count; c.next += count;               // reserve before use: these bank rows are spent now
    persist();
    const name = `issue-${dst0}-${count}.pads`;
    const dir = path.join(outDir, c.deliveryId);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const r = await run(["issue", m.bankDir, m.bankId, String(src0), String(count), m.digest, c.padPk, c.deliveryId, String(dst0), path.join(dir, name)]);
    if (r.code !== 0) {
      c.failed = (c.failed || 0) + 1; persist();
      throw new Error(`issue ${c.deliveryId} rows ${dst0}+${count} from bank ${src0}: ${r.out || r.err}`);
    }
    c.shipments.push({ name, index0: dst0, count, src0, bytes: fs.statSync(path.join(dir, name)).size });
    persist();
    rows -= count;
  }
}

// Keep a consumer `ahead` rows past its engine's horizon (the `need` its bank client reports).
// Never past what it downloaded: the client prefetches whatever is listed, so issuing on download
// would drain the bank into one consumer's cache.
function topUp(c) {
  return serial(async () => {
    const want = (c.needTo || 0) + c.ahead - c.next;
    if (want > 0) await issue(c, want);
  });
}

function json(res, code, obj) { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(obj)); }
function body(req) {
  return new Promise((resolve, reject) => {
    let b = ""; req.on("data", (d) => { b += d; if (b.length > 4096) req.destroy(); });
    req.on("end", () => { try { resolve(JSON.parse(b || "{}")); } catch (e) { reject(e); } });
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://x");
    if (req.method === "POST" && url.pathname === "/v1/consumers") {
      const b = await body(req);
      const id = String(b.delivery_id || ""), pk = String(b.pad_pk || ""), model = String(b.model || "");
      const ahead = Number(b.ahead || 0);
      if (!HEX(32).test(id) || !HEX(64).test(pk) || !cfg.models[model]) return json(res, 400, { error: "delivery_id (32 hex), pad_pk (64 hex), a served model" });
      const maxAhead = cfg.models[model].maxAhead || 256;
      if (!Number.isInteger(ahead) || ahead < 1 || ahead > maxAhead) return json(res, 400, { error: `ahead 1..${maxAhead}` });
      const old = state.consumers[id];
      if (old && (old.padPk !== pk || old.model !== model)) return json(res, 409, { error: "delivery_id already registered with another key or model" });
      const c = old || (state.consumers[id] = { deliveryId: id, padPk: pk, model, next: 0, needTo: 0, ahead, shipments: [] });
      c.ahead = ahead; persist();
      await topUp(c);
      return json(res, 200, { delivery_id: id, issued: c.next });
    }
    if (req.method === "GET" && url.pathname === "/v1/shipments") {
      const c = state.consumers[url.searchParams.get("seed_id") || ""];
      const need = Number(url.searchParams.get("need") || 0);
      if (c && Number.isSafeInteger(need) && need > (c.needTo || 0)) {
        c.needTo = Math.min(need, c.next + c.ahead);      // a horizon can run at most `ahead` past what was issued
        persist();
        try { await topUp(c); } catch (e) { console.error(String(e)); }  // list what exists; the engine waits or mints
      }
      return json(res, 200, { shipments: c ? c.shipments.map(({ name, bytes, index0, count }) => ({ name, bytes, index0, count })) : [] });
    }
    const m = /^\/v1\/shipments\/([0-9a-f]{32})\/(issue-\d+-\d+\.pads)$/.exec(url.pathname);
    if (req.method === "GET" && m) {
      const c = state.consumers[m[1]];
      const s = c && c.shipments.find((x) => x.name === m[2]);
      if (!s) return json(res, 404, { error: "no such shipment" });
      res.writeHead(200, { "content-type": "application/octet-stream", "content-length": s.bytes });
      fs.createReadStream(path.join(outDir, c.deliveryId, s.name)).pipe(res);
      return;
    }
    if (req.method === "GET" && url.pathname === "/v1/health") {
      return json(res, 200, { banks: state.banks, consumers: Object.keys(state.consumers).length });
    }
    json(res, 404, { error: "not found" });
  } catch (e) {
    json(res, 500, { error: String(e.message || e) });
  }
});
const [host, port] = (cfg.listen || "127.0.0.1:7790").split(":");
server.listen(Number(port), host, () => console.log(`pad-service listening on ${host}:${server.address().port}`));
