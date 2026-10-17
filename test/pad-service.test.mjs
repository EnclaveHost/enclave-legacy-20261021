// The host pad service (shielded/dealer/HOST-BANK.md, H2) end to end on the host: a synthetic
// model's bank minted to the service, consumers registered over HTTP, and the engine's own dealt
// import (the bank client, keyed cells, the pad check) consuming what the service issued.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const G = path.join(root, "wasm/ggml-shielded");
const hex = (n) => crypto.randomBytes(n).toString("hex");
function x25519() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
  const b = (k) => Buffer.from(k.export({ format: "jwk" })[k.type === "public" ? "x" : "d"], "base64url").toString("hex");
  return { pk: b(publicKey), sk: b(privateKey) };
}
function startService(cfgPath, sk) {
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [path.join(root, "shielded/dealer/pad-service.mjs"), cfgPath], { env: { ...process.env, PADS_BANK_SK: sk }, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    p.stdout.on("data", (d) => { out += d; const m = /listening on [^:]+:(\d+)/.exec(out); if (m) resolve({ p, port: Number(m[1]) }); });
    p.stderr.on("data", (d) => process.stderr.write(d));
    p.on("exit", (c) => reject(new Error(`service exited ${c}: ${out}`)));
  });
}
const stop = (s) => new Promise((r) => { s.p.removeAllListeners("exit"); if (s.p.exitCode !== null || s.p.signalCode !== null) return r(); s.p.on("exit", r); s.p.kill("SIGTERM"); });
async function register(port, body) {
  const r = await fetch(`http://127.0.0.1:${port}/v1/consumers`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return { status: r.status, json: await r.json() };
}
function consume(port, id, sk, dir, rows) {
  const env = { ...process.env, SHIELDED_PAD_SOURCE: `http://127.0.0.1:${port}/v1/shipments`, SHIELDED_PAD_KEYED: "1",
    SHIELDED_PAD_SEED_ID: id, SHIELDED_PAD_SK: sk, SHIELDED_PAD_LEDGER: path.join(dir, `ledger-${id}`), SHIELDED_PAD_CHECK: "1",
    SHIELDED_PAD_CACHE: path.join(dir, `cache-${id}`), SHIELDED_PAD_WINDOW: "4", SHIELDED_PAD_WAIT_MS: "15000" };
  delete env.SHIELDED_PAD_SEED;
  return spawnSync(path.join(G, "keyed-bank-fixture"), ["consume", String(rows)], { env, encoding: "utf8", timeout: 120_000 });
}

test("host pad service: a bank issued once, to consumers that import through the pad check", { timeout: 600_000 }, async () => {
  const make = spawnSync("make", ["-s", "pads-bank", "keyed-bank-fixture", ...(process.env.SHIELDED_MAKE_ARGS || "").split(" ").filter(Boolean)], { cwd: G, encoding: "utf8" });
  assert.equal(make.status, 0, make.stdout + make.stderr);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pad-service-"));
  let s = null;
  try {
    const svc = x25519(), A = x25519(), B = x25519(), C = x25519();
    const bankSecret = hex(32), bankId = hex(16), digest = hex(32);
    const bankDir = path.join(dir, "bank"); fs.mkdirSync(bankDir);
    const mint = spawnSync(path.join(G, "keyed-bank-fixture"), ["mint", bankDir, bankSecret, bankId, digest, svc.pk, "0", "64"], { encoding: "utf8" });
    assert.equal(mint.status, 0, mint.stdout + mint.stderr);
    const stateDir = path.join(dir, "state");
    const cfgPath = path.join(dir, "cfg.json");
    fs.writeFileSync(cfgPath, JSON.stringify({ listen: "127.0.0.1:0", stateDir, padsBank: path.join(G, "pads-bank"),
      models: { synthetic: { bankDir, bankId, digest, rowsPerShipment: 4, maxAhead: 32 } } }));

    s = await startService(cfgPath, svc.sk);
    const idA = hex(16), idB = hex(16), idC = hex(16);
    let r = await register(s.port, { delivery_id: idA, pad_pk: A.pk, model: "synthetic", ahead: 8 });
    assert.equal(r.status, 200, JSON.stringify(r.json)); assert.equal(r.json.issued, 8);
    // the consumer's engine imports 3 rows of both groups over HTTP, every pad through the pad check
    const ca = consume(s.port, idA, A.sk, dir, 3);
    assert.equal(ca.status, 0, ca.stdout + ca.stderr);
    assert.match(ca.stdout, /"pads":6/);
    // another key for the same delivery id is refused; a bad body is refused
    r = await register(s.port, { delivery_id: idA, pad_pk: B.pk, model: "synthetic", ahead: 8 }); assert.equal(r.status, 409);
    r = await register(s.port, { delivery_id: idB, pad_pk: B.pk, model: "nope", ahead: 8 }); assert.equal(r.status, 400);
    r = await register(s.port, { delivery_id: idB, pad_pk: B.pk, model: "synthetic", ahead: 8 }); assert.equal(r.status, 200);
    // a consumer holding someone else's delivery id but not its key opens nothing
    const wrong = consume(s.port, idB, A.sk, dir, 1);
    assert.notEqual(wrong.status, 0, wrong.stdout);
    // single issuance: A's and B's bank rows are disjoint
    const st1 = JSON.parse(fs.readFileSync(path.join(stateDir, "state.json"), "utf8"));
    const rowsOf = (c) => c.shipments.flatMap((x) => Array.from({ length: x.count }, (_, i) => x.src0 + i));
    const a = rowsOf(st1.consumers[idA]), b = rowsOf(st1.consumers[idB]);
    assert.ok(a.length >= 8 && b.length >= 8);
    assert.equal(new Set([...a, ...b]).size, a.length + b.length, "a bank row went to two consumers");
    // the cursor survives a restart: C's rows come after every row issued before
    const before = st1.banks.synthetic.cursor;
    await stop(s);
    s = await startService(cfgPath, svc.sk);
    r = await register(s.port, { delivery_id: idC, pad_pk: C.pk, model: "synthetic", ahead: 4 }); assert.equal(r.status, 200);
    const st2 = JSON.parse(fs.readFileSync(path.join(stateDir, "state.json"), "utf8"));
    assert.ok(Math.min(...rowsOf(st2.consumers[idC])) >= before);
    const cc = consume(s.port, idC, C.sk, dir, 2);
    assert.equal(cc.status, 0, cc.stdout + cc.stderr);
  } finally {
    if (s) await stop(s);                               // a failed assertion must not leave the service holding the test open
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
