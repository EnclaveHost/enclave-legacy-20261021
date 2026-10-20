// The REAL operator ingress (Caddy, custody/v2/ingress.mjs directCustodyIngress) in front of the REAL custody v2 router
// (custody/v2/http.mjs) with the measured Shield opt-in, on loopback only:
//   - what Caddy hands the custodian in X-Forwarded-For when a client spoofs one (the router reads only the rightmost
//     entry, and only from a measured forwarder);
//   - per-client buckets through the proxy: a spoofing client stays in its own bucket, another client keeps its own;
//   - the Shield host-session routes are forwarded (a malicious EK is refused by the custodian, not by the proxy), while
//     the host's private routes and other methods stay 404 at Caddy.
// Skipped unless CADDY_BIN names a Caddy binary (e.g. work/custody-caddy/caddy). Needs openssl.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { randomBytes } from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import { keccak256, toBytes } from "viem";
import { mintLocalCa } from "./helpers/local-tls.mjs";
import { directCustodyIngress } from "../custody/v2/ingress.mjs";
import { createCustodyRouter } from "../custody/v2/http.mjs";
import { custodianMeasured, measuredModule } from "../custody/v2/build-config.mjs";
import { shieldCustodyFor, defaultShieldLimits, SHIELD_OPERATOR_FORMAT, SHIELD_OPERATOR_TIER_ACK } from "../custody/v2/shield-operator.mjs";
import { maliciousEks } from "./helpers/malicious-ek.mjs";
import { options, world, other, CHAIN, VAULT, COMMITTEE, ENDPOINT, rig } from "./helpers/shield-custody-rig.mjs";

const caddy = process.env.CADDY_BIN;

test("real Caddy ingress + real custody router: the client key, per-client buckets, and the Shield routes", { ...options, skip: options.skip || (!caddy && "set CADDY_BIN to run the real Caddy ingress"), timeout: 60000 }, async () => {
  const { measured } = custodianMeasured({ vault: VAULT, hostOwnership: "0x" + "f5".repeat(20), trustedProxies: ["127.0.0.1"],
    shieldRecipients: { format: SHIELD_OPERATOR_FORMAT, acceptTier: SHIELD_OPERATOR_TIER_ACK, ekRoots: world.ca.bundlePem, ekRootPins: [world.ca.rootPin], limits: defaultShieldLimits() } });
  const M = (await import("data:text/javascript," + encodeURIComponent(measuredModule(measured)))).MEASURED;
  const r = rig({ shieldFor: (party) => shieldCustodyFor(M.shieldRecipients, { party }) });
  const member = { info: (c) => ({ v: 2, committeeId: c }) };
  const router = createCustodyRouter({ custodian: r.custodian, member, runIndependent: async () => ({}), servedCommittee: () => COMMITTEE, chainId: CHAIN, vault: VAULT,
                                       trustedProxies: M.trustedProxies });
  const seen = [];
  const backend = http.createServer((req, res) => { seen.push({ path: req.url, xff: req.headers["x-forwarded-for"], peer: req.socket.remoteAddress }); return router(req, res); });
  backend.listen(0, "127.0.0.1"); await once(backend, "listening");
  const ca = mintLocalCa();
  let child, diagnostics = "";
  const reservation = net.createServer(); reservation.listen(0, "127.0.0.1"); await once(reservation, "listening");
  const port = reservation.address().port; await new Promise((ok) => reservation.close(ok));
  const request = (route, { method = "POST", body = "{}", from = "127.0.0.2", headers = {} } = {}) => new Promise((resolve, reject) => {
    const req = https.request({ hostname: "127.0.0.1", servername: "localhost", port, path: route, method, ca: ca.caPem, localAddress: from, agent: false,
      headers: { host: "localhost", "content-type": "application/json", "content-length": Buffer.byteLength(body), ...headers }, timeout: 5000 }, (res) => {
      const c = []; res.on("data", (d) => c.push(d)); res.on("end", () => { const t = Buffer.concat(c).toString(); let j = null; try { j = JSON.parse(t); } catch {} resolve({ status: res.statusCode, body: j, text: t }); });
    });
    req.on("error", reject); req.on("timeout", () => req.destroy(new Error("timeout"))); req.end(body);
  });
  try {
    const site = directCustodyIngress({ endpoint: "https://localhost", mgmtPort: backend.address().port });
    const config = "{\n admin off\n auto_https off\n}\n" + site.replace("https://localhost {", `https://localhost:${port} {\n bind 127.0.0.1\n tls ${ca.dir}/leaf.pem ${ca.dir}/leaf.key`);
    const configPath = path.join(ca.dir, "Caddyfile"); fs.writeFileSync(configPath, config, { mode: 0o600 });
    execFileSync(caddy, ["adapt", "--config", configPath, "--adapter", "caddyfile"], { stdio: "pipe" });
    child = spawn(caddy, ["run", "--config", configPath, "--adapter", "caddyfile"], { env: { ...process.env, XDG_CONFIG_HOME: ca.dir, XDG_DATA_HOME: ca.dir }, stdio: ["ignore", "ignore", "pipe"] });
    child.stderr.on("data", (c) => { diagnostics = (diagnostics + c.toString()).slice(-3000); });
    let ready = false;
    for (let i = 0; i < 100 && !ready; i++) {
      if (child.exitCode !== null) throw new Error("Caddy exited: " + diagnostics);
      try { ready = (await request("/v2/custody/info", { method: "GET", body: "" })).status === 200; } catch {}
      if (!ready) await new Promise((ok) => setTimeout(ok, 50));
    }
    assert.ok(ready, "the ingress becomes ready");
    // 1. what reaches the custodian: Caddy's own view of the client is the RIGHTMOST X-Forwarded-For entry, whatever the
    //    client sent; the custodian's TCP peer is the proxy
    seen.length = 0;
    await request("/v2/custody/challenge", { headers: { "x-forwarded-for": "198.51.100.9" } });
    const xff = String(seen.at(-1).xff || "");
    assert.equal(xff.split(",").pop().trim(), "127.0.0.2", `X-Forwarded-For as forwarded: ${JSON.stringify(xff)}`);
    assert.match(String(seen.at(-1).peer), /127\.0\.0\.1$/);
    // 2. a spoofing client cannot escape its bucket through the proxy; another client keeps its own
    const codes = [];
    for (let i = 0; i < 35; i++) codes.push((await request("/v2/custody/challenge", { from: "127.0.0.3", headers: { "x-forwarded-for": `203.0.113.${i}` } })).status);
    assert.equal(codes.filter((c) => c === 429).length >= 4 && codes.slice(0, 29).every((c) => c === 200), true, codes.join(","));
    assert.equal((await request("/v2/custody/challenge", { from: "127.0.0.4" })).status, 200);
    // 3. the Shield routes reach the custodian, which refuses a malicious EK itself; a stale session is the custodian's 409
    const bad = maliciousEks(world, other).otherCa;
    const ch = await request("/v2/custody/shield-session/challenge", { from: "127.0.0.5", body: JSON.stringify({ hostId: keccak256(toBytes(ENDPOINT)), endpoint: ENDPOINT,
      hostChallenge: randomBytes(32).toString("hex"), keys: bad.keys }) });
    assert.deepEqual([ch.status, ch.body?.error], [403, "shield_session"], ch.text);
    assert.match(ch.body.message, /does not chain to a pinned TPM root/);
    const at = await request("/v2/custody/shield-session/attest", { from: "127.0.0.5", body: JSON.stringify({ session: "00" }) });
    assert.deepEqual([at.status, at.body?.error], [409, "shield_session"], at.text);
    // 4. still private at the proxy: the host's routes, other methods on the Shield routes, host-binding
    const forwarded = seen.length;
    for (const [route, method] of [["/state", "GET"], ["/submit", "POST"], ["/v2/custody/host-binding", "POST"], ["/v2/custody/shield-session/challenge", "GET"],
                                   ["/v2/custody/shield-session/other", "POST"], ["/v2/custody/%73hield-session/attest", "GET"]])
      assert.equal((await request(route, { method, from: "127.0.0.6" })).status, 404, `${method} ${route}`);
    assert.equal(seen.length, forwarded, "nothing private reached the custodian");
  } finally {
    if (child && child.exitCode === null) { const done = once(child, "exit"); child.kill("SIGTERM"); await done; }
    backend.closeAllConnections(); await new Promise((ok) => backend.close(ok));
    ca.cleanup();
  }
});
