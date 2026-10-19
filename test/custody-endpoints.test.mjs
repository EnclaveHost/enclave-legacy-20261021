// How a custodian is reached on the regional network boxes (docs/security/secret-custody.md §9): the platform DNS answers
// fixed names for it (relay/dns-relay.js APP_STATIC), and the box's public 443/80 router hands that name to a LOCAL service
// (network/wg-provider localRoutes) instead of a WireGuard peer.
//   run: node --test test/custody-endpoints.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import net from "node:net";
import tls from "node:tls";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRouter } from "../network/wg-provider/router.mjs";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const freePort = () => new Promise((res) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); }); });
const hasDig = spawnSync("dig", ["-v"], { stdio: "ignore" }).status === 0;

test("APP_STATIC: a custodian label answers its fixed address; an all-hex (deployment-shaped) label never does", { skip: hasDig ? false : "dig absent" }, async () => {
  const dnsPort = await freePort(), apiPort = await freePort();
  const p = spawn(process.execPath, [path.join(ROOT, "relay", "dns-relay.js")], {
    env: { ...process.env, IP_ZONE: "ip.test", APP_ZONE: "app.test", NS_NAME: "ns1.test", ENCLAVES: "https://example.invalid",
           DNS_PORT: String(dnsPort), DNS_API_PORT: String(apiPort), DNS_API_BIND: "127.0.0.1", DNS_BIND: "127.0.0.1",
           APP_STATIC: "custody-us-west=198.51.100.7, deadbeef=192.0.2.1, bad label=192.0.2.2" },
    stdio: ["ignore", "pipe", "pipe"] });
  try {
    for (let i = 0; i < 100; i++) { try { if ((await fetch(`http://127.0.0.1:${apiPort}/health`)).ok) break; } catch {} await new Promise((r) => setTimeout(r, 100)); }
    const dig = (name, type = "A") => spawnSync("dig", ["+short", "+time=2", "+tries=1", "-p", String(dnsPort), "@127.0.0.1", name, type], { encoding: "utf8" }).stdout.trim();
    assert.equal(dig("custody-us-west.app.test"), "198.51.100.7");
    assert.equal(dig("custody-us-west.app.test", "AAAA"), "");
    assert.equal(dig("deadbeef.app.test"), "", "a hex label is a deployment's, never a static one");
    assert.equal(dig("custody-ca-east.app.test"), "", "an unlisted name is untouched");
  } finally { p.kill(); }
});

test("a local route carries a TLS hello for its name to the loopback service; an unknown name is closed", async () => {
  const got = [];
  const backend = net.createServer((s) => { s.once("data", (d) => { got.push(d[0]); s.destroy(); }); });
  await new Promise((r) => backend.listen(0, "127.0.0.1", r));
  const port = await freePort();
  const local = { host: "127.0.0.1", tls: backend.address().port, http: backend.address().port };
  const router = await createRouter({ port, host: "127.0.0.1", tls: true, route: (n) => (n === "custody.test" ? local : null) });
  const hello = (servername) => new Promise((resolve) => {
    const c = tls.connect({ host: "127.0.0.1", port, servername, rejectUnauthorized: false });
    c.on("error", () => resolve()); c.on("close", () => resolve());
  });
  try {
    await hello("custody.test");
    assert.deepEqual(got, [0x16], "the backend received the TLS ClientHello");
    await hello("someone-else.test");
    assert.deepEqual(got, [0x16], "an unknown name reached nothing");
  } finally { router.close(); backend.close(); }
});

test('IP recovery is opt-in, loopback-only, and never catches unknown SNI or malformed TLS',async()=>{
 const got=[];const backend=net.createServer(s=>s.once('data',d=>{got.push(d);s.destroy();}));
 await new Promise(r=>backend.listen(0,'127.0.0.1',r));
 const local={host:'127.0.0.1',tls:backend.address().port};
 const off=await createRouter({port:0,host:'127.0.0.1',route:()=>null});
 const on=await createRouter({port:0,host:'127.0.0.1',route:()=>null,noSniRoute:local});
 const hello=(port,servername='')=>new Promise(resolve=>{const c=tls.connect({host:'127.0.0.1',port,servername,rejectUnauthorized:false});c.on('error',()=>{});c.on('close',resolve);});
 try {
  await hello(off.port);assert.equal(got.length,0);
  await hello(on.port);assert.equal(got.length,1);assert.equal(got[0][0],22);
  await hello(on.port,'unknown.test');assert.equal(got.length,1);
  await new Promise(resolve=>{const c=net.connect(on.port,'127.0.0.1',()=>c.write('GET / HTTP/1.1\r\nHost: bad\r\n\r\n'));c.on('error',()=>{});c.on('close',resolve);});
  assert.equal(got.length,1);
  for(const bad of [{host:'192.0.2.1',tls:443},{host:'localhost',tls:443},{host:'127.0.0.1',tls:0},{host:'127.0.0.1',tls:65536}])await assert.rejects(createRouter({port:0,route:()=>null,noSniRoute:bad}),/loopback TLS/);
 }finally{off.close();on.close();backend.close();}
});
