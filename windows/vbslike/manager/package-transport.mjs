/* ============================================================
   THE OWNER-COMMITTED STARTUP PACKAGE, CARRIED INTO ONE SHIELD PARTITION (vsock 9446).

   The Shield-direct front (isolation/m2/front/shield_direct.go) reads the exact package bytes from CID 2 port 9446 and
   verifies them itself, against its own RPC quorum, before it certifies any owner-committed name. This is the host's half:
   a carrier, never an authority. A substituted, truncated or foreign package is refused in the guest (bootstrap.ReadPackage,
   Reader.Authorize); this side only frames the bytes exactly as Linux guestd does (bootstrap.WritePackage):

     "enclb01\n" (8) || deployment id (32) || u32 big-endian length || package bytes (1..128 KiB)

   and serves that one frame to each connection on a loopback port, through the SAME pinned shielded-bridge the egress and
   GPU paths use (it binds THIS partition's hv_sock service only and checks every peer's VmId). The bridge's executable is
   hashed against its pin at every start; closing stdin ends it. The partition lifecycle owns it (wmi-launcher.mjs).
   The loopback listener serves ONLY that bridge: each start mints a credential, hands it to the bridge on stdin
   (--worker-auth-stdin), and requires it at the head of every connection (bridge-auth.mjs). Another local process's
   connection is closed unserved and does not count against maxServes.
   A WMI partition's hv_sock service for 9446 must be registered under GuestCommunicationServices, as egress's is; the
   launcher's preflight READS that and never writes the registry.
   ============================================================ */
import net from "node:net";
import { spawn as nodeSpawn } from "node:child_process";
import { checkPin } from "./egress.mjs";
import { BRIDGE_AUTH_FLAG, bridgeAuthLine, createBridgeGate, mintBridgeCredential } from "./bridge-auth.mjs";

export const PACKAGE_VSOCK_PORT = 9446;
/** vsock 9446 -> its hv_sock service id (Linux hyperv_transport srv_id_template, as EGRESS_SERVICE_GUID for 9443). */
export const PACKAGE_SERVICE_GUID = "000024e6-facb-11e6-bd58-64006a7986d3";
export const MAX_PACKAGE_BYTES = 128 * 1024;                 // isolation/m2/bootstrap MaxManifestBytes
const MAGIC = Buffer.from("enclb01\n");
const DEPLOYMENT = /^0x[0-9a-f]{64}$/;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** bootstrap.WritePackage, byte for byte. */
export function packageFrame(deploymentId, bytes) {
  if (!DEPLOYMENT.test(String(deploymentId || "")) || /^0x0{64}$/.test(deploymentId)) throw new Error("a package frame needs the deployment id (0x + 64 hex)");
  const raw = Buffer.from(bytes || []);
  if (!raw.length || raw.length > MAX_PACKAGE_BYTES) throw new Error(`a startup package is 1..${MAX_PACKAGE_BYTES} bytes`);
  const len = Buffer.alloc(4); len.writeUInt32BE(raw.length);
  return Buffer.concat([MAGIC, Buffer.from(deploymentId.slice(2), "hex"), len, raw]);
}

/**
 * A loopback server answering every AUTHENTICATED connection (one beginning with this start's bridge credential) with
 * the one frame, then closing. At most `maxServes` answers, counted on authenticated connections only.
 */
export function servePackage(frame, { credential, maxServes = 32, maxUnauthenticated = 16, authTimeoutMs = 2000 } = {}) {
  let served = 0;
  const gate = createBridgeGate({ credential, maxUnauthenticated, authTimeoutMs });     // throws without a credential
  const conns = new Set();                                    // closed with the server: close() never waits on a caller
  const server = net.createServer((c) => {
    conns.add(c); c.on("close", () => conns.delete(c));
    c.on("error", () => {});
    gate.admit(c, (c) => {
      if (++served > maxServes) { c.destroy(); return; }
      c.end(frame);
    });
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve({ port: server.address().port, served: () => served, gate: gate.stats,
      close: () => new Promise((r) => { server.close(() => r()); for (const c of conns) c.destroy(); }) }));
  });
}

/**
 * startPackageTransport({ bridge: { exe, sha256 }, vmId, deploymentId, bytes, spawn }) -> { port, exited, stop }
 *   the frame server, then the pinned bridge for THIS partition's 9446 service to it. `exited` settles when the bridge
 *   ends; `stop` ends the bridge, then the server. Anything that fails stops what was started before it rethrows.
 */
export async function startPackageTransport({ bridge, vmId, deploymentId, bytes, spawn = nodeSpawn, readyTimeoutMs = 10_000 }) {
  if (!bridge?.exe || !/^[0-9a-f]{64}$/.test(String(bridge.sha256 || ""))) throw new Error("the package transport needs the pinned shielded-bridge");
  if (!GUID.test(String(vmId || "")) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(vmId)) throw new Error(`not a partition id: ${vmId}`);
  const frame = packageFrame(deploymentId, bytes);
  checkPin(bridge.exe, bridge.sha256, "the shielded-bridge executable");
  // THIS start's credential: to the bridge on stdin only (never argv, environment or a log), and required of every connection
  const credential = mintBridgeCredential();
  const server = await servePackage(frame, { credential });
  let child = null;
  try {
    child = spawn(bridge.exe, [vmId, String(PACKAGE_VSOCK_PORT), String(server.port), "0", BRIDGE_AUTH_FLAG], { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
    child.stdin.on("error", () => {});
    child.stdin.write(bridgeAuthLine(credential));
    let resolveExit;
    const exited = new Promise((r) => { resolveExit = r; });
    child.once("exit", (code, signal) => resolveExit({ code, signal }));
    child.once("error", (e) => resolveExit({ error: e.message }));
    let out = "", err = "";
    child.stderr.on("data", (b) => { err = (err + b).slice(-1000); });
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("the package bridge readiness timed out")), readyTimeoutMs);
      child.stdout.on("data", (b) => { out = (out + b).slice(-1000); if (out.includes("shielded bridge ready")) { clearTimeout(timer); resolve(); } });
      exited.then((x) => { clearTimeout(timer); reject(new Error(`the package bridge exited (${x.code ?? x.signal ?? x.error}): ${err.trim().slice(-300)}`)); });
    });
    const stop = async () => {
      child.stdin.destroy();
      const t = setTimeout(() => child.kill(), 2000); t.unref?.();
      await exited; clearTimeout(t);
      await server.close();
    };
    return { port: server.port, served: server.served, gate: server.gate, exited, stop };
  } catch (e) {
    if (child) { child.stdin?.destroy(); child.kill(); }
    await server.close();
    throw e;
  }
}
