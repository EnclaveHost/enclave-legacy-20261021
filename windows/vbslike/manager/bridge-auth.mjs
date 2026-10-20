/* ============================================================
   A PER-START CREDENTIAL BETWEEN THE PINNED shielded-bridge AND ITS LOOPBACK WORKER (package 9446, custody 9445).

   The package and custody servers listen on 127.0.0.1, where ANY local process can connect, not only the bridge that
   carries this partition's hv_sock (the bridge checks the hypervisor-filled VmId of every guest connection). So each
   transport start mints a credential, hands it to ITS bridge on stdin (shielded-bridge --worker-auth-stdin), and admits
   a loopback connection only when it begins with that credential. An unauthenticated connection consumes nothing - no
   request budget, no pending slot, no package serve - and is closed within authTimeoutMs.

   Where the credential lives:
     - this process, and the bridge child: the anonymous stdin pipe whose handle only the two hold;
     - one line at the head of each bridge->worker loopback stream.
   It is never in argv, the environment, a file or a log. Reading it needs SYSTEM or administrator rights (process
   memory, or loopback capture), which T0-hv trusts anyway: this guards against OTHER local callers, not the host's
   administrator.
   ============================================================ */
import crypto from "node:crypto";

export const BRIDGE_AUTH_FLAG = "--worker-auth-stdin";
export const BRIDGE_AUTH_PREFIX = "enclave-bridge-auth-v1 ";
export const BRIDGE_AUTH_LINE_BYTES = BRIDGE_AUTH_PREFIX.length + 64 + 1;       // 88
const HEX64 = /^[0-9a-f]{64}$/;

export const mintBridgeCredential = () => crypto.randomBytes(32).toString("hex");
/** The one line the bridge reads first on stdin, and writes first on each worker connection. */
export function bridgeAuthLine(credential) {
  if (!HEX64.test(String(credential || ""))) throw new Error("a bridge credential is 32 bytes of lowercase hex");
  return `${BRIDGE_AUTH_PREFIX}${credential}\n`;
}

/**
 * createBridgeGate({ credential, maxUnauthenticated, authTimeoutMs }) -> { admit(conn, onAuthenticated), stats() }
 *   admit: the connection's first BRIDGE_AUTH_LINE_BYTES must be the credential's line; then onAuthenticated(conn, rest)
 *   runs with any bytes that followed it, and every later byte reaches the caller's own handlers. Otherwise the
 *   connection is destroyed, and nothing of the caller's runs.
 * NO ORACLE: the line is judged only WHOLE (all 88 bytes, one constant-time comparison). Until then nothing about the
 *   bytes so far is looked at - a correct prefix and a wrong one are held alike until the line completes, the client
 *   ends, or authTimeoutMs passes - so a caller learns nothing from how long its partial guess stays open. (Rejecting at
 *   the first differing byte would let parallel guessers recover the credential one hex digit at a time.)
 * BOUNDED: at most maxUnauthenticated wait at once; past that the OLDEST waiting connection is evicted, whatever it has
 *   sent (content never decides it). The bridge writes its whole line in the first segment of its connection, so it is
 *   judged on arrival; a flood costs availability only, within these bounds.
 */
export function createBridgeGate({ credential, maxUnauthenticated = 16, authTimeoutMs = 2000 } = {}) {
  const want = Buffer.from(bridgeAuthLine(credential));
  const waiting = new Map();                                  // conn -> { got: number, timer }
  let unauthenticated = 0, evicted = 0, authenticated = 0;
  const reject = (c, why) => {
    const w = waiting.get(c);
    if (!w) return;
    clearTimeout(w.timer); waiting.delete(c);
    if (why === "evicted") evicted++; else unauthenticated++;
    c.destroy();
  };
  function admit(c, onAuthenticated) {
    // oldest first (Map insertion order), whatever it has sent: eviction never depends on the bytes
    if (waiting.size >= maxUnauthenticated) reject(waiting.keys().next().value, "evicted");
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => reject(c, "timeout"), authTimeoutMs);
    timer.unref?.();
    waiting.set(c, { got: 0, timer });
    const onData = (b) => {
      const w = waiting.get(c);
      if (!w) return;
      buf = Buffer.concat([buf, b]); w.got = buf.length;
      // nothing is judged before the WHOLE line is here: a partial line, right or wrong, waits alike (no prefix oracle)
      if (buf.length < want.length) return;
      if (!crypto.timingSafeEqual(buf.subarray(0, want.length), want)) return reject(c, "mismatch");
      clearTimeout(w.timer); waiting.delete(c);
      c.off("data", onData); c.off("end", onEnd); c.off("close", onEnd);
      authenticated++;
      onAuthenticated(c, buf.subarray(want.length));
    };
    const onEnd = () => reject(c, "ended");
    c.on("data", onData);
    c.on("end", onEnd);
    c.on("close", onEnd);
    c.on("error", () => reject(c, "error"));
  }
  return { admit, stats: () => ({ unauthenticated, evicted, authenticated, waiting: waiting.size }) };
}
