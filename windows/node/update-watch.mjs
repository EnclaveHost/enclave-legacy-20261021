// update-watch.mjs -- start this host's update the moment a new release is live, not on the hour.
//
// The node asks get.enclave.host/windows/latest.json once a minute (a few hundred bytes, from its own process: nothing new
// starts on the owner's PC) and, when it names a version newer than the one installed (Program Files\Enclave's
// manifest.json), starts the \Enclave\Update task: update-host.ps1 downloads, checks and installs it (and rolls back if it
// fails). That task also runs at boot and hourly, which only matters when this node is not running.
//
// WHERE `latest` COMES FROM is the caller's choice and the whole security question: a host with a release policy
// (release-channel.mjs createSignedLatest) only ever sees versions its pinned key(s) signed, served by the mirrors its
// operator chose; a host without one reads the legacy, UNSIGNED get.enclave.host/windows/latest.json. This module only
// decides "newer than installed, not tried too recently", and the update task re-verifies everything before installing.
const parts = (v) => String(v || "").split(".").map((x) => (/^\d+$/.test(x) ? Number(x) : NaN));
/** a > b for dotted numeric versions (2026.10.12.10 > 2026.10.12.9); false when either is unreadable. */
export function newer(a, b) {
  const x = parts(a), y = parts(b);
  if (!x.length || !y.length || x.some(Number.isNaN) || y.some(Number.isNaN)) return false;
  for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return d > 0; }
  return false;
}
/**
 * createUpdateWatch({ installed, fetchLatest, trigger, now, log }) -> { check() }: `installed` is the running version,
 * fetchLatest() -> latest.json's object, trigger() starts the update task. A version is triggered once, and again only
 * after RETRY_MS (a failed install leaves this node running the old version).
 */
export const RETRY_MS = 30 * 60_000;
export function createUpdateWatch({ installed, fetchLatest, trigger, now = Date.now, log = () => {} }) {
  const tried = new Map();
  let busy = false;
  async function check() {
    if (busy || !installed) return null;
    busy = true;
    try {
      const latest = await fetchLatest();
      const v = latest && typeof latest.version === "string" ? latest.version : null;
      if (!v || !newer(v, installed)) return null;
      if (tried.has(v) && now() - tried.get(v) < RETRY_MS) return null;
      tried.set(v, now());
      log(`update: ${v} is live (this host runs ${installed}): starting the update now`);
      await trigger();
      return v;
    } catch (e) { log(`update: ${e.message}`); return null; }
    finally { busy = false; }
  }
  return { check };
}
