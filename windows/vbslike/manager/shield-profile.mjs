// Fixed single-Radeon profile; distinct from Linux's two-card V100 release.
import fs from "node:fs";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { runtimeId } from "../../../isolation/contract/runtime.mjs";
import { shieldedCard } from "../../node/shieldedcard.mjs";
export const MODEL = "qwen2.5-0.5b-q8-gguf";
export const CARD_BYTES = 12 * 2 ** 30;
export function profile(runtime) {
  return { model: MODEL, models: [MODEL], minimumGpuMilli: 500, cardBudgetBytes: CARD_BYTES,
    cards: 1, minimumCpuMilli: 250, guestFloorMiB: 8192, runtime, runtimeId: Buffer.from(runtimeId(runtime)).toString("hex") };
}
export function inferenceRefusal(derive, body, p) {
  const i = derive.inference;
  const share = body.gpuShare ?? (Number(body.gpuMilli || 0) / 1000);
  if (!i) return Number(share) === 0 ? null : "GPU allocation requires measured inference";
  if (!p || !p.ready) return "Shield worker/profile is unavailable";
  if (i.model !== MODEL || !Number.isInteger(i.gpuMilli) || i.gpuMilli < 500 || i.gpuMilli > 1000)
    return "NucBox Shield requires the pinned 0.5B model and 500..1000 GPU milli";
  if (!Number.isFinite(share) || Math.abs(share * 1000 - i.gpuMilli) > 1e-7
      || (body.gpuMilli != null && Number(body.gpuMilli) !== i.gpuMilli)) return "GPU allocation differs from measured bundle";
  if (derive.runtimeId !== p.runtimeId) return "wrong Shield runtime identity";
  if (!Number.isFinite(body.cpuShare) || body.cpuShare < 0.25) return "Shield inference needs at least 25% of this node CPU";
  if (derive.policy?.memMiB < 8192 || derive.policy?.vcpus < 4 || derive.policy?.cpuPercent < 400)
    return "Shield inference requires 8192 MiB and four vCPUs";
  if (derive.http) return "initial Shield profile serves wasi:http components";
  if ((derive.ports || []).length) return "Shield tunnel ports are not offered";
  return null;
}
// VM lifecycle owns the bridge; stdin close kills all links, including idle ones.
export async function startBridge({ exe, sha256, vmId, port = 19595 }) {
  if (createHash("sha256").update(fs.readFileSync(exe)).digest("hex") !== sha256)
    throw new Error("Shield bridge executable differs from its pin");
  const child = spawn(exe, [vmId, "19595", String(port), "0"], { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
  let resolveExit;
  const exited = new Promise(r => resolveExit = r);
  child.once("exit", (code, signal) => resolveExit({ code, signal }));
  child.once("error", e => resolveExit({ error:e.message }));
  const stop = async () => {
    child.stdin.destroy();
    const timer = setTimeout(() => child.kill(), 2000); timer.unref?.();
    await exited; clearTimeout(timer);
  };
  try {
    await new Promise((resolve, reject) => {
      let out = "", err = "";
      const timer = setTimeout(() => reject(new Error("Shield bridge readiness timed out")), 10000);
      const finish = (e) => { clearTimeout(timer); e ? reject(e) : resolve(); };
      child.once("error", finish);
      child.stderr.on("data", b => { err = (err + b).slice(-1000); });
      child.stdout.on("data", b => { out = (out + b).slice(-1000); if (out.includes("shielded bridge ready")) finish(); });
      exited.then(() => finish(new Error("Shield bridge exited: " + err)));
    });
    return { exited, stop };
  } catch (e) { await stop(); throw e; }
}
export async function probeWorker(port = 19595) {
  const c = await shieldedCard({ port, budgetGb: CARD_BYTES / 2 ** 30 });
  if (c.vramBudgetGb !== CARD_BYTES / 2 ** 30) throw new Error("worker must enforce the profile's 12-GiB budget");
  return c;
}
// Both images use the same ownership/inventory. Selection is per request, never
// a mutation of the launcher's image pin during concurrent starts.
export class ProfileLauncher {
  constructor(cpu, gpu) { this.cpu=cpu; this.gpu=gpu; }
  get boundary() { return this.cpu.boundary; }
  get marker() { return this.cpu.marker; }
  get prefix() { return this.cpu.prefix; }
  preflight() { return this.cpu.preflight(); }
  survey() { return this.cpu.survey(); }
  teardown() { return this.cpu.teardown(); }
  start(mapping, opts) { return (mapping.record.inference ? this.gpu : this.cpu).start(mapping, opts); }
  stop(handle) { return this.cpu.stop(handle); }
}

/**
 * PER-SPAWN PINNED IMAGE SELECTION (F3; work/shield-image-selection-interface.txt). Up to three launchers, each pinned to
 * its own image, and ONE rule on what the manager itself verified:
 *   opts.bootstrap            -> the Shield-direct image (owner-committed packages only), or refused
 *   mapping.record.inference  -> the GPU image, or refused
 *   otherwise                 -> the legacy image: public, relay-secret V6/V7 and the readiness witness, as before
 * A missing package can only ever cause a refusal, and no image runs a spawn of the other kind (each launcher refuses it
 * again). Inventory is shared: one VM prefix and Notes marker, and stop is by VM id, so survey, teardown and stop go to the
 * legacy launcher. Preflight reports the direct image's own checks too (its 9446/9445 services), prefixed.
 */
export class ImageLauncher {
  constructor({ legacy, shieldDirect = null, gpu = null }) {
    if (!legacy) throw new Error("an image launcher needs the legacy launcher (the witness and every legacy spawn run there)");
    if (shieldDirect && shieldDirect.imageRole !== "shield-direct") throw new Error("the Shield-direct launcher must be pinned as imageRole shield-direct");
    if (legacy.imageRole && legacy.imageRole !== "legacy") throw new Error("the legacy launcher must be pinned as imageRole legacy");
    this.legacy = legacy; this.shieldDirect = shieldDirect; this.gpu = gpu;
  }
  get boundary() { return this.legacy.boundary; }
  get marker() { return this.legacy.marker; }
  get prefix() { return this.legacy.prefix; }
  async preflight() {
    const a = await this.legacy.preflight();
    if (!this.shieldDirect) return a;
    const b = await this.shieldDirect.preflight();
    const seen = new Set((a?.checks || []).map((c) => c.name));
    const extra = (b?.checks || []).filter((c) => !seen.has(c.name) || c.ok !== true).map((c) => ({ ...c, name: `shield-direct image: ${c.name}` }));
    return { ok: a?.ok === true && b?.ok === true, checks: [...(a?.checks || []), ...extra] };
  }
  survey() { return this.legacy.survey(); }
  teardown() { return this.legacy.teardown(); }
  /** Which image a spawn runs on: the same rule start() applies. */
  roleFor(mapping, opts = {}) { return opts.bootstrap ? "shield-direct" : mapping?.record?.inference ? "gpu" : "legacy"; }
  start(mapping, opts = {}) {
    const role = this.roleFor(mapping, opts);
    if (role === "shield-direct") {
      if (!this.shieldDirect) return Promise.reject(new Error("this manager has no Shield-direct image: an owner-committed package is refused, never started on another image"));
      if (mapping?.record?.inference) return Promise.reject(new Error("an owner-committed package does not start a GPU inference domain"));
      return this.shieldDirect.start(mapping, opts);
    }
    if (role === "gpu") {
      if (!this.gpu) return Promise.reject(new Error("this manager has no GPU image"));
      return this.gpu.start(mapping, opts);
    }
    return this.legacy.start(mapping, opts);
  }
  stop(handle) { return this.legacy.stop(handle); }
}
