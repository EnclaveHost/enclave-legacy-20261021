// Display catalog requirements, not hardware capacity multiplied by a share.
// Shares are allocation metadata and only accompany a running deployment.
const amount = (value) => Number.isFinite(Number(value)) ? Math.max(0, Number(value)) : 0;
const number = (value) => String(Number(value.toFixed(3)));
const memory = (mb) => mb >= 1024 ? number(mb / 1024) + " GB" : number(mb) + " MB";
const cpuText = (mb, gf) => memory(mb) + " RAM / " + number(gf) + " GFLOPs CPU";
const shareOf = (value) => value != null && Number.isFinite(Number(value)) && Number(value) >= 0 ? Number(value) : null;
export const shareLabel = (share) => share == null ? "—" : number(share * 100) + "%";
export const supportsCpuFallback = (spec) => !!(spec?.gpuOptional && (amount(spec.vramMb) > 0 || amount(spec.gpuGflops) > 0));

// a running deployment's allocation, one entry per pool it holds: [{ pool: "cpu"|"gpu", pct: "21%" }]
export function appShares(deployment){
  if (deployment?.status !== "running") return [];
  const r = deployment.resources || {}, parts = [];
  const cpu = shareOf(r.cpuShare ?? r.share), gpu = shareOf(r.gpuShare);
  if (cpu != null) parts.push({ pool: "cpu", pct: shareLabel(cpu) });
  if (gpu > 0) parts.push({ pool: "gpu", pct: shareLabel(gpu) });
  return parts;
}
export function appShareLabel(deployment){
  if (deployment?.status !== "running") return "";
  return appShares(deployment).map((s) => s.pct + " " + s.pool.toUpperCase()).join(" · ") || "Resources";
}

// RAM/CPU and VRAM/GPU each share one allocation pool. The chart uses those
// shares as its bar scale; unlike resource amounts, percentages are comparable.
export function appResourceRows(spec, deployment, mode = "current"){
  const r = deployment?.resources || {};
  const gpu = amount(spec?.vramMb) > 0 || amount(spec?.gpuGflops) > 0;
  const withoutGpu = gpu && spec?.gpuOptional && (mode === "fallback" || (!!deployment && shareOf(r.gpuShare) === 0));
  const running = deployment?.status === "running";
  const cpuShare = running ? shareOf(r.cpuShare ?? r.share) : null;
  const gpuShare = running ? shareOf(r.gpuShare) : null;
  const mem = Math.max(amount(spec?.memMb), withoutGpu ? amount(spec?.cpuFallback?.memMb) : 0);
  const cpu = Math.max(amount(spec?.cpuGflops), withoutGpu ? amount(spec?.cpuFallback?.cpuGflops) : 0);
  return [
    { key: "ram", name: "RAM", required: spec ? memory(mem) : "—", share: cpuShare, pool: "CPU / RAM" },
    { key: "cpu", name: "CPU compute", required: spec ? number(cpu) + " GFLOPs" : "—", share: cpuShare, pool: "CPU / RAM" },
    { key: "vram", name: "VRAM", required: spec ? memory(withoutGpu ? 0 : amount(spec.vramMb)) : "—", share: gpuShare, pool: "GPU / VRAM" },
    { key: "gpu", name: "GPU compute", required: spec ? number((withoutGpu ? 0 : amount(spec.gpuGflops)) / 1000) + " TFLOPs" : "—", share: gpuShare, pool: "GPU / VRAM" },
  ];
}

export function appResources(spec, deployment){
  if (!spec) return "Requirements unavailable";
  const r = deployment?.resources || {};
  const suffix = (share) => deployment?.status === "running" && share != null && Number.isFinite(Number(share))
    ? " (" + number(amount(share) * 100) + "%)" : "";
  const gpu = amount(spec.vramMb) > 0 || amount(spec.gpuGflops) > 0;
  const withoutGpu = !!deployment && gpu && spec.gpuOptional && shareOf(r.gpuShare) === 0;
  const mem = amount(spec.memMb), cpu = amount(spec.cpuGflops);
  const fallbackMem = Math.max(mem, amount(spec.cpuFallback?.memMb));
  const fallbackCpu = Math.max(cpu, amount(spec.cpuFallback?.cpuGflops));
  const parts = [];
  if (gpu && !withoutGpu) {
    parts.push(memory(amount(spec.vramMb)) + " VRAM / " + number(amount(spec.gpuGflops) / 1000) + " TFLOPs GPU"
      + (spec.gpuOptional && !deployment ? " (optional)" : "") + suffix(r.gpuShare));
  }
  parts.push(cpuText(withoutGpu ? fallbackMem : mem, withoutGpu ? fallbackCpu : cpu) + suffix(r.cpuShare ?? r.share));
  if (!deployment && gpu && spec.gpuOptional && (fallbackMem > mem || fallbackCpu > cpu)) {
    parts.push("without GPU: " + cpuText(fallbackMem, fallbackCpu));
  }
  return parts.join(" · ");
}
