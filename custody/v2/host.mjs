#!/usr/bin/env node
// The HOST side of a custody v2 custodian (docs/security/secret-custody-v2.md §8): OUTSIDE the TEE, untrusted for
// secrecy. It
//   - launches the custodian image as an SEV-SNP guest (kernel-hashes=on: kernel + initramfs + cmdline measured);
//   - keeps the guest's SEALED state (ciphertext only; it opens solely inside that guest on this chip): GET/PUT /state;
//   - submits the transactions the guest SIGNS (POST /submit), paying the gas; it can drop them, never forge them;
//   - binds the guest to this host's registry entry: signs hostDigest(machine) with the host's registry operator key.
//
//   node custody/v2/host.mjs <config.json>
// config: { dist, ovmf, sevDevice, qemu?, cpus, memMiB, tunnelName, endpoint, registryEndpoint, hostPort, mgmtPort, stateDir,
//           committeeId?, genesis?, vcekFile?, relayUrl?, vault, rpc, registryKeyFile (JSON with registryKey), submitterKeyEnv }
// New images include a transport + accepted-owner pin in their manifest. Direct
// ingress forwards only public API routes to mgmtPort; hostPort stays private.
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import { spawn } from "node:child_process";
import { createPublicClient, createWalletClient, http as viemHttp, keccak256, toBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";
import { VAULT_V2_ABI, createChainReaderV2 } from "./chain.mjs";
import { prepareHostBinding } from './host-binding.mjs';
import { MEASURED } from './measured.mjs';

const cfg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const manifest=JSON.parse(fs.readFileSync(path.join(cfg.dist,'manifest.json'),'utf8'));
if(manifest.role!=='enclave-custodian-v2'||String(manifest.vault).toLowerCase()!==String(cfg.vault).toLowerCase()||
   !/^0x[0-9a-f]{40}$/i.test(manifest.hostOwnership||'')||/^0x0{40}$/i.test(manifest.hostOwnership)||
   !['direct','tunnel'].includes(manifest.transport))throw Error('compatible measured custody manifest required');
const bindingRpcs=cfg.rpcs||MEASURED.rpcs;
const bindingChain=createChainReaderV2({rpcs:bindingRpcs,vault:cfg.vault,hostOwnership:manifest.hostOwnership,
  chainId:8453,minAgree:Math.floor(bindingRpcs.length/2)+1,confirmations:2});
const log = (...a) => console.log(new Date().toISOString(), "[custodian-host]", ...a);
const STATE = path.join(cfg.stateDir, "state.bin");
fs.mkdirSync(cfg.stateDir, { recursive: true, mode: 0o700 });
const registryId = keccak256(toBytes(cfg.registryEndpoint));
const pub = createPublicClient({ chain: base, transport: viemHttp(cfg.rpc || "https://mainnet.base.org") });
const submitter = process.env[cfg.submitterKeyEnv || "CUSTODY_SUBMITTER_KEY"] ? privateKeyToAccount(process.env[cfg.submitterKeyEnv || "CUSTODY_SUBMITTER_KEY"]) : null;
const wallet = submitter ? createWalletClient({ chain: base, account: submitter, transport: viemHttp(cfg.rpc || "https://mainnet.base.org") }) : null;
const ALLOWED = new Set(["createCommittee", "createIndependentCommittee", "proposeHandover", "postDeal", "ackHandover", "proposeCode", "removeCode"]);

// ---- fw_cfg for the guest (unmeasured) ----
const fwPath = path.join(cfg.stateDir, "fwcfg.json");
fs.writeFileSync(fwPath, JSON.stringify({
  endpoint: cfg.endpoint, tunnelName: cfg.tunnelName, registryId, hostUrl: `http://10.0.2.2:${cfg.hostPort}`, port: 8787,
  committeeId: cfg.committeeId || null, genesis: cfg.genesis === true,
  ...(manifest.transport==='tunnel'?{relayUrl:cfg.relayUrl||'wss://api.enclave.host/v1/fleet-tunnel'}:{}),
  vcek: cfg.vcekFile ? fs.readFileSync(cfg.vcekFile).toString("base64") : null }), { mode: 0o600 });

// ---- state store + submitter (loopback; the guest reaches it as 10.0.2.2) ----
const srv = http.createServer(async (req, res) => {
  const send = (code, body, type = "application/json") => { res.writeHead(code, { "content-type": type }); res.end(typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body)); };
  try {
    if (req.url === "/state" && req.method === "GET") return fs.existsSync(STATE) ? send(200, fs.readFileSync(STATE), "application/octet-stream") : send(404, { error: "none" });
    // the capacity witness's receipts for this host (availability/witness.mjs), passed through: the guest's peers verify them
    if (req.url === "/receipts" && req.method === "GET") {
      let all = []; try { all = cfg.receiptsFile ? JSON.parse(fs.readFileSync(cfg.receiptsFile, "utf8")) : []; } catch {}
      const mine = keccak256(toBytes(cfg.registryEndpoint)).toLowerCase();
      return send(200, all.filter((e) => String(e?.payload?.hostId || "").toLowerCase() === mine).slice(0, 8));
    }
    const chunks = []; for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks);
    if (req.url === "/state" && req.method === "PUT") {
      if (body.length < 28 || body.length > 4 << 20) return send(400, { error: "bad state" });
      if (fs.existsSync(STATE)) fs.copyFileSync(STATE, `${STATE}.${Date.now()}`);   // keep history; prune below
      const tmp = `${STATE}.tmp`;
      const fd=fs.openSync(tmp,'w',0o600);
      try{fs.writeFileSync(fd,body);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
      fs.renameSync(tmp, STATE);
      const dir=fs.openSync(cfg.stateDir,'r');try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}
      const old = fs.readdirSync(cfg.stateDir).filter((f) => /^state\.bin\.\d+$/.test(f)).sort();
      for (const f of old.slice(0, Math.max(0, old.length - 20))) fs.unlinkSync(path.join(cfg.stateDir, f));
      return send(200, { ok: true });
    }
    if (req.url === "/submit" && req.method === "POST") {
      const { fn, args } = JSON.parse(body.toString("utf8"));
      if (!ALLOWED.has(fn)) return send(400, { error: `not a custodian transaction: ${fn}` });
      if (!wallet) return send(503, { error: "no submitter key configured" });
      const hash = await wallet.writeContract({ address: cfg.vault, abi: VAULT_V2_ABI, functionName: fn, args });
      const r = await pub.waitForTransactionReceipt({ hash, timeout: 120_000 });
      log(`submitted ${fn}: ${hash} ${r.status}`);
      if (r.status !== "success") return send(500, { error: `reverted: ${hash}` });
      return send(200, { tx: hash });
    }
    send(404, { error: "not found" });
  } catch (e) { log(`host api: ${e.shortMessage || e.message}`); send(500, { error: String(e.shortMessage || e.message).slice(0, 300) }); }
});
srv.listen(cfg.hostPort, "127.0.0.1", () => log(`state/submit on 127.0.0.1:${cfg.hostPort}`));

// ---- the host binding: this host's registry operator signs the guest's machine record ----
async function bindLoop() {
  const reg = JSON.parse(fs.readFileSync(cfg.registryKeyFile, "utf8"));
  const op = privateKeyToAccount(reg.registryKey.startsWith("0x") ? reg.registryKey : "0x" + reg.registryKey);
  for (;;) {
    try {
      const response=await fetch(`http://127.0.0.1:${cfg.mgmtPort}/v2/custody/info`,{signal:AbortSignal.timeout(10000)});
      if(!response.ok)throw Error(`guest info HTTP ${response.status}`);
      const i=await response.json();
      const binding=await prepareHostBinding({chain:bindingChain,operator:op,chainId:8453,vault:cfg.vault,registryId,
        registryEndpoint:cfg.registryEndpoint,endpoint:cfg.endpoint,info:i});
      if(binding.alreadyBound){log(`guest ${i.identity} bound (${i.epochs?.length||0} epoch(s) held)`);return;}
      const r = await fetch(`http://127.0.0.1:${cfg.mgmtPort}/v2/custody/host-binding`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ sig:binding.signature }),signal:AbortSignal.timeout(10000) });
      log(`host binding for ${i.identity}: HTTP ${r.status}`);
      if (r.ok) return;
    } catch (err) { log(`waiting for the guest: ${err.message}`); }
    await new Promise((r) => setTimeout(r, 10_000));
  }
}

// ---- the SEV-SNP guest ----
const dist = cfg.dist;
const cmdline = fs.readFileSync(path.join(dist, "cmdline"), "utf8").trim();
const args = [
  "-machine", "q35,accel=kvm,confidential-guest-support=cx0,memory-backend=ram0", "-cpu", "host", "-smp", String(cfg.cpus || 2), "-m", String(cfg.memMiB || 3072),
  "-nographic", "-no-reboot", "-kernel", path.join(dist, "vmlinuz"), "-initrd", path.join(dist, "initramfs.cpio.gz"), "-append", cmdline,
  "-fw_cfg", `name=opt/org.enclave.custody,file=${fwPath}`,
  "-netdev", `user,id=net0,hostfwd=tcp:127.0.0.1:${cfg.mgmtPort}-:8787`,
  "-device", "virtio-net-pci,netdev=net0,csum=off,gso=off,guest_csum=off,host_tso4=off,host_tso6=off,guest_tso4=off,guest_tso6=off,guest_ecn=off,host_ufo=off,guest_ufo=off",
  "-serial", "mon:stdio",
  "-object", `memory-backend-memfd,id=ram0,size=${cfg.memMiB || 3072}M,share=true,prealloc=false`, "-bios", cfg.ovmf,
  "-object", `sev-snp-guest,id=cx0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on,sev-device=${cfg.sevDevice || "/dev/sev"}`,
];
let child = null, stopping = false, restarts = 0;
function launch() {
  log(`launching ${manifest.transport} custodian for ${cfg.endpoint} from ${dist}`);
  child = spawn(cfg.qemu || "qemu-system-x86_64", args, { stdio: ["ignore", "inherit", "inherit"] });
  child.on("exit", (code, sig) => { if (stopping) return; restarts++; const d = Math.min(5000 * restarts, 60000); log(`guest exited ${code}/${sig}; relaunch in ${d} ms`); setTimeout(launch, d); });
  setTimeout(() => bindLoop().catch((e) => log(`bind: ${e.message}`)), 20_000);
}
for (const s of ["SIGTERM", "SIGINT"]) process.on(s, () => { stopping = true; if (child) child.kill("SIGTERM"); setTimeout(() => process.exit(0), 3000); });
launch();
