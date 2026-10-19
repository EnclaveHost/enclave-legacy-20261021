// PID 1's hand-off in the CUSTODIAN image (replaces the metal image's /opt/metal/gsup.mjs; scripts/build-custodian-v2.mjs).
// Runs the measured process plan and keeps it alive:
//   - the custodian (/opt/custodian/custodian.mjs, custody/v2/daemon.mjs) on :8787;
//   - only in explicit tunnel images, the fleet-tunnel agent, which attaches to the relay by this
//     guest's SEV-SNP quote and forwards https://api.enclave.host/t/<name>/... to the custodian.
// Its inputs are fw_cfg's opt/org.enclave.custody JSON (unmeasured: name, public URL, VCEK), never the custodian's keys.
import fs from "node:fs";
import { spawn } from "node:child_process";
import { MEASURED } from './measured.mjs';
import { custodianProcessPlan } from './process-plan.mjs';

const FW = "/sys/firmware/qemu_fw_cfg/by_name/opt/org.enclave.custody/raw";
const log = (m) => { try { fs.writeFileSync("/dev/console", `[custodian-gsup] ${m}\n`); } catch { console.log(m); } };
let cfg = {};
try { cfg = JSON.parse(fs.readFileSync(FW, "utf8")); } catch (e) { log(`no host config (${e.message}); the custodian will refuse to start`); }
const PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

function keep(name, args, env) {
  let restarts = 0;
  const run = () => {
    const c = spawn("/usr/local/bin/node", args, { env: { PATH, NODE_EXTRA_CA_CERTS: "/etc/ssl/certs/ca-certificates.crt", ...env }, stdio: ["ignore", "inherit", "inherit"] });
    c.on("exit", (code, sig) => { restarts++; const d = Math.min(2000 * restarts, 30000); log(`${name} exited code=${code} sig=${sig}; restart in ${d} ms`); setTimeout(run, d); });
  };
  run();
}
for(const p of custodianProcessPlan(cfg,MEASURED.transport))keep(p.name,p.args,p.env);
log(`custodian transport ${MEASURED.transport} started`);
