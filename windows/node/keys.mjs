// windows/node/keys.mjs -- the two chain keys a hosting node needs, generated ON the box.
//   node keys.mjs [dir] [--offline]    print the addresses, creating either key if it is missing
// operator.key signs register / heartbeat / claim / renew / release and the tunnel attach; it needs
// a few dollars of Base ETH for gas and controls nothing else (earnings go to the payout wallet).
// proof.key signs EnclaveProofOfTime checkpoints. On a fleet enclave that key is minted inside the
// CVM so the operator cannot forge "it was running"; here it sits beside the operator key on a
// machine its owner controls, which is worth saying out loud rather than implying otherwise.
//
// The endpoint is PUBLIC_URL, or the legacy relay route for NODE_NAME; with neither, no registry entry is looked up.
// --offline (install-host.ps1 -NameCheck offline) and an unreachable chain both still make and print the keys: the
// chain half of the answer is then "unknown", never a failed install.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";   // decodes %20: the installed path is C:\Program Files\Enclave
import * as chain from "./chain.mjs";

const argv = process.argv.slice(2);
const offline = argv.includes("--offline");
const dir = argv.find((a) => !a.startsWith("--")) || path.dirname(fileURLToPath(import.meta.url));
const opFile = path.join(dir, "operator.key"), pkFile = path.join(dir, "proof.key");
const madeOp = !fs.existsSync(opFile), madePk = !fs.existsSync(pkFile);
if (madeOp) chain.newOperatorKey(opFile);
if (madePk) chain.newProofKey(pkFile);
const op = chain.loadOperator(opFile), pk = chain.loadProofKey(pkFile);
const endpoint = process.env.PUBLIC_URL || (process.env.NODE_NAME ? `https://api.enclave.host/t/${process.env.NODE_NAME}` : null);
const id = endpoint ? chain.enclaveIdOf(endpoint) : null;
let e = null, bal = null, chainError = offline ? "not read (--offline)" : null;
if (!offline) {
  try {
    await chain.resolveAddresses();
    e = id ? await chain.readEnclave(id).catch(() => null) : null;
    bal = await chain.operatorBalance();
  } catch (err) { chainError = err.shortMessage || err.message; }
}
console.log(JSON.stringify({
  dir, operator: op.address, operatorCreated: madeOp, proofKey: pk.address, proofKeyCreated: madePk,
  operatorEth: bal === null ? null : (Number(bal) / 1e18).toFixed(6), enclaveId: id, endpoint,
  registered: e ? !!e.endpoint : null, registeredOperator: e && e.endpoint ? e.operator : null,
  ...(chainError ? { chain: `unknown: ${chainError}` } : {}),
  needs: bal === null ? "unknown: the chain was not read" : bal === 0n ? "gas: send a few dollars of Base ETH to the operator address, then the node registers itself" : "nothing: it can register and claim",
}, null, 1));
