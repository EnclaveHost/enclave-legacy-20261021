#!/usr/bin/env node
// scripts/network/shield-verifier.mjs -- run an independent Enclave Shield market verifier (relay/shield-independent-verifier.mjs)
// that Windows hosts' operators may choose to pin (windows/node/shield-verdict.mjs, docs/network/independent-windows.md).
//
//   pubkey --key verifier.pem
//          prints {"key":"ed25519:<SPKI>","keyId":"<sha256>"}: what a host operator puts in its verifier set
//   serve  --key verifier.pem --policy shield-policy.json --pins contract-pins.json --rpc A --rpc B [--rpc C]
//          [--listen 127.0.0.1:8790]
//          answers POST /v1/shield-verifier/{challenge,attest}. Put your own TLS in front (hosts accept https only, or
//          loopback http). The policy is yours: enclave-shield-app-policy/1 with marketEnabled, the pinned TPM roots,
//          admitted images and platforms, and the readiness witness - exactly the relay's market policy. A host's identity
//          is read from the PINNED registry through RPCs that must agree at one confirmed block.
//
// This script never creates a key. Make one yourself and keep it: openssl genpkey -algorithm ed25519 -out verifier.pem
import fs from "node:fs";
import http from "node:http";
import { createPrivateKey } from "node:crypto";
import { recoverMessageAddress } from "viem";
import { createIndependentShieldVerifier } from "../../relay/shield-independent-verifier.mjs";
import { keySpecOf, keyIdOf } from "../../windows/node/shield-verdict.mjs";
import { quorumReader, rpcClients } from "../../windows/node/host-identity.mjs";
import { validateContractPins } from "../../network/contract-pins.mjs";

const REGISTRY_GET = [{ type: "function", name: "get", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ type: "tuple", components:
  [["endpoint", "string"], ["repo", "string"], ["measurement", "bytes32"], ["operator", "address"], ["registeredAt", "uint64"], ["lastSeen", "uint64"],
   ["active", "bool"], ["cpuPricePerSec6", "uint64"], ["gpuPricePerSec6", "uint64"], ["proofKey", "address"], ["payoutWallet", "address"]].map(([name, type]) => ({ name, type })) }] }];

function args(argv) {
  const o = { rpc: [] };
  for (let i = 0; i < argv.length; i++) { const k = argv[i].replace(/^--/, ""), v = argv[++i]; if (k === "rpc") o.rpc.push(v); else o[k] = v; }
  return o;
}
async function main([cmd, ...rest]) {
  const o = args(rest);
  if (!o.key) throw new Error("--key <ed25519 private key PEM> is required");
  const signingKey = createPrivateKey(fs.readFileSync(o.key));
  if (signingKey.asymmetricKeyType !== "ed25519") throw new Error("the verifier key must be Ed25519");
  if (cmd === "pubkey") { const key = keySpecOf(signingKey); process.stdout.write(JSON.stringify({ key, keyId: keyIdOf(key) }) + "\n"); return; }
  if (cmd !== "serve") throw new Error("commands: pubkey --key K | serve --key K --policy P --pins PINS --rpc A --rpc B [--listen host:port]");
  for (const k of ["policy", "pins"]) if (!o[k]) throw new Error(`--${k} is required`);
  const policy = JSON.parse(fs.readFileSync(o.policy, "utf8"));
  const pins = validateContractPins(JSON.parse(fs.readFileSync(o.pins, "utf8").replace(/^﻿/, "")));
  const reader = quorumReader({ clients: await rpcClients(o.rpc) });
  const registryEntry = (hostId) => reader.agreed((c, blockNumber) => c.readContract({ address: pins.registry, abi: REGISTRY_GET, functionName: "get", args: [hostId], blockNumber })
    .then((x) => ({ endpoint: x.endpoint, operator: String(x.operator).toLowerCase(), active: !!x.active })));
  const v = createIndependentShieldVerifier({ policy, signingKey, registryEntry, recoverSigner: (message, signature) => recoverMessageAddress({ message, signature }),
    log: (m) => console.log(new Date().toISOString(), m) });
  const [host, port] = String(o.listen || "127.0.0.1:8790").split(/:(?=\d+$)/);
  http.createServer((req, res) => v.handle(req, res)).listen(Number(port), host, () =>
    console.log(`shield verifier ${v.keyId.slice(0, 16)}… (${v.key}) on http://${host}:${port}; registry ${pins.registry} through ${o.rpc.length} RPCs`));
}
main(process.argv.slice(2)).catch((e) => { process.stderr.write(`shield-verifier: ${e.shortMessage || e.message}\n`); process.exit(1); });
