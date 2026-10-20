// src/constants.ts
var ACTIONS = {
  "deploy.create": 0,
  "deploy.fund": 1,
  "deploy.setAppRef": 2,
  "deploy.setConfig": 3,
  "deploy.setShares": 4,
  "deploy.setMaxRate": 5,
  "deploy.setActive": 6,
  "deploy.refund": 7,
  "app.publish": 8,
  // 9 was order.pay: dropped before launch (an orderRef binds no payer)
  "api.status": 128,
  "api.logs": 129,
  "api.restart": 130,
  "api.upload": 131,
  "api.appAccess": 132,
  "api.placement": 133,
  "api.account": 134
};
var ENVIRONMENTS = { staging: 1, prod: 2 };
var ACTION_TEXT = {
  "deploy.create": "create deployments",
  "deploy.fund": "add runtime to your deployments (spends the session budget)",
  "deploy.setAppRef": "change which version a STAGING deployment runs",
  "deploy.setConfig": "change a STAGING deployment's options",
  "deploy.setShares": "resize deployments",
  "deploy.setMaxRate": "change deployments' price ceilings",
  "deploy.setActive": "suspend and resume deployments",
  "deploy.refund": "cancel deployments (unused runtime returns to your vault, or to your wallet for the ones it holds)",
  "app.publish": "publish new versions of the named apps",
  "api.status": "read deployment status",
  "api.logs": "read deployment logs",
  "api.restart": "restart deployments",
  "api.upload": "upload app bundles and configs",
  "api.appAccess": "open private apps in the browser",
  "api.placement": "choose which host serves a deployment",
  "api.account": "sign in to your Enclave account and apps (Sign in with Enclave) as you"
};
var NETWORKS = {
  base: {
    chainId: 8453,
    name: "Base",
    usdc: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    book: "0xab214342d5A490150A4A977063A2f88E21F80907",
    relay: "https://api.enclave.host",
    rpc: "https://base-rpc.publicnode.com"
  },
  "base-sepolia": {
    chainId: 84532,
    name: "Base Sepolia",
    usdc: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    relay: "https://api.enclave.host",
    rpc: "https://base-sepolia-rpc.publicnode.com"
  }
};
var BOOK_KEY_FACTORY = "sessionVaultFactory";
var ZERO_HASH = "0x0000000000000000000000000000000000000000000000000000000000000000";

// src/typed.ts
import { encodeAbiParameters, hashTypedData, keccak256 } from "viem";
var DOMAIN_NAME = "Enclave Sessions";
var DOMAIN_VERSION = "1";
var TYPES = {
  SessionGrant: [
    { name: "label", type: "string" },
    { name: "preset", type: "string" },
    { name: "sessionKey", type: "bytes32" },
    { name: "actions", type: "string[]" },
    { name: "apps", type: "string[]" },
    { name: "environments", type: "string[]" },
    { name: "budget", type: "uint256" },
    { name: "spendPerPeriod", type: "uint256" },
    { name: "periodSeconds", type: "uint32" },
    { name: "opsPerPeriod", type: "uint32" },
    { name: "maxFeePerOp", type: "uint256" },
    { name: "maxAppFeePerHour", type: "uint256" },
    { name: "maxRatePerHour", type: "uint256" },
    { name: "expiresAt", type: "uint64" },
    { name: "measurement", type: "bytes32" },
    { name: "grantNonce", type: "bytes32" },
    { name: "signBefore", type: "uint64" }
  ],
  SessionCall: [
    { name: "sessionId", type: "bytes32" },
    { name: "nonce", type: "uint256" },
    { name: "action", type: "uint8" },
    { name: "argsHash", type: "bytes32" },
    { name: "fee", type: "uint256" },
    { name: "deadline", type: "uint64" }
  ],
  SessionEnd: [
    { name: "sessionId", type: "bytes32" },
    { name: "deadline", type: "uint64" }
  ],
  TopUp: [
    { name: "sessionId", type: "bytes32" },
    { name: "amount", type: "uint256" },
    { name: "opNonce", type: "bytes32" },
    { name: "signBefore", type: "uint64" }
  ],
  Extend: [
    { name: "sessionId", type: "bytes32" },
    { name: "expiresAt", type: "uint64" },
    { name: "opNonce", type: "bytes32" },
    { name: "signBefore", type: "uint64" }
  ],
  Terminate: [
    { name: "sessionId", type: "bytes32" },
    { name: "opNonce", type: "bytes32" },
    { name: "signBefore", type: "uint64" }
  ],
  RevokeAll: [
    { name: "withdraw", type: "bool" },
    { name: "opNonce", type: "bytes32" },
    { name: "signBefore", type: "uint64" }
  ],
  Withdraw: [
    { name: "amount", type: "uint256" },
    { name: "opNonce", type: "bytes32" },
    { name: "signBefore", type: "uint64" }
  ],
  Promote: [
    { name: "deployment", type: "bytes32" },
    { name: "app", type: "string" },
    { name: "publisher", type: "address" },
    { name: "appRef", type: "string" },
    { name: "configCid", type: "string" },
    { name: "versionLabel", type: "string" },
    { name: "isPublic", type: "bool" },
    { name: "opNonce", type: "bytes32" },
    { name: "signBefore", type: "uint64" }
  ],
  Adopt: [
    { name: "deployment", type: "bytes32" },
    { name: "environment", type: "string" },
    { name: "opNonce", type: "bytes32" },
    { name: "signBefore", type: "uint64" }
  ],
  SetEnvironment: [
    { name: "deployment", type: "bytes32" },
    { name: "environment", type: "string" },
    { name: "opNonce", type: "bytes32" },
    { name: "signBefore", type: "uint64" }
  ],
  Release: [
    { name: "deployment", type: "bytes32" },
    { name: "to", type: "address" },
    { name: "opNonce", type: "bytes32" },
    { name: "signBefore", type: "uint64" }
  ]
};
function domain(chainId, vault) {
  return { name: DOMAIN_NAME, version: DOMAIN_VERSION, chainId, verifyingContract: vault };
}
function typedData(chainId, vault, primaryType, message) {
  return {
    domain: domain(chainId, vault),
    types: { [primaryType]: TYPES[primaryType] },
    primaryType,
    message
  };
}
function grantTypedData(chainId, vault, g) {
  return typedData(chainId, vault, "SessionGrant", g);
}
function digestOf(chainId, vault, primaryType, message) {
  return hashTypedData(typedData(chainId, vault, primaryType, message));
}
function grantDigest(chainId, vault, g) {
  return digestOf(chainId, vault, "SessionGrant", g);
}
function sessionIdOf(vault, sessionKey, grantNonce) {
  return keccak256(encodeAbiParameters(
    [{ type: "address" }, { type: "bytes32" }, { type: "bytes32" }],
    [vault, sessionKey, grantNonce]
  ));
}
function keyHashOf(x, y) {
  return keccak256(encodeAbiParameters([{ type: "uint256" }, { type: "uint256" }], [x, y]));
}
function checkCode(keyHash) {
  const h = keyHash.slice(2, 10).toUpperCase();
  return `${h.slice(0, 4)}-${h.slice(4, 8)}`;
}

// src/args.ts
import { decodeAbiParameters, encodeAbiParameters as encodeAbiParameters2 } from "viem";
var CREATE = [{
  type: "tuple",
  components: [
    { name: "appRef", type: "string" },
    { name: "gpuMilli", type: "uint16" },
    { name: "cpuMilli", type: "uint16" },
    { name: "appPort", type: "uint32" },
    { name: "ports", type: "string" },
    { name: "isPublic", type: "bool" },
    { name: "configCid", type: "string" },
    { name: "maxRate6", type: "uint256" },
    { name: "env", type: "uint8" },
    { name: "fund6", type: "uint256" }
  ]
}];
var PUBLISH = [{
  type: "tuple",
  components: [
    { name: "slug", type: "string" },
    { name: "name", type: "string" },
    { name: "description", type: "string" },
    { name: "version", type: "string" },
    { name: "cid", type: "string" },
    { name: "res", type: "uint32[4]" },
    { name: "ports", type: "string" },
    { name: "config", type: "string" },
    { name: "configCid", type: "string" }
  ]
}];
var B32 = { type: "bytes32" };
function encodeArgs(action, a) {
  const v = a;
  switch (action) {
    case "deploy.create": {
      const c = a;
      return encodeAbiParameters2(CREATE, [{ ...c, env: ENVIRONMENTS[c.env] }]);
    }
    case "deploy.fund":
      return encodeAbiParameters2([B32, { type: "uint256" }], [v.id, v.amount6]);
    case "deploy.setAppRef":
      return encodeAbiParameters2([B32, { type: "string" }], [v.id, v.appRef]);
    case "deploy.setConfig":
      return encodeAbiParameters2([B32, { type: "string" }], [v.id, v.configCid]);
    case "deploy.setShares":
      return encodeAbiParameters2([B32, { type: "uint16" }, { type: "uint16" }], [v.id, v.gpuMilli, v.cpuMilli]);
    case "deploy.setMaxRate":
      return encodeAbiParameters2([B32, { type: "uint256" }], [v.id, v.maxRate6]);
    case "deploy.setActive":
      return encodeAbiParameters2([B32, { type: "bool" }], [v.id, v.active]);
    case "deploy.refund":
      return encodeAbiParameters2([B32], [v.id]);
    case "app.publish":
      return encodeAbiParameters2(PUBLISH, [a]);
  }
  throw new Error(`unknown action ${String(action)}`);
}
function amountOf(action, a) {
  if (action === "deploy.create") return a.fund6;
  if (action === "deploy.fund") return a.amount6;
  return 0n;
}
function decodeArgs(action, data) {
  switch (action) {
    case "deploy.create": {
      const [c] = decodeAbiParameters(CREATE, data);
      const env = Object.keys(ENVIRONMENTS).find((k) => ENVIRONMENTS[k] === c.env);
      return { ...c, env };
    }
    case "deploy.fund": {
      const [id, amount6] = decodeAbiParameters([B32, { type: "uint256" }], data);
      return { id, amount6 };
    }
    case "deploy.setAppRef": {
      const [id, appRef] = decodeAbiParameters([B32, { type: "string" }], data);
      return { id, appRef };
    }
    case "deploy.setConfig": {
      const [id, configCid] = decodeAbiParameters([B32, { type: "string" }], data);
      return { id, configCid };
    }
    case "deploy.setShares": {
      const [id, gpuMilli, cpuMilli] = decodeAbiParameters([B32, { type: "uint16" }, { type: "uint16" }], data);
      return { id, gpuMilli, cpuMilli };
    }
    case "deploy.setMaxRate": {
      const [id, maxRate6] = decodeAbiParameters([B32, { type: "uint256" }], data);
      return { id, maxRate6 };
    }
    case "deploy.setActive": {
      const [id, active] = decodeAbiParameters([B32, { type: "bool" }], data);
      return { id, active };
    }
    case "deploy.refund": {
      const [id] = decodeAbiParameters([B32], data);
      return { id };
    }
    case "app.publish": {
      const [p] = decodeAbiParameters(PUBLISH, data);
      return { ...p };
    }
  }
}
var actionIndex = (a) => ACTIONS[a];
var actionByIndex = (i) => Object.keys(ACTIONS).find((k) => ACTIONS[k] === i && i < 128);

// src/keys.ts
import { bytesToHex, hexToBytes, sha256 } from "viem";
var ALG = { name: "ECDSA", namedCurve: "P-256" };
var SIGN = { name: "ECDSA", hash: "SHA-256" };
function subtle() {
  const c = globalThis.crypto;
  if (!c?.subtle) throw new Error("WebCrypto is not available (needs a browser or Node 20+)");
  return c.subtle;
}
async function generateKeyPair(extractable) {
  return subtle().generateKey(ALG, extractable, ["sign", "verify"]);
}
async function publicKeyXY(publicKey) {
  const raw = new Uint8Array(await subtle().exportKey("raw", publicKey));
  if (raw.length !== 65 || raw[0] !== 4) throw new Error("unexpected P-256 public key encoding");
  return { x: BigInt(bytesToHex(raw.slice(1, 33))), y: BigInt(bytesToHex(raw.slice(33, 65))) };
}
async function signerFromKeys(privateKey, x, y) {
  const keyHash = keyHashOf(x, y);
  const signBytes = async (message) => new Uint8Array(await subtle().sign(SIGN, privateKey, message));
  return {
    x,
    y,
    keyHash,
    signBytes,
    async signDigest(digest) {
      const sig = await signBytes(hexToBytes(digest));
      return { r: bytesToHex(sig.slice(0, 32)), s: bytesToHex(sig.slice(32, 64)) };
    }
  };
}
async function signerFromKeyPair(kp) {
  const { x, y } = await publicKeyXY(kp.publicKey);
  return signerFromKeys(kp.privateKey, x, y);
}
var b64u = (b) => {
  let s = "";
  for (const c of b) s += String.fromCharCode(c);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
var unb64u = (s) => {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};
async function exportPrivateKey(privateKey) {
  return b64u(new Uint8Array(await subtle().exportKey("pkcs8", privateKey)));
}
async function importPrivateKey(pkcs8) {
  return subtle().importKey("pkcs8", unb64u(pkcs8), ALG, false, ["sign"]);
}
function sha256Hex(data) {
  return sha256(typeof data === "string" ? new TextEncoder().encode(data) : data);
}

// src/grant.ts
import { bytesToHex as bytesToHex2 } from "viem";
var HOUR = 3600;
var DAY = 86400;
var USD = 1000000n;
var PRESETS = {
  /** Browser sign-in: normal platform use. Zero budget by default; top up on demand. */
  browser: {
    description: "Sign-in on this browser: deploy, manage and fund your deployments without a wallet prompt each time.",
    // publishing stays a wallet action in the browser: a browser user's apps are
    // wallet-published, and app.publish only ever reaches apps the VAULT holds
    actions: [
      "deploy.create",
      "deploy.fund",
      "deploy.setAppRef",
      "deploy.setConfig",
      "deploy.setShares",
      "deploy.setMaxRate",
      "deploy.setActive",
      "deploy.refund",
      "api.status",
      "api.logs",
      "api.restart",
      "api.upload",
      "api.appAccess",
      "api.placement",
      "api.account"
    ],
    apps: ["*"],
    environments: ["staging", "prod"],
    budget: 0n,
    spendPerPeriod: 100n * USD,
    // a daily ceiling that survives top-ups
    periodSeconds: DAY,
    opsPerPeriod: 0,
    maxFeePerOp: USD / 4n,
    // $0.25 ceiling; Base fees are ~1-2 cents per op
    maxAppFeePerHour: USD,
    // $1/h publisher fee ceiling for new deployments (named apps only)
    maxRatePerHour: 10n * USD,
    // $10/h ceiling on any deployment rate cap (a full GPU node is ~$6/h)
    expiresIn: 12 * HOUR,
    maxExpiresIn: 30 * DAY
  },
  /** An agent publishing to staging: named apps only, small budget, a week. */
  "staging-publish": {
    description: "An agent publishing STAGING versions of the named apps and running them on staging deployments.",
    actions: [
      "app.publish",
      "deploy.create",
      "deploy.fund",
      "deploy.setAppRef",
      "deploy.setConfig",
      "deploy.setActive",
      "api.status",
      "api.logs",
      "api.restart",
      "api.upload"
    ],
    apps: [],
    environments: ["staging"],
    budget: 10n * USD,
    spendPerPeriod: 5n * USD,
    periodSeconds: DAY,
    opsPerPeriod: 120,
    maxFeePerOp: USD / 10n,
    // $0.10 ceiling; the daily cap bounds the total
    maxAppFeePerHour: 0n,
    maxRatePerHour: 5n * USD,
    // a whole CPU node is ~$3/h; staging rarely needs a GPU
    expiresIn: 7 * DAY,
    maxExpiresIn: 28 * DAY
  },
  /** Authentication only: read status, nothing on-chain, no money. */
  "auth-only": {
    description: "Read deployment status only. No money, nothing on-chain.",
    actions: ["api.status"],
    apps: [],
    environments: [],
    budget: 0n,
    spendPerPeriod: 0n,
    periodSeconds: DAY,
    opsPerPeriod: 0,
    maxFeePerOp: 0n,
    maxAppFeePerHour: 0n,
    maxRatePerHour: 0n,
    expiresIn: 12 * HOUR,
    maxExpiresIn: 7 * DAY
  }
};
function randomHex32() {
  const b = new Uint8Array(32);
  globalThis.crypto.getRandomValues(b);
  return bytesToHex2(b);
}
function buildGrant(input) {
  const presetName = input.preset ?? "custom";
  const base = PRESETS[presetName];
  if (!base && !input.policy) throw new Error(`unknown preset "${presetName}"`);
  const p = { ...base ?? PRESETS["auth-only"], ...input.policy ?? {} };
  if (base && p.expiresIn > base.maxExpiresIn) throw new Error(`"${presetName}" sessions last at most ${base.maxExpiresIn / DAY} days`);
  validatePolicy(p);
  const now = input.now ?? Math.floor(Date.now() / 1e3);
  return {
    label: input.label,
    preset: presetName,
    sessionKey: input.sessionKey,
    actions: [...p.actions],
    apps: [...p.apps],
    environments: [...p.environments],
    budget: p.budget,
    spendPerPeriod: p.spendPerPeriod,
    periodSeconds: p.periodSeconds,
    opsPerPeriod: p.opsPerPeriod,
    maxFeePerOp: p.maxFeePerOp,
    maxAppFeePerHour: p.maxAppFeePerHour,
    maxRatePerHour: p.maxRatePerHour ?? 0n,
    expiresAt: BigInt(now + p.expiresIn),
    measurement: p.measurement ?? ZERO_HASH,
    grantNonce: randomHex32(),
    signBefore: BigInt(now + (input.signWithin ?? 24 * HOUR))
  };
}
function validatePolicy(p) {
  for (const a of p.actions) if (!(a in ACTIONS)) throw new Error(`unknown action "${a}"`);
  for (const e of p.environments) if (!(e in ENVIRONMENTS)) throw new Error(`unknown environment "${e}"`);
  if (p.apps.length > 8) throw new Error("a grant names at most 8 apps");
  if (p.periodSeconds <= 0) throw new Error("periodSeconds must be > 0");
  if (p.expiresIn <= 0) throw new Error("expiry must be in the future");
  const needsApp = p.actions.some((a) => a === "app.publish" || a === "deploy.setAppRef" || a === "deploy.create");
  if (needsApp && p.apps.length === 0) throw new Error("this preset needs --app (which apps the session may use)");
  if (p.actions.includes("app.publish") && p.apps.every((a) => a === "*"))
    throw new Error('publishing needs the app named explicitly ("*" never covers app.publish)');
}
var fmtUsd = (v) => {
  const n = Number(v) / 1e6;
  return n !== 0 && n < 0.01 ? `$${n.toFixed(6).replace(/0+$/, "")}` : `$${n.toFixed(2)}`;
};
var fmtDur = (s) => s >= DAY ? `${+(s / DAY).toFixed(1)} days` : `${+(s / HOUR).toFixed(1)} hours`;
function describeGrant(g, now = Math.floor(Date.now() / 1e3)) {
  const lines = [];
  const warnings = [];
  const onchain = g.actions.filter((a) => ACTIONS[a] < 128);
  const api = g.actions.filter((a) => ACTIONS[a] >= 128);
  if (onchain.length) lines.push(`May: ${onchain.map((a) => ACTION_TEXT[a] ?? a).join("; ")}.`);
  if (api.length) lines.push(`API access: ${api.map((a) => ACTION_TEXT[a] ?? a).join("; ")}.`);
  const apps = g.apps.filter((a) => a !== "*");
  if (g.apps.includes("*")) lines.push(`Apps: any app${apps.length ? `, and publishing only to ${apps.join(", ")}` : ""}.`);
  else if (apps.length) lines.push(`Apps: only ${apps.join(", ")}.`);
  if (g.environments.length) lines.push(`Environments: ${g.environments.join(" and ")}.`);
  lines.push(`Budget: ${fmtUsd(g.budget)} escrowed; at most ${fmtUsd(g.spendPerPeriod)} per ${fmtDur(g.periodSeconds)}${g.opsPerPeriod ? `, ${g.opsPerPeriod} operations per ${fmtDur(g.periodSeconds)}` : ""}; relay fee at most ${fmtUsd(g.maxFeePerOp)} per operation.`);
  if (g.maxRatePerHour > 0n) lines.push(`Deployment prices it sets: at most ${fmtUsd(g.maxRatePerHour)}/hour; production prices can only go down.`);
  lines.push(`Expires: in ${fmtDur(Number(g.expiresAt) - now)}. Unspent budget returns to your wallet when it ends.`);
  lines.push("Never allowed: withdrawing, promoting to production, secrets, opening or changing other sessions.");
  if (g.environments.includes("prod")) warnings.push("This session can act on PRODUCTION deployments (not change what version they run), including the ones your wallet holds once you let your sessions manage them (one wallet transaction, revocable on the Sessions page).");
  if (g.apps.includes("*") && g.actions.includes("deploy.create")) warnings.push("This session can deploy any FREE app from the store (paid apps only if named).");
  if (g.actions.includes("api.account")) warnings.push("This session can sign in to your Enclave account and to apps as you (Sign in with Enclave).");
  if (g.budget > 100n * 1000000n) warnings.push(`Large budget: ${fmtUsd(g.budget)}.`);
  if (Number(g.expiresAt) - now > 14 * DAY) warnings.push(`Long-lived: ${fmtDur(Number(g.expiresAt) - now)}.`);
  if (g.measurement !== ZERO_HASH) lines.push(`Key must live inside an enclave with measurement ${g.measurement.slice(0, 18)}\u2026`);
  return { lines, warnings };
}
var ser = (o) => JSON.stringify(o, (_k, v) => typeof v === "bigint" ? `${v}n` : v);
var de = (s) => JSON.parse(s, (_k, v) => typeof v === "string" && /^\d+n$/.test(v) ? BigInt(v.slice(0, -1)) : v);
function encodeGrantRequest(r) {
  return b64u(new TextEncoder().encode(ser(r)));
}
function decodeGrantRequest(s) {
  const r = de(new TextDecoder().decode(unb64u(s)));
  if (r.v !== 1 || !r.grant || !r.x || !r.y) throw new Error("not a session grant request");
  return r;
}
function grantLink(siteOrigin, r) {
  return `${siteOrigin.replace(/\/$/, "")}/grant#${encodeGrantRequest(r)}`;
}

// src/client.ts
import {
  createPublicClient,
  decodeErrorResult,
  encodeFunctionData,
  hashTypedData as hashTypedData2,
  http,
  keccak256 as keccak2562
} from "viem";

// src/abi.ts
var sessionVaultAbi = [
  {
    "type": "constructor",
    "inputs": [
      {
        "name": "_usdc",
        "type": "address",
        "internalType": "contract ISVToken"
      },
      {
        "name": "_book",
        "type": "address",
        "internalType": "contract ISVBook"
      },
      {
        "name": "_router",
        "type": "address",
        "internalType": "contract ISVRouter"
      },
      {
        "name": "_ka",
        "type": "address",
        "internalType": "contract ISVKeyAttestations"
      },
      {
        "name": "_maxVault6",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "ACT_CREATE",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint8",
        "internalType": "uint8"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "ACT_FUND",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint8",
        "internalType": "uint8"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "ACT_PUBLISH",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint8",
        "internalType": "uint8"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "ACT_REFUND",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint8",
        "internalType": "uint8"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "ACT_SET_ACTIVE",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint8",
        "internalType": "uint8"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "ACT_SET_APPREF",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint8",
        "internalType": "uint8"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "ACT_SET_CONFIG",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint8",
        "internalType": "uint8"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "ACT_SET_MAXRATE",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint8",
        "internalType": "uint8"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "ACT_SET_SHARES",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint8",
        "internalType": "uint8"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "ADOPT_TYPEHASH",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "CALL_TYPEHASH",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "END_TYPEHASH",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "ENV_PROD",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint8",
        "internalType": "uint8"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "ENV_STAGING",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint8",
        "internalType": "uint8"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "EXTEND_TYPEHASH",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "GRANT_TYPEHASH",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "PROMOTE_TYPEHASH",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "RELEASE_TYPEHASH",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "REVOKE_TYPEHASH",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "SETENV_TYPEHASH",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "TERMINATE_TYPEHASH",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "TOPUP_TYPEHASH",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "WITHDRAW_TYPEHASH",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "adopt",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "environment",
        "type": "string",
        "internalType": "string"
      },
      {
        "name": "opNonce",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "signBefore",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "sig",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "book",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "contract ISVBook"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "close",
    "inputs": [
      {
        "name": "sid",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "domainSeparator",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "epoch",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint64",
        "internalType": "uint64"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "execute",
    "inputs": [
      {
        "name": "sid",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "nonce",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "action",
        "type": "uint8",
        "internalType": "uint8"
      },
      {
        "name": "args",
        "type": "bytes",
        "internalType": "bytes"
      },
      {
        "name": "fee",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "deadline",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "x",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "y",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "r",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "sv",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "extend",
    "inputs": [
      {
        "name": "sid",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "expiresAt",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "opNonce",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "signBefore",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "sig",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "factory",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "free",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "grantDigest",
    "inputs": [
      {
        "name": "g",
        "type": "tuple",
        "internalType": "struct SessionVault.Grant",
        "components": [
          {
            "name": "label",
            "type": "string",
            "internalType": "string"
          },
          {
            "name": "preset",
            "type": "string",
            "internalType": "string"
          },
          {
            "name": "sessionKey",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "actions",
            "type": "string[]",
            "internalType": "string[]"
          },
          {
            "name": "apps",
            "type": "string[]",
            "internalType": "string[]"
          },
          {
            "name": "environments",
            "type": "string[]",
            "internalType": "string[]"
          },
          {
            "name": "budget",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "spendPerPeriod",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "periodSeconds",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "opsPerPeriod",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "maxFeePerOp",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "maxAppFeePerHour",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "maxRatePerHour",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "expiresAt",
            "type": "uint64",
            "internalType": "uint64"
          },
          {
            "name": "measurement",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "grantNonce",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "signBefore",
            "type": "uint64",
            "internalType": "uint64"
          }
        ]
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "held",
    "inputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "env",
        "type": "uint8",
        "internalType": "uint8"
      },
      {
        "name": "promoted",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "createdBy",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "initialize",
    "inputs": [
      {
        "name": "owner_",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "isLive",
    "inputs": [
      {
        "name": "sid",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "keyAttestations",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "contract ISVKeyAttestations"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "locked6",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "maxVault6",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "open",
    "inputs": [
      {
        "name": "g",
        "type": "tuple",
        "internalType": "struct SessionVault.Grant",
        "components": [
          {
            "name": "label",
            "type": "string",
            "internalType": "string"
          },
          {
            "name": "preset",
            "type": "string",
            "internalType": "string"
          },
          {
            "name": "sessionKey",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "actions",
            "type": "string[]",
            "internalType": "string[]"
          },
          {
            "name": "apps",
            "type": "string[]",
            "internalType": "string[]"
          },
          {
            "name": "environments",
            "type": "string[]",
            "internalType": "string[]"
          },
          {
            "name": "budget",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "spendPerPeriod",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "periodSeconds",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "opsPerPeriod",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "maxFeePerOp",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "maxAppFeePerHour",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "maxRatePerHour",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "expiresAt",
            "type": "uint64",
            "internalType": "uint64"
          },
          {
            "name": "measurement",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "grantNonce",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "signBefore",
            "type": "uint64",
            "internalType": "uint64"
          }
        ]
      },
      {
        "name": "ownerSig",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [
      {
        "name": "sid",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "openWithDeposit",
    "inputs": [
      {
        "name": "g",
        "type": "tuple",
        "internalType": "struct SessionVault.Grant",
        "components": [
          {
            "name": "label",
            "type": "string",
            "internalType": "string"
          },
          {
            "name": "preset",
            "type": "string",
            "internalType": "string"
          },
          {
            "name": "sessionKey",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "actions",
            "type": "string[]",
            "internalType": "string[]"
          },
          {
            "name": "apps",
            "type": "string[]",
            "internalType": "string[]"
          },
          {
            "name": "environments",
            "type": "string[]",
            "internalType": "string[]"
          },
          {
            "name": "budget",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "spendPerPeriod",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "periodSeconds",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "opsPerPeriod",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "maxFeePerOp",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "maxAppFeePerHour",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "maxRatePerHour",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "expiresAt",
            "type": "uint64",
            "internalType": "uint64"
          },
          {
            "name": "measurement",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "grantNonce",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "signBefore",
            "type": "uint64",
            "internalType": "uint64"
          }
        ]
      },
      {
        "name": "ownerSig",
        "type": "bytes",
        "internalType": "bytes"
      },
      {
        "name": "validAfter",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "validBefore",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "authSig",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [
      {
        "name": "sid",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "owner",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "ownerCall",
    "inputs": [
      {
        "name": "target",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "data",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [
      {
        "name": "ret",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "ownerNonceUsed",
    "inputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "promote",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "app",
        "type": "string",
        "internalType": "string"
      },
      {
        "name": "publisher",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "appRef",
        "type": "string",
        "internalType": "string"
      },
      {
        "name": "configCid",
        "type": "string",
        "internalType": "string"
      },
      {
        "name": "versionLabel",
        "type": "string",
        "internalType": "string"
      },
      {
        "name": "isPublic",
        "type": "bool",
        "internalType": "bool"
      },
      {
        "name": "opNonce",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "signBefore",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "sig",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "release",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "to",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "opNonce",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "signBefore",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "sig",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "revokeAll",
    "inputs": [
      {
        "name": "alsoWithdraw",
        "type": "bool",
        "internalType": "bool"
      },
      {
        "name": "opNonce",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "signBefore",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "sig",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "router",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "contract ISVRouter"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "seqOf",
    "inputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "",
        "type": "uint192",
        "internalType": "uint192"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "uint64",
        "internalType": "uint64"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "sessionIdOf",
    "inputs": [
      {
        "name": "sessionKey",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "grantNonce",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "sessionOf",
    "inputs": [
      {
        "name": "sid",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "s",
        "type": "tuple",
        "internalType": "struct SessionVault.Session",
        "components": [
          {
            "name": "keyHash",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "measurement",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "actions",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "expiresAt",
            "type": "uint64",
            "internalType": "uint64"
          },
          {
            "name": "epoch",
            "type": "uint64",
            "internalType": "uint64"
          },
          {
            "name": "envs",
            "type": "uint8",
            "internalType": "uint8"
          },
          {
            "name": "state",
            "type": "uint8",
            "internalType": "uint8"
          },
          {
            "name": "anyApp",
            "type": "bool",
            "internalType": "bool"
          },
          {
            "name": "balance6",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "spent6",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "perPeriod6",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "maxFee6",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "maxAppFeeHour6",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "maxRateHour6",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "periodStart",
            "type": "uint64",
            "internalType": "uint64"
          },
          {
            "name": "period",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "opsPerPeriod",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "periodSpent6",
            "type": "uint128",
            "internalType": "uint128"
          },
          {
            "name": "periodOps",
            "type": "uint32",
            "internalType": "uint32"
          }
        ]
      },
      {
        "name": "live",
        "type": "bool",
        "internalType": "bool"
      },
      {
        "name": "apps",
        "type": "bytes32[]",
        "internalType": "bytes32[]"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "setEnvironment",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "environment",
        "type": "string",
        "internalType": "string"
      },
      {
        "name": "opNonce",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "signBefore",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "sig",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "terminate",
    "inputs": [
      {
        "name": "sid",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "opNonce",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "signBefore",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "sig",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "terminateBySession",
    "inputs": [
      {
        "name": "sid",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "deadline",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "x",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "y",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "r",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "sv",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "topUp",
    "inputs": [
      {
        "name": "sid",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "amount",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "opNonce",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "signBefore",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "sig",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "topUpWithAuthorization",
    "inputs": [
      {
        "name": "sid",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "amount",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "opNonce",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "validAfter",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "validBefore",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "authSig",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "usdc",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "contract ISVToken"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "withdraw",
    "inputs": [
      {
        "name": "amount",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "opNonce",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "signBefore",
        "type": "uint64",
        "internalType": "uint64"
      },
      {
        "name": "sig",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "event",
    "name": "Extended",
    "inputs": [
      {
        "name": "sid",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "expiresAt",
        "type": "uint64",
        "indexed": false,
        "internalType": "uint64"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "HeldSet",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "env",
        "type": "uint8",
        "indexed": false,
        "internalType": "uint8"
      },
      {
        "name": "createdBy",
        "type": "bytes32",
        "indexed": false,
        "internalType": "bytes32"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "Promoted",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "promoted",
        "type": "bytes32",
        "indexed": false,
        "internalType": "bytes32"
      },
      {
        "name": "appRef",
        "type": "string",
        "indexed": false,
        "internalType": "string"
      },
      {
        "name": "configCid",
        "type": "string",
        "indexed": false,
        "internalType": "string"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "Released",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "to",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "RevokedAll",
    "inputs": [
      {
        "name": "epoch",
        "type": "uint64",
        "indexed": false,
        "internalType": "uint64"
      },
      {
        "name": "withdrawn6",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "SessionEnded",
    "inputs": [
      {
        "name": "sid",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "reason",
        "type": "uint8",
        "indexed": false,
        "internalType": "uint8"
      },
      {
        "name": "refund6",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      },
      {
        "name": "fee6",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "SessionOp",
    "inputs": [
      {
        "name": "sid",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "nonce",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      },
      {
        "name": "action",
        "type": "uint8",
        "indexed": true,
        "internalType": "uint8"
      },
      {
        "name": "argsHash",
        "type": "bytes32",
        "indexed": false,
        "internalType": "bytes32"
      },
      {
        "name": "amount6",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      },
      {
        "name": "fee6",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      },
      {
        "name": "result",
        "type": "bytes",
        "indexed": false,
        "internalType": "bytes"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "SessionOpened",
    "inputs": [
      {
        "name": "sid",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "keyHash",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "expiresAt",
        "type": "uint64",
        "indexed": false,
        "internalType": "uint64"
      },
      {
        "name": "actions",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      },
      {
        "name": "envs",
        "type": "uint8",
        "indexed": false,
        "internalType": "uint8"
      },
      {
        "name": "budget6",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      },
      {
        "name": "label",
        "type": "string",
        "indexed": false,
        "internalType": "string"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "ToppedUp",
    "inputs": [
      {
        "name": "sid",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "amount6",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      },
      {
        "name": "fromWallet",
        "type": "bool",
        "indexed": false,
        "internalType": "bool"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "Withdrawn",
    "inputs": [
      {
        "name": "amount6",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      }
    ],
    "anonymous": false
  },
  {
    "type": "error",
    "name": "AllowanceLeft",
    "inputs": []
  },
  {
    "type": "error",
    "name": "AppFeeTooHigh",
    "inputs": [
      {
        "name": "perHour",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "max",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "AppNotAllowed",
    "inputs": [
      {
        "name": "appId",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ]
  },
  {
    "type": "error",
    "name": "BadNonce",
    "inputs": []
  },
  {
    "type": "error",
    "name": "BadPolicy",
    "inputs": [
      {
        "name": "code",
        "type": "uint8",
        "internalType": "uint8"
      }
    ]
  },
  {
    "type": "error",
    "name": "BadRef",
    "inputs": []
  },
  {
    "type": "error",
    "name": "BadSignature",
    "inputs": []
  },
  {
    "type": "error",
    "name": "BadTarget",
    "inputs": []
  },
  {
    "type": "error",
    "name": "BudgetExceeded",
    "inputs": [
      {
        "name": "need",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "have",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "EnvNotAllowed",
    "inputs": [
      {
        "name": "env",
        "type": "uint8",
        "internalType": "uint8"
      }
    ]
  },
  {
    "type": "error",
    "name": "Exists",
    "inputs": []
  },
  {
    "type": "error",
    "name": "Expired",
    "inputs": []
  },
  {
    "type": "error",
    "name": "FeeTooHigh",
    "inputs": [
      {
        "name": "fee",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "max",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "Initialized",
    "inputs": []
  },
  {
    "type": "error",
    "name": "Insolvent",
    "inputs": []
  },
  {
    "type": "error",
    "name": "LabelMismatch",
    "inputs": []
  },
  {
    "type": "error",
    "name": "NoAttestation",
    "inputs": []
  },
  {
    "type": "error",
    "name": "NoContract",
    "inputs": [
      {
        "name": "key",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ]
  },
  {
    "type": "error",
    "name": "NonceUsed",
    "inputs": []
  },
  {
    "type": "error",
    "name": "NotAllowed",
    "inputs": [
      {
        "name": "action",
        "type": "uint8",
        "internalType": "uint8"
      }
    ]
  },
  {
    "type": "error",
    "name": "NotExpired",
    "inputs": []
  },
  {
    "type": "error",
    "name": "NotFactory",
    "inputs": []
  },
  {
    "type": "error",
    "name": "NotHeld",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ]
  },
  {
    "type": "error",
    "name": "NotLive",
    "inputs": []
  },
  {
    "type": "error",
    "name": "NotMine",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ]
  },
  {
    "type": "error",
    "name": "NotOwner",
    "inputs": []
  },
  {
    "type": "error",
    "name": "OverCap",
    "inputs": [
      {
        "name": "balance",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "cap",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "PeriodLimit",
    "inputs": [
      {
        "name": "need",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "left",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "RateCapOutOfRange",
    "inputs": [
      {
        "name": "rate",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "limit",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "RateLimit",
    "inputs": []
  },
  {
    "type": "error",
    "name": "Reentrant",
    "inputs": []
  },
  {
    "type": "error",
    "name": "TransferFailed",
    "inputs": []
  },
  {
    "type": "error",
    "name": "UnknownAction",
    "inputs": []
  },
  {
    "type": "error",
    "name": "UnknownEnvironment",
    "inputs": []
  },
  {
    "type": "error",
    "name": "WrongEnvironment",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "env",
        "type": "uint8",
        "internalType": "uint8"
      }
    ]
  },
  {
    "type": "error",
    "name": "FundRateTooLow",
    "inputs": [
      {
        "name": "rate",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "feeTimesTwo",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "LeaseUnsettled",
    "inputs": [
      {
        "name": "id",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ]
  }
];
var sessionVaultFactoryAbi = [
  {
    "type": "constructor",
    "inputs": [
      {
        "name": "usdc",
        "type": "address",
        "internalType": "contract ISVToken"
      },
      {
        "name": "book",
        "type": "address",
        "internalType": "contract ISVBook"
      },
      {
        "name": "router",
        "type": "address",
        "internalType": "contract ISVRouter"
      },
      {
        "name": "keyAttestations",
        "type": "address",
        "internalType": "contract ISVKeyAttestations"
      },
      {
        "name": "maxVault6",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "createVault",
    "inputs": [
      {
        "name": "owner",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "vault",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "implementation",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "contract SessionVault"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "isVault",
    "inputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "openFor",
    "inputs": [
      {
        "name": "owner",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "g",
        "type": "tuple",
        "internalType": "struct SessionVault.Grant",
        "components": [
          {
            "name": "label",
            "type": "string",
            "internalType": "string"
          },
          {
            "name": "preset",
            "type": "string",
            "internalType": "string"
          },
          {
            "name": "sessionKey",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "actions",
            "type": "string[]",
            "internalType": "string[]"
          },
          {
            "name": "apps",
            "type": "string[]",
            "internalType": "string[]"
          },
          {
            "name": "environments",
            "type": "string[]",
            "internalType": "string[]"
          },
          {
            "name": "budget",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "spendPerPeriod",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "periodSeconds",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "opsPerPeriod",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "maxFeePerOp",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "maxAppFeePerHour",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "maxRatePerHour",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "expiresAt",
            "type": "uint64",
            "internalType": "uint64"
          },
          {
            "name": "measurement",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "grantNonce",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "signBefore",
            "type": "uint64",
            "internalType": "uint64"
          }
        ]
      },
      {
        "name": "ownerSig",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [
      {
        "name": "vault",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "sid",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "openWithDepositFor",
    "inputs": [
      {
        "name": "owner",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "g",
        "type": "tuple",
        "internalType": "struct SessionVault.Grant",
        "components": [
          {
            "name": "label",
            "type": "string",
            "internalType": "string"
          },
          {
            "name": "preset",
            "type": "string",
            "internalType": "string"
          },
          {
            "name": "sessionKey",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "actions",
            "type": "string[]",
            "internalType": "string[]"
          },
          {
            "name": "apps",
            "type": "string[]",
            "internalType": "string[]"
          },
          {
            "name": "environments",
            "type": "string[]",
            "internalType": "string[]"
          },
          {
            "name": "budget",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "spendPerPeriod",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "periodSeconds",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "opsPerPeriod",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "maxFeePerOp",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "maxAppFeePerHour",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "maxRatePerHour",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "expiresAt",
            "type": "uint64",
            "internalType": "uint64"
          },
          {
            "name": "measurement",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "grantNonce",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "signBefore",
            "type": "uint64",
            "internalType": "uint64"
          }
        ]
      },
      {
        "name": "ownerSig",
        "type": "bytes",
        "internalType": "bytes"
      },
      {
        "name": "validAfter",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "validBefore",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "authSig",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [
      {
        "name": "vault",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "sid",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "vaultFor",
    "inputs": [
      {
        "name": "owner",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "event",
    "name": "VaultCreated",
    "inputs": [
      {
        "name": "owner",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "vault",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      }
    ],
    "anonymous": false
  }
];
var usdcAbi = [
  {
    "type": "function",
    "name": "name",
    "stateMutability": "view",
    "inputs": [],
    "outputs": [
      {
        "type": "string"
      }
    ]
  },
  {
    "type": "function",
    "name": "version",
    "stateMutability": "view",
    "inputs": [],
    "outputs": [
      {
        "type": "string"
      }
    ]
  },
  {
    "type": "function",
    "name": "balanceOf",
    "stateMutability": "view",
    "inputs": [
      {
        "name": "a",
        "type": "address"
      }
    ],
    "outputs": [
      {
        "type": "uint256"
      }
    ]
  }
];
var addressBookAbi = [
  {
    "type": "function",
    "name": "addr",
    "stateMutability": "view",
    "inputs": [
      {
        "name": "key",
        "type": "bytes32"
      }
    ],
    "outputs": [
      {
        "type": "address"
      }
    ]
  }
];
var ledgerDelegateAbi = [
  {
    "type": "function",
    "name": "setDelegate",
    "stateMutability": "nonpayable",
    "inputs": [
      {
        "name": "delegate",
        "type": "address"
      },
      {
        "name": "allowed",
        "type": "bool"
      }
    ],
    "outputs": []
  },
  {
    "type": "event",
    "name": "DelegateSet",
    "anonymous": false,
    "inputs": [
      {
        "name": "owner",
        "type": "address",
        "indexed": true
      },
      {
        "name": "delegate",
        "type": "address",
        "indexed": true
      },
      {
        "name": "allowed",
        "type": "bool",
        "indexed": false
      }
    ]
  }
];

// src/client.ts
var SessionError = class extends Error {
  constructor(code, message, detail) {
    super(message);
    this.code = code;
    this.detail = detail;
    this.name = "SessionError";
  }
  code;
  detail;
};
var ERROR_CODES = {
  NotLive: "not_live",
  Expired: "expired",
  NotAllowed: "not_allowed",
  EnvNotAllowed: "env",
  WrongEnvironment: "env",
  AppNotAllowed: "app",
  BudgetExceeded: "budget",
  PeriodLimit: "period",
  RateLimit: "rate",
  FeeTooHigh: "fee",
  BadSignature: "signature",
  BadNonce: "nonce",
  NonceUsed: "nonce",
  BadPolicy: "policy",
  UnknownAction: "policy",
  UnknownEnvironment: "policy",
  AppFeeTooHigh: "app",
  NotHeld: "env",
  NotMine: "env",
  NoAttestation: "policy",
  OverCap: "budget",
  // the deployment's price is outside what a session may pay or set: the owner's wallet acts
  RateCapOutOfRange: "price",
  FundRateTooLow: "price",
  LeaseUnsettled: "price"
};
function decodeVaultError(data) {
  if (data && data.length >= 10) {
    try {
      const e = decodeErrorResult({ abi: sessionVaultAbi, data });
      const args = e.args ?? [];
      if (e.errorName === "Error" && args[0] === "!owner")
        return new SessionError("delegation", "the ledger refused: your wallet has not let your session vault manage the deployments it holds (grant it once with setDelegate, from the wallet)", { error: "Error", args });
      return new SessionError(
        ERROR_CODES[e.errorName] ?? "revert",
        `${e.errorName}(${args.map(String).join(", ")})`,
        { error: e.errorName, args }
      );
    } catch {
    }
  }
  return new SessionError("revert", "the vault refused the operation", { data });
}
var RelayClient = class {
  constructor(base, fetchImpl) {
    this.base = base;
    this.f = fetchImpl ?? globalThis.fetch.bind(globalThis);
  }
  base;
  f;
  async request(method, path, body, headers) {
    const url = `${this.base.replace(/\/$/, "")}/v1/sessions${path}`;
    let res;
    try {
      res = await this.f(url, {
        method,
        headers: { ...body ? { "content-type": "application/json" } : {}, ...headers ?? {} },
        body: body ? ser(body) : void 0
      });
    } catch (e) {
      throw new SessionError("relay", `relay unreachable: ${e.message}`);
    }
    const text = await res.text();
    let json = {};
    try {
      json = text ? de(text) : {};
    } catch {
    }
    if (!res.ok) {
      if (typeof json.revert === "string") throw decodeVaultError(json.revert);
      const code = json.code ?? "relay";
      throw new SessionError(code, String(json.error ?? `relay HTTP ${res.status}`), json);
    }
    return json;
  }
  config() {
    return this.request("GET", "/config");
  }
};
function chainClient(chainId, rpc) {
  const net = Object.values(NETWORKS).find((n) => n.chainId === chainId);
  const url = rpc ?? net?.rpc;
  if (!url) throw new SessionError("config", `no RPC for chain ${chainId}`);
  return createPublicClient({ transport: http(url, { retryCount: 2 }) });
}
async function readSession(pc, vault, sid) {
  const [s, live, apps] = await pc.readContract({
    address: vault,
    abi: sessionVaultAbi,
    functionName: "sessionOf",
    args: [sid]
  });
  return { ...s, live, apps };
}
async function resolveFactory(pc, book) {
  const key = `0x${Array.from(new TextEncoder().encode(BOOK_KEY_FACTORY), (b) => b.toString(16).padStart(2, "0")).join("").padEnd(64, "0")}`;
  return pc.readContract({ address: book, abi: addressBookAbi, functionName: "addr", args: [key] });
}
async function vaultAddress(pc, factory, owner) {
  return pc.readContract({ address: factory, abi: sessionVaultFactoryAbi, functionName: "vaultFor", args: [owner] });
}
function spendable(s, now = BigInt(Math.floor(Date.now() / 1e3))) {
  const fresh = now >= s.periodStart + BigInt(s.period);
  const left = fresh ? s.perPeriod6 : s.perPeriod6 > s.periodSpent6 ? s.perPeriod6 - s.periodSpent6 : 0n;
  return s.balance6 < left ? s.balance6 : left;
}
async function directDeadline(pc, chainId, seconds = 600) {
  if (!Number.isSafeInteger(seconds) || seconds < 1 || seconds > 3600)
    throw new SessionError("config", "deadlineSeconds must be an integer from 1 to 3600");
  if (await pc.getChainId() !== chainId) throw new SessionError("config", "RPC chain does not match the session");
  return (await pc.getBlock()).timestamp + BigInt(seconds);
}
var Session = class {
  constructor(handle, signer, opts = {}) {
    this.handle = handle;
    this.signer = signer;
    this.relay = new RelayClient(handle.relay, opts.fetch);
    this.pc = opts.publicClient;
  }
  handle;
  signer;
  relay;
  pc;
  chain() {
    return this.pc ??= chainClient(this.handle.chainId, this.handle.rpc);
  }
  status() {
    return readSession(this.chain(), this.handle.vault, this.handle.sid);
  }
  /** Authorize a zero-relay-fee operation using chain reads only. An owner or
   * independent gas payer can broadcast the returned calldata. The vault remains
   * authoritative for scope, attestation, budget, revocation and replay checks. */
  async prepareCall(action, args, opts = {}) {
    const lane = opts.lane ?? 0n;
    if (lane < 0n || lane >= 1n << 192n) throw new SessionError("config", "lane must fit uint192");
    const deadline = await directDeadline(this.chain(), this.handle.chainId, opts.deadlineSeconds);
    const s = await this.status();
    if (!s.live) throw new SessionError("not_live", "this session is not live");
    if ((s.actions >> BigInt(ACTIONS[action]) & 1n) === 0n)
      throw new SessionError("not_allowed", `this session may not ${action}`);
    const amount = amountOf(action, args);
    if (amount > s.balance6) throw new SessionError("budget", `needs ${amount}, session has ${s.balance6}`);
    const data = encodeArgs(action, args);
    const nonce = lane << 64n | await this.seq(lane);
    const digest = digestOf(this.handle.chainId, this.handle.vault, "SessionCall", {
      sessionId: this.handle.sid,
      nonce,
      action: ACTIONS[action],
      argsHash: keccak2562(data),
      fee: 0n,
      deadline
    });
    const { r, s: sv } = await this.signer.signDigest(digest);
    return {
      chainId: this.handle.chainId,
      to: this.handle.vault,
      value: 0n,
      data: encodeFunctionData({
        abi: sessionVaultAbi,
        functionName: "execute",
        args: [this.handle.sid, nonce, ACTIONS[action], data, 0n, deadline, this.signer.x, this.signer.y, r, sv]
      })
    };
  }
  /** End and refund a session through any gas payer, without contacting a relay. */
  async prepareTermination(opts = {}) {
    const deadline = await directDeadline(this.chain(), this.handle.chainId, opts.deadlineSeconds);
    const digest = digestOf(this.handle.chainId, this.handle.vault, "SessionEnd", { sessionId: this.handle.sid, deadline });
    const { r, s } = await this.signer.signDigest(digest);
    return {
      chainId: this.handle.chainId,
      to: this.handle.vault,
      value: 0n,
      data: encodeFunctionData({
        abi: sessionVaultAbi,
        functionName: "terminateBySession",
        args: [this.handle.sid, deadline, this.signer.x, this.signer.y, r, s]
      })
    };
  }
  /** Check, quote, sign and submit one action. Throws SessionError with a code the
   *  caller can act on (budget -> top-up, expired -> extend, ...). */
  async call(action, args, opts = {}) {
    const s = await this.status();
    const now = BigInt(Math.floor(Date.now() / 1e3));
    if (!s.live) throw new SessionError(
      s.expiresAt < now ? "expired" : "not_live",
      s.expiresAt < now ? "this session has expired" : "this session has ended"
    );
    const bit = BigInt(ACTIONS[action]);
    if ((s.actions >> bit & 1n) === 0n) throw new SessionError("not_allowed", `this session may not ${action}`);
    const data = encodeArgs(action, args);
    const amount = amountOf(action, args);
    const q = await this.relay.request("POST", "/quote", {
      vault: this.handle.vault,
      sid: this.handle.sid,
      action: ACTIONS[action],
      args: data
    });
    const cap = opts.maxFee !== void 0 && opts.maxFee < s.maxFee6 ? opts.maxFee : s.maxFee6;
    if (q.fee > cap) throw new SessionError("fee", `relay fee ${q.fee} exceeds this session's cap ${cap}`);
    const need = amount + q.fee;
    if (need > s.balance6) throw new SessionError(
      "budget",
      `needs ${need}, session has ${s.balance6}`,
      { need, have: s.balance6 }
    );
    if (need > spendable(s, now)) throw new SessionError(
      "period",
      `needs ${need}, ${spendable(s, now)} left this period`,
      { need, left: spendable(s, now) }
    );
    const lane = opts.lane ?? 0n;
    const nonce = lane === 0n ? q.nonce : lane << 64n | await this.seq(lane);
    const deadline = opts.deadlineSeconds ? now + BigInt(opts.deadlineSeconds) : q.deadline;
    const digest = digestOf(this.handle.chainId, this.handle.vault, "SessionCall", {
      sessionId: this.handle.sid,
      nonce,
      action: ACTIONS[action],
      argsHash: keccak2562(data),
      fee: q.fee,
      deadline
    });
    const { r, s: sv } = await this.signer.signDigest(digest);
    const out = await this.relay.request("POST", "/execute", {
      vault: this.handle.vault,
      sid: this.handle.sid,
      nonce,
      action: ACTIONS[action],
      args: data,
      fee: q.fee,
      deadline,
      x: this.signer.x,
      y: this.signer.y,
      r,
      s: sv
    });
    return { ...out, fee: q.fee };
  }
  async seq(lane) {
    return BigInt(await this.chain().readContract({
      address: this.handle.vault,
      abi: sessionVaultAbi,
      functionName: "seqOf",
      args: [this.handle.sid, lane]
    }));
  }
  /** Sign-out: the key ends its own session; the remaining budget returns to the owner. */
  async terminate() {
    const deadline = BigInt(Math.floor(Date.now() / 1e3) + 600);
    const digest = digestOf(this.handle.chainId, this.handle.vault, "SessionEnd", { sessionId: this.handle.sid, deadline });
    const { r, s } = await this.signer.signDigest(digest);
    return this.relay.request("POST", "/end", {
      vault: this.handle.vault,
      sid: this.handle.sid,
      deadline,
      x: this.signer.x,
      y: this.signer.y,
      r,
      s
    });
  }
  /** The Authorization header for one API request, bound to method, host+path,
   *  body hash and time (the relay rejects replays and anything older than 60 s). */
  async apiAuthorization(method, url, body) {
    return signApiRequest(this.signer, this.handle.vault, this.handle.sid, method, url, body);
  }
};
async function signApiRequest(signer, vault, sid, method, url, body) {
  const u = new URL(url);
  const ts = Math.floor(Date.now() / 1e3);
  const nb = new Uint8Array(12);
  globalThis.crypto.getRandomValues(nb);
  const n = b64u(nb);
  const msg = apiMessage(method, u.host + u.pathname + u.search, body, ts, n, vault, sid);
  const sig = await signer.signBytes(new TextEncoder().encode(msg));
  const enc = (v) => b64u(hexBytes(v));
  return `EnclaveSession v1 vault=${vault},sid=${sid},ts=${ts},n=${n},x=${enc(signer.x)},y=${enc(signer.y)},sig=${b64u(sig)}`;
}
function apiMessage(method, hostPath, body, ts, n, vault, sid) {
  const bodyHash = sha256Hex(body ?? new Uint8Array()).slice(2);
  return `enclave-api-v1
${method.toUpperCase()}
${hostPath}
${bodyHash}
${ts}
${n}
${vault.toLowerCase()}
${sid.toLowerCase()}`;
}
function hexBytes(v) {
  const h = v.toString(16).padStart(64, "0");
  return Uint8Array.from(h.match(/../g), (b) => parseInt(b, 16));
}
var DOMAIN_FIELDS = [
  { name: "name", type: "string" },
  { name: "version", type: "string" },
  { name: "chainId", type: "uint256" },
  { name: "verifyingContract", type: "address" }
];
function ownerFromProvider(provider, address) {
  return {
    address,
    async signTypedData(td) {
      const payload = JSON.stringify(
        { ...td, types: { EIP712Domain: DOMAIN_FIELDS, ...td.types } },
        (_k, v) => typeof v === "bigint" ? v.toString() : v
      );
      return await provider.request({ method: "eth_signTypedData_v4", params: [address, payload] });
    }
  };
}
async function usdcDomain(pc, usdc, chainId) {
  const [name, version] = await Promise.all([
    pc.readContract({ address: usdc, abi: usdcAbi, functionName: "name" }),
    pc.readContract({ address: usdc, abi: usdcAbi, functionName: "version" })
  ]);
  return { name, version, chainId, verifyingContract: usdc };
}
var RECEIVE_TYPES = {
  ReceiveWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" }
  ]
};
async function signDeposit(owner, usdc, vault, value, commitment, validBefore) {
  const sig = await owner.signTypedData({
    domain: usdc,
    types: RECEIVE_TYPES,
    primaryType: "ReceiveWithAuthorization",
    message: { from: owner.address, to: vault, value, validAfter: 0n, validBefore, nonce: commitment }
  });
  return { validAfter: 0n, validBefore, sig };
}
async function openSession(p) {
  const td = typedData(p.chainId, p.vault, "SessionGrant", p.grant);
  const ownerSig = await p.owner.signTypedData(td);
  let deposit;
  if (p.grant.budget > 0n) {
    if (!p.usdc) throw new SessionError("config", "a funded session needs the USDC domain");
    deposit = await signDeposit(
      p.owner,
      p.usdc,
      p.vault,
      p.grant.budget,
      grantDigest(p.chainId, p.vault, p.grant),
      p.grant.signBefore
    );
  }
  const out = await p.relay.request(
    "POST",
    "/open",
    { owner: p.owner.address, grant: p.grant, ownerSig, deposit }
  );
  const expect = sessionIdOf(p.vault, p.grant.sessionKey, p.grant.grantNonce);
  if (out.sid !== expect) throw new SessionError("relay", `relay reported sid ${out.sid}, expected ${expect}`);
  return out;
}
async function prepareSessionOpen(p) {
  if (await p.publicClient.getChainId() !== p.chainId) throw new SessionError("config", "RPC chain does not match the grant");
  if (p.grant.budget > 0n && (!p.usdc || p.usdc.chainId !== p.chainId))
    throw new SessionError("config", "a funded session needs the matching chain's USDC domain");
  const vault = await vaultAddress(p.publicClient, p.factory, p.owner.address);
  const ownerSig = await p.owner.signTypedData(typedData(
    p.chainId,
    vault,
    "SessionGrant",
    p.grant
  ));
  let data;
  if (p.grant.budget > 0n) {
    const deposit = await signDeposit(
      p.owner,
      p.usdc,
      vault,
      p.grant.budget,
      grantDigest(p.chainId, vault, p.grant),
      p.grant.signBefore
    );
    data = encodeFunctionData({
      abi: sessionVaultFactoryAbi,
      functionName: "openWithDepositFor",
      args: [p.owner.address, p.grant, ownerSig, deposit.validAfter, deposit.validBefore, deposit.sig]
    });
  } else {
    data = encodeFunctionData({ abi: sessionVaultFactoryAbi, functionName: "openFor", args: [p.owner.address, p.grant, ownerSig] });
  }
  return {
    chainId: p.chainId,
    to: p.factory,
    data,
    value: 0n,
    vault,
    sid: sessionIdOf(vault, p.grant.sessionKey, p.grant.grantNonce)
  };
}
var OP_TYPE = {
  topUp: "TopUp",
  extend: "Extend",
  terminate: "Terminate",
  revokeAll: "RevokeAll",
  withdraw: "Withdraw",
  promote: "Promote",
  adopt: "Adopt",
  setEnvironment: "SetEnvironment",
  release: "Release"
};
function randomNonce() {
  const b = new Uint8Array(32);
  globalThis.crypto.getRandomValues(b);
  return `0x${Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")}`;
}
async function ownerOperation(p) {
  const opNonce = randomNonce();
  const signBefore = BigInt(Math.floor(Date.now() / 1e3) + (p.validSeconds ?? 600));
  const { op, ...fields } = p.op;
  const message = { ...fields, opNonce, signBefore };
  const sig = await p.owner.signTypedData(typedData(p.chainId, p.vault, OP_TYPE[op], message));
  return p.relay.request("POST", "/owner", { owner: p.owner.address, vault: p.vault, op, args: message, sig });
}
async function topUpFromWallet(p) {
  const opNonce = randomNonce();
  const validBefore = BigInt(Math.floor(Date.now() / 1e3) + 600);
  const commitment = hashTypedData2(typedData(
    p.chainId,
    p.vault,
    "TopUp",
    { sessionId: p.sessionId, amount: p.amount, opNonce, signBefore: validBefore }
  ));
  const dep = await signDeposit(p.owner, p.usdc, p.vault, p.amount, commitment, validBefore);
  return p.relay.request("POST", "/owner", {
    owner: p.owner.address,
    vault: p.vault,
    op: "topUpWithAuthorization",
    args: { sessionId: p.sessionId, amount: p.amount, opNonce, validAfter: dep.validAfter, validBefore, sig: dep.sig },
    sig: "0x"
  });
}

// src/store.ts
var MemoryStore = class {
  m = /* @__PURE__ */ new Map();
  async save(r) {
    this.m.set(r.id, r);
  }
  async load(id) {
    return this.m.get(id) ?? null;
  }
  async list() {
    return [...this.m.values()];
  }
  async remove(id) {
    this.m.delete(id);
  }
};
var pendingId = (keyHash) => `pending-${keyHash.slice(2, 18)}`;
async function sessionFromRecord(rec, opts = {}) {
  if (!rec.handle) throw new Error(`session ${rec.id} is not open yet`);
  const key = rec.privateKey ?? (rec.pkcs8 ? await importPrivateKey(rec.pkcs8) : void 0);
  if (!key) throw new Error(`session ${rec.id} has no private key`);
  const signer = await signerFromKeys(key, BigInt(rec.x), BigInt(rec.y));
  if (signer.keyHash !== rec.keyHash) throw new Error("stored key does not match its key hash");
  return new Session(rec.handle, signer, opts);
}

// src/attest.ts
import { bytesToHex as bytesToHex3, concat, numberToBytes, sha256 as sha2562, stringToBytes } from "viem";
var SESSION_KEY_DOMAIN = "enclave-session-key-v1";
var SESSION_KEY_MEASUREMENT_MAPPING = "sha256(SEV-SNP MEASUREMENT, the 48 raw bytes)";
var TWO_256 = 1n << 256n;
function u256(v, name) {
  const b = BigInt(v);
  if (b < 0n || b >= TWO_256) throw new Error(`${name} out of range`);
  return numberToBytes(b, { size: 32 });
}
function sessionKeyReportData(chainId, x, y) {
  return sha2562(concat([stringToBytes(SESSION_KEY_DOMAIN), u256(chainId, "chainId"), u256(x, "x"), u256(y, "y")]), "bytes");
}
function snpMeasurementToBytes32(measurement) {
  const b = typeof measurement === "string" ? measurement.replace(/^0x/, "") : bytesToHex3(measurement).slice(2);
  if (!/^[0-9a-fA-F]{96}$/.test(b)) throw new Error("an SEV-SNP measurement is 48 bytes");
  return sha2562(`0x${b}`);
}
var hexOf = (v) => typeof v === "string" ? v : bytesToHex3(v);
async function requestAttestation(relay, p) {
  const evidence = {
    type: p.evidence.type,
    report: hexOf(p.evidence.report),
    ...p.evidence.vcek !== void 0 ? { vcek: p.evidence.vcek } : {},
    ...p.evidence.auxblob !== void 0 ? { auxblob: hexOf(p.evidence.auxblob) } : {}
  };
  const res = await relay.request("POST", "/attest", { x: p.x, y: p.y, evidence });
  if (String(res.keyHash).toLowerCase() !== keyHashOf(p.x, p.y).toLowerCase())
    throw new SessionError("relay", "the relay answered for a different key", { keyHash: res.keyHash });
  return res;
}

// src/delegate.ts
import {
  encodeAbiParameters as encodeAbiParameters3,
  encodeFunctionData as encodeFunctionData2,
  getAddress,
  keccak256 as keccak2563,
  toFunctionSelector
} from "viem";
var DELEGATE_SLOT = 23n;
var SET_DELEGATE_SELECTOR = toFunctionSelector("setDelegate(address,bool)");
function delegateSlot(owner, delegate) {
  const inner = keccak2563(encodeAbiParameters3([{ type: "address" }, { type: "uint256" }], [getAddress(owner), DELEGATE_SLOT]));
  return keccak2563(encodeAbiParameters3([{ type: "address" }, { type: "bytes32" }], [getAddress(delegate), inner]));
}
function codeHasDelegation(code) {
  return !!code && code.toLowerCase().includes("63" + SET_DELEGATE_SELECTOR.slice(2).toLowerCase());
}
var supportedCache = /* @__PURE__ */ new Map();
async function ledgerSupportsDelegation(pc, ledger) {
  const key = `${pc.chain?.id ?? "?"}:${ledger.toLowerCase()}`;
  const hit = supportedCache.get(key);
  if (hit !== void 0) return hit;
  const code = await pc.getCode({ address: ledger });
  if (!code || code === "0x") return false;
  const ok = codeHasDelegation(code);
  supportedCache.set(key, ok);
  return ok;
}
async function delegationStatus(pc, ledger, owner, vault) {
  if (!await ledgerSupportsDelegation(pc, ledger)) return { supported: false, granted: false };
  const word = await pc.getStorageAt({ address: ledger, slot: delegateSlot(owner, vault) });
  return { supported: true, granted: !!word && BigInt(word) === 1n };
}
function setDelegateCall(vault, allowed) {
  return { data: encodeFunctionData2({ abi: ledgerDelegateAbi, functionName: "setDelegate", args: [getAddress(vault), allowed] }) };
}

// src/index.ts
async function newSessionKey(store, p) {
  const kp = await generateKeyPair(p.extractable);
  const signer = await signerFromKeyPair(kp);
  const { x, y } = await publicKeyXY(kp.publicKey);
  const record = {
    v: 1,
    id: pendingId(signer.keyHash),
    relay: p.relay,
    chainId: p.chainId,
    x: x.toString(),
    y: y.toString(),
    keyHash: signer.keyHash,
    label: p.label,
    createdAt: Math.floor(Date.now() / 1e3),
    ...p.extractable ? { pkcs8: await exportPrivateKey(kp.privateKey) } : { privateKey: kp.privateKey }
  };
  await store.save(record);
  return { signer, record };
}
async function completeSession(store, record, p) {
  const sid = sessionIdOf(p.vault, p.grant.sessionKey, p.grant.grantNonce);
  const open = {
    ...record,
    id: sid,
    grant: p.grant,
    handle: { chainId: record.chainId, vault: p.vault, sid, owner: p.owner, label: record.label, relay: record.relay, rpc: p.rpc }
  };
  await store.save(open);
  if (record.id !== sid) await store.remove(record.id);
  return open;
}

// src/store-node.ts
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync, chmodSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
var FileStore = class {
  dir;
  constructor(dir, opts = {}) {
    this.dir = resolve(dir ?? process.env.ENCLAVE_SESSION_DIR ?? join(homedir(), ".config", "enclave", "sessions"));
    if (!opts.allowInsideGit && insideGitTree(this.dir))
      throw new Error(`refusing to store session keys inside a git working tree (${this.dir})`);
  }
  file(id) {
    if (!/^[A-Za-z0-9_-]{1,80}$/.test(id) && !/^0x[0-9a-f]{64}$/.test(id)) throw new Error(`bad session id ${id}`);
    return join(this.dir, `${id}.json`);
  }
  async save(rec) {
    if (rec.privateKey && !rec.pkcs8) throw new Error("FileStore needs the PKCS#8 export of the key");
    mkdirSync(this.dir, { recursive: true, mode: 448 });
    chmodSync(this.dir, 448);
    const { privateKey: _k, ...plain } = rec;
    const f = this.file(rec.id);
    writeFileSync(f, ser(plain), { mode: 384 });
    chmodSync(f, 384);
  }
  async load(id) {
    const f = this.file(id);
    if (!existsSync(f)) return null;
    if ((statSync(f).mode & 63) !== 0) throw new Error(`${f} is readable by others; chmod 600 it`);
    return de(readFileSync(f, "utf8"));
  }
  async list() {
    if (!existsSync(this.dir)) return [];
    return readdirSync(this.dir).filter((n) => n.endsWith(".json")).map((n) => de(readFileSync(join(this.dir, n), "utf8")));
  }
  async remove(id) {
    rmSync(this.file(id), { force: true });
  }
  /** The session commands use when none is named. */
  activeId() {
    const f = join(this.dir, "active");
    return existsSync(f) ? readFileSync(f, "utf8").trim() || null : null;
  }
  setActive(id) {
    mkdirSync(this.dir, { recursive: true, mode: 448 });
    const f = join(this.dir, "active");
    if (id === null) rmSync(f, { force: true });
    else writeFileSync(f, id, { mode: 384 });
  }
};
function insideGitTree(dir) {
  let d = resolve(dir);
  for (; ; ) {
    if (existsSync(join(d, ".git"))) return true;
    const up = dirname(d);
    if (up === d) return false;
    d = up;
  }
}
function exportSessionString(rec) {
  if (!rec.pkcs8) throw new Error("only file-stored (exportable) sessions can be exported");
  const { privateKey: _k, ...plain } = rec;
  return b64u(new TextEncoder().encode(ser(plain)));
}
function importSessionString(s) {
  const rec = de(new TextDecoder().decode(unb64u(s.trim())));
  if (rec.v !== 1 || !rec.pkcs8 || !rec.handle) throw new Error("ENCLAVE_SESSION is not an open session export");
  return rec;
}
var EnvStore = class {
  rec;
  constructor(value = process.env.ENCLAVE_SESSION) {
    this.rec = value ? importSessionString(value) : null;
  }
  async save() {
    throw new Error("ENCLAVE_SESSION is read-only");
  }
  async load(id) {
    return this.rec && (this.rec.id === id || id === "env") ? this.rec : null;
  }
  async list() {
    return this.rec ? [this.rec] : [];
  }
  async remove() {
    throw new Error("ENCLAVE_SESSION is read-only; unset the variable");
  }
};
export {
  ACTIONS,
  ACTION_TEXT,
  BOOK_KEY_FACTORY,
  DELEGATE_SLOT,
  DOMAIN_NAME,
  DOMAIN_VERSION,
  ENVIRONMENTS,
  EnvStore,
  FileStore,
  MemoryStore,
  NETWORKS,
  PRESETS,
  RelayClient,
  SESSION_KEY_DOMAIN,
  SESSION_KEY_MEASUREMENT_MAPPING,
  SET_DELEGATE_SELECTOR,
  Session,
  SessionError,
  TYPES,
  ZERO_HASH,
  actionByIndex,
  actionIndex,
  addressBookAbi,
  amountOf,
  apiMessage,
  b64u as base64url,
  buildGrant,
  chainClient,
  checkCode,
  codeHasDelegation,
  completeSession,
  decodeArgs,
  decodeGrantRequest,
  decodeVaultError,
  delegateSlot,
  delegationStatus,
  describeGrant,
  de as deserialize,
  digestOf,
  domain,
  encodeArgs,
  encodeGrantRequest,
  exportPrivateKey,
  exportSessionString,
  fmtUsd,
  unb64u as fromBase64url,
  generateKeyPair,
  grantDigest,
  grantLink,
  grantTypedData,
  importPrivateKey,
  importSessionString,
  keyHashOf,
  ledgerDelegateAbi,
  ledgerSupportsDelegation,
  newSessionKey,
  openSession,
  ownerFromProvider,
  ownerOperation,
  pendingId,
  prepareSessionOpen,
  publicKeyXY,
  readSession,
  requestAttestation,
  resolveFactory,
  ser as serialize,
  sessionFromRecord,
  sessionIdOf,
  sessionKeyReportData,
  sessionVaultAbi,
  sessionVaultFactoryAbi,
  setDelegateCall,
  sha256Hex,
  signApiRequest,
  signDeposit,
  signerFromKeyPair,
  signerFromKeys,
  snpMeasurementToBytes32,
  spendable,
  topUpFromWallet,
  typedData,
  usdcAbi,
  usdcDomain,
  validatePolicy,
  vaultAddress
};
