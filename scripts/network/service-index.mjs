#!/usr/bin/env node
// scripts/network/service-index.mjs -- an operator's and a first user's command for the ownerless EnclaveServiceIndex
// (contracts/EnclaveServiceIndex.sol, network/service-index.mjs, docs/network/open-participation.md).
//
// Every chain read here is network/service-index.mjs agreedRead: one fixed confirmed block, the first two RPCs that return
// the same whole snapshot win, a third that lies, hangs or is on another chain neither vetoes nor decides, and a refusal
// prints the per-RPC evidence (exit 2) - never an empty answer. Give two or more --rpc you chose; three or more tolerate one bad one.
// Reading (no key):
//   pin    --index 0x.. --chain-id N --rpc A --rpc B [--out pin.json]
//          compiles the reviewed source here (solc-js 0.8.35, viaIR, optimizer 200), reads the deployed runtime code, and
//          writes {chainId, address, codeHash} only if they are the same bytes. The pin is reproducible from source + chain.
//   list   --pin pin.json --rpc A --rpc B [--kind directory]... [--window 256] [--resume cursor.json] [--lookup 0xop[:slot]]...
//          prints UNTRUSTED candidates and whether the read was complete; an incomplete one prints `next`, which --resume
//          continues at the SAME block (while it is fresh). --lookup reads a known operator's slots directly, in the same
//          snapshot, so no amount of listing spam can hide it. Nothing is fetched from, probed at or written to any endpoint.
//   lookup --pin pin.json --rpc A --rpc B --operator 0x.. [--slot N]    (the same, for one operator, without listing)
// Preparing (no key; nothing sent):
//   descriptor --kind K --operator 0x.. --endpoint URL... [--key name=value]... --out descriptor.json
//          a bounded (<= 4 KiB) content-addressed descriptor; prints the sha256 the ad commits to.
//   prepare-publish  --pin pin.json --rpc A --rpc B --operator 0x.. --slot N --kind K --endpoint URL... [--descriptor F]
//                    [--ttl-days 30] [--sequence N] --out prepared.json
//   prepare-withdraw --pin pin.json --rpc A --rpc B --operator 0x.. --slot N [--sequence N] --out prepared.json
//          the next sequence is read from the chain; the EIP-712 typed data (bound to this chain id and this contract)
//          and the direct call are written for review.
// Signing and sending (explicit keys and an explicit --yes; this script never creates a key):
//   sign   --prepared prepared.json --key-file operator.key            -> prints the operator's signature (offline)
//   send   --prepared prepared.json --rpc A --rpc B --key-file K --yes [--signature 0x..]
//          the pinned code and the current sequence are checked with agreeing reads first; the transaction goes to the
//          first --rpc. Without --signature K must be the operator (publish/withdraw); with it K only pays gas
//          (publishFor/withdrawFor; an ERC-1271 wallet operator's signature works there). A smart-contract wallet that
//          publishes directly executes prepared.json's `call` from the wallet itself, with the wallet's own tooling.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createPublicClient, createWalletClient, http, keccak256, encodeFunctionData, defineChain } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import * as si from '../../network/service-index.mjs';
import { rpcEndpoint } from '../../network/rpc-identity.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
export const SOURCE = path.join(ROOT, 'contracts', 'EnclaveServiceIndex.sol');

/** The reviewed source, compiled as the repo's deploy pipeline compiles: -> { abi, bytecode, deployedBytecode, codeHash }. */
export function compileServiceIndex() {
  const solc = createRequire(import.meta.url)('solc');
  const out = JSON.parse(solc.compile(JSON.stringify({ language: 'Solidity',
    sources: { 'contracts/EnclaveServiceIndex.sol': { content: fs.readFileSync(SOURCE, 'utf8') } },
    settings: { viaIR: true, optimizer: { enabled: true, runs: 200 }, outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object'] } } } })));
  const errors = (out.errors || []).filter((e) => e.severity === 'error');
  if (errors.length) throw new Error(errors.map((e) => e.formattedMessage).join('\n'));
  const c = out.contracts['contracts/EnclaveServiceIndex.sol'].EnclaveServiceIndex;
  const deployedBytecode = '0x' + c.evm.deployedBytecode.object;
  return { abi: c.abi, bytecode: '0x' + c.evm.bytecode.object, deployedBytecode, codeHash: keccak256(deployedBytecode) };
}

function parse(argv) {
  const o = { _: [] }, multi = new Set(['rpc', 'kind', 'endpoint', 'key', 'lookup']);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) { o._.push(a); continue; }
    const k = a.slice(2);
    if (k === 'yes') { o.yes = true; continue; }
    const v = argv[++i]; if (v === undefined) throw new Error(`--${k} needs a value`);
    if (multi.has(k)) (o[k] ||= []).push(v); else o[k] = v;
  }
  return o;
}
const need = (o, ...ks) => { for (const k of ks) if (o[k] === undefined) throw new Error(`--${k} is required`); };
/** Exactly one --kind (it repeats only for list), as a known kind name. */
const oneKind = (o) => {
  if (!Array.isArray(o.kind) || o.kind.length !== 1 || !si.SERVICE_KINDS[o.kind[0]]) throw new Error(`exactly one --kind: ${Object.keys(si.SERVICE_KINDS).join(', ')}`);
  return o.kind[0];
};
const chainOf = (id, url) => defineChain({ id, name: `chain-${id}`, nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 }, rpcUrls: { default: { http: [url] } } });
/** The --rpc list as labelled peers (labels are origins: a path or query may hold an API key). */
export const peersFor = (rpcs, chainId) => {
  if (!Array.isArray(rpcs) || rpcs.length < 2 || rpcs.length > 16) throw new Error('two to sixteen independently chosen --rpc endpoints are required');
  const seen = new Set();
  return rpcs.map((u) => {
    // network/rpc-identity.mjs: different paths, keys, ports, case, trailing dots or IPv6 spellings of one public host
    // cannot create extra votes; local test chains use distinct loopback ports, and aliases on one port count once
    let identity;
    try { ({ identity } = rpcEndpoint(u)); }
    catch (e) { throw new Error(e.code === 'url' || e.code === 'host' ? 'invalid RPC URL' : 'RPCs require HTTPS (HTTP only on loopback), without credentials or fragments'); }
    if (seen.has(identity)) throw new Error('RPC peers must use distinct public hosts or distinct loopback test ports');
    seen.add(identity);
    return { label: si.rpcLabel(u), client: createPublicClient({ chain: chainOf(chainId, u), transport: http(u, { timeout: 8000, retryCount: 0 }) }) };
  });
};
const readPolicy = (o) => ({ ...(o['deadline-ms'] ? { deadlineMs: Number(o['deadline-ms']) } : {}), ...(o['timeout-ms'] ? { requestTimeoutMs: Number(o['timeout-ms']) } : {}) });
const readPin = (f) => si.validateIndexPin(JSON.parse(fs.readFileSync(f, 'utf8')));
const json = (v) => JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? x.toString() : x), 1);
const writeNew = (f, text) => fs.writeFileSync(f, text, { flag: 'wx' });
const keyOf = (f) => { const k = fs.readFileSync(f, 'utf8').trim(); if (!/^0x[0-9a-fA-F]{64}$/.test(k)) throw new Error(`${f} is not a hex private key`); return privateKeyToAccount(k); };

/** The pinned code and (operator, slot)'s current sequence, from one agreed snapshot. */
async function indexState(peers, pin, operator, slot, policy) {
  const r = await si.agreedRead({ peers, chainId: pin.chainId, ...policy, read: async (c, blockNumber, call) => {
    const code = await call('code', () => c.getCode({ address: pin.address, blockNumber }));
    const codeHash = code ? keccak256(code) : null;
    return { codeHash, sequence: codeHash === pin.codeHash ? await call('sequence', () => c.readContract({ address: pin.address, abi: si.SERVICE_INDEX_ABI, functionName: 'sequenceOf', args: [operator, slot], blockNumber })) : null };
  } });
  if (r.value.codeHash !== pin.codeHash) throw new si.QuorumError(`the agreed code at ${pin.address} is not the pinned ${pin.codeHash}`, r.evidence);
  return { sequence: BigInt(r.value.sequence), blockNumber: r.blockNumber, evidence: r.evidence };
}
const lookupArg = (v) => { const [operator, slot] = String(v).split(':'); return { operator, ...(slot !== undefined ? { slot: Number(slot) } : {}) }; };

export async function main(argv = process.argv.slice(2), out = (s) => process.stdout.write(s + '\n')) {
  const [cmd, ...rest] = argv, o = parse(rest);
  if (cmd === 'pin') {
    need(o, 'index', 'chain-id');
    const chainId = Number(o['chain-id']), built = compileServiceIndex();
    const r = await si.agreedRead({ peers: peersFor(o.rpc, chainId), chainId, ...readPolicy(o), read: async (c, blockNumber, call) => {
      const code = await call('code', () => c.getCode({ address: o.index, blockNumber })); return { codeHash: code ? keccak256(code) : null }; } });
    if (r.value.codeHash !== built.codeHash) throw new si.QuorumError(`the agreed code at ${o.index} (${r.value.codeHash || 'none'}) is not the reviewed source's ${built.codeHash}`, r.evidence);
    const pin = si.validateIndexPin({ chainId, address: o.index, codeHash: built.codeHash });
    if (o.out) writeNew(o.out, json(pin) + '\n');
    out(json({ ...pin, checkedAtBlock: r.blockNumber, source: path.relative(ROOT, SOURCE), evidence: r.evidence }));
  } else if (cmd === 'list') {
    need(o, 'pin');
    const pin = readPin(o.pin);
    const cursor = o.resume ? JSON.parse(fs.readFileSync(o.resume, 'utf8')) : null;
    const r = await si.readServiceIndex({ peers: peersFor(o.rpc, pin.chainId), pin, kinds: o.kind || Object.keys(si.SERVICE_KINDS), window: Number(o.window || 256),
                                          cursor, lookups: (o.lookup || []).map(lookupArg), ...readPolicy(o) });
    out(json(r));
  } else if (cmd === 'lookup') {
    need(o, 'pin', 'operator');
    const pin = readPin(o.pin);
    const r = await si.readServiceIndex({ peers: peersFor(o.rpc, pin.chainId), pin, kinds: [], lookups: [{ operator: o.operator, ...(o.slot !== undefined ? { slot: Number(o.slot) } : {}) }], ...readPolicy(o) });
    out(json({ blockNumber: r.blockNumber, blockHash: r.blockHash, lookups: r.lookups, evidence: r.evidence, notice: r.notice }));
  } else if (cmd === 'descriptor') {
    need(o, 'operator', 'out');
    const kind = oneKind(o);
    const extra = Object.fromEntries((o.key || []).map((kv) => { const i = kv.indexOf('='); if (i < 1) throw new Error('--key name=value'); return [kv.slice(0, i), kv.slice(i + 1)]; }));
    const d = { format: 'enclave-service-descriptor/v1', operator: o.operator.toLowerCase(), kind, endpoints: (o.endpoint || []).map(si.validateEndpoint), ...(Object.keys(extra).length ? { keys: extra } : {}) };
    const bytes = Buffer.from(JSON.stringify(d) + '\n');
    if (bytes.length > si.LIMITS.descriptor) throw new Error('descriptor is over 4 KiB');
    writeNew(o.out, bytes);
    out(json({ out: o.out, descriptor: si.descriptorHash(bytes), bytes: bytes.length }));
  } else if (cmd === 'prepare-publish' || cmd === 'prepare-withdraw') {
    need(o, 'pin', 'operator', 'slot', 'out');
    const pin = readPin(o.pin), operator = o.operator.toLowerCase(), slot = Number(o.slot);
    if (!/^0x[0-9a-f]{40}$/.test(operator)) throw new Error('--operator must be an address');
    const sequence = o.sequence ? BigInt(o.sequence) : (await indexState(peersFor(o.rpc, pin.chainId), pin, operator, slot, readPolicy(o))).sequence + 1n;
    let prepared;
    if (cmd === 'prepare-publish') {
      const descriptor = o.descriptor ? si.descriptorHash(fs.readFileSync(o.descriptor)) : '0x' + '0'.repeat(64);
      const ad = si.validateAdInput({ slot, kind: oneKind(o), endpoints: o.endpoint, ttlSec: Math.round(Number(o['ttl-days'] || 30) * 86400), descriptor });
      const expiresAt = BigInt(Math.floor(Date.now() / 1000) + ad.ttlSec);
      const typed = si.publishTypedData({ chainId: pin.chainId, index: pin.address, operator, slot, kind: ad.kind, sequence, expiresAt, descriptor: ad.descriptor, endpoints: ad.endpoints });
      prepared = { action: 'publish', pin, typedData: typed,
        call: { to: pin.address, from: operator, data: encodeFunctionData({ abi: si.SERVICE_INDEX_ABI, functionName: 'publish', args: [slot, ad.kind, si.AD_VERSION, sequence, expiresAt, ad.descriptor, ad.endpoints] }) } };
    } else {
      prepared = { action: 'withdraw', pin, typedData: si.withdrawTypedData({ chainId: pin.chainId, index: pin.address, operator, slot, sequence }),
        call: { to: pin.address, from: operator, data: encodeFunctionData({ abi: si.SERVICE_INDEX_ABI, functionName: 'withdraw', args: [slot, sequence] }) } };
    }
    writeNew(o.out, json(prepared) + '\n');
    out(json({ out: o.out, action: prepared.action, sequence, note: 'nothing was signed or sent; review, then sign (offline) and send' }));
  } else if (cmd === 'sign') {
    need(o, 'prepared', 'key-file');
    const p = JSON.parse(fs.readFileSync(o.prepared, 'utf8')), acct = keyOf(o['key-file']);
    if (acct.address.toLowerCase() !== p.typedData.message.operator.toLowerCase()) throw new Error(`the key is ${acct.address}, not the ad's operator ${p.typedData.message.operator}`);
    out(await acct.signTypedData(p.typedData));
  } else if (cmd === 'send') {
    need(o, 'prepared', 'key-file', 'rpc');
    if (!o.yes) throw new Error('send writes to the chain: add --yes after reviewing the prepared file');
    const p = JSON.parse(fs.readFileSync(o.prepared, 'utf8')), pin = si.validateIndexPin(p.pin), acct = keyOf(o['key-file']), m = p.typedData.message;
    // the code and the sequence from agreeing RPCs, not from the one the transaction is sent through
    const state = await indexState(peersFor(o.rpc, pin.chainId), pin, m.operator.toLowerCase(), Number(m.slot), readPolicy(o));
    if (BigInt(m.sequence) <= state.sequence) throw new Error(`sequence ${m.sequence} is already used (the chain is at ${state.sequence}): prepare again`);
    const chain = chainOf(pin.chainId, o.rpc[0]);
    const pub = createPublicClient({ chain, transport: http(o.rpc[0]) }), wallet = createWalletClient({ account: acct, chain, transport: http(o.rpc[0]) });
    if ((await pub.getChainId()) !== pin.chainId) throw new Error('the sending RPC is on another chain');
    let req;
    if (o.signature) {
      req = p.action === 'publish'
        ? { functionName: 'publishFor', args: [m.operator, m.slot, m.kind, m.version, BigInt(m.sequence), BigInt(m.expiresAt), m.descriptor, m.endpoints, o.signature] }
        : { functionName: 'withdrawFor', args: [m.operator, m.slot, BigInt(m.sequence), o.signature] };
    } else {
      if (acct.address.toLowerCase() !== m.operator.toLowerCase()) throw new Error('without --signature the key must be the operator\'s');
      req = p.action === 'publish'
        ? { functionName: 'publish', args: [m.slot, m.kind, m.version, BigInt(m.sequence), BigInt(m.expiresAt), m.descriptor, m.endpoints] }
        : { functionName: 'withdraw', args: [m.slot, BigInt(m.sequence)] };
    }
    const { request } = await pub.simulateContract({ address: pin.address, abi: si.SERVICE_INDEX_ABI, account: acct, ...req });
    const hash = await wallet.writeContract(request);
    const r = await pub.waitForTransactionReceipt({ hash });
    if (r.status !== 'success') throw new Error(`reverted: ${hash}`);
    out(json({ sent: req.functionName, hash, block: r.blockNumber }));
  } else {
    throw new Error('commands: pin | list | lookup | descriptor | prepare-publish | prepare-withdraw | sign | send');
  }
}
if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url)
  main().catch((e) => {
    process.stderr.write(`service-index: ${e.shortMessage || e.message}\n`);
    // a refusal for lack of agreement prints what each RPC did; it is not "no services"
    if (e instanceof si.QuorumError) { process.stdout.write(json({ refused: e.message, evidence: e.evidence }) + '\n'); process.exit(2); }
    process.exit(1);
  });
