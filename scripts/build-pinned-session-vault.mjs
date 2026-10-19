#!/usr/bin/env node
// Compile only. No wallet, RPC, mutable address book, deployment or activation.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import solc from 'solc';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export function compilePinnedSessionVault() {
  const sources = Object.fromEntries(['SessionVault.sol', 'PinnedSessionVaultFactory.sol'].map(name =>
    [name, { content: fs.readFileSync(path.join(root, 'contracts', name), 'utf8') }]));
  const settings = { optimizer: { enabled: true, runs: 1 }, viaIR: true,
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object', 'evm.bytecode.linkReferences',
      'evm.deployedBytecode.object', 'evm.deployedBytecode.immutableReferences', 'evm.deployedBytecode.linkReferences'] } } };
  const result = JSON.parse(solc.compile(JSON.stringify({ language: 'Solidity', sources, settings })));
  const errors = (result.errors || []).filter(x => x.severity === 'error');
  if (errors.length) throw new Error(errors.map(x => x.formattedMessage).join('\n'));
  const contracts = {};
  for (const [file, name] of [['SessionVault.sol', 'SessionVaultLib'], ['SessionVault.sol', 'SessionVault'],
    ['PinnedSessionVaultFactory.sol', 'PinnedSessionAuthority'], ['PinnedSessionVaultFactory.sol', 'PinnedSessionVaultFactory']]) {
    const artifact = result.contracts[file][name];
    const runtimeBytes = artifact.evm.deployedBytecode.object.length / 2;
    if (runtimeBytes > 24576) throw new Error(`${name} exceeds EIP-170: ${runtimeBytes}`);
    if (artifact.evm.bytecode.object.length / 2 > 49152) throw new Error(`${name} exceeds EIP-3860`);
    contracts[name] = { source: file, ...artifact, runtimeBytes };
  }
  return { compiler: solc.version(), settings, sourceSha256: Object.fromEntries(Object.entries(sources)
    .map(([name, s]) => [name, createHash('sha256').update(s.content).digest('hex')])), contracts };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const directory = process.argv[2];
  if (!directory) throw new Error('usage: node scripts/build-pinned-session-vault.mjs NEW_OUTPUT_DIRECTORY');
  fs.mkdirSync(directory, { recursive: false });
  const result = compilePinnedSessionVault();
  fs.writeFileSync(path.join(directory, 'artifacts.json'), JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify({ compiler: result.compiler, sizes: Object.fromEntries(Object.entries(result.contracts)
    .map(([name, c]) => [name, c.runtimeBytes])), transactionsSent: 0 }));
}
