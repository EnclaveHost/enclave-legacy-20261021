// scripts/deploy-secret-vault-v2.mjs: the vault compiles under EIP-170, and against a real chain (anvil) the script deploys it
// over a given address book and Enclave wallet, verifies both, and only PRINTS the governance transaction (never sends it).
//   run: node --test test/custody-v2-deploy.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import { createWalletClient, http, decodeFunctionData, hexToString, encodeAbiParameters, keccak256, toHex, stringToHex } from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { anvilAvailable, startAnvil, compileContracts } from "./helpers/custody-rig.mjs";
import { deploySecretVaultV2, compileSecretVaultV2, compileHostOwnership, EIP170, NETWORKS } from "../scripts/deploy-secret-vault-v2.mjs";

test("the v2 vault fits EIP-170", () => {
  const { size } = compileSecretVaultV2();
  assert.ok(size > 0 && size <= EIP170, `runtime ${size} bytes`);
});

test("Base: the book and the Enclave wallet are the spec's", () => {
  assert.equal(NETWORKS.base.book, "0xab214342d5A490150A4A977063A2f88E21F80907");
  assert.equal(NETWORKS.base.enclaveOwner, "0x0b2d009c0c9Af05b12100D77F3c815fea822eE61");
});

test("a dry run sends nothing", async () => {
  const logs = [];
  const r = await deploySecretVaultV2({ book: NETWORKS.base.book, enclaveOwner: NETWORKS.base.enclaveOwner, hostOwnership: "0x"+"12".repeat(20), dryRun: true, log: (m) => logs.push(m) });
  assert.equal(r, null);
  assert.match(logs.join("\n"), /dry run: nothing sent/);
  await assert.rejects(deploySecretVaultV2({ book: NETWORKS.base.book, enclaveOwner: "", dryRun: true, log: () => {} }), /ENCLAVE_OWNER/);
});

test("deploy on anvil: reads back book and enclaveOwner, prints the book step, and machineHash matches the spec's encoding",
     { skip: anvilAvailable() ? false : "anvil not installed" }, async () => {
  const a = await startAnvil();
  try {
    const key = generatePrivateKey(), acct = privateKeyToAccount(key);
    await a.client.request({ method: "anvil_setBalance", params: [acct.address, "0x56bc75e2d63100000"] });
    const C = compileContracts();
    const w = createWalletClient({ account: acct, chain: a.chain, transport: http(a.url) });
    const book = (await a.client.waitForTransactionReceipt({ hash: await w.deployContract({ abi: C.book.abi, bytecode: C.book.bytecode }) })).contractAddress;
    const enclaveOwner = "0x0b2d009c0c9Af05b12100D77F3c815fea822eE61";
    const registry = (await a.client.waitForTransactionReceipt({hash:await w.deployContract({abi:C.registry.abi,bytecode:C.registry.bytecode})})).contractAddress;
    const ledger = (await a.client.waitForTransactionReceipt({hash:await w.deployContract({abi:C.ledger.abi,bytecode:C.ledger.bytecode})})).contractAddress;
    await a.client.waitForTransactionReceipt({hash:await w.writeContract({address:book,abi:C.book.abi,functionName:"set",args:[stringToHex("deployments",{size:32}),ledger]})});
    const ownershipArtifact = compileHostOwnership();
    const hostOwnership = (await a.client.waitForTransactionReceipt({hash:await w.deployContract({abi:ownershipArtifact.abi,bytecode:ownershipArtifact.bytecode,args:[registry]})})).contractAddress;
    const logs = [];
    const r = await deploySecretVaultV2({ rpc: a.url, chain: a.chain, privateKey: key, book, enclaveOwner, hostOwnership, log: (m) => logs.push(m) });
    assert.match(logs.join("\n"), /GOVERNANCE STEP \(not sent\)/);
    const { args } = decodeFunctionData({ abi: [{ type: "function", name: "set", inputs: [{ type: "bytes32" }, { type: "address" }], outputs: [] }], data: r.setData });
    assert.equal(hexToString(args[0], { size: 32 }), "secretVaultV2");
    assert.equal(args[1], r.vault);
    assert.equal(await a.client.readContract({ address: book, abi: C.book.abi, functionName: "addr", args: [args[0]] }), "0x0000000000000000000000000000000000000000");

    // machineHash (spec §1.1) from viem's ABI encoder equals the contract's
    const { abi } = compileSecretVaultV2();
    const m = { identity: acct.address, encKey: keccak256(toHex("enc")), endpoint: "https://custodian.example", chipId: keccak256(toHex("chip")),
                registryId: keccak256(toHex("https://host.example")), measurement: keccak256(toHex("m")) };
    const want = keccak256(encodeAbiParameters([{ type: "address" }, { type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }],
      [m.identity, m.encKey, keccak256(toHex(m.endpoint)), m.chipId, m.registryId, m.measurement]));
    assert.equal(await a.client.readContract({ address: r.vault, abi, functionName: "machineHash", args: [m] }), want);
  } finally { a.stop(); }
});
