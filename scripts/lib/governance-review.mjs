import { encodeAbiParameters, decodeAbiParameters, keccak256, toFunctionSelector, zeroAddress } from 'viem';

// Exact revision profiles. Unknown revisions fail closed. A snapshot is review
// input, not evidence that bytecode, dependency governance or economics is safe.
export const profiles = Object.freeze({
  ledger16: {
    schema: ['deploymentsSchema', 16n], nomination: 'setOwner(address)',
    getters: [['deploymentsSchema','uint256'],['retired','bool'],['importsSealed','bool'],
      ['usdc','address'],['registry','address'],['payout','address'],['ethUsdFeed','address'],
      ['leaseSec','uint64'],['maxGpuMilli','uint16'],['maxFeePerSec6','uint256'],
      ['runnerBps','uint16'],['claimBond6','uint256'],['bondExitDelay','uint64'],
      ['prover','address'],['proofRequiredFrom','uint64'],['feeRouter','address'],['bandwidthRouter','address']],
    dependencies: ['usdc','registry','ethUsdFeed','prover','feeRouter','bandwidthRouter'],
  },
  proof2: {
    schema: ['proofSchema', 2n], nomination: 'transferOwnership(address)',
    getters: [['proofSchema','uint256'],['deployments','address'],['registry','address'],['proofWindowSec','uint64']],
    dependencies: ['deployments','registry'],
  },
  catalog9: {
    schema: ['catalogSchema', 9n], nomination: 'transferOwnership(address)',
    getters: [['catalogSchema','uint256'],['importsSealed','bool'],['maxFeePerSec6','uint256']],
    dependencies: [],
  },
});
const abi = types => types.map(type => ({type}));
const json = value => JSON.parse(JSON.stringify(value, (_k,v) => typeof v === 'bigint' ? String(v) : v));

export function configurationHash(chainId, target, codeHash, readings) {
  let hash = keccak256(encodeAbiParameters(abi(['uint256','address','bytes32']), [BigInt(chainId),target,codeHash]));
  for (const {selector, raw} of readings) {
    hash = keccak256(encodeAbiParameters(abi(['bytes32','bytes4','bytes32']), [hash,selector,keccak256(raw)]));
  }
  return hash;
}

async function getter(client, target, name, type, blockNumber) {
  const selector = toFunctionSelector(`${name}()`);
  const {data: raw} = await client.call({to:target,data:selector,blockNumber});
  // All supported getters return one static ABI word. Refuse truncation,
  // trailing data and noncanonical booleans/integers before committing it.
  if (!/^0x[\da-f]{64}$/i.test(raw || '')) throw Error(`invalid getter response: ${name}`);
  const [value] = decodeAbiParameters(abi([type]),raw);
  if (encodeAbiParameters(abi([type]),[value]).toLowerCase() !== raw.toLowerCase()) throw Error(`noncanonical getter: ${name}`);
  return {name,type,selector,raw:raw.toLowerCase(),value};
}

export async function captureGovernanceReview(client, {target, profile, chainId, blockNumber}) {
  const p = profiles[profile];
  if (!p) throw Error('unsupported governance profile');
  if (blockNumber === undefined) throw Error('fixed block required');
  const code = await client.getCode({address:target,blockNumber});
  if (!code || code === '0x') throw Error('target code missing');
  const codeHash = keccak256(code);
  const readings = [];
  // Keep per-RPC load bounded; the outer caller compares complete snapshots
  // from independent RPC origins at exactly the same recent block.
  for (const [name,type] of p.getters) readings.push(await getter(client,target,name,type,blockNumber));
  const values = Object.fromEntries(readings.map(r => [r.name,r.value]));
  if (values[p.schema[0]] !== p.schema[1]) throw Error('unsupported contract revision');
  const owner = (await getter(client,target,'owner','address',blockNumber)).value;
  const pendingOwner = (await getter(client,target,'pendingOwner','address',blockNumber)).value;
  const dependencies = [];
  for (const name of p.dependencies) {
    const address = values[name];
    if (address.toLowerCase() === zeroAddress) { dependencies.push({name,address,enabled:false}); continue; }
    const depCode = await client.getCode({address,blockNumber});
    if (!depCode || depCode === '0x') throw Error(`dependency code missing: ${name}`);
    dependencies.push({name,address,enabled:true,codeHash:keccak256(depCode),review:'required: bytecode, proxy/upgrade paths and administrative state'});
  }
  const blockers = [];
  if (pendingOwner.toLowerCase() !== zeroAddress) blockers.push('An ownership nomination is already pending.');
  if ('importsSealed' in values && !values.importsSealed) blockers.push('Imports have not been sealed.');
  if (profile === 'ledger16') {
    if (values.retired) blockers.push('The ledger is already retired.');
    if (values.maxGpuMilli !== 1000) blockers.push('The configured GPU cap excludes otherwise valid allocations.');
    if (values.runnerBps === 0) blockers.push('Runner earnings are disabled for new deployments.');
    if (values.prover.toLowerCase() === zeroAddress) blockers.push('Proof verifier is not bound.');
    if (values.proofRequiredFrom === 0n) blockers.push('Proven-time metering is disabled.');
    if (values.feeRouter.toLowerCase() === zeroAddress || values.bandwidthRouter.toLowerCase() === zeroAddress)
      blockers.push('A one-time router binding remains unset; sealing would make it permanently unavailable.');
  }
  return json({profile,target,chainId,blockNumber:String(blockNumber),codeHash,owner,pendingOwner,
    configurationHash:configurationHash(chainId,target,codeHash,readings),selectors:readings.map(r=>r.selector),
    readings,dependencies,blockers,nominationFunction:p.nomination,
    status:'review-required; no transaction prepared or sent',
    limitations:['Code hashes identify bytecode; they do not establish that it is immutable or safe.',
      'A target seal checks this target only. Dependency code and configuration require their own disposition.',
      'Per-record catalog approval is not enumerated; clients and independent host policies must ignore global moderation.',
      'External chain, token and oracle control is not removed by sealing Enclave governance.']});
}
