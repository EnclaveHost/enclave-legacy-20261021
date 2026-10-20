// Shared operator-selected adapter plan and verified-copy accounting.
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).every(k=>keys.includes(k));
export function validateStoragePlan(plan) {
  if(!exact(plan,['version','minimumCopies','replicas'])||plan.version!==1||!Array.isArray(plan.replicas)||
    plan.replicas.length<2||plan.replicas.length>8||!Number.isInteger(plan.minimumCopies)||
    plan.minimumCopies<2||plan.minimumCopies>plan.replicas.length)throw Error('storage plan needs 2–8 adapters and a minimum of 2 verified copies');
  const hosts=new Set(),audiences=new Set();
  const replicas=plan.replicas.map(r=>{
    if(!exact(r,['upload','audience','gateway'])||typeof r.upload!=='string'||typeof r.gateway!=='string'||
      !/^0x[0-9a-f]{64}$/.test(r.audience||'')||/^0x0{64}$/.test(r.audience))throw Error('invalid storage adapter');
    const u=new URL(r.upload),g=new URL(r.gateway);
    for(const x of [u,g])if(x.protocol!=='https:'||x.username||x.password||x.search||x.hash)throw Error('storage adapters require HTTPS without credentials, query or fragment');
    if(u.pathname!=='/add-json'||g.pathname.replace(/\/$/,'')!=='/ipfs'||u.origin!==g.origin)throw Error('upload and readback must address the same adapter origin');
    // Distinct hostnames and deployments are necessary but do not prove
    // different operators. Aliases for one adapter cannot count twice.
    if(hosts.has(u.hostname)||audiences.has(r.audience))throw Error('storage adapters need distinct hostnames and deployment audiences');
    hosts.add(u.hostname);audiences.add(r.audience);
    return {upload:u.href,audience:r.audience,gateway:g.href.replace(/\/$/,'')};
  });
  return {version:1,minimumCopies:plan.minimumCopies,replicas};
}
export function replicaOptions({timeoutMs=240000,fetchImpl=fetch}={}) {
  if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>260000)throw Error('invalid storage deadline');
  return {timeoutMs,fetchImpl};
}
export async function collectReplicas(plan,pkg,operation) {
  const results=await Promise.all(plan.replicas.map(async(replica,index)=>{
    try {await operation(replica,index);return {index,...replica,verified:true};}
    catch(e){return {index,...replica,verified:false,reason:e?.name==='TimeoutError'?'deadline exceeded':'upload or exact-byte readback failed'};}
  }));
  const copies=results.filter(r=>r.verified),failures=results.filter(r=>!r.verified);
  const report={version:1,cid:pkg.cid,sha256:pkg.sha256,minimumCopies:plan.minimumCopies,
    verifiedCopies:copies.length,copies,failures,checkedAt:new Date().toISOString(),independentOperatorsVerified:false};
  if(copies.length<plan.minimumCopies){const e=Error(`storage availability requirement not met (${copies.length}/${plan.minimumCopies} verified copies)`);e.report=report;throw e;}
  return report;
}
