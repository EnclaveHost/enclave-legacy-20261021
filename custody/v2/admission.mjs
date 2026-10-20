// An optional committee-local policy selected in the measured image. These
// wallets are accepted host owners, never payout addresses or the relay's list.
// Owners explicitly trust this set's independence; this is not a Sybil-proof
// permissionless membership claim. Any group can build its own policy.
export function independentOwners(value, enclaveOwner) {
  if (!Array.isArray(value) || value.length < 3 || value.length > 64) throw Error('independent admission requires 3..64 accepted owner wallets');
  const owners=value.map(x=>String(x).toLowerCase());
  if(owners.some(x=>!/^0x[0-9a-f]{40}$/.test(x)||/^0x0{40}$/.test(x)||x===String(enclaveOwner).toLowerCase())||new Set(owners).size!==owners.length)
    throw Error('independent admission requires distinct non-Enclave owners');
  return Object.freeze(owners);
}
export function ownerAdmissionCheck(owners) {
  const allowed=new Set(owners);
  return async ({registry})=>({ok:allowed.has(String(registry?.owner).toLowerCase()),reason:'accepted owner is outside the measured committee policy'});
}
