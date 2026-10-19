// The digests EnclaveSecretVaultV2 checks signatures over (docs/security/secret-custody-v2-spec.md §1.2). Every signature
// is EIP-191 personal_sign over the 32-byte digest. test/custody-v2-contract.test.mjs pins these to the contract's own.
import { keccak256, encodeAbiParameters, toBytes, bytesToHex, recoverMessageAddress } from "viem";

const T = (type) => ({ type });
export function machineHash(m) {
  return keccak256(encodeAbiParameters([T("address"), T("bytes32"), T("bytes32"), T("bytes32"), T("bytes32"), T("bytes32")],
    [m.identity, m.encKey, keccak256(toBytes(m.endpoint)), m.chipId, m.registryId, m.measurement]));
}
const hx = (b) => (typeof b === "string" ? b : bytesToHex(b));
export const hostDigest = ({ chainId, vault, machine }) =>
  keccak256(encodeAbiParameters([T("string"), T("uint256"), T("address"), T("bytes32")], ["enclave-custody-v2 host", BigInt(chainId), vault, machineHash(machine)]));
export const genesisDigest = ({ chainId, vault, committeeId, Y, machine, codeSet }) =>
  keccak256(encodeAbiParameters([T("string"), T("uint256"), T("address"), T("bytes32"), T("bytes32"), T("bytes32"), T("bytes32")],
    ["enclave-custody-v2 genesis", BigInt(chainId), vault, committeeId, keccak256(hx(Y)), machineHash(machine), keccak256(encodeAbiParameters([T("bytes32[]")], [codeSet]))]));
export const handoverDigest = ({ chainId, vault, committeeId, fromEpoch, next, dealerIndices }) =>
  keccak256(encodeAbiParameters([T("string"), T("uint256"), T("address"), T("bytes32"), T("uint32"), T("bytes32"), T("bytes32")],
    ["enclave-custody-v2 handover", BigInt(chainId), vault, committeeId, fromEpoch,
     keccak256(encodeAbiParameters([T("bytes32[]")], [next.map(machineHash)])), keccak256(encodeAbiParameters([T("uint32[]")], [dealerIndices]))]));
export const independentGenesisDigest = ({ chainId, vault, committeeId, commitments, machines, codeSet }) =>
  keccak256(encodeAbiParameters([T("string"), T("uint256"), T("address"), T("bytes32"), T("bytes32"), T("bytes32"), T("bytes32")],
    ["enclave-custody-v2 independent genesis", BigInt(chainId), vault, committeeId, keccak256(hx(commitments)),
     keccak256(encodeAbiParameters([T("bytes32[]")], [machines.map(machineHash)])), keccak256(encodeAbiParameters([T("bytes32[]")], [codeSet]))]));
export const independentPlanDigest = ({chainId,vault,salt,machines,codeSet}) =>
  keccak256(encodeAbiParameters([T("string"),T("uint256"),T("address"),T("bytes32"),T("bytes32"),T("bytes32")],
    ["enclave-custody-v2 independent plan",BigInt(chainId),vault,salt,
      keccak256(encodeAbiParameters([T("bytes32[]")],[machines.map(machineHash)])),keccak256(encodeAbiParameters([T("bytes32[]")],[codeSet]))]));
export const dealDigest = ({ chainId, vault, committeeId, toEpoch, dealerIndex, dealCommitments, sealed }) =>
  keccak256(encodeAbiParameters([T("string"), T("uint256"), T("address"), T("bytes32"), T("uint32"), T("uint32"), T("bytes32"), T("bytes32")],
    ["enclave-custody-v2 deal", BigInt(chainId), vault, committeeId, toEpoch, dealerIndex, keccak256(hx(dealCommitments)), keccak256(encodeAbiParameters([T("bytes[]")], [sealed.map(hx)]))]));
export const ackDigest = ({ chainId, vault, committeeId, toEpoch, newCommitments }) =>
  keccak256(encodeAbiParameters([T("string"), T("uint256"), T("address"), T("bytes32"), T("uint32"), T("bytes32")],
    ["enclave-custody-v2 ack", BigInt(chainId), vault, committeeId, toEpoch, keccak256(hx(newCommitments))]));
export const codeDigest = ({ chainId, vault, committeeId, epoch, measurement, add }) =>
  keccak256(encodeAbiParameters([T("string"), T("uint256"), T("address"), T("bytes32"), T("uint32"), T("bytes32"), T("bool")],
    ["enclave-custody-v2 code", BigInt(chainId), vault, committeeId, epoch, measurement, !!add]));
export const committeeIdOf = ({ chainId, vault, salt, Y }) =>
  keccak256(encodeAbiParameters([T("uint256"), T("address"), T("bytes32"), T("bytes32")], [BigInt(chainId), vault, salt, keccak256(hx(Y))]));

// account: a viem local account; -> 65-byte hex signature (viem's are low-s)
export const signDigest = (account, digest) => account.signMessage({ message: { raw: digest } });
export const recoverDigest = (digest, signature) => recoverMessageAddress({ message: { raw: digest }, signature }).then((a) => a.toLowerCase()).catch(() => null);
