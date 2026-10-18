# Custody v2: interfaces

The exact interfaces of [secret-custody-v2.md](secret-custody-v2.md). Byte formats of the cryptography are in
`custody/v2/protocol.mjs` (the reference), pinned by `test/fixtures/custody-v2-vectors.json`. This file covers the
contract, the custodian HTTP API, guestd/supervisor authorization and the guest's unlock rules.

## 1. `EnclaveSecretVaultV2` (Base)

Source migration proposal (not the live deployed vault): wallet-based admission requires a new vault and compatible measured custodian runtime. Existing committees and encrypted bundles must be migrated explicitly before changing discovery.

No owner, no admin, no proxy. Constructor: `(address book, address enclaveOwner, address hostOwnership)`.
- `book` is the EnclaveAddressBook (`addr(bytes32)`), as in v1, for deployment/session state.
- `hostOwnership` is a deployed `EnclaveHostOwnership`. It and its registry are pinned immutably. Registry operators nominate initial wallet owners; those wallets must accept.
- `enclaveOwner` is `0x0b2d009c0c9Af05b12100D77F3c815fea822eE61` on Base.

### 1.1 Machines and seats

```solidity
struct Machine {
    address identity;      // secp256k1 key generated in the custodian's TEE (signs everything below)
    bytes32 encKey;        // X25519 public key (HPKE recipient for deals; challenge identity)
    string  endpoint;      // https origin of the custodian's API, <= 190 bytes
    bytes32 chipId;        // sha256(SNP report CHIP_ID, 64 bytes)
    bytes32 registryId;    // the HOST's EnclaveRegistry id (keccak256(bytes(host endpoint)))
    bytes32 measurement;   // sha256(SNP launch measurement, 48 bytes)
}
machineHash(m) = keccak256(abi.encode(m.identity, m.encKey, keccak256(bytes(m.endpoint)), m.chipId, m.registryId, m.measurement))
```

**Enclave-owned** is computed on chain, never supplied:
1. `registry = hostRegistry`, pinned from `hostOwnership.registry()` at construction.
2. Read `registry.get(registryId)`, decoding the stable operator/active prefix
   `(string endpoint, string repo, bytes32 measurement, address operator, uint64 registeredAt, uint64 lastSeen, bool active)`. Later schemas append fields, so this prefix holds.
3. The entry must be `active`.
4. The host binding signature `hostSig` must recover to `operator`, over
   `hostDigest(m) = keccak256(abi.encode("enclave-custody-v2 host", block.chainid, address(this), machineHash(m)))`.
5. Read `hostOwnership.authority(registryId)`. Ownership must have been accepted (nonzero). The machine is Enclave-owned iff that owner equals `enclaveOwner`. Payout declarations confer no authority.
6. Admission and handover snapshot that classification for the epoch; a wallet transfer does not retroactively redistribute stored shares.

**Seats** are `custody/v2/protocol.mjs seatLayout`, over the machine list in order:
- all Enclave machines form one seat;
- each other machine is a seat;
- `n >= 3`: weight 1 and `t = ceil(2n/3)`;
- `n < 3`: an Enclave seat is required, `t = others + 1`, and the Enclave seat's weight is `t`;
- share indices: the Enclave seat first, `1..wE`, then the others in list order.

Limits: at most 64 seats and 96 machines. Within one list, identities are unique, and chip IDs are unique among
NON-Enclave machines (Enclave replicas may share a chip, e.g. an upgrade in place).

### 1.2 Signatures

All signatures are EIP-191 `personal_sign` over a 32-byte digest, 65 bytes, low-s. Digests:

```
hostDigest     = keccak256(abi.encode("enclave-custody-v2 host",     chainid, this, machineHash))
genesisDigest  = keccak256(abi.encode("enclave-custody-v2 genesis",  chainid, this, committeeId, keccak256(Y), machineHash, keccak256(abi.encode(codeSet))))
handoverDigest = keccak256(abi.encode("enclave-custody-v2 handover", chainid, this, committeeId, fromEpoch, keccak256(abi.encode(machineHashes)), keccak256(abi.encode(dealerIndices))))
dealDigest     = keccak256(abi.encode("enclave-custody-v2 deal",     chainid, this, committeeId, toEpoch, dealerIndex, keccak256(dealCommitments), keccak256(abi.encode(sealed))))
ackDigest      = keccak256(abi.encode("enclave-custody-v2 ack",      chainid, this, committeeId, toEpoch, keccak256(newCommitments)))
codeDigest     = keccak256(abi.encode("enclave-custody-v2 code",     chainid, this, committeeId, epoch, measurement, add))
```

The type of each field above: `chainid` uint256, `this` address, `committeeId` bytes32, `fromEpoch` / `toEpoch` /
`epoch` uint32, `dealerIndex` uint32, `measurement` bytes32, `add` bool, `codeSet` bytes32[], `machineHashes` bytes32[],
`dealerIndices` uint32[], `sealed` bytes[].

**Approval weight.** A set of approvals counts the seat weights of the distinct seats with at least one signing machine
of the CURRENT epoch. The Enclave seat counts once, however many Enclave machines sign. It must reach the current `t`.

### 1.3 Committees

```solidity
function createCommittee(bytes32 salt, Machine calldata m, bytes calldata Y, bytes32[] calldata codeSet,
                         bytes calldata identitySig, bytes calldata hostSig) external returns (bytes32 committeeId)
```
- `committeeId = keccak256(abi.encode(block.chainid, address(this), salt, keccak256(Y)))`. It must not already exist.
- `Y` is 33 bytes, `0x02` or `0x03` prefixed.
- `m` must be Enclave-owned (§1.1), and `m.measurement` must be in `codeSet`.
- `identitySig` must recover to `m.identity` over `genesisDigest`.
- The code set starts with every `codeSet` entry active at once.
- Epoch 1: machines `[m]`, `t = 1`, `W = 1`, commitments `= Y`.

```solidity
function proposeHandover(bytes32 cid, Machine[] calldata next, bytes[] calldata hostSigs, uint32[] calldata dealerIndices,
                         address[] calldata approvers, bytes[] calldata approvals) external
```
- `next` is the complete new machine list. `hostSigs[i]` binds `next[i]` to its host (§1.1). Every
  `next[i].measurement` must be in the code set and active (`activeAt <= now`).
- `dealerIndices` are exactly `t_old` distinct indices in `1..W_old`.
- `approvals[i]` is by `approvers[i]`, a current machine, over `handoverDigest`. The approval weight must be `>= t_old`.
- Stores the pending handover `toEpoch = epoch + 1`: the machines with their computed Enclave flags, the new `t` and `W`,
  the dealers, and `expires = now + 1 day`. A new proposal may replace a pending one only once that one has expired.

```solidity
function postDeal(bytes32 cid, uint32 toEpoch, uint32 dealerIndex, bytes calldata dealCommitments, bytes[] calldata sealed,
                  address dealer, bytes calldata sig) external
```
- `dealer` is a current machine holding `dealerIndex`, and `sig` is over `dealDigest`.
- `dealCommitments` is `t_new` x 33 bytes. `sealed[i]` is for `next[i]`: one HPKE envelope per new machine, holding all
  its indices (protocol `sealDeal`).
- One deal per dealer index.

```solidity
function ackHandover(bytes32 cid, uint32 toEpoch, bytes calldata newCommitments, address machine, bytes calldata sig) external
```
- `machine` is in the pending `next`, and `sig` is over `ackDigest`.
- `newCommitments[0:33] == Y`, and every ack names the same `keccak256(newCommitments)`.
- When every machine in `next` has acked, the epoch activates: `epoch = toEpoch`, the new machines, `t`, `W` and
  commitments. Emits `EpochActivated(cid, epoch)`.

```solidity
function proposeCode(bytes32 cid, bytes32 measurement, address[] calldata approvers, bytes[] calldata approvals) external  // activeAt = now + 7 days
function removeCode(bytes32 cid, bytes32 measurement, address[] calldata approvers, bytes[] calldata approvals) external   // immediate
```
Both need approval weight `>= t` over `codeDigest` (`add` true or false).

Views:
- `committeeOf(cid) -> (bytes Y, uint32 epoch, uint8 t, uint8 W, uint64 activatedAt)`
- `machinesOf(cid, epoch) -> (Machine[] machines, bool[] enclave)`
- `commitmentsOf(cid, epoch) -> bytes`
- `pendingOf(cid) -> (uint32 toEpoch, Machine[] next, bool[] enclave, uint8 t, uint8 W, uint32[] dealers, uint64 expires)`
- `dealOf(cid, toEpoch, dealerIndex) -> (bytes dealCommitments, bytes[] sealed)`
- `ackCount(cid, toEpoch) -> uint256`
- `codeActiveAt(cid, measurement) -> uint64` (0 = not in the set)

Only the current and pending epochs need to be readable. Older epochs may be overwritten.

### 1.4 Policies and bundles (per deployment)

As v1 (`EnclaveSecretVault.sol`), with the v2 bundle:
- owner pinning to the ledger's beneficial owner (incl. the SessionVault factory);
- `update` and `updateBySig` with expected-revision checks;
- `claimPolicy` destroys the bundle;
- `beneficialOwnerOf`.

```solidity
struct Policy { address owner; uint64 policyRev; uint64 secretRev; bytes32 committeeId; bool paused; bytes rules; }
struct Update { uint64 expectPolicyRev; bool setPolicy; bytes32 committeeId; bool paused; bytes rules;
                bool setBundle; bytes bundle; bool clear; }
policyOf(id) -> (address owner, uint64 policyRev, uint64 secretRev, bytes32 committeeId, bool paused, bytes rules)
bundleOf(id) -> (bytes32 committeeId, uint64 secretRev, bytes bundle)   // bundle = R ‖ proof ‖ nonce ‖ ct
```
- A `setBundle` bumps `secretRev` and stores the bundle under the policy's `committeeId`, which must exist.
- The bundle may be at most 24 KiB.
- EIP-712 domain: `name "EnclaveSecretVaultV2"`, `version "1"`.

## 2. Custodian HTTP API (`/v2/custody/*`, JSON)

```
GET  /v2/custody/info       -> { v:2, identity, encKey, committeeId, epoch, indices:[k], enclave, chainId, vault }
POST /v2/custody/challenge  {}            -> { encKey, nonce, expiresAt }
POST /v2/custody/release    { v:2, id, endpoint, committeeId, epoch, policyRev, secretRev, recipientKey,
                              challenges:[{encKey,nonce}], operator:{sig, expiry}, evidence:{...v1 evidence doc...} }
                            -> { v:2, encKey, count, sealed (base64 HPKE of count x 101-byte partial records) }
```

A member's release checks are v1's (`custody/custodian.mjs decide`): its own challenge, consumed; chain state at the
agreed highest head, with high-water marks; policy present and not paused; revisions current; ownership; a live lease
held by `endpoint`; the operator signature over the v2 `operatorMessage`; rules and runtime; the hardware evidence bound
to the v2 `releaseBinding`. In addition:
- `committeeId` and `epoch` are the committee's CURRENT ones, and the bundle's committee is that committee;
- the bundle's **label proof** verifies for `labelOf(chainId, vault, id, secretRev, committeeId)`;
- the member answers with one partial per index it holds in that epoch.

Errors are `{error, message}` with v1's codes.

## 3. guestd and the supervisor (operator authorization)

The guest asks guestd on vsock `CustodyAuthPort` (9445):
- v1: `custody-auth-v1 0x<id> <binding>` (unchanged);
- v2: `custody-auth-v2 0x<vault> 0x<id> <binding>`.

guestd reports `awaitingCustodyAuth: { v, vault, binding }`. The supervisor signs:
- v1: its v1 message with its v1 vault;
- v2: `operatorMessage` v2 (protocol) for the named vault, ONLY if that vault is its measured `CUSTODY_VAULT_V2`.

It answers `POST /vms/<id>/custody-auth {binding, endpoint, sig, expiry}` as in v1.

## 4. The guest's unlock (front)

The relay-signed release carries the v2 pointer:
`{ v:2, vault, chainId, committeeId, epoch, t, policyRev, secretRev, bundle (hex), commitments (hex), machines:[{ encKey,
endpoint, enclave, indices }] }`.

1. Ask EVERY machine for a challenge (`POST /v2/custody/challenge`). Let `E` be the Enclave machines that answered.
2. Build the v2 binding over the challenges that answered, get the operator authorization (§3), and attest.
3. Send the release to every machine that issued a challenge. Open each answer and verify every partial record (DLEQ
   against `Y_k` from the commitments). Drop any machine with a failing record.
4. Choose `t` distinct indices:
   - **if `E` is non-empty**, use exactly ONE Enclave machine's partials: all of the Enclave seat's indices, from a single
     machine. If no Enclave machine in `E` answered the release with valid partials, REFUSE;
   - otherwise use any `t` indices from other seats.
5. Combine, check that the label equals `labelOf(...)`, decrypt, check `configSha256` against the delivered config, and
   hand the values to the app. Fewer than `t`: refuse, and the app does not start.
