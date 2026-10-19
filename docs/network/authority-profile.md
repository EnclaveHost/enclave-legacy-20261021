# Reviewed Base authority profile

`contracts/deployments/network-profile-base.json` is a reviewed set of Base
contract authorities for the owner-committed (new) path. You can check it
against the chain yourself without asking the mutable `EnclaveAddressBook`.
`scripts/network/verify-profile.mjs` verifies it, and
`network/authority-profile.mjs` implements it.

**This profile is a trust choice for the new path. It is not evidence of any of the following:**

- that production migrated to it;
- that governance is sealed;
- that an independent custody committee is active;
- that any service is independently operated.

Base, its sequencer, USDC (Circle) and the RPCs you choose remain trusted. The
profile lists no network endpoints.

## Identity

The profile's identity is the SHA-256 of its exact bytes:

```
sha256:ee957827032cf7208434e4c73f9e859a27e4fc5c6cab5f4a2153308c09eb4cb8
```

`sha256sum contracts/deployments/network-profile-base.json` gives the same value.

- **Encoding.** The bytes must be the canonical encoding: sorted keys, two-space
  indentation, safe integers only, and one trailing newline. A duplicated key,
  reordering or reformatting is refused even when its digest is supplied.
- **The file holds no digest of its own.** The verifier requires the digest you
  expect, given on the command line (`--expect`).
- **Get the digest independently.** The value above comes from the same
  repository as the file. If you take it from here, you are trusting the same
  source twice. Obtain the reviewed digest separately, for example from a
  reviewer you trust, or by re-deriving it as described below.
- **Changes need a new review.** There is no update key. A changed profile is a
  new review with a new digest.

## Verify

```sh
node scripts/network/verify-profile.mjs \
  --profile contracts/deployments/network-profile-base.json \
  --expect sha256:<the reviewed digest you obtained> \
  --rpc https://base-rpc.publicnode.com --rpc https://base.drpc.org --rpc https://mainnet.base.org \
  [--recompile] [--check-pins contracts/deployments/contract-pins-base.json] \
  [--export-pins NEW_FILE] [--out NEW_RESULT.json]
```

The verifier checks these, in order:

1. **Digest, before any network request.** The SHA-256 of the file must equal
   `--expect`.
2. **Canonical encoding.** The bytes must be in canonical form and at most 64 KiB.
3. **Strict schema.** It refuses:
   - unknown, missing or duplicated fields, contracts or getters;
   - a wrong chain, role or code-provenance label;
   - zero, upper-case or duplicate addresses;
   - malformed hashes, sizes or values.

   The v1 layout (`PROFILE_LAYOUT`) fixes exactly which contracts and getters
   are pinned.
4. **Internal consistency.** Every binding that names another profile contract
   must name that contract. For example:
   - `secretVaultV2.sessionVaultFactory` must be `sessionVaultFactory`.
   - `sessionVaultImplementation.book` must be `pinnedSessionAuthority`.
   - `sessionVaultFactory.authorityPins` must be the deployments ledger, the
     catalog and `pinnedSessionAuthority`.
5. **Chain quorum.** It uses `LeaseReader.agreed`:
   - 2 to 8 distinct HTTPS RPC hosts, with no credentials in the URL;
   - each RPC must report chain id 8453;
   - the block is taken from the second-highest head, minus 2 confirmations;
   - that block must be under 90 s old;
   - the block hash must be unchanged after the reads;
   - at least two peers must return identical answers for every pinned fact.

   Each RPC response is capped at 1 MiB, redirects are refused, and reads are
   paced per peer. A dead, stale, wrong-chain, oversized or lying peer is
   outvoted by two agreeing peers. With fewer than two agreeing peers, the
   verifier refuses.
6. **Comparison with the agreed answers.** It refuses if any of these hold for
   any pinned contract:
   - it has no deployed code;
   - its `keccak256(code)` or its size differs from the pin;
   - an immutable getter differs or reverts (`binding mismatch`);
   - a reviewed mutable value differs (`reviewed mutable state changed`).

   Nothing observed is adopted, and pins are never updated during verification.
7. **`--recompile` (optional, about 25 s).** For the six compiled-runtime
   contracts, it:
   - checks that the local `contracts/*.sol` hashes and the solc version match
     the profile's build;
   - recompiles them;
   - compares the live bytes with the compiler output, with immutables masked and
     the library address substituted (`verifyAuthorityRuntime`).

   This way the recorded hash is checked, not trusted.
8. **`--check-pins FILE`** refuses if `FILE` is not exactly the profile's
   contract pins.
9. **Outputs.** `--export-pins` writes the strict contract pin document, and
   `--out` writes a result. Both write only after success, and neither
   overwrites an existing file.

The output pin document is the existing format from
`network/contract-pins.mjs`, used by `enclave --contract-pins` and
`ENCLAVE_CONTRACT_PINS_FILE`. `contracts/deployments/contract-pins-base.json` is
the same document committed for convenience. Use it only after the profile
verifies, or with `--check-pins`.

**Rate limits.** Public RPCs meter each request, and a snapshot is about 75
requests per peer. If you see `chain quorum unavailable` right after other runs,
that is usually a rate limit at the head stage. Wait, or add RPCs.

## What it pins

The v1 layout pins exactly these contracts, at the review block
(52830935, `0x40ec8c62…`).

**Code provenance.** Each contract is labelled with one of:

- **compiled-runtime:** the profile repeats the runtime hash and bindings recorded
  in `contracts/deployments/independent-authorities-base.json`. That record was
  verified against compiled source at block 52823641. The draft step refuses
  any observed difference, and `--recompile` re-derives it.
- **observed:** two agreeing RPCs served these exact bytes at review. This says
  nothing about which source they come from.

| Name | Address | Role | Code |
| --- | --- | --- | --- |
| registry | `0x868eb7fc…5ccac` | host pin | observed (reports `registrySchema` 4; source HEAD declares 5) |
| deployments | `0xb1783b61…7d117b` | host pin | observed (schema 16) |
| appCatalog | `0x18419ca2…626e3` | host pin | observed |
| proofOfTime | `0x6f462d77…0e6b2` | host pin | observed |
| enclavePay | `0x580270e8…673a6` | host pin | observed |
| verificationFees | `0x87c72665…23641` | host pin | observed |
| connectivity | `0x5f8b636e…15111` | network | observed |
| sessionVaultFactory | `0xec9277a3…e097b` | new path (`PinnedSessionVaultFactory`) | compiled-runtime |
| pinnedSessionAuthority | `0xf76a138c…9cac8` | new path | compiled-runtime |
| sessionVaultImplementation | `0x87bc7bfc…1ff5c` | new path (`SessionVault`) | compiled-runtime |
| sessionVaultLib | `0xcc2824cd…f12b4` | new path | compiled-runtime |
| hostOwnership | `0xf5e9e6c0…790ea` | new path (`EnclaveHostOwnership`) | compiled-runtime |
| secretVaultV2 | `0x56b81b39…58228` | new path | compiled-runtime |
| usdc | `0x833589fc…02913` | external | observed proxy bytes only |
| paymentRouter | `0xf17157b4…9d56a` | dependency | observed |
| keyAttestations | `0xb49241ef…f61b` | dependency | observed |
| legacySessionVaultFactory | `0x1f5c887c…c9c9c` | legacy compatibility | observed |
| legacySessionVaultImplementation | `0x66c76a47…01f65` | legacy compatibility | observed |

The host pins come from the public host `contract-pins.json` (SHA-256
`b687a8da…21336`, recorded in `review.inputs`). USDC, the router, key
attestations and the new-path bindings come from the deployment record (SHA-256
`92dda05e…8c0f5`). Connectivity and the legacy factory were explicit inputs. The
legacy implementation was also an explicit input, and its consistency is
checked through `legacySessionVaultFactory.implementation`.

## Owner powers that remain

Code hashes do not remove the authority behind these contracts. The profile's
`ownerPowers` text for each contract lists those powers. It is taken from
contract source and is **not** proven for runtimes labelled `observed`.

**Current owners (pinned as reviewed state).** Wallet
`0x0b2d009c0c9af05b12100d77f3c815fea822ee61` owns the ledger, catalog,
proof-of-time, pay and key-attestation contracts, and receives ledger and pay
payouts. No transfer to a new owner is in progress (`pendingOwner` is zero).
If any of these values changes, verification refuses until someone reviews a
new profile.

**Ledger (`deployments`).** The owner can:
- slash an operator's bond, up to its amount, to the payout address (`slashBond`);
- sweep a lapsed, unfundable deployment's escrow to the payout address (`sweepEscrow`);
- set the parameters for future deployments: claim bond, GPU cap, fee cap,
  runner share, lease length, proof cutover and ETH/USD feed (zero disables ETH
  funding);
- change the payout address;
- `retire` the ledger, which is one-way.

The following are pinned. The owner set `bandwidthRouter`, `feeRouter` and
`prover` once each; per source, those can never be set again. `importsSealed`
is true and `retired` is false. The parameters for future deployments are **not**
pinned.

**Catalog (`appCatalog`).** The owner can:
- set approval and the verified flag on any version (`setApproval`, `setVerified`);
- bind any CID to an app (`grantCid`);
- move a publisher's app lineage to another address (`transferApp`);
- set the fee cap (`setMaxFee`).

Versions the owner publishes start Approved. `importsSealed` is true. Legacy
hosts admit deployments by catalog approval. On a host running wallet policy,
the host owner's policy decides whether approval is required.

**Proof of time.** The owner can set the proof window, bounded to
[60 s, ledger `leaseSec`).

**Pay (`enclavePay`).** The owner can change where payments are forwarded
(`setPayout`).

**Key attestations.** The owner can add or remove attestors (removing one voids
its bindings) and revoke any key binding. Measurement-bound session grants
depend on this contract.

**USDC.** Circle can upgrade the proxy's implementation, and the token has pause
and blacklist roles. The implementation observed during review was
`0x2ce6311d…fd779`. It is deliberately **not** pinned, so a Circle upgrade does
not change this profile's verdict. This is external trust.

**No global admin in source.** These contracts have no global admin:
- registry: registration is permissionless;
- verificationFees;
- connectivity: per-app trust belongs to that deployment's owner;
- paymentRouter: its `treasury` is immutable;
- the pinned factory, authority, implementation and library;
- `EnclaveHostOwnership`: authority is per host. The registry's active operator
  nominates the first owner, and that owner sets the policy;
- `EnclaveSecretVaultV2`: its immutable `enclaveOwner` decides which hosts count
  as Enclave-owned custody seats.

**Transitive powers.** The new-path contracts call the ledger, the catalog,
PaymentRouter and KeyAttestations, so those owners' powers apply transitively.
For example, `transferApp` affects any catalog reference a session acts on.

## Compatibility with production sessions (not a migration)

Production network sessions still use the legacy factory
`0x1f5c887c0cdf491b16ab6c449abafdf9b2ec9c9c`:

- the relay's `SESSIONS_FACTORY` (`docs/design/sessions.md`);
- the CLI's unpinned default `SESSION_VAULT_FACTORY_ADDRESS`;
- `FACTORY_V2` in `windows/node/session-api-auth.mjs`;
- directory `authorityPins` captured with `--session-factory`, which names an
  explicitly verified legacy factory (`docs/design/nan-retirement.md`). Their
  production values were not inspected here.

Vaults from the legacy factory resolve the ledger through the mutable address
book: `legacySessionVaultImplementation.book` is `0xab214342…80907`, and this is
pinned and shown. So whoever controls the book chooses which ledger those vaults
act on.

The profile's contract pins name the **pinned** factory `0xec9277a3…` instead.
As a result:

- `enclave --contract-pins` already refuses a factory without fixed
  `authorityPins()`, so legacy vaults and their session grants are not usable
  in pinned mode.
- Nothing moved: no grants, bundles, owners or book entries
  (`activation` in the deployment record is all false).
- Consumers that check vault membership against `sessionVaultFactory` from these
  pins will not recognize legacy vaults.
- Using this profile does not change any production component. Existing
  directories, hosts and the relay keep their current configuration.

An owner who wants to use the new path must open a vault under the pinned
factory and authorize grants there. That is the owner's choice, made with the
owner's own signature.

## Browser independent mode

The browser workstream builds its own explicitly validated profile, and this
document does not define that format. Map between the two as follows:

- Take the browser profile's contract addresses only from a **verified**
  `--export-pins` document, which uses the same strict format. If the browser
  profile asks for a USDC address, use `contracts.usdc.address`.
- Choose RPC origins and the quorum separately. They are the user's trust
  choices and are not part of this profile.
- This profile has no directories, gateways or other endpoints. Native
  directory origins are plain-HTTP IP addresses, and an HTTPS page cannot use
  them because of mixed-content blocking and CORS. A browser needs HTTPS
  origins that it has itself confirmed send CORS headers, so this profile
  provides no browser discovery list.

## Re-derive the profile

Anyone can rebuild the profile from the same explicit inputs. The address book
is never read:

```sh
node scripts/network/verify-profile.mjs draft \
  --record contracts/deployments/independent-authorities-base.json \
  --public-pins <public host contract-pins.json> \
  --connectivity 0x5f8b636e0768e84bd47b736652030b65db615111 \
  --legacy-factory 0x1f5c887c0cdf491b16ab6c449abafdf9b2ec9c9c \
  --legacy-implementation 0x66c76a47209f44612343dbeab98b8ef77ad01f65 \
  --rpc … --rpc … [--recompile] --out NEW_FILE
```

The draft step refuses in these cases:

- the public pins disagree with the record's ledger, catalog or registry;
- the public pins name a different factory or vault;
- a compiled-runtime contract's live hash or binding differs from the record;
- any pinned getter does not answer.

A fresh draft differs from the committed file only in `review` (block, time
and RPC hosts). The test suite rebuilds the committed bytes exactly from the
record and the recorded observation.

## Live verification (2026-10-19)

**Verified.** The committed profile verified with `--recompile`, `--check-pins`
and `--export-pins`. All six compiled-runtime contracts were re-derived, and the
exported pins were byte-identical to `contract-pins-base.json`.
- Block: 52831028 (`0xc8531b27…adca1`)
- RPCs: publicnode, drpc and base.org
- Peer failures: none

**Failover.** It also verified at block 52831046 when the first RPC was
unresolvable.

**Refused, as expected.** A copy of the profile was changed in two ways: the
pinned factory's code hash was set to the legacy hash, and the ledger owner was
set to another address. Against live RPCs, the verifier reported both
(`code hash mismatch`, `reviewed mutable state changed`).

## Tests

`node --test test/authority-profile.test.mjs` runs 11 tests. They cover:

- the committed digest and the export;
- consistency with the deployment record and the public pins;
- byte-exact re-derivation;
- refusal of a missing or wrong digest, and of non-canonical, duplicate,
  oversized and malformed input;
- 25 kinds of schema and binding refusal;
- verification with scripted peers: success, and failover around dead,
  wrong-chain, stale, oversized and lying peers;
- refusal on missing quorum, disagreement, stale blocks, empty code, a reverting
  getter, changed owner state, and two lying peers that agree with each other;
- RPC origin and response-size limits;
- the command's refusals before any network request.

## Remaining gates

1. **Independent digest distribution.** The digest still has to be published
   through a channel other than this repository, such as a site build, IPFS
   or an ENS text record. Until then, a first user reviewing this file is
   trusting the repository.
2. **Source verification of `observed` runtimes.** No artifact here proves the
   ledger, catalog, registry, proof-of-time, pay, verificationFees,
   connectivity, router or key-attestation bytes match reviewed source. The
   registry's schema 4 shows the deployed registry predates source HEAD.
3. **Governance seal.** The owner powers listed above remain until the seal is
   activated.
4. **Consumers.** These are owned elsewhere: a CLI `profile verify` or import
   command, native-client profile import, and browser independent mode taking a
   verified export. None of them consume this profile yet.
5. **Session migration.** Each owner must explicitly migrate sessions to the
   pinned factory. Nothing is migrated.
6. **RPC trust.** Verification uses an RPC quorum, not a light client.
