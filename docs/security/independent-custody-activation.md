# Independent custody: activation and recovery runbook

Status, 2026-10-19: the source and tests below are implemented. Nothing in this
document has been activated on Base, and no live committee, vault, host or
secret has been changed. The gates at the end must pass before any owner relies
on an independent committee.

This runbook is for host operators and host owners who want to form and run a
custody v2 committee **without Enclave**: no Enclave founder, no Enclave seat,
no capacity-witness receipt, no Enclave API, relay or tunnel. Owners choose whom
they trust; this process is how they authorize that choice. It does not show that
the participants are independent organizations, and it is not Sybil resistance.

## Roles

| Role | Holds | Can do | Cannot do |
| --- | --- | --- | --- |
| Host owner | accepted owner wallet in `EnclaveHostOwnership` (EOA or ERC-1271 contract wallet) | consent to a founder plan, admit members, authorize custodian code for its seat | read shares or secrets; act for another seat |
| Host operator | registry operator key | bind its guest to its registry entry, permit a founder plan | admit members, change code, read shares |
| Custodian | measured SEV-SNP guest; sealed identity and share | DKG, handover, release partials, sign approvals its owner permitted | anything its measured code does not allow |
| Gas payer | any funded wallet | submit signed calldata | forge or alter any signature |
| Coordinator | `scripts/independent-custody.mjs` | relay public messages, collect signatures | decide anything; every member re-verifies |

## Explicit pins

Every command takes its pins from the command line. None are discovered from
Enclave:

- `--chain-id` and `--vault`: an `EnclaveSecretVaultV2` with
  `createIndependentCommittee`. On Base, the deployment recorded in
  `contracts/deployments/independent-authorities-base.json` qualifies, and the
  legacy single-seat vault `0xE486…EEF5` does not.
- `--host-ownership`: optional. It pins the vault's immutable ownership
  authority in reads.
- `--measurement`: the sha256 custodian measurement (`manifest.measurementSha256`
  from `scripts/build-custodian-v2.mjs`). Each operator reproduces the image and
  compares this value before signing anything.
- `--rpcs`: at least two distinct HTTPS RPC hostnames. A majority must agree on
  one canonical block hash, and a single RPC cannot veto.
- Custodian endpoints: HTTPS origins served by each operator's own ingress
  (`custody/v2/ingress.mjs`, `scripts/prepare-custodian-ingress.mjs`).

## Measured admission policy

The custodian image fixes the admission policy, and host configuration cannot
change it:

- `independentOwners: [...]`: an explicit list of 3–64 owner wallets, built with
  `--independent-owners owners.json`. Founders and later members must come from
  this list. A new owner requires a new image (see code governance below).
- `independentAdmission: "owner-permits"` (new), built with
  `--independent-admission owner-permits`: open participation. Any distinct
  non-Enclave accepted owners may form a committee when **every** founder's
  operator and owner signs the exact plan. Later, a member joins when its own
  owner and at least `t` current governance voters (defined below) sign an
  admission for that exact machine record. One image serves any group, with no
  Enclave-built list. The two independent modes are mutually exclusive, and the
  build refuses both together.
- Neither: the legacy Enclave-founded path (capacity receipts). It is not
  independent.

Invariants that every measured member enforces for an independent committee:

- It never adds an Enclave-owned seat.
- It never gives one owner a second seat, even though the vault only enforces one
  seat per chip.
- Permits expire against the agreed chain time (at most 30 days), never against
  the guest clock.
- Contract-wallet owners are checked with ERC-1271 at the agreed block.

### The authorization point

Each owner or operator decision is judged at **one** quorum-agreed block. One
read (`readAuthorization`) returns the committee, every relevant host's operator
and accepted owner, code activation and ERC-1271 answers together. Owner consent
from one block is never combined with a different owner, operator or roster read
at another block. The decision itself is the machine's signature:

- a founder result (plan permits are judged before the DKG starts and again
  before the result is signed);
- a handover approval;
- a code approval.

Every approver re-attests and re-authorizes **every** newcomer at approval time,
including candidates it already verified at join. An admission that has expired
since the join, a candidate host whose owner has changed, or a different record
under a cached identity is refused. The coordinator re-checks its cached
candidates before proposing, drops those that fail, and lets them join again.

The vault later re-checks host bindings, code activation and seat counts, but
never owner consent. Ownership that changes after a machine has signed is not
reflected in that signature. The next decision reads it again. A handover
proposal expires after the vault's `HANDOVER_TTL`.

### Machine records, seat layout and dealing

- **A continuing seat keeps its exact record.** A machine continues into the
  next epoch only if its whole machine record (`machineHash`: identity,
  encryption key, endpoint, chip, host and measurement) equals its current
  on-chain record. The vault accepts any record under an old identity if the
  host operator signs it. Members therefore refuse a proposal that changes any
  field under a current identity, and `join` refuses a current identity. Key,
  endpoint, chip, host or code rotation needs a **new identity**, which is
  attested, admitted by owners and brought in through a handover; the old seat
  then leaves.
- **Flags come from the vault.** Every next machine's Enclave flag must equal the
  vault's own classification at the approval snapshot: an accepted owner equal to
  the Enclave wallet. Members judge the seat layout the vault will activate, never
  a proposal's claimed flags.
- **Ownership transfers and Enclave weight.** A transfer does not change the
  current epoch's weights: the vault keeps the flags stored at activation. It takes
  effect at the next handover, through `_admit`. In an independent committee, a
  seat that is now Enclave-owned (or has an inactive or unowned host) is no longer
  eligible. It keeps serving releases until the next epoch, but it is removed even
  while alive and never carried forward. An independent committee therefore never
  gains an Enclave seat. With fewer than 3 eligible seats, the next set is invalid
  and no handover happens, so no Enclave-veto layout can form. The current epoch
  keeps serving releases. In a legacy committee, the Enclave seat is the Enclave
  wallet's one governance vote, and an ordinary seat transferred to that wallet
  adds none.
- **Dealers re-verify before encrypting.** A dealer encrypts shares only for an
  on-chain pending set **it approved itself**. The approval is remembered by the
  handover digest, which binds the committee, the current epoch, every machine
  record and the dealer indices. Before encrypting, the dealer re-checks the
  pending set at a fresh snapshot (exact continuing records, vault flags,
  eligibility). It also re-attests and re-authorizes every newcomer's exact
  record, including its encryption key. Any failure withholds the deal: an
  unreachable recipient, a set the dealer did not approve, or a substituted key
  that other signers got through the vault. No share is encrypted, current shares
  stay, releases continue, and the pending set expires after the vault's
  `HANDOVER_TTL` (1 day). The coordinator asks every dealer seat for its
  approval, and staying seats deal first.
- **Time bounds:**
  - approval: snapshot at signing;
  - dealing: a fresh snapshot and fresh attestation at the deal, within the
    proposal's 1-day TTL;
  - admission: permits are live at both points (at most 30 days);
  - the vault re-checks host bindings and code when the last acknowledgement
    activates the epoch.

### Expiry

A permit's expiry gates only the **issue** of a machine signature. A code
approval that has already been issued carries no permit expiry. The vault bounds
it instead: the approval names the committee's current epoch, and each code
digest is single-use (`_usedCodeDigest`), so an add or remove cannot be replayed.
An admission is consumed when the handover is signed.

### Ownership transfer: service versus governance

The vault weighs approvals by seat. Seats can come to share one owner through
`EnclaveHostOwnership` transfers, so members define **governance voters**: the
distinct, accepted, non-Enclave current owners of current seats. Each voter
votes only through its lowest-index seat.

| After a transfer | Releases and handover dealing | Admission and code governance |
| --- | --- | --- |
| Two seats share an owner | Both seats keep serving | That owner counts once; its second seat refuses to sign code approvals |
| A seat moves to the Enclave wallet | The seat keeps serving | No vote in an independent committee |
| Fewer than `t` voters remain | Service continues | Owner governance is frozen; form a new committee and have owners re-provision |

Newcomers must still have an owner distinct from every continuing seat and from
every other newcomer. This stops one owner from acquiring seats through
admission. The canonical-seat rule covers seats that converge through transfers.
Without it, an owner holding `t` seats could add custodian code alone: the vault
counts machine signatures per seat and would accept that, as the transferred-seat
regression shows. Handover approvals remain mechanical: removals require
liveness, and additions require an admission signed by `t` distinct voters. `status` reports
`governanceVoters`, `nonVotingSeats` and `governanceAvailable`. These are
current-consent rules. They do not prove that operators are separate
organizations, and the release path never asks who owns a host.
## 1. Prepare each founder host (every operator)

1. Build or reproduce the measured image and record `measurementSha256`:
   ```sh
   node scripts/build-custodian-v2.mjs --base <metal dist> --out <new dir> --vault 0xVAULT \
     --host-ownership 0xHOSTOWNERSHIP --independent-admission owner-permits
   ```
   The build validates every measured pin, using the daemon's own policy code,
   before doing any work. It bundles the static DKG helper and streams the
   initramfs; an 816 MB base cpio peaked at about 0.9 GB RSS. Two builds of the
   same inputs are byte-identical.
2. Register the host, nominate the owner wallet with
   `EnclaveHostOwnership.proposeOwner`, and have that wallet `acceptOwner`.
3. Start the custodian with `custody/v2/host.mjs` and a direct-transport image.
   Serve the generated ingress over your own HTTPS origin. The host binds the
   guest through the loopback management port only.
4. Confirm that `GET https://<origin>/v2/custody/info` shows `hostSig`,
   `chainId`, `vault` and `independentAdmission`.

## 2. Plan, consent and check (any coordinator, then each signer)

```sh
S=scripts/independent-custody.mjs
node $S plan --endpoints https://a.example,https://b.example,https://c.example \
  --chain-id 8453 --vault 0xVAULT --measurement 0xMEAS --out plan.json
node $S digest --plan plan.json        # every signer checks this digest before signing
# each operator i (key in an env var they control; or --signature from an external signer)
node $S sign --plan plan.json --index I --role operator --key-env OPERATOR_KEY --out plan.json
# each owner i (owner-permits images); contract wallets sign externally and pass --signature
node $S sign --plan plan.json --index I --role owner --key-env OWNER_KEY --out plan.json
node $S check --plan plan.json --rpcs https://R1,https://R2,https://R3
```

`check` reads the pinned registry and ownership authority, then reports every
missing or invalid operator or owner permit, inactive host, unowned host or
duplicate owner. A custodian refuses to allocate a DKG session until all of
these pass, along with fresh peer attestation, same-code and distinct-chip
checks.

## 3. Form and activate

```sh
node $S form --plan plan.json --out result.json                       # DKG only
node $S form --plan plan.json --out result.json --activate --rpcs https://R1,https://R2,https://R3
```

- Each custodian persists its share before it signs the founder result. A crash
  resumes the same result.
- `result.json` contains `transaction`: neutral `createIndependentCommittee`
  calldata that **any** wallet can submit. The vault checks all founder and host
  signatures.
- With `--activate`, members are asked to activate in turn. A member whose host
  cannot pay gas, or is down, does not block the others. It is retried after
  another member creates the committee and then only adopts from the chain.
  `unadopted` lists members still waiting, and the exit code is 2 in that case.
  A member that was offline adopts by itself once it is back: its engine checks
  the chain every minute, and no coordinator is needed. Re-running `form` is
  idempotent, but it needs every founder to be reachable.
- After adoption, each custodian erases the DKG copy of its share. The share
  remains only in the member state that handovers erase.
- The CLI verifies that the on-chain roster, threshold and commitments match the
  founders' agreement before it writes `chainVerified: true`.

If one founder refuses before the DKG finishes, the others are not stranded.
Re-plan without that machine (`plan` with a fresh salt, then new permits from
everyone) and run `form` again. A custodian keeps every abandoned session as a
tombstone. After 16 replacements it refuses further replans, and its operator
starts a fresh custodian identity. It never forgets a tombstone. A custodian abandons its unfinished session only
for a fully permitted plan, and it never resumes an abandoned session. After a
custodian has finished a session, it cannot be re-planned.

## 4. Provision and update secrets (each app owner)

Owners encrypt to the committee key from their own machine. Nothing is dealt or
sent to Enclave:

```sh
ENCLAVE_SECRET_VAULT_V2=0xVAULT enclave custody set <deployment> --v2 --committee 0xCOMMITTEE \
  --rpc https://R1,https://R2,https://R3 KEY=value
```

An update is the same command and needs no custodian action. A release needs `t`
of the `W` seats (2 of 3, 3 of 4, …). Members that are down or refusing are
skipped.

## 5. Health

```sh
node $S status --chain-id 8453 --vault 0xVAULT --committee 0xCOMMITTEE --rpcs https://R1,https://R2
```

`status` reports the epoch, `t`/`W`, any pending handover, each member's
reachability and share for the current epoch, `servingWeight`, whether owners are
distinct, and `releaseAvailable`. The exit code is 3 when fewer than `t` seats
can serve.

## 6. Recovery: replace a lost member, or admit a new owner

A custodian's sealed state opens only on the same chip with the same measured
code. When a member's machine is lost, its identity is gone. Do not try to
restore it; replace it.

1. The new machine's operator prepares the host as in step 1.
2. Create an admission bound to the exact machine record, with an expiry in chain
   time:
   ```sh
   node $S admission --chain-id 8453 --vault 0xVAULT --committee 0xCOMMITTEE \
     --candidate https://new.example --expires-in 86400 --rpcs https://R1,https://R2 --out adm.json
   ```
3. The candidate's owner and the owners of at least `t` current seats each run:
   ```sh
   node $S admit --admission adm.json --key-env OWNER_KEY --out adm.json
   ```
4. Submit the admission:
   ```sh
   node $S join --admission adm.json --rpcs https://R1,https://R2
   ```
   `join` checks the signatures first, then posts to every current member. An
   unreachable member is reported and skipped.
5. The members' engines propose the handover: immediately when only `t` shares
   remain reachable, otherwise after the batching window. Approvers that did not
   see the join re-verify the candidate from the admission carried in the
   proposal. The dealers deal, the new set acknowledges, and the vault activates
   the epoch. The committee key does not change, so existing bundles stay
   readable. Old-epoch shares are erased.
6. Use `status` to confirm the new epoch and `releaseAvailable`.

The same steps admit a new owner who adds a seat. A member that has been silent
for 30 minutes is removed in the same handover.

## 7. Custodian code updates

The vault adds or removes an admitted measurement only with approvals from `t`
seats. A measured member signs that approval only when **its own seat owner**
permits the exact committee, measurement, direction and expiry:

```sh
node $S code-permit --chain-id 8453 --vault 0xVAULT --committee 0xCOMMITTEE --measurement 0xNEW --add \
  --expires-in 86400 --rpcs https://R1,https://R2 --out code.json
# each seat owner signs code.json's digest; collect {memberIdentity: signature} into permits.json
node $S code --request code.json --permits permits.json --rpcs https://R1,https://R2 --out tx.json
```

`tx.json` contains neutral `proposeCode`/`removeCode` calldata once the
approvals reach weight `t`. Any wallet can submit it. The vault's `CODE_DELAY`
applies. Members then move to the new image one at a time through step 6,
because a new measurement is a new identity.

## What was verified (source and local build only)

- `test/custody-v2-independent-lifecycle.test.mjs`. This uses Anvil with the real
  `EnclaveSecretVaultV2`, the real `EnclaveHostOwnership`, the real FROST helper
  and the custodian's actual genesis service. It covers:
  - EOA and ERC-1271 owner plan permits;
  - activation when one founder's host refuses gas and another founder is
    offline (the offline founder adopts itself later);
  - erasure of the DKG share;
  - 2-of-3 release with one member down, and a secret update;
  - admission refused without permits, below `t` voters, with an altered expiry,
    and as a second seat for one owner;
  - owner-admitted replacement through the vault handover, including an
    approver that re-verifies from the admission in the proposal;
  - owner-governed code approval.
- `test/custody-v2-independent-identity.test.mjs`. This uses the same real
  contracts and the actual `approve` and dealer `tick` paths. It covers:
  - every altered record field under a current identity, a duplicate identity
    and a wrong Enclave flag, each refused;
  - a pending set accepted by the vault with a substituted encryption key (t
    approval signatures from raw identity keys): every honest dealer withholds,
    nothing is dealt, shares stay and releases continue;
  - an approving dealer that withholds while its recipient is unreachable, deals
    once it re-attests, and a non-approving dealer that never deals;
  - a seat transferred to the Enclave wallet: it keeps serving, is refused as
    continuing, yields no 2-seat set, and is then rotated out by an
    owner-admitted newcomer into a 2-of-3 independent epoch that releases the
    existing bundle.
- `test/custody-v2-independent-governance.test.mjs`. This uses the same real
  contracts and covers:
  - candidates verified at join, then refused at approval because the
    admission expired (in chain time) or the host's owner changed;
  - a substituted record under a cached identity, refused;
  - the coordinator forgetting both failed candidates and proposing nothing;
  - existing seats transferred to one owner: they still release, but that owner
    gets one code vote (weight 1 < t). The test also shows the vault itself would
    accept the two machine signatures, and that adding a second distinct owner
    authorizes the change.
- `test/custody-v2-independent-runtime.test.mjs`: re-planning with the real FROST
  helper, including more than 16 replans (refused at the limit; every tombstone
  stays refused). Admission and code-permit judgments at one snapshot:
  - an owner that changed at the judged block, and expiry at that block;
  - merged seats, and seats moved to the Enclave wallet.
- `test/custody-v2-build.test.mjs`:
  - measured pins and their mutual exclusion;
  - byte-identical legacy and owner-list measured text;
  - the actual daemon bundle interpreting the pin;
  - streamed inflate and deflate, byte-identical to the one-shot path;
  - refusals before any build work;
  - the legacy tunnel route.
- `test/custody-independent-admission.test.mjs`: a whole founder roster is
  authorized from one snapshot.
- `test/independent-custody-cli.test.mjs`: offline signing, key handling and pin
  refusals.
- The existing custody and relay suites continue to pass.
- A real owner-permits image was built from the local metal base, rebuilt
  byte-identically, and its custodian files were extracted and matched against
  the manifest. Nothing was activated (see `work/claude-custody-result.md`).

Custodian self-attestation is stubbed and app-guest attestation is simulated.
None of this is hardware evidence.

## Remaining activation gates

1. **Image provenance.** The local owner-permits image was built from
   uncommitted sources on top of a local control-image base. A committed source
   revision must be rebuilt, independently reproduced and reviewed before any
   operator uses it.
2. **Legacy tunnel images.** `/v2/custody/code-approve` is now on the relay's
   custody route list. `/v2/custody/independent-genesis` is not, so independent
   formation needs direct transport (the default).
3. **Hardware quorum.** At least three SEV-SNP hosts with distinct accepted owners
   must run the measured image through steps 1–6 on real hardware, with real
   peer attestation, AMD collateral and public HTTPS ingress.
4. **Owner migration.** Existing bundles in the legacy single-seat vault are
   encrypted to the Enclave seat's key. Each owner must re-provision their values
   to the independent committee (step 4). No handover moves the legacy key.
5. **Review.** The DKG integration, the admission and code permits and the
   handover invariants have had no external cryptographic or security review.
6. **Operational independence.** Distinct wallets do not prove distinct
   organizations. Claims of organizational independence need independent
   operators actually running these steps.
7. **Rollback of sealed state.** A dishonest host can replay an older sealed
   state blob. The host launcher keeps 20 historical blobs. A replayed blob opens
   only inside the same measured guest on the same chip. That guest serves only
   the committee's current on-chain epoch, so the replay costs availability only
   on that host. Erasing old-epoch shares is defense in depth against a TEE break
   on `t` chips, and retained blobs weaken that defense. There is no hardware
   monotonic counter.
8. **Owner consent is checked off chain.** Members decide at their signature,
   using one agreed block. The vault does not re-check owner consent when a
   handover or code proposal executes, and a quorum of RPCs that lies to
   members could forge the snapshot. Closing this would need a vault change,
   which must be coordinated with the deployed contract hashes. The vault also
   accepts a changed record under a current identity, and it re-derives Enclave
   flags at execution. Integrity of machine records and of recipient keys
   depends on measured members: approvers refuse such sets, and dealers encrypt
   only for sets they approved. Dealers that are compromised already hold their
   shares; this protection covers honest dealers against other signers.
