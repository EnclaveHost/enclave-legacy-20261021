# Secret custody v2: custodians run by the hosts, inside their TEEs

Initial production deployment: Base and metal0 (2026-10-14 23:35Z), verified on hardware. Successor to
[secret-custody.md](secret-custody.md) (v1, still serving v1 bundles). The decisions in §11 are made; §6.2 adds Steven's
Enclave-seat rules. Interfaces: [secret-custody-v2-spec.md](secret-custody-v2-spec.md).

The table below is the original deployment snapshot, not the current migration
inventory. Nan's control services have since moved to minipc. The 2026-10-19
source also adds independent committee genesis, distributed key generation and
measured accepted-owner admission without an Enclave capacity witness; these
changes are not active in the legacy vault below. See
[independent custody formation](../design/decentralized-architecture.md#independent-custody-formation)
for the current implementation, validation and remaining activation gates.

**Original deployment (2026-10-14):**

| Part | Where |
|---|---|
| `EnclaveSecretVaultV2` | Base `0xE48699B8401564aaCe7A814AE4569b67a3F7eEF5` (no owner, admin or proxy; book key `secretVaultV2` NOT set) |
| Committee | `0x47742ae8c544ff66a4ad91cfbf5cecdd389013da362813ba3b55c4e247b0f7a3`: epoch 1, ONE seat (the Enclave seat), `t = 1` |
| Custodian | its own SEV-SNP VM on warden-host (`enclave-custodian-v2` user unit; image `custodian-v2-9d43e63e8`, measurement `c8663742…`) |
| Custodian key | generated in the VM, sealed with the chip's derived key; the host holds only ciphertext |
| Custodian endpoint | `https://api.enclave.host/t/custody-metal0` (relay fleet tunnel, attached by the VM's own quote) |
| Relay | `CUSTODY_VAULT_V2` on nan; the v2 pointer in signed releases; the custodian API allowed for `custody-*` tunnels |
| Guest | CPU release `d84fb52b` (front from `custody/front-prod`); guestd `custody2-568ab660bab4` |
| Supervisor | metal0 control image `dist-custody-v2-295650320` (measurement `5678855f…`): signs v2 releases for this vault only |
| CLI | `enclave custody set|migrate|status|pause|resume --v2` |

**Hardware verification (canary `0x4e62e60d`, agent wallet, hello-world, rules admitting one image `ab852fe5…`):**
- The guest logged `DOM custody: … secrets revision 1 from a v2 threshold of 1 over 1 custodian machines` and started
  the app. The custodian logged `release … OK`.
- With the custodian stopped, the guest refused (`insufficient custodian quorum … need 1`) and did not start the app.
- After a restart, the custodian reopened its sealed state with the same identity and share, and the next boot
  unlocked.
- On anvil, `test/custody-v2-e2e.test.mjs` covers the multi-seat paths: a capacity-gated join, a handover through the
  contract, `t = 2` with exactly one Enclave partial, and the two Enclave machines unable to reach `t` alone.

**Not yet (each fails closed):**
- **Only the Enclave seat exists.** No other SEV-SNP host is in the fleet.
- **Non-Enclave candidates are refused.** Their proof of capacity must be Capacity Work receipts that name the
  candidate's chip ID (§5 item 2). The capacity pipeline is not active and its receipts do not name chips yet.
  `capacityCheck` refuses every candidate until both change.
- **A single machine holds the key.** If warden-host's chip or sealed state is lost, every v2 bundle is unreadable, and
  owners must re-enter their values (§10).
- **The custodian keeps some state only in memory.** That is its per-deployment high-water marks and its AMD VCEK
  cache. After a restart, rollback protection starts again from the next read.
- **The relay is in the path.** The guest reaches the custodian through the relay's tunnel, and gets the pointer from
  the relay-signed release (v1 L3).
- **Not built yet:** the site's "Save to custody" (v1 only; v2 via the CLI) and the governance book entry.
- **No external cryptographic review.**

## 1. Why v1 is not enough

v1 removed the relay's ability to read application secrets. A guest gets its values only from a threshold of
custodians, under a fresh attestation, and nothing in the relay's path holds a usable key. The value of that is real:
an attacker who takes the relay, or any single custodian box, reads nothing.

But v1's committee is four VPSs that Enclave runs:

- **Enclave can read every secret.** Root on each box plus the passphrase on its disk gives the share key. Three boxes
  give the threshold. Nothing technical stops the operator, only policy.
- **No censorship resistance.** The same operator can stop any three custodians, or tell them to refuse one deployment.
- **The share keys sit on ordinary disks.** They are encrypted, but the passphrase is on the same machine.

v2 keeps v1's guest side (attestation, binding, config commitment, fail closed) and replaces who holds the key.

## 2. Goals

1. **No operator can read the secrets, Enclave included.** Shares live only inside attested TEEs. Admitting members
   and upgrading custodian code are decided by the members themselves, never by Enclave alone.
2. **No small group can block or read a release.** The threshold is a fraction of a large committee of independent
   hosts, with an absolute floor.
3. **Any qualified members can serve a request.** A guest asks every member; any `t` valid answers unlock. Members
   that are down, slow or refusing are skipped.
4. **Owners can stay offline.** Restarts, host moves and committee changes need nothing from the owner.
5. **Shares follow membership, not a clock.** Shares move to the new member set when it changes. There is no fixed
   schedule.

Non-goals: defending against a break of the TEE itself on `t` chips at once (§9), and replacing Base (the vault and the
leases stay on chain).

## 3. Overview

```
 owner (browser/CLI)                       Base                                  hosts (each in its own SNP guest)
 ───────────────────                       ────                                  ─────────────────────────────────
 encrypt values to committee key Y ──────▶ EnclaveSecretVault v2                 custodian 1 ── share x1 (sealed)
 + proof bound to (chain, vault, id)       - committee: Y, members, t, epoch     custodian 2 ── share x2 (sealed)
                                           - bundle: R, proof, ciphertext        ...
                                           - policy: rules, paused (as v1)       custodian n ── share xn (sealed)
                                           - custodian code set (timelocked)
 app guest (attested) ──── challenge + attested release request ──────────────▶ every member
                     ◀──── partial decryption x_i·R + proof, sealed to guest ──── each member that approves
 combine any t partials ─▶ S ─▶ bundle key ─▶ values (inside the guest only)
```

Three changes from v1:

| | v1 | v2 |
|---|---|---|
| Who holds shares | 4 Enclave-run VPSs, keys on disk | every qualified host, inside its TEE |
| What is shared | each secret's own key, dealt by the owner | ONE committee key, created by the members |
| Who changes membership | the committee creator, then reshare | the current members, on evidence (§5) |
| When shares move | only when someone reshares | whenever the member set changes (§6) |
| Cost of a member change | one reshare PER deployment, on chain | one handover for the whole committee |

## 4. Cryptography

Everything uses established constructions and reviewed implementations. JS: `@noble/curves` and `@noble/hashes`,
which v1 already uses. Go (the guest's combine step): `github.com/decred/dcrd/dcrec/secp256k1/v4` for point
operations, a NEW dependency, since v1's Go side only does scalar arithmetic. The group is secp256k1, as in v1, so v1's
Feldman commitment code and test vectors carry over. Composing these needs an external cryptographic review before
any real value depends on v2 (v1's L1 applies twice over).

### 4.1 The committee key

- The committee holds a secret scalar `x`. Nobody ever holds `x` itself. Member `i` holds a Shamir share `x_i` over a
  degree-`(t-1)` polynomial.
- `Y = x·G` is the committee's public key. `Y_i = x_i·G` are the public verification shares, derived from the Feldman
  commitments on chain.
- **Genesis is one Enclave-owned member (§6.2, §10).** It generates `x` inside its TEE and publishes `Y` and the
  commitments. Every later member receives shares by handover (§4.4), so no multi-party DKG is needed. If a committee
  ever has to be created by several parties at once, use Pedersen/Feldman DKG with complaints, following Gennaro,
  Jarecki, Krawczyk and Rabin ("Secure DKG").

### 4.2 Saving secrets (owner side)

The bundle is threshold ElGamal, with the CCA protection of TDH2 (Shoup–Gennaro):

1. Pick random `r`. Compute `R = r·G` and `S = r·Y`.
2. Bundle key `K = HKDF(S, label)`, where `label = "enclave-custody-v2" ‖ chainId ‖ vault ‖ id ‖ secretRev`.
3. `ciphertext = AES-256-GCM(K, envelope, aad = label)`. The envelope is v1's: the values plus the config commitment
   (`configSha256`), so v1's rule against config substitution is unchanged.
4. **Label proof.** A Schnorr proof of knowledge of `r` with `label` in its challenge hash.

The label proof is what stops an attacker from copying Alice's `R` into the attacker's own deployment and having the
committee decrypt it for the attacker's guest. Without the proof, members would partially decrypt any `R` stored under
the requested `id`, and a guest that receives `S` can derive any label it likes. With it, a valid entry under deployment
`id` needs knowledge of its own `r`. Members verify the proof against the requested `id` before they answer.

The vault stores `{R, labelProof, ciphertext}` per `(id, secretRev)`. That is far smaller than v1's per-member sealed
shares, and it does not change when the committee changes.

### 4.3 Unlocking (member side, then guest side)

Member `i`, once every check in §7 passes:

1. Computes the partial decryption `D_i = x_i·R`.
2. Computes a Chaum–Pedersen (DLEQ) proof that `log_G(Y_i) = log_R(D_i)`.
3. Returns `HPKE(recipientKey, D_i ‖ proof)`. `recipientKey` is the guest's key, bound into its hardware report as in
   v1. Partials are always encrypted to the attested guest: any `t` partials for an `R` reveal that bundle's `S`.

The guest:

1. Decrypts each answer and checks each DLEQ proof against `Y_i` from the on-chain commitments. A bad partial is
   identified and dropped; it cannot corrupt the result.
2. Combines any `t` valid partials: `S = Σ λ_i·D_i`, with Lagrange coefficients `λ_i`.
3. Derives `K`, decrypts, checks `configSha256`, and starts the app as in v1.

`x` and `S` never exist outside an attested TEE. A partial reveals nothing about `x_i` (DLEQ is zero-knowledge).

### 4.4 Handover (membership change)

The new members receive fresh shares of the SAME `x`, so `Y` and every stored bundle stay valid. This is proactive
resharing (Desmedt–Jajodia, with verifiable sub-sharing; CHURP covers the dynamic-committee case):

1. Each of at least `t_old` old members deals a Feldman-verified sub-sharing of its `x_i` to the new members.
2. Each new member checks its sub-shares against the dealers' commitments and combines them with Lagrange
   coefficients.
3. Old members erase their shares once the handover is recorded on chain.
4. The contract accepts a handover only if its constant commitment equals `Y`, as v1 enforces with `C0`. A handover
   cannot swap the key.

Dealers that send bad sub-shares are identified by the commitments, and the new members pick a different dealer set.
v1's L6 robustness notes apply.

## 5. Who may be a custodian

A host earns a seat only by meeting ALL of the following. The CURRENT members check each item themselves before they
deal it a share, so nobody else decides.

1. **Attestation.** A fresh SEV-SNP report from the custodian guest:
   - its measurement is in the on-chain custodian code set (§8);
   - TCB at or above the floor, debug off, VMPL 0;
   - `report_data` binds the custodian's identity, transport and DKG keys;
   - the VCEK chain, CRL and TCB checks are v1's verifier (`custody/verifiers.mjs`).

   Other TEEs (TDX, AVF) join only when their verifier is equally complete; until then they fail closed, as in v1.
2. **Proof of capacity.** Capacity Work receipts (`docs/design/paid-capacity-verification.md`):
   - at least `K` passes in the last window;
   - from at least two independent witness groups, excluding the host's own group;
   - **naming the same chip ID as the attestation in item 1.** The audit must run in an attested guest on that chip,
     or a host could pass on one machine and hold the seat on another.

   This is what makes seats expensive. Without it, an attacker could fill seats cheaply and reach `t`.
3. **Registration.** An active entry in EnclaveRegistry, plus caps: at most one seat per chip ID, and at most a fixed
   share of seats per registered operator and per payout wallet.
4. **Liveness.** Answers members' signed heartbeat challenges.

A candidate is admitted when `t` current members sign its admission. The contract records the new member set and a
hash of the evidence each member checked. Enclave holds no admission key. The capacity scheduler's
`operator-bootstrap` witness mode (Enclave-run witnesses) cannot satisfy item 2.

## 6. When shares move: on membership change, not on a clock

Shares move only when the member set changes:

- **Join.** A host passes §5. Admissions inside a short batching window (open decision, §11) go into one handover.
- **Leave.** A member misses heartbeats past a grace period, or fails a re-check of §5 (expired capacity receipts, a
  revoked TCB, its code removed from the set). It is dropped at the next handover; until then it simply does not
  answer, which the threshold absorbs.
- **Safety trigger.** If the number of reachable members nears `t`, a handover to the reachable qualified set runs at
  once, before the margin is gone.

A handover is not triggered by an app asking for its secrets. An app that runs for months must still find its shares
held by live members when it restarts, so shares follow membership, never usage.

### 6.1 The threshold

- `n` counts SEATS at the last handover: one per non-Enclave member, plus ONE for all Enclave-owned members together
  (§6.2).
- `n >= 3`: every seat holds one share and `t = ceil(2n/3)`, so `t >= 2`.
- `n < 3`: see §6.2, the seeding rule.
- **`t` never depends on who is online when a request arrives.** If it did, an outage or an attacker taking honest
  hosts offline would lower the number needed, down to the attacker's own seats.
- Trade-off at `2/3`: stealing needs `2n/3` seats. Unlocks keep working while up to `n/3` seats are down. A handover
  needs `t_old` old seats online.

### 6.2 The Enclave seat (Steven, 2026-10-14)

The nan-retirement source proposal replaces payout-based classification with accepted host ownership. A member is **Enclave-owned** when the pinned `EnclaveHostOwnership` contract names `0x0b2d009c0c9Af05b12100D77F3c815fea822eE61` as its host's accepted owner. Initial ownership requires both the registered operator's nomination and the wallet's acceptance. A payout declaration alone is insufficient. The vault reads ownership at admission/handover and snapshots the classification for the epoch.

This requires a new vault and measured runtime. The live legacy committee has not been migrated; replacing its runtime or discovery pointer alone would not migrate encrypted bundles or shares.

1. **All Enclave-owned members share ONE seat.** Each holds a copy of the same share(s). However many machines Enclave
   runs, they count once. **Enclave machines can never make up the threshold among themselves once `n >= 3`.** This is
   enforced by the sharing itself, not by policy.
2. **Seeding: below 3 seats, the Enclave seat alone unlocks.** With `n < 3` there must be an Enclave seat. It holds
   `t = (non-Enclave seats) + 1` shares; every other seat holds 1. So:
   - Enclave seat only: `t = 1`;
   - Enclave seat plus one other host: the Enclave seat holds 2 shares, the other holds 1, and `t = 2`. Enclave alone
     unlocks; the other host alone does not.
   - Without an Enclave seat, fewer than 3 seats is refused.
3. **When Enclave is online, exactly one Enclave machine takes part.** If any Enclave-owned member answers the
   challenge round, the guest must use exactly one Enclave partial. The sharing already allows at most one seat's worth.
   "At least one" cannot be enforced by the sharing (it must still work when no Enclave machine is up), so the guest's
   measured front enforces it: it waits for one Enclave partial, and refuses if none arrives.

**What rule 3 means:** while any Enclave machine is online, Enclave can block every unlock by having it refuse. v2 does
NOT resist censorship by Enclave; it resists censorship and theft by everyone else, and theft by Enclave.

## 7. The unlock protocol at request time

Unchanged from v1 except where noted:

1. The guest learns `(vault, id)`. In v1 this comes inside the relay-signed release (v1 L3). v2 keeps that for now; see
   §9.
2. The guest reads the member list and `Y_i` for the current epoch, and asks every member for a challenge.
3. The guest builds v1's release binding (chain, vault, id, policyRev, secretRev, epoch, challenge root, runtime,
   transport SPKI, recipient key) into `report_data`. The lease holder's operator signs it, as in v1.
4. The guest sends the attested request to every member. Each member checks:
   - everything v1 checks: rules, measurement, TCB, debug, `HOST_DATA` = id, lease, operator signature, freshness,
     high-water marks, paused;
   - NEW: the bundle's label proof against `id`.

   It then answers with its sealed partial (§4.3).
5. Any `t` valid partials unlock. Fewer means the guest refuses to start the app, as in v1.

## 8. The custodian itself

### 8.1 A dedicated measured guest, deployed like an app

The custodian is its own small domain release (a front plus the custodian binary), launched through the normal
deployment path. The capacity scheduler and fee wallet that place Capacity Work place one standing custodian
deployment per qualified host and pay for it. It is NOT folded into the Capacity Work app: that app is deliberately
recognizable audit work, and mixing key custody into it would muddy both its measurement and its purpose.

Two guest capabilities are needed that per-app guests do not have today:

- **Attest its own keys.** A report whose `report_data` is the custodian's key hash (the front's report path, with
  the custodian's input).
- **Sealing.** `SNP_GET_DERIVED_KEY` through `/dev/sev-guest`, root VCEK, mixing the measurement and the guest policy.
  The sealed state (`x_i`, identity keys, epoch) is stored on the host's disk as ciphertext. It can be opened only by
  the same custodian code on the same chip.

### 8.2 Persistence and rollback

- A restart on the same chip unseals and rejoins. A host move loses the seat; the member is dropped at the next
  handover and re-admitted on the new chip if it qualifies there.
- **Rollback.** The host can hand back an older sealed blob, holding an old epoch's share. The custodian refuses any
  epoch older than the chain's current one. Old shares are useful only to a TEE break on `t_old` chips that also kept
  their blobs, the standard assumption of proactive schemes.
- **TCB.** Whether the TCB is mixed into the sealing key is a trade-off. If it is, a microcode update erases the share.
  If not, an attacker who rolls back the firmware could unseal. Recommended: do not mix it, and have the custodian
  check its own fresh report against the TCB floor before using sealed state.

### 8.3 Upgrades: the control point

Whoever can add a measurement to the custodian code set can ship code that exports shares. So:

- adding a measurement needs `t` member signatures AND a public delay (recommended: at least 7 days) before it takes
  effect;
- builds are reproducible, and the doc for each release names its source commit;
- **Enclave has no override.** This is open decision 1 (§11), and it determines whether goal 1 holds at all.

Owners who reject an upgrade can move their bundles to another committee during the delay.

## 9. What v2 does and does not give

**Gives:**
- Enclave cannot read secrets or admit its own members alone.
- No single host, operator or relay can block a release, as long as `t` qualified members answer.
- Stealing costs `t` seats that are each attested and capacity-proven, on distinct chips and within operator caps.

**Does not give:**
- **TEE breaks.** A side channel or physical attack on SEV-SNP that extracts `x_i` on `t` chips defeats v2. Caps per
  chip, per operator and eventually per vendor raise that cost; they do not remove it.
- **v1 L3, the relay in the guest's path.** The pointer to the committee arrives in the relay-signed release. A
  malicious relay can point a guest at a committee it runs: an integrity attack, not a read of real secrets. Closing it
  needs the guest to read Base itself (a light client or storage proofs).
- **The owner's device.** It is still trusted for its own secrets (v1 L7).
- **Base.** Censorship by Base, or lost Base RPC access, blocks policy reads.
- **Sybil resistance in full.** Capacity proofs and caps make seats expensive, not impossible: Capacity Work notes
  time/memory trade-offs and that it does not stop outsourced work. Witness groups can collude.

**Losing state.** If more than `n − t` members permanently lose their sealed state before a handover, `x` is gone.
Every v2 bundle then becomes unreadable, and owners must re-enter their values: apps fail closed until they do. A
temporary outage of more than `n/3` members only blocks unlocks until enough return.

## 10. Rollout and migration from v1

- **Activation: the Enclave seat seeds the network (§6.2).** The committee is created by ONE Enclave-owned member,
  which generates `x` inside its TEE. Today that is metal0, the only SEV-SNP host. Every later member joins by handover
  (§4.4).
  - Until other hosts join, a v2 secret depends on that one machine's sealed state. If warden-host loses it (a new chip,
    lost storage, or a custodian code change without a handover), every v2 bundle becomes unreadable. Owners must then
    re-enter their values; apps fail closed until they do.
  - v1 stays live beside v2 until owners have moved.
- **v1 keeps serving v1 bundles** until owners move. `enclave custody migrate` (owner-signed) re-encrypts to `Y`.
  Moving bundles without the owner would need a new contract path authorized by the attested guest plus the v1
  committee; that is not proposed here.
- **Retiring v1.** When no v1 bundle remains, its four custodians are shut down and their key files destroyed, as v1
  §9 step 10 does for the relay's key.

### 10.1 Build order

1. **Crypto library:** threshold ElGamal with label proofs, DLEQ, DKG and handover. Both JS and Go, with test vectors
   shared between them (the v1 practice) and negative tests for each check.
2. **Contract v2:** the committee key, member sets and admission by member signatures, handovers with `C0 = Y`,
   bundles `{R, proof, ciphertext}`, and the custodian code set with timelocked upgrades. Foundry tests, then an
   external review.
3. **Custodian guest:** a dedicated release, derived-key sealing, attestation of its own keys, the v1 checks plus the
   label proof.
4. **Eligibility:** Capacity Work receipts bound to the chip ID; member-side verification of §5; liveness heartbeats.
5. **Handover triggers and batching** (§6).
6. **Guest side:** the front's v2 unlock (combining partials, the Go point library).
7. **Owner tooling and site:** encrypt to `Y`, migrate from v1.
8. **Hardware verification** in the v1 style: release at `t`, refusal below `t`, a handover with live apps, a host move.

## 11. Decisions (2026-10-14; Steven asked for the recommendation on each)

1. **Upgrade authority.** Adding a custodian measurement needs signatures from seats holding `t` shares, then a 7-day
   public delay. Enclave has no override. Removing one needs the same signatures and takes effect at once. With only
   the Enclave seat, Enclave decides upgrades alone, until other seats exist.
2. **Threshold.** `2/3` of seats (§6.1) and the Enclave rules (§6.2). There is no separate `T_MIN`: with `n >= 3`,
   `t >= 2`, and below 3 seats the seeding rule applies.
3. **Liveness.** Members send heartbeats every 60 s. A seat silent for 30 min is removed at the next handover.
   Admissions and removals are batched for 10 min. A handover runs at once when the reachable shares fall to `t + 1`.
4. **Capacity witnesses at launch.** Receipts from the existing witness groups are accepted, including Enclave's
   `operator-bootstrap` group: rule 3 of §6.2 already gives Enclave a veto, so its witnesses add no new power.
   Receipts must still name the candidate's chip ID.
5. **Payment.** The Enclave seat is unpaid. Other seats are paid a flat hourly rate from the verification fee router
   while they answer heartbeats; silent periods are unpaid.
6. **Handover quorum.** Never fewer than `t_old` old shares. The seeding rule (§6.2) covers the small-network case
   this question was about.
