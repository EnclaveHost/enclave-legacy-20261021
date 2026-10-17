# Paid capacity verification

Implementation branch: `codex/paid-capacity-audits-20260930`. Workload app:
`EnclaveHost/enclave-apps`, branch `codex/capacity-work-20260930`, directory
`capacity-work`. Capacity Work 1.0.0 is published and approved on Base.

## Production status (2026-10-16): RUNNING, first audit verified, bootstrap trust

The fee market runs as designed; its first and only funded source is Enclave's own canary.

| Piece | Where |
|---|---|
| Ledger (16d), proof, fees | `0xB1783B61…`, `0x6F462d77…`, `0x87c72665…` (the ledger's `feeRouter`) |
| Payer policy | source = canary `0x4e62e60d` (agent wallet), executor `0x1609E6e8…`, policy wallet `0x3e98AAC0…`; revenue 10%, ≤ 100 cpu milli, 1 USDC/day, 0.10 USDC/job, rate ≤ 200 µUSDC/s, 90 days, Capacity Work on `snp-guest-per-app` |
| Budget | accrues from the canary's PROVEN paid time: metal0's control image `dist-fee-3dfeb4c0c` routes opted-in checkpoints through the fee contract (`metal0/fee-checkpoints`) |
| Service | `enclave-capacity-audit` (user unit, warden-host): `scripts/availability/service.mjs` = witness + coordinator + metal0's host acceptor |
| Witness | `availability/witness.mjs`, key `0xD80Bf435…`, receipts every 10 min, `operator-bootstrap` |
| Expected guests | the relay's predictor (Enclave-operated): consistent with the bootstrap label |
| Observation RPC | `base.gateway.tenderly.co` (archive + 1000-block `getLogs`; the other public RPCs refuse one or the other) |
| Release listing | relay `SECRETS_RELEASE_APP_REFS` = Capacity Work 1.0.0: every audit deployment gets attested release |
| Secrets | CPU release `16c2999d`: each staged secret reaches the app as its own environment variable (Capacity Work reads `CAPACITY_WORK_TOKEN` there) |

What this does and does not give:
- **Trust is operator-bootstrap.** Enclave runs the only witness and supplies the expected measurements. Receipts say
  so, and `evidence.mjs` never counts them as independent.
- **The witness checks a boot-time quote.** For metal it verifies the control VM's attestation document, a quote bound
  to its TLS key at boot. Liveness comes from the attested `/availability` read in the same round.
- **Only metal0 is audited today, by our implementation's limits, not attestation's.** Enclave Shield and pVM hosts
  attest too.
  - **Enclave Shield: LIVE since 2026-10-16** (unit `enclave-capacity-audit-shield`, its own payer policy on
    `hyperv-partition-per-app`). Source: canary `0x0f19412d` pinned to nucbox-k11-4. k11-4 accepts offers itself
    (Windows .44+), and since .45 proves partitions through the fee router. The witness runs a fresh windows-hv-node/v1
    TPM session hourly. First audits: `0xfe63875d` (2026-10-16 09:35Z, 8.1 s) and `0x791d078e` (2026-10-17 09:20Z,
    8.2 s), both VERIFIED. A host session on Shield proves the host's boot state, and the host is not excluded:
    a capacity claim, not a confidentiality claim.
  - **pVM: blocked on the fee contract.** `EnclaveVerificationFees.configure` (line 124) accepts only
    `snp-guest-per-app` and `hyperv-partition-per-app`. The ledger's `feeRouter` is set once, so a pVM backend needs
    a new fee contract and a new ledger. A pVM branch in `verified-http.mjs` and a witness adapter are also missing.
  - A payer policy per isolation backend: the fee contract keys policies by source deployment, and each pins one
    backend, so each tier needs its own funded source.
- **The budget has two caps, and routed fees alone cannot pay.** Spending is capped by `available6`: 10% of the
  canary's proven runner credit. USDC is capped by the policy wallet's balance. Fee routing puts only 1% of each canary
  funding into that wallet, and one audit costs about 0.009 USDC, so routing alone needs about $1 of canary funding per
  audit. On 2026-10-16 the owner topped up the wallet directly with 5 USDC; `available6` and the daily cap still bound
  spending, and unused USDC can only fund jobs or return to the ledger payout (`returnUnused`).
- **First complete audit: 2026-10-16 04:16Z.** Job `0x6175863f` (deployment `0x3e6781ac`): metal0, 11 units at 22/s
  for 450 s. The cpu-ram/1 challenge took 6.5 s, the SNP evidence verified and was admission-safe, the digest equals the
  reference, and the job stopped and refunded. Cost 9152 µUSDC. The cooldown is 24 h per host.
- **What failed before it, and is fixed on main:**
  - the challenge ran before the guest was ready (`05551bee1`);
  - one verifier-side failure locked the host out of further audits (`b4e9f42ff`);
  - audit guests had no release bootstrap route (`886be0f7c`);
  - the binding used one release's runtime for every predicted image (`0b54e95cf`).
- **Receipts also qualify custodians.** Custody v2 (`docs/security/secret-custody-v2.md` §5) uses the same receipts
  for non-Enclave custodian candidates; that takes effect with the next custodian build.

### An Enclave Shield instance's config (example; no secrets)

The second instance runs `node scripts/availability/service.mjs /absolute/shield-config.json`. Its keys come from the
environment variables it names. Its pinned policy is our own copy of `windows/installer/admitted-shield-policy.json`
at a reviewed commit; with `policySha256` set, any other bytes are refused. Each witness round costs the box a TPM
quote, so `witnessEverySec` defaults to 3600 for a config with Shield hosts. `maxSpareAgeSec` must then exceed it.
The other fields are the metal instance's, with this instance's own values:

```json
{
  "classId": "cpu-shield",
  "source": "0x<the Shield payer policy's source deployment>",
  "stateDirectory": "/home/<user>/.local/state/enclave-capacity-audit-shield",
  "executorKeyEnv": "AUDIT_SHIELD_EXECUTOR_KEY", "witnessKeyEnv": "AUDIT_WITNESS_KEY",
  "profile": { "appRef": "catalog://0x<Capacity Work>/<version>", "isolationBackend": "hyperv-partition-per-app", "classId": "cpu-shield" },
  "hosts": [{ "kind": "shield", "endpoint": "https://api.enclave.host/t/nucbox-k11-4" }],
  "hostMeasurements": ["<k11-4's EK certificate sha256>"],
  "witnessEverySec": 3600,
  "shield": {
    "policyFile": "/home/<user>/.local/state/enclave-capacity-audit-shield/admitted-shield-policy.json",
    "policySha256": "<sha256 of that file>",
    "catalog": "0x18419CA2b502D423A8de6269AEeE171a378626e3",
    "gateways": ["https://<trustless gateway>"],
    "sessionAttempts": 4
  },
  "observation": { "maxSpareAgeSec": "5400" },
  "workload": { "rounds": 0, "memoryMiB": 0, "passes": 1, "timeoutMs": 0 }
}
```

`rpcRead`, `rpcSend`, `registry`, `ledger`, `fees`, `proof`, `relay`, `releasesDir`, `referenceBinary`, `policy`,
`scheduling`, `receiptTtlSec`, `intervalSec` and the rest of `observation` are as in the metal config. The workload
numbers are sized per config (zeros above are placeholders). Shield readiness polls only `/.well-known/enclave-ready`.
The expectation and the host session are loaded before the challenge timer starts (`requestVerified.prepare`). A
Shield failure on the verifier's side is INCONCLUSIVE and does not block the host: no host session from the relay,
our own derivation failing, a missing policy file, or a stale session.

## Price follows paid demand and qualified supply

`availability/pricing.mjs` prices a fixed-duration offer within one comparable
resource/isolation class. Demand and supply are normalized resource-seconds over
the same finalized observation window. Supply includes occupied qualified
capacity; only spare capacity can receive verification work.

The initial curve is `anchorRate × (paidDemand / qualifiedSupply)²`, bounded by
configured multiplier limits, a payer maximum rate, per-job spending and available
budget. At demand/supply 0.5, 1 and 2, the unconstrained multipliers are 0.25, 1 and
4. These are curve examples, not production dollar prices. A class-specific anchor
is still needed: a dimensionless ratio cannot set a dollar price by itself.

Stale observations, insufficient funds, unavailable capacity and offers below a
host's acceptance floor produce no job. Ordered observation epochs and elapsed-time
price-change limits prevent repeated polls from ratcheting the rate. Quotes expire.
Hosts explicitly accept negotiated rates; customer tariffs and already-claimed
lease prices remain intact. Compatible queued customer jobs take priority over new
verification work, even if the scarcity quote would be high.

## Accounting and execution

- `chain-observation.mjs` replays finalized ledger events with archive snapshots.
  Demand comes from USDC runner credits paired with proof-of-time checkpoints.
  Verification-funded jobs and known verification app versions are excluded.
  Missing archive state or a proof-policy change invalidates the observation.
- `accounting.mjs` matches that work to qualified hardware identities. It rejects
  conflicting aliases, duplicate service events and overlapping service intervals;
  excludes direct operator/payout self-hosting; and bounds funded queued demand
  and each owner's influence. Supply certificates must cover the observation
  window. Recent spare-capacity observations are required separately.
- `evidence.mjs` checks domain-bound EIP-712 capacity receipts. Independent mode
  requires two configured independent groups, excluding the host's group. The
  explicitly authorized bootstrap mode permits one Enclave-operated group, but
  requires the signed payload and scheduler offers to say `operator-bootstrap`.
  Such receipts cannot satisfy independent mode. `observation.mjs` binds receipts
  to the registry identity and payout wallet. Membership is explicit payer policy.
- `scheduler.mjs` spreads concurrent jobs across hardware identities, with
  cooldowns and budget reservations. `coordinator.mjs` persists pricing epochs and
  reservations and resumes unfinished jobs. It processes independent hosts
  concurrently; native reference computations are serialized to bound verifier RAM.
- `fee-chain-adapter.mjs` creates ordinary catalog deployments owned by a
  segregated fee wallet, stages a per-job secret using ERC-1271, obtains the
  host's explicit price acceptance, and funds within on-chain policy limits.
  It checks the actual lease identity and rate. Wrong-host results are rejected
  and the deployment is stopped. Existing permissionless claims do not guarantee
  that only the intended host can briefly claim a job.
- `workload.mjs` sends a fresh CPU/RAM challenge and compares the full result with
  a native reference. `verified-http.mjs` verifies the live Shield/SNP app evidence
  against independently loaded ledger, catalog, runtime and host expectations,
  and pins the workload request to that same TLS key. WebPKI alone is insufficient.
- The durable state directory holds private job tokens and authorizations with
  restrictive permissions. Transactions are journaled before submission. An
  uncertain broadcast with no transaction hash requires explicit reconciliation;
  the driver never guesses and submits a second payment. Interrupted tests fail
  rather than being rerun to select a better result. Completion waits for lease
  release/expiry and any currently refundable escrow to be returned.

The app is deliberately recognizable verification work. It uses normal WASI HTTP,
isolation, shares, scheduling and proof-of-time payments. Passing establishes the
work actually exercised, not every advertised CPU/RAM/GPU resource, exclusive
hardware possession or resistance to outsourced computation. The CPU/RAM algorithm
has possible time/memory tradeoffs and makes no GPU capacity claim. Witness trust
and per-owner demand limits are not Sybil-proof consensus or a complete defense
against wash trading or coordinated supply withholding.

## Contracts and payer authority

`EnclaveDeployments` revision 15 adds negotiated job rates, explicit refund
attribution, and a one-time binding to `EnclaveVerificationFees`. The bound router
must identify this ledger. Ordinary caps, publisher fees, runner escrow and free
self-hosting retain their behavior.

The router directs 5% of an opted-in source's existing platform fee to its
`VerificationFeeWallet`; at the current 80/20 split this is 1% of the gross host
charge. It adds no payer charge and reduces neither publisher nor runner proceeds.
Each source/payer pair has a separate immutable wallet. There is no pooled reserve,
admin withdrawal or arbitrary-call facility. Unallocated fees follow the ordinary
platform payout. Revoked/expired unused fees return only to that same platform
payout, since they came from its share.

The payer configures executor, pinned workload/backend, expiry, maximum CPU share,
rate, per-job limit, payer-wide daily limit and proven-revenue fraction (at most
10%). Newly proof-credited paid source service unlocks a spending allowance; jobs
are additionally bounded by actual segregated fee funds. Verification jobs cannot
recursively earn budget. Policy edits clear allowance, preserve the daily spend
counter and invalidate old offers. The executor cannot fund arbitrary deployments.

Ordinary ledger funding escrows the runner share and attributes refundable amounts
to the fee wallet. Each approval is exact and cleared after use. Unused job escrow
returns to that wallet, not the executor. Anyone may finish cleanup after the job's
funding deadline plus its complete duration, policy expiry or revocation. Before
then only the payer/executor may stop it. Completing a job does not drain an
otherwise active source policy's wallet.

ERC-1271 support authorizes only readable `enclave-secrets:put:` messages signed by
the policy's current executor. It cannot authorize token typed-data transfers.
The relay reads the deployment owner from the ledger, validates that contract's
signature and preserves payload binding, expiry, replay checks and isolated secret
release. This does not grant access to ordinary customer deployments.

`EnclaveAvailability` and `chain-adapter.mjs` remain an earlier, separately funded
prototype. They are not the production funding route and must not be activated for
this rollout. Native transaction gas still comes from submitters: fee-funded USDC
verification payments do not themselves implement host gas sponsorship.

## Host proof routing

`windows/node/verification-checkpoints.mjs` routes opted-in source proofs through
its ledger-bound fee contract. Both the Linux supervisor and Windows node use it.
The proof's signed domain and fields do not change. Ordinary deployments retain
normal proof batching. Missing policies, older ledgers and unavailable fee reads
fall back to ordinary proof submission, which preserves runner earnings but earns
no new verification allowance. Broadcast failures are not automatically retried
inside the planner. Individual failures do not mark rejected service as proven.
This host integration is tested in source and not deployed yet.

The active contracts on Base are:

- Ledger: `0xb36dce7689834d59364ca37ade1896d0e6404830`
- Proof of time: `0x89feafcb69e328af61561f0f73f8f3b84405f19a`
- Verification fees: `0x6773fb58e0de3806ec6aa84c3596009145ff52b8`

The address-book switch confirmed in transaction
`0xcade00a3ef36465171de84b34110cc72332ae03a485c3ca46ad9282532ae0bd1`
at Base block 52017232. The old ledger
`0xF9e71385C5cB49844F2457ba6567De0742f8B89a` is retired. Deployment IDs,
owners, configuration, active flags, balances, publisher fees, runner rates and
caps were copied and verified. Leases reset so hosts must reclaim their apps.
The original proven-time requirement was preserved.

Escrow was not transferred: the old contract still holds original owner refunds
and operator earnings. Governance separately contributed 4.671277 USDC to back
five active paid records after sealing imports, with an exact allowance consumed
by the funding transaction. This is an additional platform contribution, not an
escrow migration or new owner-refundable credit. The six previously running
self-hosted apps remain free. Stopped historical paid records remain stopped;
their source escrow rights remain intact, and resumption can require separate
refund/redeposit or explicitly authorized replacement backing. Copying their
accounting balance is not evidence that new-ledger escrow exists.

Host rate acceptance, bootstrap capacity qualification, scheduler configuration,
host checkpoint integration deployment and a real hosted canary remain necessary.
The production contract switch alone does not activate paid verification jobs.

## Deployment dependencies

The reusable coordinator entry point is:

```
node scripts/availability/run.mjs /absolute/private/config.mjs --once
```

The configuration exports `stateDirectory`, `intervalSec` (1–60), and
`configure(store)`. The latter returns `chain`, `workload`, `loadObservation`,
`policy`, and `scheduling` for `runRound`. Compose the real adapters above; do not
substitute a host-reported utilization value or an `attestationVerified` Boolean
for a verifier. A live configuration requires:

1. A revision-15 migration preserving deployments, escrow and ownership, with
   a coordinated lease cutover and a new proof-of-time contract bound to that
   ledger. The current migration engine clears leases and cannot transfer USDC: a
   dry-run import alone is insufficient. Reconcile backing and owner refund rights
   before sealing or changing the address book. A staged deployment is unused.
2. A published, pinned `capacity-work` app version, reviewed resource sizes and
   performance thresholds, authenticated secret staging, and real app-attestation
   expectations. The initial profile supports CPU/RAM work only.
3. Explicitly labeled bootstrap or independent witness identities/groups, capacity qualification evidence,
   receipt expiry and resource normalization policy. A tiny readiness VM being
   responsive is not evidence for a machine's full advertised capacity.
4. Explicit payer source, funding percentage, daily/per-job limits, expiry,
   price anchors and wallet signing policy. No production funding values were
   inferred from the test fixtures. Free self-hosting produces no paid demand or
   fee funding; an empty budget must pause verification rather than invent revenue.
5. Host-side offer acceptance and checkpoint submission through the companion.
   Choose observation freshness/window limits consistent with chain finality;
   never substitute unfinalized state just to keep quoting during an outage.
6. A hardware staging run covering valid and rejected evidence, then a bounded
   production canary. Local WASM and Anvil tests do not prove hardware isolation.

## Validation

- 79 JavaScript tests cover pricing, accounting, real event ABI replay, signature
  domains/quorums, durable recovery, concurrent scheduling, binding failures,
  workload/lease bounds and existing/contract-wallet secret authorization.
- 22 proof-domain/routing tests cover unchanged signatures, opt-in routing,
  old-ledger behavior, failed reads and mismatched bindings.
- 42 admin-console tests cover encoding, migration and generated artifacts.
- 193 relevant Solidity tests cover the ledger and companion (including 512-run
  funding fuzz coverage), ordinary pricing, self-hosting, publisher fees, fixed
  lease rates, revocation, daily limits, authorization bypass attempts, refunds
  and token-failure rollback.
- A local Anvil integration uses real contracts and signatures to prove source
  credit → existing platform-fee allocation → accepted negotiated price → exact
  job funding → lease release/refund, with no additional payer charge.
  Hardware attestation is mocked only in that test and explicitly labeled.
- The real WASI HTTP component matches its native reference at 0, 1 and 8 MiB,
  and refuses missing authentication and out-of-bounds requests. Three Rust tests
  cover input bounds and challenge sensitivity.
- solc 0.8.35/viaIR/runs=1 produces a 24,267-byte ledger runtime, below EIP-170.

Commands:

```
node --test test/availability-*.test.mjs test/verification-checkpoints.test.mjs test/proof-of-time.test.mjs
forge test --match-contract 'VerificationFeesTest|JobRatesTest|EnclaveAvailabilityTest|EnclaveDeployments.*'
node scripts/availability/test-fee-chain.mjs
node scripts/availability/test-workload.mjs /absolute/path/to/enclave-apps/capacity-work
```

## Published workload

Capacity Work 1.0.0 is approved with zero publisher fee and catalog requirements
256 MiB RAM, CPU only. No hardware capacity result is implied by publication.

- App: `catalog://0x962622b0284b438f58ad480b824d4fbf7fa9ce3dc84e2af97b65bd15392a5e6f/0`
- CID: `bafkreihcpsmtq246majw4ncfam7j3fauj57vfsfbb3cn5ace5k2lmas72i`
- WASM SHA-256: `e27c99386b9e60136e3445033e9d94144f7f52c8a10ec4de8044eab4b6025fd2`

The published bytes were retrieved through the production IPFS gateway and
compared with the tested build. Bootstrap capacity receipts and a production
verification canary remain rollout work; no capacity has been certified by this
publication alone.
