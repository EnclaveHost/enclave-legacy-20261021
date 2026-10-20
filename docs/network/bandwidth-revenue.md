# Bandwidth revenue shares (schema 16, not deployed)

**Deployment hold:** the native collection-wallet splitter below is custodial;
it is not approved for activation under the user's decentralization requirement.
Qualification still uses an administrator-managed signer list and needs the same
trust review. Bidirectional USDC/native-NKN conversion is now requested; see
[currency-conversion.md](currency-conversion.md) for the verified constraints and
remaining settlement decision. The tested implementation below is not a claim
that these newer requirements have been implemented.

A host offers a **gross USDC price per GiB**. Direct bandwidth debits the app's
existing deployment balance. `EnclaveConnectivity` snapshots the ledger's
`runnerBps` when the owner authorizes direct service. At the default 8000 bps,
$1.00 of bandwidth credits $0.80 to the serving host's normal withdrawable
earnings and routes $0.20 through the existing platform fee router. An active
verification-fee policy receives its existing 5% of that platform remainder:
$0.01 for verification and $0.19 for the platform. Without that policy, the
existing router sends the full remainder to the platform.

Bandwidth does not duplicate the publisher's compute-time royalty. The share
snapshot remains fixed for the authorization; changing runnerBps affects the
next authorization. The owner still controls maximum gross price, expiry and
total spending. The host cannot opt the owner into a higher allowance.

Self-hosted direct service costs zero when the current on-chain payout wallet
is the deployment owner. Neither the host nor platform receives a bandwidth
charge in that case. Provider qualification remains mandatory.

## Accounting

Both traffic directions count. A GiB is 2^30 bytes. Compute the cumulative
charge as ceil(sum(bytes * accepted gross price per GiB) / 2^30). Compute the
provider's cumulative entitlement as floor(cumulative charge * snapshotted
runnerBps / 10000); pay only the delta from the preceding receipt. The platform
receives the exact remainder. Splitting a byte stream into small receipts
cannot create fees or change the eventual revenue split.

Receipts bind the deployment, active host and lease, owner authorization nonce,
recent block anchor, price and monotonically increasing byte count. The
registry's compute proof key must sign them. Expired/revoked authorization,
invalid qualification, replay, exhausted budget and transfer failure revert the
entire settlement, including counters.

The legacy ledger distributes some funding fees before usage. Its nominal
USDC runtime balance therefore exceeds retained cash. `bandwidthBackingRequired6`
reports the additional cash required to back all unused credit and outstanding
compute earnings. Platform-funded rebacking, not another customer charge, must
precede spending those credits on bandwidth. Top-ups can create a new backing
shortfall. Settlement fails closed until it is filled.

## Implementation and validation

The ledger uses an immutable linked payment library and stays within EIP-170.
The library preserves compute funding, proof credits and refunds. Validation now
includes 340 Solidity tests, 54 targeted network/control tests, 63 billing/admin
regressions, native Go race tests, complete Linux guestd and egress suites, Windows
egress tests and build, site and runtime builds, and real Anvil accounting and
interrupted-broadcast recovery. The independent-probe test transfers a real 40 MiB
payload locally; it does not qualify any production host or claim hardware isolation.

## Completed settlement and controls (2026-10-03)

The production USDC adapter is `network/usdc-bandwidth.mjs`. It signs with the
registry's compute proof key and serializes the gas wallet through a durable
write-ahead transaction journal. An uncertain broadcast retries identical signed
bytes. Accepted counters and pending/confirmed receipts repair a crash before the
traffic counter file commits. The Windows host proof key remains host-controlled;
this implementation does not turn it into hardware-isolated metering.

`direct.settlement.maxPending6` is mandatory for paid service. It is an explicit
provider credit limit in USDC base units, not a reservation of customer money.
Zero settles before each charge; a positive limit batches payments on a ten-second
interval. Revocation or lease loss can leave up to that configured credit unpaid.
Rate changes require a new owner authorization. Gas comes from a separate host gas
wallet; bandwidth is debited only from the app's existing backed USDC balance.

The app Network panel supports wallet and passkey accounts. It records direct
routing, maximum gross USDC/GiB, budget and expiry on-chain. The browser reconstructs
the signing digest from the user's fields. ERC-1271 enables the existing credit
vault without a vault migration. Signed revocation and wallet revocation invalidate
unused old signatures. Agents derive direct policies from their chain quorum;
reconcilers skip NKN wallet creation and fallback allocations for new direct apps.

Host controls are available through `scripts/network/connectivity.mjs`:

```
node scripts/network/connectivity.mjs host --id HOST_ID --mode compute
node scripts/network/connectivity.mjs host --id HOST_ID --mode direct --price 0.10
node scripts/network/connectivity.mjs host --id HOST_ID --mode tuna --price 0.10
node scripts/network/connectivity.mjs host --id HOST_ID --mode both --price 0.10
```

These commands emit a transaction plan by default. `--execute --key-file PATH`
uses the selected host operator. `--config PATH` updates that host's existing
runtime configuration after confirmation; restart the agent to apply capability
changes. Direct and TUNA flags are independent; compute remains available in all
four combinations. Internet-enabled combinations require qualification first.
A TUNA provider also needs its ordinary native services configured and running.

## Independent qualification

`provider-canary.mjs` exposes a bounded diagnostic TLS endpoint, HTTP challenge,
UDP echo and authenticated loopback proxy before any app is admitted. The canary's
certificate is separate from every guest certificate. Configure `direct.probe`
with `hostname` (`probe-NAME.enclave.host`), `keyFile`, `certFile`, `tokenFile`
(64 random lowercase hex characters), `udpPort`, and private `manifestFile`.
Restrict the manifest to the agent and independent probe operator.

Without Enclave names, set `independent: true` and `probeZone` (the reviewed public
zone your checkers probe in). The `hostname` is then `probe-NAME.<probeZone>`; an
Enclave zone is refused. The checker's `qualify-provider.mjs` config then needs its
own `independent: true`, the same `probeZone`, and an https `outbound` canary. It
never takes the zone from the host's manifest. See
`docs/network/open-participation.md`, section 1b. With `direct.probe` set, the agent
starts the canary and listens on the direct ports at startup, so a checker can reach
the canary before any app is qualified. A malformed probe stops the start; it is never
ignored.

`qualification-round.mjs` runs on a separate verifier machine. Its JSON config
contains `sshHost`, optional `sshConfigFile`, `remoteManifest`, `remoteReport`,
`hostId`, `operator`, `probeKeyFile`, `connectivity`, and HTTPS Base `rpc`.
It fetches the manifest through authenticated SSH, forwards only the private
proxy, exercises all nine checks, submits the independently signed on-chain report,
and installs the signed report on the host. The signing key never leaves the
verifier. The supplied systemd timer renews within the five-minute validity window.
Keep SSH identity and known-host files under `/etc/enclave-bandwidth` when using
its `ProtectHome` sandbox. A missing report or failed renewal withdraws service.

Qualification includes a real 40 MiB bidirectional echo and SHA-256 comparison.
A timeout is not a successful negative test: forbidden destinations must produce
a SOCKS policy rejection. Direct proxies use per-app RFC-1929 credentials; the
private egress map carries them, while public status strips them. Linux guestd and
Windows shield-egress builds must include `native-direct-auth.patch`.

When direct and TUNA share one public IP, retain one public 80/443 frontend and
route the canary and direct app SNI names to the direct runtime's private listener.
Keep TUNA allocations on their own backend ports. Two processes cannot bind the
same public port. App TLS must remain passthrough; do not install guest TLS keys on
the frontend. The operator must add the direct names and canary to its frontend
configuration before independent qualification can pass.

## Native TUNA shares

`network/tuna/cmd/split-provider-revenue` implements the native NKN split. It
counts only finalized NanoPay receipts addressed to a **fresh, dedicated collection
wallet**. Ordinary funding is not revenue. Two distinct NKN RPC hosts must agree on
complete blocks; stored parent hashes detect chain regression. Cumulative channel
amounts and paid shares survive restarts. The native recipient and percentage are
pinned to the collection policy. Snapshot the production ledger's runnerBps when
creating that policy (currently 8000); changing it requires an explicit migration.

The provider receives its exact gross share. Native transfer fees come from the
platform's share. Small receipts accumulate until both payments are economical.
A 100% provider share with nonzero transfer fees requires a separate fee-payer
implementation and is refused explicitly. Raw signed payouts are saved before
broadcast and checked against their journal fields on recovery. An OS lock prevents
two payout processes from signing concurrently. Keep the encrypted collection
wallet on the payout machine, separate from the public provider's operational key.

Config fields: `collection`, `provider`, `platform` (native NKN addresses),
`providerBps`, `startHeight` (before collection first receives revenue),
`freshCollection: true`, `confirmations` (at least 10), `rpc` (2–5 distinct hosts),
absolute `walletFile`, `passwordFile`, `stateFile`, decimal NKN `fee` and `minimum`,
and `maxBlocks` (1–1000). First run without `--execute` to scan and reconcile. The
supplied payout timer uses `--execute` only after configuration and a live canary.
Never point this policy at the pre-existing us-west beneficiary and count its
historic receipts as new revenue. Native NKN settlement performs no conversion to
USDC and does not route NKN through the USDC verification-fee contract.

## Production activation gate

At Base block 52117810, both independent audit RPCs agreed on schema 15, 70 records,
22 active records, 6.070528 USDC nominal active balances, 4.671277 USDC held in their
existing escrow, and zero current owner-refundable escrow among those active
records. The **existing-ledger backing gap** was 1.399251 USDC. A fresh ledger cannot
spend that old escrow: fully rebacking the new ledger's active nominal balances would
require 6.070528 USDC at that snapshot. Recalculate immediately before cutover.
Old earnings/refund rights stay enforceable at the old ledger. Retain access to them.

The migration engine produced seven import transactions for all 70 records and
44 runner-rate snapshots. It deliberately clears leases; coordinate release and
reclaim rather than claim a zero-interruption lease migration. Preserve publisher
fee snapshots, caps, proof-of-time settings and verification-fee bindings. Inspect
any active verification policies/jobs and reconcile them before switching routers.
The audit at block 52117810 found no verification policies or jobs for the 70 records;
it also captured the proof window, lease duration, caps, bond settings and bindings.
The connectivity administrator now supports a two-step governance handover.

No production financial contract, address-book pointer, provider beneficiary or
customer balance was changed by this work. Activating the release requires the
platform's native NKN payout destination, the existing migration/governance signer,
new ledger backing, independently qualified live providers and live payment canaries.
The connected Trezor is the governance signing path; no migrator private key was
found in the configured environment or named local signer files.


For a shared frontend, `sync-fallback.mjs --direct-frontends FILE` accepts a JSON
array of direct entries `{deploymentId,names,httpsPort,httpPort}` and a diagnostic
entry `{canary:true,names:["probe-NAME.enclave.host"],httpsPort,httpPort}`. Backends
are restricted to loopback and ports outside the reserved TUNA allocation range.
It rejects name collisions and validates HAProxy before installing anything.

During native share activation, update both forward and reverse advertisements
to the fresh collection beneficiary and verify a newly established paid circuit.
Existing circuits can retain their old beneficiary until reconnection. Do not
count their legacy receipts as new-policy revenue.


## USDC TUNA settlement (implemented locally, not activated)

`EnclaveConnectivity.authorizeTuna` accepts an owner-signed provider list (one to
six IDs), expiry, aggregate USDC/GiB cap and a single shared budget. Six allows the
existing two guarded circuits to use three providers each. `viaTuna` separates
this policy from direct authorization; switching policy increments the nonce.
A failed sibling provider cannot prevent settlement to another qualified provider.
The shared price and budget caps still apply. The same qualification criteria gate
direct and TUNA service.

`settleTuna` verifies an anchored receipt signed by both the current runner's
proof key and the provider's proof key, and credits the provider operator's normal
ledger earnings. The compute operator is not credited for that TUNA traffic.
The 80/20 split is snapshotted from `runnerBps`; the platform remainder uses the
existing fee router. Direct self-hosting remains free; a remote TUNA provider is
paid even when the compute host's payout wallet belongs to the app owner.

`network/tuna-usdc-settlement.mjs` produces and verifies the two signatures.
`TunaReceiptSigner.observedBytes` must read the provider's independent durable
meter, never the request's claimed count. It is a transport integration boundary,
not an implemented meter. The shared gas wallet uses one `transactionDirectory`
and in-process queue across provider adapters. Each provider uses a separate
accepted-counter directory. One process owns the gas signer and directories.
An incomplete counter recovery stops another provider from overwriting its
pending/confirmed payment journal. No native-NKN collection wallet is used here.

`connectivity.mjs tuna --id APP_ID --providers PROVIDER_ID[,PROVIDER_ID] --price
USDC_PER_GIB --budget USDC` prepares the new policy. `revoke --id APP_ID` now
explicitly revokes either policy. These are transaction-plan commands unless
`--execute` is supplied. Do not activate the USDC policy against the current
NanoPay-only transport: the agent stops that route instead of silently charging
NKN or granting unmetered service. The normal site TUNA selection retains its
legacy-route behavior until the transport is implemented.

Validation for this follow-up: 346 Solidity tests, 49 targeted JavaScript tests,
agent/browser/vault bundles and generated contract artifacts pass. The ledger's
deployed runtime is 24,575 bytes (one byte below EIP-170); deploy through the
pinned compiler and linked-library pipeline. The real local Anvil integration
uses mock USDC and registry entries but real signatures and transactions. Direct
usage debits 2 USDC and pays 1.6/0.4; TUNA usage debits a further 1 USDC and pays
0.8 to the independent provider and 0.2 to the platform, with no extra compute-host
payment. It rejects unobserved bytes and revocation, and recovers a lost broadcast
response without duplicating payment. No live TUNA traffic or currency conversion
was exercised by that test.
