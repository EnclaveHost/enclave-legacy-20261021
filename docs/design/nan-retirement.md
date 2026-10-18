# Nan retirement — implementation and cutover gates

Censorship resistance is the acceptance criterion. Moving every service to another Enclave-operated machine is insufficient. Enclave's wallet may decline deployments on its own hosts; a consenting independent host and sufficient independent custody quorum must continue serving. Application TLS remains inside the guest.

## Implemented and deployed

Four public signed-record directories run on the existing provider machines. They verify provider records, qualification verdicts, owner network policies and short-lived routes against chain state. Windows and metal0 publish directly; the Windows enrollment path preserves the configured directories. Duplicate gossip is skipped and lease reads are batched. The current observation is 12 active app publications across all four directories. All four are still Enclave-operated.

Legacy mirrors, BYO credentials, custom domains and the temporary public-policy bridge remain during migration. This is not an outage acceptance result and nan must remain running.

Providers and the checker publish only to the four direct directory origins. The legacy DNS/API lost routes when its old provider records expired; `scripts/network/mirror-public-providers.mjs` now pulls signed provider and qualification records into that legacy consumer. It preserves negative verdicts, uses the destination's existing verification, and holds no signing keys. This bridge keeps current DNS working until DNS/ENS migration; it does not make nan authoritative for the independent directories.

## Storage release prepared

The s3-ipfs-adapter release adds direct deployment-bound EIP-191 upload authorization, preserving HMAC compatibility. CLI and console support the direct protocol but it is not the production default until the adapter has been upgraded. Contract wallets and delegated sessions require further work. The new WASM has been uploaded to the actual adapter and fetched back with its hash checked. Publishing and changing the production deployment require its owner's hardware-wallet signatures.

The 17 active/release bootstrap CIDs are copied and CID-verified on four public replicas; all missing active WASM and config objects were seeded into the actual adapter. All 936 unique retained CIDs (4,690,923,948 bytes, from 1,239 inventory entries) are now locally CAR-verified and served on every replica. All 7,488 raw/CAR HTTP HEAD checks and full content samples passed. This is a recovery snapshot, not live backing-state replication. One 101 MB adapter CAR transfer failed after two attempts, with the final response truncated; ranged raw retrieval rebuilt its exact CID, and the resulting static CAR passed complete public readback. Streaming reliability still needs investigation. The Sia S3 guest still calls indexd on nan, backed by PostgreSQL. Both that dependency and the metadata/key recovery path must migrate before storage is independent.

## Host ownership and veto: source only, not deployed

`EnclaveHostOwnership.sol` pins a registry and establishes wallet ownership through two-party consent: the registered operator nominates the initial owner and that wallet accepts. Existing ownership can only be transferred by the old owner nominating and the new owner accepting. No administrator can set a global veto. Payout declarations never confer policy authority.

A host owner commits a local admission document with `setPolicy`. The document binds chain ID, ownership contract and host ID, and carries deployment/app-reference denials and a local choice to require catalog approval. A fresh agreeing chain quorum identifies the current commitment; a missing or mismatching nonempty document fails closed for that host. Transferring ownership clears the former owner's policy. There is no network-wide application deny list.

The custody combiner now accepts a sufficient independent quorum when Enclave answers challenges but refuses or supplies invalid shares. Thresholds, share checks and duplicate-seat exclusion remain intact. The live committee still consists of a single Enclave seat, so source changes alone cannot create independent recovery.

The proposed vault now pins `EnclaveHostOwnership` and its registry at construction. Custodian admission computes the Enclave seat from accepted ownership, never payout declarations. The image builder requires an explicit `--host-ownership` pin. Its membership reader checks fresh agreeing chain state, checks that the vault matches that measured pin, and refuses legacy vaults without that authority interface. This is a new contract/runtime deployment, not an in-place update: leave existing committees on their compatible runtime until a controlled bundle/committee migration is ready. Existing committee flags remain epoch snapshots; ownership changes affect new admissions/handovers.

Do not deploy this custody change as a completed veto migration. Remaining work includes publishing and binding host ownership, signed/measured runtime releases, activating the new wallet-based custody classification, and redistribution into an independently operated committee. Frontend/CLI catalog gates and other serving paths still require review; existing production runtimes retain their old gates until explicitly activated.

### Host runtime integration (prepared, not activated)

Windows host claims, scans, forced launches and live renewal ticks now consult the host's wallet policy when explicitly configured. A refusal stops the local app before releasing its lease; it does not mark the deployment globally forbidden or permanently prevent a later retry. Linux supervisor claim/version/config gates, live audits and renewals use the same authority; its unconditional yank sweep is disabled in this mode. Resource, tenant consent, placement, isolation, publisher-fee and lease checks remain.

Activation requires `ENCLAVE_CONTRACT_PINS_FILE` plus all four settings: `ENCLAVE_HOST_OWNERSHIP`, `ENCLAVE_HOST_REGISTRY_PIN`, `ENCLAVE_HOST_CATALOG_PIN`, and `ENCLAVE_HOST_POLICY_DIR`. The directory contains public `<policyHash>.json` documents. Policy and catalog pins are read from configuration, never the mutable book. The ownership contract's registry must match the configured pin. Two independently configured RPCs must agree at a recent block; accepted wallet-policy snapshots are reused for at most 15 seconds and cannot outlive the 90-second chain freshness window. Missing ownership, unavailable quorum, unavailable committed documents and mismatches refuse locally. A zero commitment from an accepted owner means no catalog veto and no deny entries. All approval/yank checks in these two runtimes are then host-local choices. Legacy behavior remains only when this mode is unconfigured.

This mode requires an exact on-chain deployment ID: the supervisor's legacy direct, non-ledger creation API cannot satisfy wallet policy and refuses. The new contract pin file fixes the ledger, registry, catalog and proof bindings at process start in both host runtimes; the Linux address-book watcher is disabled and Windows resolution uses those pins without contacting the book. Optional payment/audit bindings are explicit, including zero for disabled services. Session factory and custody discovery entries are recorded for subsequent consumers but are not yet wired into all identity/custody paths. The production release must not be described as censorship resistant until those paths, custody and the full outage gates pass.

Capture current bindings and bytecode hashes with `node scripts/network/capture-contract-pins.mjs --book <address> --out <directory>` using agreeing fresh RPCs. Review every binding before activation; absent book entries do not prove that a legacy deployment does not exist.

Build the shared runtime with `node scripts/build-host-admission.mjs`; `--check` verifies the committed bundle. Windows' import-closure deployment and the supervisor Dockerfile include that bundle so neither depends on a missing sibling npm installation.

## Required retirement evidence

- Independent operators and custodians selected and enrolled, with an independent quorum that can actually release.
- No required nan origin in artifact, policy, host-control, identity, DNS, certificate or custody paths.
- S3 writes, raw/CAR reads and all retained content survive loss of nan and one storage endpoint.
- Clean-host startup restores artifacts, secrets and persistent state while nan and the app owner are offline.
- New users authenticate, upload and deploy through the supported independent path.
- Wallet veto stops only its own host; independent hosting continues. Ownership transfer revokes the former wallet.
- Native ENS recovery works without enclave.host, and guest TLS renewal succeeds independently.
- A timed nan outage demonstrates these properties before services or data on nan are removed.

The proposed vault also pins its deployment ledger and SessionVault factory at construction; the compatible release reader uses that ledger and the pinned host registry. A real-chain test clears the book's ledger/registry entries and verifies that the independent custody quorum can still release. Older deployed vaults and readers retain their legacy authority path until explicitly migrated. Other serving and discovery paths still resolve mutable address-book entries; this custody change alone does not remove all global authority.
