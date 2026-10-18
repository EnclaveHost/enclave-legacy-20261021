# Nan retirement — implementation and cutover gates

Censorship resistance is the acceptance criterion. Moving every service to another Enclave-operated machine is insufficient. Enclave's wallet may decline deployments on its own hosts; a consenting independent host and sufficient independent custody quorum must continue serving. Application TLS remains inside the guest.

## Implemented and deployed

Four public signed-record directories run on the existing provider machines. They verify provider records, qualification verdicts, owner network policies and short-lived routes against chain state. Windows and metal0 publish directly; the Windows enrollment path preserves the configured directories. Duplicate gossip is skipped and lease reads are batched. The current observation is 12 active app publications across all four directories. All four are still Enclave-operated.

Legacy mirrors, BYO credentials, custom domains and the temporary public-policy bridge remain during migration. This is not an outage acceptance result and nan must remain running.

## Storage release prepared

The s3-ipfs-adapter release adds direct deployment-bound EIP-191 upload authorization, preserving HMAC compatibility. CLI and console support the direct protocol but it is not the production default until the adapter has been upgraded. Contract wallets and delegated sessions require further work. The new WASM has been uploaded to the actual adapter and fetched back with its hash checked. Publishing and changing the production deployment require its owner's hardware-wallet signatures.

The active app bootstrap inventory is being copied and CID-verified separately. The Sia S3 guest still calls indexd on nan, backed by PostgreSQL. Both that dependency and the metadata/key recovery path must migrate before storage is independent.

## Host ownership and veto: source only, not deployed

`EnclaveHostOwnership.sol` pins a registry and establishes wallet ownership through two-party consent: the registered operator nominates the initial owner and that wallet accepts. Existing ownership can only be transferred by the old owner nominating and the new owner accepting. No administrator can set a global veto. Payout declarations never confer policy authority.

A host owner commits a local admission document with `setPolicy`. The document binds chain ID, ownership contract and host ID, and carries deployment/app-reference denials and a local choice to require catalog approval. A fresh agreeing chain quorum identifies the current commitment; a missing or mismatching nonempty document fails closed for that host. Transferring ownership clears the former owner's policy. There is no network-wide application deny list.

The custody combiner now accepts a sufficient independent quorum when Enclave answers challenges but refuses or supplies invalid shares. Thresholds, share checks and duplicate-seat exclusion remain intact. The live committee still consists of a single Enclave seat, so source changes alone cannot create independent recovery.

Do not deploy this custody change as a completed veto migration. Remaining work includes host admission integration, publishing and binding host ownership, signed/measured runtime releases, replacing payout-based custody classification, and redistribution into an independently operated committee. Existing catalog-wide approval gates still need replacement with the verified host-local policy in all serving paths.

## Required retirement evidence

- Independent operators and custodians selected and enrolled, with an independent quorum that can actually release.
- No required nan origin in artifact, policy, host-control, identity, DNS, certificate or custody paths.
- S3 writes, raw/CAR reads and all retained content survive loss of nan and one storage endpoint.
- Clean-host startup restores artifacts, secrets and persistent state while nan and the app owner are offline.
- New users authenticate, upload and deploy through the supported independent path.
- Wallet veto stops only its own host; independent hosting continues. Ownership transfer revokes the former wallet.
- Native ENS recovery works without enclave.host, and guest TLS renewal succeeds independently.
- A timed nan outage demonstrates these properties before services or data on nan are removed.
