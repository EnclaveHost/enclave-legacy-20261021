# Decentralization acceptance gates

Censorship resistance is the objective. An Enclave wallet may refuse service on
hosts it owns. It must not stop another consenting host, custodian quorum, storage
operator, or client from serving a deployment. Moving Nan's processes to minipc
completed server retirement, not this objective.

Independent operators do not have to exist before this architecture is finished.
Use separate owner, operator, publisher, custodian and gas-payer identities on test
infrastructure to establish protocol behavior. Do not describe those tests as a
live network of independently operated machines.

## Authority and failure tests

| Path | Required behavior under Enclave refusal | Current gap |
| --- | --- | --- |
| Host admission | Accepted host owner chooses its policy; payout and operator are not ownership | Source and wallet-policy tests exist; compatible runtime activation remains |
| Contracts | Clients retain explicit bindings when the address book is deleted or redirected | Host consumers and CLI support pins; other consumers still need wiring |
| Sessions | An owner grants a bounded session and any gas payer submits it without API/relay access | Fixed-binding factory and direct SDK transactions tested locally; factory not activated |
| Deployments | Explicit release and spending cap reach the ledger without API moderation/quotes | CLI wallet `deploy --chain-only` implemented; funded is distinct from ready |
| Guest boot | Measured guest obtains owner-authorized configuration and custody shares without Enclave's release signer | Production front still requires the signed relay release |
| Custody | Independent host can use a sufficient independent quorum despite Enclave refusing shares | Wallet classification and combiner changes exist; measured membership and release activation remain |
| Artifact storage | Fresh adapter recovers and serves verified CIDs with any one indexer/backend unavailable | Live Sia path still has one indexd/PostgreSQL writer |
| Names and TLS | Fresh client resolves and authenticates a host without enclave.host DNS or the control CA service | Provider directory replicas exist; native bootstrap and independent certificate paths remain |
| Governance | Enclave cannot retire the serving ledger, redirect authorities, or impose an arbitrary global admission restriction | Ledger administration and dependent governance still need a reviewed disposition |

## Implemented client and session path

`enclave --contract-pins pins.json ...` selects a complete version-1 authority
manifest. It does not fall back to the mutable book on a missing/zero/conflicting
binding. Pinning an address does not eliminate administration inside that contract.

`enclave --contract-pins pins.json --wallet deploy ... --chain-only --cpu <0..1>
--gpu <0..1> --max-rate <USD/hour>` submits an explicit release and cap using the
wallet and chain. It refuses relay-held secrets and implicit large-config uploads.
It returns after funding, with `readinessVerified: false`; it does not assert that a
host accepted or booted the deployment. A consenting host still applies its own
resource, isolation and owner-policy checks.

`PinnedSessionVaultFactory` gives each vault an immutable ledger/catalog binding
through an ownerless `PinnedSessionAuthority`. Existing SessionVault action,
signature, budget and revocation rules are retained. Existing vaults are unchanged;
new grants must intentionally select the new factory. Compile review artifacts with
`node scripts/build-pinned-session-vault.mjs NEW_OUTPUT_DIRECTORY`. This command
does not deploy or change a production pin.

The SDK supports relay-free operations:

```js
const opening = await prepareSessionOpen({
  publicClient, factory, owner, chainId, grant, usdc,
});
// Review the explicit factory and authorities before signing the grant.
const { to, data, value } = opening;
const hash = await gasWallet.sendTransaction({ to, data, value });
const receipt = await publicClient.waitForTransactionReceipt({ hash });
if (receipt.status !== 'success') throw new Error('Session opening reverted');

const session = new Session({ chainId, vault: opening.vault, sid: opening.sid,
  relay: '', rpc }, signer, { publicClient });
const operation = await session.prepareCall('deploy.create', deploymentArgs);
// Submit operation.to/data/value with any consenting gas payer, and check receipt.
const ending = await session.prepareTermination();
// Submitting ending returns the remaining budget to the owner, never the gas payer.
```

Direct calls sign a zero relay fee. The gas payer pays network gas. Preparation
does not reserve a nonce: concurrent callers should use distinct lanes, and callers
must rebuild an intent when its nonce has been consumed. Deadlines use chain time,
and the selected RPC's chain ID must match the handle. The SDK's preliminary checks
are conveniences; the vault enforces scope, period limits, attestation, budget,
expiry, replay protection and owner revocation when the transaction executes.

Tests exercise a fresh funded grant, publishing, funded deployment and refund using
an unrelated gas payer with no relay calls. They also reject fee tampering, replay,
an out-of-scope app, budget excess, wrong-chain preparation and already signed
calldata after owner revocation. Separate factory tests delete and redirect the old
address book. These are local-chain results, not a production migration claim.

## Guest provisioning work

The production front verifies an Enclave-signed sealed release before contacting
custodians. A sufficient independent custody quorum therefore cannot currently
boot a new guest through that front while Enclave refuses the release. Do not
remove this check or permit host-supplied config to reach the app unverified.

The replacement must bind the deployment, actual loaded AppID, measured runtime,
current owner intent, custody vault and fresh chain state. Custody bundles already
commit to the exact configuration text; that check must survive. A direct mode
must reject stale state, hostile committee substitution, configuration substitution
and secret-free downgrade, and must not silently fall back to the legacy relay.
Its chain RPC/bootstrap egress, runtime measurements and host supervisor protocol
must be activated together. Existing secret deployments remain on their validated
path until their replacement passes these gates.

## Storage and production acceptance

Copies of one Sia wallet/database must not become concurrent live writers.
Independent storage backends need separate wallets/indexers, verified read fallback,
explicit write durability, and a recoverable immutable index. Mutable object
conflicts and partial writes require defined semantics before enabling a pool.

Final acceptance includes a cold client and guest start with Enclave control,
identity, release, DNS and one storage backend denied; deployment and funding by a
new wallet; continued independent-role service under an Enclave host-wallet veto;
and owner revocation/transfer still taking effect. Production activation and these
failure demonstrations remain required. The existence of backups or four
Enclave-operated replicas does not satisfy these gates.
