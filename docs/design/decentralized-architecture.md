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
| Guest boot | Measured guest obtains owner-authorized configuration and custody shares without Enclave's release signer | Direct measured entry point and bounded guestd transport built and tested; production remains on legacy startup pending supervisor/package wiring and hardware activation |
| Custody | Independent host can use a sufficient independent quorum despite Enclave refusing shares | Wallet classification and combiner changes exist; measured membership and release activation remain |
| Artifact storage | Fresh adapter recovers and serves verified CIDs with any one indexer/backend unavailable | Live Sia path still has one indexd/PostgreSQL writer |
| Names and TLS | Fresh client resolves and authenticates a host without enclave.host DNS or the control CA service | Provider directory replicas exist; native bootstrap and independent certificate paths remain |
| Governance | Enclave cannot retire the serving ledger, redirect authorities, or impose an arbitrary global admission restriction | Irreversible ownership seal and fixed-block review tooling implemented; production ownership and dependency review remain outstanding |

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

### Owner-committed startup package

The implementation in `isolation/m2/bootstrap` authenticates a new, explicit
startup intent from the pinned deployment ledger. The owner's ledger envelope
contains `guestBootstrap: {version: 1, sha256: "<64 lowercase hex>"}`. The hash
covers the **exact UTF-8 bytes** of a public startup package. The host or any
storage provider may deliver those bytes; neither becomes an authority. There is
no fallback to an unsigned host configuration, a legacy relay, or secret-free
startup when verification fails. Direct intent cannot coexist with legacy
`config` or `configCid` fields.

The package contains version, chain ID, pinned ledger, deployment ID, current
ledger owner, exact app reference, loaded AppID, RuntimeID, exact `configText`,
and an explicit `public` or `custody-v2` secrets mode. Custody mode additionally
contains the owner-committed v2 pointer. It includes no plaintext secret values.
The package is limited to 128 KiB and config text to 32 KiB; duplicate JSON keys,
unknown package fields and excessive nesting are refused. CLI publishing and
package distribution still need wiring. A package is not self-authorizing: a
matching owner transaction on the ledger is mandatory.

The guest's reader uses at least two distinct HTTPS RPC hosts at a fixed confirmed
block, checking chain ID, ledger schema, complete ABI response, deployment ID,
active lease, block freshness and block hash before/after reading. An unavailable
or disagreeing third peer does not override an agreeing pair. A per-reader high
water mark refuses earlier state after an accepted read. This is explicitly RPC
quorum trust, not a chain light client; RPC endpoints, ledger and TLS roots belong
to the measured runtime, not a host-supplied configuration file.

`front.runDirect` authenticates the package against the loaded code and runtime,
obtains custody shares through the existing attested protocol, preserves the
decrypted bundle's exact `ConfigSha256` check, and rechecks owner, lease and
envelope immediately before app startup. A transferred owner, changed runner,
changed configuration, expired lease or unavailable quorum invalidates startup.
Egress derives from this authenticated owner config without implicitly adding
`api.enclave.host`. Application listeners and resolver files retain the existing
startup audit.

Integration tests exercise direct public startup with the ticket service refusing,
and a real cryptographic v2 quorum with both Enclave replicas refusing shares while
three independent seats complete release. They also reject an otherwise
owner-committed package whose config differs from the custody bundle's commitment.
Chain/attestation services in these integration tests are synthetic; they do not
prove hardware deployment or an independently operated production quorum.
Cross-language ABI vectors come from viem (`scripts/guest-bootstrap-vectors.mjs`).
Race-enabled tests and a bounded ABI-decoder fuzz run pass.

The actual `main` entry point now calls `runStartup`. A `bootstrapdirect` build
selects direct startup at compile time; the default build preserves legacy
release startup. Neither a host flag nor a failed ticket switches a guest between
these modes. The direct path reads a bounded deployment-bound frame on vsock
9446, uses the measured Base ledger and three distinct HTTPS RPC origins, and
never loads relay signing keys. Bootstrap RPC origins are not added to tenant
egress. Its central custom-domain watcher is disabled; independent custom-domain
authorization is still outstanding.

Guestd's dedicated `-direct-bootstrap -release` mode requires an explicit
CPU template with the direct marker and verifies its complete release manifest
against exactly one pinned release ID. An optional Shield template must carry the
same mode marker. The host accepts base64 of the exact public package at create,
refuses mixed ticket/legacy startup, routes it only to the matching starting CID,
and retains direct mode and egress admission when adopting a running guest.
The package is never included in the public VM response or persisted restart
record. This transport supplies bytes, not authorization; the guest still checks
the owner's chain commitment before use.

`ISOLATION_DIRECT_BOOTSTRAP=1 sh isolation/m4/domain-release.sh <new-dir>` builds
this separate release. Two local builds produced the same 18-file manifest and
release ID `51a7f6e8cef02398d5d7de273bd35e189736398022efe1f528dd07819d683ead`.
Live read-only checks with the measured TLS roots and RPC pins agreed on the
production ledger at Base block 52,820,654, including each of the three possible
single-provider omissions. This proves the present RPC path, not guest hardware
startup or tolerance of two compromised RPC providers.

**Activation remains incomplete:** the production guests still run legacy
release images. The supervisor still rejects the new envelope namespace; CLI
package preparation, durable package distribution, runtime admission and owner
custody-rule updates remain to be connected. Cold hardware recovery with the
control service denied is still an acceptance gate. Existing deployments and
release-key checks have not been weakened.

## Governance disposition

The live ledger's owner can retire it, raise claim bonds, slash operator bonds,
restrict new allocations, change runner economics and change proof enforcement.
Explicit address pins do not remove these powers. Its proof verifier also has
an owner-controlled proof window. These are global powers, unlike a host owner's
right to decline work on that owner's machines.

`GovernanceSeal` is an irreversible ownership sink with no forwarding, upgrade,
recovery, withdrawal or administrative entry point. It commits to the chain,
target address, target bytecode and an ordered list of getter responses. The
target's current owner must first nominate it using the target's existing
two-step handoff; anyone can then finalize, but only while the reviewed target
code and configuration still match. Nomination alone remains cancellable by the
current owner. After acceptance there is no administrative recovery path.

Prepare review evidence without a wallet or Enclave API:

```sh
node scripts/capture-governance-review.mjs \
  --ledger 0xB1783B61E1FDee6a6163DC3CdaC27bF32E7d117B \
  --catalog 0x18419ca2b502d423a8de6269aeee171a378626e3 \
  --out /path/to/new-governance-review.json
node scripts/build-governance-seal.mjs /path/to/new-seal-artifacts
```

The capture requires two agreeing RPCs at the same recent block and refuses
unknown contract revisions, malformed getters and absent dependency bytecode.
Profiles cover the ledger's 17 configuration getters, the proof verifier's four,
and the catalog's three; ownership is recorded separately so nomination does not
invalidate the commitment. It reports unsealed imports, retired/disabled ledger
settings, missing one-time router bindings and pre-existing nominations. An empty
blocker list is **not approval to seal**: bytecode identity, linked libraries,
proxies, dependent governance and the chosen permanent economic parameters still
require review. Neither command prepares or sends transactions.

Each seal checks its own target only. In particular, a ledger seal does not seal
its proof verifier, token, oracle or routers. Catalog approval/rejection rows are
not enumerable configuration commitments; independent consumers must stop using
those rows as global admission authority, regardless of catalog ownership.
USDC issuer and underlying chain/oracle authority are external trust assumptions,
not powers removed by this mechanism.

`GovernanceSeal.hosting.t.sol` uses the real registry, ledger and proof verifier
to register a new independent runner after sealing, create/fund work, submit a
signed service checkpoint via an unrelated gas payer, renew, collect earnings,
and preserve tenant stop/refund/transfer rights. Former governance shutdown,
slashing, admission restrictions and proof-window changes fail. Its token and
attested signing key are fixtures; it does not prove live TEE or custody behavior.
`GovernanceSeal.liveFork.t.sol` repeats that scenario on the actual Base ledger
and bound contracts, using a local fork and test-only role impersonation:

```sh
forge test --match-contract GovernanceSealLiveForkTest \
  --fork-url https://mainnet.base.org --fork-block-number REVIEW_BLOCK -vv
```

The fork test is skipped on the default non-Base test chain. Fork writes never
reach production. No production ownership has been changed; activation must
follow dependency review and must not freeze a configuration still needed by the
guest/custody transition.

On 2026-10-19, the read-only capture at Base block 52,819,670 found the live
ledger, proof verifier and catalog still owned by the Enclave wallet, with no
pending handoff. Imports were sealed, the ledger was active, and its current
proof/fee/bandwidth dependencies were bound. Seven local seal/hosting tests and
five review-tool tests passed. The production-code fork scenario passed at that
same block, including refusal of the former governor's attempt to slash a funded
runner bond and the runner's subsequent full bond withdrawal. These results
support the proposed governance change, not completion or activation of it.

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
