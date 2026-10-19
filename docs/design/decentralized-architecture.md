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
| Host admission | Accepted host owner chooses its policy; payout and operator are not ownership | Windows runtime enabled on its enrolled authority; Linux measured delivery and mirror tests implemented, metal0 enrollment and runtime activation remain |
| Contracts | Clients retain explicit bindings when the address book is deleted or redirected | Host consumers and CLI support pins; other consumers still need wiring |
| Sessions | An owner grants a bounded session and any gas payer submits it without API/relay access | Fixed-binding factory deployed and bytecode verified on Base; clients/grants not migrated |
| Deployments | Explicit release and spending cap reach the ledger without API moderation/quotes | CLI wallet `deploy --chain-only` implemented; funded is distinct from ready |
| Guest boot | Measured guest obtains owner-authorized configuration and custody shares without Enclave's release signer | Public startup passed on real SNP hardware with guest control egress denied; production remains on legacy startup, and independent custody/retention are outstanding |
| Custody | Independent host can use a sufficient independent quorum despite Enclave refusing shares | Independent committee genesis, DKG, measured accepted-owner admission and API coordination implemented; production vault/runtime migration and hardware quorum evidence remain |
| Artifact storage | Fresh adapter recovers and serves verified CIDs with any one indexer/backend unavailable | Verified multi-adapter publication and cold reads exist; sealed Sia snapshots now recover real artifacts with indexd blocked. Live writes, funding and renewal still depend on the existing service |
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
supervisor distribution use exact raw CIDs. A package is not self-authorizing: a
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

The supervisor resolves the exact package through operator-selected HTTPS
gateways (`GUEST_BOOTSTRAP_GATEWAYS`, up to eight; default ipfs.io and dweb.link).
It verifies size, hash and deployment/owner/app/runtime scope before claiming,
and rechecks the ledger before creating a guest. The claim path uses committed
config for resource and volume checks. Direct startup skips relay release lists,
secret-existence probes and domain probes. Custody authorization uses only the
vault committed by the owner. Neither a failed gateway nor an unsupported manager
falls back to legacy startup. Verified immutable bytes may be cached in memory;
scope is checked again on each use.

On restart, guestd preserves the package hash with the VM record. The supervisor
adopts a guest only when direct mode, package hash, loaded AppID, RuntimeID and
derivation match. A changed package replaces the guest rather than adopting old
configuration under the new commitment. Guestd does not persist package bytes.

### CLI package workflow

Use a reviewed authority manifest with `--contract-pins pins.json` throughout.
For a new deployment, `deploy <app:version> --chain-only --prepare-only --cpu …
--gpu … --max-rate …` creates an unfunded record with an unavailable startup hash
and an SNP requirement. It does not briefly run with a default configuration,
even on a host that waives compute charges.

1. `bootstrap prepare <full-id> --config-file config.json --app-id <64hex>
   --runtime-id <64hex> --public --out startup.json` creates a public package
   using the current ledger owner and app reference. For secrets, use
   `--custody-file pointer.json` instead of `--public`. The file contains a v2
   custody pointer, never plaintext secret values. The output is created
   exclusively and refuses to overwrite an existing file.
2. `bootstrap publish <full-id> --file startup.json --upload https://<adapter>/add-json
   --audience <adapter-deployment-id> --wallet` signs an endpoint-, body- and
   deployment-bound upload request. A consenting adapter can accept it without
   an Enclave upload-token issuer. The returned CID must match the exact bytes.
3. `bootstrap activate <full-id> --file startup.json --gateways https://<gateway>/ipfs
   --wallet` verifies gateway readback before submitting the owner hash to the
   ledger. This preserves placement and other envelope namespaces while replacing
   legacy config fields. Activation can also emit an unsigned transaction with
   `--unsigned --from <owner>`; publication requires a message-capable signer.
4. Fund the prepared deployment only after checking that the chosen host supports
   its direct runtime and that the public package is durably available. Activation
   does not fund the record or claim readiness.

`config show` identifies an owner startup commitment without pretending that the
catalog default is its effective config. `config set/clear` refuses app-config
edits to such records; prepare and activate a replacement package instead.
WAF-only envelope edits preserve the commitment, but still require support from
the chosen runtime. Package publication and activation currently use a direct
wallet; deployment ownership by a session vault needs a separate supported
activation flow.

Tests use the actual CLI transaction builder and supervisor launch/spawn paths,
with independent storage responses and all central API calls refused or asserted
absent. Corrupt/oversized responses cannot lead to a commitment. These are local
integration tests, not evidence of independent production storage or hardware
startup.

`ISOLATION_DIRECT_BOOTSTRAP=1 sh isolation/m4/domain-release.sh <new-dir>` builds
this separate release. Two local builds produced the same 18-file manifest and
release ID `51a7f6e8cef02398d5d7de273bd35e189736398022efe1f528dd07819d683ead`.
Live read-only checks with the measured TLS roots and RPC pins agreed on the
production ledger at Base block 52,820,654, including each of the three possible
single-provider omissions. This proves the present RPC path, not guest hardware
startup or tolerance of two compromised RPC providers.

### Hardware public-startup evidence (2026-10-19)

A separate guestd with a `db` instance prefix and isolated measured transport
ports ran EnclaveDNS 0.1.4 on the real metal0 AMD SEV-SNP processor. The existing
scoped CLI session committed a public startup package on Base; its vault owned
deployment `0x87508b958c4d14381b58fe05a781efbd3f185a36d5239abdf37e8f242f944538`.
An operator submitted the prepared session calls directly to Base without the
central relay. The test funded 0.01 USDC and used an explicit active lease.

Release `5ef70f6a950b1deadcf21119a0e02ba2f75dea029d870ef25a0e6d7940ac9aad`
retained the production measured RPC hosts and TLS roots; only transport ports
differed. After the baseline guest was destroyed, a new guest booted while
`lab-bootstrap/egress` refused all guest destinations except those measured
chain peers. Its actual dial path rejected api/ipfs/s3/nan.enclave.host before
accepting the guest. The guest received 108 bytes of owner-committed config,
started with zero tenant egress origins and reached readiness in 4,937 ms.
It did not request a release ticket.

The fresh guest's measurement was
`caf11b488b5235182d5b4628f0d663d454585d84a790bb9b303cedb2ea99690496951529ca395ff032d5a729b30a733a`.
The judge verified the AMD Turin signature chain, runtime/AppID/deployment
bindings and fresh transport challenge at T1. A separate TLS client matched
the attested SPKI before transmitting an HTTP request and received `200 ok`.
The guest and both lab services were then stopped. Owner suspension, operator
release and refund confirmed at Base blocks 52,821,885, 52,821,894 and 52,821,895.
The test spent 0.006066 USDC of runtime credit; transaction gas was additional.

This establishes a fresh **public-config guest startup** without central
guest-control access. The host's verified artifact cache was warm and its
retained bundle came from an Enclave-operated provider. The local package
broker was untrusted but available. Production services remained online for
other tenants; there were no independently operated participants or custody
shares in this test. It does not establish independent artifact retention,
storage/indexer recovery, custody quorum availability or new-user discovery.

Live reads also demonstrated that a confirmed RPC view can briefly precede a
recent claim/resume receipt. `AuthorizeWhenConfirmed` now permits a bounded
30-second wait, retrying only unavailable chain snapshots. Each attempt retains
the original two-peer agreement, confirmation depth, freshness and rollback
checks. Invalid packages and agreeing owner/commitment mismatches fail
immediately; post-custody revalidation still fails closed. Race tests cover
claim visibility, deadline/cancellation, stale/unavailable peers, bad owner
commitments and revocation before app start. This later retry change was not
included in the hardware-tested release above.

**Activation remains incomplete:** production guests still run legacy release
images. Durable package replication, production runtime admission and owner
custody-rule updates remain to be activated. End-to-end cold recovery with
independent storage and custody remains an acceptance gate. Existing
deployments and release-key checks have not been weakened.

## Startup package storage without one required backend

`bootstrap publish` and `bootstrap activate` accept `--storage-plan FILE`.
A version-1 plan names two to eight adapters, each with a distinct deployment
ID and hostname, and requires at least two verified copies. For example:

```json
{
  "version": 1,
  "minimumCopies": 2,
  "replicas": [
    {"upload":"https://storage-a.example/add-json","audience":"0x1111111111111111111111111111111111111111111111111111111111111111","gateway":"https://storage-a.example/ipfs"},
    {"upload":"https://storage-b.example/add-json","audience":"0x2222222222222222222222222222222222222222222222222222222222222222","gateway":"https://storage-b.example/ipfs"},
    {"upload":"https://storage-c.example/add-json","audience":"0x3333333333333333333333333333333333333333333333333333333333333333","gateway":"https://storage-c.example/ipfs"}
  ]
}
```

Each adapter receives its own deployment-bound wallet signature and may use its
own S3-compatible backend and credentials. Publication uploads the exact bytes,
checks the returned CID, then reads them back from that adapter's gateway and
verifies the owner package hash. Responses are bounded; redirects are refused;
a failed, corrupt or unavailable adapter does not count. Requests run concurrently
with a bounded per-adapter deadline. Two of three verified copies permit success
when one refuses. An upload acknowledgement alone is insufficient.

Activation repeats the readback against the plan before preparing/submitting the
owner's chain commitment. Falling below the required copies prevents activation;
it does not erase already stored copies or stop an existing host. The explicit
single-adapter flags remain supported for older workflows but do not establish
replicated publication. A plan cannot be mixed with those endpoint overrides.

Hosts can select the same file with `GUEST_BOOTSTRAP_STORAGE_PLAN_FILE`. It is
operator configuration, not an arbitrary URL injected by a tenant. The supervisor
reads a bounded, validated file, fetches concurrently from those gateways and
accepts any exact owner-committed package. It does not require the upload quorum
to remain available to boot from one surviving copy. Malformed plans and conflicting
gateway settings fail closed. No central provider API is needed for this explicit
configuration; automatic discovery remains separate work.

Validation runs three real Rust adapter processes, three separate disk-backed
MinIO S3 stores and certificate-verified loopback TLS fronts. With the first S3
backend stopped but its adapter still reachable, a new package publishes to the
other two. Restarting both surviving stores and adapters clears their process
memory; each independently serves the old and new package. A fresh package fetch
recovers the exact committed bytes, and losing another store refuses new activation
below the two-copy requirement. SDK/CLI tests also reject false upload claims,
corruption, duplicate service identities and insufficient copies; supervisor tests
exercise cold fetches with two endpoints refusing and the third serving.

These are local protocol and recovery tests, not SNP attestation or independently
operated production storage. Distinct hostnames/deployment IDs do not prove different
owners or backing stores. Readback proves current availability, not a future
retention guarantee. Large WASM/runtime artifacts and existing production data
have not migrated through this path; minipc's live Sia/indexd/PostgreSQL dependency
remains until their independent retention and recovery are activated and verified.

## Replicated app publication and artifact retrieval

`enclave --wallet --contract-pins pins.json publish app.wasm --slug my-app
--storage-plan storage.json` uses the same operator-selected adapter plan as startup
packages. It does not request a token from Enclave's API. Each adapter gets a
wallet signature bound to that adapter deployment, upload path, exact SHA-256,
byte count and expiry. WASM uses `/add-wasm`; a large default config uses
`/add-json`. `--config-file FILE` reads configs up to 1 MiB without shell argument
limits. The catalog version is submitted only after both WASM and any external
config have the required number of verified copies. JSON output includes their
separate availability reports.

The client computes the expected file CID before uploading: CIDv1, SHA-256,
256 KiB raw leaves and a balanced UnixFS tree with 174 links per node. It checks
the uploader's CID against that local result. Upload bodies stream in bounded
chunks instead of giving fetch a separate whole-file Buffer for every adapter.
The CLI still holds the original input file in memory; this is not a fully
streaming local-file pipeline. Input sizes are capped at the adapter limits.
Readback requests bounded byte ranges and verifies every byte against the local
full-file hash, rejecting truncation, corrupt bodies, incorrect ranges/totals or
an ignored range that would exceed the window. The default deadline bounds each
adapter's complete upload/readback attempt; very large or slow transfers can fail
that availability requirement rather than publish an unverified version.

Guestd's existing `-gateway` option accepts an explicit JSON array of gateway
origins. Operators configure these to the same stores, for example
`-gateway '["https://storage-a.example","https://storage-b.example","https://storage-c.example"]'`.
The supervisor's advisory recovery probe now supports that array through
`IPFS_GATEWAY`, or derives origins from `GUEST_BOOTSTRAP_STORAGE_PLAN_FILE`.
It probes replicas concurrently and backs off failed origins individually.
One unavailable origin cannot mark the whole group unavailable. A successful
probe still requires guestd's full CID verification before serving.

Validation compares the local importer with a fresh offline Kubo at empty,
single-byte, chunk-boundary and 174/175-chunk tree-boundary sizes. Three real
Rust adapters and separate disk-backed MinIO stores accept a 50 MiB component
with a large custom section, exercising multipart upload and a two-level UnixFS
tree. A new CID still publishes when one S3 backend stops. After both surviving
stores and adapters restart, every byte of the old and new artifacts is verified.
Guestd's actual Python CAR fetcher also reconstructs the new file through the
surviving TLS gateways with no cached output. This is artifact recovery, not a
new guest boot or application execution. CLI tests confirm that insufficient
WASM copies or insufficient config copies prevent the catalog transaction and
that no token-issuer API call occurs.

The production adapter and existing retained artifacts have not been migrated to
multiple independent backing stores. The opt-in runtime-file path below adds
publication and recovery support for kernel/runtime bytes; production activation
and retention policies remain pending. No claim is made that these tests fix the previous production Sia CAR
truncation or CONNECT failures. Production Sia/indexd/PostgreSQL, operator
independence and durable retention remain explicit completion gaps.

## Runtime and kernel artifact storage

`enclave artifact publish vmlinuz --storage-plan storage.json --wallet --json`
uses the same local CID calculation, wallet scope, multipart streaming and complete
readback checks for generic runtime bytes. The default `--kind file` selects
`/add-file`; explicit `wasm`, `json` and `image` kinds use their validating routes.
`enclave artifact verify vmlinuz --storage-plan storage.json --json` rechecks
availability without a wallet, platform session, Enclave API or contract lookup.
Neither command changes catalog records or admits a runtime. Runtime measurement
and approved-image checks still apply separately when a host boots those bytes.

Adapters must explicitly enable generic files with a positive
`upload.maxFileBytes` (default zero, hard maximum 2 GiB) and configure
`upload.walletAudience`. `/add-file` accepts only a direct wallet signature bound
to that route: legacy HMAC tokens and `allowUnsigned` do not authorize it.
Generic files share the existing four streaming slots, multipart handling and
per-wallet/global byte budgets. `/add-wasm` still rejects non-WASM bytes.
Operators must choose their own storage/retention policy; accepting bytes does
not establish durable payment, a retention contract or organizational independence.

The real three-adapter integration test additionally uploads the pinned 17,232,384-byte
kernel, stops one backing store, publishes a new multipart generic artifact to
the remaining two, then restarts both survivors. It verifies both generic files
and reconstructs the original kernel through guestd's CID-verifying CAR fetcher
into an empty output file. The pinned kernel SHA-256 is
`1a3a02d5a982946e6cec2590171ba742e5528c647790a9ed9127879b76a124e7`.
The harness also checks disabled-route refusal, unsigned and cross-route refusal,
oversize refusal before body transfer, unchanged WASM classification and gateway
sandbox/nosniff headers. Both native Rust and the release WASM running under Wasmtime pass this scenario.
These are separate test stores on one machine; no new
production kernel boot or independent operator is claimed.

## Independent custody formation

The previous v2 committee could only be created by an Enclave-owned founder;
non-Enclave membership depended on a measured Enclave capacity-witness key.
The new `createIndependentCommittee` path needs 3–64 distinct accepted owner
wallets, host IDs, encryption keys, identities and chips. It starts at
`ceil(2n/3)` and accepts only a unanimous set of founder signatures over the
exact machine order, code set and polynomial commitments. Anyone can submit
those signatures. No Enclave founder, capacity witness or transaction sender
receives administrative authority. The existing committee path is retained
for existing deployments; this function requires a new vault deployment.

`custody/dkg` pins `frost-secp256k1` 3.0.0 and its Cargo lockfile. It implements
the library's three DKG phases through private local pipes, not HTTP. The
JavaScript measured-guest adapter authenticates each first-round broadcast,
requires every member to acknowledge the same broadcast digest, and encrypts
signed second-round messages to each recipient with HPKE. Every message is
bound to chain, vault, salt, machine order, code set and transcript. The final
share is persisted before any founder signature is emitted; a crash between
persistence and signing resumes that result. See the upstream
[DKG communication requirements](https://docs.rs/frost-secp256k1/3.0.0/frost_secp256k1/keys/dkg/index.html).
This integration is not an external cryptographic audit.

Build a separate measured image with
`--independent-owners owners.json` added to `scripts/build-custodian-v2.mjs`.
The file is a JSON array of 3–64 accepted non-Enclave owner addresses. The
image includes the static musl DKG helper, its hash and build metadata. This
is an explicit committee-local admission policy: it does not claim that
distinct wallets prove independent organizations or provide permissionless
Sybil resistance. Another consenting group can choose its own measured set,
without an Enclave signing or receipt service. Payout wallets confer no seat.
The policy also applies to later candidate joins, including Enclave candidates.

The public creation plan contains `chainId`, `vault`, a fresh bytes32 `salt`,
ordered `machines`, `codeSet` and ordered `operatorPermits`. Each host operator
signs `independentPlanDigest(plan)` with `signDigest` from
`custody/v2/digests.mjs`; these permits are specific to the complete plan and
do not authorize spending or secret release. Every member checks all permits,
accepted ownership, distinct owners/chips and fresh peer attestation before
allocating a sealed DKG session. Founders must run the same measured image.
One session is retained per custodian identity; there is no public reset API.

The API route `/v2/custody/independent-genesis` supports `start`, `agree`,
`exchange`, `finish` and `activate`. The untrusted CLI coordinator is:

```sh
node scripts/independent-custody.mjs --plan signed-plan.json --out result.json
node scripts/independent-custody.mjs --plan signed-plan.json --out result.json \
  --activate --rpcs https://mainnet.base.org,https://base-rpc.publicnode.com
```

The first command obtains the founders' signed public result. The second
resumes the persisted transcript, submits through one host's configured gas
payer and lets each member adopt its own share only after the matching
committee is on chain. The coordinator verifies all founder signatures; the
activation CLI requires explicit agreeing RPCs and checks the resulting
on-chain roster, threshold and commitments. The host state writer fsyncs the file and directory;
the guest serializes sealed snapshots and awaits DKG saves. A dishonest host
can still refuse durable storage, so quorum replication and recovery remain
required availability properties.

Validation uses the actual FROST helper and real Solidity execution on Anvil.
All founders derive identical commitments; each of the three two-member
subsets decrypts the same test bundle, while one share or a repeated share
fails. The real DKG signatures create a 2-of-3 committee through an unrelated
gas payer. Tests reject altered broadcasts, split transcript acknowledgements,
modified ciphertext, missing peers, wrong recipients, unauthorized plans,
wrong code/owners and invalid private state; they exercise the crash boundary
before final signing and coordinator replay. The vault's 34 contract tests
pass, including independent genesis and its threshold code governance.
The static helper builds/runs and the daemon bundles successfully. Custodian
attestation in the admission unit test is simulated, not real hardware.

**Still not activated:** the live custody vault and single Enclave seat have
not been replaced. The new measured image needs admission/deployment, direct
custodian endpoint testing, a hardware quorum, and owner-authorized migration
of each encrypted bundle. Existing ciphertext is not transferable to a new
independent public key without an authorized decrypt/re-encrypt or separately
verified handover. None of these source tests proves live custody migration.

## Verified Base authority deployment

On 2026-10-19 the replacement authorities were deployed on Base from source
commit `d8fac3c44b32115e80501c45ee0fb919ca2df56c`. The machine-readable
[address and verification record](../../contracts/deployments/independent-authorities-base.json)
contains constructor pins, transaction receipts, runtime hashes, immutable
bindings, source hashes and funding/refund evidence.

| Contract | Base address |
| --- | --- |
| PinnedSessionVaultFactory | `0xEc9277a32f98Ad3108747FE3Da78c35E1BeE097b` |
| PinnedSessionAuthority | `0xF76A138cEb162Aa4bAB47D4787793C569759CAc8` |
| SessionVault implementation | `0x87bc7Bfc8cA8b857FB43eBc6F4E49c807351Ff5c` |
| SessionVaultLib | `0xcc2824CdD4be8AD2656B5201662E60E025BF12b4` |
| EnclaveHostOwnership | `0xF5E9E6C02449001f6E8e95E5d87413f2cb6790ea` |
| EnclaveSecretVaultV2 | `0x56b81b3970a8ac2c52f9874Bd2758eDE30758228` |

Three of four configured RPCs agreed at block 52,823,641, hash
`0xe7a5b52ba50e0688bf8e812e1e0462f22bb6f5433339702df575b38fe569b8a7`.
Verification compares all six deployed runtimes with compiled source, applies
only compiler-declared immutable slots, and checks every immutable getter,
library link and the implementation's initialized owner sentinel. Six source
and deployment tests pass. A Base fork at block 52,823,514 additionally exercised
the live host registry: a foreign operator could not nominate an owner, the
registered operator could nominate one, and the nominated wallet could accept.
Deleting the old address book on that fork did not affect the new bindings.

These deployments introduce no deployer-controlled admin role. They do not
remove governance within the existing ledger, catalog, registry or other pinned
dependencies. The dedicated deployer received 0.00025 ETH, spent
0.000082405485674447 ETH on deployment transactions and returned
0.000166594514325553 ETH; 0.0000008727526662 ETH remains after the refund fee.
Funding-transaction gas was paid separately by the operator.

**Activation remains outstanding:** no production address-book entry, host
ownership, session grant, secret bundle or runtime was changed by deployment.
Host operators must nominate wallets and those wallets must accept. Clients
must explicitly select the new factory. Compatible measured custodians must
form a committee before owners authorize bundle migration. Existing production
custody still uses its original vault and one Enclave seat.

## Direct custody transport

New custodian images default to `--transport direct`. The bundled guest
supervisor starts only the custodian; it does not start the fleet-tunnel agent
or contact Enclave's relay. The selection is measured, so unmeasured host
configuration cannot switch a direct image back to tunnel mode. Explicit
`--transport tunnel` remains available for intentional legacy transport use.
This changes the image measurement and requires a new compatible deployment.

The host launcher signs a binding only when the guest reports a consistent
identity/encryption key and its endpoint and registry ID match the host's
configuration. It checks the
current operator and accepted owner through the vault's pinned registry and
ownership contracts with RPC quorum. It no longer asks the mutable address
book which registry to use. Existing guest signatures are verified before
being treated as a completed binding. Inactive/unowned hosts, other operators,
and substituted machine records are refused before the operator signs.

An operator serves its own HTTPS origin and certificate. For a host config
containing `endpoint: "https://custody.operator.example"` and `mgmtPort: 8788`:

```sh
node scripts/prepare-custodian-ingress.mjs host-config.json NEW_CADDYFILE
caddy validate --config NEW_CADDYFILE --adapter caddyfile
```

The generated site sends only public custody API methods/routes to the
loopback guest forwarding port. `/state`, `/submit`, `/receipts` and
`/v2/custody/host-binding` are not public routes. The distinct `hostPort` state
service must remain loopback-only. The host performs binding locally through
`mgmtPort`. Configure the operator's DNS and normal HTTPS server with the
generated site; no Enclave tunnel registration or certificate API is involved.
The generator writes a new file and does not reload any server. The proxy
terminates ordinary HTTPS outside the TEE; protocol signatures, attestation
and HPKE provide the end-to-end custody protection. It is not an attested TLS
endpoint and does not replace the recipient's protocol checks.

Five direct-transport tests pass. They execute the actual bundled supervisor
with conflicting host configuration, exercise operator-binding rejection, and
run the generated site through Caddy 2.11.7 over verified local TLS. Public
protocol payloads and recipient-encrypted values cross the proxy intact; eight
private/wrong-method requests receive 404 without reaching the upstream.
The integration uses a temporary test CA and a simulated guest HTTP service;
it does not establish real hardware custody or public certificate issuance.
The existing production custodian has not been restarted or moved.

## Custody chain availability verified before activation

The old custody reader let any RPC force an unusably high target block and
required every successful answer to agree. The replacement uses an explicit
majority of configured peers (three of four in the measured image), selecting
the quorum-supported height minus two confirmations. Contract reads name one
canonical block hash using [EIP-1898](https://eips.ethereum.org/EIPS/eip-1898),
without a number-only fallback. Complete results and headers must match. All
methods enforce freshness and future-time bounds, including code admission
and handover deals. The daemon saves its high-water checkpoint in sealed state
before returning a new result; concurrent reads cannot return an older result
after a newer checkpoint is accepted. Sealed-file replay by a dishonest host
is not prevented by this checkpoint alone. This remains RPC-majority trust,
not a light-client proof of Base consensus.

Live read-only tests against the existing Base custody vault first exposed
1RPC's usage-limit refusal. The replacement measured peer list substitutes
BlockPI's [published Base endpoint](https://blockpi.io/chain/base/), alongside
Base, PublicNode and dRPC. A full committee read passed with all four peers and
with each peer omitted in turn, at blocks 52,822,955–52,822,958. The observed
committee remains epoch 1 with one machine; these checks did not alter it.
Fault tests exercise every peer position with refusal, indefinite wait,
inflated height, conflicting state, fork and wrong chain. They also reject
stale/future/moving headers, split results, backward checkpoints, failed durable
writes and number-only fallback. Real-chain DKG creation and the legacy v2
handover/release test continue to pass with hash-addressed calls.

The replacement runtime and its new RPC pins still require measured-image
activation. This check removes a source-level RPC veto and verifies public
endpoint compatibility; it does not establish live independent custody.

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

## Sia recovery without a live indexer

The companion [Sia recovery change](https://github.com/EnclaveHost/enclave-apps/pull/4)
adds a read-only export of sealed object metadata and a standalone direct-host
reader. Recovery requires a protected app key, an externally trusted snapshot
SHA-256, and the expected file SHA-256 and length. It verifies sealed metadata and
Sia download integrity, then publishes a local output only after the whole-file
commitment matches. It rejects incomplete multipart metadata and never overwrites
an existing output. Mutable-key exports are not transactional; quiesce writes if a
consistent mutable bucket image is required.

A production-data test recovered 1,501,902-byte and 23,677,756-byte artifacts while
a systemd network policy allowed only 50 Sia host IPs. Negative probes confirmed
Nan, all four Enclave provider fronts and local indexd were blocked; local indexd
was reachable outside the test. Both files matched independently retained hashes.
A deliberately wrong file hash produced no output or partial file. Temporary
remote credentials were removed. Seven tests passed, including erasure-coded
recovery after discarding the mock indexer. Native and WASM release builds passed;
this live recovery execution used the native binary.

The encrypted recovery bundle contains the snapshot, app key, native and WASM
binaries, instructions and file manifest. Four Enclave-operated providers hold
verified ciphertext copies; the passphrase remains local. These copies do not
establish independent custody. The reader uses existing prepaid Sia account
balances; it cannot renew contracts, refill accounts or publish writes. It is a
point-in-time recovery tool, not an automatic fallback for a live mutable index.
The live S3 service and its single indexd/PostgreSQL writer remain in use.

## Host inventory reconciliation without Enclave API authority

Linux reconciliation now requires explicit contract pins and a fresh agreeing RPC
snapshot for the deployment inventory and catalog versions. It does not resolve
through the mutable address book, require the Enclave domains API before enrolling
new apps, or run Kubo to hash a component. Operator-local names can use independent
domains; existing configured names survive API refusal. Component bytes are hashed
locally on each run, so a cached manifest digest cannot hide changed bytes.

Tests cover new enrollment and runtime expectation updates with HTTP API access
refused, conflicting/stale/reorganized chain answers, incomplete inventories,
invalid pins and corrupted components. A fresh local inventory also enrolled two
real leased apps from a confirmed Base snapshot with fetch restricted to the three
configured RPCs and executable lookup disabled; the existing `eyesoff.ai` name was
preserved. That test used the existing host's attested records, not an independent
operator or new hardware attestation. The scheduled metal0 reconciler is activated
with explicit pins. Its privacy agent, guest provisioning, public DNS and
certificate issuance have separate remaining activation and authority work.

## Metal0 network authority and health-probe activation

Metal0's network agent now pins the deployment ledger, registry, connectivity
contract and existing SessionVault factory. The reconciler uses matching pins.
This activates the network consumer's existing quorum-bound signature and lease
reads; it does not migrate session grants to the newly deployed factory or remove
administration inside the pinned contracts. The previous agent did not understand
these pins, so configuration alone would not have activated them.

The same rollout removes `enclave.host` as the required egress health destination.
Probes use multiple operator-selected HTTPS endpoints (the configured RPC origins
by default); one responsive endpoint suffices and losing probes are cancelled.
Control probes use the configured signed-record directories. Health observations
cannot extend a lease or authorize an app. Seventy-two targeted tests passed,
including conflicting and stale authority reads and probe refusal/failure cases.

The live agent restarted with the pinned bundle, formed two control circuits, and
renewed both local guests' proofs and two ingress/egress circuits per app. Both
EyesOff replacement exit addresses answered certificate-verified HTTPS requests.
A network-agent restart rebuilds routes; DNS caches can retain the prior exits
while the replacement routes are already healthy. This is not proof of an
independent-host refusal test: providers/checkers remain Enclave-operated, the
legacy API mirror is still configured, and guest provisioning and certificates
still have separate control dependencies. Other running agent builds require
individual activation and verification.

## Provider bootstrap and local BYO configuration

A network host can now use explicit signed-record directories without configuring
an Enclave relay. A separate bootstrap reader verifies registered provider
operators against the pinned registry before control circuits exist, resolving
the startup dependency between provider discovery and control-proxied chain
reads. Guarded hosts must choose an explicit direct or SOCKS bootstrap path;
direct bootstrap is incompatible with `controlRequired`. App admission and
contract-owner signature verification retain the live control-proxied reader.
No bootstrap observation extends a lease. Operators select their own directories,
checkers and bootstrap services; no Enclave endpoint is built into this path.

BYO WireGuard credentials can be supplied in a bounded, operator-local private
file, authenticated by the existing owner-signed policy's salted configuration
digest. This path does not ask the relay to release credentials and cannot fall
back to it when the local file is missing or invalid. The existing endpoint and
full-tunnel checks still apply. The operator is responsible for secure local
delivery and file permissions; this is not enclave secret custody.

Tests exercise registered-provider cold discovery with a refusing directory,
forged records, a disagreeing RPC and a changed live registry operator, plus
private-bootstrap refusal without direct fallback and owner-signed local BYO
admission. A read-only production preflight found four qualified providers and
three active local leases at Base block 52,826,755 without a relay configured,
with HTTP access limited in-process to the configured RPC and directory origins.
The provider roles remain Enclave-operated; this evidence does not establish
organizational independence or complete the remaining custody, governance,
storage-write and first-use DNS/certificate work.

The bundled agent is activated on metal0 with `enclaveNetwork.relay` removed and
its control/privacy settings preserved. No implicit direct registry bootstrap
was enabled. Ninety-one targeted tests passed. After the agent restart, both
established local apps renewed their leases/proofs and formed two healthy
circuits each; EyesOff answered verified HTTPS through both replacement exits
and normal DNS. The adapter and dashboard also returned HTTP 200. The route
replacement caused a brief DNS transition; guest services were not restarted.
The top-level API route mirror remains configured. Local BYO and explicit
registered-provider bootstrap are available in the installed agent, but no
production app has been switched to local BYO and no independent operator is
claimed by this rollout.

## Host route publication without the API mirror

Metal0's top-level API mirror is removed and every per-app mirror flag is off.
The running agent accepted this through SIGHUP without a restart or circuit
rebuild. New Linux enrollment now defaults to direct directory publication;
`mirrorNewApps: true` plus an explicit mirror origin is required to retain the
legacy push behavior for new apps. The updated reconciler is installed in the
scheduled service and has completed successfully.

The compatibility API instead pulls public route envelopes from the signed
directories. Its existing policy, lease, provider, signature and replay checks
still decide whether it accepts a copy. The consumer cannot sign routes, extend
their lifetimes or copy host diagnostics and credentials. An unavailable or
refusing API cannot stop independent directory publication or the production
app-zone DNS replicas, which each read their own local verified directory.
Legacy policy state must match before the compatibility API accepts a route;
it is not an authority for the directories.

Twenty-seven targeted tests cover route pulls, signatures, withdrawals, expiry,
refusal retry and opt-in enrollment mirroring. Production verification checks
directory sequence renewal, fresh API route copies, all four authoritative DNS
answers and public HTTPS after the previous mirror's data has expired. Unsigned
diagnostic host status intentionally ages out of the legacy API; it is not
fabricated from a route record. Providers remain Enclave-operated and DNS-01,
runtime provisioning, custody, governance and storage writes retain separate
remaining dependencies.


## Linux wallet-policy delivery

The metal launcher now validates an explicit `hostAdmission` configuration and
passes public contract pins and policy contents through fw_cfg. The measured guest
installs those files and binds the supervisor to the configured host ID. Both the
full image builder and its supervisor overlay carry the policy runtime dependencies.
The exact standalone guest bundle is tested against fw_cfg captured from the real
launcher using a fake QEMU; this is a configuration-boundary test, not a hardware
attestation or production activation claim.

Optional operator-selected document mirrors serve hash-named public policies.
Documents must match the wallet's current chain commitment; missing documents
fail closed. Concurrent mirror retrieval, bounded responses and deadlines, and a
verified local cache support policy changes without a VM restart. Tests use actual
HTTP servers to demonstrate rejection of substituted data, recovery through a valid
peer, cached operation with all mirrors down, and adoption of a new refusal while
another host continues admitting the deployment. The owners and chain reader in
this test are fixtures, not independent production operators.

Metal0's Base enrollment preparation still requires operator nomination, wallet
acceptance and policy commitment on the new ownership authority. Its current
control image has not been replaced by this change. Captured contract pins include
zero optional session-factory/vault entries from the current book; deployment
review must reconcile those with explicitly selected custody/session bindings
before activating them. This does not migrate the live single-seat custody vault.


Host session authentication now honors the same explicit contract pins as host
scheduling: both Linux and Windows bind the factory and delegation ledger without
reading the mutable book. Zero factory pins disable these credentials instead of
restoring legacy defaults. A real Anvil session verifies with book access forbidden,
and its owner delegation is read only from the pinned ledger. This closes runtime
fallback authority; it does not transfer existing production sessions to the new
immutable factory. The control-image overlay now includes the complete runtime
file set and supports both adding and replacing these files in a verified image.


The updated control image was staged from commit `9392b1f5` over the digest-verified
production base and booted separately on real SEV-SNP hardware (2 vCPU, 3 GiB).
The test supplied no registry credentials, disabled claiming, used an unreachable
manager address and restricted QEMU outbound networking. Its supervisor reached
healthy with zero deployments and logged immutable pins with book polling off.
The hardware signature, pinned AMD root, chip/TCB certificate binding, static
transport-key binding and minimum Turin firmware floor all passed verification.
The launch measurement matched
`a93e1cf752b556f37c62e98ccef9e9de5660093d31b88cdfde2377dc24072e95441b4059b19ed552f2a522d391be2abc`.
The test VM was stopped; the production control PID was unchanged, and EyesOff,
the dashboard and adapter health checks remained HTTP 200. This proves control
runtime boot and measured delivery; it is not a deployed-app cold recovery or a
fresh-challenge handshake test.

Metal0's registered operator nominated wallet
`0x0b2d009c0c9af05b12100d77f3c815fea822ee61` on the new host ownership contract in
Base transaction
`0x395e91a737243f9b29e9ffae7b4065a6aef6f6e5c175abaf38eaedf057ccfb0f`
(block 52828018). Owner acceptance and policy commitment remain unsigned.
Fresh agreeing Base reads also verified the immutable session factory and custody
bindings and bytecode. Their explicit candidate pin profile is prepared, but
existing owner sessions and the single-seat production custody vault have not
migrated. Production runtime activation remains pending.

The native GET/HEAD client now resolves full deployment IDs from signed public
directories, checks leases through explicitly pinned RPC/contract policy, and
authenticates fresh guest hardware evidence before application traffic. It uses
literal ingress IPs with routing-only SNI and pins the attested TLS key before
sending readiness or application bytes. A cold-client EyesOff ping passed in a
network namespace without external DNS, Nan, minipc or the control API; one
directory was unavailable, and ingress forwarders rejected the API's SNI.
See [native client operation and trust requirements](../network/native-client.md).
This removes required Enclave DNS/CA/control lookup from that native read path.
It does not yet derive first-user app/runtime pins from owner startup commitments,
replace browser discovery, activate independent custody/storage writers, or prove
organizationally independent operation. The test used existing host-supplied
app/runtime expectations and explicit checker/RPC trust.
