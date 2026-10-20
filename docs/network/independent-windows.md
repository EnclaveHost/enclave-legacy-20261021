# Independent Windows hosts

A Windows (Hyper-V / Enclave Shield) host can now be installed, identified and updated with authorities its operator
chose:

- its own public endpoint;
- pinned contracts;
- its own artifact gateways;
- release keys and mirrors it pinned.

It needs no Enclave relay tunnel, no relay name reservation and no unsigned Enclave update channel.

This is not the whole of Windows independence. Some things still need Enclave's relay (see "What still needs an Enclave
relay"), and only part of the Windows-side behavior has been run on Windows (see "What has and has not been run").

Existing hosts are unchanged unless their operator acts. A host with no recorded identity is the relay host it always
was, `https://api.enclave.host/t/<name>`, and it keeps following the legacy channel until a release policy is
installed.

## Modes

**Relay (the default; every installed host)**

| Item | Value |
| --- | --- |
| Endpoint and registry identity | `https://api.enclave.host/t/<name>` |
| Fleet tunnel | `wss://api.enclave.host/v1/fleet-tunnel` |
| Secrets, certificates, custom domains, network prices and the sponsored first registration | That relay |
| Artifacts | `ipfs.enclave.host` |
| Updates | The unsigned `get.enclave.host/windows/latest.json`, unless a release policy is installed |

**Independent (`ENCLAVE_IDENTITY_MODE=independent`, written by `install-host.ps1 -NoRelay`)**

Nothing defaults to an Enclave service:

- `PUBLIC_URL`, `IPFS_GATEWAYS` and `ENCLAVE_CONTRACT_PINS_FILE` are required.
- The tunnel and `RELAY_BASE` are used only if the operator names them.
- With no release policy, updates are off. The unsigned Enclave channel is never used.

`windows/node/host-identity.mjs` makes this decision once, at agent start. When something only the relay provided is
off, it logs that by name; it never falls back to `api.enclave.host`.

## Install

The operator supplies:

- **A public endpoint**, for example `https://box.example.org`.
  - The host's registry id is `keccak256(endpoint)`, so the endpoint is its identity on chain.
  - It must be written exactly as it will be registered, with no trailing slash.
- **A contract pin document** in the `network/contract-pins.mjs` format.
  - Capture it with `scripts/network/capture-contract-pins.mjs` and review it.
  - It replaces the mutable address book.
- **Artifact gateways.** Every artifact is CID-verified, so a gateway can withhold an artifact but cannot substitute one.
- **Optional:**
  - Base RPCs. The default is the node's list of public, non-Enclave RPCs.
  - Public directory origins and network checkers for the Enclave network.
  - A release policy (see "Signed releases").

With setup:

```
EnclaveSetup.exe --release-policy C:\ops\release-policy.json --no-relay --public-url https://box.example.org ^
  --gateways https://gw1.example,https://gw2.example --contract-pins C:\ops\contract-pins.json ^
  [--rpcs https://rpc1,https://rpc2] [--directories https://dir1,https://dir2] [--network-checkers 0x..,0x..] [--name-check chain|offline]
```

With the script directly, from an expanded bundle:

```
powershell -ExecutionPolicy Bypass -File install-host.ps1 -Name box -NoRelay -PublicUrl https://box.example.org `
  -Gateways https://gw1.example,https://gw2.example -ContractPins C:\ops\contract-pins.json -ReleasePolicy C:\ops\release-policy.json
```

**Name check.** An independent host has no relay route to reserve. After its operator key exists, `install-host.ps1` runs
`host-identity.mjs check-endpoint`:

- It reads `get(keccak256(endpoint))` on the pinned registry at one confirmed, recent block. The reader
  (`host-identity.mjs` `quorumReader`) builds on `LeaseReader.agreed` (`network/lease-reader.mjs`). Two properties must
  both hold.

  **Authorization: no single RPC decides.**
  - It needs at least two RPCs on distinct hosts (`-Rpcs` with one is refused). The same client, or one host, configured
    twice is refused.
  - Each RPC's chain id must be Base.
  - Only two **distinct** configured peers that agree **in the current round** decide. A round is one requested block.
  - The agreement key is the whole snapshot:
    - the requested block number;
    - the block the peer returned: its number (which must equal the requested one), its hash (validated as 32-byte hex)
      and its timestamp, re-read unchanged after the snapshot;
    - the whole value read.

    A liar that repeats one forged hash and value in several rounds never meets itself, and a superseded round's result
    never counts.
  - The block must be under 90 seconds old before the snapshot is read, after it is read, and at the decision.
  - The block never goes below one this reader has already accepted. This is checked at the decision, so an overlapping
    call cannot roll an accepted block back.

  **Censorship resistance: no early cut-off.** `LeaseReader` stops taking heads 250 ms after the first two. This reader
  keeps taking them until its deadline (30 s). The target block is the second-highest head so far, minus two
  confirmations, so a far-future head cannot pick it.
  - A late head is read in the current round.
  - A head that raises the target starts a new round at the higher block, where every peer is read again.

  So a fast liar plus one fast honest RPC cannot shut out a second honest RPC that answers later, and a fast stale head
  cannot pin an old block.

  **Fail closed.** The reader refuses, and the install stops, when no two distinct peers give fresh agreeing answers in
  the current round by the time every head and read has settled, or by the deadline. Once it has decided, refused or
  moved to a higher round:
  - no step of an earlier read starts another request;
  - the read's `signal` is aborted.
- If another operator has registered the endpoint, the install fails.
- `-NameCheck offline` skips the check and reports that it was skipped. In that case a collision shows up later, when
  registration reverts.
- An automatic update of an unchanged identity does not repeat the check.

**Recorded identity.** The identity is recorded in `ProgramData\Enclave\node\host.json` (`identity`,
`enclave-host-identity/v1`), and every later run reuses it:

- Automatic updates pass only `-Name` and `-Owner`, so an update cannot move a host to another endpoint, relay, gateway
  set, pin document, RPC set, directory set or checker set.
- Changing any of these needs explicit parameters and `-Reconfigure`.
- A new endpoint is a new host on chain: it gets a new registry entry and needs a new ownership enrollment.
- The pin document is copied to `node\contract-pins.json` and its sha256 is recorded. If the file is edited outside
  setup, the next run refuses to continue.

**EnclaveDNS.** It is an Enclave service, so it is off by default for an independent install. `--enclavedns` turns it on.

## What still needs an Enclave relay

| Feature | Independent host |
| --- | --- |
| Chain registration, claims, renewals and proofs | Work, using the operator key and pinned contracts. The operator key pays its own registration gas, because the host paymaster sponsors only on a relay's word about the TPM. |
| Owner and delegated-owner deployments (owner-only scope) | Work. The local wallet veto (`ENCLAVE_HOST_OWNERSHIP` and the related settings in `node-config.local.cmd`) is enforced exactly as before. |
| Owner-committed deployments (`guestBootstrap`) | **Work**, from the operator's own storage replicas and pinned contracts. See "Owner-committed startup on Shield". Legacy envelopes are unchanged. |
| Shield **market** scope | **Off by default.** It opens on an attached relay's verdict as before, or on a threshold of verdicts from verifiers the operator pinned (`ENCLAVE_SHIELD_VERIFIERS_FILE`). See "Shield market from selected verifiers". Nothing local raises it. |
| Relay-staged secrets, sealed Shield secrets | **Off.** Deployments that have relay secrets are held, not started. An owner-committed package with `custody-v2` secrets is refused by name: custodians release only to SEV-SNP evidence and the Shield image has no custody client. |
| App and custom-domain certificates from the relay CA | **Off.** Partitions keep their own self-signed certificates. `apptls.mjs` refuses before minting a key. |
| Custom domain lists | **Off** for legacy envelopes (`domains.mjs` returns `off`). An owner-committed package's own names are routed once each is proven by a WebPKI certificate on the partition's key, which today's Shield image cannot yet hold (see the gaps below). |
| Network price list | **Off.** The registered price, or the owner's price from the tray, stands. |
| Enclave network routes | **Off** unless the operator lists `ENCLAVE_NETWORK_DIRECTORIES`, plus checkers it trusts. |
| Remote owner management (SIWE login, logs, restart over the tunnel) | **Off.** There is no tunnel. The loopback controls and the tray work. The relay-free management plane is scope S3. |
| Tray's "taking new work" | Reads "not connected to the network yet". This is `host.mjs` `marketStatus`, which follows the relay attach. |

**Optional relay.** An operator may still name a relay of their own choosing (`RELAY_URL`, `RELAY_BASE` in
`node-config.local.cmd`). Its services are then used. That is the operator's choice, not a default.

**Keeping the relay route as the identity.** Keeping `https://api.enclave.host/t/<name>` as `PUBLIC_URL` in independent
mode is allowed, because it preserves the registry id and ownership. The agent warns that clients reach the host there
only while Enclave's relay routes it.

## Signed releases

`windows/node/release-channel.mjs` defines the channel.

**Policy.** A host's release policy is stored in `ProgramData\Enclave\node\release-policy.json`, which only SYSTEM and
Administrators can access. Updates never write it.

```json
{"format":"enclave-windows-release-policy/v1","channel":"stable",
 "keys":["ecdsa-p256:<base64 SPKI>"],"threshold":1,"mirrors":["https://m1.example/windows/","https://m2.example/windows/"]}
```

**Statement.** Each mirror serves `latest.signed.json`:

- The file holds a statement's exact bytes: version, channel, issue and optional expiry times, and the zip, setup and
  manifest, each with its fixed name, size and sha256.
- It carries raw `r||s` P-256 signatures over `"enclave-windows-release-signature/v1\n" || statement`.

**Why P-256 and not Ed25519.** The signature is checked natively in three places:

- Node (the agent and the updater);
- `EnclaveSetup.exe` (C# on .NET Framework, using CNG `ECDsaCng`);
- `cli/host.ps1` (Windows PowerShell 5.1, also CNG).

.NET Framework has no Ed25519, and this project should not ship its own curve code in an installer.

**What a host with a policy does:**

- **Signed statements only.** It accepts a release only from a statement signed by distinct pinned keys up to the
  threshold.
  - Unsigned envelopes are refused, as are envelopes signed by keys that are not pinned or that miss the threshold.
  - The legacy `latest.json` is never read, however consistent its hashes are.
  - The sha256 values are trusted only because they are inside the signed statement. The manifest's hash is in the
    statement, and every delta file's hash is in the manifest.
- **Highest version across all mirrors.** A stale mirror (freeze or rollback) cannot hold a host back while another
  mirror proves a newer release. A mirror serving garbage or forged data is refused and logged.
- **Equivocation stops installs.** Two different signed statements for one version mean the key signed twice, so nothing
  is installed.
- **Every download is bounded in bytes, time and memory, and checked.**
  - A pointer may be at most 64 KiB, and a file at most its signed size. An announced length over the limit is refused
    before the body is read; a body that runs past it is refused at the first byte over. Bodies are streamed to disk and
    never held in memory.
  - Each request has a hard deadline over the whole exchange: connect, headers and body. A pointer gets 15-20 seconds. A
    file gets 60 seconds plus its signed size at 128 KiB/s, capped per mirror, and all mirrors together share one overall
    deadline. A mirror that trickles is cut off and the next mirror is asked.
    - Node uses `AbortSignal` over fetch.
    - Setup (C#) uses a timer that aborts the `HttpWebRequest`. Its `Timeout` and `ReadWriteTimeout` bound single waits
      only.
    - `cli/host.ps1` waits on each `Task` for at most the time left.

    A refused request is aborted, never drained.
  - A file already on disk is judged by its size first and then hashed as a stream, so a cache file of any size costs one
    buffer.
  - Part files have random names and are created new, and only a verified part replaces the final file. A corrupt or
    truncated mirror is skipped for the next mirror, and partial files are removed.
- **The work folder is SYSTEM's and Administrators' alone.**
  - `ProgramData\Enclave-setup` holds what setup and the SYSTEM updater run. A folder made under ProgramData inherits
    "Users: create files", so any local account could plant a file there for an elevated step to trust.
  - Setup (`SecureWorkDir`) and `update-host.ps1` use the folder only if it is protected and owned by, and grants access
    only to, SYSTEM and Administrators. Otherwise they move it aside untouched (`Enclave-setup.untrusted-*`) and make it
    again. This costs one whole (non-delta) update with no rollback copy.
- **`cli/host.ps1` runs setup only as the bytes it checked.**
  - Setup is downloaded into a new folder under `%TEMP%` and checked by size and sha256.
  - It is held open (readable, not writable or deletable), hashed again through that handle, and started while held.
  - Nothing is kept if anything fails before setup starts.
- **The installed release verifies the next one.** `update-host.ps1` verifies with the installed `node.exe` and the
  installed `release-channel.mjs`, never with code from the download.
  - It refuses a release whose installer or updater lacks identity records and policy verification.
  - It does not automatically roll back to such a release.
- **No fallback.** If the policy is unreadable, or no mirror proves a signed release, the host does not update and logs
  the reason.

**Keys.** The publisher makes and keeps release keys offline. No script here creates or uses a production key. For
example, on the publisher's own machine:

```
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out release-key.pem   # keep offline
node windows/node/release-channel.mjs pubkey --key release-key.pem      # -> {"key":"ecdsa-p256:...","keyId":"..."} for policies
```

A key is an authority only for hosts whose operators pinned it. Pinning several keys with a threshold (for example, 2 of
3 held by different people) removes the single-signer authority. A second signer adds a signature without changing the
statement:

```
node windows/node/release-channel.mjs cosign --envelope release-<v>.signed.json --key mine.pem --out release-<v>.signed.json
```

### Publishing

`scripts/publish-windows-host.sh` no longer uses SSH to reach Nan. It has no built-in destination:

```
scripts/publish-windows-host.sh <build-out> --stage <channel-dir> --sign-key release-key.pem [--sign-key ...] \
  [--valid-days 90] [--dest /srv/mirror/windows] [--dest user@host:/srv/www/windows/] [--require-signed] [--no-legacy-latest]
```

**What it does:**

- Builds the channel in `<channel-dir>`. The tree is static and can be served by any HTTP host or uploaded as replicated
  artifacts.
- Signs the statement.
- Verifies the staged envelope under the signing keys.
- Copies the release files to each `--dest`, then the pointers.

**Publishing rules:**

- **Published files are immutable.** A different file under a published name stops the publish.
- **One statement per version.** A re-run reuses `release-<v>.signed.json` and only adds co-signatures, so mirrors never
  disagree about a version.
- **Legacy pointer during the transition.** `latest.json` and `EnclaveSetup.exe` are still written so that hosts without
  a policy keep updating. `--no-legacy-latest` ends that.

**Mirrors.** Mirrors run by Enclave are still Enclave-operated mirrors, not independence. Only mirrors run by other
organizations add censorship resistance, and none exist today.

## Migrating an existing host to verified releases

The verifier itself has to arrive somehow, and for every installed host it arrives over the **unsigned** channel.
Installing a policy protects **future** updates only. It does not make the bootstrap verified. Everything installed before
the policy, including the verifier, was trusted on `get.enclave.host`'s word.

1. **Publisher:** publish a release containing this change both signed and with the legacy pointer:

   ```
   publish-windows-host.sh <out> --stage <dir> --sign-key ... --dest ...
   ```

2. **Host:** the host takes that release through the legacy channel, as before. Its installer records its existing relay
   identity in `host.json`, which changes nothing about the host.
3. **Operator, optional but recommended:** check the installed release out of band.
   - Run `node release-channel.mjs verify --envelope release-<v>.signed.json --channel stable --key <spec>` on a copy of
     the envelope.
   - Compare the envelope's `manifestSha256` with the sha256 of `C:\Program Files\Enclave\manifest.json`. The control
     tree can also be rebuilt reproducibly with `windows/installer/stage-bundle.sh <commit>`.
   - This raises confidence in the bootstrap. It does not change what the bootstrap was.
4. **Operator, as Administrator, on the host:**

   ```
   "C:\Program Files\Enclave\runtime\node\node.exe" "C:\Program Files\Enclave\control\windows\node\release-channel.mjs" ^
     install-policy --policy C:\ops\release-policy.json --dest C:\ProgramData\Enclave\node\release-policy.json
   ```

   You can also re-run setup with `--release-policy`. A different existing policy is replaced only with `--replace` or
   `-Reconfigure`.
5. **From then on:** the host's minute watch and its hourly task follow only the signed channel. Removing the policy file
   is the only way back to unsigned updates, and it is a deliberate administrator action.
6. **Publisher, once the hosts that matter have policies:** stop writing the legacy pointer (`--no-legacy-latest`).

## Host ownership on the verified `0xF5E9…` contract

V2 custody pins the verified `EnclaveHostOwnership` at `0xF5E9E6C02449001f6E8e95E5d87413f2cb6790ea`
(`contracts/deployments/independent-authorities-base.json`). `nucbox-k11-4` is documented as accepted on `0xbbd885d3…`,
which has no deployment record. Moving a host to the verified contract is prepared here; **nothing is signed or sent**.

Run the steps on a repository checkout. `ENCLAVE_CONTRACT_PINS_FILE` must be the host's pins, and the pinned registry and
catalog must be the ones the verified record is bound to.

```
PUBLIC_URL=<the host's endpoint> ENCLAVE_CONTRACT_PINS_FILE=<pins> node windows/node/host-onchain.mjs prepare-ownership \
  --policy <host-policy.json> --owner <owner wallet> --policy-dir <the host's ENCLAVE_HOST_POLICY_DIR> --out <new dir>
```

1. **Prepare.** The command:
   - checks that the policy names `0xF5E9…` and this host's id;
   - checks that the deployed code matches the verified code hash;
   - checks that the contract's registry is the pinned one;
   - writes `<policyHash>.json`, `transactions.json` and `node-config.ownership.cmd`. The transactions are unsigned:
     `proposeOwner` from the operator key, then `acceptOwner` and `setPolicy` from the owner wallet.
2. **Nominate, accept, commit.** The operator nominates. The owner accepts and commits the policy with their own wallet.
   Re-read and simulate each transaction after its prerequisite confirms. (These steps happen outside this tool.)
3. **Place the policy.** Put `<policyHash>.json` in the host's policy directory.
4. **Check readiness.** Run `node windows/node/host-onchain.mjs ownership-status --policy-dir <dir>` until it reports
   `ready`.
5. **Switch.** Only then add `node-config.ownership.cmd` to `node-config.local.cmd` and restart the node.
   - The veto fails closed: switching before acceptance would refuse every deployment.
   - Until the switch, the host keeps enforcing its existing contract.

## What has and has not been run

**Run on Linux:**

| Test file | What it covers |
| --- | --- |
| `test/windows-release-channel.test.mjs` | Real P-256 keys; signature, threshold and domain-separation checks; unsigned or forged data refused; freeze, rollback and equivocation (including `1.2` against `1.2.0`) over real loopback mirrors; corrupt, truncated and oversized downloads; a 2 GiB sparse cache file hashed as a stream, with resident memory checked; mirrors that announce 50 GiB, flood without end or trickle, each cut off with the next mirror used; one deadline over all mirrors; cancellation; a trickling or flooding pointer; the cross-verifier refusals; refuse-to-replace policies; the exact CLI `update-host.ps1` calls; the agent's minute watch. |
| `test/windows-host-identity.test.mjs` | Relay-mode compatibility; required explicit pins, endpoint and gateways; the agreeing-RPC reader against `LeaseReader` on 14 scenarios (liar, dead, wrong chain, stale, far-future head, fork and mid-read reorganisation each against two fresh RPCs; split, three-way split, one answering, two stale, two on different forks), the block choice and no rollback below an accepted block; free/ours/taken on chain, including a lying or stale RPC against two fresh ones; `0xF5E9` preparation against the real verified record; offline `keys.mjs`; the real `agent.mjs` booted in independent mode. |
| `test/windows-host-identity-quorum.test.mjs` | The reader under adversarial timing. Late heads: a second honest RPC 500 ms or 1 s after a fast liar outvotes it; a liar's fastest read; a fast stale head moved past; a far-future head ignored. Authorization: a liar repeating one forged hash and value in two or more rounds is never accepted, whether the honest RPCs differ or agree; the same client or host twice is refused; returned block numbers and hashes are validated; a superseded round's result never decides, and its reads stop before their next request; nothing is requested after the deadline or a decision; overlapping calls cannot roll back an accepted block. Freshness after the whole snapshot. Whole-snapshot and block-hash agreement. Fail-closed refusals. Mutants on scratch copies of the module, including one that reproduces the forged-repeat bypass, are each caught (see the identity report). |
| `test/windows-publish-host.test.mjs` | The publisher end to end, including a host-side resolve and download from its mirrors. |
| `test/windows-installer-independence.test.mjs` | Structural checks: the C# and PowerShell verifiers' constants equal the module's; the parameter, step and marker contracts between setup, installer and updater; the ordering of the signed path. |

**One protocol, three verifiers, one verdict.** `test/windows-native/` holds the cross-language harness:

- `make-fixtures.mjs` writes `fixtures.json`, 157 cases:
  - policies, as exact JSON text for Node and C#, and as the `ENCLAVE_RELEASE_*` parts `cli/host.ps1` takes;
  - envelopes, as exact bytes judged at a fixed time;
  - each with the verdict it must get.

  The script refuses to write cases that Node does not judge as expected.
- `run.ps1` (Windows PowerShell 5.1, no install, no elevation) does the following:
  - builds `EnclaveSetup.cs`'s `ReleaseChannel`, unchanged, with the in-box csc;
  - loads `cli/host.ps1`'s functions from its syntax tree, so the install itself never runs;
  - expects every verifier to give every case its verdict, and the same version, signers and statement hash, or the same
    normalised mirrors;
  - runs the C# and PowerShell transfer code against a loopback mirror that announces 50 GiB, floods, trickles,
    truncates, corrupts and answers 404;
  - as Administrator, also tests `SecureWorkDir` on a folder under `%TEMP%`.

  Run it as: `powershell -NoProfile -File test\windows-native\run.ps1 [-Node <node.exe>]`.

  The machine's execution policy must already allow the script. The harness does not bypass or change the policy.

The cases cover:

- expiry: expired, expiring exactly now, and a null expiry;
- issue time: issued in the future past one day of skew;
- times .NET refuses (`02-30`, `24:00`, offsets);
- sizes written `1.0` or `1e3`, which .NET reads as decimals, so Node refuses them too;
- policy keys: malformed, duplicate, off-curve or P-384;
- thresholds: `0`, too high, `1.0` or a string;
- mirror spellings that .NET and WHATWG normalise differently (now refused everywhere);
- mirror hosts as written:
  - IPv6 only as `::1`, compressed or in full, and written back `[::1]`;
  - `::2`, `::`, IPv4-mapped, link-local and documentation addresses refused;
  - numeric hosts only as a plain dotted quad (`127.1`, `2130706433` and `0x7f000001` refused);
  - plain http only for `localhost`, `127.0.0.1` and `[::1]`;
- 16 against 17 signatures, and 64 KiB against 64 KiB + 1;
- case differences, a final newline and non-ASCII digits, which .NET `$` and `\d` would otherwise accept.

**Run natively on Windows** (by the coordinator on minipc, 2026-10-20, without Wine and without changing the execution
policy; evidence in `windows-native-hardening-fixed-review/`):

- The C# verifier: `EnclaveSetup.cs`'s `ReleaseChannel`, extracted unchanged and built with `Harness.cs` by the in-box
  .NET Framework 4 csc. It gave the expected verdict on all 157 fixtures, the same as Node. The first run gave 119 of
  120; the miss was the `http://[::1]` mirror, fixed by judging mirror hosts as written.
- The C# bounded-transfer tests against the misbehaving loopback mirror, all passing:
  - a 50 GiB announcement refused before the body;
  - an endless body cut off at the limit, not drained;
  - a trickle cut at the hard deadline;
  - short and corrupt bodies;
  - failover past six bad mirrors;
  - no part files left behind;
  - an existing wrong file never replaced;
  - one deadline over all mirrors;
  - resolve past trickling, flooding and announcing pointers.
- The whole of `EnclaveSetup.cs` and `TrayTheme.cs`, compiled with the in-box csc.
- `install-host.ps1`, `update-host.ps1` and `cli/host.ps1`, parsed by Windows PowerShell's own parser with 0 errors.
  They were parsed only, not run.

**Not run on Windows:**

- Any PowerShell at run time:
  - `run.ps1` itself;
  - `cli/host.ps1`'s functions (its verdicts, `Read-Bounded` and transfers);
  - `update-host.ps1`'s `SecureWorkDir`;
  - the file lock;
  - `install-host.ps1`, `update-host.ps1` and `cli/host.ps1` as scripts.

  The PowerShell verdicts and transfers are therefore checked only statically and by Node's structural tests.
- `Start-CheckedSetup`'s `-Verb RunAs` under its file lock. `run.ps1` tests the lock with an unelevated start only.
- Setup's UI flow, `SecureWorkDir` in C#, an update or install of any kind.
- Hyper-V, Shield, TPM and service behavior.
- A live chain name check.

Before relying on this, do a Windows run covering:

1. A fresh independent install.
2. An update of a legacy host, checking that its identity is recorded unchanged.
3. Policy installation followed by a signed update.
4. A corrupt-mirror update.
5. A refused unsigned update.

## Owner-committed startup on Shield (S4b)

An independent Windows host starts an owner-committed deployment (an envelope carrying `guestBootstrap`, the same
package format as the SNP tier: `sdk/bootstrap/package.mjs`) in a Shield partition, with no relay secret, name or verdict
service. `windows/node/shield-startup.mjs` does the work; `host.mjs` calls it before any claim and again at every launch.

A Shield partition cannot read Base itself (the SNP front does; a Shield image has no such front), so the host does the
chain half, and only from authorities its operator chose:

1. **Pinned authority.** The ledger and catalog are the operator's contract pins (`ENCLAVE_CONTRACT_PINS_FILE`). Without
   pins, owner-committed startup is refused: the mutable address book is not a startup authority.
2. **Fresh same-block quorum.** The deployment row and its catalog version are read in one agreed read
   (`host-identity.mjs` `quorumReader`): two RPCs on distinct hosts must agree on both values and the block hash at a recent
   confirmed block. A stale, lone or disagreeing RPC decides nothing; the answer is "unknown", never a start.
3. **The exact package.** The bytes come from the operator's own storage replicas (`ENCLAVE_STARTUP_STORAGE_PLAN_FILE`, the
   storage plan format, or `ENCLAVE_STARTUP_GATEWAYS`; not both; there is no default replica). They are hash-checked and
   bound to Base, the pinned ledger, the deployment, its **current** owner, its appRef and this host's partition RuntimeID.
4. **The exact app.** The partition's AppID is derived with the manager's own rule (`windows/vbslike/manager/derive.mjs`)
   from the catalog component (CID-verified through `IPFS_GATEWAYS`) and the record `node-bridge.mjs isolationPlan` builds.
   It must equal the package's `appId`. The package's `configText` replaces every other config (the envelope's and the
   version's), exactly as on Linux, and is measured into the AppID (`enclave-catalog-bundle/5`).
5. **Current wallet policy.** The host-wallet admission (`ENCLAVE_HOST_OWNERSHIP` and related settings) is asked at the
   same moment.

The envelope must name this backend: `{"isolation":{"require":"hyperv-partition-per-app"},"guestBootstrap":{...}}`. The
CLI's default names `snp-guest-per-app`; such a package is refused here by name, because its RuntimeID is the SNP tier's.

**Launch, restart and adoption.**

- A launch re-verifies everything and needs this host's live lease at the quorum block.
- A partition the manager already holds is adopted only if it runs the committed AppID on the committed runtime. Otherwise
  (an older package's config, say) it is retired, confirmed gone, and the committed one is started.
- A new commitment on the ledger restarts the deployment (`envelopeVerdict` reads the package hash).
- An owner transfer, a revoked wallet policy or a package that no longer verifies is a definite refusal: the partition is
  retired and the lease is given back.
- A running partition outlasts an unanswered re-verification (an RPC or replica outage) for 10 minutes, never longer.

**Secrets.** Public packages work. A `custody-v2` package is refused by name: custodians release only to SEV-SNP evidence
(`docs/security/secret-custody.md` §3.4), and the Shield image has no custody client. It is not started without its values,
and no plaintext is fetched into the host. The host-side boundary that such an image would use is built and tested:
`secrets.mjs custodyAuthorization` signs only the guest's release binding, for the vault the owner committed, with custody
v2's exact operator message. Relay-staged secrets are never consulted for an owner-committed deployment.

**Names.** The package's `names.hosts` are the only candidates; no relay domain map is read. Each name is routed (the
splice's `allowedNames`) only while a proof stands: a WebPKI certificate for the name, chaining to the public roots,
presented by the partition on exactly the TLS key the manager's readiness judge bound (`network/owner-names.mjs`
`proveNameControl`). Proofs lapse after 5 minutes and are re-made. Two deployments that prove one name follow
`OwnerNameTable` (the later issuance wins; a tie selects neither). Legacy relay-mapped names are untouched.

## Shield market from selected verifiers

The market used to open only on the attached Enclave relay's verdict. A host's operator can now pin verifiers instead of,
or beside, a relay:

```json
{"format":"enclave-shield-verifier-set/v1","threshold":2,
 "verifiers":[{"key":"ed25519:<base64 SPKI>","url":"https://verifier-a.example"},
              {"key":"ed25519:<base64 SPKI>","url":"https://verifier-b.example"}]}
```

Set `ENCLAVE_SHIELD_VERIFIERS_FILE` to that file. The node also needs `SHIELD_WITNESS_CONFIG` (the readiness witness the
verifiers check) and its operator key. There is no built-in verifier, Enclave's included. A relay is a verifier only if
the operator lists it.

**What a verifier checks** (`relay/shield-independent-verifier.mjs`), with the relay's own code:

- the credential round for the presented EK and AK (`vbs-credential.mjs`);
- the hv-node attach (`hvnode-verify.mjs`): EK chain to the verifier's pinned TPM roots, the activated credential, a quote
  over the verifier's nonce bound to the transport key, the replayed boot log (Secure Boot on, production signing,
  VBS/HVCI), and possession of the transport key;
- identity: the registry entry for `keccak256(endpoint)` names this endpoint, and its registered operator signed this
  exchange (verifier, host, nonce, transport key, EK and the host's challenge);
- the policy's pinned readiness witness (`shield-market-evidence.mjs`, shared with `shield-marketplace.mjs`): a guest
  report over the verifier's second nonce, under the IDKS of that authenticated boot, for the witness AppID and RuntimeID,
  on an image and platform the verifier's policy admits (`verifyShieldAppPolicy`).

**What a verdict says** (`windows/node/shield-verdict.mjs`): tier `hv-node`, technology `windows-tpm-host`,
`hostExcluded: false`, market `shield-capacity`, bound to the host id, endpoint, transport key and this round's host
challenge, valid for at most five minutes. It is signed with Ed25519 over a domain-separated canonical statement. It never
says TEE and never admits an app; per-app evidence is still each client's to check.

**What the host accepts:** `threshold` valid verdicts from distinct pinned keys, each for this round. Forged, unpinned,
replayed, wrong-host, wrong-key, stale, over-long, and self-asserted verdicts count for nothing. Below the threshold the
host stays owner-only. The window is the earliest expiry and is never extended. The serving grace after a lapse is the
relay window's (15 minutes, existing work only).

**Running a verifier:** `node scripts/network/shield-verifier.mjs pubkey --key verifier.pem`, then `serve --key verifier.pem
--policy <enclave-shield-app-policy/1> --pins <contract pins> --rpc A --rpc B`, behind the verifier operator's own TLS. The
script never creates a key.

## Shield S4b: what has been run, and the gates before relying on it

Run on Linux (fake Hyper-V, synthetic TPM, in-process RPCs):

| Test file | What it covers |
| --- | --- |
| `test/windows-shield-startup.test.mjs` | Envelope rules; the shared vector's AppID from a fresh agreed read; config replacement and measurement; stale and disagreeing RPCs; owner transfer, a moving commitment, revoked wallet policy, another runtime, custody-v2 and an absent replica; a real `Host` and real manager launching from the operator's replica with Enclave endpoints blocked; restart replacing an older package's partition; owner transfer and revocation retiring a running one; no claim for an unverifiable package; owner-name proofs; the custody-v2 boundary's exact message. |
| `test/windows-shield-verifier.test.mjs` | The node's real `buildHvNodeFrame` over a synthetic TPM through the credential round, to a verifier running the relay's checks over HTTP; threshold; refusals for the wrong operator, endpoint, registry entry, boot, IDKS, app, image and TPM root, and a reused session; forged, unpinned, replayed, wrong-node, wrong-key, stale and over-long verdicts; no self-assertion opening the market. |

Not run, and needed before relying on it (the coordinator's native mini PC; no automatic VM changes):

1. **A real Shield partition from an owner package.** Start one public package (no config, then V5 config) on Hyper-V. The
   manager's view must show the package AppID, and a client verifying the app's evidence against the package's AppID must
   pass.
2. **A real TPM against a verifier.** Run `scripts/network/shield-verifier.mjs serve` against the mini PC's fTPM: AMD EK
   chain, real boot log, PCR 0, readiness witness. It must yield a verdict, and the node must open the market window.
   Then repeat with Secure Boot off (it must be refused at the node), and with a verifier whose policy omits the image (it
   must be refused at the verifier).
3. **Restart adoption on Hyper-V.** Restart the agent and the manager with a running owner-committed partition; then
   commit a new package and check that it is replaced, not adopted.
4. **Live chain.** A quorum read of the pinned ledger and catalog over the operator's RPCs, and replicas serving the
   package.

Gaps that need work outside these files:

- **Owner names on Shield.** The Shield image holds one certificate for its zone label and cannot yet produce a CSR for,
  or install, a certificate for an owner name. Until it can (an ACME client in the image, or the m2/front `names.go` rules
  ported to it), name proofs fail and owner names stay unrouted. The host side is in place.
- **custody-v2 on Shield.** Needs a custody client in the Shield image that reports a release binding with a recipient key
  in its VM report, and custodians that admit Shield evidence under an owner policy that names the weaker tier explicitly.
  Until then such packages are refused.
- **Clients' view of verifiers.** Verdicts are public statements, and `/availability` names the verifier key ids, but the
  site and the SDK do not yet show or check them.
