# Open participation: providers and service advertisements without approval

Anyone can operate an Enclave-network provider, or advertise a directory, checker, storage adapter, DNS replica or
release/artifact replica. None of the following is needed:

- Enclave's approval;
- a name reservation;
- a fleet secret;
- the mutable address book;
- an `enclave.host` probe.

Operators choose every authority they trust and every service they ask.

**Status (2026-10-20):**

- The provider and checker source paths have fixture and process-level tests. Public operator activation remains to be verified.
- `EnclaveServiceIndex` is deployed on Base at `0x54dEcb43DE6f9Cc953Ba582B190b56C5a60B5941`.
  The deployment, code pin and activation evidence are in `contracts/deployments/service-index-{base,pin-base,activation-base}.json`.
  Cold CLI discovery has verified signed provider records; browser/host rollout and profile activation remain pending.
- All providers, directories and checkers that exist today are Enclave-operated. Nothing here creates independent
  operators. It only stops requiring Enclave to admit them.

## 1. Run a provider with your own authorities

On a Linux server with a public IPv4 address, as root, from a directory holding the release's `wg-provider.mjs` and
`install.sh`:

```
bash install.sh 2026.10.19 fra \
  --checkers 0xCHECKER1,0xCHECKER2 \
  --rpc https://base-rpc.publicnode.com --rpc https://base.drpc.org \
  --directory https://dir1.example.org --directory https://dir2.example.net \
  --pins authority-pins.json \
  --zone apps.example.org --probe-zone probe.example.org \
  [--roles guard,ingress,egress] [--public-address 203.0.113.10] [--uplink eth0] [--relay https://domains.example.org]
```

**What the installer does:**

- Makes the operator key on the server.
- Writes `provider.json` with `"bootstrap": "explicit"`.
- Has the new release check the file before anything is switched (`wg-provider.mjs --check-config`).
- Starts the service.

**Useful flags:**

- `--config-only` writes and checks the configuration and stops there: no packages, firewall or service.
- `ENCLAVE_NETWORK_ROOT=<dir>` stages the whole tree elsewhere.

**Kept on update:** fields you manage in `provider.json`: `kind`, `hostId`, `pricePerGiB6`, `proofKeyFile`,
`localRoutes`, `noSniRoute`, `budget`, `ports`.

**What explicit mode means at runtime** (`network/service-index.mjs` `resolveProviderBootstrap`):

| Setting | Explicit mode |
| --- | --- |
| Contracts | Only `authorityPins`: `deployments`, `registry`, `connectivity`, `sessionVaultFactory`. All four are required. A zero `connectivity` disables paid service; a zero `sessionVaultFactory` accepts only wallet (EOA or ERC-1271) owner policies. **The address book is never read; a config that names one is refused.** |
| Chain reads | Two or more https RPCs on distinct hosts. The existing lease reader requires two agreeing RPCs at a fresh block. |
| Records | 1 to 8 directories. There is **no relay fallback.** |
| Qualification | One or more checker addresses. Only these may ask for probes. |
| Names | Your app zone, and the probe zone your checkers use. Nothing defaults to `app.enclave.host` or `probe.enclave.host`. |
| Custom domains | Only if `--relay` names a source for the custom-domain map. Without it, app-zone names only. |

**Unchanged:** signed provider records, owner-signed network policies, two-RPC lease admission, checker-only probes and
on-chain qualification. None of them is relaxed.

**Enclave's own fleet** keeps its old command, as an explicit opt-in to Enclave's defaults: the relay fallback, the
mutable address book, and `app.enclave.host` / `probe.enclave.host`.

```
bash install.sh <release> <region> <checker[,checker]> [roles] --legacy-enclave-defaults
```

Without that flag the positional form is refused. An installed provider whose `provider.json` has no `bootstrap` field
runs exactly as before.

## 1b. Run a qualification checker with your own targets

The checker (`scripts/network/wg-qualify.mjs`) qualifies providers and signs verdicts. In independent mode it uses no
Enclave relay, no address book, and no default probe target:

```
node wg-qualify.mjs --independent --key-file checker.key --wg /opt/.../enclave-wg \
  --directories-file dirs.json --pins authority-pins.json --rpc https://rpc-a --rpc https://rpc-b --rpc https://rpc-c \
  --outbound https://canary.example.org/ --dns 9.9.9.9,1.1.1.1 (--smtp 203.0.113.25:25 | --smtp-domain example.org) [--loop 240]
```

**What independent mode means:**

- **Records** come only from the named directories. `--relay` and `--book` are refused.
- **Community providers** are checked against the **pinned** registry, read through the agreeing quorum. This works with
  the deployed registry: it is schema 4, where `register` is open and first come by endpoint, and the struct the reader
  decodes is unchanged. The deployed registry has no `registerRelay` or capability bits, and nothing here assumes them.
- **On-chain attestations.** The digest this checker signs for a paid provider is the one two RPCs agree on at one block.
  One lying RPC cannot get it to sign anything else. A zero `connectivity` pin disables attestations.
- **Probe targets are the operator's own:** the HTTPS canary, the DNS resolvers given to probe peers, and the SMTP target
  or mail domain. Probe names are in the provider's probe zone.
- **Direct-host probes** (`network/provider-probes.mjs`, `scripts/network/qualify-provider.mjs`): with
  `independent: true`, the checker's own config names `probeZone` and `outbound`. Both are required. Neither defaults to
  an Enclave name, an Enclave zone is refused, and the host's manifest supplies neither. A manifest whose hostname is
  outside the checker's zone is refused before any probe runs.
- **The direct-host canary** (`network/provider-canary.mjs`, configured as `direct.probe`): with `independent: true`, the
  host operator names the reviewed `probeZone`, and the hostname must be `probe-<label>.<probeZone>`, a single label of at
  most 63 characters. Enclave zones are refused, and the name is judged before any key, certificate or token file is
  read. Token, path, port and SNI protections are unchanged. The manifest carries no zone.
  - **Startup.** `createNetworkHost` (`network/enclave-network-host.mjs`) starts the canary from the daemon's
    `enclaveNetwork.direct.probe`:
    - The probe is checked first: no unknown fields, absolute file paths, a UDP port of 1024 to 65535, an IP `bindHost`,
      and the name and zone rules above.
    - The canary is started only after every other configuration check.
    - The direct runtime then listens on its public ports **at startup**, so a checker can reach the canary before any app
      is qualified. Without a probe, it listens at the first direct app, as before.
    - If any step fails, everything already bound is closed.
    - The returned host's `close()` releases the runtime and the canary, and may be called more than once.
  - **Proof.** `test/provider-canary-independent.test.mjs` starts the canary through that real entry point, from a daemon
    config file with no Enclave authority, and qualifies it with the real checker, as child processes with `enclave.host`
    blocked. `test/enclave-network-host-canary.test.mjs` counts sockets to show that no start, refusal or failure leaves
    anything bound.
  - **Agent shutdown.** `network/privacy-agent.mjs` closes the network host last, and always, in each of these cases:
    on SIGTERM or SIGINT; when `agent.start()` fails; when a setup step after the host's creation fails; and when a stop
    arrives during startup. The daemon then exits by itself, with the canary and direct ports free.
    `test/privacy-agent-lifecycle.test.mjs` shows this with the real daemon process. Against the previous agent, the same
    test's daemon did not exit after SIGTERM, nor after a failed start.

**Without `--independent`,** the checker behaves exactly as before. That is the compatibility path for Enclave's fleet
(`checker.service` passes `--relay https://api.enclave.host`).

## 2. Pin distribution and trust assumptions (exact)

| What you configure | Where it comes from | What you are trusting |
| --- | --- | --- |
| `authorityPins` (deployments, registry, connectivity, sessionVaultFactory) | The reviewed deployment records in `contracts/deployments/` and the captured pins (`scripts/network/capture-contract-pins.mjs`). Compare them across at least two sources you consider separate. The contracts are immutable, so a pin never needs updating. | That whoever handed you these addresses gave the real ones, and that the code at them is what was reviewed. Re-derive the code hashes; `capture-contract-pins` records them. |
| RPCs (two or more; three or more to tolerate one bad one) | Your choice: different operators, ideally including one you run. | That no two of them collude. This is RPC-quorum trust, not a light client. The first two RPCs that return the same whole snapshot at one fixed block decide. A third that lies, hangs or is on another chain can neither veto nor decide. With only two, either can refuse service, never forge it. |
| Directories | Any operators. They carry signed records. | Availability only. Every record is checked against its signature and chain state; a directory cannot forge one. A directory can withhold records, which is why you list several. |
| Checkers | Your explicit choice. | That these keys judge providers honestly. Checkers are trust anchors. An index ad never makes a checker trusted. |
| App zone / probe zone | DNS zones you or your checkers control. | The zone's DNS operator. |
| Service index pin `{chainId, address, codeHash}` | `contracts/deployments/service-index-pin-base.json`. `service-index.mjs pin` re-derives `codeHash` by compiling `contracts/EnclaveServiceIndex.sol` here and refuses if the deployed code differs. | That you have the address of the index others use. Anyone can deploy another copy, and the code is the same, so the address is what you are agreeing on. The contract has no owner, so it cannot change after that. |

## 3. The service index

`contracts/EnclaveServiceIndex.sol` is ownerless:

- **No administration.** No owner, administrator, pause, upgrade or global delete.
- **Bounded ads.** An operator has up to 8 slots. Each ad carries:
  - a kind: `directory`=1, `checker`=2, `storage`=3, `dns`=4, `replica`=5;
  - a format version;
  - 1 to 4 endpoints of at most 256 printable ASCII bytes;
  - an optional sha256 of a bounded descriptor (4 KiB or less);
  - an expiry at most 90 days ahead.
- **Changes need a higher sequence.** Publish, replace and withdraw each need a strictly higher per-slot sequence, which
  survives withdrawal. Withdrawing with a new sequence also revokes a signed ad that was never submitted.
- **Who can change an ad.** Only the operator, in one of two ways:
  - **Directly.** An EOA, or a smart-contract wallet calling from its own address, through its own tooling. Take the
    `call` from `prepare-publish` / `prepare-withdraw`.
  - **By an EIP-712 signature** bound to the chain id and this contract. Anyone may pay the gas for a signed change.
    - **EOA operators:** a low-s secp256k1 signature.
    - **Wallet operators:** ERC-1271 `isValidSignature`. Gas-sponsored submission needs it. The contract asks with a
      `STATICCALL` capped at 500k gas, reads at most 32 bytes back, and caps signatures at 2048 bytes. A wallet that
      reverts, returns the wrong value or too little, or burns its gas is refused.
- **No takedown.** Anyone may remove an ad that has already expired. Nobody but its operator may remove a live one.
- **Bounded reads.** Enumeration is by kind, in pages of 64.

**Reading** (`network/service-index.mjs` `agreedRead` / `readServiceIndex`, `service-index.mjs list|lookup`). The rule is
`LeaseReader.agreed`'s, with deadlines:

- **Picking the block.**
  - Each RPC reports its chain id and head. An RPC on another chain, or one that fails, is excluded.
  - Once two heads are in, the others get 250 ms.
  - The block is the **second-highest** head minus 2. One RPC claiming a far-future head cannot choose it.
- **Reading at that block.** Every RPC that reported a head reads the whole snapshot there:
  - block hash and timestamp;
  - the code hash;
  - the pages;
  - the lookups.

  A block in the future, or older than 90 s, is that RPC's failure, as is a block hash that changes during the read.
- **Deciding.** The **first two identical snapshots** win; there is never a single-answer fallback.
- **Time limits.** Each request is limited to 8 s and the whole read to 30 s, so a hanging RPC cannot stall discovery.
- **Evidence.** Every result names each RPC's part: `agreed`, `disagreed`, `failed` (with stage and reason), `pending` or
  `late`.
- **No quorum is a refusal.** `QuorumError` carries the same evidence; the command prints it and exits 2. It is never
  reported as an empty directory.
- **Pins hold.** The agreed code must be the pinned code, and the chain must be the pinned chain.
- **Completeness.** Each kind is read in a window of up to 1024 ads, 256 by default. The result says:
  - `status: complete`, when every listed ad was examined; or
  - `status: incomplete`, with `windows` and a `next` cursor. `--resume` continues at the **same block** while it is
    fresh, and a cursor whose block hash the RPCs do not have is refused.
- **Incomplete means partial.** An incomplete result proves nothing about ads it did not reach.
- **Known operators can't be hidden.** `--lookup 0xOP[:slot]`, or `lookup --operator`, reads `get(operator, slot)` in the
  same snapshot, up to 32 operators. No amount of listing spam can hide an operator you already know of.
- **Expired ads are dropped.**
- **Candidates are untrusted.** Each is marked `trust: "untrusted-candidate"`, with a notice. Distinct keys are not
  distinct organizations, and nothing is admitted automatically.

**What an ad is not.** An ad is the operator key's own claim. It does not prove:

- honest content;
- organizational independence;
- an accepted host owner;
- a checker's authority.

**No probing.** The reader never fetches, probes or writes an advertised endpoint. Before a candidate reaches you, it
drops endpoints that name:

- loopback, private, link-local, CGNAT, multicast, documentation or reserved IPv4 addresses (including numeric forms such
  as `http://2130706433/`);
- IPv6 literals;
- single-label or special-use names (`localhost`, `.local`, `.internal`, `.home.arpa` and similar);
- credentials, queries or fragments.

A public name can still resolve to a private address. Anything that contacts candidates automatically must use a
resolver-side guard (`network/guarded-fetch.mjs`). Operators should add a candidate to their configuration by hand,
after their own checks.

### Advertise (operator)

```
node scripts/network/service-index.mjs pin --index 0xINDEX --chain-id 8453 --rpc https://rpc-a --rpc https://rpc-b --out pin.json
node scripts/network/service-index.mjs descriptor --kind directory --operator 0xYOU --endpoint https://dir1.example.org \
  --key recordKey=0x... --out descriptor.json                       # optional; prints the sha256 the ad commits to
node scripts/network/service-index.mjs prepare-publish --pin pin.json --rpc https://rpc-a --rpc https://rpc-b \
  --operator 0xYOU --slot 0 --kind directory --endpoint https://dir1.example.org --descriptor descriptor.json \
  --ttl-days 30 --out ad.json                                       # next sequence read from chain; nothing signed or sent
node scripts/network/service-index.mjs sign --prepared ad.json --key-file operator.key     # offline; prints the signature
node scripts/network/service-index.mjs send --prepared ad.json --rpc https://rpc-a --rpc https://rpc-b --key-file payer.key --signature 0x.. --yes
#   or, from the operator key itself:  send --prepared ad.json --rpc https://rpc-a --rpc https://rpc-b --key-file operator.key --yes
#   (the pinned code and the sequence are checked with agreeing reads first; the transaction goes to the first --rpc)
#   a smart-contract wallet operator: execute ad.json's `call` from the wallet, or have its owner sign the typed data
#   (ERC-1271) and send it with --signature through any gas payer
node scripts/network/service-index.mjs prepare-withdraw --pin pin.json --rpc ... --rpc ... --operator 0xYOU --slot 0 --out w.json
```

Replace an ad by preparing it again: the sequence rises automatically. Renew it before its expiry. A provider installation
advertises nothing on its own.

### Discover (first user)

```
node scripts/network/service-index.mjs list --pin pin.json --rpc https://rpc-a --rpc https://rpc-b --rpc https://rpc-c \
  --kind directory --kind checker [--window 256] [--lookup 0xKNOWN_OPERATOR]
node scripts/network/service-index.mjs list ... --resume next.json      # continue an incomplete read at the same block
node scripts/network/service-index.mjs lookup --pin pin.json --rpc ... --rpc ... --operator 0xKNOWN [--slot N]
```

**What counts as a separate RPC vote.** The command and the library refuse the same client object twice, a repeated
label, and the same public hostname under a different path, key, query or port. For local test chains, the rule is a
distinct loopback port. Each RPC reads one block header, which must be exactly the requested number, with a 32-byte hash
and a whole-second timestamp; re-read after the snapshot, it must be unchanged. Distinct configured endpoints are still
not distinct organizations: two hostnames can share an operator or upstream node. Choose RPCs you have reason to
believe are separately operated.

Take the candidates as places to look:

- **Directories:** list several. Their records are verified anyway.
- **Checkers, storage, replicas:** trusting one is your decision, made on evidence outside the index.

## 4. Deploying another index

The Base instance above already exists. These steps are for operators choosing to deploy another instance; deploying
one is not required to use the existing ownerless contract.

1. Compile with `compileServiceIndex()` (solc-js 0.8.35, viaIR, optimizer 200).
2. Deploy from any funded key. Deploying gives that key no power: the tests show the deployer cannot remove or forge
   anything.
3. Record the address, transaction and `codeHash` under `contracts/deployments/`.
4. Distribute the pin with the reviewed network profile. `service-index.mjs pin` lets anyone re-derive the code hash from
   source.

## 5. Tests

- **`test/EnclaveServiceIndex.t.sol`** (Foundry, 10 tests; 3 of them cover wallet operators):
  - own-slot publish, replace and withdraw;
  - no takedown or administrative surface for the deployer;
  - wrong signer, high-s signature, another contract and another chain id refused;
  - a withdrawal revokes an unsent signature;
  - expiry bounds, and pruning only once expired;
  - slot, endpoint and content bounds;
  - bounded pages;
  - a wallet publishing by direct call;
  - ERC-1271 sponsored publish and withdraw, with no replay and no other chain;
  - wallets that revert, give a wrong or short answer, or burn gas, and oversized signatures, all refused.
- **`test/service-index.test.mjs`** (real Anvil, 15 tests):
  - a reproducible pin, with other code refused;
  - two operators registering independently, one directly and one signed through a gas payer, through the CLI;
  - replacement, and an older signature that can't be replayed;
  - withdrawal;
  - a failed takedown by the deployer;
  - a wrong signer, and a signature for another chain;
  - expiry and pruning;
  - RPC disagreement across two chains, a single RPC, the wrong chain, and a stale view;
  - 70 ads with a 50-candidate bound, and 8 unsafe endpoints dropped;
  - the provider bootstrap rules;
  - `install.sh --config-only` in explicit, refused, legacy-opt-in and update-preserving runs;
  - through RPC proxies: 2 honest RPCs plus a liar, a wrong-chain, a hanging, a future-head or a reorganizing RPC all
    decide correctly; 1 honest plus a liar, or plus a hanging RPC, fails closed with evidence (the command exits 2);
  - resume at the same block; a known operator found by lookup past the window; a forged cursor refused;
  - a wallet operator publishing directly, and sponsored through ERC-1271;
  - the real `wg-qualify --independent` process with `enclave.host` blocked, against the deployed schema-4 registry
    source and a lying RPC:
    - it signs the honest digest and uses the operator's probe targets;
    - it makes no address-book read;
    - the legacy form does reach for the relay;
  - probe targets in a non-Enclave zone.
- **Mutation checks.** In a scratch copy, these weaknesses were re-introduced one at a time, and the named test fails for
  each:
  - all-must-agree;
  - the highest head choosing the block;
  - no reorg recheck;
  - no request timeout;
  - lookups dropped;
  - no freshness check;
  - a single answer accepted;
  - the code pin not enforced;
  - no ERC-1271;
  - the checker trusting its first RPC;
  - probes ignoring independent targets.

Run: `node --test test/service-index.test.mjs`, then
`FOUNDRY_TEST=test forge test --match-path test/EnclaveServiceIndex.t.sol`.
