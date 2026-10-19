# Deployed contract source verification (Base)

`scripts/network/verify-deployed-sources.mjs` rebuilds each deployed Enclave contract and checks it against the live
chain. It takes the exact git commit and blob recorded in `contracts/deployments/source-verification-base.json`, and the
pinned solc-js binary. Then it compares the result, byte for byte, with the runtime code that two or more agreeing RPCs
return at one block. Nothing is signed or written.

The authority profile (`docs/network/authority-profile.md`) labels these contracts `observed`. This tool closes that gap
for every one of them except the external USDC proxy.

## Result (2026-10-19, block 52831645)

| Contract | Address | Build (commit, settings) | Result |
| --- | --- | --- | --- |
| registry | `0x868eb7fc…5ccac` | `b17db9a3` (2026-08-09), runs 200 | full match, no immutables |
| deployments (ledger) | `0xb1783b61…7d117b` | `4b7419bb` (2026-10-12, rev 16d), runs 1, viaIR | full match; immutables `usdc`, `registry`; links `EnclaveLedgerBandwidth` |
| ledger library `EnclaveLedgerBandwidth` | `0x3dfee18b…02215` | same build | full match; guard holds its own address |
| appCatalog | `0x18419ca2…626e3` | `f2e9a71d` (2026-08-18), runs 200, viaIR | full match, no immutables |
| proofOfTime | `0x6f462d77…0e6b2` | `44d5b928` (2026-07-28), runs 200, viaIR | full match; immutables `deployments`, `registry` |
| enclavePay | `0x580270e8…673a6` | `cf6022cc` (2026-07-14), runs 200 | full match; immutable `usdc` |
| verificationFees | `0x87c72665…23641` | `28dd23c2` (2026-09-30), runs 200, viaIR | full match; immutables `ledger`, `proof`, `token` |
| connectivity | `0x5f8b636e…15111` | sources at `4b7419bb`, unit names `contracts/…`, runs 200, viaIR | full match; immutables `ledger`, `registry` |
| paymentRouter | `0xf17157b4…9d56a` | `09ccf9cd` (2026-07-20), runs 200 | full match; immutables `usdc`, `treasury` |
| keyAttestations | `0xb49241ef…f61b` | `ee28c686` (2026-10-06), runs 200 | full match, no immutables |
| legacy SessionVaultFactory | `0x1f5c887c…c9c9c` | `4aea7d89` (2026-10-07), runs 1, viaIR | full match; immutable `implementation` |
| legacy SessionVault implementation | `0x66c76a47…01f65` | same build | full match; six immutables; links `SessionVaultLib` |
| legacy SessionVaultLib | `0x5510ae9f…05027` | same build | full match; guard holds its own address |
| USDC | `0x833589fc…02913` | external proxy, solc 0.6.12 | proxy bytes pinned; **source not verified**; implementation not pinned |

- **Compiler:** solc-js `0.8.35+commit.47b9dedd.Emscripten.clang`, npm package `solc@0.8.35`. The SHA-256 of
  `soljson.js` is pinned in the manifest. Every Enclave runtime's CBOR trailer names solc 0.8.35.
- **Commits:** all nine are on the public `https://github.com/EnclaveHost/enclave.git`. Each one is the first commit
  holding the exact source blobs; any later commit with the same blobs is equivalent.
- **Code hashes:** every code hash equals the one the authority profile pins (digest `sha256:ee957827…`).

### Coordinator verification

A separate live run passed at block **52831935** after adding an address-binding check: when an authority profile is supplied, both the runtime hash and the exact contract address must match. Identical code at another address does not establish the profile's authority.

The npm package's `soljson.js` SHA-256 (`fa4345d6…323b`) differs from the published compiler artifact (`ecabf2b0bf0c3ab0c6bb9cebd309900bd3b5e80c833d2bc68a330fa5508398f5`). The JavaScript formatting differs; digest equality is **not** claimed. The coordinator downloaded the separate artifact from the [official compiler repository](https://github.com/argotorg/solc-bin), checked its complete SHA-256 against that repository's `bin/list.json`, and used it to recompile all ten builds. All **13** Enclave runtimes, including metadata and declared immutable/library slots, matched live chain bytes again at block **52832002**. This independently confirms the reported source matches using the published compiler rather than relying solely on the local npm artifact. The normal command still requires the npm artifact digest recorded in the manifest.

### What "full match" means here

1. The compiler output and the live runtime have the same length.
2. They are identical byte for byte, **including the CBOR metadata trailer**. The metadata embeds the
   keccak-256 of every source file, the source unit names and the settings, so this is not a metadata-stripped
   comparison.
3. The only bytes allowed to differ are the slots the compiler itself declares:
   - `immutableReferences`;
   - `linkReferences`;
   - a library's own-address guard (`library_deploy_address` under viaIR, or `PUSH20 <self>` under legacy codegen).
4. Every occurrence of a slot carries the same value.
5. Each slot value equals the manifest's value. The manifest's values were cross-checked against independent sources
   before they were recorded:
   - every address immutable equals the authority profile's getter binding;
   - the legacy vault's `usdc`, `book`, `router`, `keyAttestations`, `maxVault6`, `factory` and library link equal
     `contracts/deployments/ledger-15d-base.json`;
   - each library guard holds that library's own address.

   That is 26 cross-checks in total.

Some cases are reported as mismatches, never as matches:
- **Metadata-only differences.** A comment-only edit, a renamed source unit or a different settings set leaves the
  executable bytes equal but changes the metadata. The tool reports
  `executable bytes equal but metadata differs (partial match only)`.
- **Executable differences.** The report gives the first differing offset and the number of differing bytes.

## Findings

**The registry is schema 4, not HEAD's schema 5.**
- The live registry is the `b17db9a3` source.
- HEAD's `contracts/EnclaveRegistry.sol` (blob `b7064f3e`, unchanged since `9895865c`, 2026-08-11) is schema 5. It adds
  the `CAP_*` capability bits, `registerRelay`, `setCaps` and `CapsSet`.
- None of those selectors (`registerRelay` `204d567f`, `setCaps` `4d13968b`, `CAP_HOST` `1819aa1d`) appears in the live
  runtime.
- **Consequence:** statements that the deployed registry offers permissionless `registerRelay` or capability bits are
  wrong for `0x868e…`. The 2026-10-19 parity audit cites `EnclaveRegistry.sol:176,232` and capability bits, which
  describes source, not this deployment. Host `register` exists, and the deployed source has no owner or admin.

**The ledger is rev 16d. HEAD's source has the same schema number but is different code.**
- The live ledger is `4b7419bb`'s `EnclaveDeployments.sol` (blob `3f3d2c3a`).
- HEAD's `contracts/EnclaveDeployments.sol` also declares `deploymentsSchema = 16`, but differs in 68 lines.
- The main difference: the deployed ledger has wallet-chosen delegates.
  - `setDelegate` and `isDelegate` exist.
  - `_requireOwned` accepts the record's owner **or** an approved delegate.
- **The schema constant therefore does not identify the code.** Use this verification, not the schema number.
- The set of functions that check the contract `owner` is identical in both sources. All of them are owner-only
  except `fundEscrow`, which consults the owner only for accounting while imports are open:
  `fundEscrow`, `import*`, `retire`, `sealImports`, `setBandwidthRouter`, `setClaimBond`, `setEthUsdFeed`,
  `setFeeRouter`, `setLeaseSec`, `setMaxFee`, `setMaxGpuMilli`, `setOwner`, `setPayout`, `setProofRequiredFrom`,
  `setProver`, `setRunnerBps`, `slashBond` and `sweepEscrow`. So the profile's ledger owner-power list holds for the
  deployed bytes.

**The ledger has a separate library.** `EnclaveLedgerBandwidth` at `0x3dfee18b44b7ecd389eca78da10b6ad032802215` is
called by the ledger. It is not listed in the authority profile. It is pinned transitively, because its address is
embedded in the ledger runtime whose hash the profile pins, and it is now source-verified.

**Connectivity was built by a different pipeline.**
- Its metadata matches only with source unit names `contracts/EnclaveConnectivity.sol` and
  `contracts/EnclaveDeployments.sol`.
- `build-contract-artifacts.mjs` uses bare names, and no committed artifact ever contained this metadata.
- The sources are committed: connectivity blob `c0fb0bed`, plus the live ledger's blob `3f3d2c3a`. The live interface is
  the pre-v2 `tuna` one; `b28a9b2e` renamed it afterwards.
- The deploy script that used these unit names is not identified. Only its inputs and settings are reproduced.

**These deployed sources are identical to the work tree's HEAD:** catalog, proof of time, pay, verificationFees,
connectivity, router, key attestations and the legacy session vault. For them, the owner-power text in the authority
profile, which was taken from HEAD source, describes the deployed bytes.

**The router's treasury is not a plain wallet.**
- The immutable `treasury` `0x271a59b4…8f44d` has 23 bytes of code, `0xef0100 63c0c19a…dae32b`. That is an EIP-7702
  delegation from an EOA to the 11,185-byte contract `0x63c0c19a282a1b52b07dd5a65b58948a07dae32b`.
- The EOA's key holder controls the treasury and can change the delegation. Neither the key holder nor the delegate
  contract is verified here.
- Payments routed through PaymentRouter land there.

**The owner and admin addresses are plain EOAs.** The owner and payout `0x0b2d…ee61` and the USDC proxy admin
`0x4fc78503…ca44` have no code.

## USDC: what is pinned and what is not

- **Pinned:** the proxy runtime (`0xa6705a10…`, 1852 bytes, CBOR solc 0.6.12).
- **Observed only, not pinned:** on every run, the tool reads and reports these two ZeppelinOS slots:
  - the implementation, `keccak("org.zeppelinos.proxy.implementation")`; observed value `0x2ce6311d…fd779`, a contract;
  - the admin, `keccak("org.zeppelinos.proxy.admin")`; observed value `0x4fc78503…ca44`, an EOA.
- **Not source-verified:** neither the proxy nor the implementation.
- **The admin can upgrade the implementation at any time without changing the proxy hash.** A passing run therefore says
  nothing about future USDC behaviour, and the report marks `implementationPinned: false`. The tests show that a
  changed implementation still passes the proxy check, and that changed proxy bytes do not.

## Run it

You need a git directory that holds the manifest's commits. A blobless clone is enough; blobs are fetched on demand.

```sh
git clone --bare --filter=blob:none https://github.com/EnclaveHost/enclave.git /tmp/enclave-history.git
node scripts/network/verify-deployed-sources.mjs \
  --manifest contracts/deployments/source-verification-base.json \
  --git-dir /tmp/enclave-history.git \
  --rpc https://base-rpc.publicnode.com --rpc https://mainnet.base.org --rpc https://base.drpc.org \
  [--profile contracts/deployments/network-profile-base.json --profile-digest sha256:<reviewed digest>] \
  [--out NEW_RESULT.json]
```

**Refusals before any compile:**
- solc version, package or `soljson.js` digest differs from the manifest;
- a source's blob id at the commit, or its SHA-256, differs from the manifest;
- the manifest has unknown fields or uses settings outside optimizer, viaIR and evmVersion;
- the build imports a unit that is not pinned.

**Chain reads** use `LeaseReader.agreed`:
- 2 to 8 distinct HTTPS RPC hosts;
- chain id 8453;
- one confirmed, fresh block whose hash is unchanged after the reads;
- at least two identical answers.

**Resources:** one solc job at a time. The 2026-10-19 run peaked at 366 MiB RSS and took about 40 s, all 10 builds
included.

**Exit status:** 0 only if every Enclave contract is a full match and every external proxy hash matches.

## Tests

`node --test test/deployed-sources.test.mjs` runs 11 tests offline. They cover:

- **Manifest checks:**
  - strictness and completeness against the profile's `observed` entries;
  - agreement with the profile bindings and the ledger-15d record;
  - 13 refusal cases.
- **Metadata hashing:** the IPFS hash and the CBOR trailer.
- **Offline rebuilds:** three deployed sources present at HEAD (router, pay, key attestations) rebuild to exactly the
  live code hashes.
- **Precise mismatches:**
  - a changed executable byte, reported with its offset;
  - a metadata-only change;
  - a wrong, undeclared, missing or inconsistent slot value;
  - a length difference;
  - empty code.
- **Inputs that must not fully match:** a comment-only change, other runs, and a renamed unit.
- **Libraries:** link checks and own-address guards, under both legacy codegen and viaIR.
- **Source pinning:** blob, digest, commit and path, and refusal of unpinned imports.
- **Compiler pinning.**
- **End to end with scripted peers:**
  - a full match;
  - a proxy implementation that is observed but not pinned;
  - two agreeing liars;
  - a single liar;
  - wrong chain;
  - stale blocks;
  - missing code;
  - changed proxy bytes.
- **CLI argument refusals.**

## Remaining gaps

- **USDC.** The proxy and implementation sources are not verified, and the implementation is upgradeable by Circle's
  admin. This is external trust.
- **Treasury.** The router treasury's EIP-7702 delegate `0x63c0c19a…` and the ledger's `ethUsdFeed`
  `0x71041ddd…` (9571 bytes, an external price feed) are not verified.
- **Connectivity deploy pipeline.** The script that compiled with `contracts/…` unit names is not identified. Its exact
  inputs and output are reproduced.
- **Bytes, not behaviour.** Source verification ties the bytes to the source. It does not audit what that source does.
  Owner powers are as documented in the profile and above.
- **Contracts outside the profile are not covered:** the address book, the session v1 factory and library, the credit
  vault, featured, reviews, availability, host paymaster and secret vault v1.
- **RPC trust.** The chain reads are an RPC quorum, not a light client.
- **The profile file is not updated.** The authority profile still labels these runtimes `observed`, and its owner-power
  text still says it is not proven for these bytes. Updating the profile is a separate reviewed change, and needs a new
  digest.
