# Enclave

**Compute that cannot see your data.** Deploy a WebAssembly app into a hardware-isolated VM of its own, check from your browser or the CLI which hardware and code it runs on, and pay per second by card or from a wallet.

Enclave is source-available, commercial software ([license](#license)). This README separates what serves customers today from research and roadmap; the [threat model](#threat-model-what-you-are-trusting) below says what each kind of host protects you from and whom you still trust.

- **Site / app store / dashboard:** https://enclave.host
- **Developer guide + API reference:** https://enclave.host/develop (OpenAPI spec: [site/openapi.json](site/openapi.json))
- **REST API:** https://api.enclave.host/v1 (CORS-enabled; drive it from a browser)
- **Deployed apps:** `https://<id>.app.enclave.host` (the deployment id's first 8 hex chars), TLS terminated in-enclave — or **your own domain**, with its certificate minted inside the enclave too ([docs/custom-domains.md](docs/custom-domains.md))

## What runs today

Three kinds of host serve apps, and every one of them runs each app in a VM of its own. TLS terminates inside that VM.

| host | your app runs in | status |
|---|---|---|
| **Confidential server** (AMD SEV-SNP) | its own SEV-SNP guest, with memory encrypted by the processor | production (metal0) |
| **Windows machine running Enclave Shield** | its own VBS-isolated Hyper-V partition, booted from our measured paravisor image | production on one machine; host exclusion not yet tested by us (below) |
| **Android phone** (pVM tier) | its own protected VM (pKVM), CPU only | production on one Pixel 10 |

GPU inference runs through Enclave Shield's masked offload: the GPU computes on masked tensors and every result is checked, so a card outside any confidential boundary never sees plaintext. It serves metal0's two V100-class cards and the Windows host's integrated GPU.

Each kind of host is a single machine today, so there is no failover within a tier: if a host goes down, the apps on it stop until it returns.

Not live, and not to be read as such: Enclave Shield's CPU isolation on Linux (a design; nothing upstream provides it on x86) or on any OS other than Windows; several hardware-separated apps inside one confidential guest (`isolation/` M4b, design). The original hosted fleet, which ran every app as a process inside one shared confidential VM, was retired on 2026-10-14. The live list of attached hosts is at https://enclave.host/develop#fleet, and the dated engineering record of what has and has not been demonstrated is at https://enclave.host/develop#progress.

## Threat model: what you are trusting

Each kind of host protects against different parties, and each still relies on someone. The deploy dialog and each dashboard row name the kind of host and what it protects.

| host | protects your app from | you still trust | who checks the evidence |
|---|---|---|---|
| **Confidential server** | the host OS, hypervisor and operator, and other tenants: the processor encrypts the guest's memory and keeps them out | AMD (processor and its signing chain; the root key is pinned), and the image built from this repo's release tag | the site and `enclave attest` check the server's report (AMD chain, a fresh nonce). Unpinned, the verdict is **limited**: the measurement is compared against Enclave's published allowlist. Pin a measurement you derived yourself (`enclave attest --expect`) for **verified**. For a public deployment, its **Verify** button then checks the app's own guest in your browser, for card and wallet accounts alike. The guest's report, fetched from the app's public address over a fresh nonce, must bind the key the app's TLS certificate carries, name this deployment and app, come from the same processor, and match the relay's published prediction of that guest (`/v1/expected-guest`). That makes it **limited** too. Run live against production on 2026-10-17: all 18 checks passed on a public app's guest on metal0. **Gaps:** the CLI checks only the server, and a private deployment has no public address to ask. |
| **Enclave Shield on Windows** | other tenants (the hypervisor separates partitions); Windows itself, which VBS keeps out of a partition's memory per Microsoft's design (our own host-side test has not run, so these hosts report `host_excluded: no`) | Microsoft (Hyper-V hypervisor, secure kernel, boot chain), the machine's owner and anyone with physical access. Partition memory is **not** encrypted. | the relay checks both at attach. Your browser can check them too: a Shield deployment's **Verify** button checks the machine's TPM-quoted boot (with a credential the page mints itself), then that app's own partition report under that boot's key, over a fresh nonce. That works for card and wallet accounts alike. The verdict stays **limited**, because host exclusion is unevidenced and the image list is the operator's. The CLI does not do this check yet. |
| **Android phone** | the Android host OS, which pKVM keeps out of the VM's memory, and other tenants | Google (pKVM, the DICE/RKP attestation chain to Google's pinned root; revocation is not checked) and the phone's hardware | the relay checks each app's protected VM at attach. For a public deployment, its **Verify** button checks that VM in your browser too, for card and wallet accounts alike. It verifies the phone first, then the app VM's evidence, fetched from the app's public address over a fresh nonce. That evidence must chain to Google's root, bind the key the app's TLS certificate carries, name the app the deployment runs, and come from the phone's own VM or a sibling VM. A sibling must prove it holds the phone's registered proof key, which only VMs of the pinned build ever hold. **Limited:** the expected app, the allow-lists and the proof key are the relay's statements. Run live against production on 2026-10-18: all 14 checks passed on a public hello-world deployment on the Pixel 10, including its sibling statement recovering to the phone's registered proof key. **Gap:** a private deployment has no public address to ask. |

Across every host:

- **Enclave's own servers** run discovery and placement, the API relay, the site and its IPFS gateway, the certificate service and its DNS zone, card checkout, and the measurement allowlist that admits new hosts and releases. The catalog, the deployment ledger, the host registry and payment routing are public contracts on Base.
- **Deployment secrets** (environment variables) are stored by the API relay, whose operator, Enclave, can read them. For data Enclave must never see, use [encrypted volumes](https://enclave.host/develop#docs-encvol), whose keys derive from your own signature in your browser. A custody path that takes secrets off the relay is rolling out on SEV-SNP hosts ([docs/security/secret-custody.md](docs/security/secret-custody.md)); its custodians are still operated by Enclave.
- **GPUs.** Tenant code never runs on a GPU, and today a GPU is reached only through Shield's masked offload ([Tenant isolation](#tenant-isolation-by-host-type) covers several tenants on one card).
- **No external audit** of the platform, Enclave Shield or secret custody has been done. Every review so far is internal.
- **Contract upgrades** are owner-governed; [Contract upgrades and refunds](#contract-upgrades-and-refunds) says what moves and what doesn't.

## Getting started: a passkey and a card

No wallet, seed phrase, browser extension or crypto is needed to use Enclave.

1. **Sign in with a passkey** at [enclave.host](https://enclave.host): Face ID, Touch ID, Windows Hello, a password manager or a security key. On a computer without a passkey, **Use your phone** shows a QR code that you approve on your phone.
2. **Add credit by card.** Payment goes through hosted Stripe Checkout, and your balance is shown in dollars.
3. **Deploy** from any app's card with a dollar budget. You can top up, suspend, resume, change the version or cancel from the dashboard. Cancelling returns unused runtime to your credit.

The platform pays all network fees. Refunds are handled by support and go back to the original card through Stripe ([docs/billing-runbook.md](docs/billing-runbook.md) §3, §6). In the terminal, `enclave login` signs the CLI in to the same account through your phone or browser ([cli/README.md](cli/README.md)).

How credit works underneath: your credit is held in a credit vault, a contract on Base that only your passkey can authorize spending from. It can be spent only on Enclave compute: there is no withdrawal path and no owner. The company holds one narrow recovery role. If the vault factory is ever redeployed, that role can move a vault's whole balance to the same customer's vault at the new factory, an address only the same passkey can spend from. It cannot choose an amount or a recipient. The contract's own trust note records the cost: a full compromise of governance could misuse that path (`contracts/EnclaveCreditVault.sol`). The balance is capped at $2,000.

**Your credit is tied to the first passkey you created.** The vault accepts signatures only from that key. The contract can register more keys, but the site does not offer that yet, so a second passkey today adds another way to **sign in**, not another way to **spend credit**. If you lose that first passkey, no one can recover the credit, because a recovery path would mean the company holds your funds. Keep the balance to what you plan to spend soon.

### Prefer a wallet?

Any Ethereum wallet works too, paying in USDC or ETH on Base, and agents use one with scoped [wallet sessions](https://enclave.host/develop#docs-sessions). A wallet gives you direct on-chain ownership of each deployment. It is also still required for the following, which credit deployments don't support yet:

- live logs, and the raw attestation document of a private deployment (the in-browser **Verify** check works for every account);
- secrets and custom domains;
- config overrides;
- deploying apps that charge a publisher fee, and publishing your own apps.

## How it works

1. **Apps are Wasm components** (`wasi:http`). Anyone publishes to the on-chain app store (`EnclaveAppCatalog` on Base): the bytes go to IPFS addressed by CID, the listing, versions, and resource specs live on-chain. A version may declare an hourly publisher fee (capped on-chain, immutable per version, covered by approval): deployers see it in the rate up front and the publisher's cut of every funding forwards straight to their wallet, non-custodially. The enclave image ships no deployable apps; everything it runs is fetched by CID and hash-verified inside the enclave.
2. **Deployments are on-chain work items** (`EnclaveDeployments`: create → fund → claim → lease). A deployment references a catalog **version** (`catalog://<appId>/<versionIndex>`), the immutable wasm + config + ports record the catalog owner approved. Funding comes from card credit (the customer's credit vault creates and funds the record when they deploy) or directly in USDC (EIP-3009) or ETH. It is metered per second; top up to extend, stop anytime.
3. **Enclaves claim the work.** Each enclave self-registers in `EnclaveRegistry`, polls for funded work it can serve, claims it, and runs the app. How apps on one machine are kept apart from each other depends on the host type (see [Tenant isolation](#tenant-isolation-by-host-type) below).
4. **Every layer attests.** A release is built from this repo's release tag; the enclave's launch measurement covers the code it runs, the enclave proves that measurement in an attestation quote over the verifier's own nonce, and TLS keys never leave it. The site and CLI (`enclave attest`) check the quote client-side before connecting.

Beyond plain web apps: GPU inference via `wasi-nn` (ONNX, GGUF through a bundled llama.cpp backend, and image diffusion through a stable-diffusion.cpp backend; on today's hosts the GPU is reached only through Enclave Shield's masked offload, which serves GGUF models), attested read-only **model volumes** mounted at `/models` (dm-verity images; the attestation commits to the exact weight bytes), raw TCP/UDP services reached through the Enclave network (WireGuard circuits whose providers route by SNI and never hold a TLS key; `network/`), and per-deployment dedicated IPv6 (inbound and outbound).

## Tenant isolation, by host type

"The TEE protects tenants from the host" and "tenants are protected from each other" are separate properties. Which boundary sits between two customers on the same machine depends on the host:

| host type | boundary between two customers' apps |
|---|---|
| **Enclave Shield hosts** (Windows) | **A separate VM per app.** Every market deployment runs in its own Hyper-V partition (`windows/vbslike/manager`), and market scope refuses any other placement (`windows/node/host.mjs`). Separation between apps is enforced by the hypervisor, not a process boundary. These hosts do not yet exclude their own operator: the launcher that signs the report runs in the root partition. |
| **pVM phone hosts** | **A separate protected VM per app** (`relay/pvm-app-attest.mjs`, backend `avf-pvm-per-app`). CPU only. |
| **Confidential servers** (SEV-SNP, e.g. metal0) | **A separate SEV-SNP guest per app.** The node's own confidential VM runs the control plane only; `isolation/m4/guestd` launches every app in its own SNP guest on the same machine, the app's TLS ends inside that guest, and the node serves only deployments that require this isolation. App-vs-app separation is enforced by the processor, and each guest is also protected from the host and its operator. The node side is `metal/` (`isolation.backend: "snp-guest-per-app"`), the guest side `isolation/m4/guestd`. |
| **Shared-VM hosts** (the original hosted fleet, retired 2026-10; none serving today) | **Shared confidential VM, separate process per app.** The hardware boundary is around the whole VM and protects every tenant from the host. Inside it, each app is its own `wasmtime` process with a loopback wall between apps, so a sandbox escape in one app would reach the others on that VM. This is the original design. |

**GPU sharing.** Tenant code never runs on the GPU. A Wasm app reaches the card only through the platform's own `wasi-nn` backends (llama.cpp, ONNX Runtime, stable-diffusion.cpp), so no device pointer or kernel crosses the boundary (raw PTX submission is refused). A GPU outside a confidential boundary is used only through Enclave Shield's masked, verified offload (`shielded/`). One untrusted worker per card serves every tenant on it, and the design treats that worker, the host and the card as hostile. Each app's trusted half runs inside the app's own VM, masks every tensor with a fresh one-time pad before it leaves, and checks every result (Freivalds) before any output leaves the VM. A co-tenant on the same card can therefore do no more than the card's owner could ([docs/shielded-inference.md](docs/shielded-inference.md)). It can learn padded request shapes, size buckets and coarse timing. It cannot read prompts, activations, KV cache or outputs, and it cannot alter a result undetected. What sharing does **not** give you is availability: a stalled or crashed worker affects every tenant on that card, whose apps fall back to computing on the CPU inside their VM. Model weights are public and are not masked, so a private model cannot use the offload. NVIDIA MPS appeared only in the retired shared-VM GPU flavors, where it divided capacity; it was not an isolation boundary there, and NVIDIA does not present it as one.

Every host serving today runs one VM per app. The shared-VM model applied only to the retired hosted flavors.

## Architecture and roadmap

The goal is one app contract on every kind of machine, where only the protection level changes with the host:

- **One portable app bundle and one versioned domain contract.** The same Wasm package runs on every backend. The contract has a Go reference and a Rust mirror that pass one set of conformance vectors (`isolation/contract/`). *Live.*
- **An OS-independent isolation contract.** Each app gets its own hardware domain, and a smaller measured trusted layer keeps the ordinary host OS out of it. The contract also covers measured identity, attestation, key and traffic binding, fail-closed verification and cleanup. *Live as one VM per app on all three host types; host exclusion is processor-enforced on SEV-SNP and pKVM-enforced on the phones, and unproven by us on Windows.*
- **Enclave Shield** is the protection for machines without confidential-computing hardware. It has two parts:
  - **Per-app CPU isolation that keeps the host OS out.** *Live on Windows* (VBS-isolated Hyper-V partitions). The rest is roadmap: Linux is a design, and nothing upstream provides that backend on x86. No other OS has a backend.
  - **Masked, verified GPU offload** for any GPU outside a confidential boundary. *Live* on the hosts above. There has been no external review, and performance figures stay unpublished until they are stable.
- **Confidential hardware** (SEV-SNP today) adds protection from the machine's operator and memory encryption without changing the app contract. *Live.*
- **Fewer indispensable parties.** On the roadmap: publisher-signed bundles, a trust policy you keep locally instead of our allowlist, reproducible measurements, mirrors, interchangeable coordinators and secrets that recover without us. *Not built.*

The full architecture, the isolation contract property by property, and the dated evidence note are at https://enclave.host/develop#architecture (source: `site/develop.html`). The research behind per-app hardware isolation, with its evidence scripts, is under `isolation/`.

## Repository layout

| path | what it is |
|---|---|
| `supervisor.js` | the in-enclave service: REST API, deployment lifecycle, metering, attestation endpoints |
| `wasm/` | wasm-manager sidecar: the wasmtime sandbox that runs tenant apps, incl. `wasi-nn` inference (ONNX Runtime + llama.cpp/GGUF + stable-diffusion.cpp), and the Shield-side ggml backend (`wasm/ggml-shielded/`) |
| `worker/` | GPU worker of the retired shared-VM GPU flavors (trusted PTX only; tenant PTX was never accepted). Kept for reference, serves nothing |
| `mps-daemon/` | NVIDIA MPS control daemon of the retired shared-VM GPU flavors; on metal boxes MPS is at most an optional cap on the platform's own Shield worker, never a per-tenant boundary |
| `shielded/` | the GPU offload component of **Enclave Shield**: inference on an *untrusted* GPU, where activations and KV cache never leave the trusted domain in plaintext. Required for any card outside a confidential boundary, on any host; the large-model performance research on it is a separate line of work with unpublished numbers. It serves market work today: CUDA workers on metal0's two V100-class cards (a 27B GGUF model, over vsock to the per-app SNP guest) and a Vulkan worker on the Windows Shield host's integrated GPU; the TEE-side ggml backend is under `wasm/ggml-shielded/` ([docs](docs/shielded-inference.md)) |
| `isolation/` | per-app hardware isolation research: the backend-neutral app-domain contract (`contract/`), and milestones M1 to M4 with their evidence scripts; M4a (one SEV-SNP guest per app, `m4/guestd`) runs in production on metal0; M4b is design. Where a milestone also runs the same image on ordinary KVM, that run is a control for the confidential path, not a product tier: there is no ordinary-Linux host backend, and none is built or listed unless a hardware-enforced, measured boundary excludes the host OS |
| `windows/` | the Windows host: the node (`node/`; its original VBS-enclave engine in `vbs/` is retired), and the partition-per-app backend built on Hyper-V partitions with the same guest image as Linux (`vbslike/`): the isolation manager the Windows host installer runs for every market deployment |
| `contracts/` | Solidity on Base: `EnclaveRegistry`, `EnclaveAppCatalog`, `EnclaveDeployments`, and for card customers `EnclaveCreditVault` (passkey-signed, closed-loop credit) |
| `relay/` | the control services Enclave runs: the API gateway, fleet discovery and placement, attestation checks, certificate coordination, accounts and billing, and the MCP server for coding agents (`mcp.enclave.host`). It carries no app traffic ([relay/README.md](relay/README.md)) |
| `network/` | the Enclave network that carries app traffic: WireGuard circuits through qualified providers, the owner's own peer, or a host's own public address; TLS stays end to end into the app's VM |
| `egress.js` / `net-guard.mjs` | outbound egress shim and network guard |
| `site/` | the enclave.host static site, published to IPFS (LWC-style web components, soft-nav router; `npm run build:site`) |
| `cli/` | the `enclave` CLI (deploy, fund, attest-verify from a terminal) |
| `enclaves/` | the release's enclave config (`cpu/config.yml`): supervisor environment + image pins a metal guest is built from |
| `scripts/` | build, release, and CI setup |
| `test/` | `npm test` (node --test) |

## Resources: apps declare specs, deployments buy shares

**Apps** declare their exact resource specs in the on-chain catalog (EnclaveAppCatalog): `vramMb` + `gpuGflops` of one GPU card (both 0 = CPU-only app) and `memMb` + `cpuGflops` of the node (compute in GFLOPS = 1/1000 TFLOPS). Every deployment references a catalog version (`catalog://<appId>/<versionIndex>`); the enclave image ships no deployable apps.

**Deployments** buy exactly TWO shares, the only two settings on the deploy page:

- **`gpuShare`** (0–100%): a slice of ONE GPU card. VRAM and compute move together: the share is a reservation of that fraction of the card on the host's Shield worker (scheduling and accounting, not a hardware boundary; the masking is what protects the data on the card). 0 = CPU-only app.
- **`cpuShare`** (1–100%): a slice of the node's vCPU+RAM. The wasm guest's memory cap is that slice of the node's RAM.

The app's specs set the **minimum shares**: each pool's floor is the spec divided by the server's spec, taking the **larger** of the memory and compute axes, rounded up to the whole percent. Server specs are each host's own: metal0's pooled card is 62 GB / 214.7 TFLOPS today, live at `https://api.enclave.host/availability` (VRAM is probed from the card at boot via `nvidia-smi memory.total`, `GPU_VRAM_GB` is only the fallback; compute via `GPU_TFLOPS`); node from `NODE_RAM_GB`/`NODE_GFLOPS` ( CPU compute is denominated in GFLOPS because a whole node is only ~1/1000 of a card). Each axis floors on its own hardware: the two shares are **independent** (ledger schema 13). Earlier ledgers also required **`gpuShare >= cpuShare` whenever `gpuShare > 0`**, which lifted a GPU app's GPU minimum to its CPU minimum and forced CPU-heavy apps to over-buy card; clients still apply that lift when the live ledger predates 13. Runners enforce the minimums at deploy and claim time; the site's deploy page floors its two dials at them.

The leftovers are the point: a tenant buying 100% GPU + 10% CPU leaves 90% of that node's CPU/RAM rentable by CPU-only apps. Pricing is additive: `rate = gpuShare × cardRate + cpuShare × nodeRate`, per second. The current rates live on-chain in `EnclaveDeployments` and are shown live on [enclave.host](https://enclave.host).

Routing: GPU work (`gpuShare > 0`) runs **only** on GPU-enabled enclaves. CPU-only work is served by CPU-only enclaves first; GPU enclaves bid on it only after a grace window (`CPU_CLAIM_GRACE_SEC`, default 120s) and only out of leftover CPU pool.

## Contract upgrades and refunds

The deployment ledger and the on-chain address book are governed by an owner key held on a hardware wallet, and governance points the on-chain address book at the live revision of each contract. Here is what that means for money you have put in:

- **Refunds while a deployment runs.** For a deployment you funded from a wallet, `refund(id)` pays you your own unspent escrow: the host's share of what you funded in USDC, after the host is paid for time it has proven. `refundableOf(id)` quotes the exact figure. The publisher's cut, the platform's share and ETH fundings leave at funding time and are never refunded. For a deployment paid from card credit, cancelling returns unused runtime to your credit. Refunds of credit to your card go through support ([docs/billing-runbook.md](docs/billing-runbook.md)).
- **A new contract revision never moves records by redeploying.** A deploy from CI mints a fresh, empty contract at a new address, after a one-click approval. A live ledger is replaced only by a migration (`scripts/migrate-contract.mjs`). The migration imports every record, balance and rate cap into the new revision, diffs them field by field against the source and then seals the import. The 2026-10-12 cutover moved all 74 records.
- **Escrow does not move in a migration. It goes home.** Imported records carry no escrow: the USDC stays on the old contract. The platform re-backs the new records so they keep running, but that re-backed escrow is not refundable to the owner on the new ledger. Instead, the old ledger is retired (`retire()`, one-way). Retiring stops every claim, renewal and funding there and opens `refund()` to any caller, which still always pays each record's **owner**. One permissionless sweep therefore returns every record's held escrow to the wallet that funded it, with no owner signature needed and nothing the platform can redirect. The audit before the 2026-10-12 cutover found no active record holding owner-refundable escrow.
- **Card credit never migrates.** Credit vaults are separate contracts that stay where they are. Rotating the vault factory changes only the addresses of new vaults.

## Releases (operators)

`enclaves/cpu/config.yml` is the release's enclave config: the supervisor's non-secret environment (`GPU_COUNT=0`, CPU-enclave mode, the contract addresses) and the digest pin of the wasm-manager image. A release is a `vX.Y.Z-cpu` tag plus its GitHub Release, cut by `.github/workflows/release-cpu.yml`, which also builds `ghcr.io/enclavehost/enclave-supervisor:vX.Y.Z-cpu`. Metal boxes follow it: `metal/update.mjs` takes the newest `-cpu` release and builds the guest image at that tag (`metal/build-image.mjs`), health-gated with rollback; see [metal/README.md](metal/README.md) to run one. The GPU flavors (`enclaves/gpu`, `enclaves/gpu8`) and their hosted fleet were retired on 2026-10-14.

How the routing is enforced:

- **Deploys**: the supervisor floors `resources.{gpuShare, cpuShare}` at the app's spec-derived minimums and refuses `gpuShare > 0` on a CPU enclave. The two shares are otherwise independent — a GPU app may buy more node than card. CPU-only requests are served on either flavor from the node's CPU pool.
- **On-chain**: `EnclaveDeployments.create(appRef, gpuMilli, cpuMilli, ...)` takes the two shares in 1/1000ths (the contract bounds each and prices both additively; from schema 13 they are independent of one another). GPU enclaves only adopt `gpuMilli > 0` work; CPU-only work goes to CPU enclaves first, with GPU enclaves as a delayed fallback (`CPU_CLAIM_GRACE_SEC`). Each runner re-derives the app's minimum shares from its catalog specs (via `cidStatus`) and skips under-provisioned deployments.
- **Apps**: catalog apps declare exact specs on-chain on four axes: `vramMb`/`gpuGflops`/`memMb`/`cpuGflops` (EnclaveAppCatalog, returned by `cidStatus`). Those specs only set minimum shares; GPU-needing apps are refused on nodes with `NODE_HAS_GPU=0`.

## CI/CD (push-to-main deploys)

Every push to `main` runs `.github/workflows/deploy.yml`, which diffs against the
last successfully deployed commit and deploys only what changed:

| what changed | what happens |
|---|---|
| `site/**` | scp + IPFS publish to the site box (`site/deploy.sh`) |
| `relay/**` | scp + systemd restart on the relay box (`relay/deploy.sh`) |
| `contracts/<Name>.sol` | that contract deploys to Base (`scripts/deploy-*.mjs`), **after a one-click approval** on the `contract-deploy` environment; addresses are wired into `enclaves/cpu/config.yml` + the site and committed back |
| `Dockerfile` / `supervisor.js` / `package*.json` | a new release (`release-cpu.yml` builds the supervisor image, tags `vX.Y.Z-cpu` and publishes the GitHub Release) |
| `wasm/**` | the wasm-manager image is built + digest-repinned (`scripts/release.sh`), then a release |
| `metal/**` (code) | a new release (metal boxes build the guest image at the tag) |
| `enclaves/cpu/config.yml` (non-`image:` lines) | a new release (the supervisor environment is part of the guest image) |

Releases are auto-versioned (the latest `vX.Y.Z` / `vX.Y.Z-cpu` tag, patch-bumped,
released as `-cpu`) and dispatch `release-cpu.yml`. Running enclaves need nothing
from CI: each metal box pulls the newest `-cpu` release on its own timer
(`metal/update.mjs`), stages the new image beside the live one, and rolls back if
it does not come back healthy. A registry redeploy automatically cascades into a
deployments redeploy (claims are gated to the registry).

Deliberately still manual:

- **Approving contract deploys:** a CI deploy mints a fresh, empty contract at
  a new address and moves no state by itself. Approve or reject under the run's
  **Review deployments** prompt; rejecting skips the contract jobs and the rest
  of the pipeline continues on the next push. Replacing a live contract is a
  migration, not a deploy: see [Contract upgrades and refunds](#contract-upgrades-and-refunds).

One-time setup on a new machine/repo: `scripts/ci-setup.sh` (SSH deploy key,
repo secrets/vars, the `contract-deploy` environment), then set
`DEPLOYER_PRIVATE_KEY` on that environment. The local `scripts/hooks/pre-push`
site-deploy hook predates this pipeline and is now redundant; disable it with
`git config --unset core.hooksPath` if you don't want pushes deploying the site
twice.

## Development

- `npm test` runs the supervisor/contract test suite (`test/*.test.mjs`).
- `npm install` also points `core.hooksPath` at `.githooks/`: the pre-commit and pre-push hooks refuse cryptocurrency private keys (Ethereum/Bitcoin hex, WIF, xprv, BIP39 seed phrases, keystore JSON) and, when [gitleaks](https://github.com/gitleaks/gitleaks) is on your PATH, provider tokens too. GitHub's own push protection never sees a raw wallet key, so the hook is the real block; `.github/workflows/secret-scan.yml` is the backstop. A confirmed false positive is bypassed with `--no-verify`.
- `npm run build:site` bundles the site into `site/dist/` (Tailwind + esbuild + build-time component prerender). `site/` itself is valid unbundled ES modules; serve it raw for dev, or `npm run watch:site` for CSS. Site URLs are extensionless (`/apps`, `/dashboard`): `site/_redirects` rewrites them on the DNSLink/subdomain IPFS gateway, and the router always fetches the real `.html` files, so soft navigation works on any dumb static server; only a HARD reload of a pretty URL needs rewrite support (use `npx serve site`, or just hit the `.html` path; the router re-prettifies the bar).
- `site/deploy.sh` builds and publishes the site to the box and IPFS (the IPNS gateway caches ~5 min). CI does this automatically on push.

## Documentation & support

- App developers: the guide and API reference live on the site at https://enclave.host/develop
- Coding agents: MCP server at `https://mcp.enclave.host` (Streamable HTTP) exposing the full platform surface as tools; state changes come back as unsigned Base transactions, keys stay with the agent (`claude mcp add --transport http enclave https://mcp.enclave.host`)

## License

Enclave is commercial, proprietary software: **source-available, not open
source**. The source is published so anyone can audit it and verify that the
running enclave images match this repo — see [LICENSE](LICENSE) for exactly what that permits (reading, auditing, local
verification builds, and using the CLI against the hosted service) and what it
doesn't (production use, redistribution, or running your own service from it).
Third-party components (`site/vendor/`, upstream patches, build-time
dependencies) remain under their own licenses — attribution and license
copies for everything distributed with the built artifacts live in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) (regenerate with
`node scripts/build-notices.mjs` after dependency changes).
