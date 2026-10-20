# Enclave Shield image: owner names and custody without Enclave services

This covers the two Shield-image paths that an independently operated Windows host needs beyond owner-committed startup
([independent-windows.md](independent-windows.md)): **certificates for owner-committed names**, and **custody-v2
secrets released to the partition itself**.

The tier is stated and never raised. A Shield partition is Hyper-V (`T0-hv`). Its evidence is the host's TPM and the
secure kernel's signature over the partition's own OpenHCL VBS report. The host's operator and hypervisor are trusted,
and every verdict says `tier hv-node`, `hostExcluded: false`. Nothing here is SEV-SNP operator exclusion, and nothing
here lets Shield evidence satisfy an SNP or default policy.

## Before anything else: the Shield image sources

The production Shield guest is the isolation/m3 monitor and the isolation/m2 front, booted as the VTL0 payload of the
measured OpenHCL IGVM. Its sealed-secret mode and its egress server were developed on branches that this repository's
squashed history does not contain:

- `front/shield_secrets.go`, `front/shield_egress.go`, `m2/shieldconfig`, `m2/cmd/shield-egress` and domexec's secret
  mode: on `origin/isolation/egress-blob-cache`;
- the report producer `m3/vtpmclient`: commit `d023349f` on `origin/codex/nucbox-vtpm-runtime-20260929`.

The production source at `1dad2bb50a8029c38842f8092fdd39f9987228be` is now integrated with the independent guest code:
sealed-secret startup, measured app config, native command ports, Shield broker, public-web egress, and the host egress
server. The existing SNP `public-https` behavior remains separate from Shield's configured-origin/public-web behavior.
This is source integration, not an activated image. The image measurement and host transport gates below remain open.

## The guest's own report (restored)

| File | What |
| --- | --- |
| `isolation/m3/vtpmclient/client.go`, `client_test.go` | Verbatim from production commit `d023349f`, identical on every branch that carries it. Writes the 64-byte guest input to NV `0x01400002`, waits past OpenHCL's refresh limit and reads the HCLA report at `0x01400001`. Refuses a report whose claims do not bind exactly that input. |
| `isolation/m3/monitor/main.go` | The production `-vbs-tpm` hook: on a Hyper-V partition whose image carries the TPM driver, every report the monitor serves carries `vbsVmReport` next to the launcher's signed document. |
| `isolation/m3/dominit.c` | The production hook: loads `/enclave_openhcl_tpm.ko` when the image carries it, and passes `-vbs-tpm`. |

The guest input is always `<the front's 32-byte binding> || <the AppID the monitor loaded>`:

- the front supplies the first half;
- the monitor writes the AppID from its own table;
- neither the app nor the host supplies either half.

The OpenHCL volatile-input patch (`isolation/m3/openhcl`) is still required before such a report proves current-guest
input; see the gates below.

## Feature 1: certificates for owner-committed names

### The guest: the Shield-direct front

`isolation/m2/front/shield_direct.go` is built only with `-tags 'bootstrapdirect shielddirect'`. It is a distinct
measured binary, so no flag, request or file can switch another build onto it. Legacy builds retain their existing startup; a direct build without Shield support refuses a Shield secret pipe
(`shield_direct_off.go`). The one hook in `front/main.go` runs only on an m3 domain with no SEV-SNP `HOST_DATA`.

The front uses the SNP direct guest's own code:

- `bootstrap.Reader`, through the measured RPC set and the host's egress;
- `AuthorizeWhenConfirmed` on the exact package bytes, for the AppID and RuntimeID this domain runs;
- `names.go`, `acme.go` and `certs.go`, unchanged.

So the names rules are exactly the SNP rules:

- a CSR is produced for the guest-held key only;
- a certificate is installed only if it chains to the measured WebPKI roots;
- the authorization is refreshed every minute;
- names are revoked on any agreed change of owner, runner, operator, appRef or envelope, or when the lease ends;
- after an RPC outage, names lapse `NameGrace` (10 minutes) after the last agreed read, and never later than the lease.

Three things differ, each no weaker on this tier:

- **The deployment id.** There is no `HOST_DATA`. The id comes from the package frame the host serves on vsock 9446,
  and must match the `<8 hex>.<zone>` name the launcher gave the domain (`/cert.name`). On SNP, `HOST_DATA` is also the
  host's choice. In both cases the chain check (`Authorize`) limits the host to deployments whose owner committed this
  exact app and runtime.
- **The tier.** The owner's envelope must say `isolation.require: "hyperv-partition-per-app"`, read from the agreed
  envelope by `bootstrap.Authorization.IsolationRequire` (a new file, `bootstrap/isolation.go`). AppID and RuntimeID
  can coincide across tiers, so an SNP-targeted or un-tiered package is refused here.
- **App start.** The package's config is measured into the AppID by the bundle. Public apps retain their existing
  startup; the front gates their names. A `custody-v2` app waits on the private secret pipe until the front verifies
  the package, obtains and checks the custody bundle, sets up egress, and revalidates the lease. Failure closes the pipe
  empty and ends the domain.

### The host: carrying the package

| File | What |
| --- | --- |
| `windows/vbslike/manager/package-transport.mjs` | Frames the exact bytes as `bootstrap.WritePackage` does (`enclb01\n`, then id, then u32 length, then raw; Go and JS pin one hex vector). Serves the frame on loopback through the same pinned `shielded-bridge` that egress uses, for this partition's vsock 9446 only. |
| `server.mjs` | Accepts `bootstrap` only on a manager that states its image is Shield-direct (`ENCLAVE_SHIELD_DIRECT=1`). It must be a public CPU spawn with no secrets, and the package must commit this spawn: the deployment, the manager's own derived AppID and the RuntimeID. The record shows `bootstrapSha256`; the bytes are never listed. |
| `wmi-launcher.mjs`, `main.mjs` | Package and egress hooks. A spawn carrying a package without both is refused before any VM is defined. The preflight reads the 9446 hv_sock registration and never writes it. |
| `windows/node/shield-startup.mjs`, `host.mjs`, `isolation-client.mjs` | The node passes the verified bytes to a Shield-direct manager. A package that commits names starts only on such a manager. On adoption, a partition holding an older package hash is retired. |

### The responder: an explicit, separate opt-in

`relay/dns-challenge-shield.mjs` makes the owner-selected DNS-01 responder accept a Shield guest's push. It is
enabled by `ATTESTED_SHIELD_POLICY`, which needs:

- `ATTESTED_SHIELD_PINS` (the pinned registry);
- `ATTESTED_SHIELD_RPCS` (two or more RPC hosts, read at one agreed block).

Without the policy, only SEV-SNP evidence is accepted, and `ATTESTED_MEASUREMENTS` is required as before. Each
adapter refuses the other's documents.

A Shield push must satisfy every SNP push rule. The shared `pushPreconditions` covers:

- fields, the time window and the value;
- the deployment and owner's alias;
- possession of the named key;
- a document whose nonce is this push.

In addition, the push must satisfy:

1. The document is the Hyper-V format (`hyperv-partition-domain/v1`, `T0-hv`) and carries a `vbsVmReport`.
2. The report verifies under the IDKS of a **host session this responder challenged itself**:
   - its own nonce and its own credential for the host's EK and AK;
   - the TPM quote and the replayed production boot log;
   - the registry entry for `keccak256(endpoint)`, and that operator's signature over the exchange, which names this
     responder's zone-bound id.
3. The report binds `Bind2(the named key, the push nonce, RuntimeID) || AppID`, on a (VBS launch digest, RuntimeID)
   pair and a platform the operator pinned (`verifyShieldAppPolicy`).

Host sessions use `POST /v1/shield-session/{challenge,attest}`. They live 10 minutes, one per host. The node renews
them for every responder its running packages name (`windows/node/shield-sessions.mjs`; agent.mjs runs it every
2 minutes).

The shared host-session code is `relay/shield-host-session.mjs`. The S4b market verifier now uses it too, unchanged in
behaviour.

## Feature 2: custody-v2 recipient evidence

### Owner-committed Shield rules

`custody/v2/shield-rules.mjs` defines a distinct rule format, written by the owner into the vault policy:

```json
{"format":"enclave-custody-shield-rules/1",
 "acceptTier":"windows-tpm-host/hv-node/T0-hv/hostExcluded:false",
 "appId":"<64 hex>",
 "images":[{"measurement":"<64 hex VBS launch digest>","runtimeId":"<64 hex>"}],
 "platforms":"attested",
 "minimumGuestSvn":0}
```

- `acceptTier` must be exactly that string: it is the owner's explicit acceptance of this tier.
- `custody/rules.mjs` is unchanged. It refuses this object, and it refuses the platform `shield` by name, so default and
  SNP rules never admit Shield evidence.
- The Shield parser refuses SNP rules.

### The evidence and the custodian

`custody/v2/shield-evidence.mjs`, enabled by `custodian.mjs`'s optional `shield` (the operator's choice):

- **The guest input.** It is `shieldReleaseInput || AppID`, where
  `shieldReleaseInput = sha256("enclave-custody-shield-v1\n" || v2.releaseBinding || owner)`.
  - `releaseBinding` already commits the chain, vault, deployment, revisions, committee, epoch, every challenge, the
    RuntimeID, the transport key and the recipient key R.
  - The owner added here is the ledger owner the custodian read.
  - `isolation/m2/custody/shield.go` computes the same bytes, pinned by a shared vector.
- **The signer.** A live host session this custodian challenged (`/v2/custody/shield-session/*`, through
  `shieldChallenge` and `shieldAttest`). At each release, the session must:
  - have been made for the lease-holding endpoint;
  - have been made by the operator that the release's **own** agreed chain read names;
  - come from a TPM/platform pair the owner admitted.
- **No nonce in the document.** The challenges are bound in the input, as on SNP.
- **The response.** The partials are HPKE-sealed to R, exactly as for SNP. The host carries public evidence and
  ciphertext only.
- **The SNP path.** It is unchanged: the SNP verifier receives exactly its previous arguments (a test pins this).

The node's session client (`shield-sessions.mjs`, `custodianTargets`) uses the same TPM round, addressed by each
custodian's committee key.

## What is NOT done, and why

- **The guest path is implemented and integration-tested, not hardware-activated.** `shield_direct_custody.go` obtains
  the real custody-v2 partials using a guest-created recipient key. Its monitor evidence binds the v2 release to the
  agreed ledger owner. It checks the measured config and deployment files, the decrypted bundle's config hash, and a
  fresh lease both after retrieval and after egress setup. Only then does it write the runtime's private pipe. Failure
  closes the pipe empty. The legacy relay release endpoint stays uninitialized in this build.
  - The Go integration fixture uses real encrypted threshold partials and a real bootstrap reader, with RPC and monitor
    evidence fixtures. It survives refusal by both Enclave-designated members and refuses changed config, a changed
    owner during egress setup, unsuitable monitor evidence, and an unavailable independent quorum.
  - A Windows partition still needs the custody-auth-v2 transport on vsock 9445, connected to the node's existing
    `windows/node/secrets.mjs custodyAuthorization` boundary. The manager's public-only package gate must be expanded
    only alongside that transport and the new measured image. Neither is activated yet.
- **The custodian daemon.** `custody/v2/daemon.mjs` is a measured SEV-SNP bundle. Installing the Shield adapter and its
  two routes there changes its measurement, so that is a committee `code-approve` step. It is not done here.
- **Committee discovery at the node.** Reading the vault's committee machines, to call `custodianTargets` for a running
  custody package, is not wired in agent.mjs yet.
- **The host-side egress server.** Its production source (`m2/cmd/shield-egress`) is restored and cross-compiles for
  Windows. Deployment and pinning of the new executable remain pending.
- **Owner tooling.** Public Shield package preparation is being integrated in the CLI and site. Shield custody rule
  creation, custody bundle hashes and canonical measured config still require end-to-end validation before release.
- **Image selection.** A Shield-direct front requires a package and cannot replace the shared legacy image for every
  spawn: doing so would break legacy apps and the host's readiness witness. Activation requires separately pinned
  images selected by the manager, with the selected RuntimeID checked at startup and adoption. A missing package must
  not downgrade a direct spawn to the legacy image.

## Tests (Linux, single job, no VM)

| Test | Covers |
| --- | --- |
| `go test ./isolation/m3/vtpmclient ./isolation/m3/monitor` | The restored producer and monitor. |
| `go test ./isolation/m2/bootstrap` | `IsolationRequire`. |
| `go test -tags 'bootstrapdirect shielddirect' ./isolation/m2/front` | The exact package, committed names started, refused for another tier, another deployment, a malformed frame, a chain refusal and missing custody channels; the frame vector. Direct custody tests additionally cover an independent threshold and startup failure cases. The default and `bootstrapdirect` builds also pass in full (SNP unchanged). |
| `go test ./isolation/m2/custody` | The `ShieldReleaseInput` vector. |
| `test/shield-dns-challenge.test.mjs` | Accepted only under the Shield policy with the responder's own host session. Refusals: forged or changed binding, wrong owner, runtime or image, another boot's report, a relabelled tier, app A's evidence for app B, a moved deployment, sessions from strangers, other zones or other roots. The SNP adapter refuses Shield documents and vice versa. The node client end to end over HTTP. The responder process with and without its pins. |
| `test/windows-shield-package-transport.test.mjs` | The frame vector, serving, the pinned bridge, the manager's gates and the launcher's refusal. |
| `test/shield-custody.test.mjs` | A real committee share and bundle through the real `decide()`: only the guest's R opens the owner's values. Refusals: no adapter, SNP or default rules, a missing acknowledgement, a forged or changed binding, wrong owner, runtime, image or app, another boot, a stranger's, another endpoint's or another root's session, a moved lease, a changed owner. SNP arguments unchanged. The node client to a custodian over HTTP. |

## Hardware gates (not run here; no automatic VM changes)

1. **Build and repin the image.** Build the Shield VTL0 image with the Shield-direct front (`-tags 'bootstrapdirect
   shielddirect'`), the restored vtpmclient, monitor and dominit hooks, the matching TPM driver
   (`isolation/m3/vtpm`, against the complete kernel build) and the OpenHCL volatile-input patch. Recompute its VBS
   launch digest and pin it in responders, custodians and client policies. Never reuse an old allowlist.
2. **OpenHCL volatile input.** A pre-write report must bind zeros after a VMGS carrying a nonzero prior input. A fresh
   complete write must then produce a valid report with the fresh input and the expected digest.
3. **The direct front on a real partition.** On the NucBox, it reads its package on vsock 9446 and its own RPC quorum
   through egress (9443, `shield-egress`). It refuses an SNP-targeted envelope and certifies nothing before it has
   authorized the package.
4. **A real ACME order.** It goes through an owner-run responder with `ATTESTED_SHIELD_POLICY`, using the node's
   responder session and the real fTPM IDKS. The guest installs a WebPKI chain on its own key, and the host's name proof
   (S4b `proveNameControl`) routes it.
5. **A custody release.** After the lineage merge and domexec gating: a Shield guest receives partials from a committee
   whose custodians installed the adapter (with `code-approve`), under owner-committed Shield rules. A committee
   without the adapter refuses.
