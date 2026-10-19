# Cold host runtime setup

A host with no previous Enclave runtime, guest cache or host `/boot` kernel can
install a caller-pinned CPU release and start a per-app guest manager from it.
Nothing in this path registers the host, admits it, or authorizes a deployment.
The owner's chain commitment, the guest's own checks and the client's attestation
policy still decide whether anything runs or is trusted.

## Trust and capacity prerequisites

These are the operator's explicit choices. No Enclave service supplies them.

| Input | Where it comes from |
| --- | --- |
| Release pin | A 64-hex domain release ID the operator reviewed (for example by rebuilding with `isolation/m4/domain-release.sh`). The pin is the trust decision; the download source is not. |
| Firmware approval | `isolation/m4/verifying-firmware.txt` in the operator's own checkout. A release whose `firmware.fd` is not listed there is refused at download, build and launch. |
| Verifier code | The same checkout's `isolation/` tree: `m4/release-manifest.py`, the image builder and launcher, and the `m2/client.mjs` judge guestd runs on every guest. |
| Chip collateral | `-vcek` (this chip's VCEK, DER), `-chain` (AMD chain; the repository fixture by default) and `-min-tcb` (the operator's TCB floor). Guestd refuses to start without all three. |
| Component sources | `-gateway`: a JSON array of one to eight HTTP(S) gateway origins. Every block is verified against its CID; the list decides availability only. |
| Pool budget | `-guest-mem-mib` and `-guest-cpus` together (otherwise every create is refused), and `-guest-host-floor-mib` for a live memory floor. |
| Pairing key | `guestd -gen-key FILE` once. The same private file is given to this host's supervisor as `GUESTD_KEY_FILE`; it is never published. |

Host software: an SEV-SNP capable kernel and KVM, QEMU with `sev-snp-guest`, a
systemd user manager (`systemd-run --user`), vhost-vsock, Go (guestd builds
`m2/fwd` and the bundle tool), Python 3, Node, and `sev-snp-measure` at
`~/.local/bin/sev-snp-measure`. The host's `/boot` kernel, `/lib/modules`, an
installed `wasmtime` and the distro OVMF are **not** used in this mode.

## 1. Download the release

```sh
node scripts/network/fetch-runtime.mjs --release-id <64-hex-release> \
  --out /srv/enclave/release-<id> \
  --artifact-gateways http://<provider-a>:8189/ipfs,http://<provider-b>:8189/ipfs
```

The output directory must not exist; an existing path is refused before any
request and is never modified or removed. The manifest is fetched by the pin's
raw CID and checked for canonical form, paths and size limits; every file is
streamed and checked against its committed digest and size. A failed or
substituting source permits the next one. The release's firmware must be listed
in the local `verifying-firmware.txt`, and the finished tree must pass
`release-manifest.py verify --expect <pin>`, the same verifier every pinned build
and launch runs. Any failure removes the new directory after active writers
settle. Source gateways here include the `/ipfs` path.

## 2. Start the manager from that release

```sh
GUESTD_ENABLE=1 guestd -isolation <checkout>/isolation -root /srv/enclave/guests \
  -cpu-release /srv/enclave/release-<id> -isolation-release <64-hex-release> \
  -gateway '["http://<provider-a>:8189","http://<provider-b>:8189"]' \
  -release -direct-bootstrap -auth-key /srv/enclave/pair.key \
  -guest-mem-mib 2048 -guest-cpus 1 -guest-host-floor-mib 16384 \
  -vcek /srv/enclave/vcek.der -min-tcb /srv/enclave/min-tcb.json
```

Component gateways are origins: the fetcher appends `/ipfs/<cid>`. `-cpu-release`:

- requires exactly one `-isolation-release` pin and an absolute directory, and
  verifies the complete release against it before anything else starts;
- takes kernel, firmware, command line and image template only from that release,
  and refuses `-ovmf`, `-cpu-template`, `-legacy-isolation*` and every `-shield-*`
  flag rather than letting one silently win;
- requires an explicit `-gateway` JSON list, so a cold host never falls back to
  the Enclave-operated default component gateway by omission;
- refuses inherited `DOMAIN_RELEASE_*`, `OVMF_OVERRIDE`, `KERNEL_HASHES`,
  `APP_IMAGE_TEMPLATE`, `SHIELDED_*` and `BUNDLETOOL`, any of which would change
  a build or boot input the pin is meant to fix;
- takes the RuntimeID and SET/mem64 capabilities from the release template, with
  no host `wasmtime` or capability probe.

Every image build (`m4/build-app-guest.sh`) and every launch
(`m2/run-domain.sh start`) re-verifies the whole release against the same pin,
rechecks the firmware approval and refuses firmware or kernel-hash overrides, a
plain-KVM launch and a Shield image. The command line is passed literally. A
release changed after guestd started is therefore refused rather than booted.
Stopping a guest does not read the release, so removing or losing it never
strands a running guest.

On a host that already runs another guestd, give this one its own
`-instance-prefix` (its startup sweep stops unadopted guests under its own
prefix), its own `-root` and `-listen`, and separate vsock ports
(`-bootstrap-port`, `-egress-port`, `-custody-auth-port`).

## 3. Owner startup package sources

The host's supervisor, not guestd, fetches the owner-committed startup package
and checks its hash, deployment, owner, app and RuntimeID scope before claiming.
Select sources with `GUEST_BOOTSTRAP_STORAGE_PLAN_FILE` (the storage plan
described in [decentralized-architecture.md](../design/decentralized-architecture.md#startup-package-storage-without-one-required-backend))
or `GUEST_BOOTSTRAP_GATEWAYS` (comma-separated, including `/ipfs`; not both).
Without either, the supervisor uses `https://ipfs.io/ipfs` and
`https://dweb.link/ipfs`, which are not Enclave-operated but are also not the
operator's own choice. The supervisor reaches guestd with
`ISOLATION_BACKEND=snp-guest-per-app`, `VMMGR_URL` and `GUESTD_KEY_FILE`, and
creates the guest with the exact package bytes; the guest re-checks the owner's
commitment on chain before starting the app.

## Evidence and what it does not show

On 2026-10-19 (`cold-host-proof`, outside the repository):

- release `5ef70f6a…9aad` and the AppID `167f4fae…b773` bundle were downloaded
  from a literal-IP EU replica after the first selected replica refused;
- the real image builder ran from that release in a network and mount namespace
  with no default route and `/boot`, `/lib/modules`, the previous runtime and
  bundle caches hidden, and predicted `caf11b48…a733a`, the measurement of the
  earlier real SNP boot;
- a fresh guestd started from the downloaded release with an empty store, stated
  RuntimeID `f548e338…c74f` and firmware `142589cc…`, and an authenticated
  `/prefetch` through explicit public gateways derived the exact owner AppID.

Not shown: network isolation covered the image build only, not the downloads or
the manager prefetch. The prefetch used a derivation record from the earlier
hardware run, not one this host derived from chain. No guest was booted from the
downloaded release, the manager was stopped, and no owner-startup request,
lease claim or chain write took place. The replicas are Enclave-operated. The
host's VCEK and TCB floor were already present; obtaining them on a host that
has never run a guest is not yet automated (`isolation/m2/vcek-prep.mjs` needs
a guest report). The tests above (`test/pinned-host-runtime.test.mjs`,
`isolation/m4/guestd/cpu_release_test.go`) drive the real launcher, builder and
fetcher with fixtures; they do not boot hardware.
