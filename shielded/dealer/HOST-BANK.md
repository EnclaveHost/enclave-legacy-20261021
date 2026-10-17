# Host pad bank: one attested pad service per Shield host

Status: design (2026-10-17, Steven: "each enclave shield host should be storing their own
banks regardless of apps"). Branch `shield/host-bank`. Nothing here is deployed.

## Why

Today every Shield app mints its own one-time pads inside its own guest (the pad spill,
PAD-SPILL.md): its refill threads compute `u = r.W` and seal the result to a bank file on the
host's disk under a key that lives only in that process. Measured on metal0 on 2026-10-17:

- **A relaunch throws the bank away.** The sealing key dies with the process, so a fresh
  guest re-mints its whole bank (192 GiB for Z-Image, ~15 min at ~400% CPU, 312 MB/s of model
  re-reads, 200 MB/s of bank writes). Each guestd or release change relaunches the guest.
- **Minting is unscheduled across apps.** Z-Image's bank refill pushed eyesoff's page latency
  from ~3.7 s to 6.8-11.6 s through shared disk I/O; per-guest cgroup weights did not stop it.
- **Every app pays the full minting cost separately**, even when two apps run the same model.

## The constraint that shapes everything

A pad is `(r, u)` with `u = r.W`. Whoever knows `r` for a row can unmask that row: the GPU
host sees `x + r`. So:

1. **The minter must be trusted by the consumer.** It cannot be host software (the host is
   exactly who Shield hides the data from). The pad service is an attested TEE, verified like
   an app guest.
2. **Each pad goes to exactly one consumer, once.** Two consumers holding the same `r` means
   one of them can unmask the other's traffic (with the host's help, which it has).
3. **A consumer must learn the masks of its own pads and nothing else.** The existing dealt
   pads (PLAN.md) derive every `r` from one per-consumer seed. Shared across consumers, a seed
   would let app A compute app B's masks. A shared bank therefore needs **per-pad keys**.

Pads depend only on the model (`W`), never on the app, so one bank per (host, model) serves
every app on that model.

## Design

### Parties

| Party | Trust | Role |
|---|---|---|
| Pad service (PS) | attested TEE on the host (SNP guest on metal0, VBS partition on a Windows host) | mints, seals, stores, issues pads; one per host |
| Host | untrusted | stores the sealed bank files, schedules the PS, carries traffic |
| Relay | platform authority (as today for secrets release and the pads ledger) | verifies the PS's attestation and certifies its delivery key; keeps the rollback-proof ledger per bank |
| Consumer | the app's engine in its own TEE | verifies the PS certificate, opens its pads, uses each once |

### Per-pad keys

The PS generates a bank secret `B` per (host, model, epoch) inside the TEE. For pad cell
`(g, i)` (group ordinal `g` of the model's canonical group manifest, index `i`):

    cellkey(g, i) = ChaCha20(B, counter = (g << 48) | (i << 24))[0:32]     (a PRF output)
    r(g, i)       = ChaCha20(cellkey(g, i), block counter 0..) reduced to [0, M)   (as maskbank_issue)
    u(g, i)       = r(g, i) . W_g  (mod M, balanced)

A consumer receives `cellkey(g, i)` (32 bytes) with `u(g, i)` for each of its cells. Knowing
any set of cell keys reveals neither `B` nor any other cell's key (PRF security). The `r`
expansion and its reduction are exactly today's, keyed per cell instead of per seed.

### The bank on disk

The PS stores cells as `AEAD(K_store, nonce = (g, i), cellkey || u)` in per-model bank files
on host storage. `K_store` must survive PS restarts and be unavailable to anything but the
same PS release on the same machine:

- metal0 (SNP): derived with `MSG_KEY_REQ` (VCEK root, mixed with the PS's measurement), so
  a different image or a different chip cannot derive it.
- Windows/VBS: the partition's vTPM seal to its PCR policy (to be confirmed with the VBS
  attestation path, VBS-ATTESTATION notes).

The host can delete, truncate or roll back bank files; it cannot read or forge cells.

### Single issuance, rollback-proof

Each bank has a relay ledger mark, like today's per-consumer pads ledger. The PS reserves
signed windows `[mark, mark + W)` before issuing from them and issues each index once, in
order, per group. After a restart it resumes at the relay's mark and abandons the unissued
rest of its last window (a few seconds of minting; never a reissue). A host that rolls the
bank files back cannot make the PS issue an index twice, because the PS never issues below the
relay mark. The PS also records issued cells in its own sealed state (fast path), but the relay
mark is the authority.

### Delivery

1. The consumer's engine has an X25519 pad key in its attestation (as today's dealt consumers).
2. It asks the PS (via the host, which only carries ciphertext) for `n` rows of model `m`.
3. The PS issues the next `n` unissued indices for every group from its sealed bank (minting on
   the spot if the bank is short), and returns a shipment boxed to the consumer's pad key: per
   cell `cellkey || u`, ChaCha20-Poly1305, exactly the v2 cell format plus a 32-byte key prefix
   (format v4).
4. The shipment carries the PS's signature with its delivery key and the relay's certificate
   for that key (PS measurement, host, model digest, epoch). The consumer pins the relay key,
   checks the certificate, and refuses pads from anything else.

A request from a party that is not a real consumer only wastes pads (they are never reissued);
it cannot make the real consumer reuse them. Consumer tickets from the relay (deployment +
pad key) rate-limit that waste.

### Scheduling

The PS owns all minting on its host: one cgroup with a CPU quota and I/O limits sized to what
the host's other tenants leave free, minting only when no request is waiting, and per-model
bank targets (`target rows`, `low-water mark`). Minting stays CPU work inside the PS: the
host's GPU workers must never see `r` (the dealer's GPU path, SHIELDED_ZERO_PADS, sends `r` in
the clear and is only for a dealer-owned GPU).

### Consumers

The engine's dealt mode already imports shipments, keeps per-group cursors, refuses on
exhaustion and never mints (shielded-tee.c, `l->dealt`). Changes: derive `r` from each cell's
key (format v4) instead of a seed; fetch from the PS endpoint; verify the PS certificate. The
in-guest pad spill and refill minting go away for consumers of a host bank.

The PS issues against the consumer's horizon, never against its downloads. The bank client
prefetches whatever is listed inside its cache budget, so issuing more on each download drains
the bank into one consumer's cache (the first H2 run spent 64 rows on a 3-row consumer). The
client reports its horizon on each listing (`?seed_id=X&need=N&floor=F`; sources that only
store shipments ignore it) and the PS keeps that consumer `ahead` rows past `need`, with `need`
capped at `ahead` past what was already issued. Until H3's relay tickets and per-bank ledger, a
consumer can still raise its horizon on every poll; that wastes bank rows, never reuses them.

### Failure of the pad service (enclave-88, 2026-10-17)

One PS per host is a shared point of failure, so no consumer may depend on it being up:

- **Consumers keep a local reserve.** A consumer imports ahead of use (its ring plus a sealed
  in-guest buffer of `reserve rows`, sized to the app's largest burst: one 512px Z-Image image,
  a few thousand prompt tokens for eyesoff). A PS crash, preemption or update leaves every
  consumer serving from what it holds; it re-fetches when the PS returns.
- **A consumer whose reserve and PS are both gone falls back to minting in its own guest**
  (today's path, slower), never to failing the request. This keeps today's code as the floor.
- **Test (H2):** kill the PS mid-load while a consumer runs a long request; the request
  completes from the reserve, the consumer logs the outage, re-fetches after the PS restarts,
  and no index is ever issued twice (checked against the ledger).

### Priority between consumers (enclave-88)

The PS mints and serves by consumer priority, not first come: a consumer below its reserve's
low-water mark is served before any refill for another, and per-host policy names the
protected consumers (eyesoff on metal0). Bank refill minting never runs while a protected
consumer has a request in flight, and its CPU/IO budget comes from what the host leaves after
the protected guests (cgroup limits on the PS unit, measured, not weights alone: on 2026-10-17
CPUWeight/IOWeight=20 on the Z-Image guest did not stop eyesoff's latency spikes).

### Migration (enclave-88)

- No consumer relaunches to move. A running guest keeps its per-app bank and in-guest minting;
  it moves to the PS at its next natural relaunch, on a release that supports both (per-app
  bank as the fallback above).
- eyesoff (512 GiB per-app spill, relaunch costs 5-33 min of eyesoff) moves last, in a quiet
  window agreed with enclave-88, with a rollback release that keeps today's per-app bank.
- Z-Image moves first.

### Reviews

Security review of the per-pad keys, the v4 format and the per-bank relay ledger by enclave-a8
or enclave-87 before H3. enclave-88 reviews uptime/rollout (REQUEST -> ACK for every step).

## What it does not change

The masking construction, the Freivalds checks, and the total minting work (three int8 MACs
per offloaded MAC). It moves that work into one scheduled place per host and keeps it.

## Phases

- **H1 (engine, CPU-testable):** cell keys: `cellkey` derivation, v4 cell format
  (`cellkey || u`), dealt-mode import deriving `r` per cell; selftest that a v4 import
  equals self-minted pads and that one cell's key does not open another.
- **H2 (pad service, host-testable):** a PS process on top of the persistent dealer
  (PERSISTENT-DEALER.md, `--jobs-stdin`): per-model banks, sealed store, issuance API,
  local ledger; consumer `shielded-run`/sd guest end to end on the host.
  Done (2026-10-17): `pad-service.mjs` + `pads-bank issue`, test/pad-service.test.mjs (single
  issuance across consumers and a restart, wrong key refused, engine import through the pad
  check). Still open in H2: the kill-the-PS-mid-request test, the persistent-dealer minting
  loop, and the consumer reserve + in-guest mint fallback.
- **H3 (trust):** PS attestation, relay certificate for its delivery key, per-bank relay
  ledger, consumer tickets; consumer pins and verifies.
- **H4 (metal0):** the PS as a measured SNP guest under guestd; Z-Image switches to it, then
  eyesoff. **H5:** the Windows/VBS host.

## Open questions

- K_store on VBS partitions (vTPM sealing available to a partition?).
- Bank sizing per model when several apps share it; priority between models.
- Whether the 27B's MTP head groups (draft rows) share the bank or use a separate manifest.
