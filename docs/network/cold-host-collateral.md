# Cold-host SEV-SNP collateral

`guestd` will not start a guest without three files: the chip's VCEK, AMD's ASK/ARK
chain and the operator's minimum-TCB policy (see [cold-host.md](cold-host.md)).
`isolation/m2/vcek-prep.mjs` reads the chip ID and TCB from a guest's report, so
a host that has never run a guest could not obtain its VCEK.
`isolation/m2/host-collateral.mjs` closes that cycle: the operator **states**
the chip, and the tool installs collateral only if it verifies against that
statement.

No Enclave service, relay, Nan host, previous deployment, dynamic CA or opaque
proxy is involved. The only network party is AMD's Key Distribution Service
(KDS), and only when the operator asks for a fetch.

## What is checked before anything is installed

The checks reuse the repository's existing verifier code:

| Check | Code |
| --- | --- |
| VCEK → ASK → ARK signatures; ARK pinned by SHA-256 per product; AMD subject names; RSA-4096 ASK/ARK; every certificate valid at the stated time | `verifier/snp.mjs` `checkChain` / `parseAmdChain`, pins in `relay/snp-verify.mjs` `AMD_ARK_SHA256` |
| The ASK is not revoked by AMD's ARK-signed CRL, and the CRL is current | `verifier/snp.mjs` `checkCrl` (policy `required` by default; `stale-ok` or `none` only when chosen, and recorded) |
| The VCEK names exactly the stated chip (Turin: the first 8 bytes of CHIP_ID) and the stated TCB, and has an EC P-384 key | `relay/snp-verify.mjs` `vcekMatchesReport` |
| The stated TCB meets the **caller's** minimum-TCB policy | `relay/snp-verify.mjs` `checkMinTcb` |

- **The chain source.** By default the chain is the repository's pinned
  `test/fixtures/amd/<product>-cert_chain.pem`. A chain given with `--chain`
  or downloaded with `--fetch-chain` is used only if it verifies the same way
  and carries the **same ASK** as the repository copy. A different ASK needs
  `--allow-ask-rotation` after review.
- **The TCB floor.** It is never derived from the hardware. The stated TCB shows
  what the chip runs; the floor (`--min-tcb policy.json`, the same
  `{ "<product>": { <every field> } }` format guestd reads) is the operator's
  decision, based on AMD security bulletins.
- **A wrong statement.** A statement that is wrong in any field produces no
  installed collateral. If a statement matches its own VCEK but not the real
  hardware (a VCEK genuinely issued for another chip or TCB), the first guest's
  report fails verification later, because the verifier requires the report's
  CHIP_ID and REPORTED_TCB to equal the VCEK's.

## 1. Host inventory

Read-only steps, with no root needed:

```sh
node isolation/m2/host-collateral.mjs inventory
grep -m2 -E '^(cpu family|model)\s' /proc/cpuinfo
cat /sys/module/kvm_amd/parameters/sev_snp      # Y when the kernel enabled SNP
ls -l /dev/sev                                  # the SEV firmware device exists
```

`inventory` reads only `/proc/cpuinfo`, the `kvm_amd` `sev_snp` parameter and
whether `/dev/sev` exists. It reports the product line (from CPUID
family/model) and whether SNP is enabled.

### Firmware inventory: CHIP_ID and reported TCB

`isolation/m2/sev-inventory.c` is a small read-only helper (184 lines, no
dependencies beyond libc and the kernel UAPI header). Review it, then build it
on the host:

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror -static -o sev-inventory isolation/m2/sev-inventory.c
sudo ./sev-inventory > fw.json            # one JSON object; nothing else is printed or changed
node isolation/m2/host-collateral.mjs inventory --firmware --helper-output fw.json \
  --statement-out statement.json
```

**What the helper sends, and why it cannot change the firmware:**

- **Two read commands only.** It issues `SNP_PLATFORM_STATUS` (API version,
  state, `MASK_CHIP_ID`, `MASK_CHIP_KEY`, `VLEK_EN`, current and **reported**
  TCB), then `SEV_GET_ID2`: first a length probe, which the firmware answers
  with `INVALID_LEN` and the needed size, then the ID itself. Both are
  sent through `SEV_ISSUE_CMD` on `/dev/sev`. In Linux 7.2
  `drivers/crypto/ccp/sev-dev.c`, neither command changes firmware state.
- **Read-only open.** It opens `/dev/sev` `O_RDONLY`, so the kernel refuses
  every command that checks for write access. That is not enough on its own:
  `SNP_COMMIT` has no write check. The real guard is the helper's command
  allowlist; any other command aborts the program, and no other command
  identifier appears in the source.
- **No inputs.** The device path is fixed and there are no arguments. It never
  sends init, shutdown, update, key generation, import, export, commit or
  config commands.
- **Pinned to the reviewed UAPI.** Structures and command numbers come from
  `<linux/psp-sev.h>`. Compile-time assertions pin the values reviewed against
  `linux-api-headers` 7.2: `SEV_ISSUE_CMD` `0xc0105300`, `SEV_GET_ID2` 8,
  `SNP_PLATFORM_STATUS` 9, struct sizes 16, 12 and 32 bytes, and the reported
  TCB at offset 24. A header that differs fails to compile.
- **Bounds and errors:**
  - the ID length must be one of the two known formats (see "GET_ID2 ID
    formats" below), read into a 64-byte buffer; any other length exits 69;
  - a firmware answer of a different length than it asked for is refused;
  - `EINTR` is retried at most 3 times;
  - a busy or unresponsive PSP exits 75 with a clear message; it is never
    retried in a loop.
- **Exit codes:** 0 ok, 64 usage, 69 unavailable or unsupported (no
  `/dev/sev`, kernel older than 6.11, firmware API too old, an unsupported ID
  length), 70 firmware or protocol error, 75 busy, 77 permission.

### GET_ID2 ID formats (corrected after the first hardware run)

The first run on real hardware, a Turin host with firmware API 1.58 and SNP
initialized, ran on 2026-10-19 as an unprivileged member of the `kvm` group.
Only the two allowed commands were sent. The helper failed at `get_id2_length`
(exit 70): the firmware's length probe answered **8**, and the earlier helper
accepted only multiples of 64. That rule had assumed every product returns the
64-byte report CHIP_ID; no source said so.

The reported TCB was `0103020500000075` in report byte order (as a u64:
`0x7500000005020301`). No firmware state or guest was changed.

The corrected rule accepts exactly the formats primary sources give, and the
wrapper requires the one that matches the CPU's product line:

| Product | GET_ID2 answer | Sources |
| --- | --- | --- |
| Turin (family 1Ah) | 8 bytes: the KDS hardware ID | real Turin firmware 1.58 (probe length 8); virtee/snphost `vek_url` puts the raw GET_ID2 bytes in `/vcek/v1/Turin/<id>`; real Turin reports carry them as CHIP_ID[0:8] with CHIP_ID[8:64] zero |
| Milan, Genoa (family 19h) | 64 bytes: the CHIP_ID | the reports' CHIP_ID and KDS URLs |

- **Buffer.** virtee/sev's `Firmware::get_identifier` uses the same 64-byte
  buffer and returns exactly the length the kernel writes back. Linux
  `sev_ioctl_do_get_id2` warns that software must not assume the length.
- **Exact hardware ID.** The Turin ID is kept exactly: it becomes the
  statement's chip ID, the KDS path component and the collateral's `hwId`.
  It is never padded or reinterpreted.
- **Refused:** a Turin answer of 64 bytes, a Milan/Genoa answer of 8 bytes, and
  every other length (for example a 128-byte multi-socket answer).
- **No socket choice.** The `--socket` option was removed. Which socket signs
  guest reports is not something the helper may guess. On such hosts, state
  the chip by hand after confirming it against a guest report.

Node does not need root. Run the helper as root and give its saved output to
`--helper-output`; `--helper /abs/path` runs it directly only when the caller
already has access. `inventory` without `--firmware` is unchanged.

**What the statement step refuses:**

- **Unsupported platforms:**
  - a non-AMD vendor;
  - an unknown product line;
  - processors that disagree;
  - `MASK_CHIP_KEY` (unsigned reports);
  - `MASK_CHIP_ID` (reports carry a zero CHIP_ID);
  - a loaded VLEK (this verifier requires VCEK-signed reports);
  - SNP not initialized (unless `--allow-uninitialized`, which is recorded);
  - an ID whose format does not match the product line (see the table above),
    including multi-socket answers.
- **Bad firmware values:**
  - a zero (masked) chip ID;
  - an all-zero TCB;
  - a reported TCB whose reserved bytes are nonzero for the product line that
    `/proc/cpuinfo` names (a mismatched product).

**What the statement is:**

- **An operator claim.** `statement.json` records the product, CHIP_ID, raw and
  decoded **reported** TCB, current TCB, KDS URL and firmware facts. It remains
  a claim until `prepare --statement statement.json` verifies the AMD VCEK
  chain against it.
- **No floor.** The floor still comes only from `--min-tcb`.

**Fallback.** On a host where the helper cannot be used, the statement can
still be given by hand (`--product`, `--chip-id`, `--tcb`) or as a canonical
KDS URL from another reviewed tool.

Use the **reported** TCB. Guest reports carry `REPORTED_TCB`, and the VCEK must
match that TCB, not a newer committed version. A KDS URL printed by such a tool
can be given unchanged as `--kds-url`. It is accepted only in exact canonical
form: product, hardware ID and each SPL parameter must be exactly what the
verifier would request.

## 2. Prepare the collateral

All in one step: state the chip, choose the floor, fetch from KDS, and install
into a new directory.

```sh
node isolation/m2/host-collateral.mjs prepare \
  --product Turin --chip-id <16-hex Turin hardware ID, e.g. fa11afcf54ae9c53> \
  --tcb fmc=1,bootloader=3,tee=2,snp=5,microcode=117 \
  --min-tcb /srv/enclave/policy/min-tcb.json \
  --fetch-vcek --fetch-crl --out /srv/enclave/collateral-<date>
```

Offline, with files fetched or carried elsewhere (every check still applies):

```sh
node isolation/m2/host-collateral.mjs prepare --kds-url '<canonical KDS VCEK URL>' \
  --min-tcb policy.json --vcek vcek.der --crl Turin-crl.der [--chain Turin-cert_chain.pem] \
  --out /srv/enclave/collateral-<date> [--at 2026-10-19T00:00:00Z]
```

**KDS fetches:**

- 10-second deadline per attempt, covering the whole answer, body included;
  at most 4 attempts.
- **Retries:** only on 429 or 5xx.
  - **Retry-After:** honored only when present and valid (delta-seconds or an
    HTTP-date). A missing or malformed header uses the backoff of 2, 4 then 8
    seconds, never an immediate retry. Each wait is capped at 30 seconds.
  - **Release:** every answer that is not read to completion is released
    **before** the attempt's timer is cleared and before any retry. That
    covers 429/5xx bodies, a final 404, an oversize declared or streamed
    body, and a body still streaming at the deadline. The request is aborted
    and the body stream cancelled. A body cut off by the deadline counts as a
    timeout, never as a short answer.
- A 404 ends the fetch.
- Byte caps, counted as the answer streams: VCEK 16 KiB, chain 32 KiB,
  CRL 256 KiB.
- Redirects are refused.

**Installation:**

- **Bounded local reads.** Operator files (VCEK, chain, CRL, floor, statement,
  helper output) are opened once. The type and size are checked on that
  descriptor (regular files only; a FIFO is refused without blocking), and at
  most limit + 1 bytes are read. A file that grows after the check is
  refused, never read past its limit.
- **New directory only.** `--out` must be absolute and must not exist. The
  check happens before any request, the directory is reserved with an
  exclusive `mkdir`, and nothing existing is ever overwritten.
- **Staged writes.** Files are written to `.staging`, fsynced, then renamed
  into place. `collateral.json` is renamed last; its presence marks a complete
  set.
- **Cleanup.** If installation fails, everything this run created is removed.
  Inputs are verified **before** the destination is created, so refused
  collateral leaves no directory behind.

**Installed files:**

- `vcek.der`;
- `cert_chain.pem` (the exact verified chain);
- `min-tcb.json` (canonical);
- `crl.der` (when one was checked);
- `collateral.json`.

`collateral.json` records:

- the stated product, hardware ID, CHIP_ID and reported TCB (fields and raw);
- the KDS URL;
- the floor and its hash;
- the VCEK hash, serial and validity;
- the chain hash, plus the ASK and ARK hashes;
- the CRL hash and window, or the explicit policy `none`;
- the checks performed;
- `checkedAt`.

It contains no host path, and with `--at` it is byte-for-byte reproducible from
the same inputs.

## 3. Start guestd with it

```sh
guestd ... -vcek /srv/enclave/collateral-<date>/vcek.der \
  -chain /srv/enclave/collateral-<date>/cert_chain.pem \
  -min-tcb /srv/enclave/collateral-<date>/min-tcb.json
```

A firmware update changes the reported TCB and so needs a new VCEK. Prepare a
new directory with the new statement, then point guestd at it. Old directories
are never modified.

## Limits and activation gates

- **What real hardware has verified (2026-10-19/20, one existing Turin host).**
  1. The corrected `sev-inventory` (source sha256 `e8913b98…607e`) ran
     unprivileged through the `kvm` group and exited 0. It returned firmware
     API 1.58, SNP initialized, 4 running guests, ID length 8, hardware ID
     `fa11afcf54ae9c53` and reported TCB `0103020500000075`.
  2. `prepare --statement` then fetched a **fresh** VCEK, chain and CRL from
     AMD KDS. The downloaded chain carried the repository's pinned ASK; the CRL
     policy was `required`.
  3. That collateral matched a guest report captured from one of the host's
     **existing** running guests, on chip, TCB, AMD chain and report
     signature, and met the operator's existing floor.

  Evidence is in `work/cold-hardware-review/` (`run-fixed.json`,
  `statement.json`, `fresh-collateral/`, `live-report-verification.json`).
- **What it did not verify.** This was an existing running host, not a cold
  boot:
  - no new guest was started from this collateral, and acquiring it did not
    use a guest report;
  - the floor is the prior operator policy, not a new advisory review;
  - no application measurement or TLS peer binding was judged.

  Still **pending**: on a host that has never run a guest, run the helper,
  prepare, start guestd with the new `-vcek`, `-chain` and `-min-tcb`, boot one
  guest, and confirm its attested verdict names the same hardware ID and TCB.
- **Firmware inventory history.** The first real run found the 8-byte Turin ID
  format (see above). The corrected helper is compiled, source-audited and
  mock-tested, and passed the real run described here.
- **Multi-socket hosts are unsupported** by the helper. Their ID answers are
  refused, and the chip must be stated by hand after it is confirmed against a
  guest report.
- **ASK rotation.** The equality check between a downloaded ASK and the
  repository ASK has no positive test: no second genuine AMD-signed ASK exists
  in the repository. A real rotation needs review, then `--allow-ask-rotation`
  or an updated repository chain.
- **CRL freshness** depends on the copy supplied or fetched. AMD's CRLs carry a
  `nextUpdate` of a few weeks, so offline bundles go stale and are refused under
  the default policy.
- **The floor is a policy decision.** The examples' values are the test
  fixtures' TCBs, not a recommendation.
