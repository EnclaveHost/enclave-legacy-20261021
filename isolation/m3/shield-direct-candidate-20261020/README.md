# Shield-direct guest candidate, 2026-10-20

Status: built, **not hardware validated or activated**. This is the CPU guest
that verifies owner startup packages and obtains custody-v2 releases itself.
It must be selected separately from the existing legacy and GPU images.

`candidate.json` records the committed guest source, every initrd file,
pinned kernel/OpenHCL/generator inputs, runtime identity and measurement tests.
Image SHA-256: `c7084346a908465404fdf6de332a76b3c2ca844101eb9e8071aa8a1468f197ec`.
VBS digest: `6a3135a9378688805a36905c5e0f1443bb65031014618f390a6e3d6e2d90b86a`.
RuntimeID: `297b6c2c0aee68c38ed612972afd11b12865e21ee39c01f4336e8721b3ef02f8`.
The runtime identity alone does not identify this image: legacy images can
use the same runtime. Admission must also pin the image hash and image role.

The initrd preserves the runtime, libraries and kernel modules from the
verified public-web baseline. Five executables were compiled from `0ed5a8ba`:
init, domexec, front, monitor and secretrun. Front uses both `bootstrapdirect`
and `shielddirect` tags. All five executables are static ELF binaries.
The C compiler, Go toolchain and file hashes are recorded in the manifest.

The assembly recipe first reproduces the pinned historical image and its twin,
then assembles this candidate twice. Both image and measurement bytes match.
A debug-enabled twin and six input mutations each change the measurement.
This proves assembly repeatability on one builder, not independent compiler
reproduction or actual guest security. The debug twin is a rejection fixture,
never a serving candidate.

A portable build-input archive now includes the public pinned artifacts, guest
source, required Go modules and relocatable build scripts. Rebuilding with the
bundled modules and relocated inputs produced this exact candidate with network
downloads disabled. `portable-build.json` records the 133,516,433-byte archive
and its SHA-256 `5bb131dea929d6efbe3bcaa2b3113f49b8cfeccc37a65527729091ecb67a1bef`.
The archive's INPUTS.json pins 781 files, and rebuild.sh refuses mismatched
compiled initrd or image bytes. The tested compiler/static-libc toolchain is
specified but not bundled; upstream firmware/runtime binaries were not rebuilt
from source. This is still one-builder reproduction; another operator's rebuild remains
unproven.

`publication.json` records public distribution of the candidate and portable
inputs. Each object has a UnixFS CID, raw-byte SHA-256 and CAR SHA-256. Four
existing providers serve both forms at `/ipfs/<CID>` and
`/ipfs/<CID>?format=car`. Fresh downloads from each provider's numeric address
verified every CAR block and reconstructed the exact original bytes, without
Nan, Enclave DNS or this workstation serving as the source. HTTP is transport
only: recipients must verify the published CID and pinned hashes.

The Windows host separately fetched the 77,056,796-byte candidate from a public
replica and verified its SHA-256 before staging it. No VM or image pointer was
changed. These are all existing Enclave-operated providers; this establishes
public retrieval and replica copies, not independent operator diversity.

Before activation: validate separate legacy/direct/GPU selection; boot a fresh
hardware partition; test volatile report input across VMGS reuse; verify the
real package and custody transports; exercise public, owner-name and custody
startup and failure cleanup; obtain the separate custodian measurement approval.
No production image pointer or custodian policy was changed by this build.
