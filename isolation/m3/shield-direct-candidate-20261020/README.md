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

The build was prepared in `work/shield-direct-build-0ed5a8ba` in the coordinator
workspace. The manifest hashes its compile, packaging and image assembly
scripts. Those scripts still depend on the local pinned artifact inventory;
a portable, independently retrievable build-input bundle remains required.

Before activation: validate separate legacy/direct/GPU selection; boot a fresh
hardware partition; test volatile report input across VMGS reuse; verify the
real package and custody transports; exercise public, owner-name and custody
startup and failure cleanup; obtain the separate custodian measurement approval.
No production image pointer or custodian policy was changed by this build.
