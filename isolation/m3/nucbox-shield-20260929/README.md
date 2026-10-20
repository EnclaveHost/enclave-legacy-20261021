# NucBox hosted Shield image (2026-09-29)

Source changes in this branch implement the V4 inference bundle, measured
model/share policy, UID-checked broker and Wasmtime 49 path. The CPU runtime
remains Wasmtime 48.0.1. The measured root manifest lists every regular file;
large model/runtime binaries remain in the release artifact store.

Image SHA-256: `a35d660f08a4df80ab35faa4cab4a4438fbffe9d553df83a8277a5eb30cf8bcd`.
VBS measurement: `0bd3c1e381ca9174d2b532f2f9914de4306d42acf50ebb9be9f537731de7d80e`.
RuntimeID: `297b6c2c0aee68c38ed612972afd11b12865e21ee39c01f4336e8721b3ef02f8`.

Assembly uses the prior patched OpenHCL paravisor and TPM kernel (no host-restored
report data). Compile monitor and shieldbroker with CGO_ENABLED=0 and domexec
with musl, then install in the measured root. Include `plat/shield-nucbox.enabled`,
`plat/rt-shield` from the qualified native Shield runtime and the pinned public
Qwen2.5-0.5B Q8 model. Keep runtime/front distinct UIDs and front sockets private.
Create the initrd with sorted NUL-delimited paths, cpio newc --owner=0:0
--reproducible, gzip -n -1. The IGVM builder uses paravisor base 1 GiB to
accommodate the embedded model, and proves deterministic output, debug twin,
and measurement changes after kernel/initrd/paravisor mutations.

Release artifacts and exact assembly script:
`/home/steven/enclave-bench/nucbox-shield-20260929/hosted-gpu-12g/{root,build.py,build.json}`.
The sibling control branch `codex/nucbox-shield-hosting-20260929` owns scheduler,
manager, bridge lifecycle, worker task, and certificate selection. Refer to
its `windows/vbslike/SHIELDED-GPU.md` for supported apps and deployment scope.

This image permits only the pinned model, 500–1000 GPU milli, at least four
vCPUs, 400 CPU percent in the guest policy and 8192 MiB. It does not permit
arbitrary host paths, user worker addresses, graphics passthrough, or secrets.
Successful hardware-bound app evidence is distinct from admission policy;
NucBox remains owner-only T0-hv with hostExcluded=false.

The measured guest budgets 12 GiB across the Radeon pool. A 500-milli app
reserves 6 GiB; the worker and control profile must use the same 12-GiB limit.
