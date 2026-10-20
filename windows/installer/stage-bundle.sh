#!/bin/bash
# stage-bundle.sh <commit> <outdir> -- the Linux half of the Windows host bundle (docs/design/windows-host-installer.md).
# From one pinned commit it builds what does not need Windows:
#   control/   the node (windows/node) and the isolation manager (windows/vbslike), plus every file their imports reach
#              (iterated until the import closure closes), the node's npm dependencies from its lockfile, and the Python
#              helpers; the repo LAYOUT is kept because the node imports ../../relay/* and ../vbslike/*
#   network/   the network agent (Enclave network) and its Windows helpers, built from source (network/build.mjs: esbuild
#              + Go); the directory keeps its historical name, which installed hosts and install-host.ps1 use
#   setup/     the tray's and the installer's sources (compiled on Windows by windows/installer/build-bundle.ps1), and the
#              hosting panel the tray shows (host-ui, shared with the Android app)
# and control-<c8>.tar.gz with MANIFEST-control-<c8>.txt (sha256 of every file). Deterministic: sorted names, mtime 0,
# owner 0, gzip -n. build-bundle.ps1 adds the Windows-only parts and makes the zip.
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: $0 <commit> <outdir>" >&2; exit 2; }
NC=$(git rev-parse --verify "$1^{commit}"); OUT=$(realpath -m "$2"); N8=${NC:0:8}
mkdir -p "$OUT"; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
C="$T/control"; mkdir -p "$C"

git archive --format=tar "$NC" windows/node windows/vbslike/manager windows/vbslike/datapath windows/vbslike/verify \
  relay/fixtures/tpm-roots.pem wasm/ipfs_fetch.py \
  contracts/EnclaveDeployments.abi.json contracts/EnclaveVerificationFees.abi.json | tar -x -C "$C"   # read by availability/host-acceptor.mjs (audit-jobs.mjs)
cp "$C/wasm/ipfs_fetch.py" "$C/windows/node/ipfs_fetch.py"          # fetch-cid.py imports it from its own directory
rm -rf "$C/windows/node/ops" "$C/windows/node/test-fixtures" "$C/windows/vbslike/manager/testdata"
find "$C" \( -name '*.test.mjs' -o -name '*.md' \) -delete

ROOTS="windows/node/agent.mjs windows/node/host.mjs windows/vbslike/manager/main.mjs"
closure() { node --input-type=module -e '
  import fs from "node:fs"; import path from "node:path";
  const root = process.argv[1]; const seen = new Set(); const todo = process.argv.slice(2);
  const re = /(?:import\s[^"'"'"'`]*?from\s*|import\s*\(\s*|export\s[^"'"'"'`]*?from\s*)["'"'"'`](\.{1,2}\/[^"'"'"'`]+)["'"'"'`]/g;
  const missing = [];
  while (todo.length) { const f = todo.pop(); if (seen.has(f)) continue; seen.add(f);
    let src; try { src = fs.readFileSync(path.join(root, f), "utf8"); } catch { missing.push(f); continue; }
    for (const m of src.matchAll(re)) { const t = path.normalize(path.join(path.dirname(f), m[1])); if (!seen.has(t)) todo.push(t); } }
  for (const f of missing) console.log(f);
  console.error(`import closure: ${seen.size} files, ${missing.length} missing`);' "$C" $ROOTS; }
for round in 1 2 3 4 5 6 7 8; do
  MISSING=$(closure); [ -z "$MISSING" ] && break
  for f in $MISSING; do
    git cat-file -e "$NC:$f" 2>/dev/null || { echo "MISSING $f: not in $N8 either, so the node cannot start" >&2; exit 1; }
    echo "closure: adding $f" >&2; git archive --format=tar "$NC" "$f" | tar -x -C "$C"
  done
done
[ -z "$(closure 2>/dev/null)" ] || { echo "the import closure did not close" >&2; exit 1; }

# the node's dependencies, exactly as its lockfile pins them (pure JS; no install scripts run)
(cd "$C/windows/node" && npm ci --omit=dev --ignore-scripts --no-audit --no-fund --silent)

# the privacy agent and the Enclave network's Windows helpers, from source at the same commit
W=$(mktemp -d); git archive --format=tar "$NC" | tar -x -C "$W"   # the whole tree: network's bundles reach relay/, isolation/, windows/
# network/build.mjs uses the repo's esbuild (a root devDependency): borrow this checkout's root node_modules
TOP=$(git rev-parse --show-toplevel)
[ -d "$TOP/node_modules/esbuild" ] || { echo "run 'npm ci' at the repo root first: network/build.mjs needs its esbuild" >&2; exit 1; }
ln -s "$(realpath "$TOP/node_modules")" "$W/node_modules"
(cd "$W/network" && npm ci --ignore-scripts --no-audit --no-fund --silent && node build.mjs "$W/dist" >/dev/null)
mkdir -p "$T/network"
for f in privacy-agent.mjs windows-circuit-worker.mjs enclave-wg.exe enclave-circuit-firewall.exe; do
  cp "$W/dist/$f" "$T/network/$f"
done
rm -rf "$W"

mkdir -p "$T/setup"; git archive --format=tar "$NC" windows/tray windows/installer host-ui | tar -x -C "$T/setup"

# Carry the full source identity inside the hashed archive; an eight-character filename is not provenance.
printf '{"format":"enclave-control-source/1","commit":"%s"}\n' "$NC" > "$T/control-source.json"
(cd "$T" && find . -type f | sort | sed 's|^\./||' | while read -r f; do printf '%s  %s\n' "$(sha256sum "$f" | cut -c1-64)" "$f"; done) > "$OUT/MANIFEST-control-$N8.txt"
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --format=gnu -C "$T" -cf - control network setup control-source.json | gzip -n -9 > "$OUT/control-$N8.tar.gz"
echo "commit $NC -> $OUT/control-$N8.tar.gz sha256 $(sha256sum "$OUT/control-$N8.tar.gz" | cut -c1-64) ($(wc -l < "$OUT/MANIFEST-control-$N8.txt") files, $(du -h "$OUT/control-$N8.tar.gz" | cut -f1))"
