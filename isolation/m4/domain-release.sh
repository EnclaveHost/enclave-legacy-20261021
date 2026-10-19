#!/bin/sh
# Create an M4a DOMAIN RELEASE: every input of a per-app guest's launch measurement except the app, pinned by one
# id (release-manifest.py). A verifier who holds the release and an app's bundle reconstructs the expected
# measurement without this host's binaries (expected-measurement.sh). Not published anywhere by this script.
#
# WHY. A measurement is a function of the SOURCE REVISION of everything in the image, not only of the app: on
# 2026-09-24 a change that no guest executes (catalog code linked into the front) moved every per-app measurement.
# So "recompute from the bundle" is only meaningful against pinned template bytes.
#
#   usage: domain-release.sh <new release dir>
set -e
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?usage: domain-release.sh <new release dir>}
out=$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$out")
[ ! -e "$out" ] || { echo "domain-release.sh: $out exists; a release is created once" >&2; exit 2; }
. "$here/../m1/domain.env"
fw=$(sha256sum "$OVMF" | cut -c1-64)
grep -qE "^$fw[[:space:]]" "$here/verifying-firmware.txt" || {
  echo "domain-release.sh: $OVMF is not pinned as VERIFYING in verifying-firmware.txt; refusing" >&2; exit 2; }
mkdir -p "$out"
"$here/app-image-template.sh" "$out/template"
cp "$KERNEL" "$out/kernel"
cp "$OVMF" "$out/firmware.fd"
python3 "$here/release-manifest.py" write "$out" --cmdline "$APPEND"
