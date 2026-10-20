#!/bin/bash
# publish-windows-host.sh -- turn a built Windows host release (windows/installer/build-bundle.ps1's output:
# enclave-host-<version>.zip, EnclaveSetup.exe, SHA256SUMS) into a release CHANNEL directory any static host can serve,
# sign it with the publisher's own key(s), and copy it to the mirrors named on the command line. No destination is
# built in: Nan is retired and no Enclave origin is assumed. Earlier versions stay.
#
#   scripts/publish-windows-host.sh <out-dir> --stage <channel-dir> [--channel stable] [--sign-key <p256.pem>]...
#                                   [--valid-days N] [--dest <dir | rsync-target>]... [--require-signed] [--no-legacy-latest]
#
#   --stage DIR      the channel directory to add this release to (kept between releases: it is the mirror's master copy).
#                    Its layout is what update-host.ps1 and release-channel.mjs read under a mirror URL:
#                      latest.signed.json                    the SIGNED pointer (release-channel.mjs envelope)
#                      release-<v>.signed.json               the same envelope, kept per version
#                      enclave-host-<v>.zip  EnclaveSetup-<v>.exe  manifest-<v>.json  files/<sha256>  SHA256SUMS-<v>
#                      latest.json  EnclaveSetup.exe         the LEGACY unsigned pointer and download name, for hosts that
#                                                            have no release policy yet (omit with --no-legacy-latest)
#                      host.ps1                              the one-line install (cli/host.ps1)
#   --sign-key PEM   a P-256 private key the PUBLISHER holds (repeat for several signers; a co-signer elsewhere can add
#                    theirs later: release-channel.mjs cosign). This script never creates a key; a host trusts only keys
#                    its operator pinned in its release policy, so this signature means nothing until someone pins it.
#   --dest D         a mirror: a local directory, or an rsync target (host:/path/windows/). Repeat for several. Release
#                    files go first, the pointers last, so a mirror never names files it does not have yet. Existing files
#                    are never overwritten (a published version is immutable; a different file under the same name stops
#                    the publish).
#   --require-signed refuse to publish without at least one --sign-key.
# Without --dest the channel is only staged: serve or upload it however you replicate artifacts.
set -euo pipefail
usage() { sed -n '2,32p' "$0" >&2; exit 2; }
OUT=${1:-}; [ -n "$OUT" ] && [ "${OUT#--}" = "$OUT" ] || usage; shift
STAGE= CHANNEL=stable VALID_DAYS=0 REQUIRE_SIGNED=0 LEGACY=1; KEYS=(); DESTS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --stage) STAGE=${2:?}; shift 2 ;;
    --channel) CHANNEL=${2:?}; shift 2 ;;
    --sign-key) KEYS+=("${2:?}"); shift 2 ;;
    --valid-days) VALID_DAYS=${2:?}; shift 2 ;;
    --dest) DESTS+=("${2:?}"); shift 2 ;;
    --require-signed) REQUIRE_SIGNED=1; shift ;;
    --no-legacy-latest) LEGACY=0; shift ;;
    *) usage ;;
  esac
done
[ -n "$STAGE" ] || { echo "--stage <channel-dir> is required: the directory this channel is built in" >&2; exit 2; }
[ ${#KEYS[@]} -gt 0 ] || [ $REQUIRE_SIGNED = 0 ] || { echo "--require-signed: no --sign-key given" >&2; exit 1; }
TOP=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
CH="node $TOP/windows/node/release-channel.mjs"
ZIP=$(ls "$OUT"/enclave-host-*.zip | sort | tail -1); SETUP="$OUT/EnclaveSetup.exe"
[ -f "$ZIP" ] && [ -f "$SETUP" ] || { echo "need enclave-host-*.zip and EnclaveSetup.exe in $OUT" >&2; exit 1; }
VERSION=$(basename "$ZIP" .zip | sed 's/^enclave-host-//')
SETUP_VERSIONED="EnclaveSetup-$VERSION.exe"
mkdir -p "$STAGE/files"; STAGE=$(cd "$STAGE" && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT

# put <src> at <stage>/<name>, or check it is already there byte for byte: a published file never changes
place() {
  local src=$1 dst="$STAGE/$2"
  if [ -e "$dst" ]; then cmp -s "$src" "$dst" || { echo "$2 is already in $STAGE with different content: a published version is immutable" >&2; exit 1; }
  else cp "$src" "$dst.tmp.$$" && mv "$dst.tmp.$$" "$dst"; fi
}
place "$ZIP" "$(basename "$ZIP")"
place "$SETUP" "$SETUP_VERSIONED"
ZSHA=$(sha256sum "$ZIP" | cut -c1-64); SSHA=$(sha256sum "$SETUP" | cut -c1-64)
printf '%s  %s\n%s  %s\n' "$ZSHA" "$(basename "$ZIP")" "$SSHA" "$SETUP_VERSIONED" > "$T/SHA256SUMS-$VERSION"
place "$T/SHA256SUMS-$VERSION" "SHA256SUMS-$VERSION"
# DELTA UPDATES (update-host.ps1): every file of the release by its sha256 under files/, and the release's manifest
python3 - "$ZIP" "$STAGE" "$VERSION" "$T/manifest-$VERSION.json" <<'PY'
import hashlib, json, os, sys, zipfile
zpath, stage, version, mout = sys.argv[1:5]
z = zipfile.ZipFile(zpath)
entries = {i.filename.replace("\\", "/"): i for i in z.infolist() if not i.is_dir()}
raw = z.read(entries["manifest.json"])
man = json.loads(raw.decode("utf-8-sig"))
if man.get("version") != version: sys.exit(f"the zip's manifest is for {man.get('version')}, not {version}")
sent = 0
for f in man["files"]:
    data = z.read(entries[f["path"]])
    if hashlib.sha256(data).hexdigest() != f["sha256"]: sys.exit(f"{f['path']} does not match its manifest")
    dst = os.path.join(stage, "files", f["sha256"])
    if os.path.exists(dst): continue
    open(dst + ".tmp", "wb").write(data); os.replace(dst + ".tmp", dst); sent += 1
open(mout, "wb").write(raw)
print(f"file store: {len(man['files'])} files, {sent} new")
PY
place "$T/manifest-$VERSION.json" "manifest-$VERSION.json"

# THE SIGNED POINTER: a statement of this version's three artifacts (names, sizes, sha256), signed by the given key(s).
# ONE statement per version, ever: hosts refuse a version for which two different signed statements exist, so a re-run
# (another mirror, another co-signer) reuses release-<v>.signed.json and only adds signatures to the same bytes.
KEYARGS=(); for k in "${KEYS[@]}"; do KEYARGS+=(--key "$k"); done
if [ -e "$STAGE/release-$VERSION.signed.json" ] && [ ${#KEYS[@]} -gt 0 ]; then
  $CH cosign --envelope "$STAGE/release-$VERSION.signed.json" "${KEYARGS[@]}" --out "$T/release.signed.json"
elif [ ${#KEYS[@]} -gt 0 ]; then
  $CH statement --channel "$CHANNEL" --version "$VERSION" --zip "$ZIP" --setup "$SETUP" --manifest "$STAGE/manifest-$VERSION.json" \
    --valid-days "$VALID_DAYS" --out "$T/statement.json"
  $CH sign --statement "$T/statement.json" "${KEYARGS[@]}" --out "$T/release.signed.json"
else
  echo "WARNING: no --sign-key: $VERSION is published UNSIGNED. Hosts with a release policy will not install it." >&2
fi
MSHA=$(sha256sum "$STAGE/manifest-$VERSION.json" | cut -c1-64)
cat > "$T/latest.json" <<JSON
{"version":"$VERSION","file":"$(basename "$ZIP")","sha256":"$ZSHA","bytes":$(stat -c%s "$ZIP"),"setup":"$SETUP_VERSIONED","setupSha256":"$SSHA","manifest":"manifest-$VERSION.json","manifestSha256":"$MSHA"}
JSON
cp "$TOP/cli/host.ps1" "$T/host.ps1"

# the pointers last, each by rename: a reader never sees one naming files that are not there yet
point() { cp "$1" "$STAGE/$2.tmp.$$" && mv "$STAGE/$2.tmp.$$" "$STAGE/$2"; }
point "$T/host.ps1" host.ps1
[ $LEGACY = 1 ] && { point "$SETUP" EnclaveSetup.exe; point "$T/latest.json" latest.json; }
[ ${#KEYS[@]} -gt 0 ] && { point "$T/release.signed.json" "release-$VERSION.signed.json"; point "$T/release.signed.json" latest.signed.json; }
find "$STAGE" -type d -exec chmod 0755 {} + ; find "$STAGE" -type f -exec chmod 0644 {} +
# the staged signed pointer must verify under exactly the keys that signed it before any mirror gets it
[ ${#KEYS[@]} -gt 0 ] && echo "signed pointer: $($CH verify --envelope "$STAGE/latest.signed.json" --channel "$CHANNEL" "${KEYARGS[@]}")"

# THE MIRRORS: release files (never overwriting), then the pointers
# (release-<v>.signed.json gains co-signatures over the same statement bytes, so it is replaced like a pointer)
POINTERS=("release-$VERSION.signed.json" latest.signed.json latest.json EnclaveSetup.exe host.ps1)
for D in "${DESTS[@]}"; do
  EXCL=(); for p in "${POINTERS[@]}"; do EXCL+=(--exclude "/$p"); done
  if [[ "$D" == *:* ]]; then
    command -v rsync >/dev/null || { echo "rsync is needed for $D" >&2; exit 1; }
    rsync -a --ignore-existing "${EXCL[@]}" "$STAGE/" "${D%/}/"
    for p in "${POINTERS[@]}"; do [ -e "$STAGE/$p" ] && rsync -a --delay-updates "$STAGE/$p" "${D%/}/$p"; done
  else
    mkdir -p "$D/files"
    (cd "$STAGE" && find . -type f ! -name '*.tmp.*' | sed 's|^\./||') | while read -r f; do
      case " ${POINTERS[*]} " in *" $f "*) continue ;; esac
      if [ -e "$D/$f" ]; then cmp -s "$STAGE/$f" "$D/$f" || { echo "$D/$f differs from the release: not overwritten" >&2; exit 1; }
      else mkdir -p "$(dirname "$D/$f")"; cp "$STAGE/$f" "$D/$f.tmp.$$" && mv "$D/$f.tmp.$$" "$D/$f"; fi
    done
    for p in "${POINTERS[@]}"; do [ -e "$STAGE/$p" ] && { cp "$STAGE/$p" "$D/$p.tmp.$$" && mv "$D/$p.tmp.$$" "$D/$p"; }; done
  fi
  echo "mirrored to $D"
done
echo "published Enclave host $VERSION ($CHANNEL): zip $ZSHA, setup $SSHA, ${#KEYS[@]} signature(s), staged in $STAGE, ${#DESTS[@]} mirror(s)"
cat "$T/latest.json"
