#!/bin/sh
# M4a: build ONE SNP guest that runs exactly ONE app, from a canonical isolation/contract bundle.
#
# Why a guest per app rather than a domain per app (M3a's shape):
#   * app-vs-app separation becomes the SNP GUEST boundary - its own ASID, its own memory-encryption key, its
#     own vCPU state - instead of the guest kernel. That is the strongest separation this hardware offers.
#   * the app's identity is MEASURED. Without IGVM the launch carries kernel-hashes=on, so the initramfs is in
#     the launch measurement. M3b's IGVM path does NOT measure the guest image (isolation/m3/PLAN.md section
#     16), so `report_data[32:64]` there is the app ID as stated by code whose own identity is unestablished.
#     Here the bundle's bytes are inside the measured image, so the AppID's preimage is measured with it.
#
# The app ID is the contract's: sha256 of ALL the bundle's bytes. It is written to /app.sha256, which is
# exactly what the M2 front already puts in report_data[32:64] - so no front change, and the report names the
# AppID rather than a bare artifact hash. The bundle itself is copied in beside the artifact so a verifier's
# expected measurement covers the bytes the ID is taken over.
#
# usage: build-app-guest.sh <app.bundle> <out.cpio.gz> [vcpus=1]
# prints: app_id, the image size and the predicted launch measurement
set -e
here=$(cd "$(dirname "$0")" && pwd)
m2=$here/../m2
if [ -n "${DOMAIN_RELEASE_DIR:-}${DOMAIN_RELEASE_ID:-}" ]; then
  . "$here/pinned-domain-env.sh"
  [ -z "${SHIELDED_IMAGE_TEMPLATE:-}" ] || { echo "pinned CPU release cannot select a Shield template" >&2; exit 2; }
  APP_IMAGE_TEMPLATE=$DOMAIN_RELEASE_DIR/template
fi
bundle=$1; out=$2; vcpus=${3:-1}
[ -f "$bundle" ] && [ -n "$out" ] || { echo "usage: build-app-guest.sh <app.bundle> <out.cpio.gz> [vcpus]"; exit 2; }

d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
# The bundle tool is built from the contract package, so the ID here is the ID every backend computes. Built per
# run (the Go build cache makes that cheap): a cached tool outlived a contract change once and would have judged a
# new bundle by the old rules.
BUNDLETOOL=${BUNDLETOOL:-$d/bundletool}
[ -x "$BUNDLETOOL" ] || (cd "$here/../contract" && CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -ldflags='-s -w -buildid=' -o "$BUNDLETOOL" ./cmd/bundle)

app_id=$("$BUNDLETOOL" id "$bundle")
[ ${#app_id} = 64 ] || { echo "bundle id did not give 32 bytes of hex: $app_id"; exit 1; }

# template + one app: the same two steps a verifier reassembles from a published release (domain-release.sh)
inference=$("$BUNDLETOOL" inference "$bundle")
if [ -n "$inference" ]; then
  [ -n "${SHIELDED_IMAGE_TEMPLATE:-}" ] || { echo "no Shield inference template configured" >&2; exit 2; }
  cp -a "$SHIELDED_IMAGE_TEMPLATE" "$d/template"
elif [ -n "${APP_IMAGE_TEMPLATE:-}" ]; then
  cp -a "$APP_IMAGE_TEMPLATE" "$d/template"
else
  "$here/app-image-template.sh" "$d/template"
fi
"$here/assemble-app-image.sh" "$d/template" "$bundle" "$out" > /dev/null
if [ -z "${DOMAIN_RELEASE_DIR:-}" ]; then . "$here/../m1/domain.env"; fi
echo "app_guest $out: app_id $app_id, $(stat -c %s "$out") bytes, vcpus $vcpus"

# The launch digest this guest will have. vCPU count is part of the identity, so predict and boot with the
# same one. Because the bundle is in the image, two different apps give two DIFFERENT measurements - which is
# the property M4a needs and M3a deliberately does not have (there the app is not in the measurement).
~/.local/bin/sev-snp-measure --mode snp --vcpus "$vcpus" --vcpu-family 26 --vcpu-model 2 --vcpu-stepping 1 \
  --vmm-type QEMU --ovmf "$OVMF" --kernel "$KERNEL" --initrd "$out" --append "$APPEND" \
  | sed 's/^/predicted measurement: /'
