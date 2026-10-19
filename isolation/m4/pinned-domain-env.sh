# Sourced by the builder and launcher, whose `here` is an isolation/mN directory.
# A release supplies every measured boot input, including its guest modules.
# No host kernel, host module tree or installed wasmtime is needed in this mode.
# The release is verified in full against its pin on every build and every launch,
# so a release changed after an earlier verification is refused, not booted.
[ -n "${DOMAIN_RELEASE_DIR:-}" ] && [ -n "${DOMAIN_RELEASE_ID:-}" ] || {
  echo "pinned domain needs a release directory and explicit release id" >&2; exit 2;
}
case "$DOMAIN_RELEASE_DIR" in /*) ;; *) echo "release directory must be absolute" >&2; exit 2;; esac
[ -z "${OVMF_OVERRIDE:-}" ] && [ "${KERNEL_HASHES:-on}" = on ] || {
  echo "pinned domain refuses firmware or kernel-hash overrides" >&2; exit 2;
}
APPEND=$(python3 "$here/../m4/release-manifest.py" field "$DOMAIN_RELEASE_DIR" cmdline --expect "$DOMAIN_RELEASE_ID") || exit 1
OVMF=$DOMAIN_RELEASE_DIR/firmware.fd
KERNEL=$DOMAIN_RELEASE_DIR/kernel
# The manifest verifier proves the tree is exactly what the pin lists; a pin that
# lists no kernel or firmware is not a bootable CPU release.
[ -f "$KERNEL" ] && [ ! -L "$KERNEL" ] && [ -f "$OVMF" ] && [ ! -L "$OVMF" ] || {
  echo "pinned release has no regular kernel and firmware" >&2; exit 1;
}
_release_fw=$(sha256sum < "$OVMF" | cut -c1-64)
case "$_release_fw" in *[!0-9a-f]*) _release_fw= ;; esac
[ ${#_release_fw} = 64 ] && grep -qE "^$_release_fw[[:space:]]" "$here/../m4/verifying-firmware.txt" || {
  echo "pinned domain firmware is not approved as verifying" >&2; exit 1;
}
