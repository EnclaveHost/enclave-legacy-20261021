#!/bin/sh
# Start or stop one M2 app domain. A serving domain lives until its lease ends, so unlike M1's run
# script, `start` returns once the VMM is launched and `stop` ends it (recording the host's accounting
# first). The domain runs in its OWN transient cgroup with its resource share, as in M1.
#
# usage: run-domain.sh start <domain.cpio.gz> <snp|plain> <tag> <workdir> [vcpus=1] [memMiB=512] [cpuQuota%=100]
#        run-domain.sh stop <tag> <workdir>
#   snp   : T1, an SEV-SNP guest (host excluded from its memory; PSP report available)
#   plain : T0, the same image as an ordinary KVM guest (no confidentiality from the host, no report)
# start writes the guest console to <workdir>/<tag>.serial and prints a HOST line with the unit, the
# domain's vsock CID and the launch time.
set -e
here=$(cd "$(dirname "$0")" && pwd)
if [ "${1:-}" = start ]; then
  if [ -n "${DOMAIN_RELEASE_DIR:-}${DOMAIN_RELEASE_ID:-}" ]; then
    . "$here/../m4/pinned-domain-env.sh"
  else
    . "$here/../m1/domain.env"
  fi
fi
# A caller may point this LAUNCH at a different firmware without editing domain.env, which is how
# verify-firmware.sh tests whether a build actually verifies the SEV kernel hash table. domain.env stays the
# default so an ordinary run is unchanged.
#
# It changes the launch ONLY. build-domain.sh predicts a measurement with domain.env's OVMF, so a suite run with
# this variable set would predict against one firmware and launch another, and check 1 would fail for the wrong
# reason. To move a SUITE to another firmware, change domain.env. A pinned release (DOMAIN_RELEASE_DIR/ID,
# m4/pinned-domain-env.sh) supplies kernel, firmware and command line itself and refuses this override.
OVMF=${OVMF_OVERRIDE:-$OVMF}

# FW_DEBUGCON=1 captures the firmware's own DEBUG() output to <tag>.debugcon. It is NOT on the serial console:
# OVMF writes DEBUG() to I/O port 0x402 unless built with DEBUG_ON_SERIAL_PORT, so without this a DEBUG firmware
# looks as silent as a RELEASE one and its verdict - "Hash comparison failed for initrd" - is invisible.
#
# KERNEL_HASHES=off launches WITHOUT the SEV kernel hash table, which is how verify-firmware.sh asks whether a
# firmware refuses to boot when there is nothing to verify against. Default on, so an ordinary run is unchanged.
KERNEL_HASHES=${KERNEL_HASHES:-on}

# HOST_DATA=<64 lowercase hex> launches an snp domain with those 32 bytes as SEV-SNP HOST_DATA: the host's
# launch-time word, signed by the PSP into every report the guest ever gets, fixed for the guest's life, and NOT
# part of the launch measurement. The per-app manager (m4/guestd) puts the deployment id there, so a client can
# check which deployment it reached without the measurement becoming per-deployment. Unset = all zero, as before.
HOST_DATA=${HOST_DATA:-}
if [ -n "$HOST_DATA" ]; then
  printf '%s' "$HOST_DATA" | grep -qE '^[0-9a-f]{64}$' || { echo "run-domain.sh: HOST_DATA must be 64 lowercase hex" >&2; exit 2; }
  HD_OPT=",host-data=$(printf '%s' "$HOST_DATA" | xxd -r -p | base64 -w0)"
fi

cmd=$1; shift
case "$cmd" in
start)
  img=$1; mode=$2; tag=$3; W=$4; vcpus=${5:-1}; mem=${6:-512}; quota=${7:-100}
  case "$mode" in
    snp)   MACH="-machine q35,accel=kvm,confidential-guest-support=sev0,memory-backend=ram1
                  -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=$KERNEL_HASHES${HD_OPT:-}
                  -object memory-backend-memfd,id=ram1,size=${mem}M,share=true" ;;
    plain) [ -z "${DOMAIN_RELEASE_DIR:-}" ] || { echo "pinned SNP release cannot launch as plain KVM" >&2; exit 2; }
           MACH="-machine q35,accel=kvm"
           # The verifying firmware refuses to boot a guest with no kernel hash table, and a plain guest has no
           # SEV and therefore no table: an AmdSevX64 build meets that by refusing to load the kernel and falling
           # through to its boot manager (measured: "Failed to mount root securely"). T0 is the explicitly
           # untrusted tier, used for parity against T1, and no security claim rests on its firmware - so it
           # launches on the distro one. See m1/domain.env.
           OVMF=${OVMF_T0:-$OVMF} ;;
    *) echo "mode must be snp or plain"; exit 2 ;;
  esac
  # A vsock CID is global to the host: take one from a range nothing else here uses. GUEST_CID lets the caller choose
  # it (guestd does, so its ticket service and egress server know the guest before it boots; m4/guestd/release.go).
  # Host-side only: the CID is not part of the launch measurement.
  if [ -n "${GUEST_CID:-}" ]; then
    case "$GUEST_CID" in *[!0-9]*) echo "run-domain.sh: GUEST_CID must be a number" >&2; exit 2 ;; esac
    # 131072-196607 is guestd's own band (m4/guestd/release.go), above the 65536-131071 a launch without GUEST_CID
    # draws from at random, so the two never collide
    [ "$GUEST_CID" -ge 131072 ] && [ "$GUEST_CID" -lt 196608 ] || { echo "run-domain.sh: GUEST_CID must be in 131072-196607 (guestd's band)" >&2; exit 2; }
    cid=$GUEST_CID
  else
    cid=$(( 65536 + $(od -An -N2 -tu2 /dev/urandom) ))
  fi
  set --
  pin_shield=0
  if [ -f "$img.shield" ]; then
    # a pinned CPU release has no Shield template, so an image claiming Shield devices was not built from it
    [ -z "${DOMAIN_RELEASE_DIR:-}" ] || { echo "pinned CPU release cannot launch a Shield image" >&2; exit 2; }
    model=$(cat "$img.shield")
    case "$model" in qwen2.5-0.5b-q8-gguf|qwen3.8-27b-mtp-q4-vl-gguf) ;; *) echo "invalid Shield model" >&2; exit 2;; esac
    [ -n "${SHIELDED_SHM_DIR:-}" ] || { echo "missing Shield rings" >&2; exit 2; }
    case "$SHIELDED_SHM_DIR${SHIELDED_MODEL_FILE:-}" in *,*) echo "commas are forbidden in QEMU asset paths" >&2; exit 2;; esac
    for card in 0 1; do
      ring="$SHIELDED_SHM_DIR/card-$card"
      [ -f "$ring" ] && [ "$(stat -c %s "$ring")" = 67108864 ] || { echo "bad Shield ring" >&2; exit 2; }
      set -- "$@" -object "memory-backend-file,id=sh$card,mem-path=$ring,size=64M,share=on" -device "ivshmem-plain,memdev=sh$card,addr=$((5+card))"
    done
    if [ "$model" = qwen3.8-27b-mtp-q4-vl-gguf ]; then
      [ -f "${SHIELDED_MODEL_FILE:-}" ] || { echo "missing Shield model" >&2; exit 2; }
      set -- "$@" -drive "file=$SHIELDED_MODEL_FILE,format=raw,if=virtio,readonly=on,cache=none"
      # The pad spill (wasm/ggml-shielded/shielded-spill.h): a scratch disk per guest, the SECOND virtio disk (vdb,
      # pinned to a slot after the model's), that the measured engine fills with one-time pads while the app is idle.
      # Everything on it is sealed under keys that never leave the guest and die with it, so it is created empty
      # here and removed at stop; nothing on it outlives the guest. Opt-in by SHIELDED_PAD_BANK_DIR.
      if [ -n "${SHIELDED_PAD_BANK_DIR:-}" ]; then
        case "$tag" in ''|*[!0-9A-Za-z_-]*) echo "invalid tag for the pad bank" >&2; exit 2 ;; esac
        case "$SHIELDED_PAD_BANK_DIR" in *,*) echo "commas are forbidden in QEMU asset paths" >&2; exit 2 ;; esac
        gib=${SHIELDED_PAD_BANK_GIB:-192}
        case "$gib" in ''|*[!0-9]*) echo "SHIELDED_PAD_BANK_GIB must be a whole number" >&2; exit 2 ;; esac
        mkdir -p "$SHIELDED_PAD_BANK_DIR"
        # A guest that ended without a stop left its bank behind; its keys are gone, so the bytes are noise. Only
        # banks idle for 10 minutes whose guest unit is gone, so a guest starting beside this one keeps its own.
        find "$SHIELDED_PAD_BANK_DIR" -maxdepth 1 -name '*.padbank' -mmin +10 2>/dev/null | while read -r old; do
          t=$(basename "$old" .padbank)
          systemctl --user list-units --plain --no-legend "m2-$t-*" 2>/dev/null | grep -q . || rm -f "$old"
        done
        bank="$SHIELDED_PAD_BANK_DIR/$tag.padbank"
        rm -f "$bank"
        truncate -s "${gib}G" "$bank"
        # 4 KiB logical blocks: the engine aligns its slots to them, so no I/O is a partial host block (cache=none)
        set -- "$@" -drive "file=$bank,format=raw,if=none,id=padbank,cache=none" \
          -device "virtio-blk-pci,drive=padbank,addr=0x10,logical_block_size=4096,physical_block_size=4096"
      fi
      # Pause until critical vCPUs are placed on physical cores sharing an L3.
      qmp_dir=$(mktemp -d /tmp/enclave-shield-qmp.XXXXXX)
      trap 'rm -rf "$qmp_dir"' EXIT
      set -- "$@" -S -qmp "unix:$qmp_dir/qmp,server=on,wait=off"
      pin_shield=1
    fi
  fi
  unit="m2-$tag-$$"
  t0=$(date +%s%3N)
  # CPU domains have only the console and vsock. Shield additionally maps two
  # untrusted masked-data BARs and, for 27B, a public model block device whose
  # contents the measured loader copies and authenticates before execution.
  # shellcheck disable=SC2086
  systemd-run --user --unit="$unit" --collect -q \
    -p CPUQuota="${quota}%" -p MemoryMax="$((mem + 768))M" -p TasksMax=256 \
    qemu-system-x86_64 $MACH -cpu host -smp "$vcpus" -m "${mem}M" -bios "$OVMF" \
      -kernel "$KERNEL" -initrd "$(realpath "$img")" -append "$APPEND" \
      -device "vhost-vsock-pci,guest-cid=$cid" \
      "$@" -nodefaults -display none -serial "file:$W/$tag.serial" ${FW_DEBUGCON:+-debugcon "file:$W/$tag.debugcon" -global isa-debugcon.iobase=0x402} -no-reboot
  if [ "${pin_shield:-0}" = 1 ]; then
    if ! python3 "$here/pin-shield-cpus.py" --qmp "$qmp_dir/qmp" --vcpus "$vcpus" --out "$W/$tag.cpu-placement.json"; then
      systemctl --user stop "$unit"
      echo "Shield vCPU placement failed; guest stopped before app startup" >&2
      exit 1
    fi
  fi
  echo "HOST mode=$mode vcpus=$vcpus memMiB=$mem cpuQuota=${quota}% unit=$unit cid=$cid t0_ms=$t0"
  ;;
stop)
  tag=$1; W=$2
  unit=$(sed -n 's/.* unit=\([^ ]*\).*/\1/p' "$W/$tag.host" | head -1)
  if systemctl --user is-active -q "$unit"; then
    systemctl --user show "$unit" -p CPUUsageNSec -p MemoryPeak | sed 's/^/HOST /'
    systemctl --user stop "$unit"
    echo "HOST stopped unit=$unit"
  else
    echo "HOST ERROR unit=$unit was not running at stop (the domain ended early)"
  fi
  # the guest's pad spill, if it had one: noise without the guest's keys
  if [ -n "${SHIELDED_PAD_BANK_DIR:-}" ]; then
    case "$tag" in ''|*[!0-9A-Za-z_-]*) ;; *) rm -f "$SHIELDED_PAD_BANK_DIR/$tag.padbank" ;; esac
  fi
  ;;
*) echo "usage: run-domain.sh start|stop ..."; exit 2 ;;
esac
