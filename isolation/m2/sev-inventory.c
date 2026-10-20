// isolation/m2/sev-inventory.c - read-only AMD SEV-SNP host inventory for cold-host collateral
// (docs/network/cold-host-collateral.md). It asks the SEV firmware, through the Linux /dev/sev UAPI, for exactly two
// things and prints them as JSON: SNP_PLATFORM_STATUS (API version, state, mask flags, current and REPORTED TCB) and
// SEV_GET_ID2 (the CHIP_ID). Nothing else.
//
// Safety, by construction:
//   - The only commands this program can send are SNP_PLATFORM_STATUS and SEV_GET_ID2; issue() aborts on any other
//     value, and no other SEV/SNP command identifier appears in this file (test/host-collateral-inventory.test.mjs
//     checks the source). Neither command changes firmware state (Linux 7.2 drivers/crypto/ccp/sev-dev.c:
//     sev_ioctl_do_get_id2, sev_ioctl_do_snp_platform_status). The device is opened O_RDONLY, so the kernel also
//     refuses the commands that check FMODE_WRITE (FACTORY_RESET, PEK/PDH generation and import, SNP_SET_CONFIG,
//     SNP_VLEK_LOAD); SNP_COMMIT has no such check in the kernel, which is why the allowlist above is the real guard.
//   - The device path is fixed (/dev/sev); there are no arguments that select a device, command or buffer.
//   - The ID length the firmware asks for must be one of the two formats known from primary sources, read into a
//     64-byte buffer (as virtee/sev Firmware::get_identifier does); every other length is refused, never guessed:
//       8 bytes  - Turin (family 1Ah): the KDS hardware ID. Observed on real Turin firmware 1.58 (2026-10-19: probe
//                  length 8); virtee/snphost puts exactly these bytes in the KDS VCEK URL; Turin attestation reports
//                  carry them as CHIP_ID[0:8] with CHIP_ID[8:64] zero (test/fixtures/verifier turin reports).
//       64 bytes - Milan/Genoa (family 19h): the full CHIP_ID, as in their reports and KDS URLs.
//     A longer answer (for example 128 bytes from a multi-socket SEV API) is unsupported: which socket signs guest
//     reports is not something this helper may choose.
//   - EINTR is retried at most 3 times; a busy or unresponsive PSP is reported (exit 75), never retried in a loop.
// Exit codes: 0 ok, 64 usage, 69 unavailable/unsupported (including an unsupported ID length), 70 firmware or protocol
// error, 75 busy (retry later),
// 77 permission. Every outcome is one JSON object on stdout.
//
// Layout: the structures and command numbers come from <linux/psp-sev.h> (Linux UAPI; verified against
// linux-api-headers 7.2). The static assertions pin the values this program was reviewed against, so a header that
// differs fails to COMPILE instead of issuing a different command. Firmware semantics: AMD SEV-SNP Firmware ABI
// (56860), SNP_PLATFORM_STATUS and GET_ID; the kernel copies the firmware's status page into the UAPI struct.
//
// Build on the host (kernel headers with SNP host support, Linux 6.11 or later):
//   cc -std=c11 -O2 -Wall -Wextra -Werror -static -o sev-inventory isolation/m2/sev-inventory.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/psp-sev.h>

_Static_assert(SEV_ISSUE_CMD == 0xc0105300UL, "SEV_ISSUE_CMD differs from the reviewed UAPI");
_Static_assert(SEV_GET_ID2 == 8, "SEV_GET_ID2 differs from the reviewed UAPI");
_Static_assert(SNP_PLATFORM_STATUS == 9, "SNP_PLATFORM_STATUS differs from the reviewed UAPI");
_Static_assert(sizeof(struct sev_issue_cmd) == 16, "sev_issue_cmd layout");
_Static_assert(offsetof(struct sev_issue_cmd, data) == 4 && offsetof(struct sev_issue_cmd, error) == 12, "sev_issue_cmd layout");
_Static_assert(sizeof(struct sev_user_data_get_id2) == 12 && offsetof(struct sev_user_data_get_id2, length) == 8, "get_id2 layout");
_Static_assert(sizeof(struct sev_user_data_snp_status) == 32, "snp_status layout");
_Static_assert(offsetof(struct sev_user_data_snp_status, build_id) == 4 && offsetof(struct sev_user_data_snp_status, guest_count) == 12, "snp_status layout");
_Static_assert(offsetof(struct sev_user_data_snp_status, current_tcb_version) == 16, "snp_status layout");
_Static_assert(offsetof(struct sev_user_data_snp_status, reported_tcb_version) == 24, "snp_status layout");
_Static_assert(SEV_RET_INVALID_LEN == 4, "firmware status INVALID_LEN");

#define SEV_DEVICE "/dev/sev"
#define ID_BUFFER_BYTES 64       /* the largest supported format; the buffer is never larger than the answer allows */

#ifdef SEV_INVENTORY_MOCK
// test/sev-inventory-mock.c supplies these for the fixture harness; the real build has no way to reach them.
int sev_open(void);
int sev_ioctl(int fd, unsigned long request, struct sev_issue_cmd *cmd);
#else
static int sev_open(void) { return open(SEV_DEVICE, O_RDONLY | O_CLOEXEC | O_NOCTTY); }
static int sev_ioctl(int fd, unsigned long request, struct sev_issue_cmd *cmd) { return ioctl(fd, request, cmd); }
#endif

static const char *errno_name(int e) {
  switch (e) {
    case ENOENT: return "ENOENT"; case EACCES: return "EACCES"; case EPERM: return "EPERM"; case ENODEV: return "ENODEV";
    case ENXIO: return "ENXIO"; case EINVAL: return "EINVAL"; case EIO: return "EIO"; case EBUSY: return "EBUSY";
    case ETIMEDOUT: return "ETIMEDOUT"; case ENOMEM: return "ENOMEM"; case EFAULT: return "EFAULT"; case EINTR: return "EINTR";
    case ENOTTY: return "ENOTTY"; case 524: return "ENOTSUPP";
    default: return "other";
  }
}
static const char *fw_name(uint32_t code) {
  switch (code) {
    case SEV_RET_SUCCESS: return "SUCCESS"; case SEV_RET_INVALID_PLATFORM_STATE: return "INVALID_PLATFORM_STATE";
    case SEV_RET_INVALID_LEN: return "INVALID_LEN"; case SEV_RET_INACTIVE: return "INACTIVE";
    case SEV_RET_INVALID_ADDRESS: return "INVALID_ADDRESS"; case SEV_RET_INVALID_COMMAND: return "INVALID_COMMAND";
    case SEV_RET_UNSUPPORTED: return "UNSUPPORTED"; case SEV_RET_INVALID_PARAM: return "INVALID_PARAM";
    case SEV_RET_INVALID_PAGE_STATE: return "INVALID_PAGE_STATE"; case SEV_RET_RMP_INIT_REQUIRED: return "RMP_INIT_REQUIRED";
    default: return "other";
  }
}

static void hex(const unsigned char *b, size_t n) { for (size_t i = 0; i < n; i++) printf("%02x", b[i]); }
// TCB_VERSION is a little-endian u64; print its bytes in that order, the order an attestation report stores them.
static void tcb_hex(uint64_t v) { for (int i = 0; i < 8; i++) printf("%02x", (unsigned)((v >> (8 * i)) & 0xff)); }

static int fail(int code, const char *stage, int err, uint32_t fw, const char *message) {
  printf("{\"v\":1,\"tool\":\"enclave-sev-inventory\",\"error\":{\"stage\":\"%s\",\"errno\":%d,\"errno_name\":\"%s\",\"fw_error\":%u,"
         "\"fw_error_name\":\"%s\",\"message\":\"%s\"}}\n", stage, err, err ? errno_name(err) : "none", fw, fw_name(fw), message);
  return code;
}

// The ONLY path to the device. Any command other than the two read commands aborts the program.
static int issue(int fd, uint32_t command, void *data, uint32_t *fw_error) {
  if (command != SNP_PLATFORM_STATUS && command != SEV_GET_ID2) abort();
  struct sev_issue_cmd c;
  memset(&c, 0, sizeof c);
  c.cmd = command; c.data = (uint64_t)(uintptr_t)data;
  int r = -1, e = 0;
  for (int attempt = 0; attempt < 3; attempt++) {
    r = sev_ioctl(fd, SEV_ISSUE_CMD, &c); e = r < 0 ? errno : 0;
    if (!(r < 0 && e == EINTR)) break;
  }
  *fw_error = c.error;
  return r < 0 ? -e : 0;
}

// errno from a command -> exit code and an operator-readable cause
static int command_failure(const char *stage, int err, uint32_t fw) {
  switch (err) {
    case ENODEV: case ENXIO: return fail(69, stage, err, fw, "the SEV firmware is not available on this platform (no PSP SEV device)");
    case EINVAL: return fail(69, stage, err, fw, "the kernel does not accept this command (SNP host support needs Linux 6.11 or later)");
    case 524: return fail(69, stage, err, fw, "the SEV firmware API is too old for this command");
    case EBUSY: case ETIMEDOUT: return fail(75, stage, err, fw, "the SEV firmware is busy or unresponsive; retry later");
    case EPERM: case EACCES: return fail(77, stage, err, fw, "permission denied by the kernel");
    case EIO: return fail(70, stage, err, fw, "the SEV firmware refused the command");
    default: return fail(70, stage, err, fw, "the command failed");
  }
}

int main(int argc, char **argv) {
  if (argc > 1) {
    if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) {
      puts("usage: sev-inventory   (read-only: SNP_PLATFORM_STATUS and SEV_GET_ID2 on " SEV_DEVICE "; prints one JSON object)");
      return 0;
    }
    return fail(64, "usage", 0, 0, "sev-inventory takes no arguments");
  }
  int fd = sev_open();
  if (fd < 0) {
    int e = errno;
    if (e == ENOENT || e == ENODEV || e == ENXIO) return fail(69, "open", e, 0, SEV_DEVICE " does not exist: not an AMD SEV host, or the ccp SEV driver is not loaded");
    if (e == EACCES || e == EPERM) return fail(77, "open", e, 0, SEV_DEVICE " needs root (or the group the host grants it)");
    return fail(70, "open", e, 0, "cannot open " SEV_DEVICE);
  }

  struct sev_user_data_snp_status st;
  memset(&st, 0, sizeof st);
  uint32_t fw = 0;
  int r = issue(fd, SNP_PLATFORM_STATUS, &st, &fw);
  if (r < 0) { close(fd); return command_failure("snp_platform_status", -r, fw); }
  if (fw != SEV_RET_SUCCESS) { close(fd); return fail(70, "snp_platform_status", 0, fw, "the firmware reported an error with a successful ioctl"); }

  // GET_ID2: ask for the length first (no buffer); the firmware answers INVALID_LEN with the length it needs.
  struct sev_user_data_get_id2 probe;
  memset(&probe, 0, sizeof probe);
  r = issue(fd, SEV_GET_ID2, &probe, &fw);
  if (r < 0 && !(r == -EIO && fw == SEV_RET_INVALID_LEN)) { close(fd); return command_failure("get_id2_length", -r, fw); }
  if (r == 0 && fw != SEV_RET_SUCCESS) { close(fd); return fail(70, "get_id2_length", 0, fw, "the firmware reported an error with a successful ioctl"); }
  uint32_t need = probe.length;
  if (need != 8 && need != 64) {
    close(fd); return fail(69, "get_id2_length", 0, fw, "unsupported ID length: only 8 bytes (Turin hardware ID) or 64 bytes (Milan/Genoa CHIP_ID) are known formats; other lengths, including multi-socket answers, are refused rather than guessed");
  }
  unsigned char id[ID_BUFFER_BYTES];
  memset(id, 0, sizeof id);
  struct sev_user_data_get_id2 get;
  memset(&get, 0, sizeof get);
  get.address = (uint64_t)(uintptr_t)id; get.length = need;
  r = issue(fd, SEV_GET_ID2, &get, &fw);
  close(fd);
  if (r < 0) return command_failure("get_id2", -r, fw);
  if (fw != SEV_RET_SUCCESS) return fail(70, "get_id2", 0, fw, "the firmware reported an error with a successful ioctl");
  if (get.length != need) return fail(70, "get_id2", 0, fw, "the firmware wrote a different CHIP_ID length than it asked for");

  printf("{\"v\":1,\"tool\":\"enclave-sev-inventory\",\"uapi\":\"linux/psp-sev.h\",\"device\":\"" SEV_DEVICE "\",\"open\":\"O_RDONLY\","
         "\"commands\":[\"SNP_PLATFORM_STATUS\",\"SEV_GET_ID2\"],\"snp_status\":{\"api_major\":%u,\"api_minor\":%u,\"state\":%u,"
         "\"rmp_initialized\":%u,\"build_id\":%u,\"mask_chip_id\":%u,\"mask_chip_key\":%u,\"vlek_en\":%u,\"guest_count\":%u,\"current_tcb\":\"",
         st.api_major, st.api_minor, st.state, (unsigned)st.is_rmp_initialized, st.build_id, (unsigned)st.mask_chip_id,
         (unsigned)st.mask_chip_key, (unsigned)st.vlek_en, st.guest_count);
  tcb_hex(st.current_tcb_version);
  printf("\",\"reported_tcb\":\"");
  tcb_hex(st.reported_tcb_version);
  printf("\"},\"id_length\":%u,\"id\":\"", need);
  hex(id, need);
  printf("\"}\n");
  return fflush(stdout) == 0 ? 0 : 70;
}
