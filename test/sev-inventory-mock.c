// Test-only firmware stand-in for isolation/m2/sev-inventory.c, linked with -DSEV_INVENTORY_MOCK. It emulates what Linux
// 7.2 drivers/crypto/ccp/sev-dev.c does for the two commands the helper may send (sev_ioctl_do_snp_platform_status,
// sev_ioctl_do_get_id2: a length probe answered with INVALID_LEN and the needed length, then a copy of exactly that
// many bytes) and the errno/firmware-status pairs it returns. The scenario comes from SEV_MOCK. Any other ioctl request
// or command exits 99, which the tests treat as a failure. This simulates firmware; it proves nothing about hardware.
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/psp-sev.h>

// The real Genoa and Turin chips of test/fixtures/verifier (their KDS VCEKs are in the same directory).
static const char *GENOA_ID = "1af1aa6c1f56037a05849a59b8815cf909583f9ba9ef2f053218c437f33ba183e4e415b039b37f8205250ad15f8b88a0a3add9f4c081c0779a48ed2214378e44";
static const char *GENOA_TCB = "0a00000000001754";
static const char *TURIN_TCB = "0103020500000075";    /* also what the real Turin host reported on 2026-10-19 */
static const char *TURIN_ID = "fa11afcf54ae9c53";      /* the 8-byte Turin hardware ID GET_ID2 returns (real host: length 8) */
static const char *scenario(void) { const char *s = getenv("SEV_MOCK"); return s ? s : "ok-genoa"; }
static int is(const char *s) { return !strcmp(scenario(), s); }
static int calls = 0;
// Turin scenarios: "ok-turin*" and "turin-*"; their GET_ID2 answer is 8 bytes unless the scenario says otherwise.
static int turin(void) { return !strncmp(scenario(), "ok-turin", 8) || !strncmp(scenario(), "turin-", 6); }

static void unhex(const char *h, unsigned char *out, size_t n) { for (size_t i = 0; i < n; i++) { unsigned v; sscanf(h + 2 * i, "%2x", &v); out[i] = (unsigned char)v; } }
static uint64_t tcb(const char *h) { unsigned char b[8]; unhex(h, b, 8); uint64_t v = 0; for (int i = 7; i >= 0; i--) v = (v << 8) | b[i]; return v; }

int sev_open(void) {
  if (is("open-enoent")) { errno = ENOENT; return -1; }
  if (is("open-eacces")) { errno = EACCES; return -1; }
  return 3;
}

int sev_ioctl(int fd, unsigned long request, struct sev_issue_cmd *c) {
  calls++;
  if (fd != 3 || request != SEV_ISSUE_CMD || (c->cmd != SNP_PLATFORM_STATUS && c->cmd != SEV_GET_ID2)) {
    fprintf(stderr, "mock: forbidden request 0x%lx command %u\n", request, c->cmd);
    exit(99);
  }
  if (is("eintr-once") && calls == 1) { errno = EINTR; return -1; }
  if (c->cmd == SNP_PLATFORM_STATUS) {
    if (is("busy")) { errno = EBUSY; return -1; }
    if (is("not-snp")) { errno = EINVAL; return -1; }
    if (is("no-psp")) { errno = ENODEV; return -1; }
    if (is("fw-error")) { c->error = SEV_RET_INVALID_COMMAND; errno = EIO; return -1; }
    struct sev_user_data_snp_status *st = (struct sev_user_data_snp_status *)(uintptr_t)c->data;
    memset(st, 0, sizeof *st);
    st->api_major = 1; st->api_minor = 55; st->state = 1; st->is_rmp_initialized = 1; st->build_id = 21; st->guest_count = 0;
    const char *t = turin() ? TURIN_TCB : GENOA_TCB;
    st->current_tcb_version = tcb(t);
    st->reported_tcb_version = is("zero-tcb") ? 0 : tcb(t);
    if (is("lagging-tcb")) st->current_tcb_version = tcb("0a00000000001854");
    st->mask_chip_id = is("masked-chip"); st->mask_chip_key = is("masked-key"); st->vlek_en = is("vlek");
    c->error = is("status-success-error") ? SEV_RET_INVALID_COMMAND : 0;
    return 0;
  }
  // SEV_GET_ID2
  struct sev_user_data_get_id2 *g = (struct sev_user_data_get_id2 *)(uintptr_t)c->data;
  // Formats: Milan/Genoa answer 64 (the CHIP_ID); Turin answers 8 (its hardware ID), as the real host did. The
  // mismatch scenarios swap them; two-sockets/odd/huge are lengths no primary source defines for this helper.
  uint32_t need = is("two-sockets") ? 128 : is("odd-length") ? 48 : is("huge-length") ? 4096
                : is("turin-64") ? 64 : is("genoa-8") ? 8 : turin() ? 8 : 64;
  if (is("id-busy")) { errno = EBUSY; return -1; }
  if (is("old-api")) { errno = 524; return -1; }
  if (!g->address || !g->length) {
    if (is("probe-success-error")) { g->length = 64; c->error = SEV_RET_INVALID_COMMAND; return 0; }
    if (is("probe-success")) { g->length = 0; c->error = 0; return 0; }
    g->length = need; c->error = SEV_RET_INVALID_LEN; errno = EIO; return -1;
  }
  if (g->length < need) { g->length = need; c->error = SEV_RET_INVALID_LEN; errno = EIO; return -1; }
  unsigned char id[128];
  memset(id, 0, sizeof id);
  if (need > sizeof id) { fprintf(stderr, "mock: helper accepted an unsupported length %u\n", need); exit(99); }
  if (!is("zero-id") && !is("turin-zero-id")) {
    if (need == 8) unhex(turin() ? TURIN_ID : "1af1aa6c1f56037a", id, 8);
    else if (is("turin-64")) { unhex(TURIN_ID, id, 8); }       /* 8-byte ID padded to 64: a format no source gives */
    else unhex(GENOA_ID, id, 64);
  }
  memcpy((void *)(uintptr_t)g->address, id, need);
  g->length = is("truncated") ? 32 : is("turin-truncated") ? 4 : need;
  c->error = 0;
  return 0;
}
