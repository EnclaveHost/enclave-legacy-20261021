/* pads-bank: the pad service's issuance step (shielded/dealer/HOST-BANK.md).
 *
 *   PADS_BANK_SK=<64 hex>  pads-bank issue BANK_DIR BANK_ID SRC0 COUNT MODEL_DIGEST \
 *                              CONSUMER_PK CONSUMER_ID DST0 OUT
 *
 * Re-seals bank rows [SRC0, SRC0+COUNT) - format-4 shipments in BANK_DIR under BANK_ID, boxed to
 * the service's own key PADS_BANK_SK - into OUT, a format-4 shipment boxed to CONSUMER_PK under
 * CONSUMER_ID at its indices [DST0, DST0+COUNT). The service's caller keeps the bank cursor: each
 * bank row is issued once. Secrets come from the environment, never argv (other processes on the
 * host can read argv). Prints one JSON line; exit 0 only when OUT is published.
 */
#include "shielded-pads.h"
#include "shielded-tee.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(const char *what, int rc) { printf("{\"ok\":false,\"error\":\"%s\",\"rc\":%d}\n", what, rc); return 1; }

int main(int argc, char **argv) {
    if (argc != 11 || strcmp(argv[1], "issue")) {
        fprintf(stderr, "usage: PADS_BANK_SK=hex pads-bank issue BANK_DIR BANK_ID SRC0 COUNT MODEL_DIGEST CONSUMER_PK CONSUMER_ID DST0 OUT\n");
        return 2;
    }
    uint8_t sk[32], bank_id[16], digest[32], cpk[32], cid[16];
    const char *skh = getenv("PADS_BANK_SK");
    if (!skh || !sh_pads_hex2bin(skh, sk, 32)) return fail("PADS_BANK_SK is not 64 hex", SH_ERR_RANGE);
    if (!sh_pads_hex2bin(argv[3], bank_id, 16) || !sh_pads_hex2bin(argv[6], digest, 32) ||
        !sh_pads_hex2bin(argv[7], cpk, 32) || !sh_pads_hex2bin(argv[8], cid, 16)) return fail("bad hex argument", SH_ERR_RANGE);
    char *e1 = NULL, *e2 = NULL, *e3 = NULL;
    const unsigned long long src0 = strtoull(argv[4], &e1, 10), count = strtoull(argv[5], &e2, 10), dst0 = strtoull(argv[9], &e3, 10);
    if (!e1 || *e1 || !e2 || *e2 || !e3 || *e3 || !count) return fail("bad number", SH_ERR_RANGE);

    int err = 0;
    sh_pads_reader *bank = sh_pads_reader_open_keyed(argv[2], bank_id, sk, &err);
    memset(sk, 0, sizeof sk);
    if (!bank) return fail("bank unreadable", err);
    sh_pads_reader_require_digest(bank, digest);
    sh_pads_group groups[1024];
    const uint32_t n = sh_pads_reader_groups(bank, groups, 1024);
    if (!n || n >= 1024) { sh_pads_reader_close(bank); return fail("bank has no shipments", SH_ERR_EXHAUST); }
    int rc = sh_pads_reader_bind(bank, groups, n);
    if (rc != SH_OK) { sh_pads_reader_close(bank); return fail("bank group table", rc); }
    sh_pads_writer *w = sh_pads_writer_open_keyed(argv[10], digest, cid, groups, n, dst0, count, cpk, &err);
    if (!w) { sh_pads_reader_close(bank); return fail("cannot open the consumer shipment", err); }
    rc = sh_pads_reissue(bank, src0, w, dst0, count);
    const int crc = sh_pads_writer_close(w);     /* publishes only when every cell was written */
    sh_pads_reader_close(bank);
    if (rc != SH_OK) return fail(rc == SH_ERR_EXHAUST ? "bank rows not minted yet" : "reissue failed", rc);
    if (crc != SH_OK) return fail("publish failed", crc);
    printf("{\"ok\":true,\"groups\":%u,\"src0\":%llu,\"count\":%llu,\"dst0\":%llu}\n", n, src0, count, dst0);
    return 0;
}
