/* Fixture for test/pad-service.test.mjs: a synthetic model (the keyed-selftest weights) as a
 * pad service's bank, and a consumer engine that imports from the service over HTTP.
 *
 *   keyed-bank-fixture mint DIR BANK_SECRET_HEX BANK_ID_HEX DIGEST_HEX SERVICE_PK_HEX INDEX0 COUNT
 *       mints bank rows [INDEX0, INDEX0+COUNT) (format 4, boxed to the service) into DIR
 *   keyed-bank-fixture consume ROWS
 *       runs the link's dealt import for ROWS rows with the SHIELDED_PAD_* environment (keyed,
 *       pad check on); prints {"pads":N} and exits 0 when every pad imported and passed
 */
#include "shielded-tee.h"
#include "shielded-pads.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t st = 4242;
static uint32_t nxt(void) { st = st * 1664525U + 1013904223U; return st; }

int main(int argc, char **argv) {
    const int64_t KA = 256, NA = 48, NB = 16, KC = 192, NC = 40;
    int8_t *wa = malloc(KA * NA), *wb = malloc(KA * NB), *wc = malloc(KC * NC);
    for (int64_t i = 0; i < KA * NA; i++) wa[i] = (int8_t)((int)(nxt() % 239) - 119);
    for (int64_t i = 0; i < KA * NB; i++) wb[i] = (int8_t)((int)(nxt() % 239) - 119);
    for (int64_t i = 0; i < KC * NC; i++) wc[i] = (int8_t)((int)(nxt() % 239) - 119);
    if (argc < 2) return 2;
    int err = 0;
    sh_link *l = sh_link_open("127.0.0.1", 1, false, &err);
    if (!l) { printf("{\"error\":\"link open rc %d\"}\n", err); return 1; }
    const int a = sh_link_add_weight(l, "blk.0.attn_q.weight", wa, KA, NA, 8, -1);
    const int b = sh_link_add_weight(l, "blk.0.attn_k.weight", wb, KA, NB, 8, a);
    const int c = sh_link_add_weight(l, "blk.0.ffn_down.weight", wc, KC, NC, 8, -1);
    if (a < 0 || b < 0 || c < 0) return 1;
    if (!strcmp(argv[1], "mint") && argc == 9) {
        uint8_t bank[32], bank_id[16], digest[32], pk[32];
        if (!sh_pads_hex2bin(argv[3], bank, 32) || !sh_pads_hex2bin(argv[4], bank_id, 16) ||
            !sh_pads_hex2bin(argv[5], digest, 32) || !sh_pads_hex2bin(argv[6], pk, 32)) return 2;
        const uint64_t index0 = strtoull(argv[7], NULL, 10), count = strtoull(argv[8], NULL, 10);
        char p[700]; snprintf(p, sizeof p, "%s/bank-%llu-%llu.pads", argv[2], (unsigned long long)index0, (unsigned long long)count);
        const int rc = sh_link_mint_shipment_keyed(l, bank, bank_id, digest, index0, count, pk, p);
        printf("{\"minted\":%s,\"rc\":%d}\n", rc == SH_OK ? "true" : "false", rc);
        return rc == SH_OK ? 0 : 1;
    }
    if (!strcmp(argv[1], "consume") && argc == 3) {
        const int rows = atoi(argv[2]);
        int32_t *R = calloc((size_t)2 * rows * KA, sizeof *R), *U = calloc((size_t)2 * rows * (NA + NB), sizeof *U);
        const int got = sh_link_dealt_selftest(l, rows, R, U);
        printf("{\"pads\":%d,\"error\":\"%s\"}\n", got, got == 2 * rows ? "" : sh_link_last_error(l));
        return got == 2 * rows ? 0 : 1;
    }
    return 2;
}
