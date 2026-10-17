/* Keyed pads (format 4, shielded/dealer/HOST-BANK.md), end to end on synthetic weights, no worker:
 *   a host bank mints cells whose mask r comes from each cell's own key (sh_pad_cellkey of the
 *   bank secret) -> every cell reads back equal to an exact int64 oracle of r.W, with its key;
 *   distinct cells have distinct keys and masks; a format-2 reader sees no format-4 shipment and
 *   each writer refuses the other format's cells; a flipped key byte is refused; the link's own
 *   dealt import (SHIELDED_PAD_KEYED=1, the refill threads' path) yields the same pads and passes
 *   the pad check, and a cell minted under the wrong key FAILS it.
 *
 *   make keyed-selftest && ./keyed-selftest
 */
#include "shielded-tee.h"
#include "shielded-pads.h"
#include "shielded-field.h"
#include "tweetnacl.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static uint32_t st = 4242;
static uint32_t nxt(void) { st = st * 1664525U + 1013904223U; return st; }

static sh_link *build(int8_t *wa, int8_t *wb, int8_t *wc, int64_t KA, int64_t NA, int64_t NB, int64_t KC, int64_t NC) {
    int err = 0;
    sh_link *l = sh_link_open("127.0.0.1", 1, false, &err);
    assert(l);
    const int a = sh_link_add_weight(l, "blk.0.attn_q.weight", wa, KA, NA, 8, -1); assert(a >= 0);
    const int b = sh_link_add_weight(l, "blk.0.attn_k.weight", wb, KA, NB, 8, a);  assert(b >= 0);
    const int c = sh_link_add_weight(l, "blk.0.ffn_down.weight", wc, KC, NC, 8, -1); assert(c >= 0);
    return l;
}

/* u for (group g, mask r): group 0 = attn_q rows then attn_k rows, group 1 = ffn_down. */
static void oracle_u(int g, const int32_t *r, const int8_t *wa, const int8_t *wb, const int8_t *wc,
                     int64_t KA, int64_t NA, int64_t NB, int64_t KC, int64_t NC, int32_t *u) {
    const int64_t K = g == 0 ? KA : KC, ulen = g == 0 ? NA + NB : NC;
    for (int64_t j = 0; j < ulen; j++) {
        const int8_t *w; int64_t row;
        if (g == 0) { if (j < NA) { w = wa; row = j; } else { w = wb; row = j - NA; } }
        else { w = wc; row = j; }
        int64_t exact = 0;
        for (int64_t k = 0; k < K; k++) exact += (int64_t)r[k] * w[row * K + k];
        u[j] = (int32_t)sh_balanced(exact);
    }
}

/* A keyed shipment of [index0, index0 + count) under bank; `bad_index` (or -1) gets its u from
 * the wrong key, as a lying pad service would. */
static void mint_keyed(const char *path, const uint8_t bank[32], const uint8_t delivery_id[16], const uint8_t digest[32],
                       const sh_pads_group *table, int ng, uint64_t index0, uint64_t count, const uint8_t pk[32],
                       const int8_t *wa, const int8_t *wb, const int8_t *wc,
                       int64_t KA, int64_t NA, int64_t NB, int64_t KC, int64_t NC, int64_t bad_index) {
    int err = 0;
    sh_pads_writer *w = sh_pads_writer_open_keyed(path, digest, delivery_id, table, (uint32_t)ng, index0, count, pk, &err);
    assert(w && err == SH_OK);
    const size_t cap = sh_pads_writer_scratch_bytes(w);
    uint8_t *plain = malloc(cap), *cell = malloc(cap);
    int32_t *r = malloc((size_t)KA * sizeof *r), *u = malloc((size_t)(NA + NB) * sizeof *u);
    /* a keyed writer refuses an unkeyed cell */
    assert(sh_pads_writer_cell_with(w, index0, 0, u, plain, cell) == SH_ERR_RANGE);
    for (uint64_t i = index0; i < index0 + count; i++)
        for (int g = 0; g < ng; g++) {
            const int64_t K = g == 0 ? KA : KC;
            uint8_t key[32];
            sh_pad_cellkey(bank, (uint32_t)g, i, key);
            uint8_t mkey[32]; memcpy(mkey, key, 32);
            if ((int64_t)i == bad_index) mkey[0] ^= 1;                 /* u for another mask */
            sh_pad_r(mkey, 0, 0, K, r);
            oracle_u(g, r, wa, wb, wc, KA, NA, NB, KC, NC, u);
            assert(sh_pads_writer_cell_keyed_with(w, i, (uint32_t)g, key, u, plain, cell) == SH_OK);
        }
    assert(sh_pads_writer_close(w) == SH_OK);
    free(plain); free(cell); free(r); free(u);
}

int main(void) {
    const int64_t KA = 256, NA = 48, NB = 16, KC = 192, NC = 40;
    int8_t *wa = malloc(KA * NA), *wb = malloc(KA * NB), *wc = malloc(KC * NC);
    for (int64_t i = 0; i < KA * NA; i++) wa[i] = (int8_t)((int)(nxt() % 239) - 119);
    for (int64_t i = 0; i < KA * NB; i++) wb[i] = (int8_t)((int)(nxt() % 239) - 119);
    for (int64_t i = 0; i < KC * NC; i++) wc[i] = (int8_t)((int)(nxt() % 239) - 119);

    sh_link *probe = build(wa, wb, wc, KA, NA, NB, KC, NC);
    sh_pads_group table[4];
    const int ng = sh_link_group_table(probe, table, 4);
    assert(ng == 2 && table[0].u_len == (uint64_t)(NA + NB) && table[1].u_len == (uint64_t)NC);
    sh_link_close(probe);

    uint8_t bank[32], delivery_id[16], digest[32], pk[32], sk[32];
    for (int i = 0; i < 32; i++) { bank[i] = (uint8_t)nxt(); digest[i] = (uint8_t)(i * 5); }
    for (int i = 0; i < 16; i++) delivery_id[i] = (uint8_t)(100 + i);
    crypto_box_keypair(pk, sk);

    /* --- cell keys: deterministic, distinct per cell, and not the bank --- */
    {
        uint8_t a[32], b[32], c[32], d[32];
        sh_pad_cellkey(bank, 0, 7, a); sh_pad_cellkey(bank, 0, 7, b);
        sh_pad_cellkey(bank, 1, 7, c); sh_pad_cellkey(bank, 0, 8, d);
        assert(!memcmp(a, b, 32) && memcmp(a, c, 32) && memcmp(a, d, 32) && memcmp(c, d, 32) && memcmp(a, bank, 32));
        int32_t *ra = malloc(KA * sizeof *ra), *rd = malloc(KA * sizeof *rd);
        sh_pad_r(a, 0, 0, KA, ra); sh_pad_r(d, 0, 0, KA, rd);
        assert(memcmp(ra, rd, KA * sizeof *ra));                      /* neighbouring cells: unrelated masks */
        for (int64_t k = 0; k < KA; k++) assert(ra[k] >= 0 && ra[k] < SH_M_MOD);
        free(ra); free(rd);
    }

    char dir[] = "/tmp/keyed-selftest-XXXXXX";
    assert(mkdtemp(dir));
    char ship[600];
    snprintf(ship, sizeof ship, "%s/bank-0-20.pads", dir);
    const uint64_t COUNT = 20;
    mint_keyed(ship, bank, delivery_id, digest, table, ng, 0, COUNT, pk, wa, wb, wc, KA, NA, NB, KC, NC, -1);

    /* --- the link's own keyed mint (what the pad service runs) equals the oracle cell for cell,
     *     serial and with three threads and a 7-row pass --- */
    {
        const char *cfg[][2] = { {"1", "16"}, {"3", "7"} };
        for (int c = 0; c < 2; c++) {
            char md[] = "/tmp/keyed-mint-XXXXXX"; assert(mkdtemp(md));
            char mp[600]; snprintf(mp, sizeof mp, "%s/bank-3-20.pads", md);
            setenv("SHIELDED_MINT_THREADS", cfg[c][0], 1); setenv("SHIELDED_MINT_BATCH", cfg[c][1], 1);
            sh_link *ml = build(wa, wb, wc, KA, NA, NB, KC, NC);
            assert(sh_link_mint_shipment_keyed(ml, bank, delivery_id, digest, 3, 20, pk, mp) == SH_OK);
            sh_link_close(ml);
            unsetenv("SHIELDED_MINT_THREADS"); unsetenv("SHIELDED_MINT_BATCH");
            int e = 0; sh_pads_reader *mr = sh_pads_reader_open_keyed(md, delivery_id, sk, &e);
            assert(mr && sh_pads_reader_bind(mr, table, (uint32_t)ng) == SH_OK);
            int32_t *rr = malloc(KA * sizeof *rr), *uu = malloc((NA + NB) * sizeof *uu), *ww = malloc((NA + NB) * sizeof *ww);
            for (uint64_t idx = 3; idx < 23; idx++)
                for (int g = 0; g < ng; g++) {
                    uint8_t key[32], expect[32];
                    assert(sh_pads_reader_cell_keyed(mr, (uint32_t)g, idx, uu, key, NULL) == SH_OK);
                    sh_pad_cellkey(bank, (uint32_t)g, idx, expect); assert(!memcmp(key, expect, 32));
                    sh_pad_r(key, 0, 0, g == 0 ? KA : KC, rr);
                    oracle_u(g, rr, wa, wb, wc, KA, NA, NB, KC, NC, ww);
                    if (memcmp(uu, ww, table[g].u_len * sizeof *uu)) { fprintf(stderr, "link keyed mint differs g%d idx%llu cfg%d\n", g, (unsigned long long)idx, c); return 1; }
                }
            free(rr); free(uu); free(ww); sh_pads_reader_close(mr);
            char rm[700]; snprintf(rm, sizeof rm, "rm -rf %s", md); (void)!system(rm);
        }
    }

    /* --- a seed writer refuses keyed cells --- */
    {
        char p2[600]; snprintf(p2, sizeof p2, "%s/seed.pads.x", dir);
        int err = 0;
        sh_pads_writer *w = sh_pads_writer_open(p2, digest, delivery_id, table, (uint32_t)ng, 0, 1, pk, &err);
        assert(w);
        const size_t cap = sh_pads_writer_scratch_bytes(w);
        uint8_t *plain = malloc(cap), *cell = malloc(cap), key[32] = {1};
        int32_t *u = calloc((size_t)(NA + NB), sizeof *u);
        assert(sh_pads_writer_cell_keyed_with(w, 0, 0, key, u, plain, cell) == SH_ERR_RANGE);
        sh_pads_writer_close(w);                                     /* incomplete: never published */
        assert(access(p2, F_OK) != 0);
        free(plain); free(cell); free(u);
    }

    /* --- read back: u equals the oracle for each cell's own mask, the key is the bank's --- */
    int err = 0;
    sh_pads_reader *rd = sh_pads_reader_open_keyed(dir, delivery_id, sk, &err);
    assert(rd && sh_pads_reader_keyed(rd) && sh_pads_reader_bind(rd, table, (uint32_t)ng) == SH_OK);
    assert(sh_pads_reader_extent(rd) == COUNT);
    int32_t *r = malloc(KA * sizeof *r), *u = malloc((NA + NB) * sizeof *u), *want = malloc((NA + NB) * sizeof *want);
    for (uint64_t idx = 0; idx < COUNT; idx++)
        for (int g = 0; g < ng; g++) {
            const int64_t K = g == 0 ? KA : KC;
            uint8_t key[32], expect[32];
            uint32_t sg = UINT32_MAX;
            assert(sh_pads_reader_cell_keyed(rd, (uint32_t)g, idx, u, key, &sg) == SH_OK && sg == (uint32_t)g);
            sh_pad_cellkey(bank, (uint32_t)g, idx, expect);
            assert(!memcmp(key, expect, 32));
            sh_pad_r(key, 0, 0, K, r);
            oracle_u(g, r, wa, wb, wc, KA, NA, NB, KC, NC, want);
            if (memcmp(u, want, table[g].u_len * sizeof *u)) { fprintf(stderr, "MISMATCH g%d idx%llu\n", g, (unsigned long long)idx); return 1; }
        }
    /* the seed API on a keyed reader is refused (it would drop the keys) */
    assert(sh_pads_reader_cell(rd, 0, 0, u) == SH_ERR_RANGE);
    assert(sh_pads_reader_cell_keyed(rd, 0, COUNT, u, (uint8_t[32]){0}, NULL) == SH_ERR_EXHAUST);
    sh_pads_reader_close(rd);

    /* --- a format-2 reader sees no format-4 shipment --- */
    {
        int e2 = 0;
        sh_pads_reader *r2 = sh_pads_reader_open(dir, delivery_id, sk, &e2);
        if (r2) {
            if (sh_pads_reader_bind(r2, table, (uint32_t)ng) == SH_OK) assert(sh_pads_reader_cell(r2, 0, 0, u) != SH_OK);
            sh_pads_reader_close(r2);
        }
    }

    /* --- a flipped byte inside a cell's key is refused --- */
    {
        char td[] = "/tmp/keyed-tamper-XXXXXX"; assert(mkdtemp(td));
        char tp[600]; snprintf(tp, sizeof tp, "%s/bank-0-2.pads", td);
        mint_keyed(tp, bank, delivery_id, digest, table, ng, 0, 2, pk, wa, wb, wc, KA, NA, NB, KC, NC, -1);
        FILE *f = fopen(tp, "r+b"); assert(f);
        fseek(f, 0, SEEK_END); const long size = ftell(f);
        /* the first cell starts at data_off (4 KiB-aligned): byte 16 + 3 = inside its key */
        fseek(f, 4096 + 16 + 3, SEEK_SET); const int c = fgetc(f);
        fseek(f, 4096 + 16 + 3, SEEK_SET); fputc(c ^ 0x40, f); fclose(f);
        assert(size > 4096 + 64);
        int e3 = 0; sh_pads_reader *r3 = sh_pads_reader_open_keyed(td, delivery_id, sk, &e3);
        assert(r3 && sh_pads_reader_bind(r3, table, (uint32_t)ng) == SH_OK);
        uint8_t key[32];
        assert(sh_pads_reader_cell_keyed(r3, 0, 0, u, key, NULL) == SH_ERR_VERIFY);
        assert(sh_pads_reader_cell_keyed(r3, 1, 0, u, key, NULL) == SH_OK);   /* the next cell is untouched */
        sh_pads_reader_close(r3);
        char rm[700]; snprintf(rm, sizeof rm, "rm -rf %s", td); (void)!system(rm);
    }

    /* --- the link's own dealt import, keyed: same pads, and the pad check passes --- */
    char ledger[600]; snprintf(ledger, sizeof ledger, "%s/ledger", dir);
    char hex_id[33], hex_sk[65];
    sh_pads_bin2hex(delivery_id, 16, hex_id); sh_pads_bin2hex(sk, 32, hex_sk);
    setenv("SHIELDED_PAD_SOURCE", dir, 1); setenv("SHIELDED_PAD_LEDGER", ledger, 1);
    setenv("SHIELDED_PAD_SEED_ID", hex_id, 1); setenv("SHIELDED_PAD_SK", hex_sk, 1);
    setenv("SHIELDED_PAD_KEYED", "1", 1); setenv("SHIELDED_PAD_CHECK", "1", 1);
    unsetenv("SHIELDED_PAD_SEED");                                      /* a keyed consumer has no seed */
    {
        sh_link *l = build(wa, wb, wc, KA, NA, NB, KC, NC);
        int32_t *R = calloc((size_t)2 * 3 * KA, sizeof *R), *U = calloc((size_t)2 * 3 * (NA + NB), sizeof *U);
        const int got = sh_link_dealt_selftest(l, 3, R, U);
        if (got != 6) { fprintf(stderr, "keyed import: rc %d err '%s'\n", got, sh_link_last_error(l)); return 1; }
        /* R holds, per group, 3 rows of K: row i of group 0 is r from cellkey(bank, 0, i) */
        int32_t *rr = malloc(KA * sizeof *rr);
        for (uint64_t i = 0; i < 3; i++) {
            uint8_t key[32]; sh_pad_cellkey(bank, 0, i, key); sh_pad_r(key, 0, 0, KA, rr);
            assert(!memcmp(R + i * KA, rr, KA * sizeof *rr));
        }
        free(rr); free(R); free(U);
        sh_link_close(l);
    }
    /* a cell whose u was minted under the wrong key opens (the box is fine) but FAILS the pad check */
    {
        char bd[] = "/tmp/keyed-bad-XXXXXX"; assert(mkdtemp(bd));
        char bp[600], bl[600]; snprintf(bp, sizeof bp, "%s/bank-0-4.pads", bd); snprintf(bl, sizeof bl, "%s/ledger", bd);
        mint_keyed(bp, bank, delivery_id, digest, table, ng, 0, 4, pk, wa, wb, wc, KA, NA, NB, KC, NC, 1);
        setenv("SHIELDED_PAD_SOURCE", bd, 1); setenv("SHIELDED_PAD_LEDGER", bl, 1);
        sh_link *l = build(wa, wb, wc, KA, NA, NB, KC, NC);
        int32_t *R = calloc((size_t)2 * 3 * KA, sizeof *R), *U = calloc((size_t)2 * 3 * (NA + NB), sizeof *U);
        assert(sh_link_dealt_selftest(l, 3, R, U) == SH_ERR_VERIFY);
        assert(strstr(sh_link_last_error(l), "FAILED the check"));
        free(R); free(U); sh_link_close(l);
        char rm[700]; snprintf(rm, sizeof rm, "rm -rf %s", bd); (void)!system(rm);
    }
    /* a keyed link without a delivery id refuses to open */
    unsetenv("SHIELDED_PAD_SEED_ID");
    { int e4 = 0; assert(sh_link_open("127.0.0.1", 1, false, &e4) == NULL && e4 == SH_ERR_RANGE); }

    char rm[700]; snprintf(rm, sizeof rm, "rm -rf %s", dir); (void)!system(rm);
    free(r); free(u); free(want); free(wa); free(wb); free(wc);
    printf("{\"keyed_selftest\":true,\"cells\":%llu}\n", (unsigned long long)(COUNT * (uint64_t)ng));
    return 0;
}
