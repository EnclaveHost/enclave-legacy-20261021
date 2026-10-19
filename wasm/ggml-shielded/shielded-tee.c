#define _GNU_SOURCE
#include "shielded-tee.h"
#include "shielded-idle.h"
#include "shielded-parwork.h"
#include "shielded-source-profile.h"
#include "shielded-pads.h"
#include "shielded-bank.h"
#include "shielded-http.h"
#include "shielded-wide.h"
#include "shielded-field.h"
#include "shielded-pad-check.h"
#include "shielded-pad-parallel.h"
#include "shielded-sha256.h"
#include "shielded-pad-manifest.h"
#include "shielded-mint-balance.h"
#include "shielded-spill.h"
#include "shielded-spill-cpu.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>
#if defined(__aarch64__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif

#include "shielded-spill.inc"

#define SH_ALIGN 64
static int64_t align_up(int64_t x) { return (x + SH_ALIGN - 1) & ~(int64_t)(SH_ALIGN - 1); }

static double now_ms(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6; }

/* ---------------------------------------------------------------------------
 * SIMD dispatch. The two builds of shielded-simd.c are checked against each
 * other once, on this CPU, before the fast one is trusted: a vectorised loop
 * that disagrees with its scalar twin is a bug that would otherwise surface as
 * verification failures on every request.
 * ------------------------------------------------------------------------ */
#define SIMD_TABLE_REFILL(sfx, nm, refill_fn) { nm, sh_simd_##sfx##_pad_planes, sh_simd_##sfx##_mask_planes, \
    sh_simd_##sfx##_unmask, sh_simd_##sfx##_encode, sh_simd_##sfx##_descale, sh_simd_##sfx##_fv_dot, \
    sh_simd_##sfx##_fv_dot_x, sh_simd_##sfx##_fv_prepare, refill_fn, \
    sh_simd_##sfx##_values_within, sh_simd_##sfx##_reply32_balanced, sh_simd_##sfx##_outlier_add, \
    sh_simd_##sfx##_outlier_add_stride, \
    sh_simd_##sfx##_fv_dots, sh_simd_##sfx##_fv_dots_x, sh_simd_##sfx##_unmask_fv, \
    sh_simd_##sfx##_unmask24, sh_simd_##sfx##_unmask24_fv, sh_simd_##sfx##_encode_checked }
#define SIMD_TABLE(sfx, nm) SIMD_TABLE_REFILL(sfx, nm, sh_simd_##sfx##_refill)
#if !defined(__aarch64__)
static const sh_simd simd_avx512  = SIMD_TABLE(avx512, "avx512-vnni");
static const sh_simd simd_avx512_crt = SIMD_TABLE_REFILL(avx512,
    "avx512-vnni-vector-crt", sh_simd_avx512_refill_vector_crt);
#endif
static const sh_simd simd_generic = SIMD_TABLE(generic, "generic");
#if defined(__aarch64__)
static const sh_simd simd_neon    = SIMD_TABLE(neon, "neon-sdot");
#ifdef SH_HAVE_NEON_TUNED
static const sh_simd simd_neon_tuned = SIMD_TABLE(neon_tuned, "neon-sdot-tuned");
#endif
#endif

const sh_simd *sh_simd_generic(void) { return &simd_generic; }

/* The request path keeps the Freivalds vectors as int32 rows, one per rep
 * ([rep][n]); the reference fv_dot takes them int64 and interleaved ([n][rep]).
 * Both forms are derived from the same values and checked against each other. */
static void fv_rows_i32(const int64_t *inter, int reps, int64_t n, int32_t *rows) {
    for (int64_t j = 0; j < n; j++)
        for (int r = 0; r < reps; r++) rows[(size_t)r * n + j] = (int32_t)inter[j * reps + r];
}

static bool simd_agree(const sh_simd *a, const sh_simd *b) {
    enum { K = 96 + 32, N = 37, B = 5 };   /* K not a multiple of 64: exercises the tail */
    uint64_t seed = 0x243f6a8885a308d3ull;
#define RND() (seed ^= seed << 13, seed ^= seed >> 7, seed ^= seed << 17, seed)
    int32_t r[B * K]; int64_t x[B * K]; int8_t W[N * K];
    for (int i = 0; i < B * K; i++) { r[i] = (int32_t)(RND() % (uint64_t)SH_M_MOD); x[i] = (int64_t)(RND() % (1u << 26)) - (1 << 25); }
    for (int i = 0; i < N * K; i++) W[i] = (int8_t)((int)(RND() % 239) - 119);
    uint8_t pa[3 * B * K], pb[3 * B * K]; int8_t ma[3 * B * K], mb[3 * B * K];
    a->pad_planes(r, B * K, pa, pa + B * K, pa + 2 * B * K);
    b->pad_planes(r, B * K, pb, pb + B * K, pb + 2 * B * K);
    if (memcmp(pa, pb, sizeof pa)) return false;
    a->mask_planes(x, r, B * K, ma, ma + B * K, ma + 2 * B * K);
    b->mask_planes(x, r, B * K, mb, mb + B * K, mb + 2 * B * K);
    if (memcmp(ma, mb, sizeof ma)) return false;
    int32_t ua[B * N], ub[B * N], acc[12 * N];
    a->refill(pa, B, W, K, N, ua, N, acc);
    b->refill(pb, B, W, K, N, ub, N, acc);
    if (memcmp(ua, ub, sizeof ua)) return false;
    /* and both against the int64 truth */
    for (int bb = 0; bb < B; bb++)
        for (int j = 0; j < N; j++) {
            int64_t s = 0;
            for (int k = 0; k < K; k++) s += (int64_t)r[bb * K + k] * W[j * K + k];
            if (ua[bb * N + j] != (int32_t)sh_balanced(s)) return false;
        }
    int64_t ya[B * N], yb[B * N];
    a->unmask(ua, ub, B * N, ya); b->unmask(ua, ub, B * N, yb);
    if (memcmp(ya, yb, sizeof ya)) return false;
    int64_t s[N * 2], sta[K * 2], stb[K * 2];
    for (int i = 0; i < N * 2; i++) s[i] = 1 + (int64_t)(RND() % (SH_FV_S_RANGE - 1));
    a->fv_prepare(W, K, N, s, 2, sta); b->fv_prepare(W, K, N, s, 2, stb);
    if (memcmp(sta, stb, sizeof sta)) return false;
    for (int rep = 0; rep < 2; rep++) {
        if (a->fv_dot(ya, s, 2, rep, N) != b->fv_dot(ya, s, 2, rep, N)) return false;
        if (a->fv_dot_x(x, sta, 2, rep, K) != b->fv_dot_x(x, sta, 2, rep, K)) return false;
    }
    /* The request-path forms: fused, int32 rows. Against each other AND against
     * the reference dots, so a layout slip fails here and not as a verification
     * failure on the first token. */
    int32_t s32[2 * N], st32[2 * K];
    fv_rows_i32(s, 2, N, s32); fv_rows_i32(sta, 2, K, st32);
    int64_t da[2], db[2], dxa[2], dxb[2], fa[2], fb[2], yfa[B * N], yfb[B * N];
    a->fv_dots(ya, s32, 2, N, da);       b->fv_dots(ya, s32, 2, N, db);
    a->fv_dots_x(x, st32, 2, K, dxa);    b->fv_dots_x(x, st32, 2, K, dxb);
    a->unmask_fv(ua, ub, s32, 2, N, yfa, fa); b->unmask_fv(ua, ub, s32, 2, N, yfb, fb);
    if (memcmp(yfa, ya, N * sizeof(int64_t)) || memcmp(yfb, ya, N * sizeof(int64_t))) return false;
    for (int rep = 0; rep < 2; rep++) {
        if (da[rep] != db[rep] || da[rep] != a->fv_dot(ya, s, 2, rep, N)) return false;
        if (fa[rep] != fb[rep] || fa[rep] != da[rep]) return false;
        if (dxa[rep] != dxb[rep] || dxa[rep] != a->fv_dot_x(x, sta, 2, rep, K)) return false;
    }
    /* The packed reply: the same balanced values as 3-byte little-endian
     * two's complement (what a 1.2 worker sends) must unmask to exactly what
     * the int32 form did, in both the plain and the fused form, from both
     * builds. B*N = 185 values: the vector loop, its two-short stop and the
     * scalar tail are all exercised. Values near +-M/2 are included so the
     * balancing corrections fire. */
    {
        uint8_t packed[3 * B * N];
        for (int i = 0; i < B * N; i++) {
            int32_t v = ua[i];
            if (i % 7 == 0) v = (int32_t)(SH_M_MOD / 2) - (i % 3);
            if (i % 11 == 0) v = -(int32_t)(SH_M_MOD / 2) + 1 + (i % 3);
            ua[i] = v;
            packed[3 * i] = (uint8_t)v; packed[3 * i + 1] = (uint8_t)(v >> 8); packed[3 * i + 2] = (uint8_t)(v >> 16);
        }
        int64_t y32[B * N], y24a[B * N], y24b[B * N], f32[2], f24a[2], f24b[2];
        a->unmask(ua, ub, B * N, y32);
        a->unmask24(packed, ub, B * N, y24a); b->unmask24(packed, ub, B * N, y24b);
        if (memcmp(y32, y24a, sizeof y32) || memcmp(y32, y24b, sizeof y32)) return false;
        a->unmask_fv(ua, ub, s32, 2, N, y32, f32);
        a->unmask24_fv(packed, ub, s32, 2, N, y24a, f24a); b->unmask24_fv(packed, ub, s32, 2, N, y24b, f24b);
        if (memcmp(y32, y24a, N * sizeof(int64_t)) || memcmp(y32, y24b, N * sizeof(int64_t))) return false;
        if (f32[0] != f24a[0] || f32[1] != f24a[1] || f32[0] != f24b[0] || f32[1] != f24b[1]) return false;
        /* and the whole B*N run through the fused form as one long row */
        int32_t s_long[B * N];
        for (int i = 0; i < B * N; i++) s_long[i] = 1 + (int32_t)(RND() % (SH_FV_S_RANGE - 1));
        a->unmask24_fv(packed, ub, s_long, 1, B * N, y24a, f24a); b->unmask24_fv(packed, ub, s_long, 1, B * N, y24b, f24b);
        a->unmask(ua, ub, B * N, y32);
        if (memcmp(y32, y24a, sizeof y32) || memcmp(y32, y24b, sizeof y32) || f24a[0] != f24b[0]) return false;
        a->fv_dots(y32, s_long, 1, B * N, f32);
        if (f24a[0] != f32[0]) return false;
    }
    /* encode: the vector path rounds under MXCSR exactly as lrintf does, including
     * ties to even, and its scalar tail must agree with itself. */
    float fsrc[B * K]; int64_t ea[B * K], eb[B * K];
    for (int i = 0; i < B * K; i++) fsrc[i] = ((float)(int)(RND() % 200001) - 100000.0f) / 8.0f;   /* .0/.125 steps: exact ties */
    a->encode(fsrc, B * K, 4.0f, ea); b->encode(fsrc, B * K, 4.0f, eb);
    if (memcmp(ea, eb, sizeof ea)) return false;
    if (!a->encode_checked(fsrc, B * K, 4.0f, (float)SH_FV_X_LIMIT, ea) ||
        memcmp(ea, eb, sizeof ea) ||
        !b->encode_checked(fsrc, B * K, 4.0f, (float)SH_FV_X_LIMIT, eb) ||
        memcmp(ea, eb, sizeof ea)) return false;
#undef RND
    return true;
}

const sh_simd *sh_simd_get(void) {
    static const sh_simd *chosen = NULL;
    if (chosen) return chosen;
    const char *off = getenv("SHIELDED_NO_SIMD");
#if defined(__aarch64__)
    /* The phone anchor: SDOT (FEAT_DotProd) is the whole refill win; checked
     * against the generic build exactly as AVX-512 is on x86. */
    bool want_neon = !(off && *off && strcmp(off, "0"));
    if (want_neon) want_neon = (getauxval(AT_HWCAP) & HWCAP_ASIMDDP) != 0;
    const sh_simd *fast = &simd_neon;
#ifdef SH_HAVE_NEON_TUNED
    const char *tuned = getenv("SHIELDED_ARM_TUNED");
    if (tuned && !strcmp(tuned, "1")) fast = &simd_neon_tuned;
#endif
    if (want_neon && !simd_agree(fast, &simd_generic)) {
        fprintf(stderr, "[shielded] the NEON kernels disagree with the generic ones on this CPU; using generic\n");
        want_neon = false;
    }
    chosen = want_neon ? fast : &simd_generic;
    return chosen;
#else
    bool want_avx512 = !(off && *off && strcmp(off, "0"));
    if (want_avx512) {
        __builtin_cpu_init();
        want_avx512 = __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512bw") &&
                      __builtin_cpu_supports("avx512dq") && __builtin_cpu_supports("avx512vl") &&
                      __builtin_cpu_supports("avx512vnni");
    }
    const char *vector_crt = getenv("SHIELDED_REFILL_VECTOR_CRT");
    const sh_simd *fast = vector_crt && !strcmp(vector_crt, "1") ? &simd_avx512_crt : &simd_avx512;
    if (want_avx512 && !simd_agree(fast, &simd_generic)) {
        fprintf(stderr, "[shielded] the AVX-512 kernels disagree with the generic ones on this CPU; using generic\n");
        want_avx512 = false;
    }
    chosen = want_avx512 ? fast : &simd_generic;
    return chosen;
#endif
}
const sh_simd *sh_link_simd(void) { return sh_simd_get(); }

/* ---------------------------------------------------------------------------
 * OS entropy. Both the pad seed and the Freivalds secret come from here and
 * nowhere else -- see rule 4 in the header, and the commit that had to fix it.
 * ------------------------------------------------------------------------ */
static bool os_random(void *buf, size_t n) {
    uint8_t *p = (uint8_t *)buf;
    while (n) {
        ssize_t r = getrandom(p, n, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return false;
        p += r; n -= (size_t)r;
    }
    return true;
}

/* ---------------------------------------------------------------------------
 * ChaCha20 keystream, for the pad bank.
 *
 * Pads are the one value that never has to agree across languages: only the
 * TEE generates them and only the TEE consumes them, so the requirement is
 * cryptographic strength and speed, not reproducibility. ChaCha20 keeps this
 * file dependency-free, which matters for something linked into the engine
 * inside the measurement.
 * ------------------------------------------------------------------------ */
#define ROTL32(v, c) (((v) << (c)) | ((v) >> (32 - (c))))
#define QR(a, b, c, d) ( \
    a += b, d ^= a, d = ROTL32(d, 16), \
    c += d, b ^= c, b = ROTL32(b, 12), \
    a += b, d ^= a, d = ROTL32(d, 8),  \
    c += d, b ^= c, b = ROTL32(b, 7))

/* ChaCha20 block: one definition, in shielded-pads.c (the dealt-pad derivation
 * and the mask bank must draw the same stream). */
void sh_chacha20_block(const uint32_t key[8], uint64_t counter, uint32_t out[16]);
#define chacha20_block sh_chacha20_block

typedef struct {
    pthread_mutex_t mu;
    uint32_t key[8];
    uint64_t counter;      /* strictly monotonic; the machine-checkable form of "never reused" */
    uint64_t issued_hi;
    uint64_t capacity;
    void (*stream)(const uint32_t *, uint64_t, int32_t *, size_t);
} sh_maskbank;

#if !defined(__aarch64__)
/* Public self-test material only. Include a carry into the high counter word,
 * multiple SIMD blocks and a partial block before admitting the sampler. */
static bool mask_stream_agrees(void) {
    const uint32_t key[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    const uint64_t starts[] = {0, UINT64_C(0xfffffff9), UINT64_MAX - 255};
    for (size_t t = 0; t < sizeof starts / sizeof *starts; t++) {
        int32_t fast[259], scalar[259];
        sh_simd_avx512_mask_stream(key, starts[t], fast, 259);
        size_t at = 0;
        for (uint64_t ctr = starts[t]; at < 259; ctr++) {
            uint32_t words[16]; chacha20_block(key, ctr, words);
            for (int j = 0; j < 8 && at < 259; j++) {
                const uint64_t v = ((uint64_t)words[2*j+1] << 32) | words[2*j];
                scalar[at++] = (int32_t)(v % (uint64_t)SH_M_MOD);
            }
        }
        if (memcmp(fast, scalar, sizeof fast)) return false;
    }
    return true;
}
#endif

static bool maskbank_init(sh_maskbank *b) {
    pthread_mutex_init(&b->mu, NULL);
    b->counter = 0; b->issued_hi = 0; b->capacity = UINT64_C(1) << 40;
    b->stream = NULL;
#if !defined(__aarch64__)
    const char *vector = getenv("SHIELDED_MASK_CHACHA16");
    const sh_simd *simd = sh_simd_get();
    if (vector && !strcmp(vector, "1") &&
        (simd == &simd_avx512 || simd == &simd_avx512_crt)) {
        if (!mask_stream_agrees()) {
            fprintf(stderr, "[shielded] vector mask stream disagrees; refusing mask bank\n");
            pthread_mutex_destroy(&b->mu);
            return false;
        }
        b->stream = sh_simd_avx512_mask_stream;
    }
#endif
    return os_random(b->key, sizeof b->key);
}

/* Fill `n` pad values uniform over [0, M). Drawn as uint64 and reduced, so the
 * modulo bias is ~2^-40 rather than the ~2^-8 a uint32 draw would carry. One
 * issuance index covers one call, however many values it produces; the index
 * never repeats, so no two calls share keystream. */
static int maskbank_issue(sh_maskbank *b, int32_t *dst, size_t n) {
    /* One issuance owns 2^24 blocks, eight field values per block. Reject a
     * request that could overlap the next window before consuming an index. */
    if (!dst || n > (UINT64_C(1) << 27)) return SH_ERR_RANGE;
    pthread_mutex_lock(&b->mu);
    if (b->counter >= b->capacity) { pthread_mutex_unlock(&b->mu); return SH_ERR_EXHAUST; }
    const uint64_t index = b->counter++;
    if (b->counter <= b->issued_hi) { pthread_mutex_unlock(&b->mu); return SH_ERR_EXHAUST; }
    b->issued_hi = b->counter;
    pthread_mutex_unlock(&b->mu);
    if (b->stream) {
        b->stream(b->key, index << 24, dst, n);
        return SH_OK;
    }
    uint32_t blk[16];
    uint64_t ctr = index << 24;      /* room for 2^24 blocks under one index */
    size_t produced = 0;
    while (produced < n) {
        chacha20_block(b->key, ctr++, blk);
        for (int i = 0; i + 1 < 16 && produced < n; i += 2) {
            const uint64_t v = ((uint64_t)blk[i + 1] << 32) | blk[i];
            dst[produced++] = (int32_t)(v % (uint64_t)SH_M_MOD);
        }
    }
    return SH_OK;
}

/* ---------------------------------------------------------------------------
 * Nodes and groups
 * ------------------------------------------------------------------------ */
typedef struct {
    char     name[64];
    const int8_t *w;            /* (N,K) borrowed */
    sh_weight_read_fn w_read; void *w_ctx; /* optional authenticated public-weight storage */
    sh_weight_refill_fn w_refill; /* optional trusted local pad computation */
    uint8_t public_digest[32]; bool public_digest_ready; /* private registered byte identity */
    int64_t   K, N;
    int32_t   max_m;
    int       group;
    int64_t   w_off, x_off, y_off;
    int64_t   u_off;            /* this node's columns within its group's u rows */
    int64_t  *s, *s_tilde;      /* preparation scratch; dealt links release it after conversion */
    int32_t  *s32, *st32;       /* the same values as the request path reads them: [REPS][N], [REPS][K] */
    int32_t  *sM, *stM;         /* dealt-pad check (SHIELDED_PAD_CHECK): s over N and (W.s) mod M over K */
} sh_node;

/* THE RING. `depth` slots of (r, u). Around it, in ring order:
 *
 *     [head-held, head)                 HELD: handed to the request in flight
 *     [head, head+count)                READY: generated, waiting
 *     [head+count, +generating)         RESERVED: a refill thread is writing
 *
 * A request takes from the front by advancing head -- the pad is CONSUMED at
 * that moment, whatever happens to the request afterwards (rule 1: a pad that
 * left the ready run never comes back). It holds the slot by POINTER until its
 * unmask is done and then releases it; a refill may only reserve a slot that
 * is neither ready, held nor reserved, which is what `held` in the deficit
 * guarantees. Refill threads reserve slot indices under the lock and write
 * the ring OUTSIDE it, so a lm_head refill (608 KB of u) no longer holds the
 * mutex against the request path; `ready` lets them finish out of order while
 * `count` still advances in ring order. Before this, take_pads memcpy'd r and
 * u out of the ring under the lock on every exchange -- 608 KB per lm_head
 * token -- and the refill thread memcpy'd them in under the same lock. */
typedef struct {
    int64_t   K;
    int       nodes[SH_GROUP_MAX];
    int       n_nodes;
    int64_t   u_len;            /* sum of N over the group */
    int32_t   max_m;
    int       depth, count, head, generating, held;
    uint8_t  *ready;            /* per slot: written by a refill, not yet counted */
    int32_t  *r_store;          /* depth x K, each in [0,M) */
    int32_t  *u_store;          /* depth x u_len, balanced */
    uint64_t pads_used, pads_missed;
    double on_path_ms;          /* request-thread counters; refill threads do not write them */
    uint64_t cursor;            /* dealt pads: the next shipment index this group imports */
    /* The disk tier (shielded-spill.h): the ring's discipline over this
     * group's spill slots, under pool_mu. In slot order: [sp_head - sp_held,
     * sp_head) are being read, [sp_head, +sp_count) are sealed and ready,
     * [+sp_count, +sp_writing) are being written. Several refill threads finish
     * out of order, so a write is counted, and a read retired, only in slot
     * order (sp_flag), as the ring's `ready` does for its writes. */
    uint32_t  sp_head, sp_count, sp_writing, sp_held;
    uint8_t  *sp_flag;          /* per slot: SP_WRITTEN / SP_READ, not yet folded */
    uint64_t *sp_wid;           /* per slot: the write id it was sealed under */
    int32_t   sp_last_m;        /* rows the request path last took here (prompt chunk or decode step) */
} sh_group;

struct sh_link {
    sh_pipe   *pipe;
    char       host[128];
    int        port, vsock_port;
    uint64_t   reserve_bytes;
    bool       shm_configured;
    char       shm_path[256];
    size_t     shm_bytes;
    bool       verify;
    bool       overlap_verify;
    /* An OPT-IN hook the backend fills with trusted work it has proved does
     * not depend on the reply in flight. It runs inside the same window the
     * Freivalds RHS uses -- after the request is published, before the spin --
     * and under the same contract: exactly once per exchange, never touching
     * the pipe, and never reading reply bytes. Nothing here can weaken
     * verification-before-use, because nothing here may look at the reply. */
    void     (*idle_fn)(void *);
    void      *idle_ctx;
    /* Idle spin, accumulated on the LINK rather than read off the pipe. The
     * pipe is recreated between phases and its counters restart, which is how
     * an earlier per-token figure divided one pipe's lifetime by the whole
     * run's tokens. Folding the delta in after every exchange survives that:
     * a value lower than the last one seen means a fresh pipe, so the delta is
     * the new value itself. */
    sh_idle_acc idle;
    /* Bytes per reply value: 4 (FIELD_GEMM, protocol 1.1) or 3 (FIELD_GEMM24,
     * 1.2). Decided at start from the worker's HELLO; SHIELDED_REPLY32=1
     * forces the wide form against a worker that offers both. */
    int        ywidth;
    sh_node   *nodes;   size_t n_nodes,  cap_nodes;
    sh_group  *groups;  size_t n_groups, cap_groups;
    int64_t    wbytes, abytes;
    sh_maskbank bank;
    const sh_simd *simd;

    pthread_mutex_t pool_mu;
    pthread_cond_t  need_refill;   /* a deficit appeared */
    pthread_cond_t  pool_filled;   /* a pad was published (start waits on it) */
    pthread_t *threads; int n_threads; bool threads_running, stop;
    int threads_env;               /* SHIELDED_REFILL_THREADS, or -1 = derive from the weights */
    int pool_depth, refill_batch, refill_unit, target_ms, warm_ms, pad_wait_us, refill_cost_priority;
    int64_t Kmax, Nmax, ulen_max;

    /* request-path scratch (caller thread) */
    const int32_t **rp; const int32_t **up; int *slots; size_t p_cap;   /* per-row pad pointers, m of each */
    int32_t *r;       size_t r_cap;      /* pads generated ON the path, pool dry */
    int32_t *u;       size_t u_cap;
    int8_t  *planes;  size_t planes_cap;
    uint8_t *gplanes; size_t gplanes_cap;
    int32_t *acc;     size_t acc_cap;
    uint8_t *hdr;     size_t hdr_cap;
    int64_t *fv_rhs;  size_t fv_rhs_cap; /* [node][row][rep], trusted caller only */

    /* Dealt pads (shielded-pads.h, shielded/dealer/PLAN.md): the ring is
     * filled from shipments on disk, r is derived from pad_seed, every index
     * is consumed inside a ledger window reserved BEFORE use, and nothing is
     * ever minted on the request path (a dry ring stalls the request). */
    bool       dealt;
    char       pad_dir[512], pad_ledger[512];
    bool       zero_pads;                   /* SHIELDED_ZERO_PADS: r = u = 0, x goes to the worker IN THE CLEAR - the dealer's own worker only */
    char       bank_url[1024];              /* http:// bank (shielded-bank.c); pad_dir is then the local cache */
    sh_bank   *padbank;
    uint64_t   bank_cache_max;
    bool       pad_prune;                   /* unlink spent shipments in pad_dir (the consumer's own copy) */
    char       win_url[1024];               /* http:// window agent: POST {want, seed_id} -> signed window */
    uint8_t    win_pk[32]; bool have_win_pk;
    char       pad_seed_id_hex[33];
    bool       receipt_due;                 /* a window was taken: report the delta since the last receipt (outside the lock) */
    uint64_t   receipt_pads, receipt_rows;  /* what has been reported so far */
    bool       receipt_failed;              /* logged once */
    uint8_t    pad_seed[32], pad_seed_id[16], pad_sk[32];
    uint64_t   pad_window, win_lo, win_hi;
    int        pad_bank_wait_ms;
    sh_pads_reader *pads;
    sh_window_fn win_fn; void *win_ctx;     /* a provider (the pVM's owner-app path) replaces the ledger file */

    /* The disk tier (shielded-spill.h): pads the refill threads mint while the
     * link is idle, sealed onto a host disk, imported when a ring runs low.
     * Local-mint links only. NULL when unconfigured or turned off. */
    sh_spill  *spill;
    bool       spill_off;                   /* a failure ended it for this link's life */
    uint64_t   spill_fp;                    /* the registration its layout was cut for */
    uint32_t   spill_slots;                 /* per group */
    uint64_t   spill_wid;                   /* the next write id; never reused */
    int        spill_minters, spill_mint_max, spill_mint_busy, spill_idle_ms, spill_min_rows;
    /* The CPU governor (shielded-spill-cpu.h), on when SHIELDED_PAD_SPILL_CPU_HEADROOM is set: minters follow
     * the CPU the rest of the guest leaves, not the idle rule. spill_cpu_cap is its current answer (pool_mu);
     * spill_batch the rows one spill mint makes (<= the refill batch), the most a minter runs past a cap cut. */
    bool       spill_cpu_on, spill_cpu_running;
    double     spill_cpu_headroom;
    int        spill_cpu_ms, spill_cpu_cap, spill_batch;
    pthread_t  spill_cpu_thread;
    /* Minting's own thread CPU, so the governor does not count it as load: finished batches in
     * spill_mint_cpu_ns, running ones from their thread's clock (pool_mu). */
    uint64_t   spill_mint_cpu_ns;
    struct { clockid_t clock; uint64_t t0; bool active; } spill_mt[128];
    int        spill_mt_n;
    double     spill_last_take;             /* now_ms() of the request path's last take */
    double     spill_t0;                    /* attach time, for the "full" line */
    bool       spill_full_said;
    uint8_t   *spill_io;                    /* the request path's I/O buffer */
    uint64_t   spill_written, spill_imported, spill_onpath, spill_failed;
    uint64_t   spill_said, spill_said_onpath;   /* imports already reported */
    /* The gauge (sh_spill_gauge_read), under pool_mu. Kept here rather than
     * read off the groups, which a registration reallocates without pool_mu. */
    bool       spill_g_on;
    uint32_t   spill_g_groups;
    uint64_t   spill_g_ready, spill_g_cap, spill_g_row_bytes, spill_g_bytes;

    uint64_t   exchanges, macs, verify_fail, pads_used, pads_missed;
    sh_link_profile profile; /* caller-owned, independent of every other link */
    /* Background importers publish this monotonic latch atomically. Keep it
     * separate from the caller-owned remote-product counter. Never reset it
     * when stopping/restarting refill threads or reconnecting the socket. */
    bool       pad_integrity_failed;
    uint64_t   pads_waited;
    double     pad_wait_ms;
    double     last_wire_us;
    char       transport[192];
    char       err[256];
};

static bool sh_integrity_failed(const sh_link *l) {
    return l && (l->verify_fail || __atomic_load_n(&l->pad_integrity_failed, __ATOMIC_ACQUIRE));
}

static int dealt_reserve(sh_link *l, uint64_t *lo, uint64_t *hi);   /* dealt pads: below, after the refill loop */
static void spill_drop(sh_link *l);                                 /* the disk tier: below, after the refill picker */
static void dealt_advanced(sh_link *l);
static void dealt_receipt(sh_link *l);
const char *sh_link_transport(const sh_link *l) { return l && l->transport[0] ? l->transport : "not connected"; }
int sh_link_set_rcvlowat(sh_link *l, int cap, uint64_t *buffer_bytes) {
    return l ? sh_pipe_set_rcvlowat(l->pipe, cap, buffer_bytes) : SH_ERR_IO;
}
int sh_link_set_rcvbuf(sh_link *l, int bytes, uint64_t *actual_bytes) {
    return l ? sh_pipe_set_rcvbuf(l->pipe, bytes, actual_bytes) : SH_ERR_IO;
}
double sh_link_last_wire_us(const sh_link *l) { return l ? l->last_wire_us : 0.0; }
void sh_link_wire_timing(const sh_link *l, sh_wire_timing *out) {
    sh_sp_dump("tee");
    sh_pipe_wire_timing(l ? l->pipe : NULL, out);
    if (l && out && out->peak.metadata_valid && out->peak.first_node < l->n_nodes)
        snprintf(out->peak.first_node_name, sizeof out->peak.first_node_name, "%s", l->nodes[out->peak.first_node].name);
}

const char *sh_link_last_error(const sh_link *l) { return l ? l->err : ""; }

void sh_link_stats(const sh_link *l, uint64_t *e, uint64_t *m, uint64_t *v) {
    if (!l) return;
    if (e) *e = l->exchanges;
    if (m) *m = l->macs;
    if (v) *v = l->verify_fail + (uint64_t)__atomic_load_n(&l->pad_integrity_failed, __ATOMIC_ACQUIRE);
}
void sh_link_set_idle_work(sh_link *l, void (*fn)(void *), void *ctx) {
    if (!l) return;
    l->idle_fn = fn; l->idle_ctx = ctx;
}
void sh_link_profile_snapshot(const sh_link *l, sh_link_profile *out) {
    if (!out) return;
    *out = l ? l->profile : (sh_link_profile){0};
    /* The idle spin lives on the pipe, not the link: it is measured where the
     * waiting happens. Folded in here so one snapshot answers "how much window
     * is left" without a second accessor at every call site. */
    if (l) { out->idle_ms = (double)l->idle.total_ns / 1e6; out->idle_n = l->idle.total_n; }
}
void sh_link_pool_stats(const sh_link *l, uint64_t *consumed, uint64_t *missed) {
    if (!l) return;
    if (consumed) *consumed = l->pads_used;
    if (missed) *missed = l->pads_missed;
}
void sh_link_pad_wait_stats(const sh_link *l, uint64_t *waited, double *wait_ms) {
    if (waited) *waited = l ? l->pads_waited : 0;
    if (wait_ms) *wait_ms = l ? l->pad_wait_ms : 0;
}
void sh_link_node_pool_stats(const sh_link *l, int node, uint64_t *consumed,
                             uint64_t *missed, double *on_path_ms) {
    const sh_group *g = l && node >= 0 && (size_t)node < l->n_nodes
                      ? &l->groups[l->nodes[node].group] : NULL;
    if (consumed) *consumed = g ? g->pads_used : 0;
    if (missed) *missed = g ? g->pads_missed : 0;
    if (on_path_ms) *on_path_ms = g ? g->on_path_ms : 0;
}
int sh_link_refill_threads(const sh_link *l) { return l ? l->n_threads : 0; }
void sh_link_spill_stats(sh_link *l, sh_link_spill *out) {
    if (!out) return;
    memset(out, 0, sizeof *out);
    if (!l) return;
    pthread_mutex_lock(&l->pool_mu);
    out->attached = l->spill != NULL;
    out->off = l->spill_off;
    out->slots = l->spill_slots;
    out->rows = l->spill ? UINT64_MAX : 0;
    for (size_t i = 0; l->spill && i < l->n_groups; i++)
        if (l->groups[i].sp_count < out->rows) out->rows = l->groups[i].sp_count;
    if (out->rows == UINT64_MAX) out->rows = 0;
    out->written = l->spill_written; out->imported = l->spill_imported;
    out->onpath = l->spill_onpath; out->failed = l->spill_failed;
    pthread_mutex_unlock(&l->pool_mu);
}

/* Open links, for sh_spill_gauge_read. Order: gauge_mu, then a pool_mu. */
#define SH_GAUGE_LINKS 16
static pthread_mutex_t gauge_mu = PTHREAD_MUTEX_INITIALIZER;
static sh_link *gauge_links[SH_GAUGE_LINKS];
static void gauge_add(sh_link *l) {
    pthread_mutex_lock(&gauge_mu);
    for (int i = 0; i < SH_GAUGE_LINKS; i++) if (!gauge_links[i]) { gauge_links[i] = l; break; }
    pthread_mutex_unlock(&gauge_mu);
}
static void gauge_remove(sh_link *l) {
    pthread_mutex_lock(&gauge_mu);
    for (int i = 0; i < SH_GAUGE_LINKS; i++) if (gauge_links[i] == l) gauge_links[i] = NULL;
    pthread_mutex_unlock(&gauge_mu);
}
void sh_spill_gauge_read(sh_spill_gauge *out) {
    if (!out) return;
    memset(out, 0, sizeof *out);
    const double now = now_ms();
    bool any = false;
    pthread_mutex_lock(&gauge_mu);
    for (int i = 0; i < SH_GAUGE_LINKS; i++) {
        sh_link *l = gauge_links[i];
        if (!l) continue;
        out->links++;
        pthread_mutex_lock(&l->pool_mu);
        if (l->spill_g_on && !l->spill_off && l->spill_g_groups) {
            const uint64_t rows = l->spill_g_ready / l->spill_g_groups;
            const uint64_t room = l->spill_g_cap / l->spill_g_groups;
            const double quiet = now - l->spill_last_take;
            const uint64_t q = quiet > 0 ? (uint64_t)quiet : 0;
            out->rows = any && out->rows < rows ? out->rows : rows;
            out->rows_cap = any && out->rows_cap < room ? out->rows_cap : room;
            out->quiet_ms = any && out->quiet_ms < q ? out->quiet_ms : q;
            out->idle_ms = (uint64_t)l->spill_idle_ms;
            out->attached++; any = true;
            out->capacity += l->spill_g_cap; out->ready += l->spill_g_ready;
            out->minters += (uint32_t)l->spill_minters;
            out->row_bytes += l->spill_g_row_bytes; out->bytes += l->spill_g_bytes;
        }
        out->written += l->spill_written; out->imported += l->spill_imported;
        out->onpath += l->spill_onpath; out->failed += l->spill_failed;
        pthread_mutex_unlock(&l->pool_mu);
    }
    pthread_mutex_unlock(&gauge_mu);
}

const char *sh_link_refill_priority(const sh_link *l) { return l && l->refill_cost_priority ? "cost" : "deficit"; }
int sh_link_reply_width(const sh_link *l) { return l && l->pipe ? l->ywidth : 0; }

static int env_int(const char *name, int dflt, int lo, int hi) {
    const char *e = getenv(name);
    if (!e || !*e) return dflt;
    int v = atoi(e);
    return v < lo ? lo : v > hi ? hi : v;
}

sh_link *sh_link_open(const char *host, int port, bool verify, int *err) {
    sh_link *l = (sh_link *)calloc(1, sizeof *l);
    if (!l) { if (err) *err = SH_ERR_NOMEM; return NULL; }
    snprintf(l->host, sizeof l->host, "%s", host);
    l->port = port; l->verify = verify; l->ywidth = 4;
    l->overlap_verify = env_int("SHIELDED_OVERLAP_VERIFY", 0, 0, 1) != 0;
    l->vsock_port = env_int("SHIELDED_VSOCK_PORT", -1, -1, 1 << 30);
    const char *r = getenv("SHIELDED_RESERVE_BYTES");
    if (r && *r) { char *end = NULL; unsigned long long v = strtoull(r, &end, 10); if (end && *end == 0) l->reserve_bytes = v; }
    l->simd = sh_simd_get();
    if (!maskbank_init(&l->bank)) { free(l); if (err) *err = SH_ERR_IO; return NULL; }
    pthread_mutex_init(&l->pool_mu, NULL);
    pthread_cond_init(&l->need_refill, NULL);
    pthread_condattr_t filled_attr;
    pthread_condattr_init(&filled_attr);
    pthread_condattr_setclock(&filled_attr, CLOCK_MONOTONIC);
    pthread_cond_init(&l->pool_filled, &filled_attr);
    pthread_condattr_destroy(&filled_attr);
    l->threads_env  = env_int("SHIELDED_REFILL_THREADS", -1, 0, 64);
    l->pool_depth   = env_int("SHIELDED_POOL_DEPTH", -1, -1, 4096);   /* -1: 4 x the widest max_m, within [16, 32] */
    l->refill_batch = env_int("SHIELDED_REFILL_BATCH", 4, 1, 64);
    /* The refill unit (pick_refill_group): a group short of this many pads is
     * refilled at once, one missing at least this many is topped up. Bounded
     * by the batch, so the default batch of 4 is untouched. With a 64-row
     * batch and a 64-deep pool on the 27B (2026-09-21, k = 3 drafting):
     * unit 8 -> 8.4 plain / 10.0 spec tok/s, 16 -> 9.2 / 11.0, 32 -> 9.2 /
     * 10.9 with pads starting to miss. 16 streams the weights once per 16
     * pads; a pool should hold at least twice the unit. */
    l->refill_unit  = env_int("SHIELDED_REFILL_UNIT", 16, 1, 64);
    l->target_ms    = env_int("SHIELDED_REFILL_TARGET_MS", 6, 1, 10000);
    l->warm_ms      = env_int("SHIELDED_WARM_MS", 5000, 0, 600000);
    l->pad_wait_us  = env_int("SHIELDED_PAD_WAIT_US", 0, 0, 50000);
    /* Dealt mode: all four are required together, or the link refuses to open
     * rather than silently minting its own pads. */
    const char *pad_dir = getenv("SHIELDED_PAD_SOURCE");
    if (pad_dir && *pad_dir) {
        const char *ledger = getenv("SHIELDED_PAD_LEDGER");
        snprintf(l->pad_dir, sizeof l->pad_dir, "%s", pad_dir);
        snprintf(l->pad_ledger, sizeof l->pad_ledger, "%s", ledger && *ledger ? ledger : "");
        /* The ledger path may be empty when the host installs a window
         * provider before start (sh_link_set_window_provider); start_pools
         * refuses to run with neither. */
        const bool ok = sh_pads_hex2bin(getenv("SHIELDED_PAD_SEED"), l->pad_seed, 32)
                     && sh_pads_hex2bin(getenv("SHIELDED_PAD_SEED_ID"), l->pad_seed_id, 16)
                     && sh_pads_hex2bin(getenv("SHIELDED_PAD_SK"), l->pad_sk, 32);
        if (!ok) {
            pthread_mutex_destroy(&l->pool_mu); pthread_cond_destroy(&l->need_refill); pthread_cond_destroy(&l->pool_filled);
            pthread_mutex_destroy(&l->bank.mu);
            free(l); if (err) *err = SH_ERR_RANGE; return NULL;
        }
        l->dealt = true;
        sh_pads_bin2hex(l->pad_seed_id, 16, l->pad_seed_id_hex);
        l->pad_window  = (uint64_t)env_int("SHIELDED_PAD_WINDOW", 64, 1, 1 << 20);
        l->pad_bank_wait_ms = env_int("SHIELDED_PAD_WAIT_MS", 10000, 0, 600000);
        /* An http:// source is a bank: shipments are fetched into a local
         * cache (SHIELDED_PAD_CACHE, default under /tmp) that the reader
         * scans; spent files are unlinked there since the copy is ours. */
        if (!strncmp(pad_dir, "http://", 7)) {
            snprintf(l->bank_url, sizeof l->bank_url, "%s", pad_dir);
            const char *cache = getenv("SHIELDED_PAD_CACHE");
            if (cache && *cache) snprintf(l->pad_dir, sizeof l->pad_dir, "%s", cache);
            else snprintf(l->pad_dir, sizeof l->pad_dir, "/tmp/shielded-pads-%s", l->pad_seed_id_hex);
            l->bank_cache_max = (uint64_t)env_int("SHIELDED_PAD_CACHE_MB", 2048, 64, 1 << 20) << 20;
        }
        l->pad_prune = env_int("SHIELDED_PAD_PRUNE", l->bank_url[0] ? 1 : 0, 0, 1) != 0;
        const char *wurl = getenv("SHIELDED_PAD_WINDOW_URL"), *wpk = getenv("SHIELDED_PAD_LEDGER_PK");
        if (wurl && *wurl) {
            if (strncmp(wurl, "http://", 7) || !wpk || !sh_pads_hex2bin(wpk, l->win_pk, 32)) {
                pthread_mutex_destroy(&l->pool_mu); pthread_cond_destroy(&l->need_refill); pthread_cond_destroy(&l->pool_filled);
                pthread_mutex_destroy(&l->bank.mu);
                free(l); if (err) *err = SH_ERR_RANGE; return NULL;      /* a window URL without the ledger key is refused */
            }
            snprintf(l->win_url, sizeof l->win_url, "%s", wurl);
            l->have_win_pk = true;
            const char *tok = getenv("SHIELDED_PAD_AGENT_TOKEN");
            if (tok && *tok) sh_http_set_bearer(tok);      /* the agent's per-boot token: our windows and receipts, nobody else's */
        }
    }
    l->refill_cost_priority = env_int("SHIELDED_REFILL_COST_PRIORITY", 0, 0, 1);
    /* The dealer minting through its OWN worker: every pad is zero, so the
     * "masked" planes carry x itself. Never a tenant's setting - the wasm
     * manager does not know this name, and the link says so loudly. */
#ifdef SHIELDED_DEALER_MODE
    l->zero_pads = env_int("SHIELDED_ZERO_PADS", 0, 0, 1) != 0;
#else
    l->zero_pads = false;                       /* not a thing outside the dealer's own build */
#endif
    if (l->zero_pads) {
        /* The product check assumes |x.W| < M/2 (true for encoded activations,
         * never for a 24-bit mask row); the mint checks u = r.W mod M itself
         * with the pad-check vectors instead. */
        l->verify = false;
        fprintf(stderr, "[shielded] SHIELDED_ZERO_PADS: activations go to %s:%d UNMASKED, products checked mod M by the mint (dealer mode)\n", host ? host : "?", port);
    }
    gauge_add(l);
    if (err) *err = SH_OK;
    return l;
}

void sh_link_configure(sh_link *l, int vsock_port, uint64_t reserve_bytes, int refill_threads) {
    if (!l || l->pipe || l->threads_running) return;
    l->vsock_port = vsock_port;
    l->reserve_bytes = reserve_bytes;
    if (refill_threads >= 0 && refill_threads <= 64) l->threads_env = refill_threads;
}

void sh_link_configure_shm(sh_link *l, const char *path, uint64_t bytes) {
    if (!l || l->pipe || l->threads_running) return;
    l->shm_configured = true;
    l->shm_path[0] = 0; l->shm_bytes = 0;
    if (!path || !*path || strlen(path) >= sizeof l->shm_path ||
        bytes < SH_RING_BYTES || bytes > SH_RING_MAX_FILE) return;
    snprintf(l->shm_path, sizeof l->shm_path, "%s", path);
    l->shm_bytes = (size_t)bytes;
}

static void stop_threads(sh_link *l) {
    if (!l->threads_running) return;
    pthread_mutex_lock(&l->pool_mu);
    l->stop = true;
    pthread_cond_broadcast(&l->need_refill);
    pthread_cond_broadcast(&l->pool_filled);
    pthread_mutex_unlock(&l->pool_mu);
    for (int i = 0; i < l->n_threads; i++) pthread_join(l->threads[i], NULL);
    if (l->spill_cpu_running) { pthread_join(l->spill_cpu_thread, NULL); l->spill_cpu_running = false; }
    free(l->threads); l->threads = NULL;
    l->threads_running = false; l->stop = false;
}

static void free_pools(sh_link *l) {
    for (size_t g = 0; g < l->n_groups; g++) {
        free(l->groups[g].r_store); free(l->groups[g].u_store); free(l->groups[g].ready);
        l->groups[g].r_store = NULL; l->groups[g].u_store = NULL; l->groups[g].ready = NULL;
        l->groups[g].count = l->groups[g].head = l->groups[g].generating = l->groups[g].held = 0;
    }
}

void sh_link_quiesce(sh_link *l) {
    if (!l) return;
    stop_threads(l);
    free_pools(l);
    sh_pipe_close(l->pipe); l->pipe = NULL;
}

static void node_free_checks(sh_node *nd) {
    free(nd->s); free(nd->s_tilde); free(nd->s32); free(nd->st32);
    free(nd->sM); free(nd->stM);
    nd->s = nd->s_tilde = NULL; nd->s32 = nd->st32 = nd->sM = nd->stM = NULL;
}

void sh_link_close(sh_link *l) {
    if (!l) return;
    gauge_remove(l);
    stop_threads(l);
    if (l->dealt && l->win_url[0]) dealt_receipt(l);      /* the last window's usage, before the counters go */
    spill_drop(l);
    free_pools(l);
    for (size_t i = 0; i < l->n_nodes; i++) {
        node_free_checks(&l->nodes[i]);
    }
    free(l->nodes); free(l->groups);
    free(l->rp); free(l->up); free(l->slots);
    free(l->r); free(l->u); free(l->planes); free(l->gplanes); free(l->acc); free(l->hdr);
    free(l->fv_rhs);
    sh_pipe_close(l->pipe);
    sh_bank_close(l->padbank);
    sh_pads_reader_close(l->pads);
    pthread_mutex_destroy(&l->pool_mu); pthread_cond_destroy(&l->need_refill); pthread_cond_destroy(&l->pool_filled);
    pthread_mutex_destroy(&l->bank.mu);
    memset(l->pad_seed, 0, sizeof l->pad_seed); memset(l->pad_sk, 0, sizeof l->pad_sk);
    free(l);
}


/* fv_prepare over row ranges on several threads: the products of the ranges
 * are independent and sum mod P2. On the streamed path registration is driven
 * from sh_plan during graph compute. The count follows the machine, not the
 * pool policy. */
typedef struct { const sh_simd *simd; const int8_t *W; int64_t K, N; const int64_t *s; int reps; int64_t *st; } fv_job;
static void *fv_job_main(void *arg) { fv_job *j = (fv_job *)arg; j->simd->fv_prepare(j->W, j->K, j->N, j->s, j->reps, j->st); return NULL; }
static void fv_prepare_parallel(sh_link *l, const int8_t *W, int64_t K, int64_t N, const int64_t *s, int reps, int64_t *st) {
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    int nt = ncpu > 1 ? (int)(ncpu > 16 ? 16 : ncpu) : 1;
    if (N < 64 || (int64_t)nt * 8 > N) nt = 1;
    if (nt == 1) { l->simd->fv_prepare(W, K, N, s, reps, st); return; }
    fv_job *jobs = (fv_job *)calloc((size_t)nt, sizeof *jobs);
    pthread_t *th = (pthread_t *)calloc((size_t)nt, sizeof *th);
    int64_t *part = (uint64_t)K > SIZE_MAX / ((size_t)nt * reps * sizeof(int64_t)) ? NULL :
        (int64_t *)malloc((size_t)nt * K * reps * sizeof(int64_t));
    if (!jobs || !th || !part) { free(jobs); free(th); free(part); l->simd->fv_prepare(W, K, N, s, reps, st); return; }
    bool made[16] = {false};
    for (int t = 0; t < nt; t++) {
        const int64_t j0 = N * t / nt, j1 = N * (t + 1) / nt;
        jobs[t] = (fv_job){ l->simd, W + j0 * K, K, j1 - j0, s + j0 * reps, reps, part + (size_t)t * K * reps };
        if (sh_thread_create(&th[t], fv_job_main, &jobs[t]) == 0) made[t] = true; else fv_job_main(&jobs[t]);
    }
    for (int t = 0; t < nt; t++) if (made[t]) pthread_join(th[t], NULL);
    for (int64_t i = 0; i < K * reps; i++) {
        int64_t v = 0;
        for (int t = 0; t < nt; t++) v = (v + part[(size_t)t * K * reps + i]) % SH_FV_P2;
        st[i] = v;
    }
    free(jobs); free(th); free(part);
}

static int fv_prepare(sh_link *l, sh_node *nd) {
    const int64_t K = nd->K, N = nd->N;
    nd->s       = (int64_t *)malloc((size_t)N * SH_FV_REPS * sizeof(int64_t));
    nd->s_tilde = (int64_t *)malloc((size_t)K * SH_FV_REPS * sizeof(int64_t));
    nd->s32     = (int32_t *)malloc((size_t)N * SH_FV_REPS * sizeof(int32_t));
    nd->st32    = (int32_t *)malloc((size_t)K * SH_FV_REPS * sizeof(int32_t));
    if (!nd->s || !nd->s_tilde || !nd->s32 || !nd->st32) return SH_ERR_NOMEM;
    /* s from the OS CSPRNG. Predictable s == forgeable results; see rule 4. */
    uint64_t *raw = (uint64_t *)malloc((size_t)N * SH_FV_REPS * sizeof(uint64_t));
    if (!raw) return SH_ERR_NOMEM;
    if (!os_random(raw, (size_t)N * SH_FV_REPS * sizeof(uint64_t))) { free(raw); return SH_ERR_IO; }
    for (int64_t i = 0; i < N * SH_FV_REPS; i++)
        nd->s[i] = 1 + (int64_t)(raw[i] % (uint64_t)(SH_FV_S_RANGE - 1));
    free(raw);
    fv_prepare_parallel(l, nd->w, K, N, nd->s, SH_FV_REPS, nd->s_tilde);
    /* s < 2^20 and s_tilde < P2 < 2^31: both fit the int32 rows every
     * verification path reads, including sh_link_verify. The interleaved
     * preparation arrays are no longer needed once those rows are complete. */
    fv_rows_i32(nd->s, SH_FV_REPS, N, nd->s32);
    fv_rows_i32(nd->s_tilde, SH_FV_REPS, K, nd->st32);
    /* Dealt links import pads and never run compact refill. Releasing these
     * temporaries there saves retained memory. Keep the local-mint allocation
     * layout: freeing them early regressed compact refill in paired benchmarks. */
    if (l->dealt) {
        free(nd->s); free(nd->s_tilde);
        nd->s = nd->s_tilde = NULL;
    }
    return SH_OK;
}

/* Pad verification is requested explicitly by the trusted configuration. A
 * failed allocation or entropy read must fail registration, never disable it. */
static int pad_check_prepare(sh_node *nd) {
    const int64_t K = nd->K, N = nd->N;
    nd->sM = (int32_t *)malloc((size_t)N * sizeof(int32_t));
    nd->stM = (int32_t *)calloc((size_t)K, sizeof(int32_t));
    if (!nd->sM || !nd->stM) return SH_ERR_NOMEM;
    uint64_t raw[256];
    for (int64_t at = 0; at < N;) {
        const size_t n = (size_t)(N - at < 256 ? N - at : 256);
        if (!os_random(raw, n * sizeof *raw)) return SH_ERR_IO;
        for (size_t i = 0; i < n; i++) nd->sM[at++] = 1 + (int32_t)(raw[i] % (SH_FV_S_RANGE - 1));
    }
    const char *tiled = getenv("SHIELDED_PAD_PREPARE_TILED");
    const int use_tiled = tiled && !strcmp(tiled, "1");
    /* Default off: an absent SHIELDED_PAD_PREPARE_THREADS leaves both serial
     * paths below exactly as they were. A malformed value fails registration
     * rather than quietly selecting a different preparation policy. */
    int prepare_threads = 1;
    if (sh_pad_par_parse_threads(getenv("SHIELDED_PAD_PREPARE_THREADS"), &prepare_threads) != SH_PAD_PAR_OK)
        return SH_ERR_PROTO;
    /* Diagnostic only, default off. It changes no arithmetic and no policy: it
     * reports what the existing policy already decided. Malformed value fails
     * registration rather than being read as "profiling was off". */
    int prepare_profile = 0;
    if (sh_pad_par_parse_flag(getenv("SHIELDED_PAD_PREPARE_PROFILE"), &prepare_profile) != SH_PAD_PAR_OK)
        return SH_ERR_PROTO;
    sh_pad_par_stats pstats;
    if (prepare_threads > 1) {
        /* Disjoint column ranges of stM; every worker is joined before return. */
        sh_pad_check_prepare_dispatch(nd->w, K, N, nd->sM, nd->stM, use_tiled, prepare_threads,
                                      prepare_profile ? &pstats : NULL);
        if (prepare_profile) sh_pad_par_report(&pstats, nd->name, use_tiled);
        return SH_OK;
    }
    if (use_tiled) {
        sh_pad_check_tiled(nd->w, K, N, nd->sM, nd->stM);
        if (prepare_profile) {
            sh_pad_par_stats_serial(&pstats, prepare_threads, K, N);
            sh_pad_par_report(&pstats, nd->name, use_tiled);
        }
        return SH_OK;
    }
    for (int64_t k = 0; k < K; k++) nd->stM[k] = (int32_t)sh_dot_mod_i8(nd->w + k, K, nd->sM, N, SH_M_MOD);
    if (prepare_profile) {
        sh_pad_par_stats_serial(&pstats, prepare_threads, K, N);
        sh_pad_par_report(&pstats, nd->name, use_tiled);
    }
    return SH_OK;
}

int sh_link_add_weight(sh_link *l, const char *name, const int8_t *w_fixed,
                       int64_t K, int64_t N, int32_t max_m, int share_x_with) {
    if (sh_integrity_failed(l)) return SH_ERR_VERIFY;
    if (!l || !name || !*name || strlen(name) >= sizeof(((sh_node *)0)->name) || !w_fixed ||
        K <= 0 || N <= 0 || max_m <= 0 || l->n_nodes >= INT_MAX || l->n_groups >= INT_MAX ||
        (uint64_t)K > SIZE_MAX / (SH_FV_REPS * sizeof(int64_t)) ||
        (uint64_t)N > SIZE_MAX / (SH_FV_REPS * sizeof(int64_t)) ||
        K > INT64_MAX / N || (uint64_t)K > SIZE_MAX / (uint64_t)N) return SH_ERR_RANGE;
    if (K % SH_QK != 0 || K % 16 != 0) {
        snprintf(l->err, sizeof l->err, "K=%lld not a multiple of %d", (long long)K, SH_QK); return SH_ERR_PROTO;
    }
    if (share_x_with >= 0) {
        if ((size_t)share_x_with >= l->n_nodes) { snprintf(l->err, sizeof l->err, "share_x_with out of range"); return SH_ERR_PROTO; }
        const sh_group *g = &l->groups[l->nodes[share_x_with].group];
        if (g->K != K || g->n_nodes >= SH_GROUP_MAX || g->u_len > INT64_MAX - N) {
            snprintf(l->err, sizeof l->err, "node %zu cannot share x with %d", l->n_nodes, share_x_with);
            return SH_ERR_PROTO;
        }
    }
    /* Check aligned byte offsets before reading weights or publishing a node. */
    if (l->wbytes < 0 || l->abytes < 0 || l->wbytes > INT64_MAX - SH_ALIGN || l->abytes > INT64_MAX - SH_ALIGN) return SH_ERR_RANGE;
    const bool profile_registration = getenv("SHIELDED_PROFILE") != NULL;
    const double tp0 = profile_registration ? now_ms() : 0;
    sh_node staged = {0}; sh_node *nd = &staged;
    nd->w_off = align_up(l->wbytes); nd->x_off = align_up(l->abytes);
    uint64_t t1, t2, yoff, ab, wb;   /* overflow-checked 64-bit arithmetic (shielded-wide.h): the same bound the wide form checked */
    if (max_m < 0 || K < 0 || N < 0 || nd->x_off < 0 || nd->w_off < 0) return SH_ERR_RANGE;
    if (sh_mul_u64(3 * (uint64_t)max_m, (uint64_t)K, &t1) || sh_add_u64((uint64_t)nd->x_off, t1, &t2) || sh_add_u64(t2, SH_ALIGN - 1, &yoff)) return SH_ERR_RANGE;
    yoff &= ~(uint64_t)(SH_ALIGN - 1);
    if (sh_mul_u64((uint64_t)max_m, (uint64_t)N, &t1) || sh_mul_u64(t1, 4, &t2) || sh_add_u64(yoff, t2, &ab)) return SH_ERR_RANGE;
    if (sh_mul_u64((uint64_t)K, (uint64_t)N, &t1) || sh_add_u64((uint64_t)nd->w_off, t1, &wb)) return SH_ERR_RANGE;
    if (ab > (uint64_t)INT64_MAX || wb > (uint64_t)INT64_MAX) return SH_ERR_RANGE;
    nd->y_off = (int64_t)yoff;
    snprintf(nd->name, sizeof nd->name, "%s", name);
    nd->w = w_fixed; nd->K = K; nd->N = N; nd->max_m = max_m;

    {   /* A min/max scan vectorises; values outside the byte lane wrap at the worker. */
        int lo = 0, hi = 0;
        for (int64_t i = 0; i < K * N; i++) { const int v = w_fixed[i]; lo = v < lo ? v : lo; hi = v > hi ? v : hi; }
        if (hi > SH_WEIGHT_BYTE_LIMIT || lo < -SH_WEIGHT_BYTE_LIMIT) {
            snprintf(l->err, sizeof l->err, "%s: fixed weight %d exceeds the int8 lane (+-%d)",
                     name, hi > SH_WEIGHT_BYTE_LIMIT ? hi : lo, SH_WEIGHT_BYTE_LIMIT);
            return SH_ERR_RANGE;
        }
    }
    /* A post-start registration changes refill strides. Stop and discard the
     * old rings before reallocating; discarded pads are never reissued. */
    if (l->threads_running) { stop_threads(l); free_pools(l); }
    if (l->n_nodes == l->cap_nodes) {
        size_t cap = l->cap_nodes ? l->cap_nodes * 2 : 16;
        if (cap < l->cap_nodes || cap > SIZE_MAX / sizeof(sh_node)) return SH_ERR_RANGE;
        sh_node *nn = (sh_node *)realloc(l->nodes, cap * sizeof *nn);
        if (!nn) return SH_ERR_NOMEM;
        l->nodes = nn; l->cap_nodes = cap;
    }
    if (share_x_with < 0 && l->n_groups == l->cap_groups) {
        size_t cap = l->cap_groups ? l->cap_groups * 2 : 16;
        if (cap < l->cap_groups || cap > SIZE_MAX / sizeof(sh_group)) return SH_ERR_RANGE;
        sh_group *ng = (sh_group *)realloc(l->groups, cap * sizeof *ng);
        if (!ng) return SH_ERR_NOMEM;
        l->groups = ng; l->cap_groups = cap;
    }
    const double t_scan = profile_registration ? now_ms() : 0;
    int rc = SH_OK;
    if (l->verify) rc = fv_prepare(l, nd);
    const double t_fv = profile_registration ? now_ms() : 0;
    const char *pad_check = getenv("SHIELDED_PAD_CHECK");
    if (rc == SH_OK && pad_check && *pad_check && strcmp(pad_check, "0")) rc = pad_check_prepare(nd);
    if (rc != SH_OK) {
        node_free_checks(nd);
        snprintf(l->err, sizeof l->err, "%s: verification setup failed (%d)", name, rc);
        return rc;
    }
    const double t_pad = profile_registration ? now_ms() : 0;
    const char *public_cache = getenv("SHIELDED_PUBLIC_WEIGHT_CACHE");
    if (l->verify && public_cache && !strcmp(public_cache, "1")) {
        sha256_ctx sha; sha_init(&sha);
        sha_update(&sha, (const uint8_t *)nd->w, (size_t)(K*N));
        sha_final(&sha, nd->public_digest); nd->public_digest_ready = true;
    }

    const double t_identity = profile_registration ? now_ms() : 0;
    /* Commit only after both verification setups succeed. Failure leaves the
     * existing group memberships, offsets and node counts unchanged. */
    if (share_x_with >= 0) {
        sh_group *g = &l->groups[l->nodes[share_x_with].group];
        nd->group = l->nodes[share_x_with].group; nd->u_off = g->u_len;
        g->nodes[g->n_nodes++] = (int)l->n_nodes; g->u_len += N;
        if (max_m < g->max_m) g->max_m = max_m;
    } else {
        sh_group *g = &l->groups[l->n_groups]; memset(g, 0, sizeof *g);
        g->K = K; g->nodes[0] = (int)l->n_nodes; g->n_nodes = 1; g->u_len = N; g->max_m = max_m;
        nd->group = (int)l->n_groups++;
    }
    l->wbytes = (int64_t)wb; l->abytes = (int64_t)ab;
    if (K > l->Kmax) l->Kmax = K;
    if (N > l->Nmax) l->Nmax = N;
    if (l->groups[nd->group].u_len > l->ulen_max) l->ulen_max = l->groups[nd->group].u_len;
    l->nodes[l->n_nodes] = staged;
    const int node = (int)l->n_nodes++;
    if (profile_registration) {
        const double t_done = now_ms();
        fprintf(stderr, "[shielded] profile registration checks %s: scan_alloc=%.3fms fv=%.3fms "
                        "pad=%.3fms public_identity=%.3fms commit=%.3fms total=%.3fms\n",
                name, t_scan - tp0, t_fv - t_scan, t_pad - t_fv,
                t_identity - t_pad, t_done - t_identity, t_done - tp0);
    }
    return node;
}

int sh_link_set_weight_reader(sh_link *l, int node, sh_weight_read_fn reader, void *ctx) {
    if (!l || !reader || !ctx || node < 0 || (size_t)node >= l->n_nodes ||
        !l->dealt || !l->verify || l->pipe || l->threads_running) return SH_ERR_RANGE;
    sh_node *nd = &l->nodes[node];
    if (!nd->w || nd->w_read || !nd->sM || !nd->stM) return SH_ERR_RANGE;
    nd->w_read = reader; nd->w_ctx = ctx; nd->w = NULL;
    return SH_OK;
}

int sh_link_set_local_weight_source(sh_link *l, int node, sh_weight_read_fn reader,
                                    sh_weight_refill_fn refill, void *ctx) {
    if (!l || !reader || !refill || !ctx || node < 0 || (size_t)node >= l->n_nodes ||
        l->dealt || !l->verify || l->pipe || l->threads_running) return SH_ERR_RANGE;
    sh_node *nd = &l->nodes[node];
    if (!nd->w || nd->w_read || nd->w_refill || !nd->s32 || !nd->st32) return SH_ERR_RANGE;
    nd->w_read = reader; nd->w_refill = refill; nd->w_ctx = ctx; nd->w = NULL;
    return SH_OK;
}

/* ---------------------------------------------------------------------------
 * Pad generation: r from the bank, u = r.W for every node of the group.
 * Runs on the refill threads, and on the request path only when the pool is
 * dry (counted, because that number should be ~0 in steady state).
 * ------------------------------------------------------------------------ */
typedef struct {
    uint8_t *planes; int32_t *acc;
} gen_scratch;

static int gen_scratch_init(const sh_link *l, gen_scratch *s, int b) {
    /* Providers own their scratch; only the native branch of generate_products
     * uses these buffers. Registration is frozen while refill/mint workers run,
     * so size once for the native nodes instead of the whole link's maxima. */
    int64_t K = 0, N = 0;
    for (size_t i = 0; i < l->n_nodes; i++) {
        const sh_node *nd = &l->nodes[i];
        if (!nd->w || nd->w_refill) continue;
        if (nd->K > K) K = nd->K;
        if (nd->N > N) N = nd->N;
    }
    s->planes = NULL; s->acc = NULL;
    if (!K) return SH_OK;
    s->planes = (uint8_t *)malloc((size_t)3 * b * K);
    s->acc    = (int32_t *)malloc((size_t)12 * N * sizeof(int32_t));
    if (s->planes && s->acc) return SH_OK;
    free(s->planes); free(s->acc); s->planes = NULL; s->acc = NULL;   /* half an allocation is not a scratch */
    return SH_ERR_NOMEM;
}

static int generate_products(sh_link *l, const sh_group *g, int b,
                             const int32_t *r, uint8_t *planes,
                             int32_t *u_out, int32_t *acc) {
    bool planes_ready = false;
    for (int i = 0; i < g->n_nodes; i++) {
        const sh_node *nd = &l->nodes[g->nodes[i]];
        if (nd->w_refill) {
            const int rrc = nd->w_refill(nd->w_ctx, r, b, u_out + nd->u_off, g->u_len);
            if (rrc != SH_OK) {
                memset(u_out, 0, (size_t)b * g->u_len * sizeof *u_out);
                __atomic_store_n(&l->pad_integrity_failed, true, __ATOMIC_RELEASE);
                return SH_ERR_VERIFY;
            }
            continue;
        }
        if (!nd->w) return SH_ERR_RANGE; /* compact dealt nodes never mint */
        // Compact providers prepare their own exact representation. Do not
        // also compute and write the unused CRT planes for those groups.
        if (!planes_ready) {
            const size_t n = (size_t)b * g->K;
            l->simd->pad_planes(r, n, planes, planes + n, planes + 2*n);
            planes_ready = true;
        }
        l->simd->refill(planes, b, nd->w, g->K, nd->N, u_out + nd->u_off, g->u_len, acc);
    }
    return SH_OK;
}

static int generate(sh_link *l, const sh_group *g, int b, int32_t *r_out, int32_t *u_out, gen_scratch *s) {
    const int64_t K = g->K;
#ifdef SHIELDED_DEALER_MODE
    if (l->zero_pads) {
        memset(r_out, 0, (size_t)b * K * sizeof *r_out);
        memset(u_out, 0, (size_t)b * g->u_len * sizeof *u_out);
        return SH_OK;
    }
#endif
    int rc = maskbank_issue(&l->bank, r_out, (size_t)b * K);
    if (rc != SH_OK) return rc;
    return generate_products(l, g, b, r_out, s->planes, u_out, s->acc);
}

/* Slots a refill may write: everything that is not ready, held or reserved. */
static int group_deficit(const sh_group *g) { return g->depth - g->count - g->held - g->generating; }

/* Urgent groups always win, lowest ready+reserved count first. Among groups
 * with a full batch missing, the optional cost policy prepares expensive
 * masks earlier: a vocabulary projection otherwise waits behind many small
 * groups until it is nearly empty, then stalls decode on a single-row refill.
 * Eligibility, batch size, ring reservations and one-use pads are unchanged.
 * Cast before multiplying so even large dimensions cannot overflow integers. */
static sh_group *pick_refill_group(sh_link *l, int B, int *deficit) {
    sh_group *best = NULL;
    int best_low = -1;
    double best_score = -1;
    *deficit = 0;
    /* The refill unit is min(B, refill_unit) pads, not the whole batch B. A group with
     * fewer than that coming is LOW and refilled at once with whatever fits;
     * a group missing at least that many is topped up (b = min(deficit, B))
     * even though it is not low. B <= the unit is exactly the old rule. With the
     * batch raised to 64 for prefill on the card (SHIELDED_REFILL_BATCH=64:
     * one weight pass per 64 pads instead of per 4) the old rule made every
     * group with a 64-deep pool permanently low, so each token's single
     * missing pad was minted alone, one weight pass per pad, on every refill
     * thread at once: decode fell from 7.3 to 4.1 tok/s. Waiting for a WHOLE
     * batch instead (an earlier fix) starved prefill: each 64-row chunk found
     * the pool short and minted the shortfall on the request thread, 81 s
     * against 25 s for a 492-token prompt. Eight-at-a-time keeps both: decode
     * refills in 8-row passes, prefill finds the pool topped up. (27B,
     * 2026-09-21.) */
    const int unit = B < l->refill_unit ? B : l->refill_unit;
    for (size_t i = 0; i < l->n_groups; i++) {
        sh_group *c = &l->groups[i];
        const int d = group_deficit(c);
        if (d <= 0) continue;
        const int coming = c->count + c->generating;
        if (coming < unit) {
            if (best_low < 0 || coming < best_low) {
                best = c; *deficit = d; best_low = coming;
            }
        } else if (best_low < 0 && d >= unit) {
            double score = (double)d;
            if (l->refill_cost_priority) score *= (double)c->K * (double)c->u_len;
            if (score > best_score) {
                best = c; *deficit = d; best_score = score;
            }
        }
    }
    return best;
}

/* ---------------------------------------------------------------------------
 * The disk tier (shielded-spill.h). Slot state is in sh_group (sp_*) under
 * pool_mu; the reads, writes and AEAD run outside it, like a refill.
 *
 * Refill threads with no ring to fill mint into the spill once the request
 * path has been quiet for SHIELDED_PAD_SPILL_IDLE_MS (2 s), at most
 * SHIELDED_PAD_SPILL_THREADS at a time (all but one), so a request that
 * arrives finds a thread free for its rings. A ring refill imports from the
 * spill when it holds pads for that group and mints otherwise; a request that
 * finds its ring short imports the shortfall itself before minting on the
 * path. Every pad still serves exactly one exchange.
 * ------------------------------------------------------------------------ */
#define SP_WRITTEN 1
#define SP_READ    2
#define SP_TAKE_MAX 64              /* pads one take moves (the refill batch is at most 64) */

static bool spill_usable(const sh_link *l) { return l->spill && !l->spill_off; }

static uint32_t spill_free(const sh_link *l, const sh_group *g) {
    return l->spill_slots - g->sp_count - g->sp_writing - g->sp_held;
}

/* pool_mu held. In-flight reads and writes finish and retire as usual;
 * nothing new starts, and every ring is then refilled by minting. */
static void spill_fail(sh_link *l, const char *what, int rc) {
    if (l->spill_off) return;
    l->spill_off = true; l->spill_failed++; l->spill_g_on = false;
    fprintf(stderr, "[shielded] pad spill off: %s failed (rc %d); minting every pad from here\n", what, rc);
}

/* The registration a group's spilled pads belong to: its shape and nodes. */
static uint64_t spill_group_fp(const sh_link *l, size_t i) {
    uint64_t h = UINT64_C(1469598103934665603);
#define SP_MIX(v) do { h ^= (uint64_t)(v); h *= UINT64_C(1099511628211); } while (0)
    const sh_group *g = &l->groups[i];
    SP_MIX(i); SP_MIX(g->K); SP_MIX(g->u_len); SP_MIX(g->n_nodes);
    for (int j = 0; j < g->n_nodes; j++) {
        const sh_node *nd = &l->nodes[g->nodes[j]];
        SP_MIX(g->nodes[j]); SP_MIX(nd->K); SP_MIX(nd->N); SP_MIX(nd->u_off);
    }
#undef SP_MIX
    return h;
}

/* Refill threads stopped and no request in flight. */
static void spill_drop(sh_link *l) {
    for (size_t i = 0; i < l->n_groups; i++) {
        sh_group *g = &l->groups[i];
        free(g->sp_flag); free(g->sp_wid); g->sp_flag = NULL; g->sp_wid = NULL;
        g->sp_head = g->sp_count = g->sp_writing = g->sp_held = 0;
    }
    free(l->spill_io); l->spill_io = NULL;
    sh_spill_detach(l->spill); l->spill = NULL; l->spill_slots = 0;
}

/* start_pools, before the refill threads start. Across a re-registration
 * (a weight added after start: the MTP head the first speculative request
 * discovers) every group whose registration is unchanged keeps its spilled
 * pads; a changed or new group starts empty in a region of its own. Only when
 * the partition's headroom cannot hold those is the spill laid out again. */
static void spill_start(sh_link *l) {
    if (l->dealt || l->zero_pads || l->spill_off || !l->n_groups) return;
    const size_t n = l->n_groups;
    int64_t *K = (int64_t *)malloc(n * sizeof *K), *U = (int64_t *)malloc(n * sizeof *U);
    uint64_t *fp = (uint64_t *)malloc(n * sizeof *fp);
    uint8_t *kept = (uint8_t *)calloc(n, 1);
    if (!K || !U || !fp || !kept) { free(K); free(U); free(fp); free(kept); return; }
    for (size_t i = 0; i < n; i++) { K[i] = l->groups[i].K; U[i] = l->groups[i].u_len; fp[i] = spill_group_fp(l, i); }
    if (l->spill) {
        if (sh_spill_extend(l->spill, K, U, fp, n, kept) == SH_OK) {
            size_t same = 0;
            bool ok = true;
            for (size_t i = 0; i < n; i++) {
                sh_group *g = &l->groups[i];
                if (kept[i] && g->sp_flag && g->sp_wid && !g->sp_writing && !g->sp_held) { same++; continue; }
                free(g->sp_flag); free(g->sp_wid);
                g->sp_flag = (uint8_t *)calloc(l->spill_slots, 1);
                g->sp_wid = (uint64_t *)calloc(l->spill_slots, sizeof *g->sp_wid);
                g->sp_head = g->sp_count = g->sp_writing = g->sp_held = 0;
                ok = ok && g->sp_flag && g->sp_wid;
            }
            if (!ok) {
                fprintf(stderr, "[shielded] pad spill off: no memory for %u slots per group\n", l->spill_slots);
                spill_drop(l); l->spill_off = true;
            } else if (same < n) {
                l->spill_full_said = false;
                fprintf(stderr, "[shielded] pad spill: re-registration kept the pads of %zu of %zu groups\n", same, n);
            }
        } else {
            fprintf(stderr, "[shielded] pad spill: re-registration outgrew the headroom; laying the spill out again\n");
            spill_drop(l);
        }
    }
    if (!l->spill && !l->spill_off) {
        char why[192];
        l->spill = sh_spill_attach(K, U, fp, n, l->bank.stream, why, sizeof why);
        if (!l->spill) {
            if (why[0]) { fprintf(stderr, "[shielded] pad spill off: %s\n", why); l->spill_off = true; }
        } else {
            l->spill_slots = sh_spill_slots(l->spill);
            bool ok = (l->spill_io = sh_spill_io_alloc(l->spill)) != NULL;
            for (size_t i = 0; ok && i < n; i++) {
                sh_group *g = &l->groups[i];
                g->sp_flag = (uint8_t *)calloc(l->spill_slots, 1);
                g->sp_wid = (uint64_t *)calloc(l->spill_slots, sizeof *g->sp_wid);
                g->sp_head = g->sp_count = g->sp_writing = g->sp_held = 0;
                ok = g->sp_flag && g->sp_wid;
            }
            if (!ok) {
                fprintf(stderr, "[shielded] pad spill off: no memory for %u slots per group\n", l->spill_slots);
                spill_drop(l); l->spill_off = true;
            } else {
                l->spill_t0 = now_ms(); l->spill_full_said = false;
                fprintf(stderr, "[shielded] pad spill: partition %d, %.1f GiB, %u pads per group over %zu groups (%.2f MiB a row)\n",
                        sh_spill_part(l->spill), sh_spill_bytes(l->spill) / 1073741824.0, l->spill_slots, n,
                        sh_spill_row_bytes(l->spill) / 1048576.0);
            }
        }
    }
    free(K); free(U); free(fp); free(kept);
    if (!spill_usable(l)) return;
    l->spill_idle_ms = env_int("SHIELDED_PAD_SPILL_IDLE_MS", 2000, 0, 3600000);
    /* 1: every ring refill imports when the spill holds pads. Decode with
     * MTP consumes about as many pads as minting makes (two rows a round), so
     * a decode that minted its own (8, release 90176a59) ran its rings dry on
     * long answers and stalled on single-pad imports mid-round. */
    l->spill_min_rows = env_int("SHIELDED_PAD_SPILL_MIN_ROWS", 1, 1, 1 << 20);
    l->spill_mint_max = env_int("SHIELDED_PAD_SPILL_THREADS", l->n_threads > 1 ? l->n_threads - 1 : 1, 0, 64);
    /* While requests run, refills import from the spill and leave threads
     * free: half of them keep minting into it, so a busy stretch drains the
     * spill far slower than it consumes. */
    l->spill_mint_busy = env_int("SHIELDED_PAD_SPILL_BUSY_THREADS", l->n_threads / 2, 0, 64);
    /* Mint on measured spare CPU instead (shielded-spill-cpu.h): the headroom in cores, unset = the idle rule. */
    const char *hr = getenv("SHIELDED_PAD_SPILL_CPU_HEADROOM");
    char *hr_end = NULL;
    const double headroom = hr && *hr ? strtod(hr, &hr_end) : -1;
    l->spill_cpu_on = hr && *hr && hr_end && !*hr_end && headroom >= 0 && headroom <= 256;
    l->spill_cpu_headroom = l->spill_cpu_on ? headroom : 0;
    l->spill_cpu_ms = env_int("SHIELDED_PAD_SPILL_CPU_MS", 500, 50, 60000);
    l->spill_cpu_cap = 0;                        /* nothing until the first measurement */
    l->spill_batch = env_int("SHIELDED_PAD_SPILL_BATCH", l->refill_batch, 1, l->refill_batch);
    l->spill_last_take = now_ms();
}

/* After spill_start, refill threads stopped: the gauge's totals, laid out
 * again from the groups this thread owns, and published under pool_mu for
 * sh_spill_gauge_read. */
static void spill_gauge_reset(sh_link *l) {
    const bool on = spill_usable(l);
    uint64_t ready = 0;
    for (size_t i = 0; on && i < l->n_groups; i++) ready += l->groups[i].sp_count;
    pthread_mutex_lock(&l->pool_mu);
    l->spill_g_on = on;
    l->spill_g_groups = on ? (uint32_t)l->n_groups : 0;
    l->spill_g_ready = ready;
    l->spill_g_cap = on ? (uint64_t)l->spill_slots * l->n_groups : 0;
    l->spill_g_row_bytes = on ? sh_spill_row_bytes(l->spill) : 0;
    l->spill_g_bytes = on ? sh_spill_bytes(l->spill) : 0;
    pthread_mutex_unlock(&l->pool_mu);
}

/* pool_mu held: whether any group's spill has room for a minting batch. */
static bool spill_wants_mint(const sh_link *l, int B) {
    if (!spill_usable(l) || l->spill_mint_max <= 0) return false;
    if (l->spill_batch > 0 && l->spill_batch < B) B = l->spill_batch;
    const uint32_t unit = (uint32_t)B < l->spill_slots ? (uint32_t)B : l->spill_slots;
    for (size_t i = 0; i < l->n_groups; i++) if (spill_free(l, &l->groups[i]) >= unit) return true;
    return false;
}

/* pool_mu held: the group whose spill is emptiest, if a minter is free: up
 * to SHIELDED_PAD_SPILL_THREADS of them once the link has been idle
 * SHIELDED_PAD_SPILL_IDLE_MS, SHIELDED_PAD_SPILL_BUSY_THREADS while it is
 * not; with the CPU governor on, as many as it allows (spill_cpu_cap). Only ever when no ring needs a refill (refill_main asks rings first).
 * Always a whole batch, the refill's own amortisation. */
static sh_group *pick_spill_group(sh_link *l, int B, int *b) {
    if (!spill_usable(l)) return NULL;
    if (l->spill_batch > 0 && l->spill_batch < B) B = l->spill_batch;
    if (l->spill_cpu_on) {
        if (l->spill_minters >= l->spill_cpu_cap) return NULL;
    } else {
        const bool idle = now_ms() - l->spill_last_take >= (double)l->spill_idle_ms;
        if (l->spill_minters >= (idle ? l->spill_mint_max : l->spill_mint_busy)) return NULL;
    }
    if (l->spill_wid + (uint64_t)B >= SH_SPILL_WID_LIMIT) return NULL;
    const uint32_t unit = (uint32_t)B < l->spill_slots ? (uint32_t)B : l->spill_slots;
    sh_group *best = NULL;
    uint64_t best_have = UINT64_MAX;
    for (size_t i = 0; i < l->n_groups; i++) {
        sh_group *c = &l->groups[i];
        if (spill_free(l, c) < unit) continue;
        const uint64_t have = (uint64_t)c->sp_count + c->sp_writing;
        if (have < best_have) { best = c; best_have = have; }
    }
    if (best) *b = (int)unit;
    return best;
}

/* pool_mu held: reserve b slots after the ready run for a write, with fresh
 * write ids. */
static uint32_t spill_reserve(sh_link *l, sh_group *g, int b, uint64_t *wid) {
    const uint32_t cap = l->spill_slots;
    const uint32_t slot0 = (uint32_t)(((uint64_t)g->sp_head + g->sp_count + g->sp_writing) % cap);
    for (int i = 0; i < b; i++) {
        wid[i] = l->spill_wid++;
        g->sp_wid[(slot0 + (uint32_t)i) % cap] = wid[i];
    }
    g->sp_writing += (uint32_t)b;
    return slot0;
}

/* pool_mu held: b slots from slot0 are sealed on the disk. Count forward in
 * slot order over whatever is finished. */
static void spill_publish(sh_link *l, sh_group *g, uint32_t slot0, int b) {
    const uint32_t cap = l->spill_slots;
    for (int i = 0; i < b; i++) g->sp_flag[(slot0 + (uint32_t)i) % cap] |= SP_WRITTEN;
    uint32_t at = (uint32_t)(((uint64_t)g->sp_head + g->sp_count) % cap);
    while (g->sp_writing > 0 && (g->sp_flag[at] & SP_WRITTEN)) {
        g->sp_flag[at] &= (uint8_t)~SP_WRITTEN;
        at = (at + 1) % cap; g->sp_count++; g->sp_writing--; l->spill_g_ready++;
    }
}

/* pool_mu held: take up to `want` sealed pads off group g's spill, oldest
 * first. They are consumed HERE (rule 1): whatever the read does, these
 * slots never come back. -> how many, the first slot and their write ids. */
static int spill_take(sh_link *l, sh_group *g, int want, uint32_t *slot0, uint64_t *wid) {
    if (!spill_usable(l) || want <= 0) return 0;
    if (want > SP_TAKE_MAX) want = SP_TAKE_MAX;
    const int n = g->sp_count < (uint32_t)want ? (int)g->sp_count : want;
    if (n <= 0) return 0;
    const uint32_t cap = l->spill_slots;
    *slot0 = g->sp_head;
    for (int i = 0; i < n; i++) wid[i] = g->sp_wid[(g->sp_head + (uint32_t)i) % cap];
    g->sp_head = (g->sp_head + (uint32_t)n) % cap;
    g->sp_count -= (uint32_t)n; g->sp_held += (uint32_t)n;
    l->spill_g_ready -= (uint64_t)n;
    return n;
}

/* pool_mu held: the read of n slots from slot0 is over. The oldest held slot
 * moves only over retired ones, so a write never lands on a slot still being
 * read by a slower thread. */
static void spill_retire(sh_link *l, sh_group *g, uint32_t slot0, int n) {
    const uint32_t cap = l->spill_slots;
    for (int i = 0; i < n; i++) g->sp_flag[(slot0 + (uint32_t)i) % cap] |= SP_READ;
    uint32_t tail = (uint32_t)(((uint64_t)g->sp_head + cap - g->sp_held) % cap);
    while (g->sp_held > 0 && (g->sp_flag[tail] & SP_READ)) {
        g->sp_flag[tail] &= (uint8_t)~SP_READ;
        tail = (tail + 1) % cap; g->sp_held--;
    }
}

/* Dealt pads: fill b slots of group gi from the shipments - r derived from
 * the seed, u read and opened. Waits up to pad_wait_ms for a bank that has
 * not prefetched the index yet; past that the bank is behind and the link
 * stops (a dealt engine never mints for itself). */
static int dealt_import(sh_link *l, const sh_group *g, uint32_t gi, uint64_t index0, int b, int32_t *r_out, int32_t *u_out) {
    if (__atomic_load_n(&l->pad_integrity_failed, __ATOMIC_ACQUIRE)) return SH_ERR_VERIFY;
    const char *tiled_env = getenv("SHIELDED_PAD_CHECK_TILED");
    const bool tiled_check = tiled_env && !strcmp(tiled_env, "1");
    for (int i = 0; i < b; i++) {
        const uint64_t index = index0 + (uint64_t)i;
        const double t0 = now_ms();
        int rc;
        sh_sp_stamp sp = sh_sp_now();
        uint32_t shipment_group = UINT32_MAX;
        for (;;) {
            rc = sh_pads_reader_cell_ordinal(l->pads, gi, index,
                                           u_out + (size_t)i * g->u_len, &shipment_group);
            if (rc != SH_ERR_EXHAUST || l->stop || now_ms() - t0 >= (double)l->pad_bank_wait_ms) break;
            usleep(50000);
        }
        if (rc != SH_OK) {
            snprintf(l->err, sizeof l->err, "dealt pads: group %u index %llu %s", gi, (unsigned long long)index,
                     rc == SH_ERR_EXHAUST ? "not in any shipment (bank behind)" : rc == SH_ERR_VERIFY ? "failed to open (tampered or wrong key)" : "unreadable");
            if (rc == SH_ERR_VERIFY) __atomic_store_n(&l->pad_integrity_failed, true, __ATOMIC_RELEASE);
            return rc;
        }
        SH_SP_END(sp, "pad_read_open_wait", gi, g->u_len);
        sp = sh_sp_now();
        /* The reader matches by name, not by position. Use the ordinal of
         * the authenticated cell we just opened, even when the consumer's
         * registration order differs or it uses only a subset of groups. */
        sh_pad_r(l->pad_seed, shipment_group, index, g->K, r_out + (size_t)i * g->K);
        SH_SP_END(sp, "pad_prg", gi, g->K);
        sp = sh_sp_now();
        /* The pad check: every node of the group, (u . s) == (r . (W s)) mod M. */
        for (int n = 0; n < g->n_nodes; n++) {
            const sh_node *nd = &l->nodes[g->nodes[n]];
            if (!nd->sM) continue;
            const int32_t *rr = r_out + (size_t)i * g->K, *uu = u_out + (size_t)i * g->u_len + nd->u_off;
            int64_t a, b;
            if (tiled_check) {
                a = sh_pad_check_dot_field(uu, nd->sM, nd->N);
                b = sh_pad_check_dot_field(rr, nd->stM, nd->K);
            } else {
                a = sh_dot_mod_i32(uu, nd->sM, nd->N, SH_M_MOD);
                b = sh_dot_mod_i32(rr, nd->stM, nd->K, SH_M_MOD);
            }
            if (a != b) {
                snprintf(l->err, sizeof l->err, "dealt pads: group %u index %llu: pad FAILED the check on %s (the dealer minted u != r.W for this seed)", gi, (unsigned long long)index, nd->name);
                __atomic_store_n(&l->pad_integrity_failed, true, __ATOMIC_RELEASE);
                return SH_ERR_VERIFY;
            }
        }
        SH_SP_END(sp, "pad_freivalds", gi, g->u_len);
    }
    return SH_OK;
}

/* This thread's CPU time, ns. */
static uint64_t thread_cpu_ns(clockid_t c) {
    struct timespec ts;
    return clock_gettime(c, &ts) == 0 ? (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec : 0;
}

/* pool_mu held: minting's thread CPU so far, finished batches and running ones. */
static uint64_t spill_mint_cpu_now(const sh_link *l) {
    uint64_t ns = l->spill_mint_cpu_ns;
    for (int i = 0; i < l->spill_mt_n; i++)
        if (l->spill_mt[i].active) { const uint64_t t = thread_cpu_ns(l->spill_mt[i].clock); if (t > l->spill_mt[i].t0) ns += t - l->spill_mt[i].t0; }
    return ns;
}

/* The CPU governor (shielded-spill-cpu.h): every SHIELDED_PAD_SPILL_CPU_MS, the CPUs a refill thread may run on,
 * their busy share in this guest less minting's own, and the cap that leaves SHIELDED_PAD_SPILL_CPU_HEADROOM cores
 * free. A /proc/stat it cannot read turns it off for the link's life and the idle rule applies again. */
static bool spill_cpu_sample(sh_link *l, uint8_t *mask, sh_cpu_ticks *t, char *buf, size_t cap) {
    cpu_set_t set; CPU_ZERO(&set);
    memset(mask, 0, SH_CPU_MASK_MAX);
    if (l->n_threads <= 0 || pthread_getaffinity_np(l->threads[0], sizeof set, &set) != 0) return false;
    for (int c = 0; c < SH_CPU_MASK_MAX && c < CPU_SETSIZE; c++) mask[c] = CPU_ISSET(c, &set) ? 1 : 0;
    const int fd = open("/proc/stat", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    size_t n = 0;
    for (;;) {
        const ssize_t r = read(fd, buf + n, cap - 1 - n);
        if (r <= 0) break;
        n += (size_t)r;
        if (n >= cap - 1) break;
    }
    close(fd);
    buf[n] = 0;
    return sh_cpu_stat_parse(buf, mask, SH_CPU_MASK_MAX, t);
}

static void *spill_cpu_main(void *arg) {
    sh_link *l = (sh_link *)arg;
    const size_t cap = 256 * 1024;
    char *buf = (char *)malloc(cap);
    uint8_t *mask = (uint8_t *)malloc(SH_CPU_MASK_MAX);
    sh_cpu_ticks a, b;
    bool ok = buf && mask && spill_cpu_sample(l, mask, &a, buf, cap);
    pthread_mutex_lock(&l->pool_mu);
    uint64_t mint_a = spill_mint_cpu_now(l);
    if (!ok) {
        fprintf(stderr, "[shielded] pad spill cpu governor off: /proc/stat or the refill CPUs unreadable; minting only while idle\n");
        l->spill_cpu_on = false;
        pthread_cond_broadcast(&l->need_refill);
    } else {
        fprintf(stderr, "[shielded] pad spill cpu governor: %d refill CPUs, %.1f cores headroom, every %d ms, %d rows a mint\n",
                a.cpus, l->spill_cpu_headroom, l->spill_cpu_ms, l->spill_batch);
    }
    pthread_mutex_unlock(&l->pool_mu);
    double wall_a = now_ms(), said_at = 0;
    int said_cap = -1;
    while (ok) {
        /* sleep a period, waking for a stop */
        for (double until = now_ms() + l->spill_cpu_ms; now_ms() < until; ) {
            pthread_mutex_lock(&l->pool_mu);
            const bool stop = l->stop;
            pthread_mutex_unlock(&l->pool_mu);
            if (stop) goto done;
            struct timespec ts = { 0, 25L * 1000000L };
            nanosleep(&ts, NULL);
        }
        if (!spill_cpu_sample(l, mask, &b, buf, cap)) continue;      /* a torn read: keep the last cap */
        const double wall_b = now_ms(), dt = (wall_b - wall_a) / 1000.0;
        pthread_mutex_lock(&l->pool_mu);
        const uint64_t mint_b = spill_mint_cpu_now(l);
        const uint64_t dtot = b.total > a.total ? b.total - a.total : 0, dbusy = b.busy > a.busy ? b.busy - a.busy : 0;
        const double busy_frac = dtot ? (double)dbusy / (double)dtot : 0;
        const double mint_cores = dt > 0 && mint_b > mint_a ? (double)(mint_b - mint_a) / 1e9 / dt : 0;
        const int prev = l->spill_cpu_cap;
        const int next = sh_spill_cpu_cap(b.cpus, busy_frac, mint_cores, l->spill_cpu_headroom, l->spill_mint_max, prev);
        l->spill_cpu_cap = next;
        if (next > prev) pthread_cond_broadcast(&l->need_refill);
        const int minters = l->spill_minters;
        pthread_mutex_unlock(&l->pool_mu);
        /* what it decided, at most every 10 s and only when the cap moved since the last line */
        if (next != said_cap && wall_b - said_at >= 10000) {
            fprintf(stderr, "[shielded] pad spill cpu: %.1f of %d refill CPUs busy (%.1f minting) -> mint on up to %d threads (%d now)\n",
                    busy_frac * b.cpus, b.cpus, mint_cores, next, minters);
            said_cap = next; said_at = wall_b;
        }
        a = b; mint_a = mint_b; wall_a = wall_b;
    }
done:
    free(buf); free(mask);
    return NULL;
}

static void *refill_main(void *arg) {
    sh_link *l = (sh_link *)arg;
    gen_scratch s;
    const int B = l->refill_batch;
    if (gen_scratch_init(l, &s, B) != SH_OK) return NULL;
    /* Private staging, used only when the reserved slots wrap around the ring
     * end; otherwise the batch is generated straight into the ring. */
    int32_t *r = (int32_t *)malloc((size_t)B * l->Kmax * sizeof(int32_t));
    int32_t *u = (int32_t *)malloc((size_t)B * l->ulen_max * sizeof(int32_t));
    if (!r || !u) { free(r); free(u); free(s.planes); free(s.acc); return NULL; }
    /* This thread's spill I/O buffer; without one it neither mints into nor
     * imports from the spill. */
    uint8_t *io = spill_usable(l) ? sh_spill_io_alloc(l->spill) : NULL;
    /* this thread's slot in the minting CPU account (the governor reads its clock while it mints) */
    pthread_mutex_lock(&l->pool_mu);
    int mt = -1;
    if (l->spill_mt_n < (int)(sizeof l->spill_mt / sizeof l->spill_mt[0]) &&
        pthread_getcpuclockid(pthread_self(), &l->spill_mt[l->spill_mt_n].clock) == 0) {
        mt = l->spill_mt_n++;
        l->spill_mt[mt].active = false;
    }
    pthread_mutex_unlock(&l->pool_mu);
    for (;;) {
        pthread_mutex_lock(&l->pool_mu);
        sh_group *g = NULL; int deficit = 0;
        bool to_spill = false;
        for (;;) {
            if (l->stop) { pthread_mutex_unlock(&l->pool_mu); goto done; }
            /* Which group, and whether to bother. Every partial batch still
             * streams the group's weights, while a full four-row batch
             * amortises that stream across four pads. In
             * steady state every group loses exactly one pad per token, and
             * refilling each deficit-1 group as it appeared kept two cores
             * busy at a quarter efficiency for the whole decode. So: a group
             * that is LOW (fewer than a batch ready or coming) is refilled at
             * once with whatever fits -- at start-up that is every group in
             * turn, so the first token finds a pad in each -- and otherwise a
             * group is refilled only once a whole batch fits. The default
             * chooses the largest deficit; the opt-in cost policy also
             * weights the full-batch choice by the matrix work per pad.
             * Lowest-first among the low ones in either policy. */
            g = pick_refill_group(l, B, &deficit);
            if (g) break;
            if (io && (g = pick_spill_group(l, B, &deficit)) != NULL) { to_spill = true; break; }
            if (io && spill_wants_mint(l, B)) {
                /* Idleness is a matter of time, which no signal announces:
                 * look again shortly. */
                struct timespec dl; clock_gettime(CLOCK_REALTIME, &dl);
                dl.tv_nsec += 200L * 1000000L;
                if (dl.tv_nsec >= 1000000000L) { dl.tv_sec++; dl.tv_nsec -= 1000000000L; }
                pthread_cond_timedwait(&l->need_refill, &l->pool_mu, &dl);
            } else {
                pthread_cond_wait(&l->need_refill, &l->pool_mu);
            }
        }
        if (to_spill) {
            /* Mint a batch into the spill: generate()'s work with the spill's
             * masks, then seal and write. */
            const size_t gi = (size_t)(g - l->groups);
            const int b = deficit;
            uint64_t wid[SP_TAKE_MAX];
            const uint32_t slot0 = spill_reserve(l, g, b, wid);
            if (l->spill_imported + l->spill_onpath != l->spill_said) {
                /* The first mint after a busy spell: say what the spell drew. */
                fprintf(stderr, "[shielded] pad spill: the last requests imported %llu pads (%llu on the request path); minting back\n",
                        (unsigned long long)(l->spill_imported + l->spill_onpath - l->spill_said),
                        (unsigned long long)(l->spill_onpath - l->spill_said_onpath));
                l->spill_said = l->spill_imported + l->spill_onpath;
                l->spill_said_onpath = l->spill_onpath;
            }
            l->spill_minters++;
            if (mt >= 0) { l->spill_mt[mt].t0 = thread_cpu_ns(CLOCK_THREAD_CPUTIME_ID); l->spill_mt[mt].active = true; }
            pthread_cond_broadcast(&l->need_refill);         /* another minter may start too */
            pthread_mutex_unlock(&l->pool_mu);
            for (int i = 0; i < b; i++) sh_spill_mask(l->spill, wid[i], r + (size_t)i * g->K, g->K);
            int rc = generate_products(l, g, b, r, s.planes, u, s.acc);
            const bool minted = rc == SH_OK;
            if (minted) rc = sh_spill_write(l->spill, gi, slot0, b, wid, u, io);
            const uint64_t mint_t1 = mt >= 0 ? thread_cpu_ns(CLOCK_THREAD_CPUTIME_ID) : 0;
            pthread_mutex_lock(&l->pool_mu);
            l->spill_minters--;
            if (mt >= 0) {
                if (mint_t1 > l->spill_mt[mt].t0) l->spill_mint_cpu_ns += mint_t1 - l->spill_mt[mt].t0;
                l->spill_mt[mt].active = false;
            }
            if (rc == SH_OK) {
                spill_publish(l, g, slot0, b);
                l->spill_written += (uint64_t)b;
                if (!l->spill_full_said && !spill_wants_mint(l, B)) {
                    l->spill_full_said = true;
                    fprintf(stderr, "[shielded] pad spill full: %u pads per group, %llu written in %.0f s\n",
                            l->spill_slots, (unsigned long long)l->spill_written, (now_ms() - l->spill_t0) / 1000.0);
                }
            } else if (minted) {
                spill_fail(l, "a write", rc);
            } else {
                /* The mint itself failed: what the ring path does on a failed
                 * generate (the latch, if any, is already set). */
                spill_fail(l, "a mint", rc);
                if (!l->stop) fprintf(stderr, "[shielded] refill stopped: pad mint failed (group %s, rc %d)\n", l->nodes[g->nodes[0]].name, rc);
                l->stop = true;
                pthread_cond_broadcast(&l->pool_filled);
            }
            pthread_mutex_unlock(&l->pool_mu);
            continue;
        }
        /* A ring refill imports from the spill only while this group is being
         * read a prompt at a time (its last take was SHIELDED_PAD_SPILL_MIN_ROWS
         * rows or more): a prompt drains the rings far faster than minting
         * refills them, which is what the spill is for. A decode step takes
         * one or two rows and minting keeps up with that, as it always has,
         * so decode leaves the spill to the next prompt. A request whose ring
         * runs dry still imports its shortfall (sh_link_gemm_stride). */
        uint64_t sp_wid[SP_TAKE_MAX];
        uint32_t sp_slot0 = 0;
        const int sp_n = io && g->sp_last_m >= l->spill_min_rows
                       ? spill_take(l, g, deficit < B ? deficit : B, &sp_slot0, sp_wid) : 0;
        const int b = sp_n > 0 ? sp_n : deficit < B ? deficit : B;
        const int first = (g->head + g->count + g->generating) % g->depth;
        uint64_t index0 = 0;
        if (l->dealt) {
            /* Reserve-before-use: no index is imported unless the ledger's
             * mark is already past it, so a restart can never replay one. */
            while (g->cursor + (uint64_t)b > l->win_hi) {
                uint64_t lo, hi;
                if (dealt_reserve(l, &lo, &hi) != SH_OK || lo != l->win_hi) {
                    snprintf(l->err, sizeof l->err, "dealt pads: ledger window refused; stopping");
                    l->stop = true;
                    pthread_cond_broadcast(&l->pool_filled);
                    pthread_mutex_unlock(&l->pool_mu);
                    goto done;
                }
                l->win_hi = hi;
                dealt_advanced(l);
            }
            index0 = g->cursor;
            g->cursor += (uint64_t)b;
        }
        g->generating += b;
        const bool receipt = l->receipt_due; l->receipt_due = false;
        pthread_mutex_unlock(&l->pool_mu);
        if (receipt) dealt_receipt(l);

        const bool direct = first + b <= g->depth;
        int32_t *r_out = direct ? g->r_store + (size_t)first * g->K     : r;
        int32_t *u_out = direct ? g->u_store + (size_t)first * g->u_len : u;
        int rc;
        if (l->dealt) {
            rc = dealt_import(l, g, (uint32_t)(g - l->groups), index0, b, r_out, u_out);
        } else if (sp_n > 0) {
            rc = sh_spill_read(l->spill, (size_t)(g - l->groups), sp_slot0, sp_n, sp_wid, r_out, u_out, io);
            pthread_mutex_lock(&l->pool_mu);
            spill_retire(l, g, sp_slot0, sp_n);
            if (rc == SH_OK) l->spill_imported += (uint64_t)sp_n;
            else spill_fail(l, "a read", rc);
            pthread_mutex_unlock(&l->pool_mu);
            /* The ring slots are still this thread's: whatever did not open is
             * minted instead. The spill pads taken for it are burned. */
            if (rc != SH_OK) rc = generate(l, g, b, r_out, u_out, &s);
        } else {
            rc = generate(l, g, b, r_out, u_out, &s);
        }
        if (rc == SH_OK && !direct) {
            for (int i = 0; i < b; i++) {
                const int slot = (first + i) % g->depth;
                memcpy(g->r_store + (size_t)slot * g->K,     r + (size_t)i * g->K,     (size_t)g->K * sizeof(int32_t));
                memcpy(g->u_store + (size_t)slot * g->u_len, u + (size_t)i * g->u_len, (size_t)g->u_len * sizeof(int32_t));
            }
        }

        pthread_mutex_lock(&l->pool_mu);
        if (rc == SH_OK) {
            for (int i = 0; i < b; i++) g->ready[(first + i) % g->depth] = 1;
            /* Count forward in ring order over whatever is finished. */
            while (g->generating > 0 && g->ready[(g->head + g->count) % g->depth]) {
                g->ready[(g->head + g->count) % g->depth] = 0;
                g->count++; g->generating--;
            }
            pthread_cond_broadcast(&l->pool_filled);
        } else {
            /* Bank exhausted: the reservation is abandoned and nothing more
             * happens until the process restarts. Say why, once. */
            g->generating -= b;
            if (!l->stop) fprintf(stderr, "[shielded] refill stopped: %s (group %s, rc %d)\n", l->err[0] ? l->err : "pad bank exhausted", l->nodes[g->nodes[0]].name, rc);
            l->stop = true;
            pthread_cond_broadcast(&l->pool_filled);
        }
        pthread_mutex_unlock(&l->pool_mu);
    }
done:
    free(r); free(u); free(s.planes); free(s.acc); free(io);
    return NULL;
}

/* How many refill threads the registered weights need.
 *
 * Each pad of a group costs three residue planes of u = r.W, i.e. 3.K.N int8
 * MACs, and the request path consumes one pad per group per token, so refill
 * has to sustain 3 x (the offloaded MACs of one token) per token time. Measured
 * (2026-08-26, EPYC 9115, AVX-512 VNNI, batch 4): ~250 G-MAC/s per core, and
 * the 0.5B decodes at ~6 ms/token on this box, which is the default target.
 *   0.5B: 1.36 G MAC/token -> 5.4 core-ms/token -> 1 thread, clamped up to 2
 *   4B:   12  G MAC/token -> 48 core-ms/token   -> 10 threads
 * The 1.25 is headroom for sharing the cores with the engine's own threads.
 * Clamped to [2, ncores/2]; SHIELDED_REFILL_THREADS overrides the whole thing. */
#define SH_REFILL_GMACS_PER_CORE 250.0
static int derive_threads(const sh_link *l) {
    if (l->threads_env >= 0) return l->threads_env;
    if (l->dealt) return 2;                    /* reading and opening cells, not MACs */
    double macs = 0;
    for (size_t i = 0; i < l->n_nodes; i++) macs += (double)l->nodes[i].K * (double)l->nodes[i].N;
    const double core_ms = 3.0 * macs / (SH_REFILL_GMACS_PER_CORE * 1e9) * 1e3;
    /* Pads per token is the batch width, not 1: a tenant serving several users
     * (or verifying a speculative draft) takes m per group per step, and a
     * step is only ~2-4x longer than a single token at m=8. Sized for half
     * the widest batch the graph may present, which over-provisions a
     * single-user decode by idle threads that cost nothing, and stops a
     * batched one from generating pads on the request path. */
    int32_t mmax = 1;
    for (size_t i = 0; i < l->n_groups; i++) if (l->groups[i].max_m > mmax) mmax = l->groups[i].max_m;
    const double m_eff = mmax > 2 ? mmax / 2.0 : 1.0;
    int want = (int)(core_ms * m_eff * 1.25 / (double)l->target_ms + 0.999);
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    int hi = ncpu > 4 ? (int)(ncpu / 2) : 2;
    if (want < 2) want = 2;
    if (want > hi) want = hi;
    return want;
}

/* One ledger window, through the provider when the host supplied one (the
 * pVM asks its owner app, which asks the platform) and the file otherwise. */
/* A window from an http:// agent (the wasm manager inside the CVM, or a
 * test stub): POST {"want","seed_id"} and verify the platform's signature
 * exactly as the pVM does; an agent cannot hand out a window the ledger
 * did not sign. */
static int dealt_reserve_http(sh_link *l, uint64_t *lo, uint64_t *hi) {
    char body[128]; snprintf(body, sizeof body, "{\"want\":%llu,\"seed_id\":\"%s\"}", (unsigned long long)l->pad_window, l->pad_seed_id_hex);
    uint8_t *resp = NULL; size_t rlen = 0; int status = 0;
    if (sh_http_post_json(l->win_url, body, 30000, &resp, &rlen, &status) != 0) { snprintf(l->err, sizeof l->err, "dealt pads: window agent %s unreachable", l->win_url); return SH_ERR_IO; }
    int rc = SH_ERR_IO;
    if (status == 200 && resp) {
        const char *s = (const char *)resp;
        const char *pl = strstr(s, "\"lo\":"), *ph = strstr(s, "\"hi\":"), *pi = strstr(s, "\"iat\":"), *ps = strstr(s, "\"sig\":\"");
        if (pl && ph && pi && ps) {
            const unsigned long long L = strtoull(pl + 5, NULL, 10), H = strtoull(ph + 5, NULL, 10), I = strtoull(pi + 6, NULL, 10);
            char sig_hex[129] = ""; snprintf(sig_hex, sizeof sig_hex, "%.128s", ps + 7);
            uint8_t sig[64];
            if (strlen(sig_hex) == 128 && sh_pads_hex2bin(sig_hex, sig, 64) && sh_pads_window_verify(l->win_pk, l->pad_seed_id_hex, L, H, I, sig) && H > L) {
                *lo = L; *hi = H; rc = SH_OK;
            } else snprintf(l->err, sizeof l->err, "dealt pads: window signature REJECTED (agent %s)", l->win_url);
        } else snprintf(l->err, sizeof l->err, "dealt pads: malformed window from %s", l->win_url);
    } else snprintf(l->err, sizeof l->err, "dealt pads: window agent %s answered http %d", l->win_url, status);
    free(resp);
    return rc;
}

static int dealt_reserve(sh_link *l, uint64_t *lo, uint64_t *hi) {
    *lo = *hi = 0;
    const int rc = l->win_fn ? l->win_fn(l->win_ctx, l->pad_window, lo, hi) :
                   l->win_url[0] ? dealt_reserve_http(l, lo, hi) :
                   sh_pads_window_reserve(l->pad_ledger, l->pad_window, lo, hi);
    if (rc != SH_OK) return rc;
    if (*hi > SH_PADS_INDEX_LIMIT) return SH_ERR_EXHAUST;
    /* Retain this floor across reconnect/reprepare. A correctly signed old
     * window must not reset the cursors to indices already reserved here. */
    if (*lo < l->win_hi || *hi <= *lo) return SH_ERR_VERIFY;
    return SH_OK;
}

/* After a new window (pool mutex held): cursor advances when an importer
 * reserves work, BEFORE it reads the cells. Keep the whole unpublished ring
 * suffix, including jobs that finished out of order: generating only shrinks
 * when the contiguous ready prefix advances. Otherwise another thread can
 * prune a file before its importer has even retained a descriptor. */
static void dealt_advanced(sh_link *l) {
    uint64_t floor = UINT64_MAX;
    for (size_t i = 0; i < l->n_groups; i++) {
        const sh_group *g = &l->groups[i];
        const uint64_t pending = g->generating > 0 ? (uint64_t)g->generating : 0;
        const uint64_t safe = pending <= g->cursor ? g->cursor - pending : 0;
        if (safe < floor) floor = safe;
    }
    if (floor == UINT64_MAX) floor = l->win_lo;
    if (l->padbank) { sh_bank_set_floor(l->padbank, floor); sh_bank_set_need(l->padbank, l->win_hi + l->pad_window); }
    if (l->pad_prune && l->pads) {
        const int n = sh_pads_reader_prune_below(l->pads, floor, true);
        if (n) fprintf(stderr, "[shielded] dealt pads: dropped %d spent shipment(s) below %llu\n", n, (unsigned long long)floor);
    }
    if (l->win_url[0]) l->receipt_due = true;
}

/* Usage receipt through the window agent (the pVM signs its own on the
 * control channel): the DELTA of cells consumed and rows reserved since the
 * last one, so the platform's totals add up. Best effort, never on the
 * request path, never blocking a window: a missing route is logged once. */
static void dealt_receipt(sh_link *l) {
    if (!l->win_url[0] || l->receipt_failed) return;
    char url[1100]; snprintf(url, sizeof url, "%s", l->win_url);
    char *tail = strrchr(url, '/');
    if (!tail || strcmp(tail, "/window")) return;
    snprintf(tail, sizeof url - (size_t)(tail - url), "/receipt");
    pthread_mutex_lock(&l->pool_mu);
    const uint64_t pads = l->pads_used, rows = l->win_hi;   /* rows reserved so far = the window's far edge */
    pthread_mutex_unlock(&l->pool_mu);
    if (pads <= l->receipt_pads && rows <= l->receipt_rows) return;
    const uint64_t dp = pads - l->receipt_pads, dr = rows - l->receipt_rows;
    char body[192]; snprintf(body, sizeof body, "{\"seed_id\":\"%s\",\"pads\":%llu,\"tokens\":%llu}", l->pad_seed_id_hex, (unsigned long long)dp, (unsigned long long)dr);
    uint8_t *resp = NULL; size_t rlen = 0; int status = 0;
    const int rc = sh_http_post_json(url, body, 10000, &resp, &rlen, &status);
    free(resp);
    if (rc == 0 && status == 200) { l->receipt_pads = pads; l->receipt_rows = rows; return; }
    if (rc != 0 || status == 404) { l->receipt_failed = true; fprintf(stderr, "[shielded] dealt pads: no usage receipts (%s: %s%d)\n", url, rc ? "unreachable " : "http ", status); }
    else fprintf(stderr, "[shielded] dealt pads: receipt refused (http %d); retrying at the next window\n", status);
}

/* ---- pad-budget diagnostic (SHIELDED_PAD_BUDGET) -------------------------
 *
 * Read-only metadata for one link at one instant. It TRY-locks pool_mu, copies
 * scalars and per-group ring state, calls the reader's coverage union under the
 * reader mutex (pool_mu -> r->mu, the order dealt_advanced already establishes
 * by calling prune_below with pool_mu held), and returns. No cell is opened or
 * decrypted, no window is reserved, no directory is scanned, nothing is bound,
 * pruned or started: this cannot advance any durable state.
 *
 * Try-lock, not lock: pool_mu is held by a refill across dealt_reserve, which
 * can fsync a ledger or make an HTTP round trip. Waiting there would let a
 * diagnostic stall decode. BUSY means NOT OBSERVED, never an empty ring.
 *
 * Two things pool_mu does NOT cover, both the caller's obligation:
 *   - start_pools replaces l->pads and l->groups without pool_mu, so the caller
 *     must exclude sh_link_start. In the backend that is sh_state::mu, which
 *     sh_card_compute holds around its sh_link_start call.
 *   - threads_running is written by start_pools and stop_threads, neither under
 *     pool_mu, so reading it here is meaningful only under the SAME exclusion of
 *     sh_link_start/sh_link_close; pool_mu does not order it. The backend export
 *     holds sh_state::mu, which does.
 *   - the request path writes pads_used/pads_missed WITHOUT pool_mu (take_pads
 *     releases it before the gemm updates them), so those are read only when the
 *     caller passes SH_PAD_BUDGET_F_REQUEST_PATH_EXCLUDED. Without it they stay
 *     zero and counters_valid is false, rather than being read in a data race.
 * A mutex cannot protect against destruction; a direct caller must externally
 * exclude every non-refill link API, close included.
 *
 * Refill threads resume the instant pool_mu is released, so several links read
 * in sequence are a sequence of observations, not one atomic inventory. */
static bool budget_mono_ns(uint64_t *out) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) { *out = 0; return false; }
    *out = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
    return true;
}

int sh_link_pad_budget(sh_link *l, sh_pad_budget *b, uint32_t flags,
                       sh_pad_interval *intervals, uint32_t cap_intervals,
                       sh_pad_group_budget *groups, uint32_t cap_groups) {
    if (!b) return SH_PAD_BUDGET_UNAVAILABLE;
    memset(b, 0, sizeof *b);
    b->version = SH_PAD_BUDGET_VERSION;
    b->card = -1;
    b->status = SH_PAD_BUDGET_UNAVAILABLE;
    b->reader_status = SH_PAD_BUDGET_UNAVAILABLE;
    b->cap_intervals = cap_intervals;
    b->cap_groups = cap_groups;
    b->mono_valid = budget_mono_ns(&b->mono_start_ns);
    if (!l) { if (!budget_mono_ns(&b->mono_end_ns)) b->mono_valid = false; return b->status; }

    if (pthread_mutex_trylock(&l->pool_mu) != 0) {
        b->status = b->reader_status = SH_PAD_BUDGET_BUSY;
        if (!budget_mono_ns(&b->mono_end_ns)) b->mono_valid = false;
        return b->status;
    }
    b->link_observed = true;      /* pool_mu is held: the link fields below are READ, not defaults */
    b->dealt = l->dealt;
    b->threads_running = l->threads_running;
    b->stop = l->stop;
    b->pad_integrity_failed = __atomic_load_n(&l->pad_integrity_failed, __ATOMIC_ACQUIRE);
    b->pad_window = l->pad_window;
    b->win_lo = l->win_lo;
    b->win_hi = l->win_hi;
    b->n_groups = (uint32_t)l->n_groups;

    const bool counters = (flags & SH_PAD_BUDGET_F_REQUEST_PATH_EXCLUDED) != 0;
    b->counters_valid = counters;
    if (counters) {
        b->link_pads_used = l->pads_used;
        b->link_pads_missed = l->pads_missed;
        b->pads_waited = l->pads_waited;
    }

    int status = SH_PAD_BUDGET_OK;
    if (!l->dealt) {
        status = SH_PAD_BUDGET_UNAVAILABLE;       /* a generated-pad link has no shipments at all */
    } else {
        /* Refill threads not running: the rings are not being served, so ready
         * counts are not a live supply. Say UNSTARTED and keep the metadata;
         * this is never to be read as an empty ring. */
        if (!l->threads_running) status = SH_PAD_BUDGET_UNSTARTED;
        uint32_t written = 0;
        for (size_t i = 0; i < l->n_groups; i++) {
            if (!groups || written == cap_groups) {
                if (status == SH_PAD_BUDGET_OK || status == SH_PAD_BUDGET_UNSTARTED)
                    status = SH_PAD_BUDGET_INCOMPLETE;
                break;
            }
            const sh_group *g = &l->groups[i];
            sh_pad_group_budget *o = &groups[written++];
            memset(o, 0, sizeof *o);
            o->group = (uint32_t)i;
            if (g->n_nodes > 0 && g->nodes[0] >= 0 && (size_t)g->nodes[0] < l->n_nodes)
                snprintf(o->name, sizeof o->name, "%.*s",
                         (int)sizeof o->name - 1, l->nodes[g->nodes[0]].name);
            o->K = g->K; o->u_len = g->u_len;
            o->depth = g->depth; o->ready = g->count;
            o->generating = g->generating; o->held = g->held;
            o->cursor = g->cursor;
            if (counters) { o->pads_used = g->pads_used; o->pads_missed = g->pads_missed; }
        }
        b->written_groups = written;

        if (!l->pads) {
            b->reader_status = SH_PAD_BUDGET_NO_READER;
            if (status == SH_PAD_BUDGET_OK) status = SH_PAD_BUDGET_NO_READER;
        } else {
            uint32_t n_iv = 0, n_bound = 0;
            uint64_t n_files = 0;
            bool bound_table = false;
            b->reader_status = sh_pads_reader_coverage(l->pads, intervals, cap_intervals,
                                                       &n_iv, &n_files, &n_bound, &bound_table);
            b->n_intervals = n_iv;
            b->reader_files = n_files;
            b->reader_bound_groups = n_bound;
            /* BUSY means the reader mutex was never taken, so `n_files` and
             * `n_bound` were never read: report them as unknown rather than
             * publishing the zeroed out-parameters as observations. */
            const bool read_reader = b->reader_status != SH_PAD_BUDGET_BUSY &&
                                     b->reader_status != SH_PAD_BUDGET_UNAVAILABLE;
            b->reader_bound_table_present = read_reader && bound_table;
            if (!read_reader) { b->reader_files = 0; b->reader_bound_groups = 0; }
            /* No bind epoch. Tracking one would mean a field in the private
             * reader struct, which three RTLD_GLOBAL libraries each define;
             * always unknown, and the value is not interpretable. */
            b->bind_epoch = 0;
            b->bind_epoch_known = false;
            b->intervals_are_bound_coverage = b->reader_status == SH_PAD_BUDGET_OK;
            if (b->reader_status != SH_PAD_BUDGET_OK && status == SH_PAD_BUDGET_OK)
                status = b->reader_status;
        }
    }
    pthread_mutex_unlock(&l->pool_mu);

    b->status = status;
    if (!budget_mono_ns(&b->mono_end_ns)) b->mono_valid = false;
    return status;
}

void sh_link_set_window_provider(sh_link *l, sh_window_fn fn, void *ctx) {
    if (!l) return;
    l->win_fn = fn; l->win_ctx = ctx;
}

/* Bind already delivered files before uploading weights. Empty banks remain
 * admissible (delivery can run during upload); present but incompatible files
 * fail explicitly, rather than becoming a misleading bank-behind timeout. */
static int dealt_bind(sh_link *l) {
    if (!l->dealt) return SH_OK;
    if (l->n_groups >= SH_PADS_GROUP_LIMIT) return SH_ERR_RANGE;
    for (size_t gi = 0; gi < l->n_groups; gi++)
        if (l->groups[gi].K <= 0 || l->groups[gi].K > SH_PADS_K_LIMIT) return SH_ERR_RANGE;
    if (!l->pads) {
        int err = SH_OK;
        if (l->bank_url[0] && !l->padbank) {
            l->padbank = sh_bank_open(l->bank_url, l->pad_seed_id_hex, l->pad_dir, l->bank_cache_max, &err);
            if (!l->padbank) { snprintf(l->err, sizeof l->err, "dealt pads: cannot start the bank client for %s (cache %s)", l->bank_url, l->pad_dir); return err ? err : SH_ERR_IO; }
        }
        l->pads = sh_pads_reader_open(l->pad_dir, l->pad_seed_id, l->pad_sk, &err);
        if (!l->pads) { snprintf(l->err, sizeof l->err, "dealt pads: cannot read %s", l->pad_dir); return err ? err : SH_ERR_IO; }
        const char *dh = getenv("SHIELDED_PAD_MODEL_DIGEST");
        uint8_t digest[32];
        if (dh && *dh) {
            if (!sh_pads_hex2bin(dh, digest, 32)) { snprintf(l->err, sizeof l->err, "dealt pads: SHIELDED_PAD_MODEL_DIGEST is not 64 hex"); return SH_ERR_RANGE; }
            sh_pads_reader_require_digest(l->pads, digest);
        }
    }
    sh_pads_group *table = (sh_pads_group *)calloc(l->n_groups ? l->n_groups : 1, sizeof *table);
    if (!table) return SH_ERR_NOMEM;
    int rc = sh_link_group_table(l, table, (uint32_t)l->n_groups);
    if (rc >= 0) rc = sh_pads_reader_bind(l->pads, table, (uint32_t)l->n_groups);
    free(table);
    if (rc < 0) {
        snprintf(l->err, sizeof l->err, "dealt pads: available shipments do not bind this model's complete registered groups (rc %d)", rc);
        if (rc == SH_ERR_VERIFY) __atomic_store_n(&l->pad_integrity_failed, true, __ATOMIC_RELEASE);
        return rc;
    }
    return SH_OK;
}

/* Reserve only after worker setup. Binding is repeated because registration
 * or delivered coverage may have changed since the pre-upload check. */
static int dealt_open(sh_link *l) {
    if (!l->dealt) return SH_OK;
    if (!l->win_fn && !l->win_url[0] && !l->pad_ledger[0]) { snprintf(l->err, sizeof l->err, "dealt pads: no ledger (SHIELDED_PAD_LEDGER), no window agent (SHIELDED_PAD_WINDOW_URL) and no window provider"); return SH_ERR_RANGE; }
    int rc = dealt_bind(l);
    if (rc != SH_OK) return rc;
    uint64_t lo, hi;
    rc = dealt_reserve(l, &lo, &hi);
    if (rc != SH_OK) { snprintf(l->err, sizeof l->err, "dealt pads: invalid, replayed or exhausted ledger window (%s)", l->win_fn ? "provider refused" : l->pad_ledger); return rc; }
    l->win_lo = lo; l->win_hi = hi;
    for (size_t i = 0; i < l->n_groups; i++) l->groups[i].cursor = lo;
    if (l->padbank) { sh_bank_set_floor(l->padbank, lo); sh_bank_set_need(l->padbank, hi + l->pad_window); }
    return SH_OK;
}

static int start_pools(sh_link *l) {
    stop_threads(l);
    if (sh_integrity_failed(l)) return SH_ERR_VERIFY;
    free_pools(l);
    { const int rc = dealt_open(l); if (rc != SH_OK) return rc; }
    for (size_t i = 0; i < l->n_groups; i++) {
        sh_group *g = &l->groups[i];
        /* A batched step takes m pads from a group at once, and the pool is
         * refilled between steps: a depth below ~4m starves it (bench-batch at
         * m=8 with the old fixed 16: hundreds of on-path refills). Sized from
         * what the graph may ask for, but CAPPED at 32 (never below max_m): max_m is the widest
         * batch the link accepts, and with prefill on the card (max_m 64)
         * the 4m rule made 256 pads per group -- 10 GB of pads on a 27B and
         * a refill that never idles, which cost 22% of decode (7.31 -> 5.67
         * tok/s, 2026-09-20). A prefill wider than the pool fills the rest on
         * the request path, in batches, which the measurement shows is cheap
         * (0.5 s of a 1 s 17-row prefill). SHIELDED_POOL_DEPTH overrides. */
        {
            int want = g->max_m * 4;
            if (want < 16) want = 16;
            if (want > 32) want = 32;
            if (want < g->max_m) want = g->max_m;     /* never narrower than the widest exchange */
            g->depth = l->pool_depth > 0 ? l->pool_depth : want;
        }
        g->r_store = (int32_t *)malloc((size_t)g->depth * g->K * sizeof(int32_t));
        g->u_store = (int32_t *)malloc((size_t)g->depth * g->u_len * sizeof(int32_t));
        g->ready   = (uint8_t *)calloc((size_t)g->depth, 1);
        if (!g->r_store || !g->u_store || !g->ready) return SH_ERR_NOMEM;
    }
    l->n_threads = derive_threads(l);
    spill_start(l);
    spill_gauge_reset(l);
    if (l->n_threads > 0) {
        l->threads = (pthread_t *)calloc((size_t)l->n_threads, sizeof(pthread_t));
        if (!l->threads) return SH_ERR_NOMEM;
        l->stop = false;
        l->spill_mt_n = 0; l->spill_mint_cpu_ns = 0; l->spill_cpu_cap = 0;
        int made = 0;
        for (int i = 0; i < l->n_threads; i++) if (sh_thread_create(&l->threads[i], refill_main, l) == 0) made++; else break;
        l->n_threads = made;                       /* join exactly what was created */
        if (!made) { free(l->threads); l->threads = NULL; l->threads_running = false; return SH_OK; }
        l->threads_running = true;
        l->spill_cpu_running = spill_usable(l) && l->spill_cpu_on && l->spill_mint_max > 0 &&
                               sh_thread_create(&l->spill_cpu_thread, spill_cpu_main, l) == 0;
        if (spill_usable(l) && l->spill_cpu_on && !l->spill_cpu_running) {
            fprintf(stderr, "[shielded] pad spill cpu governor did not start; minting only while idle\n");
            l->spill_cpu_on = false;
        }

        /* Warm the pool before the first exchange. Returning with every ring
         * empty made the first token generate 49 pads on the request path
         * (19.6 ms of refill-on-path in a 64-token decode, all in token one).
         * Bounded: a pathological box still starts, it just pays on the path. */
        struct timespec dl; clock_gettime(CLOCK_MONOTONIC, &dl);
        dl.tv_sec += l->warm_ms / 1000; dl.tv_nsec += (long)(l->warm_ms % 1000) * 1000000L;
        if (dl.tv_nsec >= 1000000000L) { dl.tv_sec++; dl.tv_nsec -= 1000000000L; }
        pthread_mutex_lock(&l->pool_mu);
        pthread_cond_broadcast(&l->need_refill);
        for (;;) {
            bool warm = true;
            for (size_t i = 0; i < l->n_groups && warm; i++) warm = l->groups[i].count > 0;
            if (warm || l->stop) break;
            if (pthread_cond_timedwait(&l->pool_filled, &l->pool_mu, &dl) == ETIMEDOUT) break;
        }
        pthread_mutex_unlock(&l->pool_mu);
    }
    return sh_integrity_failed(l) ? SH_ERR_VERIFY : SH_OK;
}

/* Dealt mode: a short ring means the importers have not caught up yet, not
 * that pads can be made here. Wait for m ready pads (the deficit logic keeps
 * the threads importing) up to the bank wait; past that the request fails
 * with EXHAUST and the bank is genuinely behind. */
static void dealt_wait(sh_link *l, sh_group *g, int m) {
    pthread_mutex_lock(&l->pool_mu);
    if (g->count < m && !l->stop) {
        const int before = g->count;
        const double started = now_ms();
        struct timespec dl; clock_gettime(CLOCK_MONOTONIC, &dl);
        dl.tv_sec += l->pad_bank_wait_ms / 1000; dl.tv_nsec += (long)(l->pad_bank_wait_ms % 1000) * 1000000L;
        if (dl.tv_nsec >= 1000000000L) { dl.tv_sec++; dl.tv_nsec -= 1000000000L; }
        pthread_cond_broadcast(&l->need_refill);
        while (g->count < m && !l->stop) {
            if (pthread_cond_timedwait(&l->pool_filled, &l->pool_mu, &dl) == ETIMEDOUT) break;
        }
        /* This wait was already charged to mask_ms by the exchange caller.
         * Expose it separately so importing pads is not mistaken for masking
         * arithmetic. take_pads sees these slots ready and will not recount. */
        l->pad_wait_ms += now_ms() - started;
        l->pads_waited += (uint64_t)((g->count < m ? g->count : m) - before);
    }
    pthread_mutex_unlock(&l->pool_mu);
}

/* Take up to m ready pads from the front of group g's ring, by slot index.
 * They are consumed here and held until release_pads. */
/* One contiguous piece of a row's mask. Every pointer moves by the same
 * offset, which is what makes the range split legal here. */
#define SH_PAR_MIN_MASK 1024
typedef struct {
    const sh_simd *simd;
    const int64_t *x;
    const int32_t *r;
    int8_t *p0, *p1, *p2;
} sh_mask_range;
static void sh_mask_range_fn(void *ctx, int64_t lo, int64_t hi) {
    const sh_mask_range *mr = (const sh_mask_range *)ctx;
    mr->simd->mask_planes(mr->x + lo, mr->r + lo, (size_t)(hi - lo),
                          mr->p0 + lo, mr->p1 + lo, mr->p2 + lo);
}

static int take_pads(sh_link *l, sh_group *g, int m, int *slots) {
    pthread_mutex_lock(&l->pool_mu);
    l->spill_last_take = now_ms();               /* the link is busy: no new spill mints */
    g->sp_last_m = m;                            /* prompt chunk or decode step: decides what refills import */
    const int before = g->count < m ? g->count : m;
    /* An in-flight full refill can finish sooner than a separate, partial
     * request-thread refill. Only wait when the missing pads are ALREADY
     * reserved, and release the mutex while their producers write/publish.
     * A timeout consumes only the ready prefix; unpublished and held slots
     * remain owned exactly as before. Default zero preserves the old path. */
    if (l->pad_wait_us > 0 && !l->stop && g->count < m &&
        g->count + g->generating >= m) {
        const double started = now_ms();
        struct timespec dl; clock_gettime(CLOCK_MONOTONIC, &dl);
        dl.tv_nsec += (long)l->pad_wait_us * 1000L;
        if (dl.tv_nsec >= 1000000000L) { dl.tv_sec++; dl.tv_nsec -= 1000000000L; }
        while (!l->stop && g->count < m && g->generating > 0) {
            if (pthread_cond_timedwait(&l->pool_filled, &l->pool_mu, &dl) != 0) break;
        }
        l->pad_wait_ms += now_ms() - started;
    }
    int take = g->count < m ? g->count : m;
    l->pads_waited += (uint64_t)(take - before);
    for (int i = 0; i < take; i++) slots[i] = (g->head + i) % g->depth;
    g->head = (g->head + take) % g->depth;
    g->count -= take;
    g->held += take;
    pthread_mutex_unlock(&l->pool_mu);
    return take;
}

/* The slots may be overwritten from here on; the deficit they open is what
 * wakes a refill thread. */
static void release_pads(sh_link *l, sh_group *g, int n) {
    if (n <= 0) return;
    pthread_mutex_lock(&l->pool_mu);
    g->held -= n;
    pthread_cond_signal(&l->need_refill);
    pthread_mutex_unlock(&l->pool_mu);
}

/* --- start: connect, upload public weights, install the vetted graph ------ */
static int json_append(char **buf, size_t *len, size_t *cap, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    for (;;) {
        size_t avail = *cap - *len;
        va_list cp; va_copy(cp, ap);
        int n = vsnprintf(*buf + *len, avail, fmt, cp);
        va_end(cp);
        if (n < 0) { va_end(ap); return SH_ERR_NOMEM; }
        if ((size_t)n < avail) { *len += (size_t)n; va_end(ap); return SH_OK; }
        size_t ncap = (*cap ? *cap : 1024) * 2;
        while (ncap < *len + (size_t)n + 1) ncap *= 2;
        char *nb = (char *)realloc(*buf, ncap);
        if (!nb) { va_end(ap); return SH_ERR_NOMEM; }
        *buf = nb; *cap = ncap;
    }
}

/* One integer field of the HELLO reply, for a LOG LINE only (-1 when absent);
 * the two workers space their JSON differently, so walk past the colon. */
static double hello_num(const char *hello, const char *key) {
    const char *p = strstr(hello, key);
    if (!p) return -1.0;
    p += strlen(key);
    while (*p == ' ' || *p == ':') p++;
    return strtod(p, NULL);
}

/* Optional capability, never an allocation size or a security assertion.
 * Accept only a bounded unsigned JSON integer. Missing/malformed means off. */
static uint64_t hello_public_cache_bytes(const char *hello) {
    const char *key = "\"public_weight_cache_bytes\"";
    const char *p = strstr(hello, key); if (!p) return 0;
    p += strlen(key); while (*p == ' ' || *p == '\t') p++;
    if (*p++ != ':') return 0;
    while (*p == ' ' || *p == '\t') p++;
    if (*p < '0' || *p > '9') return 0;
    uint64_t value = 0;
    do {
        const unsigned d = (unsigned)(*p++ - '0');
        if (value > (UINT64_MAX-d)/10) return 0;
        value = value*10+d;
    } while (*p >= '0' && *p <= '9');
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return (*p == ',' || *p == '}') ? value : 0;
}

static int public_cache_call(sh_link *l, const sh_node *nd, uint8_t action, bool *hit) {
    uint8_t payload[57]; payload[0] = action;
    /* SET_TENSOR's header is the same three u64s; no format duplication. */
    sh_pack_set_tensor_header(payload+1, 1, (uint64_t)nd->w_off, (uint64_t)(nd->K*nd->N));
    memcpy(payload+25, nd->public_digest, 32);
    sh_reply reply = {0};
    int rc = sh_pipe_call(l->pipe, SH_CMD_PUBLIC_WEIGHT_CACHE, payload, sizeof payload, &reply);
    if (rc == SH_OK) {
        if (reply.len != 1 || !reply.data || ((const uint8_t *)reply.data)[0] > 1) rc = SH_ERR_PROTO;
        else *hit = ((const uint8_t *)reply.data)[0] != 0;
    }
    sh_reply_free(&reply);
    if (rc != SH_OK) snprintf(l->err, sizeof l->err, "public weight cache %s %s: %s",
        action ? "admit" : "lookup", nd->name, rc == SH_ERR_PROTO ? "invalid reply" : sh_pipe_last_error(l->pipe));
    return rc;
}

/* One cached-weight chunk read on a helper thread (sh_link_start's upload): the node's authenticated
 * reader fills buf[0..part) from offset off; rc carries the reader's verdict back to the loop. */
typedef struct { sh_node *nd; size_t off, part; uint8_t *buf; int rc; } sh_prefetch;
static void *prefetch_main(void *arg) {
    sh_prefetch *p = (sh_prefetch *)arg;
    p->rc = p->nd->w_read(p->nd->w_ctx, p->off, p->buf, p->part);
    return NULL;
}

int sh_link_start(sh_link *l) {
    /* Binding mutates the reader table; stop old importers before checking
     * it, including on reconnect. Joining also observes their final latch. */
    if (l->dealt) stop_threads(l);
    /* A reconnect retains the prepared secret challenges. Once the peer has
     * failed one, never give it another verification attempt with those same
     * challenges. Recovery requires a new link and fresh registration. */
    if (sh_integrity_failed(l)) {
        snprintf(l->err, sizeof l->err, "link retired after verification failure; recreate trusted state");
        return SH_ERR_VERIFY;
    }
    int err = SH_OK;
    const int binding = dealt_bind(l);
    if (binding != SH_OK) return binding;  /* no connect, upload or reservation */
    if (l->pipe) { sh_pipe_close(l->pipe); l->pipe = NULL; }
    sh_idle_new_pipe(&l->idle);   /* the next sample comes from a counter starting at zero */
    /* vsock first when the guest was told the worker listens on one, TCP as the
     * fallback: a guest without the vsock driver, or a host without the
     * device, still reaches the card over slirp -- more slowly, not not at all. */
    int vport = l->vsock_port;
    /* Unset means "if this guest has a vsock device, the worker listens on the
     * same port number there" -- which is what the launcher does -- so a guest
     * with the driver gets the fast path with no configuration at all. 0
     * disables it explicitly. A port nothing answers on fails the connect at
     * once and the link takes TCP. */
    if (vport < 0) vport = access("/dev/vsock", F_OK) == 0 ? l->port : 0;
    if (vport > 0) {
        l->pipe = sh_pipe_open("vsock", vport, &err);
        if (l->pipe) snprintf(l->transport, sizeof l->transport, "vsock:%d", vport);
        else snprintf(l->transport, sizeof l->transport, "tcp %s:%d (vsock port %d unreachable)", l->host, l->port, vport);
    } else {
        snprintf(l->transport, sizeof l->transport, "tcp %s:%d", l->host, l->port);
    }
    if (!l->pipe) l->pipe = sh_pipe_open(l->host, l->port, &err);
    if (!l->pipe) { snprintf(l->err, sizeof l->err, "connect %s:%d failed", l->host, l->port); return err; }

    uint8_t pay[256]; sh_reply rep;
    /* The tenant's slice of the card, reserved at HELLO (protocol 1.3). The
     * manager sets SHIELDED_RESERVE_BYTES from the share the deployment bought;
     * the worker holds that much device memory for this connection until it
     * closes, and refuses the HELLO when the card cannot give it -- which this
     * link treats like any other failed start: the backend computes in the
     * enclave and reconnects with backoff, so the tenant runs until the memory
     * is there. Unset or 0 sends the 4-byte HELLO every worker accepts and
     * reserves nothing. Nothing in the reply is trusted beyond the version:
     * the reservation is the untrusted host's own bookkeeping, and the
     * tenant's privacy does not depend on it. */
    const uint64_t reserve = l->reserve_bytes;
    size_t n = sh_pack_hello(pay, 1, reserve);
    int rc = sh_pipe_call(l->pipe, SH_CMD_HELLO, pay, n, &rep);
    if (rc != SH_OK) { snprintf(l->err, sizeof l->err, "HELLO%s: %s", reserve ? " (with reservation)" : "", sh_pipe_last_error(l->pipe)); return rc; }
    /* The one-frame exchange is protocol 1.1; an older worker would refuse it
     * as an unknown command, so say what is wrong here rather than there. */
    int hello_minor = -1;
    uint64_t public_cache_bytes = 0;
    {
        /* HELLO is JSON from either worker. Version and optional public-cache
         * capability control the wire path; neither authenticates a product. */
        int major = -1, minor = -1;
        char hello[1024] = { 0 };   /* bounded capability parsing; no peer-sized allocation */
        if (rep.data) snprintf(hello, sizeof hello, "%.*s", (int)(rep.len < sizeof hello - 1 ? rep.len : sizeof hello - 1), (const char *)rep.data);
        const char *p = strstr(hello, "\"version\"");
        if (p) {
            p += 9;
            while (*p && (*p < '0' || *p > '9')) p++;
            major = atoi(p);
            while (*p >= '0' && *p <= '9') p++;
            while (*p && (*p < '0' || *p > '9')) p++;
            minor = atoi(p);
        }
        if (major != 1 || minor < 1) {
            sh_reply_free(&rep);
            snprintf(l->err, sizeof l->err, "worker speaks protocol %d.%d; this link needs 1.1 (FIELD_GEMM)", major, minor);
            return SH_ERR_PROTO;
        }
        /* 1.2 adds FIELD_GEMM24: the same request, the products as 3-byte
         * values. Every product is balanced below 2^23.8, so nothing is lost
         * and 25% of every reply's bytes are -- 152 KB of the 0.5B's lm_head
         * exchange, the largest of its 49. A 1.1 worker never sees command
         * 13; SHIELDED_REPLY32=1 keeps the int32 form against a 1.2 worker
         * (the A/B, and the escape hatch). What crosses is unchanged either
         * way: the same masked products, narrower. */
        const char *w32 = getenv("SHIELDED_REPLY32");
        l->ywidth = (minor >= 2 && !(w32 && *w32 && strcmp(w32, "0"))) ? 3 : 4;
        {
            size_t tl = strlen(l->transport);
            snprintf(l->transport + tl, sizeof l->transport - tl, " proto 1.%d reply int%d", minor, l->ywidth * 8);
        }
        hello_minor = minor;
        const char *pc = getenv("SHIELDED_PUBLIC_WEIGHT_CACHE");
        if (l->verify && pc && !strcmp(pc, "1") && minor >= 4)
            public_cache_bytes = hello_public_cache_bytes(hello);
        /* What the worker says it holds: this connection's reservation and the
         * sum over every live tenant, under SHIELDED_VERBOSE. Logged, never
         * acted on (see the reserve comment above). A 1.2 worker sends neither. */
        const char *vb = getenv("SHIELDED_VERBOSE");
        if (vb && *vb && strcmp(vb, "0")) {
            const double MB = 1024.0 * 1024.0;
            fprintf(stderr, "[shielded] link: proto 1.%d, asked to reserve %.0f MiB; worker holds %.0f MiB for this link, "
                            "%.0f MiB for all tenants, driver free %.0f MiB of a %.0f MiB budget\n",
                    minor, (double)reserve / MB,
                    hello_num(hello, "\"vram_reserve\"") / MB, hello_num(hello, "\"vram_reserved\"") / MB,
                    hello_num(hello, "\"vram_free\"") / MB, hello_num(hello, "\"vram_budget\"") / MB);
        }
    }
    sh_reply_free(&rep);

    const struct { int64_t size; const char *role; } bufs[2] = {
        { l->wbytes, "weights" }, { l->abytes, "activations" } };
    for (int i = 0; i < 2; i++) {
        n = sh_pack_alloc(pay, (uint64_t)bufs[i].size, bufs[i].role);
        rc = sh_pipe_call(l->pipe, SH_CMD_ALLOC_BUFFER, pay, n, &rep);
        if (rc != SH_OK) { snprintf(l->err, sizeof l->err, "ALLOC(%s): %s",
                                    bufs[i].role, sh_pipe_last_error(l->pipe)); return rc; }
        sh_reply_free(&rep);
    }

    /* Weights are PUBLIC: they cross in the clear, by design. Cached (authenticated, on-disk) weights are
     * read chunk by chunk and each chunk is one request/reply round trip. Default: 1 MiB chunks, read then
     * sent, serially (the 27B's 24 GiB upload was the SUM of cache read + link time that way: 16 MB/s on a
     * 31 MB/s link). SHIELDED_UPLOAD_PREFETCH=<MiB> (1..64) turns on the pipelined form: a helper thread
     * reads + authenticates the NEXT chunk into a second buffer while the current one is in flight. Two
     * buffers at most; the helper only ever calls the node's reader, never the socket; it is joined before
     * any failure returns; a buffer is sent only after its reader returned success. Weights held in RAM
     * (no reader) go in 32 MiB chunks as before. */
    long pf_mib = 0; { const char *e = getenv("SHIELDED_UPLOAD_PREFETCH"); if (e && *e) pf_mib = strtol(e, NULL, 10); }
    const bool prefetch = pf_mib >= 1 && pf_mib <= 64;
    uint64_t cache_hit_bytes = 0; size_t cache_hits = 0, cache_misses = 0;
    for (size_t i = 0; i < l->n_nodes; i++) {
        sh_node *nd = &l->nodes[i];
        const size_t bytes = (size_t)(nd->K * nd->N);
        const bool reuse = nd->public_digest_ready && bytes <= public_cache_bytes;
        if (reuse) {
            bool hit = false; rc = public_cache_call(l, nd, 0, &hit);
            if (rc != SH_OK) return rc;
            if (hit) { cache_hits++; cache_hit_bytes += bytes; continue; }
            cache_misses++;
        }
        const size_t CHUNK = nd->w_read ? (prefetch ? (size_t)pf_mib << 20 : 1u << 20) : 32u << 20;
        uint8_t *bufs[2] = { NULL, NULL };
        if (nd->w_read) {
            bufs[0] = (uint8_t *)malloc(CHUNK);
            if (prefetch) bufs[1] = (uint8_t *)malloc(CHUNK);
            if (!bufs[0] || (prefetch && !bufs[1])) { free(bufs[0]); free(bufs[1]); return SH_ERR_NOMEM; }
        }
        sh_prefetch pf = { nd, 0, 0, NULL, 0 };
        int cur = 0;
        for (size_t off = 0; off < bytes; off += CHUNK) {
            const size_t part = bytes - off < CHUNK ? bytes - off : CHUNK;
            if (nd->w_read && (!prefetch || off == 0)) {   /* serial mode every chunk; pipelined mode the first only */
                if (nd->w_read(nd->w_ctx, off, bufs[cur], part) != 0) {
                    free(bufs[0]); free(bufs[1]); snprintf(l->err, sizeof l->err, "authenticated weight read failed: %s", nd->name);
                    return SH_ERR_VERIFY;
                }
            }
            const uint8_t *data = nd->w_read ? bufs[cur] : (const uint8_t *)nd->w + off;
            pthread_t th; bool started = false; const size_t next = off + CHUNK;
            const bool ahead = prefetch && nd->w_read && next < bytes;
            if (ahead) {   /* the next chunk's read starts before this exchange leaves */
                pf.off = next; pf.part = bytes - next < CHUNK ? bytes - next : CHUNK; pf.buf = bufs[cur ^ 1]; pf.rc = 0;
                started = sh_thread_create(&th, prefetch_main, &pf) == 0;
                if (!started) prefetch_main(&pf);   /* no thread: read it here, still correct */
            }
            uint8_t hdr[24];
            sh_pack_set_tensor_header(hdr, 1, (uint64_t)(nd->w_off + (int64_t)off), part);
            sh_frame f = { SH_CMD_SET_TENSOR, hdr, 24, data, part };
            rc = sh_pipe_exchange(l->pipe, &f, 1, &rep);
            if (started) pthread_join(th, NULL);   /* joined before ANY return below */
            if (rc != SH_OK) { free(bufs[0]); free(bufs[1]); snprintf(l->err, sizeof l->err, "upload %s: %s", nd->name, sh_pipe_last_error(l->pipe)); return rc; }
            sh_reply_free(&rep);
            if (ahead) {
                if (pf.rc != 0) { free(bufs[0]); free(bufs[1]); snprintf(l->err, sizeof l->err, "authenticated weight read failed: %s", nd->name); return SH_ERR_VERIFY; }
                cur ^= 1;   /* the authenticated next chunk becomes the current one */
            }
        }
        free(bufs[0]); free(bufs[1]);
        if (reuse) {
            bool admitted = false; rc = public_cache_call(l, nd, 1, &admitted);
            if (rc != SH_OK) return rc;
        }
    }
    if (public_cache_bytes) fprintf(stderr, "[shielded] public worker cache: hits=%zu misses=%zu skipped_upload_bytes=%llu (worker claims; products still verified)\n",
        cache_hits, cache_misses, (unsigned long long)cache_hit_bytes);
    char *js = NULL; size_t jl = 0, jc = 0;
    json_append(&js, &jl, &jc, "{\"nodes\":[");
    for (size_t i = 0; i < l->n_nodes; i++) {
        sh_node *nd = &l->nodes[i];
        json_append(&js, &jl, &jc,
            "%s{\"op\":\"FIELD_GEMM\",\"id\":\"%s\",\"w\":{\"bid\":1,\"offset\":%lld},"
            "\"x\":{\"bid\":2,\"offset\":%lld},\"y\":{\"bid\":2,\"offset\":%lld},"
            "\"K\":%lld,\"N\":%lld,\"max_m\":%d}",
            i ? "," : "", nd->name, (long long)nd->w_off,
            (long long)nd->x_off, (long long)nd->y_off,
            (long long)nd->K, (long long)nd->N, nd->max_m);
    }
    /* The exchange this link uses returns its products in-band, so declared
     * outputs exist only to satisfy install's rule that something be readable. */
    json_append(&js, &jl, &jc, "],\"outputs\":[");
    for (size_t i = 0; i < l->n_nodes; i++)
        json_append(&js, &jl, &jc, "%s{\"bid\":2,\"offset\":%lld,\"nbytes\":%lld}",
                    i ? "," : "", (long long)l->nodes[i].y_off, (long long)(l->nodes[i].N * 4));
    json_append(&js, &jl, &jc, "]}");
    rc = sh_pipe_call(l->pipe, SH_CMD_GRAPH_INSTALL, js, jl, &rep);
    free(js);
    if (rc != SH_OK) { snprintf(l->err, sizeof l->err, "GRAPH_INSTALL: %s", sh_pipe_last_error(l->pipe)); return rc; }
    sh_reply_free(&rep);

    /* The shared-memory ring (shielded-wire.h): opened only when per-link
     * config or the legacy environment names one AND the worker speaks 1.2.
     * Anything short of a
     * granted ring leaves the link on the socket exactly as before; the
     * transport string says which, so the profile line can be read. */
    {
        const char *shm = l->shm_configured ? l->shm_path : getenv("SHIELDED_SHM");
        if (shm && *shm && !env_int("SHIELDED_SHM_DISABLE", 0, 0, 1)) {
            if (hello_minor < 2) {
                snprintf(l->transport + strlen(l->transport), sizeof l->transport - strlen(l->transport),
                         " (shm ring: worker speaks 1.%d, needs 1.2)", hello_minor);
            } else {
                int index = l->shm_configured ? -1 : env_int("SHIELDED_SHM_RING", 0, -1, 7);
                const char *nb = getenv("SHIELDED_SHM_BYTES");
                size_t bytes = l->shm_configured ? l->shm_bytes : (nb && *nb ? (size_t)strtoull(nb, NULL, 10) : 0);
                int arc = index < 0 ? sh_pipe_shm_attach_available(l->pipe, shm, bytes, &index)
                                    : sh_pipe_shm_attach(l->pipe, shm, index, bytes);
                if (arc == SH_OK)
                    snprintf(l->transport + strlen(l->transport), sizeof l->transport - strlen(l->transport),
                             " + shm ring %d (%s)%s", index, shm,
                             sh_pipe_ring_stream_load(l->pipe) ? " stream-load" : "");
                else if (arc == SH_ERR_IO)
                    snprintf(l->transport + strlen(l->transport), sizeof l->transport - strlen(l->transport), " (shm ring unavailable: %s)", sh_pipe_last_error(l->pipe));
                else {
                    /* The worker answered SHM_ATTACH with nonsense: the same
                     * peer serves the socket, so do not trust it either. */
                    snprintf(l->err, sizeof l->err, "SHM_ATTACH: %s", sh_pipe_last_error(l->pipe));
                    return arc;
                }
            }
        }
    }

    return start_pools(l);
}

/* The SIMD mask and Freivalds kernels have finite integer bounds, so the
 * activation is checked at the link boundary before any pad is taken or any
 * output written. The predicate lives in the SIMD table (shielded-simd.c),
 * which is compiled with the arch flags this file is not: the identical source
 * here scanned ~9.9 MB a pass at baseline ISA. This limit is public and never
 * adapted, and the check keeps its place in the order -- before pads, before
 * output. */

/* --- Freivalds over an unrelated prime ------------------------------------ */
static bool fv_check(const sh_link *l, const sh_node *nd, const int64_t *x, const int64_t *y, int32_t m) {
    if (m < 0 || m > nd->max_m || !x || !y ||
        !l->simd->values_within(x, (size_t)m * nd->K, SH_FV_X_LIMIT) ||
        !l->simd->values_within(y, (size_t)m * nd->N, (uint64_t)SH_HALF_M + 1)) return false;
    for (int32_t row = 0; row < m; row++) {
        int64_t lhs[SH_FV_REPS], rhs[SH_FV_REPS];
        l->simd->fv_dots(y + (int64_t)row * nd->N, nd->s32, SH_FV_REPS, nd->N, lhs);
        l->simd->fv_dots_x(x + (int64_t)row * nd->K, nd->st32, SH_FV_REPS, nd->K, rhs);
        for (int rep = 0; rep < SH_FV_REPS; rep++)
            if (lhs[rep] != rhs[rep]) return false;
    }
    return true;
}

int sh_link_gemm_local(sh_link *l, const int *nodes, size_t n_nodes,
                       const int64_t *x_field, int32_t m, int64_t **y_out) {
    return sh_link_gemm_local_stride(l, nodes, n_nodes, x_field, m, y_out, NULL);
}

int sh_link_gemm_local_stride(sh_link *l, const int *nodes, size_t n_nodes,
                       const int64_t *x_field, int32_t m, int64_t **y_out,
                       const int64_t *y_stride) {
    if (sh_integrity_failed(l)) return SH_ERR_VERIFY;
    if (!n_nodes || !m) return SH_OK;
    if (!l || !nodes || !x_field || !y_out || m < 0 || n_nodes > SH_GROUP_MAX) return SH_ERR_PROTO;
    /* Every node in a group reads the SAME activation, so this used to rescan
     * the same prefix once per node. `checked` advances instead, so each
     * element is examined exactly once while the order in which PROTO and
     * VERIFY are reported stays what it was -- a node's own validity is still
     * decided before the range its K implies is looked at. */
    size_t checked = 0;
    for (size_t i = 0; i < n_nodes; i++) {
        if (nodes[i] < 0 || (size_t)nodes[i] >= l->n_nodes || !y_out[i]) return SH_ERR_PROTO;
        const sh_node *nd = &l->nodes[nodes[i]];
        if (m > nd->max_m) return SH_ERR_PROTO;
        const size_t need = (size_t)m * (size_t)nd->K;
        if (need > checked) {
            if (!l->simd->values_within(x_field + checked, need - checked, SH_FV_X_LIMIT)) {
                snprintf(l->err, sizeof l->err, "activation outside the supported integer range; abort the request");
                return SH_ERR_VERIFY;
            }
            checked = need;
        }
    }
    for (size_t i = 0; i < n_nodes; i++) {
        const sh_node *nd = &l->nodes[nodes[i]];
        const int64_t K = nd->K, N = nd->N;
        int64_t *y = y_out[i];
        const int64_t ystr = y_stride ? y_stride[i] : N;
        if (nd->w_read) {
            // One bounded block of whole weight rows, reused across all inputs.
            const int64_t rows = K < (1 << 20) ? (1 << 20) / K : 1;
            int8_t *block = (int8_t *)malloc((size_t)rows * K);
            if (!block) return SH_ERR_NOMEM;
            for (int64_t j0 = 0; j0 < N; j0 += rows) {
                const int64_t nr = N - j0 < rows ? N - j0 : rows;
                if (nd->w_read(nd->w_ctx, (uint64_t)j0 * K, (uint8_t *)block, (size_t)nr * K) != 0) {
                    free(block); snprintf(l->err, sizeof l->err, "authenticated weight read failed: %s", nd->name);
                    return SH_ERR_VERIFY;
                }
                for (int32_t row = 0; row < m; row++) for (int64_t j = 0; j < nr; j++) {
                    int64_t acc = 0;
                    for (int64_t k = 0; k < K; k++) acc += x_field[(int64_t)row * K + k] * block[j * K + k];
                    y[(int64_t)row * ystr + j0 + j] = sh_balanced(acc);
                }
            }
            free(block);
            l->macs += (uint64_t)m * K * N;
            continue;
        }
        for (int32_t row = 0; row < m; row++) {
            const int64_t *xr = x_field + (int64_t)row * K;
            int64_t *yr = y + (int64_t)row * ystr;
            for (int64_t j = 0; j < N; j++) {
                const int8_t *w = nd->w + j * K;
                int64_t acc = 0;
                for (int64_t k = 0; k < K; k++) acc += xr[k] * w[k];
                yr[j] = sh_balanced(acc);
            }
        }
        l->macs += (uint64_t)m * (uint64_t)K * (uint64_t)N;
    }
    return SH_OK;
}

bool sh_link_is_live(const sh_link *l) { return l && sh_pipe_is_live(l->pipe); }
bool sh_link_is_dealt(const sh_link *l) { return l && l->dealt; }

const int8_t *sh_link_weight(const sh_link *l, int node) {
    if (!l || node < 0 || (size_t)node >= l->n_nodes) return NULL;
    return l->nodes[node].w;
}

bool sh_link_verify(const sh_link *l, int node, const int64_t *x, const int64_t *y, int32_t m) {
    if (!l || !l->verify || node < 0 || (size_t)node >= l->n_nodes) return false;
    return fv_check(l, &l->nodes[node], x, y, m);
}

static int ensure(void **p, size_t *cap, size_t want) {
    if (*cap >= want) return SH_OK;
    void *n = realloc(*p, want);
    if (!n) return SH_ERR_NOMEM;
    *p = n; *cap = want;
    return SH_OK;
}

typedef struct {
    sh_link *link;
    const int *nodes;
    size_t n_nodes;
    const int64_t *x;
    int32_t m;
    double elapsed_ms;
    int ran;            /* the transport ran it; see the rhs_done note below */
} sh_verify_work;

/* The RHS depends only on the trusted input and secret check vectors, so it
 * can run while the masked request travels. Nothing here touches the pipe or
 * a reply. The worker still has to pass the SAME unrelated-prime check before
 * the caller can use any output. */
/* The window with no RHS to compute: the hook alone. Same contract. */
static void sh_idle_only(void *ctx) {
    sh_link *l = ((sh_verify_work *)ctx)->link;
    if (l->idle_fn) l->idle_fn(l->idle_ctx);
}
static void sh_verify_rhs(void *ctx) {
    sh_verify_work *w = (sh_verify_work *)ctx;
    sh_link *l = w->link;
    const double t0 = now_ms();
    for (size_t i = 0; i < w->n_nodes; i++) {
        const sh_node *nd = &l->nodes[w->nodes[i]];
        for (int32_t row = 0; row < w->m; row++)
            l->simd->fv_dots_x(w->x + (size_t)row * nd->K, nd->st32, SH_FV_REPS, nd->K,
                               l->fv_rhs + (i * (size_t)w->m + row) * SH_FV_REPS);
    }
    w->elapsed_ms = now_ms() - t0;
    /* Then the backend's deferred work, if it registered any. Ordering is
     * deliberate: the RHS is what the window exists for and must not be
     * displaced by an optional passenger. */
    if (l->idle_fn) l->idle_fn(l->idle_ctx);
    w->ran = 1;
    l->profile.rhs_ms += w->elapsed_ms;
}

/* The int32 wire format can represent much more than a field element. Check
 * the untrusted values before kernels subtract a pad in int32 or accumulate
 * under the |y| < 2^24 bound. Unsigned addition avoids overflow even for
 * INT32_MIN/MAX; the reduction permits vectorization of this extra int32-only
 * pass. Packed int24 inputs already keep subtraction/accumulation in range. */
/* The int32 reply range check used to live here. It is the same predicate, now
 * in the SIMD table (shielded-simd.c): this file is compiled once at baseline
 * ISA while that one is compiled twice with the arch flags, and at baseline the
 * check cost 3.5 ms of every 27B pass against 0.22 ms in the table. It is still
 * a SEPARATE pass that completes before any kernel touches the reply, because
 * the contract is that an out-of-range reply leaves the caller's output
 * untouched. test/fixtures/shielded-reply-balanced.c carries the portable
 * reference and holds every table's version to it at the field edges,
 * INT32_MIN/MAX, and a bad value in every position. */

int sh_link_gemm(sh_link *l, const int *nodes, size_t n_nodes,
                 const int64_t *x_field, int32_t m, int64_t **y_out) {
    return sh_link_gemm_stride(l, nodes, n_nodes, x_field, m, y_out, NULL);
}

/* The plaintext fault bits exist ONLY in a build compiled with
 * -DSHIELDED_ALLOW_FAULT_DIAG_PLAINTEXT, which no deployment build passes
 * (metal/build-image.mjs and the Android anchor builds have fixed flag lists;
 * test/shielded-fault-logs pins that). An environment variable alone is not a
 * gate here: a deployment's environment can be set by the host. In any other
 * build the variable is ignored and one line says so. */
int sh_fault_diag_plaintext(void) {
    static int v = -1;
    if (v < 0) {
        const char *e = getenv("SHIELDED_FAULT_DIAG_PLAINTEXT");
#ifdef SHIELDED_ALLOW_FAULT_DIAG_PLAINTEXT
        v = e && !strcmp(e, "1");
#else
        if (e && *e && strcmp(e, "0"))
            fprintf(stderr, "[shielded] SHIELDED_FAULT_DIAG_PLAINTEXT ignored: this build does not allow activation-dependent fault diagnostics\n");
        v = 0;
#endif
    }
    return v;
}

void sh_fv_postmortem(const int8_t *w, int64_t K, int64_t N, const int64_t *x, int m,
                      const int64_t *y, int64_t ystr, int plaintext_bits, char *out, size_t cap) {
    if (!out || !cap) return;
    out[0] = 0;
    if (!w || !x || !y || K <= 0 || N <= 0 || m <= 0) { snprintf(out, cap, "no local weights; no recompute"); return; }
    /* Everything accumulated here except `wraps` is a function of which values
     * differ, i.e. of the worker's error alone (see the header). */
    uint64_t bad = 0, wraps = 0, blocks = 0, rows_bad = 0;
    int64_t first = -1, last = -1;
    for (int r = 0; r < m; r++) {
        uint64_t row_bad = 0;
        int64_t prev_block = -1;
        for (int64_t j = 0; j < N; j++) {
            const int8_t *wr = w + (size_t)j * (size_t)K;
            const int64_t *xr = x + (size_t)r * (size_t)K;
            int64_t sacc = 0;
            for (int64_t k = 0; k < K; k++) sacc += (int64_t)wr[k] * xr[k];
            const int64_t truth = sh_balanced(sacc);
            if (truth != sacc) wraps++;
            if (y[(size_t)r * (size_t)ystr + (size_t)j] != truth) {
                bad++; row_bad++;
                if (first < 0 || j < first) first = j;
                if (j > last) last = j;
                const int64_t blk = j / 32;
                if (blk != prev_block) { blocks++; prev_block = blk; }
            }
        }
        if (row_bad) rows_bad++;
    }
    char wrapped[64] = "";
    if (plaintext_bits) snprintf(wrapped, sizeof wrapped, " [plaintext opt-in: %llu true value(s) outside the field]", (unsigned long long)wraps);
    snprintf(out, cap, "recomputed %d x %lld: %llu of %llu values differ, in %llu row(s), %llu 32-col block run(s), cols %lld..%lld%s%s",
             m, (long long)N, (unsigned long long)bad, (unsigned long long)((uint64_t)m * (uint64_t)N),
             (unsigned long long)rows_bad, (unsigned long long)blocks, (long long)first, (long long)last,
             bad ? "" : " (the reply matches the local product: the CHECK side is suspect)", wrapped);
}

int sh_link_gemm_stride(sh_link *l, const int *nodes, size_t n_nodes,
                 const int64_t *x_field, int32_t m, int64_t **y_out,
                 const int64_t *y_stride) {
    const double t_entry = now_ms();   /* prologue: input range scan and buffer ensures */
    if (sh_integrity_failed(l)) {
        snprintf(l->err, sizeof l->err, "link retired after verification failure; recreate trusted state");
        return SH_ERR_VERIFY;
    }
    if (!n_nodes) return SH_OK;
    if (!l || !nodes || !x_field || !y_out) return SH_ERR_PROTO;
    if (n_nodes > SH_GROUP_MAX) { snprintf(l->err, sizeof l->err, "too many nodes in one exchange"); return SH_ERR_PROTO; }
    for (size_t i = 0; i < n_nodes; i++)
        if (nodes[i] < 0 || (size_t)nodes[i] >= l->n_nodes || !y_out[i]) return SH_ERR_PROTO;
    sh_group *g = &l->groups[l->nodes[nodes[0]].group];
    for (size_t i = 0; i < n_nodes; i++)
        if (l->nodes[nodes[i]].group != l->nodes[nodes[0]].group) {
            snprintf(l->err, sizeof l->err, "exchanged nodes do not share an activation"); return SH_ERR_PROTO;
        }
    if (m < 1 || m > g->max_m) {
        snprintf(l->err, sizeof l->err, "m=%d outside this group's [1,%d]", m, g->max_m); return SH_ERR_PROTO;
    }
    const int64_t K = g->K;
    if (!l->simd->values_within(x_field, (size_t)m * K, SH_FV_X_LIMIT)) {
        snprintf(l->err, sizeof l->err, "activation outside the supported integer range; abort the request");
        return SH_ERR_VERIFY;
    }
    /* The RHS depends only on the trusted input and the secret check vectors,
     * so it is dead time on the one thread a decode round is serialized on --
     * ~3.6 ms per pass on the 27B. The ring publishes before it spins and
     * takes a work callback for exactly this. It used to be excluded whenever
     * a ring was attached, which looked like a leftover but was hiding the
     * rhs_done bug fixed below; with that fixed the exclusion is gone. */
    const bool overlap = l->verify && l->overlap_verify;
    int rc;
    /* Steady state allocates nothing: every buffer here has grown to its
     * largest use by the second token. */
    if ((rc = ensure((void **)&l->planes, &l->planes_cap, (size_t)3 * m * K)) != SH_OK) return rc;
    if ((rc = ensure((void **)&l->hdr,    &l->hdr_cap,    8 + 4 * n_nodes)) != SH_OK) return rc;
    if (overlap && (rc = ensure((void **)&l->fv_rhs, &l->fv_rhs_cap,
                               n_nodes * (size_t)m * SH_FV_REPS * sizeof(int64_t))) != SH_OK) return rc;
    if (l->p_cap < (size_t)m) {
        const int32_t **rp = (const int32_t **)realloc(l->rp, (size_t)m * sizeof *rp);
        if (rp) l->rp = rp;
        const int32_t **up = (const int32_t **)realloc(l->up, (size_t)m * sizeof *up);
        if (up) l->up = up;
        int *slots = (int *)realloc(l->slots, (size_t)m * sizeof *slots);
        if (slots) l->slots = slots;
        if (!rp || !up || !slots) return SH_ERR_NOMEM;
        l->p_cap = (size_t)m;
    }

    /* ONE pad per plaintext row -- rule 2 -- from the pool, or made here if the
     * pool is dry. Shared-x nodes see the same pad by construction: they are
     * in the same group and read the same masked planes. Pool pads are used IN
     * PLACE and held until the unmask below; the rows made here live in the
     * link's private scratch. Either way each row's pad is one pointer. */
    double t0 = now_ms();
    l->profile.pre_ms += t0 - t_entry;
    if (l->dealt && l->threads_running) dealt_wait(l, g, m);
    const double tp_a = now_ms();
    l->profile.dealt_wait_ms += tp_a - t0;
    const int took = l->threads_running ? take_pads(l, g, m, l->slots) : 0;
    l->profile.pads_ms += now_ms() - tp_a;
    /* A background rejection must reach the backend as an integrity error,
     * even if a different group still had ready pads. Taken pads stay burned. */
    if (sh_integrity_failed(l)) { rc = SH_ERR_VERIFY; goto fail; }
    for (int i = 0; i < took; i++) {
        l->rp[i] = g->r_store + (size_t)l->slots[i] * K;
        l->up[i] = g->u_store + (size_t)l->slots[i] * g->u_len;
    }
    if (took < m && l->dealt) {
        /* A dealt engine has no key to mint with; the bank is behind. */
        snprintf(l->err, sizeof l->err, "dealt pads: %d of %d ready for group %s; the bank is behind", took, m, l->nodes[g->nodes[0]].name);
        rc = SH_ERR_EXHAUST; goto fail;
    }
    if (took < m) {
        const int miss = m - took;
        if ((rc = ensure((void **)&l->r,       &l->r_cap,       (size_t)miss * K * sizeof(int32_t))) != SH_OK) goto fail;
        if ((rc = ensure((void **)&l->u,       &l->u_cap,       (size_t)miss * g->u_len * sizeof(int32_t))) != SH_OK) goto fail;
        if ((rc = ensure((void **)&l->gplanes, &l->gplanes_cap, (size_t)3 * miss * K)) != SH_OK) goto fail;
        if ((rc = ensure((void **)&l->acc,     &l->acc_cap,     (size_t)12 * l->Nmax * sizeof(int32_t))) != SH_OK) goto fail;
        gen_scratch s = { l->gplanes, l->acc };
        double tg = now_ms();
        /* The ring is short: import what the spill holds for this group, then
         * mint the rest here as before. */
        int from_spill = 0;
        if (l->threads_running && l->spill_io) {
            uint64_t wid[SP_TAKE_MAX];
            uint32_t slot0 = 0;
            pthread_mutex_lock(&l->pool_mu);
            from_spill = spill_take(l, g, miss, &slot0, wid);
            pthread_mutex_unlock(&l->pool_mu);
            if (from_spill > 0) {
                const int src = sh_spill_read(l->spill, (size_t)(g - l->groups), slot0, from_spill, wid, l->r, l->u, l->spill_io);
                pthread_mutex_lock(&l->pool_mu);
                spill_retire(l, g, slot0, from_spill);
                if (src == SH_OK) l->spill_onpath += (uint64_t)from_spill;
                else spill_fail(l, "a read on the request path", src);
                pthread_mutex_unlock(&l->pool_mu);
                if (src != SH_OK) from_spill = 0;      /* burned; mint all of them */
            }
        }
        rc = from_spill < miss
           ? generate(l, g, miss - from_spill, l->r + (size_t)from_spill * K, l->u + (size_t)from_spill * g->u_len, &s)
           : SH_OK;
        const double elapsed_ms = now_ms() - tg;
        l->profile.refill_ms += elapsed_ms;
        g->on_path_ms += elapsed_ms;
        if (rc != SH_OK) { snprintf(l->err, sizeof l->err, "pad bank exhausted; stall the request"); goto fail; }
        for (int i = 0; i < miss; i++) {
            l->rp[took + i] = l->r + (size_t)i * K;
            l->up[took + i] = l->u + (size_t)i * g->u_len;
        }
        l->pads_missed += (uint64_t)miss;
        g->pads_missed += (uint64_t)miss;
        l->profile.missed_pads += miss;
    }
    l->pads_used += (uint64_t)m; l->profile.used_pads += (uint64_t)m;
    g->pads_used += (uint64_t)m;

    /* Splitting the activation into its three byte planes is a pure map over
     * K with no reduction, and it sits on the one thread a decode round is
     * serialized on. SHIELDED_FIELD_THREADS spreads it; width 1 is this loop. */
    const double tk_a = now_ms();
    for (int32_t row = 0; row < m; row++) {
        sh_mask_range mr = { l->simd, x_field + (size_t)row * K, l->rp[row],
                             l->planes + (size_t)row * K,
                             l->planes + ((size_t)m + row) * K,
                             l->planes + ((size_t)2 * m + row) * K };
        sh_par_for(K, SH_PAR_MIN_MASK, sh_mask_range_fn, &mr);
    }
    {
        const double dk = now_ms() - tk_a;
        l->profile.mask_kernel_ms += dk;
        l->profile.mask_elems += (uint64_t)m * (uint64_t)K;
        if (dk > 0.020) { l->profile.mask_slow_n++; l->profile.mask_slow_ms += dk; }
    }
    const size_t hn = sh_pack_field_gemm(l->hdr, (uint32_t)n_nodes, (uint32_t)m, nodes);
    double t1 = now_ms(); l->profile.mask_ms += t1 - t0;

    {
        sh_frame f = { l->ywidth == 3 ? SH_CMD_FIELD_GEMM24 : SH_CMD_FIELD_GEMM, l->hdr, hn, l->planes, (size_t)3 * m * K };
        sh_reply rep;
        /* The reply length is OURS to know, from the request and the width
         * this exchange uses -- never anything the worker says. The ring
         * carries the int32 form only; the socket the negotiated one. A ring
         * miss (no reply in the spin budget, a length that is not `want`)
         * sends the SAME frame on the socket -- the same ciphertext under the
         * same pad, which tells the host nothing a retransmit would not. */
        const bool via_ring = sh_pipe_ring_live(l->pipe);
        const size_t yw = via_ring ? 4 : (size_t)l->ywidth;
        f.cmd = yw == 3 ? SH_CMD_FIELD_GEMM24 : SH_CMD_FIELD_GEMM;
        size_t want = 0;
        for (size_t i = 0; i < n_nodes; i++) want += (size_t)m * l->nodes[nodes[i]].N * yw;
        sh_verify_work work = { l, nodes, n_nodes, x_field, m, 0, 0 };
        /* The RHS runs in whichever path published the request first, and
         * EXACTLY once: the ring runs it inside its spin window (it publishes
         * before spinning, so the work happens even when no reply arrives),
         * and a fallback to the socket must then not ask for it again. */
        /* THE RHS RUNS EXACTLY ONCE, AND "ONCE" MUST MEAN OBSERVED.
         *
         * The ring refuses a frame BEFORE it publishes when the reply will not
         * fit its 6 MiB slot -- the 27B's prefill lm_head is 17 x 248320 x 4 =
         * 16.9 MB -- and then the work callback never runs. This used to set
         * rhs_done from `overlap` alone, so the socket fallback was told the
         * RHS had already been computed when it had not, and the unmask below
         * compared its LHS against an uninitialised fv_rhs. That is a
         * verification FAILURE on the first pass, i.e. the exact symptom that
         * had this whole overlap gated off behind !sh_pipe_ring_live(). Ask
         * the work item whether it ran. */
        if (via_ring) {
            rc = sh_pipe_ring_exchange_work(l->pipe, &f, want, &rep,
                                            overlap ? sh_verify_rhs : (l->idle_fn ? sh_idle_only : NULL), &work);
            { double ms = 0; uint64_t nn = 0; sh_pipe_idle(l->pipe, &ms, &nn);
              sh_idle_fold(&l->idle, (uint64_t)(ms * 1e6), nn); }
        } else {
            rc = SH_ERR_IO;
        }
        const bool served_ring = via_ring && rc == SH_OK;   /* for the post-mortem only */
        if (rc == SH_ERR_IO)
            rc = sh_pipe_exchange_work(l->pipe, &f, 1, &rep, (overlap && !work.ran) ? sh_verify_rhs : NULL, &work);
        /* Do not double-count RHS work in the phase totals. The contention
         * detector still sees the full send-to-receive wall time. */
        double t2 = now_ms(); l->profile.wire_ms += t2 - t1 - work.elapsed_ms; l->last_wire_us = (t2 - t1) * 1000.0;
        if (rc != SH_OK) {
            snprintf(l->err, sizeof l->err, "exchange: %s", sh_pipe_last_error(l->pipe));
            /* SH_ERR_PROTO is reserved for THIS link's pre-flight refusals
             * above (a property of the node). Anything wrong that came back
             * over the wire -- an oversize frame, a bad status -- is the
             * worker misbehaving, and the caller must treat it like a
             * refusal: take the link down and reconnect, not keep shipping
             * pads to a peer that answers nonsense. */
            if (rc == SH_ERR_PROTO) rc = SH_ERR_VIOLATION;
            goto fail;
        }
        l->exchanges++;

        /* `want` was computed before the exchange from the request and the
         * width; a mismatch is a lying peer, not a shorter read. */
        if (rep.len != want) {
            snprintf(l->err, sizeof l->err, "worker returned %zu bytes, expected %zu", rep.len, want);
            rc = SH_ERR_VIOLATION; goto fail;           /* the worker's fault: reconnect, see above */
        }
        /* A full scan of every reply value, which is a pass over megabytes and
         * is charged to no phase. It is a security check -- a value outside the
         * balanced range breaks the field arithmetic downstream -- so it stays;
         * the timer is here to say what it costs, because it is a candidate for
         * fusing into the unmask pass that already reads the same bytes. */
        const double tc_a = now_ms();
        const bool reply_ok = !(yw == 4) || l->simd->reply32_balanced((const int32_t *)rep.data, want / 4);
        l->profile.check_ms += now_ms() - tc_a;
        if (!reply_ok) {
            snprintf(l->err, sizeof l->err, "worker returned an int32 value outside the balanced field range");
            rc = SH_ERR_VIOLATION; goto fail;
        }

        /* Unmask, then verify, then hand back -- never the other way round.
         * With verification on, the unmask and the lhs dot are one pass. */
        size_t off = 0;
        for (size_t i = 0; i < n_nodes; i++) {
            const sh_node *nd = &l->nodes[nodes[i]];
            const uint8_t *ym = rep.data + off;         /* int32 or packed int24 rows, yw bytes each */
            off += (size_t)m * nd->N * yw;
            int64_t *y = y_out[i];
            const int64_t ystr = y_stride ? y_stride[i] : nd->N;   /* wider row: a column-split slice */
            bool ok = true;
            if (l->verify) {
                /* Profile split: [3] is the fused unmask + lhs pass over y,
                 * [4] the rhs pass over x. */
                for (int32_t row = 0; row < m; row++) {
                    int64_t lhs[SH_FV_REPS], rhs_local[SH_FV_REPS];
                    const int64_t *rhs = overlap ? l->fv_rhs + (i * (size_t)m + row) * SH_FV_REPS : rhs_local;
                    double t3 = now_ms();
                    if (yw == 3)
                        l->simd->unmask24_fv(ym + (size_t)row * nd->N * 3, l->up[row] + nd->u_off, nd->s32, SH_FV_REPS, nd->N,
                                             y + (size_t)row * ystr, lhs);
                    else
                        l->simd->unmask_fv((const int32_t *)ym + (size_t)row * nd->N, l->up[row] + nd->u_off, nd->s32, SH_FV_REPS, nd->N,
                                           y + (size_t)row * ystr, lhs);
                    double t4 = now_ms(); l->profile.unmask_lhs_ms += t4 - t3;
                    if (!overlap) {
                        l->simd->fv_dots_x(x_field + (size_t)row * K, nd->st32, SH_FV_REPS, K, rhs_local);
                        l->profile.rhs_ms += now_ms() - t4;
                    }
                    for (int rep_i = 0; rep_i < SH_FV_REPS; rep_i++) ok = ok && lhs[rep_i] == rhs[rep_i];
                }
            } else {
                double t3 = now_ms();
                for (int32_t row = 0; row < m; row++) {
                    if (yw == 3)
                        l->simd->unmask24(ym + (size_t)row * nd->N * 3, l->up[row] + nd->u_off, (size_t)nd->N, y + (size_t)row * ystr);
                    else
                        l->simd->unmask((const int32_t *)ym + (size_t)row * nd->N, l->up[row] + nd->u_off, (size_t)nd->N, y + (size_t)row * ystr);
                }
                l->profile.unmask_lhs_ms += now_ms() - t3;
            }
            l->macs += (uint64_t)m * (uint64_t)nd->K * (uint64_t)nd->N;
            if (!ok) {
                l->verify_fail++;
                snprintf(l->err, sizeof l->err,
                         "%s: verification FAILED -- the worker lied or the field wrapped. "
                         "Link retired; recreate trusted state. Do not sample, stream, or cache this.", nd->name);
                {   /* Evidence for the log: the exchange is already rejected and
                     * the link retires below either way. */
                    char pm[512];
                    sh_fv_postmortem(nd->w, K, nd->N, x_field, m, y, ystr, sh_fault_diag_plaintext(), pm, sizeof pm);
                    fprintf(stderr, "[shielded] verify post-mortem: %s m=%d served=%s width=%zu exchange=%llu overlap=%d: %s\n",
                            nd->name, (int)m, served_ring ? "ring" : "socket", yw,
                            (unsigned long long)l->exchanges, (int)overlap, pm);
                }
                rc = SH_ERR_VERIFY; goto fail;
            }
        }
        l->profile.completed_calls++;
    }
    release_pads(l, g, took);
    return SH_OK;
fail:
    /* Whatever failed, the pads were consumed the moment they were taken:
     * releasing the slots lets a refill overwrite them, never re-issues them. */
    release_pads(l, g, took);
    return rc;
}

/* ---- dealt pads: the group table and the dealer's mint ------------------- */
int sh_link_group_table(const sh_link *l, sh_pads_group *out, uint32_t cap) {
    if (!l || l->n_groups > cap) return SH_ERR_RANGE;
    for (size_t i = 0; i < l->n_groups; i++) {
        const sh_group *g = &l->groups[i];
        memset(&out[i], 0, sizeof out[i]);
        out[i].group = (uint32_t)i; out[i].K = (uint32_t)g->K; out[i].u_len = (uint64_t)g->u_len;
        snprintf(out[i].name, SH_PADS_NAME_MAX, "%s", l->nodes[g->nodes[0]].name);
    }
    return (int)l->n_groups;
}

int sh_link_manifest_geometry(const sh_link *l,
        sh_pads_manifest_group *groups, size_t group_capacity,
        sh_pads_member *members, size_t member_capacity,
        uint32_t *group_count, uint32_t *member_count) {
    if (sh_integrity_failed(l)) return SH_ERR_VERIFY;
    if (!l || !group_count || !member_count || l->pipe || l->threads_running ||
        !l->n_groups || l->n_groups > SH_PADS_MANIFEST_MAX_GROUPS ||
        !l->n_nodes || l->n_nodes > SH_PADS_MANIFEST_MAX_MEMBERS) return SH_ERR_RANGE;
    const bool query = !groups && !members && !group_capacity && !member_capacity;
    if (!query && (!groups || !members || group_capacity < l->n_groups || member_capacity < l->n_nodes))
        return SH_ERR_RANGE;
    sh_pads_manifest_group *gs = (sh_pads_manifest_group *)calloc(l->n_groups, sizeof *gs);
    sh_pads_member *ms = (sh_pads_member *)calloc(l->n_nodes, sizeof *ms);
    if (!gs || !ms) { free(gs); free(ms); return SH_ERR_NOMEM; }
    int rc = SH_ERR_RANGE;
    uint32_t next = 0;
    for (size_t i = 0; i < l->n_groups; i++) {
        const sh_group *g = &l->groups[i];
        if (g->K <= 0 || g->K > SH_PADS_K_LIMIT || g->u_len <= 0 ||
            g->n_nodes <= 0 || g->n_nodes > SH_GROUP_MAX ||
            (size_t)g->n_nodes > l->n_nodes - next) goto done;
        gs[i].identity.group = (uint32_t)i;
        gs[i].identity.K = (uint32_t)g->K;
        gs[i].identity.u_len = (uint64_t)g->u_len;
        gs[i].member0 = next; gs[i].member_count = (uint32_t)g->n_nodes;
        int64_t offset = 0;
        for (int j = 0; j < g->n_nodes; j++) {
            if (g->nodes[j] < 0 || (size_t)g->nodes[j] >= l->n_nodes) goto done;
            const sh_node *n = &l->nodes[g->nodes[j]];
            const char *end = (const char *)memchr(n->name, 0, sizeof n->name);
            if (!end || end == n->name || end - n->name >= SH_PADS_NAME_MAX ||
                n->group != (int)i || n->K != g->K || n->N <= 0 ||
                n->u_off != offset || n->N > g->u_len - offset) goto done;
            memcpy(ms[next].name, n->name, (size_t)(end - n->name));
            ms[next].N = (uint64_t)n->N;
            if (!j) memcpy(gs[i].identity.name, ms[next].name, SH_PADS_NAME_MAX);
            next++; offset += n->N;
        }
        if (offset != g->u_len) goto done;
    }
    if (next != l->n_nodes) goto done;
    {
        sh_pads_manifest view = {0};
        view.groups = gs; view.members = ms;
        view.group_count = (uint32_t)l->n_groups; view.member_count = next;
        rc = sh_pads_manifest_validate(&view); // also reject duplicate member identities
        if (rc != SH_OK) goto done;
    }
    if (sh_integrity_failed(l)) { rc = SH_ERR_VERIFY; goto done; }
    if (!query) {
        memcpy(groups, gs, l->n_groups * sizeof *gs);
        memcpy(members, ms, l->n_nodes * sizeof *ms);
    }
    *group_count = (uint32_t)l->n_groups; *member_count = next;
done:
    free(gs); free(ms); return rc;
}

/* One mint worker: its fixed stride or explicitly assigned original group IDs,
 * 16 indices per weight pass, own scratch including the writer's (cells go to
 * disjoint offsets of one fd). Scheduling never renumbers a group or pad. */
typedef struct {
    sh_link *l; const uint8_t *seed; uint64_t index0, count;
    sh_pads_writer *w;
    size_t gi0, gstep; int rc;
    const sh_mint_assignment *assignment;
} sh_mint_task;

static void *sh_mint_worker(void *arg) {
    sh_mint_task *t = (sh_mint_task *)arg;
    sh_link *l = t->l;
    enum { B = 16 };
    gen_scratch s;
    int32_t *r = (int32_t *)malloc((size_t)B * l->Kmax * sizeof(int32_t));
    int32_t *u = (int32_t *)malloc((size_t)B * l->ulen_max * sizeof(int32_t));
    const size_t wsz = sh_pads_writer_scratch_bytes(t->w);
    uint8_t *wplain = (uint8_t *)malloc(wsz), *wcell = (uint8_t *)malloc(wsz);
    s.planes = NULL; s.acc = NULL;
    int rc = (gen_scratch_init(l, &s, B) == SH_OK && r && u && wplain && wcell) ? SH_OK : SH_ERR_NOMEM;
    const size_t begin = t->assignment ? t->assignment->offsets[t->gi0] : t->gi0;
    const size_t end = t->assignment ? t->assignment->offsets[t->gi0 + 1] : l->n_groups;
    const size_t step = t->assignment ? 1 : t->gstep;
    for (size_t at = begin; rc == SH_OK && at < end; at += step) {
        const size_t gi = t->assignment ? t->assignment->order[at] : at;
        const sh_group *g = &l->groups[gi];
        const int64_t K = g->K;
        for (uint64_t i0 = 0; i0 < t->count && rc == SH_OK; i0 += B) {
            const int b = (int)((t->count - i0) < B ? (t->count - i0) : B);
            for (int i = 0; i < b; i++) sh_pad_r(t->seed, (uint32_t)gi, t->index0 + i0 + (uint64_t)i, K, r + (size_t)i * K);
            rc = generate_products(l, g, b, r, s.planes, u, s.acc);
            for (int i = 0; i < b && rc == SH_OK; i++) rc = sh_pads_writer_cell_with(t->w, t->index0 + i0 + (uint64_t)i, (uint32_t)gi, u + (size_t)i * g->u_len, wplain, wcell);
        }
    }
    free(r); free(u); free(wplain); free(wcell); free(s.planes); free(s.acc);
    t->rc = rc;
    return NULL;
}

int sh_link_mint_shipment(sh_link *l, const uint8_t seed[32], const uint8_t seed_id[16], const uint8_t model_digest[32],
                          uint64_t index0, uint64_t count, const uint8_t consumer_pk[32], const char *path) {
    if (!l || !l->n_groups || !count) return SH_ERR_RANGE;
    if (sh_integrity_failed(l)) return SH_ERR_VERIFY;
    for (size_t i = 0; i < l->n_nodes; i++) if (!l->nodes[i].w && !l->nodes[i].w_refill) return SH_ERR_RANGE;
    int nth = env_int("SHIELDED_MINT_THREADS", 1, 1, 64);
    if ((size_t)nth > l->n_groups) nth = (int)l->n_groups;
    sh_mint_assignment balanced;
    const sh_mint_assignment *assignment = NULL;
    if (nth > 1 && env_int("SHIELDED_MINT_BALANCE", 0, 0, 1)) {
        if (l->n_groups > SH_MINT_BALANCE_GROUPS) return SH_ERR_RANGE;
        uint64_t costs[SH_MINT_BALANCE_GROUPS];
        for (size_t i = 0; i < l->n_groups; i++) {
            const sh_group *g = &l->groups[i];
            if (g->K <= 0 || g->u_len <= 0 || (uint64_t)g->K > UINT64_MAX / (uint64_t)g->u_len) return SH_ERR_RANGE;
            costs[i] = (uint64_t)g->K * (uint64_t)g->u_len;
        }
        const int rc = sh_mint_balance(costs, (uint32_t)l->n_groups, (uint32_t)nth, &balanced);
        if (rc != SH_MINT_BALANCE_OK) return rc == SH_MINT_BALANCE_NOMEM ? SH_ERR_NOMEM : SH_ERR_RANGE;
        assignment = &balanced;
    }
    sh_pads_group *table = (sh_pads_group *)calloc(l->n_groups, sizeof *table);
    if (!table) return SH_ERR_NOMEM;
    int rc = sh_link_group_table(l, table, (uint32_t)l->n_groups);
    if (rc < 0) { free(table); return rc; }
    int err = SH_OK;
    sh_pads_writer *w = sh_pads_writer_open(path, model_digest, seed_id, table, (uint32_t)l->n_groups, index0, count, consumer_pk, &err);
    free(table);
    if (!w) return err;
    /* SHIELDED_MINT_THREADS: the group loop across N threads (groups are independent; the
     * refill kernel is the cost and runs single-threaded per group). 1 = the serial path. */
    if (nth <= 1) {
        sh_mint_task t = { l, seed, index0, count, w, 0, 1, SH_OK, NULL };
        sh_mint_worker(&t);
        rc = t.rc;
    } else {
        sh_mint_task *tasks = (sh_mint_task *)calloc((size_t)nth, sizeof *tasks);
        pthread_t *th = (pthread_t *)calloc((size_t)nth, sizeof *th);
        char *started = (char *)calloc((size_t)nth, 1);
        if (!tasks || !th || !started) { free(tasks); free(th); free(started); sh_pads_writer_close(w); return SH_ERR_NOMEM; }
        for (int i = 0; i < nth; i++) { sh_mint_task t = { l, seed, index0, count, w, (size_t)i, (size_t)nth, SH_OK, assignment }; tasks[i] = t; }
        for (int i = 0; i < nth; i++) started[i] = sh_thread_create(&th[i], sh_mint_worker, &tasks[i]) == 0;
        /* a share whose thread could not start is minted here, on the calling thread: every
         * group is covered exactly once either way, so the shipment is complete or the error is real */
        for (int i = 0; i < nth; i++) if (!started[i]) sh_mint_worker(&tasks[i]);
        rc = SH_OK;
        for (int i = 0; i < nth; i++) { if (started[i]) pthread_join(th[i], NULL); if (rc == SH_OK && tasks[i].rc != SH_OK) rc = tasks[i].rc; }
        free(tasks); free(th); free(started);
    }
    const int crc = sh_pads_writer_close(w);
    return rc != SH_OK ? rc : crc;
}

/* Mint through the link's worker: with SHIELDED_ZERO_PADS the exchange sends
 * x unmasked and returns x.W mod M balanced, so feeding x = r (the seed's mask
 * row) yields exactly the u a shipment carries - on whatever GPU the dealer
 * owns, Freivalds-checked like any exchange, instead of the CPU refill kernel
 * (a 27B row is a 30 GB weight stream either way, but a GPU streams it at
 * memory speed and a batch of rows streams it once). The dealer never sees a
 * tenant's x; this worker sees the dealer's r, which the dealer holds anyway. */
int sh_link_mint_shipment_worker(sh_link *l, const uint8_t seed[32], const uint8_t seed_id[16], const uint8_t model_digest[32],
                                 uint64_t index0, uint64_t count, const uint8_t consumer_pk[32], const char *path) {
#ifndef SHIELDED_DEALER_MODE
    (void)seed; (void)seed_id; (void)model_digest; (void)index0; (void)count; (void)consumer_pk; (void)path;
    if (l) snprintf(l->err, sizeof l->err, "mint via worker: not in this build (libggml-shielded-dealer.so carries it)");
    return SH_ERR_RANGE;
#else
    if (!l || !l->n_groups || !count) return SH_ERR_RANGE;
    if (!l->zero_pads) { snprintf(l->err, sizeof l->err, "mint via worker needs SHIELDED_ZERO_PADS=1 (the masked path would return x.W, not r.W)"); return SH_ERR_RANGE; }
    if (!l->pipe) { snprintf(l->err, sizeof l->err, "mint via worker: no worker link"); return SH_ERR_IO; }
    sh_pads_group *table = (sh_pads_group *)calloc(l->n_groups, sizeof *table);
    if (!table) return SH_ERR_NOMEM;
    int rc = sh_link_group_table(l, table, (uint32_t)l->n_groups);
    if (rc < 0) { free(table); return rc; }
    int err = SH_OK;
    sh_pads_writer *w = sh_pads_writer_open(path, model_digest, seed_id, table, (uint32_t)l->n_groups, index0, count, consumer_pk, &err);
    free(table);
    if (!w) return err;
    int mmax = 1;
    for (size_t i = 0; i < l->n_groups; i++) if (l->groups[i].max_m > mmax) mmax = l->groups[i].max_m;
    int32_t *r = (int32_t *)malloc((size_t)mmax * l->Kmax * sizeof(int32_t));
    int64_t *x = (int64_t *)malloc((size_t)mmax * l->Kmax * sizeof(int64_t));
    int32_t *u = (int32_t *)malloc((size_t)mmax * l->ulen_max * sizeof(int32_t));
    int64_t *ybuf = (int64_t *)malloc((size_t)mmax * l->ulen_max * sizeof(int64_t));
    int64_t *yout[SH_GROUP_MAX];
    if (!r || !x || !u || !ybuf) { free(r); free(x); free(u); free(ybuf); sh_pads_writer_close(w); return SH_ERR_NOMEM; }
    rc = SH_OK;
    for (size_t gi = 0; gi < l->n_groups && rc == SH_OK; gi++) {
        const sh_group *g = &l->groups[gi];
        const int64_t K = g->K;
        const int B = g->max_m > 0 ? g->max_m : 1;
        for (uint64_t i0 = 0; i0 < count && rc == SH_OK; i0 += (uint64_t)B) {
            const int b = (int)((count - i0) < (uint64_t)B ? (count - i0) : (uint64_t)B);
            for (int i = 0; i < b; i++) {
                sh_pad_r(seed, (uint32_t)gi, index0 + i0 + (uint64_t)i, K, r + (size_t)i * K);
                for (int64_t k = 0; k < K; k++) x[(size_t)i * K + k] = r[(size_t)i * K + k];
            }
            /* one exchange for the whole group: every node reads the same planes */
            size_t off = 0;
            for (int n = 0; n < g->n_nodes; n++) { yout[n] = ybuf + off; off += (size_t)b * l->nodes[g->nodes[n]].N; }
            rc = sh_link_gemm(l, g->nodes, (size_t)g->n_nodes, x, b, yout);
            if (rc != SH_OK) break;
            for (int n = 0; n < g->n_nodes; n++) {
                const sh_node *nd = &l->nodes[g->nodes[n]];
                if (!nd->sM || !nd->stM) { snprintf(l->err, sizeof l->err, "mint via worker: no mod-M check vectors (set SHIELDED_PAD_CHECK=1 before the model loads)"); rc = SH_ERR_RANGE; break; }
                for (int i = 0; i < b; i++) {
                    for (int64_t j = 0; j < nd->N; j++) {
                        int64_t v = yout[n][(size_t)i * nd->N + j] % SH_M_MOD;      /* the writer's balanced range [-M/2, M/2], as the in-process mint */
                        if (v < 0) v += SH_M_MOD;
                        if (v > SH_M_MOD / 2) v -= SH_M_MOD;
                        u[(size_t)i * g->u_len + nd->u_off + j] = (int32_t)v;
                    }
                    /* the worker's word is checked here, the way a consumer checks a shipment: (u . s) == (r . (W s)) mod M */
                    const int64_t a = sh_dot_mod_i32(&u[(size_t)i * g->u_len + nd->u_off], nd->sM, nd->N, SH_M_MOD);
                    const int64_t c = sh_dot_mod_i32(&r[(size_t)i * K], nd->stM, K, SH_M_MOD);
                    if (a != c) { snprintf(l->err, sizeof l->err, "mint via worker: the worker's product for %s row %llu FAILED the mod-M check", nd->name, (unsigned long long)(index0 + i0 + (uint64_t)i)); rc = SH_ERR_VERIFY; break; }
                }
                if (rc != SH_OK) break;
            }
            if (rc != SH_OK) break;
            for (int i = 0; i < b && rc == SH_OK; i++) rc = sh_pads_writer_cell(w, index0 + i0 + (uint64_t)i, (uint32_t)gi, u + (size_t)i * g->u_len);
        }
    }
    free(r); free(x); free(u); free(ybuf);
    const int crc = sh_pads_writer_close(w);
    return rc != SH_OK ? rc : crc;
#endif
}

/* The bank client's counters for the profile line (zeros without a bank). */
void sh_link_bank_stats(const sh_link *l, uint64_t *files, uint64_t *bytes, int *last_status, char *err, size_t err_cap) {
    sh_bank_stats(l ? l->padbank : NULL, files, bytes, last_status, err, err_cap);
}
bool sh_link_has_bank(const sh_link *l) { return l && l->padbank; }

/* Test hook: dealt mode without a worker. Opens the shipments, binds the
 * groups, takes a window, and imports `rows` pads per group through the same
 * path the refill threads use. Returns the number of rows imported, or an
 * error; dealt-selftest.c checks them against the shipment's plaintext. */
int sh_link_dealt_selftest(sh_link *l, int rows, int32_t *r_out, int32_t *u_out) {
    if (sh_integrity_failed(l)) return SH_ERR_VERIFY;
    if (!l || !l->dealt || !l->n_groups) return SH_ERR_RANGE;
    int rc = dealt_open(l);
    if (rc != SH_OK) return rc;
    int done = 0;
    for (size_t gi = 0; gi < l->n_groups; gi++) {
        sh_group *g = &l->groups[gi];
        const uint64_t index0 = g->cursor;
        if (index0 + (uint64_t)rows > l->win_hi) return SH_ERR_EXHAUST;
        g->cursor += (uint64_t)rows;
        rc = dealt_import(l, g, (uint32_t)gi, index0, rows, r_out + (size_t)done * l->Kmax, u_out + (size_t)done * l->ulen_max);
        if (rc != SH_OK) return rc;
        done += rows;
    }
    return done;
}

/* Standalone sparse mint; existing v2 dealer/consumer paths stay unchanged. */
#include "shielded-pad-mint-v3.inc"
