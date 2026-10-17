/* Dealt pads: see shielded-pads.h and shielded/dealer/PLAN.md. */
#define _GNU_SOURCE
#include "shielded-pads.h"
#include "shielded-field.h"
#include "shielded-tee.h"
#include "tweetnacl.h"
#include "poly1305-donna.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/random.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

/* ChaCha20 block with a 64-bit counter and a zero nonce: the mask bank's stream
 * (shielded-tee.c) and the dealt-pad derivation draw from this one definition. */
#define B_ROTL32(v, c) (((v) << (c)) | ((v) >> (32 - (c))))
#define B_QR(a, b, c, d) (a += b, d ^= a, d = B_ROTL32(d, 16), c += d, b ^= c, b = B_ROTL32(b, 12), a += b, d ^= a, d = B_ROTL32(d, 8), c += d, b ^= c, b = B_ROTL32(b, 7))
void sh_chacha20_block(const uint32_t key[8], uint64_t counter, uint32_t out[16]) {
    static const uint32_t C[4] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
    uint32_t s[16];
    s[0] = C[0]; s[1] = C[1]; s[2] = C[2]; s[3] = C[3];
    for (int i = 0; i < 8; i++) s[4 + i] = key[i];
    s[12] = (uint32_t)counter; s[13] = (uint32_t)(counter >> 32);
    s[14] = 0; s[15] = 0;
    uint32_t x[16]; memcpy(x, s, sizeof x);
    for (int i = 0; i < 10; i++) {
        B_QR(x[0], x[4], x[ 8], x[12]); B_QR(x[1], x[5], x[ 9], x[13]);
        B_QR(x[2], x[6], x[10], x[14]); B_QR(x[3], x[7], x[11], x[15]);
        B_QR(x[0], x[5], x[10], x[15]); B_QR(x[1], x[6], x[11], x[12]);
        B_QR(x[2], x[7], x[ 8], x[13]); B_QR(x[3], x[4], x[ 9], x[14]);
    }
    for (int i = 0; i < 16; i++) out[i] = x[i] + s[i];
}

/* TweetNaCl's entropy hook: the OS, as everywhere else in the trusted half.
 * Weak, so a host that already defines one (the pVM payload) keeps its own. */
__attribute__((weak)) void randombytes(unsigned char *p, unsigned long long n) {
    while (n) {
        ssize_t r = getrandom(p, n, 0);
        if (r < 0) { if (errno == EINTR) continue; abort(); }
        p += r; n -= (unsigned long long)r;
    }
}

/* ---- r derivation ------------------------------------------------------ */
#if defined(__aarch64__)
#include "shielded-pad-r4.h"
static pthread_once_t pad_r4_once = PTHREAD_ONCE_INIT;
static int pad_r4_enabled;
static void pad_r4_init(void) {
    const char *v = getenv("SHIELDED_PAD_R4");
    pad_r4_enabled = v && strcmp(v, "1") == 0;
    if (pad_r4_enabled) fprintf(stderr, "shielded-pads: sampler=neon4 exact-stream\n");
}
#endif
void sh_pad_r(const uint8_t seed[32], uint32_t group, uint64_t index, int64_t K, int32_t *r_out) {
    if (!seed || !r_out || group >= SH_PADS_GROUP_LIMIT || index >= SH_PADS_INDEX_LIMIT ||
        K <= 0 || K > SH_PADS_K_LIMIT) abort();
#if defined(__aarch64__)
    pthread_once(&pad_r4_once, pad_r4_init);
    if (pad_r4_enabled) { sh_pad_r_four_blocks(seed, group, index, K, r_out); return; }
#endif
    uint32_t key[8];
    for (int i = 0; i < 8; i++)
        key[i] = (uint32_t)seed[4 * i] | ((uint32_t)seed[4 * i + 1] << 8) |
                 ((uint32_t)seed[4 * i + 2] << 16) | ((uint32_t)seed[4 * i + 3] << 24);
    uint64_t ctr = ((uint64_t)group << 48) | (index << 24);
    uint32_t blk[16];
    int64_t produced = 0;
    while (produced < K) {
        sh_chacha20_block(key, ctr++, blk);
        for (int i = 0; i + 1 < 16 && produced < K; i += 2) {
            const uint64_t v = ((uint64_t)blk[i + 1] << 32) | blk[i];
            r_out[produced++] = (int32_t)(v % (uint64_t)SH_M_MOD);
        }
    }
}

/* A keyed cell's own mask key (format 4, HOST-BANK.md): the first 32 bytes of ChaCha20 under the
 * bank secret at counter (group << 48) | (index << 24) - a PRF output, so any set of cell keys
 * reveals neither the bank secret nor another cell's key. r for the cell is
 * sh_pad_r(cellkey, 0, 0, K): the seed stream, keyed per cell. */
void sh_pad_cellkey(const uint8_t bank[32], uint32_t group, uint64_t index, uint8_t key_out[32]) {
    if (!bank || !key_out || group >= SH_PADS_GROUP_LIMIT || index >= SH_PADS_INDEX_LIMIT) abort();
    uint32_t key[8], blk[16];
    for (int i = 0; i < 8; i++)
        key[i] = (uint32_t)bank[4 * i] | ((uint32_t)bank[4 * i + 1] << 8) |
                 ((uint32_t)bank[4 * i + 2] << 16) | ((uint32_t)bank[4 * i + 3] << 24);
    sh_chacha20_block(key, ((uint64_t)group << 48) | (index << 24), blk);
    for (int i = 0; i < 8; i++) {
        key_out[4 * i] = (uint8_t)blk[i]; key_out[4 * i + 1] = (uint8_t)(blk[i] >> 8);
        key_out[4 * i + 2] = (uint8_t)(blk[i] >> 16); key_out[4 * i + 3] = (uint8_t)(blk[i] >> 24);
    }
    volatile uint32_t *vk = key, *vb = blk;
    for (int i = 0; i < 8; i++) vk[i] = 0;
    for (int i = 0; i < 16; i++) vb[i] = 0;
}

/* ---- helpers ------------------------------------------------------------ */
static void pads_wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

/* NaCl-compatible precomputation with contributory X25519 validation.
 * TweetNaCl's beforenm accepts an all-zero DH result, yielding a public key
 * for the secretbox. Check the raw result before HSalsa20 hides that zero. */
static int box_shared_checked(uint8_t key[32], const uint8_t pk[32], const uint8_t sk[32]) {
    static const uint8_t zero[16] = {0}, sigma[16] = "expand 32-byte k";
    uint8_t raw[32];
    int rc = crypto_scalarmult(raw, sk, pk);
    uint8_t nonzero = 0;
    for (size_t i = 0; i < sizeof raw; i++) nonzero |= raw[i];
    if (rc == 0 && nonzero) rc = crypto_core_hsalsa20(key, zero, raw, sigma);
    else rc = -1;
    pads_wipe(raw, sizeof raw);
    if (rc != 0) { pads_wipe(key, 32); return SH_ERR_VERIFY; }
    return SH_OK;
}

static void put_u64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static void put_u32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }

/* Cells and the header are ChaCha20-Poly1305 (RFC 8439) under the shipment
 * key: the shipment key is fresh per file, so the 96-bit nonce only has to be
 * unique within it - (index, group) is, and the header takes an all-0xEE
 * nonce no cell can have (group 0xEEEEEEEE is far past the 65,535 cap). The
 * key wrap stays crypto_box (32 bytes; speed is irrelevant there). */
static void cell_nonce(uint8_t n[12], uint64_t index, uint32_t group) { put_u64(n, index); put_u32(n + 8, group); }
static void hdr_nonce(uint8_t n[12]) { memset(n, 0xEE, 12); }
static void key_nonce(uint8_t n[24], const uint8_t seed_id[16]) { memcpy(n, seed_id, 16); memset(n + 16, 0xFF, 8); }

/* RFC 8439 reserves block zero for the tag key. Never wrap the 32-bit
 * stream counter, size_t allocations, signed pread sizes, or file offsets. */
static bool cell_size_valid(uint64_t u_len) {
    return u_len && u_len <= (UINT64_C(64) * UINT32_MAX) / 3 &&
        u_len <= (SIZE_MAX - SH_PADS_CELL_TAG - SH_PADS_CELL_KEY) / 3 &&
        u_len <= (INT64_MAX - SH_PADS_CELL_TAG - SH_PADS_CELL_KEY) / 3;
}
static uint64_t cell_bytes(uint64_t u_len) { return SH_PADS_CELL_TAG + 3 * u_len; }
/* A format-4 cell carries its 32-byte mask key ahead of u, inside the same box. */
static uint64_t cell_bytes_k(uint64_t u_len, bool keyed) { return cell_bytes(u_len) + (keyed ? SH_PADS_CELL_KEY : 0); }
static bool shipment_layout(const sh_pads_group *groups, uint32_t n_groups, uint64_t count, bool keyed,
                            uint64_t *data_off, uint64_t *row_bytes, uint64_t *file_bytes) {
    if (!groups || !n_groups || n_groups >= SH_PADS_GROUP_LIMIT || !count || count > SH_PADS_INDEX_LIMIT) return false;
    uint64_t row = 0;
    for (uint32_t g = 0; g < n_groups; g++) {
        if (!groups[g].K || groups[g].K > SH_PADS_K_LIMIT || groups[g].group >= SH_PADS_GROUP_LIMIT ||
            !cell_size_valid(groups[g].u_len)) return false;
        uint64_t cb = cell_bytes_k(groups[g].u_len, keyed);
        if (row > INT64_MAX - cb) return false;
        row += cb;
    }
    uint64_t off = sizeof(sh_pads_hdr) + (uint64_t)n_groups * sizeof(sh_pads_group);
    off = (off + 4095) & ~UINT64_C(4095);
    if (count > (INT64_MAX - off) / row) return false;
    *data_off = off; *row_bytes = row; *file_bytes = off + count * row;
    return true;
}
static void chacha_ietf_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out[64]);
static int  aead_seal(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *msg, size_t n, uint8_t *out /* n + 16 */);
static int  aead_open(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *box /* n + 16 */, size_t n, uint8_t *out);

/* Serialise the fixed header + table, with key_box/hdr_box zeroed, and hash it. */
static int header_hash(const sh_pads_hdr *h, const sh_pads_group *groups, uint32_t n, uint8_t out[64]) {
    sh_pads_hdr c = *h;
    memset(c.key_box, 0, sizeof c.key_box);
    memset(c.hdr_box, 0, sizeof c.hdr_box);
    const size_t len = sizeof c + (size_t)n * sizeof(sh_pads_group);
    uint8_t *buf = (uint8_t *)malloc(len);
    if (!buf) return SH_ERR_NOMEM;
    memcpy(buf, &c, sizeof c);
    memcpy(buf + sizeof c, groups, (size_t)n * sizeof(sh_pads_group));
    crypto_hash(out, buf, len);
    free(buf);
    return SH_OK;
}

static int secretbox_seal(uint8_t *out /* 16 + n */, const uint8_t *msg, size_t n, const uint8_t nonce[24], const uint8_t key[32]) {
    uint8_t *m = (uint8_t *)calloc(n + 32, 1), *c = (uint8_t *)malloc(n + 32);
    if (!m || !c) { free(m); free(c); return SH_ERR_NOMEM; }
    memcpy(m + 32, msg, n);
    crypto_secretbox(c, m, n + 32, nonce, key);
    memcpy(out, c + 16, n + 16);
    pads_wipe(m, n + 32);
    free(m); free(c);
    return SH_OK;
}
static int secretbox_open(uint8_t *msg, const uint8_t *box /* 16 + n */, size_t n, const uint8_t nonce[24], const uint8_t key[32]) {
    uint8_t *c = (uint8_t *)calloc(n + 32, 1), *m = (uint8_t *)malloc(n + 32);
    if (!c || !m) { free(c); free(m); return SH_ERR_NOMEM; }
    memcpy(c + 16, box, n + 16);
    const int rc = crypto_secretbox_open(m, c, n + 32, nonce, key);
    if (rc == 0) memcpy(msg, m + 32, n);
    pads_wipe(m, n + 32);
    free(c); free(m);
    return rc == 0 ? SH_OK : SH_ERR_VERIFY;
}

/* ---- writer ------------------------------------------------------------- */
struct sh_pads_writer {
    int fd, dirfd;
    char *path, *tmp_path;
    sh_pads_hdr hdr;
    sh_pads_group *groups;
    uint64_t *group_off;               /* within a row */
    uint8_t key[32];
    uint8_t *cell, *plain;             /* scratch: largest cell */
    size_t cell_cap;
    uint8_t *claimed;                 /* atomically claim each AEAD nonce once */
    uint64_t total_cells, completed;
    int failed;
    bool keyed;                       /* format 4: every cell carries its own mask key */
};

static int writer_fail(sh_pads_writer *w, int rc) {
    int expected = SH_OK;
    __atomic_compare_exchange_n(&w->failed, &expected, rc, false, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
    return rc;
}

/* Retry only bytes from this one sealed buffer, never re-encrypt after a short
 * write. The layout has already bounded every offset/length to off_t. */
static int writer_pwrite_all(int fd, const void *buffer, size_t length, uint64_t offset) {
    const uint8_t *p = (const uint8_t *)buffer;
    while (length) {
        const ssize_t n = pwrite(fd, p, length, (off_t)offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return SH_ERR_IO;
        p += (size_t)n; length -= (size_t)n; offset += (uint64_t)n;
    }
    return SH_OK;
}

static sh_pads_writer *writer_open(const char *path, const uint8_t model_digest[32],
                                   const uint8_t seed_id[16], const sh_pads_group *groups, uint32_t n_groups,
                                   uint64_t index0, uint64_t index_count, const uint8_t consumer_pk[32], bool keyed, int *err) {
    if (!err) return NULL;
    *err = SH_OK;
    if (!path || !*path || !model_digest || !seed_id || !consumer_pk || !groups || !n_groups || n_groups >= SH_PADS_GROUP_LIMIT || !index_count ||
        index0 >= SH_PADS_INDEX_LIMIT || index_count > SH_PADS_INDEX_LIMIT - index0 ||
        index_count > SH_PADS_WRITER_MAX_CELLS / n_groups) { *err = SH_ERR_RANGE; return NULL; }
    uint64_t layout_off, layout_row, layout_bytes;
    if (!shipment_layout(groups, n_groups, index_count, keyed, &layout_off, &layout_row, &layout_bytes)) { *err = SH_ERR_RANGE; return NULL; }
    sh_pads_writer *w = (sh_pads_writer *)calloc(1, sizeof *w);
    if (!w) { *err = SH_ERR_NOMEM; return NULL; }
    w->keyed = keyed;
    uint8_t esk[32] = {0}, shared[32] = {0};
    w->fd = w->dirfd = -1;
    w->total_cells = index_count * n_groups;
    w->claimed = (uint8_t *)calloc((size_t)((w->total_cells + 7) / 8), 1);
    w->path = strdup(path);
    const size_t path_len = strlen(path);
    static const char suffix[] = ".tmp.XXXXXX";
    if (path_len > SIZE_MAX - sizeof suffix) { *err = SH_ERR_RANGE; goto fail; }
    w->tmp_path = (char *)malloc(path_len + sizeof suffix);
    if (!w->claimed || !w->path || !w->tmp_path) { *err = SH_ERR_NOMEM; goto fail; }
    memcpy(w->tmp_path, path, path_len); memcpy(w->tmp_path + path_len, suffix, sizeof suffix);
    struct stat existing;
    if (lstat(path, &existing) == 0 || errno != ENOENT) { *err = SH_ERR_IO; goto fail; }
    char *parent = strdup(path);
    if (!parent) { *err = SH_ERR_NOMEM; goto fail; }
    char *slash = strrchr(parent, '/');
    if (!slash) strcpy(parent, ".");
    else if (slash == parent) slash[1] = 0;
    else *slash = 0;
    w->dirfd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    free(parent);
    if (w->dirfd < 0) { *err = SH_ERR_IO; goto fail; }
    w->groups = (sh_pads_group *)calloc(n_groups, sizeof *w->groups);
    w->group_off = (uint64_t *)calloc(n_groups, sizeof *w->group_off);
    if (!w->groups || !w->group_off) { *err = SH_ERR_NOMEM; goto fail; }
    memcpy(w->groups, groups, (size_t)n_groups * sizeof *groups);
    uint64_t row = 0, biggest = 0;
    for (uint32_t g = 0; g < n_groups; g++) {
        w->group_off[g] = row;
        const uint64_t cb = cell_bytes_k(groups[g].u_len, keyed);
        row += cb;
        if (cb > biggest) biggest = cb;
    }
    w->cell_cap = (size_t)biggest;
    w->cell = (uint8_t *)malloc(w->cell_cap);
    w->plain = (uint8_t *)malloc(w->cell_cap);
    if (!w->cell || !w->plain) { *err = SH_ERR_NOMEM; goto fail; }

    sh_pads_hdr *h = &w->hdr;
    memset(h, 0, sizeof *h);
    memcpy(h->magic, SH_PADS_MAGIC, 8);
    h->version = keyed ? SH_PADS_VERSION_KEYED : SH_PADS_VERSION;
    h->group_count = n_groups;
    memcpy(h->model_digest, model_digest, 32);
    memcpy(h->seed_id, seed_id, 16);
    h->index0 = index0; h->index_count = index_count;
    h->data_off = layout_off;
    h->row_bytes = layout_row;

    /* Shipment key, boxed to the consumer from an ephemeral pair. */
    randombytes(w->key, 32);
    uint8_t epk[32], nonce[24];
    crypto_box_keypair(epk, esk);
    if (box_shared_checked(shared, consumer_pk, esk) != SH_OK) { *err = SH_ERR_VERIFY; goto fail; }
    memcpy(h->dealer_pk, epk, 32);
    key_nonce(nonce, seed_id);
    if (secretbox_seal(h->key_box, w->key, 32, nonce, shared) != SH_OK) { *err = SH_ERR_NOMEM; goto fail; }
    pads_wipe(esk, sizeof esk); pads_wipe(shared, sizeof shared);

    uint8_t digest[64], hn[12];
    if (header_hash(h, w->groups, n_groups, digest) != SH_OK) { *err = SH_ERR_NOMEM; goto fail; }
    hdr_nonce(hn);
    if (aead_seal(w->key, hn, digest, 64, h->hdr_box) != SH_OK) { *err = SH_ERR_NOMEM; goto fail; }

    w->fd = mkostemp(w->tmp_path, O_CLOEXEC);
    if (w->fd < 0) { *err = SH_ERR_IO; goto fail; }
    if (writer_pwrite_all(w->fd, h, sizeof *h, 0) != SH_OK ||
        writer_pwrite_all(w->fd, w->groups, (size_t)n_groups * sizeof *w->groups, sizeof *h) != SH_OK) {
        *err = SH_ERR_IO; goto fail;
    }
    if (ftruncate(w->fd, (off_t)layout_bytes) != 0) { *err = SH_ERR_IO; goto fail; }
    return w;
fail:
    pads_wipe(esk, sizeof esk); pads_wipe(shared, sizeof shared);
    writer_fail(w, *err);
    sh_pads_writer_close(w);
    return NULL;
}

static int writer_cell(sh_pads_writer *w, uint64_t index, uint32_t group, const uint8_t *cellkey,
                       const int32_t *u, uint8_t *plain, uint8_t *cell);
sh_pads_writer *sh_pads_writer_open(const char *path, const uint8_t model_digest[32],
                                    const uint8_t seed_id[16], const sh_pads_group *groups, uint32_t n_groups,
                                    uint64_t index0, uint64_t index_count, const uint8_t consumer_pk[32], int *err) {
    return writer_open(path, model_digest, seed_id, groups, n_groups, index0, index_count, consumer_pk, false, err);
}
sh_pads_writer *sh_pads_writer_open_keyed(const char *path, const uint8_t model_digest[32],
                                          const uint8_t seed_id[16], const sh_pads_group *groups, uint32_t n_groups,
                                          uint64_t index0, uint64_t index_count, const uint8_t consumer_pk[32], int *err) {
    return writer_open(path, model_digest, seed_id, groups, n_groups, index0, index_count, consumer_pk, true, err);
}
int sh_pads_writer_cell_with(sh_pads_writer *w, uint64_t index, uint32_t group, const int32_t *u, uint8_t *plain, uint8_t *cell) {
    return writer_cell(w, index, group, NULL, u, plain, cell);
}
int sh_pads_writer_cell_keyed_with(sh_pads_writer *w, uint64_t index, uint32_t group, const uint8_t cellkey[32],
                                   const int32_t *u, uint8_t *plain, uint8_t *cell) {
    if (!cellkey) return SH_ERR_RANGE;
    return writer_cell(w, index, group, cellkey, u, plain, cell);
}
int sh_pads_writer_cell(sh_pads_writer *w, uint64_t index, uint32_t group, const int32_t *u) {
    return w ? sh_pads_writer_cell_with(w, index, group, u, w->plain, w->cell) : SH_ERR_RANGE;
}

/* With caller-owned disjoint scratch (each >= cell_cap bytes), distinct cells
 * may seal/write concurrently. Atomic nonce claims reject colliding callers;
 * completion advances only after every ciphertext byte was written. */
static int writer_cell(sh_pads_writer *w, uint64_t index, uint32_t group, const uint8_t *cellkey,
                       const int32_t *u, uint8_t *plain, uint8_t *cell) {
    if (!w || !u || !plain || !cell || group >= w->hdr.group_count) return SH_ERR_RANGE;
    if (w->keyed != (cellkey != NULL)) return SH_ERR_RANGE;   /* a keyed shipment needs every key; a seed one none */
    if (index < w->hdr.index0 || index >= w->hdr.index0 + w->hdr.index_count) return SH_ERR_RANGE;
    const int failed = __atomic_load_n(&w->failed, __ATOMIC_ACQUIRE);
    if (failed != SH_OK) return failed;
    const uint64_t ordinal = (index - w->hdr.index0) * w->hdr.group_count + group;
    const uint8_t bit = (uint8_t)(1u << (ordinal % 8));
    if (__atomic_fetch_or(&w->claimed[ordinal / 8], bit, __ATOMIC_ACQ_REL) & bit)
        return writer_fail(w, SH_ERR_RANGE);
    const uint64_t u_len = w->groups[group].u_len;
    const size_t kb = cellkey ? SH_PADS_CELL_KEY : 0;
    if (cellkey) memcpy(plain, cellkey, kb);
    uint8_t *p = plain + kb;
    for (uint64_t j = 0; j < u_len; j++) {
        const int64_t v = (int64_t)u[j] + SH_HALF_M;
        if (v < 0 || v >= SH_M_MOD) { pads_wipe(plain, kb); return writer_fail(w, SH_ERR_RANGE); }
        p[3 * j] = (uint8_t)v; p[3 * j + 1] = (uint8_t)(v >> 8); p[3 * j + 2] = (uint8_t)(v >> 16);
    }
    uint8_t nonce[12];
    cell_nonce(nonce, index, group);
    int rc = aead_seal(w->key, nonce, plain, kb + (size_t)(3 * u_len), cell);
    pads_wipe(plain, kb);
    if (rc != SH_OK) return writer_fail(w, rc);
    const uint64_t off = w->hdr.data_off + (index - w->hdr.index0) * w->hdr.row_bytes + w->group_off[group];
    const size_t n = (size_t)cell_bytes_k(u_len, w->keyed);
    if (writer_pwrite_all(w->fd, cell, n, off) != SH_OK) return writer_fail(w, SH_ERR_IO);
    __atomic_add_fetch(&w->completed, 1, __ATOMIC_RELEASE);
    return SH_OK;
}

size_t sh_pads_writer_scratch_bytes(const sh_pads_writer *w) { return w ? w->cell_cap : 0; }

int sh_pads_writer_close(sh_pads_writer *w) {
    if (!w) return SH_OK;
    int rc = __atomic_load_n(&w->failed, __ATOMIC_ACQUIRE);
    if (rc == SH_OK && __atomic_load_n(&w->completed, __ATOMIC_ACQUIRE) != w->total_cells)
        rc = SH_ERR_RANGE;
    if (w->fd >= 0) {
        if (rc == SH_OK && fsync(w->fd) != 0) rc = SH_ERR_IO;
        if (close(w->fd) != 0 && rc == SH_OK) rc = SH_ERR_IO;
        if (rc == SH_OK && link(w->tmp_path, w->path) != 0) rc = SH_ERR_IO;
        if (w->tmp_path && unlink(w->tmp_path) != 0 && rc == SH_OK) rc = SH_ERR_IO;
        if (rc == SH_OK && fsync(w->dirfd) != 0) rc = SH_ERR_IO;
    }
    if (w->dirfd >= 0) close(w->dirfd);
    pads_wipe(w->key, sizeof w->key);
    if (w->plain) pads_wipe(w->plain, w->cell_cap);
    free(w->path); free(w->tmp_path); free(w->claimed);
    free(w->groups); free(w->group_off); free(w->cell); free(w->plain); free(w);
    return rc;
}

/* ---- reader ------------------------------------------------------------- */
typedef struct {
    char path[512];
    int fd;
    sh_pads_hdr hdr;
    sh_pads_group *groups;
    uint64_t *group_off;
    uint8_t key[32];
    int *ordinal_of;                    /* consumer group -> this shipment's group, or -1 */
} sh_pads_file;

/* Several importer threads read cells concurrently: the file list is guarded
 * by `mu` (scans mutate it), cell scratch is per call, and pread on a shared
 * descriptor is safe. */
struct sh_pads_reader {
    char dir[512];
    uint8_t seed_id[16];
    uint8_t sk[32];
    pthread_mutex_t mu;
    bool have_digest; uint8_t model_digest[32];   /* when set, shipments for another model are not ours */
    sh_pads_file *files; size_t n_files, cap_files;
    sh_pads_group *bound; uint32_t n_bound;
    bool keyed;                       /* accepts format 4 (keyed cells) only, else format 2 only */
};

static void file_close(sh_pads_file *f) {
    if (f->fd >= 0) close(f->fd);
    free(f->groups); free(f->group_off); free(f->ordinal_of);
    pads_wipe(f->key, sizeof f->key);
    memset(f, 0, sizeof *f); f->fd = -1;
}

static bool reader_has(const sh_pads_reader *r, const char *path) {
    for (size_t i = 0; i < r->n_files; i++) if (!strcmp(r->files[i].path, path)) return true;
    return false;
}

/* Open one shipment: header, key unwrap, header check, group table. */
/* f->fd is open: read and verify the header and the group table (the one judgment the reader,
 * sh_pads_shipment_check and sh_pads_shipment_check_fd share). Closes f on any failure. */
static int file_judge(sh_pads_reader *r, sh_pads_file *f) {
    if (pread(f->fd, &f->hdr, sizeof f->hdr, 0) != (ssize_t)sizeof f->hdr) { file_close(f); return SH_ERR_IO; }
    sh_pads_hdr *h = &f->hdr;
    if (memcmp(h->magic, SH_PADS_MAGIC, 8) || h->version != (r->keyed ? SH_PADS_VERSION_KEYED : SH_PADS_VERSION) ||
        !h->group_count || h->group_count >= SH_PADS_GROUP_LIMIT ||
        !h->index_count || h->index0 >= SH_PADS_INDEX_LIMIT || h->index_count > SH_PADS_INDEX_LIMIT - h->index0 ||
        memcmp(h->seed_id, r->seed_id, 16) || (r->have_digest && memcmp(h->model_digest, r->model_digest, 32))) { file_close(f); return SH_ERR_VERIFY; }
    f->groups = (sh_pads_group *)calloc(h->group_count, sizeof *f->groups);
    f->group_off = (uint64_t *)calloc(h->group_count, sizeof *f->group_off);
    if (!f->groups || !f->group_off) { file_close(f); return SH_ERR_NOMEM; }
    const size_t tb = (size_t)h->group_count * sizeof(sh_pads_group);
    if (pread(f->fd, f->groups, tb, sizeof *h) != (ssize_t)tb) { file_close(f); return SH_ERR_IO; }

    uint64_t layout_off, layout_row, layout_bytes;
    struct stat st;
    if (!shipment_layout(f->groups, h->group_count, h->index_count, r->keyed, &layout_off, &layout_row, &layout_bytes) ||
        h->data_off != layout_off || h->row_bytes != layout_row) { file_close(f); return SH_ERR_VERIFY; }
    if (fstat(f->fd, &st) != 0) { file_close(f); return SH_ERR_IO; }
    if (!S_ISREG(st.st_mode) || st.st_size < 0 || (uint64_t)st.st_size != layout_bytes) { file_close(f); return SH_ERR_VERIFY; }

    uint8_t shared[32], nonce[24];
    if (box_shared_checked(shared, h->dealer_pk, r->sk) != SH_OK) { file_close(f); return SH_ERR_VERIFY; }
    key_nonce(nonce, h->seed_id);
    int rc = secretbox_open(f->key, h->key_box, 32, nonce, shared);
    pads_wipe(shared, sizeof shared);
    if (rc != SH_OK) { file_close(f); return SH_ERR_VERIFY; }

    uint8_t want[64], got[64], hn[12];
    rc = header_hash(h, f->groups, h->group_count, want);
    if (rc != SH_OK) { file_close(f); return rc; }
    hdr_nonce(hn);
    if (aead_open(f->key, hn, h->hdr_box, 64, got) != SH_OK || memcmp(want, got, 64)) { file_close(f); return SH_ERR_VERIFY; }

    uint64_t row = 0;
    for (uint32_t g = 0; g < h->group_count; g++) {
        f->group_off[g] = row;
        row += cell_bytes_k(f->groups[g].u_len, r->keyed);
    }
    if (row != h->row_bytes) { file_close(f); return SH_ERR_VERIFY; }
    return SH_OK;
}

static int file_open(sh_pads_reader *r, const char *path, sh_pads_file *f) {
    memset(f, 0, sizeof *f); f->fd = -1;
    snprintf(f->path, sizeof f->path, "%s", path);
    f->fd = open(path, O_RDONLY | O_CLOEXEC);
    if (f->fd < 0) return SH_ERR_IO;
    return file_judge(r, f);
}

static int file_bind(sh_pads_reader *r, sh_pads_file *f, uint32_t *missing) {
    free(f->ordinal_of);
    f->ordinal_of = (int *)malloc((size_t)r->n_bound * sizeof(int));
    if (!f->ordinal_of) return SH_ERR_NOMEM;
    for (uint32_t b = 0; b < r->n_bound; b++) {
        f->ordinal_of[b] = -1;
        for (uint32_t g = 0; g < f->hdr.group_count; g++) {
            const sh_pads_group *sg = &f->groups[g], *bg = &r->bound[b];
            if (!strncmp(sg->name, bg->name, SH_PADS_NAME_MAX) && sg->K == bg->K && sg->u_len == bg->u_len) { f->ordinal_of[b] = (int)g; break; }
        }
        if (f->ordinal_of[b] < 0) {
            if (missing) *missing = b;
            return SH_ERR_VERIFY;   /* a shipment that lacks a group is not usable */
        }
    }
    return SH_OK;
}

static int reader_scan(sh_pads_reader *r, bool defer_binding) {
    DIR *d = opendir(r->dir);
    if (!d) return SH_ERR_IO;
    struct dirent *e;
    int added = 0;
    while ((e = readdir(d))) {
        const size_t n = strlen(e->d_name);
        if (n < 6 || strcmp(e->d_name + n - 5, ".pads")) continue;
        char path[512];
        snprintf(path, sizeof path, "%s/%s", r->dir, e->d_name);
        if (reader_has(r, path)) continue;
        if (r->n_files == r->cap_files) {
            const size_t cap = r->cap_files ? r->cap_files * 2 : 8;
            sh_pads_file *nf = (sh_pads_file *)realloc(r->files, cap * sizeof *nf);
            if (!nf) { closedir(d); return SH_ERR_NOMEM; }
            r->files = nf; r->cap_files = cap;
        }
        sh_pads_file *f = &r->files[r->n_files];
        if (file_open(r, path, f) != SH_OK) continue;          /* not ours, or damaged: skipped, never trusted */
        if (!defer_binding && r->n_bound && file_bind(r, f, NULL) != SH_OK) { file_close(f); continue; }
        r->n_files++; added++;
    }
    closedir(d);
    return added;
}

static int shipment_check(sh_pads_file *f, const uint8_t seed_id[16], const uint8_t consumer_sk[32],
                          const uint8_t *model_digest, uint64_t *index0, uint64_t *index_count) {
    sh_pads_reader r; memset(&r, 0, sizeof r);           /* a throwaway reader: the judgment uses its seed, key and digest only */
    memcpy(r.seed_id, seed_id, 16); memcpy(r.sk, consumer_sk, 32);
    if (model_digest) { r.have_digest = true; memcpy(r.model_digest, model_digest, 32); }
    const int rc = file_judge(&r, f);
    if (rc == SH_OK) { if (index0) *index0 = f->hdr.index0; if (index_count) *index_count = f->hdr.index_count; file_close(f); }
    pads_wipe(r.sk, sizeof r.sk);
    return rc;
}
int sh_pads_shipment_check(const char *path, const uint8_t seed_id[16], const uint8_t consumer_sk[32],
                           const uint8_t *model_digest, uint64_t *index0, uint64_t *index_count) {
    if (!path || !seed_id || !consumer_sk) return SH_ERR_RANGE;
    sh_pads_file f; memset(&f, 0, sizeof f); f.fd = -1;
    snprintf(f.path, sizeof f.path, "%s", path);
    f.fd = open(path, O_RDONLY | O_CLOEXEC);
    if (f.fd < 0) return SH_ERR_IO;
    return shipment_check(&f, seed_id, consumer_sk, model_digest, index0, index_count);
}
int sh_pads_shipment_check_fd(int fd, const uint8_t seed_id[16], const uint8_t consumer_sk[32],
                              const uint8_t *model_digest, uint64_t *index0, uint64_t *index_count) {
    if (fd < 0 || !seed_id || !consumer_sk) return SH_ERR_RANGE;
    sh_pads_file f; memset(&f, 0, sizeof f);
    snprintf(f.path, sizeof f.path, "<fd %d>", fd);
    do { f.fd = fcntl(fd, F_DUPFD_CLOEXEC, 0); } while (f.fd < 0 && errno == EINTR);   /* our own descriptor to close; the caller's stays */
    if (f.fd < 0) return SH_ERR_IO;
    return shipment_check(&f, seed_id, consumer_sk, model_digest, index0, index_count);
}

static sh_pads_reader *reader_open(const char *dir, const uint8_t seed_id[16], const uint8_t consumer_sk[32], bool keyed, int *err) {
    *err = SH_OK;
    sh_pads_reader *r = (sh_pads_reader *)calloc(1, sizeof *r);
    if (!r) { *err = SH_ERR_NOMEM; return NULL; }
    r->keyed = keyed;
    snprintf(r->dir, sizeof r->dir, "%s", dir);
    memcpy(r->seed_id, seed_id, 16);
    memcpy(r->sk, consumer_sk, 32);
    pthread_mutex_init(&r->mu, NULL);
    const int rc = reader_scan(r, false);
    if (rc < 0) { *err = rc; sh_pads_reader_close(r); return NULL; }
    return r;
}
sh_pads_reader *sh_pads_reader_open(const char *dir, const uint8_t seed_id[16], const uint8_t consumer_sk[32], int *err) {
    return reader_open(dir, seed_id, consumer_sk, false, err);
}
sh_pads_reader *sh_pads_reader_open_keyed(const char *dir, const uint8_t delivery_id[16], const uint8_t consumer_sk[32], int *err) {
    return reader_open(dir, delivery_id, consumer_sk, true, err);
}
bool sh_pads_reader_keyed(const sh_pads_reader *r) { return r && r->keyed; }

int sh_pads_reader_bind(sh_pads_reader *r, const sh_pads_group *groups, uint32_t n_groups) {
    if (!r || !n_groups) return SH_ERR_RANGE;
    free(r->bound);
    r->bound = (sh_pads_group *)calloc(n_groups, sizeof *groups);
    if (!r->bound) return SH_ERR_NOMEM;
    memcpy(r->bound, groups, (size_t)n_groups * sizeof *groups);
    r->n_bound = n_groups;
    /* Include deliveries since the previous bind, but judge their group set
     * below so a mismatch is not silently discarded as an empty bank. */
    const int scanned = reader_scan(r, true);
    if (scanned < 0) return scanned;
    /* Re-bind what is already open; drop shipments that do not fit. */
    size_t kept = 0;
    const size_t present = r->n_files;
    uint32_t missing = UINT32_MAX;
    int rejected = SH_OK;
    for (size_t i = 0; i < r->n_files; i++) {
        const int rc = file_bind(r, &r->files[i], &missing);
        if (rc == SH_OK) { if (kept != i) r->files[kept] = r->files[i]; kept++; }
        else { rejected = rc; file_close(&r->files[i]); }
    }
    r->n_files = kept;
    if (present && !kept) {
        if (missing < n_groups) {
            const sh_pads_group *g = &r->bound[missing];
            fprintf(stderr, "[shielded] dealt pads: no available shipment covers registered group %.64s K=%u u_len=%llu\n",
                    g->name, g->K, (unsigned long long)g->u_len);
        }
        return rejected;  /* incompatible present files are not an empty bank */
    }
    return SH_OK;
}

static sh_pads_file *reader_find(sh_pads_reader *r, uint64_t index) {
    for (size_t i = 0; i < r->n_files; i++) {
        sh_pads_file *f = &r->files[i];
        if (index >= f->hdr.index0 && index < f->hdr.index0 + f->hdr.index_count) return f;
    }
    return NULL;
}

static int reader_cell(sh_pads_reader *r, uint32_t group, uint64_t index,
                       int32_t *u_out, uint8_t *key_out, uint32_t *shipment_group) {
    if (shipment_group) *shipment_group = UINT32_MAX;
    if (!r || !r->n_bound || group >= r->n_bound || !u_out) return SH_ERR_RANGE;
    if (r->keyed != (key_out != NULL)) return SH_ERR_RANGE;   /* keyed cells need somewhere to put the key, seed cells have none */
    /* Resolve under the lock, then retain a descriptor while decrypting outside
     * it. Pruning can close/reuse the table's fd as soon as the lock is released. */
    pthread_mutex_lock(&r->mu);
    sh_pads_file *f = reader_find(r, index);
    if (!f) { reader_scan(r, false); f = reader_find(r, index); }
    int fd = -1, g = -1; uint64_t u_len = 0, off = 0; uint8_t key[32], seed_id[16];
    if (f) {
        g = f->ordinal_of[group];
        u_len = f->groups[g].u_len;
        off = f->hdr.data_off + (index - f->hdr.index0) * f->hdr.row_bytes + f->group_off[g];
        do { fd = fcntl(f->fd, F_DUPFD_CLOEXEC, 0); } while (fd < 0 && errno == EINTR);
        memcpy(key, f->key, 32); memcpy(seed_id, f->hdr.seed_id, 16);
    }
    const bool found = f != NULL;
    pthread_mutex_unlock(&r->mu);
    if (!found) return SH_ERR_EXHAUST;
    if (fd < 0) { pads_wipe(key, sizeof key); return SH_ERR_IO; }
    const size_t kb = r->keyed ? SH_PADS_CELL_KEY : 0;
    const size_t n = (size_t)cell_bytes_k(u_len, r->keyed);
    uint8_t *cell = (uint8_t *)malloc(n), *plain = (uint8_t *)malloc(kb + (size_t)(3 * u_len));
    int rc = SH_OK;
    if (!cell || !plain) rc = SH_ERR_NOMEM;
    else if (pread(fd, cell, n, (off_t)off) != (ssize_t)n) rc = SH_ERR_IO;
    else {
        uint8_t nonce[12];
        cell_nonce(nonce, index, (uint32_t)g);
        (void)seed_id;
        rc = aead_open(key, nonce, cell, kb + (size_t)(3 * u_len), plain);
        const uint8_t *p = plain + kb;
        for (uint64_t j = 0; rc == SH_OK && j < u_len; j++) {
            const int64_t v = (int64_t)p[3 * j] | ((int64_t)p[3 * j + 1] << 8) | ((int64_t)p[3 * j + 2] << 16);
            if (v >= SH_M_MOD) { rc = SH_ERR_VERIFY; break; }
            u_out[j] = (int32_t)(v - SH_HALF_M);
        }
        if (rc == SH_OK && kb) memcpy(key_out, plain, kb);
    }
    pads_wipe(key, sizeof key);
    if (plain) pads_wipe(plain, kb);
    free(cell); free(plain); close(fd);
    if (rc == SH_OK && shipment_group) *shipment_group = (uint32_t)g;
    return rc;
}

int sh_pads_reader_cell_ordinal(sh_pads_reader *r, uint32_t group, uint64_t index,
                                 int32_t *u_out, uint32_t *shipment_group) {
    return reader_cell(r, group, index, u_out, NULL, shipment_group);
}
int sh_pads_reader_cell_keyed(sh_pads_reader *r, uint32_t group, uint64_t index,
                              int32_t *u_out, uint8_t key_out[32], uint32_t *shipment_group) {
    if (!key_out) return SH_ERR_RANGE;
    return reader_cell(r, group, index, u_out, key_out, shipment_group);
}
int sh_pads_reader_cell(sh_pads_reader *r, uint32_t group, uint64_t index, int32_t *u_out) {
    return sh_pads_reader_cell_ordinal(r, group, index, u_out, NULL);
}

uint32_t sh_pads_reader_groups(const sh_pads_reader *r, sh_pads_group *out, uint32_t cap) {
    if (!r) return 0;
    pthread_mutex_lock((pthread_mutex_t *)&r->mu);
    if (!r->n_files) { pthread_mutex_unlock((pthread_mutex_t *)&r->mu); return 0; }
    const sh_pads_file *f = &r->files[0];
    uint32_t n = f->hdr.group_count < cap ? f->hdr.group_count : cap;
    if (out) memcpy(out, f->groups, (size_t)n * sizeof *out);
    pthread_mutex_unlock((pthread_mutex_t *)&r->mu);
    return n;
}

int sh_pads_reader_prune_below(sh_pads_reader *r, uint64_t floor, bool unlink_files) {
    if (!r || !floor) return 0;
    int dropped = 0;
    pthread_mutex_lock(&r->mu);
    for (size_t i = 0; i < r->n_files; ) {
        sh_pads_file *f = &r->files[i];
        if (f->hdr.index0 + f->hdr.index_count > floor) { i++; continue; }
        char path[512]; snprintf(path, sizeof path, "%s", f->path);
        file_close(f);
        if (unlink_files) unlink(path);
        r->n_files--;
        if (i < r->n_files) { r->files[i] = r->files[r->n_files]; memset(&r->files[r->n_files], 0, sizeof r->files[0]); r->files[r->n_files].fd = -1; }
        dropped++;
    }
    pthread_mutex_unlock(&r->mu);
    return dropped;
}

/* Insert [lo,hi) into a sorted, disjoint, non-adjacent list, merging everything
 * it touches. Adjacency merges (a[j].hi == lo and a[k].lo == hi both count as
 * touching), nesting collapses, and a new interval is only appended when it
 * touches nothing. Returns -1 rather than truncating when a genuinely new
 * interval does not fit. */
static int sh_iv_insert(sh_pad_interval *a, uint32_t *n, uint32_t cap, uint64_t lo, uint64_t hi) {
    uint32_t j = 0;
    while (j < *n && a[j].hi < lo) j++;          /* first interval that can touch [lo,hi) */
    uint32_t k = j;
    while (k < *n && a[k].lo <= hi) {            /* absorb every interval it touches */
        if (a[k].lo < lo) lo = a[k].lo;
        if (a[k].hi > hi) hi = a[k].hi;
        k++;
    }
    if (k > j) {
        a[j].lo = lo; a[j].hi = hi;
        if (k > j + 1) {
            memmove(&a[j + 1], &a[k], (size_t)(*n - k) * sizeof *a);
            *n -= (k - j - 1);
        }
        return 0;
    }
    if (*n >= cap) return -1;                    /* never claim coverage we could not represent */
    memmove(&a[j + 1], &a[j], (size_t)(*n - j) * sizeof *a);
    a[j].lo = lo; a[j].hi = hi; (*n)++;
    return 0;
}

int sh_pads_reader_coverage(sh_pads_reader *r, sh_pad_interval *out, uint32_t cap,
                            uint32_t *n_out, uint64_t *n_files, uint32_t *n_bound,
                            bool *bound_table) {
    if (n_out) *n_out = 0;
    if (n_files) *n_files = 0;
    if (n_bound) *n_bound = 0;
    if (bound_table) *bound_table = false;
    if (!r) return SH_PAD_BUDGET_UNAVAILABLE;
    if (!out && cap) return SH_PAD_BUDGET_UNAVAILABLE;
    uint32_t n = 0;
    int status = SH_PAD_BUDGET_OK;
    /* Try-lock only: this mutex is held across directory scans and header
     * authentication, and a diagnostic must never wait behind them. BUSY means
     * NOT OBSERVED; it must never be read as "no files" or "no coverage", and
     * nothing else in this call may be treated as having been read. */
    if (pthread_mutex_trylock(&r->mu) != 0) return SH_PAD_BUDGET_BUSY;
    if (n_files) *n_files = (uint64_t)r->n_files;
    if (n_bound) *n_bound = r->n_bound;
    /* Read the table POINTER as well as the count. sh_pads_reader_bind frees
     * the old table first and can then fail its calloc while n_bound still
     * holds the previous value, so a positive count does not by itself mean a
     * group set is bound. Nothing is repaired here and no binding behaviour
     * changes; the diagnostic simply refuses to call that state bound. */
    const bool have_table = r->bound != NULL;
    if (bound_table) *bound_table = have_table;
    if (r->n_files > (size_t)SH_PAD_BUDGET_MAX_FILES) {
        /* Conservative: refuse BEFORE scanning any of them, even though the
         * merged union might have fitted. The point of the cap is a finite
         * bound on work done under this mutex, not a bound on the answer. */
        status = SH_PAD_BUDGET_INCOMPLETE;
    } else {
        for (size_t i = 0; i < r->n_files; i++) {
            const uint64_t lo = r->files[i].hdr.index0, cnt = r->files[i].hdr.index_count;
            if (!cnt) continue;                   /* an empty extent covers nothing */
            if (lo > UINT64_MAX - cnt) { status = SH_PAD_BUDGET_INVALID; n = 0; break; }
            if (sh_iv_insert(out, &n, cap, lo, lo + cnt) != 0) { status = SH_PAD_BUDGET_INCOMPLETE; break; }
        }
        /* A reader with no bound group set has not had file_bind's guarantee
         * applied, so its extents are not coverage for any registered group.
         * The intervals are still real and are kept, explicitly labelled.
         * A count without a table is worse than unbound: it is a state a failed
         * rebind can leave behind, so it gets its own conservative status. */
        if (status == SH_PAD_BUDGET_OK) {
            if (r->n_bound > 0 && !have_table)      status = SH_PAD_BUDGET_BIND_INVALID;
            else if (r->n_bound == 0 || !have_table) status = SH_PAD_BUDGET_UNBOUND;
        }
    }
    pthread_mutex_unlock(&r->mu);
    if (n_out) *n_out = (status == SH_PAD_BUDGET_OK || status == SH_PAD_BUDGET_UNBOUND ||
                         status == SH_PAD_BUDGET_BIND_INVALID) ? n : 0;
    return status;
}

uint64_t sh_pads_reader_extent(const sh_pads_reader *r) {
    uint64_t hi = 0;
    if (!r) return 0;
    pthread_mutex_lock((pthread_mutex_t *)&r->mu);
    for (size_t i = 0; i < r->n_files; i++) {
        const uint64_t e = r->files[i].hdr.index0 + r->files[i].hdr.index_count;
        if (e > hi) hi = e;
    }
    pthread_mutex_unlock((pthread_mutex_t *)&r->mu);
    return hi;
}

void sh_pads_reader_close(sh_pads_reader *r) {
    if (!r) return;
    for (size_t i = 0; i < r->n_files; i++) file_close(&r->files[i]);
    free(r->files); free(r->bound);
    pthread_mutex_destroy(&r->mu);
    pads_wipe(r->sk, sizeof r->sk);
    free(r);
}

void sh_pads_reader_require_digest(sh_pads_reader *r, const uint8_t model_digest[32]) {
    if (!r) return;
    pthread_mutex_lock(&r->mu);
    memcpy(r->model_digest, model_digest, 32); r->have_digest = true;
    /* Drop anything already opened for another model. */
    size_t kept = 0;
    for (size_t i = 0; i < r->n_files; i++) {
        if (!memcmp(r->files[i].hdr.model_digest, model_digest, 32)) { if (kept != i) r->files[kept] = r->files[i]; kept++; }
        else file_close(&r->files[i]);
    }
    r->n_files = kept;
    pthread_mutex_unlock(&r->mu);
}

/* ---- ledger window (P1: a local file) ----------------------------------- */
int sh_pads_window_reserve(const char *ledger_path, uint64_t want, uint64_t *lo, uint64_t *hi) {
    if (!ledger_path || !want || !lo || !hi) return SH_ERR_RANGE;
    if (want > SH_PADS_INDEX_LIMIT) return SH_ERR_EXHAUST;
    int fd = open(ledger_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) return SH_ERR_IO;
    if (flock(fd, LOCK_EX) != 0) { close(fd); return SH_ERR_IO; }
    char buf[32] = {0};
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return SH_ERR_IO; }
    if (st.st_size < 0 || st.st_size >= (off_t)sizeof buf) { close(fd); return SH_ERR_VERIFY; }
    ssize_t n = pread(fd, buf, sizeof buf - 1, 0);
    uint64_t mark = 0;
    if (n < 0) { close(fd); return SH_ERR_IO; }
    if (n > 0) {
        char *end; errno = 0;
        mark = strtoull(buf, &end, 10);
        if (errno || buf[0] < '0' || buf[0] > '9' ||
            !((end == buf+n) || (end == buf+n-1 && *end == '\n'))) { close(fd); return SH_ERR_VERIFY; }
    }
    if (mark > SH_PADS_INDEX_LIMIT || want > SH_PADS_INDEX_LIMIT - mark) { close(fd); return SH_ERR_EXHAUST; }
    const uint64_t next = mark + want;
    const int len = snprintf(buf, sizeof buf, "%llu\n", (unsigned long long)next);
    /* Advance the mark BEFORE handing out the window (reserve-before-use). */
    if (pwrite(fd, buf, (size_t)len, 0) != len || ftruncate(fd, len) != 0 || fsync(fd) != 0) { close(fd); return SH_ERR_IO; }
    close(fd);
    *lo = mark; *hi = next;
    return SH_OK;
}


/* ---- HMAC/HKDF-SHA512 over TweetNaCl's crypto_hash --------------------- */
/* Bootstrap messages are small and bounded. Never derive a known zero key or
 * dereference NULL because an allocation failed during key derivation. */
static int hmac_sha512(const uint8_t *key, size_t klen, const uint8_t *m1, size_t n1, const uint8_t *m2, size_t n2, uint8_t out[64]) {
    if (n1 > 256 || n2 > 256 - n1) return SH_ERR_RANGE;
    uint8_t k[128] = {0}, kh[64], inner[128 + 256], ih[64], outer[128 + 64];
    if (klen > 128) { crypto_hash(kh, key, klen); memcpy(k, kh, 64); } else if (klen) memcpy(k, key, klen);
    for (int i = 0; i < 128; i++) inner[i] = k[i] ^ 0x36;
    if (n1) memcpy(inner + 128, m1, n1);
    if (n2) memcpy(inner + 128 + n1, m2, n2);
    crypto_hash(ih, inner, 128 + n1 + n2);
    for (int i = 0; i < 128; i++) outer[i] = k[i] ^ 0x5c;
    memcpy(outer + 128, ih, 64);
    crypto_hash(out, outer, sizeof outer);
    pads_wipe(k, sizeof k); pads_wipe(kh, sizeof kh); pads_wipe(inner, sizeof inner);
    pads_wipe(ih, sizeof ih); pads_wipe(outer, sizeof outer);
    return SH_OK;
}
/* HKDF-SHA512 (RFC 5869), bounded to two blocks for this private bootstrap
 * helper. The seed box needs only 32 bytes with a fixed info string. */
static int hkdf_sha512(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len,
                       const char *info, uint8_t *okm, size_t okm_len) {
    const size_t il = strlen(info);
    if (il > 64 || okm_len > 128) return SH_ERR_RANGE;
    uint8_t prk[64], t[64], buf[64 + 64 + 1]; size_t tl = 0, done = 0; uint8_t ctr = 1;
    int rc = hmac_sha512(salt, salt_len, ikm, ikm_len, NULL, 0, prk);
    while (rc == SH_OK && done < okm_len) {
        if (tl) memcpy(buf, t, tl);
        memcpy(buf + tl, info, il); buf[tl + il] = ctr;
        rc = hmac_sha512(prk, 64, buf, tl + il + 1, NULL, 0, t);
        if (rc != SH_OK) break;
        const size_t n = okm_len - done < 64 ? okm_len - done : 64;
        memcpy(okm + done, t, n); done += n; tl = 64; ctr++;
    }
    pads_wipe(prk, sizeof prk); pads_wipe(t, sizeof t); pads_wipe(buf, sizeof buf);
    if (rc != SH_OK) pads_wipe(okm, okm_len);
    return rc;
}

/* ---- ChaCha20 (RFC 8439: 32-bit counter, 96-bit nonce) + Poly1305 -------- */
#define P_ROTL(v, c) (((v) << (c)) | ((v) >> (32 - (c))))
#define P_QR(a, b, c, d) (a += b, d ^= a, d = P_ROTL(d, 16), c += d, b ^= c, b = P_ROTL(b, 12), a += b, d ^= a, d = P_ROTL(d, 8), c += d, b ^= c, b = P_ROTL(b, 7))
static uint32_t ld32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void chacha_ietf_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out[64]) {
    static const uint32_t C[4] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
    uint32_t s[16], x[16];
    for (int i = 0; i < 4; i++) s[i] = C[i];
    for (int i = 0; i < 8; i++) s[4 + i] = ld32(key + 4 * i);
    s[12] = counter; s[13] = ld32(nonce); s[14] = ld32(nonce + 4); s[15] = ld32(nonce + 8);
    memcpy(x, s, sizeof x);
    for (int i = 0; i < 10; i++) {
        P_QR(x[0], x[4], x[8], x[12]); P_QR(x[1], x[5], x[9], x[13]); P_QR(x[2], x[6], x[10], x[14]); P_QR(x[3], x[7], x[11], x[15]);
        P_QR(x[0], x[5], x[10], x[15]); P_QR(x[1], x[6], x[11], x[12]); P_QR(x[2], x[7], x[8], x[13]); P_QR(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; i++) { const uint32_t v = x[i] + s[i]; out[4 * i] = (uint8_t)v; out[4 * i + 1] = (uint8_t)(v >> 8); out[4 * i + 2] = (uint8_t)(v >> 16); out[4 * i + 3] = (uint8_t)(v >> 24); }
}
/* RFC 8439 AEAD with no AAD, Poly1305 by poly1305-donna (incremental, so the
 * tag runs over the ciphertext without a padded copy): tag over ct || pad16 ||
 * le64(0) || le64(ct_len) under the one-time key from block 0, data from
 * blocks 1.. Layout on the wire: 16-byte tag, then the ciphertext. */
static void aead_tag(const uint8_t otk[32], const uint8_t *ct, size_t n, uint8_t tag[16]) {
    static const uint8_t zeros[16] = {0};
    poly1305_context st;
    poly1305_init(&st, otk);
    poly1305_update(&st, ct, n);
    if (n % 16) poly1305_update(&st, zeros, 16 - n % 16);
    uint8_t lens[16] = {0};
    for (int i = 0; i < 8; i++) lens[8 + i] = (uint8_t)((uint64_t)n >> (8 * i));
    poly1305_update(&st, lens, 16);
    poly1305_finish(&st, tag);
}
static void aead_stream(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *in, size_t n, uint8_t *out) {
    uint8_t blk[64];
    for (size_t off = 0, ctr = 1; off < n; off += 64, ctr++) {
        chacha_ietf_block(key, (uint32_t)ctr, nonce, blk);
        const size_t take = n - off < 64 ? n - off : 64;
        for (size_t i = 0; i < take; i++) out[off + i] = in[off + i] ^ blk[i];
    }
    pads_wipe(blk, sizeof blk);
}
static int aead_seal(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *msg, size_t n, uint8_t *out) {
    uint8_t blk[64], otk[32];
    chacha_ietf_block(key, 0, nonce, blk); memcpy(otk, blk, 32);
    aead_stream(key, nonce, msg, n, out + 16);
    aead_tag(otk, out + 16, n, out);
    pads_wipe(otk, sizeof otk); pads_wipe(blk, sizeof blk);
    return SH_OK;
}
static int aead_open(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *box, size_t n, uint8_t *out) {
    uint8_t blk[64], otk[32], tag[16];
    chacha_ietf_block(key, 0, nonce, blk); memcpy(otk, blk, 32);
    aead_tag(otk, box + 16, n, tag);
    pads_wipe(otk, sizeof otk); pads_wipe(blk, sizeof blk);
    if (!poly1305_verify(tag, box)) return SH_ERR_VERIFY;
    aead_stream(key, nonce, box + 16, n, out);
    return SH_OK;
}
int sh_aead_seal(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *msg, size_t n, uint8_t *out) {
    return aead_seal(key, nonce, msg, n, out);
}
int sh_aead_open(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *box, size_t n, uint8_t *out) {
    return aead_open(key, nonce, box, n, out);
}

int sh_pads_seed_open(const uint8_t epk[32], const uint8_t nonce[12], const uint8_t *box, size_t box_len,
                      const uint8_t pad_sk[32], const uint8_t pad_pk[32], uint8_t seed_out[32]) {
    if (!seed_out) return SH_ERR_RANGE;
    if (!epk || !nonce || !box || !pad_sk || !pad_pk || box_len != 32 + 16) {
        pads_wipe(seed_out, 32); return SH_ERR_RANGE;
    }
    uint8_t shared[32], salt[64], key[32], plain[32], laid[48];
    int rc = SH_ERR_VERIFY;
    if (crypto_scalarmult(shared, pad_sk, epk) != 0) goto done;
    // RFC 7748 section 6.1: low-order public inputs eliminate the recipient's
    // secret contribution. TweetNaCl returns success even for an all-zero DH.
    uint8_t nonzero = 0;
    for (size_t i = 0; i < sizeof shared; i++) nonzero |= shared[i];
    if (!nonzero) goto done;
    memcpy(salt, epk, 32); memcpy(salt + 32, pad_pk, 32);
    rc = hkdf_sha512(shared, 32, salt, 64, "enclave-pads-seed-box", key, 32);
    if (rc != SH_OK) goto done;
    memcpy(laid, box + 32, 16); memcpy(laid + 16, box, 32);   /* Node's ct||tag -> our tag||ct */
    rc = aead_open(key, nonce, laid, 32, plain);
    if (rc == SH_OK) memcpy(seed_out, plain, 32);
 done:
    if (rc != SH_OK) pads_wipe(seed_out, 32);
    pads_wipe(shared, sizeof shared); pads_wipe(key, sizeof key); pads_wipe(plain, sizeof plain);
    return rc;
}

bool sh_pads_window_verify(const uint8_t ledger_pk[32], const char *seed_id_hex, uint64_t lo, uint64_t hi, uint64_t iat, const uint8_t sig[64]) {
    char msg[256];
    const int n = snprintf(msg, sizeof msg, "enclave-pads-window\n%s\n%llu\n%llu\n%llu", seed_id_hex,
                           (unsigned long long)lo, (unsigned long long)hi, (unsigned long long)iat);
    if (n <= 0 || n >= (int)sizeof msg) return false;
    uint8_t sm[64 + 256], m[64 + 256]; unsigned long long mlen = 0;
    memcpy(sm, sig, 64); memcpy(sm + 64, msg, (size_t)n);
    return crypto_sign_open(m, &mlen, sm, 64 + (unsigned long long)n, ledger_pk) == 0 && mlen == (unsigned long long)n;
}

int sh_pads_request_sign(const uint8_t transport_sk[64], const char *kind, const char *const *fields, size_t n_fields, const char *nonce_hex, uint8_t sig_out[64]) {
    memset(sig_out, 0, 64);
    if (!transport_sk || !kind || !nonce_hex || (n_fields && !fields)) return SH_ERR_RANGE;
    /* exact length first: "enclave-pads-<kind>" then "\n<field>" per field then "\n<nonce>" */
    size_t need = strlen("enclave-pads-") + strlen(kind) + 1 + strlen(nonce_hex);
    for (size_t i = 0; i < n_fields; i++) { if (!fields[i]) return SH_ERR_RANGE; need += 1 + strlen(fields[i]); }
    if (need > 65536) return SH_ERR_RANGE;
    char *msg = (char *)malloc(need + 1); uint8_t *sm = (uint8_t *)malloc(64 + need);
    if (!msg || !sm) { free(msg); free(sm); return SH_ERR_NOMEM; }
    size_t at = (size_t)snprintf(msg, need + 1, "enclave-pads-%s", kind);
    for (size_t i = 0; i < n_fields; i++) at += (size_t)snprintf(msg + at, need + 1 - at, "\n%s", fields[i]);
    at += (size_t)snprintf(msg + at, need + 1 - at, "\n%s", nonce_hex);
    int rc = SH_ERR_RANGE;
    if (at == need) { unsigned long long smlen = 0; crypto_sign(sm, &smlen, (const uint8_t *)msg, at, transport_sk); memcpy(sig_out, sm, 64); rc = SH_OK; }
    memset(sm, 0, 64 + need); free(sm); free(msg);
    return rc;
}

/* ---- hex --------------------------------------------------------------- */
bool sh_pads_hex2bin(const char *hex, uint8_t *out, size_t n) {
    if (!hex || strlen(hex) != 2 * n) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        for (int k = 0; k < 2; k++) {
            const char c = hex[2 * i + k];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
            else return false;
        }
        out[i] = (uint8_t)v;
    }
    return true;
}
void sh_pads_bin2hex(const uint8_t *in, size_t n, char *out) {
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2 * i] = d[in[i] >> 4]; out[2 * i + 1] = d[in[i] & 15]; }
    out[2 * n] = 0;
}

/* Explicit standalone API only: integrated consumers remain v2. */
#include "shielded-pads-v3.inc"
