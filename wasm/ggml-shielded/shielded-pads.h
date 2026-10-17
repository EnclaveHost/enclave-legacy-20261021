/* Dealt pads: shipments of u = r.W minted OFF the trusted half.
 *
 * shielded/dealer/PLAN.md is the design. A shipment (`.pads`) carries, for a
 * range of pad indices and every weight group of one model, the unblinding
 * vectors u; the mask r is never shipped - both the dealer and the consumer
 * derive it from a shared 32-byte seed with sh_pad_r(). Each (index, group)
 * cell is an independent ChaCha20-Poly1305 box under a per-shipment key that
 * is itself boxed to the consumer's X25519 pad key, so an operator's bank
 * holds ciphertext and sizes only and a consumer can start on any row.
 *
 * Layout, little-endian:
 *   sh_pads_hdr (fixed 256 bytes) | groups[] (sh_pads_group, 80 bytes each)
 *   | cells: row-major by index, group order as in groups[], each cell =
 *     16-byte Poly1305 tag + 3*u_len bytes of u+M/2 in [0,M) (M ~ 2^23.8)
 */
#ifndef SHIELDED_PADS_H
#define SHIELDED_PADS_H
#include "shielded-pad-budget.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SH_PADS_MAGIC     "ENCLPAD1"
#define SH_PADS_VERSION   2u          /* 2: ChaCha20-Poly1305 cells (1 was XSalsa20-Poly1305) */
#define SH_PADS_NAME_MAX  64
#define SH_PADS_CELL_TAG  16          /* Poly1305 */
/* Format 4 (host pad bank, shielded/dealer/HOST-BANK.md): every cell carries its own 32-byte
 * mask key ahead of u inside the same box, so a consumer derives the masks of the cells it was
 * given and of nothing else; r = sh_pad_r(cellkey, 0, 0, K). Readers and writers are opened
 * for one format and refuse the other. */
#define SH_PADS_VERSION_KEYED 4u
#define SH_PADS_CELL_KEY  32
#define SH_PADS_HDR_BYTES 256
/* ChaCha counter fields: group16 | index24 | block24; 8 values per block.
 * Exhaustion requires a fresh seed, never masking/reducing an index. */
#define SH_PADS_INDEX_LIMIT (UINT64_C(1) << 24)
#define SH_PADS_GROUP_LIMIT (UINT32_C(1) << 16)
#define SH_PADS_K_LIMIT     (INT64_C(8) << 24)
/* Writer admission cap: at most 8 MiB of nonce-claim bitmap per open file.
 * This is a resource policy, separate from the larger PRF domain limits. */
#define SH_PADS_WRITER_MAX_CELLS (UINT64_C(1) << 26)

typedef struct {
    uint32_t group;                   /* consumer's ordinal at mint time */
    uint32_t K;
    uint64_t u_len;                   /* sum of N over the group's nodes */
    char     name[SH_PADS_NAME_MAX];  /* the group's first node, for binding by name */
} sh_pads_group;

/* Fixed header. Everything but key_box/hdr_box is covered by hdr_box, the
 * secretbox of the SHA-512 of (fixed fields with those two zeroed || group
 * table) under the shipment key. */
typedef struct {
    char     magic[8];
    uint32_t version;
    uint32_t group_count;
    uint8_t  model_digest[32];
    uint8_t  seed_id[16];
    uint64_t index0, index_count;
    uint64_t data_off;                /* first cell */
    uint64_t row_bytes;               /* one index, all groups */
    uint8_t  dealer_pk[32];           /* ephemeral X25519 public key of this shipment */
    uint8_t  key_box[48];             /* crypto_box(shipment key) to the consumer's pad key */
    uint8_t  hdr_box[80];             /* ChaCha20-Poly1305 of sha512(header || groups): tag || ct */
#define SH_PADS_HDR_PAD (256 - 8 - 4 - 4 - 32 - 16 - 8 - 8 - 8 - 8 - 32 - 48 - 80)
#if SH_PADS_HDR_PAD > 0
    uint8_t  pad[SH_PADS_HDR_PAD];   /* absent when the fields fill the 256 bytes exactly (a zero-length array is a GNU extension) */
#endif
} sh_pads_hdr;

/* A keyed cell's mask key: ChaCha20(bank, (group << 48) | (index << 24))[0:32], a PRF output. */
void sh_pad_cellkey(const uint8_t bank[32], uint32_t group, uint64_t index, uint8_t key_out[32]);

/* The engine's ChaCha20 block (64-bit counter, zero nonce). */
void sh_chacha20_block(const uint32_t key[8], uint64_t counter, uint32_t out[16]);
/* The cells' AEAD (RFC 8439 ChaCha20-Poly1305, no associated data) under a
 * caller's key and nonce, for the pad spill (shielded-spill.c). Layout: the
 * 16-byte tag, then the n-byte ciphertext. Either call works in place: seal
 * with msg == out + 16, open with out == box + 16. */
int sh_aead_seal(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *msg, size_t n, uint8_t *out);
int sh_aead_open(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *box, size_t n, uint8_t *out);
/* r for (seed, group, index): ChaCha20 keyed by the seed, block counter
 * (group << 48) | (index << 24) | block, values uniform over [0, M) by the
 * same uint64 draw the engine's own mask bank uses. Both sides call this.
 * Requires group < GROUP_LIMIT, index < INDEX_LIMIT, 0 < K <= K_LIMIT;
 * invalid calls abort rather than generating repeated masks. Public writer,
 * reader and link entry points reject invalid geometry before reaching it. */
void sh_pad_r(const uint8_t seed[32], uint32_t group, uint64_t index, int64_t K, int32_t *r_out);

/* --- writer (the dealer) -------------------------------------------------- */
typedef struct sh_pads_writer sh_pads_writer;
/* Creates a private temporary file beside path, mints a shipment key, boxes it
 * to consumer_pk, and reserves the cell area. An existing destination refuses;
 * no final .pads name is exposed until successful close. Failed/crashed temp
 * files never match the bank's .pads scan. The parent directory must be trusted
 * and support hard links and directory fsync (the normal local dealer store).
 * close must run only after all writer calls/threads have finished. */
sh_pads_writer *sh_pads_writer_open(const char *path, const uint8_t model_digest[32],
                                    const uint8_t seed_id[16], const sh_pads_group *groups, uint32_t n_groups,
                                    uint64_t index0, uint64_t index_count, const uint8_t consumer_pk[32], int *err);
/* Cells may be written in any order, exactly once per file; each is boxed
 * independently. A duplicate claim or failed claimed write retires the file.
 * Retry by creating a fresh file/key, never reseal a cell under the old nonce.
 * Internal short-write retries preserve the already-sealed ciphertext.
 * u is the balanced row (u_len values in (-M/2, M/2]). This scratch-owning form
 * is serialized; concurrent callers use cell_with and disjoint private scratch. */
int  sh_pads_writer_cell(sh_pads_writer *w, uint64_t index, uint32_t group, const int32_t *u);
/* Format 4: the same writer, every cell sealed with its mask key (sh_pads_writer_cell* refuse
 * such a writer, and the keyed call refuses a format-2 one). */
sh_pads_writer *sh_pads_writer_open_keyed(const char *path, const uint8_t model_digest[32],
                                          const uint8_t delivery_id[16], const sh_pads_group *groups, uint32_t n_groups,
                                          uint64_t index0, uint64_t index_count, const uint8_t consumer_pk[32], int *err);
int  sh_pads_writer_cell_keyed_with(sh_pads_writer *w, uint64_t index, uint32_t group, const uint8_t cellkey[32],
                                    const int32_t *u, uint8_t *plain, uint8_t *cell);
/* thread-safe form: caller-owned scratch of sh_pads_writer_scratch_bytes(w) bytes each */
int  sh_pads_writer_cell_with(sh_pads_writer *w, uint64_t index, uint32_t group, const int32_t *u, uint8_t *plain, uint8_t *cell);
size_t sh_pads_writer_scratch_bytes(const sh_pads_writer *w);
/* Refuses incomplete/failed files. A complete file is flushed, linked atomically
 * without replacing an existing path, and its directory flushed. Always frees
 * the writer and attempts to remove its temporary name. A directory-fsync failure can leave
 * a complete final file but returns an error, never a durability success. */
int  sh_pads_writer_close(sh_pads_writer *w);

/* --- reader (the consumer: the pVM, or the CVM engine) -------------------- */
typedef struct sh_pads_reader sh_pads_reader;
/* Scans `dir` for shipments of `seed_id` readable with `consumer_sk` and keeps
 * the ones whose header verifies. Rescans on demand when an index is missing. */
sh_pads_reader *sh_pads_reader_open(const char *dir, const uint8_t seed_id[16], const uint8_t consumer_sk[32], int *err);
/* A reader of format-4 shipments only (cells carry their mask keys). */
sh_pads_reader *sh_pads_reader_open_keyed(const char *dir, const uint8_t delivery_id[16], const uint8_t consumer_sk[32], int *err);
bool sh_pads_reader_keyed(const sh_pads_reader *r);
/* A keyed reader's cell: u and the cell's mask key (wiped by the caller after deriving r). */
int  sh_pads_reader_cell_keyed(sh_pads_reader *r, uint32_t group, uint64_t index,
                               int32_t *u_out, uint8_t key_out[32], uint32_t *shipment_group);
/* Host pad bank issuance: bank rows [src0, src0+count) re-sealed to a consumer's keyed writer at
 * [dst0, dst0+count); same group table on both sides. */
int  sh_pads_reissue(sh_pads_reader *bank, uint64_t src0, sh_pads_writer *dst, uint64_t dst0, uint64_t count);
/* The group table of the first shipment the reader holds (for tools that
 * bind without a model): copies up to `cap` entries, returns the count. */
uint32_t sh_pads_reader_groups(const sh_pads_reader *r, sh_pads_group *out, uint32_t cap);
/* Binds the consumer's group table: every group must appear in every shipment
 * with the same K and u_len (matched by name); records the ordinal map.
 * Rescans delivered files. An empty bank is permitted; if files with valid
 * headers are present but none bind, returns SH_ERR_VERIFY (or allocation
 * error), instead of silently treating incompatible geometry as an empty bank.
 * Serialize with cell reads, pruning, rebinding and close. */
int  sh_pads_reader_bind(sh_pads_reader *r, const sh_pads_group *groups, uint32_t n_groups);
/* Reads and opens one cell into `u_out` (u_len balanced values). Returns
 * SH_ERR_EXHAUST when no shipment on disk covers the index (after a rescan),
 * SH_ERR_VERIFY when the box does not open (tampered or wrong key). */
int  sh_pads_reader_cell(sh_pads_reader *r, uint32_t group, uint64_t index, int32_t *u_out);
/* Also returns the matched SHIPMENT ordinal on success. sh_pad_r must use
 * this ordinal, not the consumer's local group index: binding permits a
 * reordered/subset group table. The ordinal and cell come from the same
 * authenticated shipment and retained descriptor. On failure it is UINT32_MAX. */
int  sh_pads_reader_cell_ordinal(sh_pads_reader *r, uint32_t group, uint64_t index,
                                  int32_t *u_out, uint32_t *shipment_group);
/* One shipment file judged on its own by the reader's rules (magic, version,
 * extents, this seed, this calibration digest when given, key box under the
 * consumer key, header box, group table): SH_OK with its index range filled,
 * SH_ERR_VERIFY when it is not ours or damaged, SH_ERR_IO when unreadable.
 * Nothing stays open, nothing is trusted on failure. The pVM signs a delivery
 * acknowledgment (shielded/anchor/avf/PAD-ACK.md) only after SH_OK. */
int sh_pads_shipment_check(const char *path, const uint8_t seed_id[16], const uint8_t consumer_sk[32],
                           const uint8_t *model_digest /* 32 bytes or NULL */, uint64_t *index0, uint64_t *index_count);
/* The same judgment by an open descriptor (read by offset, the caller's position untouched):
 * a receiver judges the file it holds while it is still hidden and cannot be pruned under it. */
int sh_pads_shipment_check_fd(int fd, const uint8_t seed_id[16], const uint8_t consumer_sk[32],
                              const uint8_t *model_digest /* 32 bytes or NULL */, uint64_t *index0, uint64_t *index_count);
/* Pin the model: shipments whose header digest differs are ignored (the
 * dealer prints the digest it recorded; SHIELDED_PAD_MODEL_DIGEST carries it). */
void sh_pads_reader_require_digest(sh_pads_reader *r, const uint8_t model_digest[32]);
/* Drop (and, when `unlink_files`, delete) every shipment wholly below
 * `floor`: the caller's lowest live cursor, so nothing still to be imported
 * can go. Returns the number dropped. */
int  sh_pads_reader_prune_below(sh_pads_reader *r, uint64_t floor, bool unlink_files);
/* The highest index any shipment on disk covers, plus one (0 = none). */
uint64_t sh_pads_reader_extent(const sh_pads_reader *r);

/* Diagnostic only (SHIELDED_PAD_BUDGET). The UNION of the extents of the files
 * this reader currently holds, as half-open [lo,hi) intervals, sorted, disjoint
 * and non-adjacent. Takes `mu`; performs no scan, no bind, no prune and no
 * decrypt, so it neither consumes nor authorises anything.
 *
 * Takes `mu` with a TRY-lock and returns SH_PAD_BUDGET_BUSY on contention,
 * because this mutex is held across scans and header authentication; BUSY is
 * missing evidence and never an empty bank.
 *
 * Otherwise returns SH_PAD_BUDGET_OK, SH_PAD_BUDGET_INCOMPLETE when `cap` intervals were
 * not enough, or SH_PAD_BUDGET_INVALID when a held header's index0+index_count
 * would overflow uint64. Under either failure NOTHING about coverage is
 * claimed and the partial list must not be read as coverage. `n_out`,
 * `n_files` and `n_bound` are written when non-NULL and the mutex was taken.
 *
 * A pure ACCESSOR: it adds no field to sh_pads_reader and changes no existing
 * reader function. libanchor, libengine and libggml-shielded each carry a copy
 * of these symbols and anchor_payload.c dlopens with RTLD_NOW|RTLD_GLOBAL, so
 * growing the private reader struct on one side could let an older definition
 * allocate or bind a reader that a newer accessor then reads past the end of.
 * That is why no bind epoch is tracked here; an epoch would need a separately
 * reviewed whole-library ABI change, never a field added on one side. */
int sh_pads_reader_coverage(sh_pads_reader *r, sh_pad_interval *out, uint32_t cap,
                            uint32_t *n_out, uint64_t *n_files, uint32_t *n_bound,
                            bool *bound_table);
void sh_pads_reader_close(sh_pads_reader *r);

/* --- ledger window ---------------------------------------------------------
 * Reserve-before-use: the mark advances to lo+W BEFORE any index in [lo, lo+W)
 * is consumed, so a restart resumes at the mark and can never replay. The P1
 * ledger is a local file holding the mark; P2 moves it to the platform. */
int  sh_pads_window_reserve(const char *ledger_path, uint64_t want, uint64_t *lo, uint64_t *hi);

/* --- the platform's seed box and signed windows (relay/pads.mjs) ------------
 * seed box: X25519(epk, pad key) -> HKDF-SHA512(shared, salt = epk || pad_pk,
 * info "enclave-pads-seed-box") -> ChaCha20-Poly1305 (RFC 8439, no AAD).
 * Opening is allocation-free and rejects all-zero DH outputs. seed_out is
 * cleared on every failure; it must point to a writable 32-byte buffer. */
int  sh_pads_seed_open(const uint8_t epk[32], const uint8_t nonce[12], const uint8_t *box, size_t box_len,
                       const uint8_t pad_sk[32], const uint8_t pad_pk[32], uint8_t seed_out[32]);
/* A ledger window: Ed25519 over "enclave-pads-window\n<seed_id hex>\n<lo>\n<hi>\n<iat>". */
bool sh_pads_window_verify(const uint8_t ledger_pk[32], const char *seed_id_hex, uint64_t lo, uint64_t hi, uint64_t iat, const uint8_t sig[64]);
/* Ed25519 detached signature by the pVM's transport key over the request
 * line set "enclave-pads-<kind>\n<field>\n...\n<nonce hex>" (fields already text). */
/* SH_OK with the signature, else SH_ERR_RANGE (a NULL or an absurdly long transcript, > 64 KiB) or
 * SH_ERR_NOMEM, with sig_out zeroed: a truncated transcript is never signed. */
int  sh_pads_request_sign(const uint8_t transport_sk[64], const char *kind, const char *const *fields, size_t n_fields, const char *nonce_hex, uint8_t sig_out[64]);

/* Hex helpers for the env/CLI surface. */
bool sh_pads_hex2bin(const char *hex, uint8_t *out, size_t n);
void sh_pads_bin2hex(const uint8_t *in, size_t n, char *out /* 2n+1 */);

#ifdef __cplusplus
}
#endif
#endif
