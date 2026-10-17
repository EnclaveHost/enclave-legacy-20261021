/*
 * shielded-tee.h -- the trusted half, in C: pads, refill, Freivalds, and the
 * link that drives one shielded worker.
 *
 * Mirrors shielded/tee.py. What the worker sees is public weights and masked
 * activations; what never crosses is the pad, the Freivalds secret, or any
 * plaintext activation. The four rules most easily broken by accident, all of
 * which this file is responsible for:
 *
 *  1. PADS ARE ONE-TIME. Issuance is a monotonic counter that STALLS at capacity
 *     and never wraps. Two activations under one pad hand the adversary their
 *     difference, and successive decode activations differ by very little.
 *  2. ONE PLAINTEXT GETS ONE PAD. Weights fed by the same activation (q/k/v from
 *     one attn_norm, gate/up from one ffn_norm) share the pad, because masking
 *     one x three times under three pads is three encryptions of one value for
 *     no benefit. Such weights form a GROUP and are exchanged together.
 *  3. VERIFY BEFORE USE, over the INTEGERS. A product that exceeds M/2 wraps and
 *     stays congruent mod M, so a mod-M check accepts it and it decodes to
 *     garbage with no error signal. The check runs modulo an unrelated prime and
 *     catches a lying worker AND a field wrap in the same two dot products.
 *  4. THE FREIVALDS SECRET COMES FROM THE OS CSPRNG. A worker that can predict s
 *     solves d.s == 0 over three outputs and forges freely.
 *
 * THE POOL. u = r.W is the one term that can never be offloaded, and at three
 * residue planes it costs the TEE three times the work of the matmul it
 * unmasks. It is also independent of the activation, so it is computed AHEAD of
 * the request: background threads keep a pool of (r, r.W) pairs per group, and
 * the exchange itself only masks, sends, unmasks and verifies. Refill is a
 * throughput term on spare cores, not a latency term on the decode chain.
 */
#ifndef SHIELDED_TEE_H
#define SHIELDED_TEE_H

#include "shielded-pad-budget.h"
#include <stdbool.h>
#include "shielded-pads.h"
#include <stddef.h>
#include <stdint.h>

#include "shielded-wire.h"
#include "shielded-simd.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SH_FV_S_RANGE (1 << 20)
#define SH_FV_REPS    2            /* ~2^-40 soundness per check */
#define SH_GROUP_MAX  8            /* weights sharing one activation */

typedef struct sh_link sh_link;

/* Errors beyond the wire's. */
#define SH_ERR_VERIFY   -10   /* worker lied, or the field wrapped */
#define SH_ERR_EXHAUST  -11   /* pad bank dry: stall the request, never wrap */
#define SH_ERR_RANGE    -12   /* weights do not fit the int8 lane */

/* Tunables read from the environment at open:
 *   SHIELDED_REFILL_THREADS  background refill threads; unset = derived from the
 *                            registered weights at start (see derive_threads in
 *                            shielded-tee.c), clamped to [2, ncores/2]
 *   SHIELDED_REFILL_TARGET_MS the token time the derived count must keep up
 *                            with (default 6, the measured 0.5B decode)
 *   SHIELDED_POOL_DEPTH      ready pads kept per group (default 16)
 *   SHIELDED_REFILL_BATCH    pads generated per batch (default 4)
 *   SHIELDED_WARM_MS         longest sh_link_start waits for one ready pad per
 *                            group before the first exchange (default 5000)
 *   SHIELDED_OVERLAP_VERIFY  1 = compute the Freivalds input-side dots after
 *                            sending the socket request, before reading its
 *                            reply (default 0; no change to the ring path)
 * and at start:
 *   SHIELDED_VSOCK_PORT      try AF_VSOCK to the host on this port before TCP;
 *                            unset = the TCP port number when /dev/vsock exists, 0 = never */
/* Dealt pads (shielded-pads.h, shielded/dealer/PLAN.md), all read at open and
 * required TOGETHER - a partial set refuses to open rather than minting:
 *   SHIELDED_PAD_SOURCE      directory of .pads shipments (the operator's bank)
 *   SHIELDED_PAD_SEED        64 hex: the 32-byte seed r is derived from
 *   SHIELDED_PAD_SEED_ID     32 hex: names the seed; shipments carry it
 *   SHIELDED_PAD_SK          64 hex: this consumer's X25519 pad secret key
 *   SHIELDED_PAD_LEDGER      path of the ledger file (P1: local; P2: platform)
 *   SHIELDED_PAD_MODEL_DIGEST optional 64 hex: only shipments minted for this
 *                            model (the digest the dealer printed) are used
 *   SHIELDED_PAD_CHECK       1 = verify every imported pad against the weights
 *                            (Freivalds mod M; one weight pass per node at
 *                            registration): a wrong dealer is refused at
 *                            import, before any use
 *   SHIELDED_PAD_WINDOW      indices reserved per ledger call (default 64)
 *   SHIELDED_PAD_WAIT_MS     how long a refill waits for a missing index
 *                            before the link stops (default 10000)
 *   SHIELDED_PAD_SOURCE=http://host:port/v1/pads/shipments
 *                            a bank instead of a directory (shielded-bank.c):
 *                            shipments are fetched into SHIELDED_PAD_CACHE
 *                            (default /tmp/shielded-pads-<seed_id>), at most
 *                            SHIELDED_PAD_CACHE_MB (2048) ahead of the window
 *   SHIELDED_PAD_PRUNE       unlink spent shipments in the source directory
 *                            (default 1 for a bank cache, 0 for a directory)
 *   SHIELDED_PAD_WINDOW_URL  an http:// window agent answering
 *                            POST {want, seed_id} with {lo, hi, iat, sig};
 *                            requires SHIELDED_PAD_LEDGER_PK (64 hex, the
 *                            platform's Ed25519 ledger key) and replaces the
 *                            ledger file, like the pVM's provider does
 *   SHIELDED_PAD_AGENT_TOKEN bearer sent to the window agent (its per-boot
 *                            token, from the manager's bootstrap) */
sh_link *sh_link_open(const char *host, int port, bool verify, int *err);
/* Explicit per-link transport/reservation for a pooled tenant. Call before start;
 * avoids mutating process-wide environment while other links refill/reconnect. */
void sh_link_configure(sh_link *l, int vsock_port, uint64_t reserve_bytes, int refill_threads);
/* Per-card optional BAR, before start. Empty path explicitly keeps sockets. */
void sh_link_configure_shm(sh_link *l, const char *path, uint64_t bytes);
void     sh_link_close(sh_link *l);
/* Stop/join refill workers, discard unused pads and disconnect. The caller
 * excludes exchanges/start; registration, integrity latch and mask counters
 * survive. A later sh_link_start obtains fresh pools without pad reuse. */
void     sh_link_quiesce(sh_link *l);
const char *sh_link_last_error(const sh_link *l);
/* A remote product verification failure retires the link permanently. Further
 * start/register/compute calls return SH_ERR_VERIFY without consuming pads or
 * sending requests. Close it and register fresh trusted state to recover;
 * transport failures alone do not retire it. */

/* Register one weight as a FIELD_GEMM node, before connecting.
 * `w_fixed` is (N,K) int8 -- THE encoding, one row per output, borrowed for the
 * life of the link. `share_x_with` is an earlier node fed by the SAME
 * activation, or -1. Returns the node index, or negative on error. */
/* Diagnostic only (SHIELDED_PAD_BUDGET), read-only, allocation-free, and it
 * starts nothing: a dealt link that has not been started reports UNSTARTED rather
 * than being brought up. Fills `b` and as much of the caller's interval and
 * group arrays as they hold, taking pool_mu and then the reader mutex, which
 * is the order dealt_advanced already uses. Performs no cell read, no window
 * reserve, no directory scan, no bind and no prune.
 *
 * The caller must exclude a concurrent sh_link_start: the reader pointer and
 * the group array are replaced by start_pools without pool_mu. In the backend
 * that exclusion is sh_state::mu, which sh_card_compute already holds around
 * sh_link_start.
 *
 * Every lock is a TRY-lock: SH_PAD_BUDGET_BUSY means not observed, never an
 * empty ring or bank. Pass SH_PAD_BUDGET_F_REQUEST_PATH_EXCLUDED only when the
 * caller also excludes the request path, which writes pads_used/pads_missed
 * without pool_mu; without the flag those stay zero with counters_valid false.
 * INCOMPLETE means a caller array was too small; the record then claims
 * nothing about coverage. */
int sh_link_pad_budget(sh_link *l, sh_pad_budget *b, uint32_t flags,
                       sh_pad_interval *intervals, uint32_t cap_intervals,
                       sh_pad_group_budget *groups, uint32_t cap_groups);

int sh_link_add_weight(sh_link *l, const char *name, const int8_t *w_fixed,
                       int64_t K, int64_t N, int32_t max_m, int share_x_with);

/* Replace the borrowed weight after registration with a trusted reader of
 * the SAME encoded bytes. The reader must authenticate storage before copying
 * into the private output buffer; return 0 only for an exact successful read.
 * Context must outlive the link. Dealt + verified + pad-checked links only,
 * before start; the caller may release w_fixed only after this returns SH_OK.
 * Upload/reconnect and exact local fallback use the reader; a read failure is
 * SH_ERR_VERIFY and must abort the request. No disk read during normal GEMM. */
typedef int (*sh_weight_read_fn)(void *ctx, uint64_t offset, uint8_t *out, size_t bytes);
int sh_link_set_weight_reader(sh_link *l, int node, sh_weight_read_fn reader, void *ctx);

/* Trusted local-mint storage adapter. Installed only before start, after
 * verification vectors were built from the exact registered bytes. It owns no
 * mask state: refill receives fresh bank-issued r and returns exact r.W mod M.
 * A failure retires the link; no partial result may be published. */
typedef int (*sh_weight_refill_fn)(void *ctx, const int32_t *r, int batch,
                                 int32_t *u, int64_t stride);
int sh_link_set_local_weight_source(sh_link *, int node, sh_weight_read_fn,
                                    sh_weight_refill_fn, void *ctx);

/* Ship the public weights, install the vetted graph, start the refill threads.
 * Restartable: a weight added after start means a fresh connection carrying
 * the whole set. */
int sh_link_start(sh_link *l);

/* One masked exchange: every node in `nodes` must belong to one group (share
 * the activation). `x_field` is the PLAINTEXT field-encoded activation, (m,K)
 * int64, balanced. `y_out[i]` receives (m,N_i) int64, exact and verified.
 * On any failure the result is SH_ERR_VERIFY and y_out must be DISCARDED by
 * the caller: rows of already-checked nodes, and the unmasked rows of the
 * failing one, may have been written before the check fired. */
int sh_link_gemm(sh_link *l, const int *nodes, size_t n_nodes,
                 const int64_t *x_field, int32_t m, int64_t **y_out);

/* The same exchange, writing into a WIDER output row. y_out[i] points at the
 * first element of this link's column slice and y_stride[i] is the full row
 * length; NULL means the node's own N (the ordinary layout). This is what a
 * column-split placement needs: several links each own a contiguous slice of
 * the same weight's output columns and write straight into one row. */
/* Post-mortem of a FAILED Freivalds check, for the log and nothing else: the
 * exact product W.x recomputed locally in int64 and reduced to the balanced
 * field, compared column by column with the unmasked reply. The pattern names
 * the mechanism -- a few kernel blocks (transfer or kernel), every column (the
 * pad's u), a trailing range (a short or stale reply), no difference at all
 * (the check side). w is (N,K) int8, x is m rows of K, y is m rows at stride
 * ystr. Writes one summary line into out. Runs only after a check has already
 * failed and the link is being retired; it changes no decision.
 *
 * WHAT IT MAY SAY. The log is host-visible, and a worker can trigger this path
 * at will, so the line must not depend on the activations. The unmasked reply
 * is balanced(W.x + d) where d is the worker's error, so "which values differ
 * from balanced(W.x)" depends on d alone: counts, rows, blocks and the column
 * range are functions of what the worker sent, never of x. No product or
 * activation VALUE is ever printed. The one x-dependent quantity -- how many
 * true values lie outside the field -- is included only when plaintext_bits is
 * nonzero (SHIELDED_FAULT_DIAG_PLAINTEXT=1, a development opt-in, off by
 * default, which leaks those bits by design). */
void sh_fv_postmortem(const int8_t *w, int64_t K, int64_t N, const int64_t *x, int m,
                      const int64_t *y, int64_t ystr, int plaintext_bits, char *out, size_t cap);
/* SHIELDED_FAULT_DIAG_PLAINTEXT=1: fault diagnostics may include bits that
 * depend on the activations (never values). Honoured only in a build compiled
 * with -DSHIELDED_ALLOW_FAULT_DIAG_PLAINTEXT (no deployment build is); in any
 * other build it is ignored with a warning. Read once; default 0. */
int sh_fault_diag_plaintext(void);

int sh_link_gemm_stride(sh_link *l, const int *nodes, size_t n_nodes,
                        const int64_t *x_field, int32_t m, int64_t **y_out,
                        const int64_t *y_stride);

/* Both GEMM entry points reject |x_field| >= SH_FV_X_LIMIT (2^26) with
 * SH_ERR_VERIFY before using pads or writing output. This public arithmetic
 * bound protects masking, verification and the exact local accumulator; it
 * does not replace the tighter product-wrap check against the field modulus.
 * Callers must abort on this error, including on a local fallback. */

/* The same product, computed in the TEE in plain int64, with no worker
 * involved. Numerically IDENTICAL to sh_link_gemm -- the offloaded path is
 * exact -- which is what makes it a fallback rather than a degraded mode. */
int sh_link_gemm_local(sh_link *l, const int *nodes, size_t n_nodes,
                       const int64_t *x_field, int32_t m, int64_t **y_out);
int sh_link_gemm_local_stride(sh_link *l, const int *nodes, size_t n_nodes,
                              const int64_t *x_field, int32_t m, int64_t **y_out,
                              const int64_t *y_stride);

/* True once the worker is connected and the graph installed. */
bool sh_link_is_live(const sh_link *l);
/* Dealt mode: the ring is fed from shipments and the link never mints; an
 * EXHAUST from sh_link_gemm then means the bank is behind and the caller
 * must refuse to proceed rather than compute in the clear. */
bool sh_link_is_dealt(const sh_link *l);

/* The encoded weight, (N,K), for the caller's TEE-side outlier term. */
const int8_t *sh_link_weight(const sh_link *l, int node);

/* Run the integrity check directly on a candidate (x, y) pair. Exposed so the
 * probe can assert BOTH directions against the same code the online path uses. */
bool sh_link_verify(const sh_link *l, int node, const int64_t *x, const int64_t *y, int32_t m);

/* Counters, for the probe and for tests. */
void sh_link_stats(const sh_link *l, uint64_t *exchanges, uint64_t *macs, uint64_t *verify_fail);

/* Cumulative for this link only. Like sh_link_stats, the caller must serialize
 * snapshots with operations on the SAME link. Different links own independent
 * counters. Fresh links start at zero; reconnecting the pipe keeps the totals.
 * wire_ms excludes the verification RHS overlapped with the request. */
typedef struct {
    double mask_ms, wire_ms, refill_ms, unmask_lhs_ms, rhs_ms;
    /* Inside the exchange but in none of the phases above: the balanced-range
     * scan over every reply value, and pad take/release. Named so the
     * ~9 ms/pass that sh_link_gemm_stride does not otherwise account for
     * stops being a subtraction. */
    double check_ms, pads_ms;
    /* Entry of the exchange to the start of masking: the input range scan over
     * m*K and the buffer ensures. Untimed until now, and over half of the
     * TEE-side link work had no timer at all. */
    double pre_ms;
    /* Inside mask_ms: the plane split itself, and dealt_wait, separately. */
    double mask_kernel_ms, dealt_wait_ms;
    /* mask kernel: elements masked, and calls over 20 us (count + time) */
    uint64_t mask_elems, mask_slow_n; double mask_slow_ms;
    /* Spin left over AFTER the overlapped RHS: the budget any further
     * overlap would have to fit into. */
    double idle_ms; uint64_t idle_n;
    uint64_t completed_calls, missed_pads, used_pads;
} sh_link_profile;
/* Register trusted work to run in the exchange's idle window (opt-in). The
 * callee must not read reply bytes, must not touch the link's pipe, and must
 * be safe to run exactly once per exchange. Pass NULL to clear. */
void sh_link_set_idle_work(sh_link *l, void (*fn)(void *), void *ctx);
void sh_link_profile_snapshot(const sh_link *l, sh_link_profile *out);

/* Dealt pads. The group table this link would bind a shipment against
 * (ordinal, first node's name, K, u_len); returns the group count. */
int sh_link_group_table(const sh_link *l, sh_pads_group *out, uint32_t cap);
/* The dealer's mint: with the model's weights registered (no worker needed),
 * write one shipment of `count` indices from `index0` for every group, r from
 * `seed`, cells boxed to `consumer_pk`. */
/* Ledger windows from the host instead of SHIELDED_PAD_LEDGER: the pVM's owner
 * app asks the platform (relay/pads.mjs) and the payload verifies the signed
 * window before answering. Must return SH_OK with lo == the previous hi. */
typedef int (*sh_window_fn)(void *ctx, uint64_t want, uint64_t *lo, uint64_t *hi);
void sh_link_set_window_provider(sh_link *l, sh_window_fn fn, void *ctx);
int sh_link_dealt_selftest(sh_link *l, int rows, int32_t *r_out, int32_t *u_out);
/* The bank client (http:// source): fetch counters and the last listing status. */
void sh_link_bank_stats(const sh_link *l, uint64_t *files, uint64_t *bytes, int *last_status, char *err, size_t err_cap);
bool sh_link_has_bank(const sh_link *l);
/* The same shipment minted through the link's worker (needs SHIELDED_ZERO_PADS=1,
 * which only a SHIELDED_DEALER_MODE build reads; elsewhere this returns SH_ERR_RANGE). */
int sh_link_mint_shipment_worker(sh_link *l, const uint8_t seed[32], const uint8_t seed_id[16], const uint8_t model_digest[32],
                                 uint64_t index0, uint64_t count, const uint8_t consumer_pk[32], const char *path);
int sh_link_mint_shipment(sh_link *l, const uint8_t seed[32], const uint8_t seed_id[16], const uint8_t model_digest[32],
                          uint64_t index0, uint64_t count, const uint8_t consumer_pk[32], const char *path);
/* Format 4 (host pad bank): every cell keyed from `bank` (sh_pad_cellkey) and sealed with its key. */
int sh_link_mint_shipment_keyed(sh_link *l, const uint8_t bank[32], const uint8_t delivery_id[16], const uint8_t model_digest[32],
                                uint64_t index0, uint64_t count, const uint8_t consumer_pk[32], const char *path);
/* Pool health: pads consumed, and how many had to be generated on the
 * request path because the pool was dry (the number that should be ~0). */
void sh_link_pool_stats(const sh_link *l, uint64_t *consumed, uint64_t *missed);
/* Waiting for reserved local pads or imported dealt pads: newly ready pads
 * and elapsed wait. This time is already included in the link's mask_ms;
 * it is a breakdown, not extra time to add to that profile. */
void sh_link_pad_wait_stats(const sh_link *l, uint64_t *waited, double *wait_ms);
/* The same counters for this node's shared-activation group, plus time spent
 * generating missing pads on the request path. Public weight metadata only. */
void sh_link_node_pool_stats(const sh_link *l, int node, uint64_t *consumed,
                             uint64_t *missed, double *on_path_ms);
/* Refill threads actually running (derived or from the environment), for logs. */
int  sh_link_refill_threads(const sh_link *l);
const char *sh_link_refill_priority(const sh_link *l);
/* Bytes per reply value after start: 4 (FIELD_GEMM) or 3 (FIELD_GEMM24); 0 before. */
int  sh_link_reply_width(const sh_link *l);

/* The wall time of the last exchange's wire phase (send, wait, receive), in
 * microseconds: what the backend watches to notice a card that is being
 * shared with something else. */
double sh_link_last_wire_us(const sh_link *l);
void sh_link_wire_timing(const sh_link *l, sh_wire_timing *out);

/* How the worker is reached ("vsock:9500", "tcp 10.0.2.2:9500 ..."), for logs. */
const char *sh_link_transport(const sh_link *l);
int sh_link_set_rcvlowat(sh_link *l, int cap, uint64_t *buffer_bytes);
int sh_link_set_rcvbuf(sh_link *l, int bytes, uint64_t *actual_bytes);

/* The SIMD table this process runs on, for callers with hot loops of their own. */
const sh_simd *sh_link_simd(void);

#ifdef __cplusplus
}
#endif
#endif
