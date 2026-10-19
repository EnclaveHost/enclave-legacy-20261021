/* The pad spill's CPU governor, the parts without threads: read the CPUs the refill side runs on from /proc/stat,
 * and turn what the rest of the guest uses into how many refill threads may mint into the spill.
 *
 * Why measured and not the idle rule: a prompt keeps the link "busy" (a pad taken in the last 2 s) while it uses
 * three quarters of the refill CPUs, so idle-only minting left a quarter of them idle for the whole prompt, and
 * minting a fixed half of the threads beside a decode took cores the decode wanted. The governor mints on what the
 * other work leaves, minus a headroom, measured in the guest (the host's view counts haltpoll's idle polling as busy).
 *
 * Its own minting is not "other work": the caller subtracts the minters' thread CPU, or the governor would see its
 * own threads as load and throttle itself to nothing. Steal is load: a vCPU the host took is not a CPU to mint on. */
#ifndef SHIELDED_SPILL_CPU_H
#define SHIELDED_SPILL_CPU_H
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SH_CPU_MASK_MAX 1024

typedef struct { uint64_t busy, total; int cpus; } sh_cpu_ticks;

/* /proc/stat text -> the busy and total ticks of the cpuN lines whose N is set in mask (one byte per CPU, n bytes).
 * busy = user + nice + system + irq + softirq + steal (guest time is inside user); total = busy + idle + iowait.
 * -> false when no listed CPU appears (an unreadable file, an empty mask). */
static bool sh_cpu_stat_parse(const char *text, const uint8_t *mask, int n, sh_cpu_ticks *out) {
    memset(out, 0, sizeof *out);
    for (const char *p = text; p && *p; ) {
        const char *eol = strchr(p, '\n');
        if (p[0] == 'c' && p[1] == 'p' && p[2] == 'u' && p[3] >= '0' && p[3] <= '9') {
            char *q;
            const long cpu = strtol(p + 3, &q, 10);
            if (cpu >= 0 && cpu < n && mask[cpu]) {
                uint64_t f[8] = {0};
                int k = 0;
                for (; k < 8; k++) {
                    char *e;
                    const unsigned long long v = strtoull(q, &e, 10);
                    if (e == q || (eol && e > eol)) break;
                    f[k] = (uint64_t)v; q = e;
                }
                if (k >= 4) {                       /* user nice system idle [iowait irq softirq steal] */
                    const uint64_t busy = f[0] + f[1] + f[2] + f[5] + f[6] + f[7];
                    out->busy += busy;
                    out->total += busy + f[3] + f[4];
                    out->cpus++;
                }
            }
        }
        p = eol ? eol + 1 : NULL;
    }
    return out->cpus > 0;
}

/* How many threads may mint next. cpus: CPUs in the mask; busy_frac: their busy share over the period, from the
 * ticks; mint_cores: CPU the minters themselves used over it (thread CPU seconds per wall second); headroom: cores
 * left free for bursts the period average hides; max: the most minters there may ever be; prev: the current cap.
 * Down at once, up one a period: a burst stops minting quickly, and minting comes back without overshooting. */
static int sh_spill_cpu_cap(int cpus, double busy_frac, double mint_cores, double headroom, int max, int prev) {
    if (cpus <= 0 || max <= 0) return 0;
    if (busy_frac < 0) busy_frac = 0;
    if (busy_frac > 1) busy_frac = 1;
    double other = busy_frac * cpus - (mint_cores > 0 ? mint_cores : 0);
    if (other < 0) other = 0;
    const double spare = cpus - other - (headroom > 0 ? headroom : 0);
    int want = spare >= 1 ? (int)spare : 0;
    if (want > max) want = max;
    if (prev < 0) prev = 0;
    return want < prev ? want : (want > prev + 1 ? prev + 1 : want);
}
#endif
