/* The pad spill's CPU governor (shielded-spill-cpu.h): /proc/stat parsing and the cap rule.
 * cc -O2 -o spill-cpu-selftest spill-cpu-selftest.c && ./spill-cpu-selftest */
#include "shielded-spill-cpu.h"
#include <stdio.h>
static int fails = 0;
#define CHECK(c, what) do { if (c) printf("ok   %s\n", what); else { fails++; printf("FAIL %s (line %d)\n", what, __LINE__); } } while (0)

int main(void) {
    const char *stat =
        "cpu  1000 0 500 9000 100 0 0 0 0 0\n"
        "cpu0 100 10 50 800 20 5 5 10 7 0\n"          /* busy 100+10+50+5+5+10=180, total 180+800+20=1000 */
        "cpu1 300 0 100 600 0 0 0 0 0 0\n"            /* busy 400, total 1000 */
        "cpu7 900 0 50 50 0 0 0 0 0 0\n"              /* busy 950, total 1000 */
        "cpu15 0 0 0 1000 0 0 0 0 0 0\n"              /* busy 0, total 1000 */
        "intr 12345 0 0\nctxt 999\n";
    uint8_t mask[SH_CPU_MASK_MAX] = {0};
    sh_cpu_ticks t;
    mask[7] = mask[15] = 1;
    CHECK(sh_cpu_stat_parse(stat, mask, SH_CPU_MASK_MAX, &t) && t.cpus == 2 && t.busy == 950 && t.total == 2000, "only the masked CPUs, aggregate line skipped");
    memset(mask, 0, sizeof mask); mask[0] = 1;
    CHECK(sh_cpu_stat_parse(stat, mask, SH_CPU_MASK_MAX, &t) && t.busy == 180 && t.total == 1000, "steal and irq are busy, iowait is not, guest is inside user");
    memset(mask, 0, sizeof mask); mask[3] = 1;
    CHECK(!sh_cpu_stat_parse(stat, mask, SH_CPU_MASK_MAX, &t), "a CPU the file does not list: no reading");
    CHECK(!sh_cpu_stat_parse("", mask, SH_CPU_MASK_MAX, &t), "an empty file: no reading");
    mask[1] = 1;
    CHECK(sh_cpu_stat_parse("cpu1 5 0 5 90\n", mask, SH_CPU_MASK_MAX, &t) && t.busy == 10 && t.total == 100, "an old four-field line still reads");

    /* the cap: 9 refill CPUs, the eyesoff layout */
    CHECK(sh_spill_cpu_cap(9, 0.0, 0, 1.0, 15, 0) == 1, "idle: up one a period");
    CHECK(sh_spill_cpu_cap(9, 0.0, 0, 1.0, 15, 7) == 8, "idle: tops out at cpus - headroom");
    CHECK(sh_spill_cpu_cap(9, 0.0, 0, 1.0, 15, 8) == 8, "idle: stays");
    CHECK(sh_spill_cpu_cap(9, 0.0, 0, 1.0, 4, 4) == 4, "never past the thread limit");
    CHECK(sh_spill_cpu_cap(9, 6.3 / 9, 0, 1.0, 15, 8) == 1, "a prompt using 6.3 cores: cut at once to what is left");
    CHECK(sh_spill_cpu_cap(9, 8.0 / 9, 1.0, 1.0, 15, 1) == 1, "its own minting is not load (7 other + 1 minting -> 1 still)");
    CHECK(sh_spill_cpu_cap(9, 1.0, 0, 1.0, 15, 3) == 0, "every CPU busy with other work: none");
    CHECK(sh_spill_cpu_cap(9, 0.5, 0, 0, 15, 0) == 1, "zero headroom still ramps one at a time");
    CHECK(sh_spill_cpu_cap(9, 1.5, -2, -1, 15, 2) == 0, "out-of-range inputs clamp");
    CHECK(sh_spill_cpu_cap(0, 0, 0, 1, 15, 3) == 0 && sh_spill_cpu_cap(9, 0, 0, 1, 0, 3) == 0, "no CPUs or no minters: none");
    return fails != 0;
}
