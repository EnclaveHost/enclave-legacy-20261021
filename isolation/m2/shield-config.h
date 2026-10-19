/* Shield settings the deployment's app config may carry (dominit reads them from ENCLAVE_CONFIG before it starts the
 * app). Only top-level keys of the config object count: the scanner skips every string, escapes included, so text
 * inside a value (a system prompt quoting a key, say) never matches, and a key only counts when a ':' follows it.
 * The config is the deployment's own (owner-signed, CID-pinned); an unreadable value falls back to the default. */
#ifndef SHIELD_CONFIG_H
#define SHIELD_CONFIG_H
#include <string.h>

#define SHIELD_BUSY_DEFAULT (-2)   /* `true`: the engine's own default (half its refill threads) */
#define SHIELD_BUSY_CPU     (-3)   /* `false`: the CPU governor, as when the key is absent */

/* "shieldPadBusyMint": how the pad spill mints while requests run.
 *   absent / unreadable -> -1, false -> SHIELD_BUSY_CPU: on the CPU the guest leaves unused, measured
 *                          (SHIELDED_PAD_SPILL_CPU_HEADROOM; the caller sets it). `false` used to mean idle-only,
 *                          the stand-in for "do not take a request's CPU", which the governor does by measurement.
 *   true                -> SHIELD_BUSY_DEFAULT: a fixed half of the refill threads
 *   0..64               -> exactly that many minting threads; 0 = strictly idle-only (larger numbers clamp to 64) */
static int shield_busy_mint(const char *json) {
    static const char key[] = "\"shieldPadBusyMint\"";
    if (!json) return -1;
    int depth = 0;
    for (const char *p = json; *p; p++) {
        if (*p == '"') {
            const char *s = p++;
            while (*p && *p != '"') { if (*p == '\\' && p[1]) p++; p++; }
            if (!*p) return -1;                       /* unterminated string */
            if (depth != 1 || (size_t)(p - s + 1) != sizeof key - 1 || memcmp(s, key, sizeof key - 1) != 0) continue;
            const char *v = p + 1;
            while (*v == ' ' || *v == '\t' || *v == '\n' || *v == '\r') v++;
            if (*v != ':') continue;                  /* the key's text as a VALUE, not a key */
            v++;
            while (*v == ' ' || *v == '\t' || *v == '\n' || *v == '\r') v++;
            if (strncmp(v, "true", 4) == 0) return SHIELD_BUSY_DEFAULT;
            if (strncmp(v, "false", 5) == 0) return SHIELD_BUSY_CPU;
            if (*v >= '0' && *v <= '9') {
                long n = 0;
                while (*v >= '0' && *v <= '9') { if (n <= 64) n = n * 10 + (*v - '0'); v++; }
                return n > 64 ? 64 : (int)n;
            }
            return -1;
        }
        if (*p == '{' || *p == '[') depth++;
        else if (*p == '}' || *p == ']') depth--;
    }
    return -1;
}
#endif
