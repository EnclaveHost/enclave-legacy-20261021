#include <stdio.h>
/* shield-config.h: the app-config switches dominit reads. cc -I. test-shield-config.c && ./a.out */
#include "shield-config.h"
static int fails = 0;
static void t(const char *j, int want, const char *what) { int got = shield_busy_mint(j); if (got != want) { fails++; printf("FAIL %s: got %d want %d\n", what, got, want); } else printf("ok   %s\n", what); }
int main(void) {
  t(NULL, -1, "no config");
  t("{}", -1, "absent");
  t("{\"shieldPadBusyMint\":true}", SHIELD_BUSY_DEFAULT, "true");
  t("{\"shieldPadBusyMint\" : false}", SHIELD_BUSY_CPU, "false = the CPU governor");
  t("{\"shieldPadBusyMint\": 0}", 0, "0 = strictly idle-only");
  t("{\"a\":1, \"shieldPadBusyMint\": 6}", 6, "number");
  t("{\"shieldPadBusyMint\":999}", 64, "clamped");
  t("{\"shieldPadBusyMint\":\"yes\"}", -1, "string value is unreadable");
  t("{\"system\":\"set \\\"shieldPadBusyMint\\\": true here\"}", -1, "inside a string (escaped quotes)");
  t("{\"x\":\"shieldPadBusyMint\"}", -1, "as a value");
  t("{\"x\":\"shieldPadBusyMint\",\"shieldPadBusyMint\":5}", 5, "a value with the key's text, then the real key");
  t("{\"models\":{\"shieldPadBusyMint\":true}}", -1, "nested key ignored");
  t("{\"models\":{\"a\":[1,{\"b\":2}]},\"shieldPadBusyMint\":4}", 4, "after nested objects");
  t("{\"shieldPadBusyMint\":tru", -1, "truncated");
  t("{\"s\":\"unterminated", -1, "unterminated string");
  t("{\"shieldPadBusyMintX\":true}", -1, "longer key");
  return fails != 0;
}
