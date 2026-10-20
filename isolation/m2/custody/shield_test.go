package custody

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The same vector as test/shield-custody.test.mjs (custody/v2/shield-evidence.mjs shieldReleaseInput).
func TestShieldReleaseInputMatchesTheCustodian(t *testing.T) {
	var b [32]byte
	for i := range b {
		b[i] = 0xab
	}
	got, err := ShieldReleaseInput(b, "0x"+string(bytes.Repeat([]byte("33"), 20)))
	if err != nil || hex.EncodeToString(got[:]) != "4e01ef1a9ae8565737835fb7577a968701ce4492461eb812164a7c2eb8eefd53" {
		t.Fatalf("drift: %x %v", got, err)
	}
	if again, _ := ShieldReleaseInput(b, "0x"+string(bytes.Repeat([]byte("33"), 20))); again != got {
		t.Fatal("not deterministic")
	}
	other, _ := ShieldReleaseInput(b, "0x"+string(bytes.Repeat([]byte("34"), 20)))
	if other == got {
		t.Fatal("the owner is not bound")
	}
	for _, bad := range []string{"", "0x33", "0x" + string(bytes.Repeat([]byte("00"), 20)), string(bytes.Repeat([]byte("33"), 21)), "0x" + string(bytes.Repeat([]byte("zz"), 20))} {
		if _, err := ShieldReleaseInput(b, bad); err == nil {
			t.Fatalf("%q accepted as an owner", bad)
		}
	}
}
