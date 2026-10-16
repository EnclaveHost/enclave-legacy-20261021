package main

import (
	"strings"
	"testing"
)

const zimageVolume = "z-image-turbo-q4km-sd sha256 604d18e9717366bcda7f9a0671c4293c0c1f97ae436c4726a2ccb651531de6f6 " +
	"5562b24e6477efa10f3d1e4abee4572f5a09f177e151412c7977f651e20715ea 4096 4096 1973169 1973170\n"

func TestParseShieldVolume(t *testing.T) {
	v, err := parseShieldVolume([]byte(zimageVolume))
	if err != nil || v.model != "z-image-turbo-q4km-sd" || v.dblocks != 1973169 || v.hstart != 1973170 {
		t.Fatalf("the release's descriptor: %+v %v", v, err)
	}
	if v.minBytes() != 1973171*4096 {
		t.Fatalf("minBytes %d", v.minBytes())
	}
	bad := []string{
		"",
		strings.Replace(zimageVolume, "sha256", "sha1", 1),
		strings.Replace(zimageVolume, " 4096 4096", " 512 4096", 1),
		strings.Replace(zimageVolume, "604d18e9", "604D18E9", 1),
		strings.Replace(zimageVolume, "1973170", "1973169", 1), // the hash tree must start after the data
		strings.Replace(zimageVolume, "1973169 ", "0 ", 1),
		zimageVolume + " extra",
	}
	for _, b := range bad {
		if _, err := parseShieldVolume([]byte(b)); err == nil {
			t.Fatalf("accepted %q", b)
		}
	}
}
