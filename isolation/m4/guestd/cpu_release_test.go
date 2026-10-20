package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCPUReleaseModeRefusesCompetingInputs(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	gw := `["http://192.0.2.1:8080","https://storage-b.example"]`
	ok := map[string]bool{"cpu-release": true, "isolation-release": true, "gateway": true}
	with := func(f string) map[string]bool {
		m := map[string]bool{f: true}
		for k := range ok {
			m[k] = true
		}
		return m
	}
	noEnv := func(string) string { return "" }
	dir, id, err := cpuReleaseMode("/srv/release/", pin, gw, ok, noEnv)
	if err != nil || dir != "/srv/release" || id != pin {
		t.Fatalf("a complete cold-host start refused: %q %q %v", dir, id, err)
	}
	cases := []struct {
		name, dir, pin, gw string
		set                map[string]bool
		env                func(string) string
		want               string
	}{
		{"relative directory", "release", pin, gw, ok, noEnv, "absolute"},
		{"no pin", "/r", "", gw, ok, noEnv, "exactly one"},
		{"none", "/r", "none", gw, ok, noEnv, "exactly one"},
		{"two pins", "/r", pin + "," + strings.Repeat("cd", 32), gw, ok, noEnv, "exactly one"},
		{"explicit firmware", "/r", pin, gw, with("ovmf"), noEnv, "-ovmf competes"},
		{"second template", "/r", pin, gw, with("cpu-template"), noEnv, "-cpu-template competes"},
		{"legacy tree", "/r", pin, gw, with("legacy-isolation"), noEnv, "-legacy-isolation competes"},
		{"shield model", "/r", pin, gw, with("shield-model-file"), noEnv, "-shield-model-file competes"},
		{"default component gateway", "/r", pin, "https://ipfs.enclave.host", map[string]bool{"isolation-release": true}, noEnv, "explicit -gateway"},
		{"single gateway string", "/r", pin, "https://storage-a.example", ok, noEnv, "JSON array"},
		{"empty list", "/r", pin, `[]`, ok, noEnv, "JSON array"},
		{"duplicate", "/r", pin, `["https://a.example","https://a.example"]`, ok, noEnv, "distinct"},
		{"credentials", "/r", pin, `["https://u:p@a.example"]`, ok, noEnv, "credentials"},
		{"query", "/r", pin, `["https://a.example/?token=1"]`, ok, noEnv, "query"},
		{"scheme", "/r", pin, `["file:///srv/ipfs"]`, ok, noEnv, "http(s)"},
		{"inherited firmware override", "/r", pin, gw, ok, func(k string) string {
			if k == "OVMF_OVERRIDE" {
				return "/other.fd"
			}
			return ""
		}, "OVMF_OVERRIDE"},
		{"inherited template", "/r", pin, gw, ok, func(k string) string {
			if k == "APP_IMAGE_TEMPLATE" {
				return "/old/template"
			}
			return ""
		}, "APP_IMAGE_TEMPLATE"},
		{"inherited other release", "/r", pin, gw, ok, func(k string) string {
			if k == "DOMAIN_RELEASE_DIR" {
				return "/other"
			}
			return ""
		}, "DOMAIN_RELEASE_DIR"},
	}
	for _, c := range cases {
		if _, _, err := cpuReleaseMode(c.dir, c.pin, c.gw, c.set, c.env); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

func TestCPUReleaseFilesNeedsABootableRegularTree(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"kernel", "firmware.fd", "template/init", "template/front", "template/rt/runtime.json"} {
		p := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(f), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := cpuReleaseFiles(dir); err != nil {
		t.Fatal(err)
	}
	k := filepath.Join(dir, "kernel")
	if err := os.Remove(k); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "firmware.fd"), k); err != nil {
		t.Fatal(err)
	}
	if err := cpuReleaseFiles(dir); err == nil || !strings.Contains(err.Error(), "kernel") {
		t.Fatalf("a symlinked kernel was accepted: %v", err)
	}
}
