package main

import (
	"bytes"
	"enclave.host/isolation/contract"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDomainConfigFile(t *testing.T) {
	dir := t.TempDir()
	if e := writeAppConfig(dir, nil); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(dir, "app.config")
	if _, e := os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("absent config created a file")
	}
	cfg := []byte(`{"http":[{"name":"canary"}]}`)
	if e := writeAppConfig(dir, cfg); e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(p)
	if e != nil || !bytes.Equal(got, cfg) {
		t.Fatal("config differs")
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0444 {
		t.Fatal("config is writable")
	}
	out, _ := json.Marshal(domain{AppConfig: cfg})
	if bytes.Contains(out, []byte("canary")) {
		t.Fatal("config leaked in domain status")
	}
	if e := writeAppConfig(dir, make([]byte, contract.MaxConfigBytes+1)); e == nil {
		t.Fatal("oversized config accepted")
	}
}
