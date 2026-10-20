package contract

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestMeasuredAppConfig(t *testing.T) {
	text := []byte(`{"http":[{"name":"ping"}],"unicode":"你好"}`)
	m := Manifest{ABI: ABI, World: WorldHTTP, Artifact: Artifact{Kind: KindWasmComponent}, ConfigBase64: base64.StdEncoding.EncodeToString(text)}
	b, e := Build(m, []byte("component"))
	if e != nil {
		t.Fatal(e)
	}
	got, _, e := Parse(b)
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := got.AppConfig()
	if e != nil || !bytes.Equal(cfg, text) {
		t.Fatalf("config mismatch: %v", e)
	}
	m.ConfigBase64 = base64.StdEncoding.EncodeToString([]byte(`{"different":true}`))
	b2, _ := Build(m, []byte("component"))
	if AppID(b) == AppID(b2) {
		t.Fatal("config not measured")
	}
	for _, bad := range []string{"%%%", base64.StdEncoding.EncodeToString([]byte("null")), base64.StdEncoding.EncodeToString([]byte("[]")), base64.StdEncoding.EncodeToString([]byte{0xff}), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), MaxConfigBytes+1))} {
		m.ConfigBase64 = bad
		b, _ := Build(m, []byte("component"))
		if _, _, e := Parse(b); e == nil {
			t.Fatal("invalid config accepted")
		}
	}
	m.ConfigBase64 = base64.StdEncoding.EncodeToString(text)
	m.World = WorldCLI
	m.HTTP = 8080
	if cfg, e := m.AppConfig(); e != nil || !bytes.Equal(cfg, text) {
		t.Fatalf("command config was not preserved: %v", e)
	}
	for _, port := range []int{0, -1, MaxHTTPPort + 1} {
		m.HTTP = port
		if _, e := m.AppConfig(); e == nil {
			t.Fatal("invalid command port admitted")
		}
	}
}

func TestSecretDeploymentBoundManifest(t *testing.T) {
	m := Manifest{World: WorldHTTP, ConfigBase64: "e30=", SecretDeployment: "0x" + strings.Repeat("a", 64)}
	if _, e := m.AppConfig(); e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{"bad", "0x" + strings.Repeat("A", 64)} {
		m.SecretDeployment = id
		if _, e := m.AppConfig(); e == nil {
			t.Fatal("invalid deployment accepted")
		}
	}
	m.SecretDeployment = "0x" + strings.Repeat("a", 64)
	m.ConfigBase64 = ""
	if _, e := m.AppConfig(); e == nil {
		t.Fatal("missing measured config accepted")
	}
}

func TestSecretCommandProtectedPorts(t *testing.T) {
	m := Manifest{ABI: ABI, World: WorldCLI, HTTP: 8000, ConfigBase64: "e30=", SecretDeployment: "0x" + strings.Repeat("a", 64), Ports: []string{"tcp:2222", "udp:47998"}}
	b, err := Build(m, []byte("component"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, err := Parse(b)
	if err != nil || len(parsed.Ports) != 2 {
		t.Fatalf("ports not preserved: %v", err)
	}
	m.Ports[0] = "tcp:2223"
	other, err := Build(m, []byte("component"))
	if err != nil || AppID(other) == AppID(b) {
		t.Fatal("port not bound to app identity")
	}
	m.SecretDeployment = ""
	if _, err := m.AppConfig(); err == nil {
		t.Fatal("configured ports accepted without deployment identity")
	}
}
