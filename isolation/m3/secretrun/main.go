// secretrun waits for the front's authenticated release over an inherited pipe.
// It is measured platform code, quiet, unprivileged, and under the app seccomp filter.
package main

import (
	"enclave.host/isolation/m2/appconfig"
	"enclave.host/isolation/m2/shieldconfig"
	"encoding/json"
	"io"
	"os"
	"sort"
	"syscall"
)

func main() {
	if run() != nil {
		os.Exit(125)
	}
}
func run() error {
	p := os.NewFile(7, "secret-pipe")
	b, e := io.ReadAll(io.LimitReader(p, 65537))
	p.Close()
	if e != nil {
		return e
	}
	if len(b) > 65536 {
		return syscall.E2BIG
	}
	var env map[string]string
	if e = json.Unmarshal(b, &env); e != nil {
		return e
	}
	if e = shieldconfig.Validate(env); e != nil {
		return e
	}
	cfg, e := os.ReadFile("/app.config")
	if e != nil {
		return e
	}
	resolved, e := appconfig.Resolve(string(cfg), env)
	if e != nil {
		return e
	}
	if len(resolved) > appconfig.EnvMaxBytes {
		return syscall.E2BIG
	}
	args := append([]string(nil), os.Args[1:]...)
	if len(args) < 2 || args[0] != "/plat/rt/ld-linux-x86-64.so.2" || args[len(args)-1] != "/app.wasm" {
		return syscall.EINVAL
	}
	// A public-web domain (the monitor's root-owned marker, from the measured config) reaches the internet through
	// the front's SOCKS front: the runtime is told where, as ENCLAVE_EGRESS (ENCLAVE_ names are never a secret's).
	publicWeb, e := shieldconfig.PublicWebMarked(shieldconfig.PublicWebMarker, 0)
	if e != nil {
		return e
	}
	native := []string{"HOME=/tmp", "PATH=/plat", "ENCLAVE_CONFIG=" + resolved}
	names := make([]string, 0, len(env))
	for k := range env {
		names = append(names, k)
	}
	sort.Strings(names)
	artifact := args[len(args)-1]
	args = args[:len(args)-1]
	for _, k := range names {
		native = append(native, k+"="+env[k])
		args = append(args, "--env", k)
	}
	if publicWeb {
		native = append(native, shieldconfig.PublicWebEgressEnv)
		args = append(args, "--env", "ENCLAVE_EGRESS")
	}
	args = append(args, artifact)
	for i := range b {
		b[i] = 0
	}
	return syscall.Exec(args[0], args, native)
}
