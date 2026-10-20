// Package shieldconfig validates env-only secret delivery for the Shield CLI runtime.
package shieldconfig

import (
	"enclave.host/isolation/m2/appconfig"
	"errors"
	"strings"
)

// Native runtime controls may not be changed by an app's WASI environment.
// The CLI inherits only validated names; values never appear in argv.
func Validate(env map[string]string) error {
	if err := appconfig.ValidateSecrets(env); err != nil {
		return errors.New("invalid secret environment")
	}
	for k := range env {
		u := strings.ToUpper(k)
		for _, prefix := range []string{"LD_", "GLIBC_", "GCONV_", "MALLOC_", "RUST_", "WASMTIME_", "GGML_", "SHIELDED_", "SSL_", "OPENSSL_"} {
			if strings.HasPrefix(u, prefix) {
				return errors.New("secret name conflicts with native runtime controls")
			}
		}
		switch u {
		case "HOME", "PATH", "TMPDIR", "TMP", "TEMP", "LOCPATH", "NLSPATH", "LANG", "LANGUAGE", "TZ", "TZDIR":
			return errors.New("secret name conflicts with native runtime controls")
		}
		if strings.HasPrefix(u, "LC_") {
			return errors.New("secret name conflicts with native runtime controls")
		}
	}
	return nil
}
