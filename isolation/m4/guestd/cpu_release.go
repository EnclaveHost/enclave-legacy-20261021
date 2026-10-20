package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
)

// -cpu-release names a complete downloaded release, and the release alone supplies the guest kernel, firmware, command
// line and image template (m4/pinned-domain-env.sh). So no flag may name a second one, and nothing inherited from the
// environment may redirect a build or boot input; either would make the release pin describe a guest guestd never ran.
var cpuReleaseFlagConflicts = []string{"ovmf", "cpu-template", "legacy-isolation", "legacy-isolation-release",
	"shield-template", "shield-release", "shield-model-file", "shield-shm-dir"}

var cpuReleaseEnvConflicts = []string{"DOMAIN_RELEASE_DIR", "DOMAIN_RELEASE_ID", "OVMF_OVERRIDE", "KERNEL_HASHES",
	"APP_IMAGE_TEMPLATE", "SHIELDED_IMAGE_TEMPLATE", "SHIELDED_MODEL_FILE", "SHIELDED_SHM_DIR", "SHIELDED_PAD_BANK_DIR",
	"BUNDLETOOL"}

// cpuReleaseMode checks a -cpu-release start before anything runs: an absolute directory, exactly one explicit release
// pin, no competing flag or inherited override, and component sources the operator chose (the -gateway default is an
// Enclave-operated gateway, which a cold host must not depend on by omission). -> the clean directory and the pin.
func cpuReleaseMode(dir, isoRelease, gateway string, set map[string]bool, getenv func(string) string) (string, string, error) {
	if !filepath.IsAbs(dir) {
		return "", "", errors.New("-cpu-release must be an absolute directory")
	}
	ids, err := parseReleaseIDs(isoRelease)
	if err != nil || len(ids) != 1 {
		return "", "", errors.New("-cpu-release needs exactly one explicit -isolation-release pin")
	}
	for _, f := range cpuReleaseFlagConflicts {
		if set[f] {
			return "", "", fmt.Errorf("-cpu-release supplies every boot input; -%s competes with it", f)
		}
	}
	if !set["gateway"] {
		return "", "", errors.New("-cpu-release needs explicit -gateway component sources (a JSON array of origins)")
	}
	if err := componentGateways(gateway); err != nil {
		return "", "", err
	}
	for _, k := range cpuReleaseEnvConflicts {
		if getenv(k) != "" {
			return "", "", fmt.Errorf("inherited %s would change a pinned build or boot; unset it", k)
		}
	}
	return filepath.Clean(dir), ids[0], nil
}

// componentGateways accepts what wasm/ipfs_fetch.py's gateway_config accepts as an explicit list: one to eight distinct
// http(s) origins with no credentials, query or fragment. Each serves /ipfs/<cid>; every block is verified either way.
func componentGateways(v string) error {
	var list []string
	if json.Unmarshal([]byte(v), &list) != nil || len(list) < 1 || len(list) > 8 {
		return errors.New("-gateway must be a JSON array of one to eight gateway origins")
	}
	seen := map[string]bool{}
	for _, g := range list {
		u, err := url.Parse(g)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil ||
			u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || seen[g] {
			return fmt.Errorf("-gateway: %q is not a distinct http(s) origin without credentials or query", g)
		}
		seen[g] = true
	}
	return nil
}

// cpuReleaseFiles: the boot inputs a verified release must actually contain. The manifest verifier proves the tree is
// exactly what the pin lists; this proves the pin lists a bootable CPU release.
func cpuReleaseFiles(dir string) error {
	for _, f := range []string{"kernel", "firmware.fd", "template/init", "template/front", "template/rt/runtime.json"} {
		st, err := os.Lstat(filepath.Join(dir, f))
		if err != nil || !st.Mode().IsRegular() {
			return fmt.Errorf("CPU release has no regular %s", f)
		}
	}
	return nil
}
