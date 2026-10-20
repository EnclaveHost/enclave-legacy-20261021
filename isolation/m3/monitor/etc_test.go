package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"enclave.host/isolation/m2/shieldconfig"
)

func ownerOf(t *testing.T, p string) (int, os.FileMode) {
	t.Helper()
	st, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return int(st.Sys().(*syscall.Stat_t).Uid), st.Mode()
}

// checkDomainEtc is the layout a secret domain's front and runtime meet (m2/front shield_egress.go): /etc and
// nsswitch.conf the monitor's (root), hosts the front's, and nothing else in /etc.
func checkDomainEtc(t *testing.T, dir string, root, front int) {
	checkDomainEtcMode(t, dir, root, front, false)
}

// checkDomainEtcMode adds the public-web layout: nsswitch.conf also says dns, and resolv.conf (root's, read-only)
// names the front's DNS stub.
func checkDomainEtcMode(t *testing.T, dir string, root, front int, publicWeb bool) {
	t.Helper()
	etc := filepath.Join(dir, "etc")
	if uid, m := ownerOf(t, etc); uid != root || !m.IsDir() || m.Perm() != 0o755 {
		t.Fatalf("etc: uid %d mode %v, want uid %d drwxr-xr-x", uid, m, root)
	}
	ns := filepath.Join(etc, "nsswitch.conf")
	if uid, m := ownerOf(t, ns); uid != root || !m.IsRegular() || m.Perm() != 0o444 {
		t.Fatalf("nsswitch.conf: uid %d mode %v, want uid %d -r--r--r--", uid, m, root)
	}
	wantNS := map[bool]string{false: "hosts: files\n", true: "hosts: files dns\n"}[publicWeb]
	if b, _ := os.ReadFile(ns); string(b) != wantNS {
		t.Fatalf("nsswitch.conf says %q, want %q", b, wantNS)
	}
	rc := filepath.Join(etc, "resolv.conf")
	if publicWeb {
		if uid, m := ownerOf(t, rc); uid != root || !m.IsRegular() || m.Perm() != 0o444 {
			t.Fatalf("resolv.conf: uid %d mode %v, want uid %d -r--r--r--", uid, m, root)
		}
		if b, _ := os.ReadFile(rc); string(b) != shieldconfig.PublicWebResolv ||
			!strings.Contains(string(b), "nameserver 127.0.0.2\n") || !strings.Contains(string(b), "use-vc") {
			t.Fatalf("resolv.conf says %q", b)
		}
	} else if _, err := os.Lstat(rc); !os.IsNotExist(err) {
		t.Fatalf("a domain that is not public-web has a resolv.conf (%v)", err)
	}
	hosts := filepath.Join(etc, "hosts")
	if uid, m := ownerOf(t, hosts); uid != front || !m.IsRegular() || m.Perm() != 0o644 {
		t.Fatalf("hosts: uid %d mode %v, want the front's uid %d -rw-r--r--", uid, m, front)
	}
	if b, _ := os.ReadFile(hosts); string(b) != "127.0.0.1 localhost\n" {
		t.Fatalf("hosts starts as %q", b)
	}
	es, _ := os.ReadDir(etc)
	if want := map[bool]int{false: 2, true: 3}[publicWeb]; len(es) != want {
		t.Fatalf("etc holds %d entries, want %d", len(es), want)
	}
}

// As the test user (not root): the front's uid is the caller's own, so the modes and contents are checked; a chown to
// another uid, which only root may make, FAILS rather than leaving hosts owned by the monitor.
func TestASecretDomainsEtcGivesTheFrontHostsAndNothingElse(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root, TestASecretDomainsEtcUnderRoot checks this with real ownership")
	}
	dir := t.TempDir()
	if err := writeDomainEtc(dir, os.Getuid(), false); err != nil {
		t.Fatal(err)
	}
	checkDomainEtc(t, dir, os.Getuid(), os.Getuid())
	if err := writeDomainEtc(dir, os.Getuid(), false); err == nil {
		t.Fatal("a domain's /etc was laid out over an existing one")
	}
	if err := writeDomainEtc(t.TempDir(), os.Getuid()+1, false); err == nil {
		t.Fatal("hosts could not be given to the front, and the domain was built anyway")
	}
	web := t.TempDir()
	if err := writeDomainEtc(web, os.Getuid(), true); err != nil {
		t.Fatal(err)
	}
	checkDomainEtcMode(t, web, os.Getuid(), os.Getuid(), true)
}

// With real ownership: run as root, which a user namespace gives an ordinary user:
//
//	go test -c -o /tmp/monitor.test ./monitor && unshare --map-root-user --map-auto /tmp/monitor.test -test.run UnderRoot -test.v
//
// (m3/test-domexec-egress.sh runs exactly that). /etc and nsswitch.conf are root's; hosts is the front's uid alone.
func TestASecretDomainsEtcUnderRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (a user namespace's will do); see the comment")
	}
	const front = 1001 // a non-root uid the namespace maps (a front uid in a domain is far higher; ownership is what is checked)
	dir := t.TempDir()
	if err := writeDomainEtc(dir, front, false); err != nil {
		t.Fatal(err)
	}
	checkDomainEtc(t, dir, 0, front)
	web := t.TempDir()
	if err := writeDomainEtc(web, front, true); err != nil {
		t.Fatal(err)
	}
	checkDomainEtcMode(t, web, 0, front, true)
}

// main.go, from its source: only a SECRET domain gets /etc, and its hosts goes to the FRONT's uid, never the runtime's.
func TestOnlyASecretDomainGetsEtcAndTheFrontOwnsHosts(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, `if d.SecretDeployment != "" {`)
	j := strings.Index(src, "writeDomainEtc(d.dir, d.FrontUID, publicWeb)")
	k := strings.Index(src, "if err := writeAppConfig(d.dir, d.AppConfig)")
	if i < 0 || j < 0 || k < 0 || !(i < j && j < k) {
		t.Fatal("main.go no longer lays out /etc inside the secret-deployment branch, for the front's uid")
	}
	if strings.Count(src, "writeDomainEtc(") != 2 { // the call and the definition
		t.Fatal("writeDomainEtc is called from somewhere else too")
	}
	// the mode is the MEASURED config's, decided once, and marks the domain only inside this branch
	if p := strings.Index(src, "publicWeb := shieldconfig.PublicWebMode(string(d.AppConfig))"); p < i || p > j {
		t.Fatal("main.go no longer derives public web from the measured config, inside the secret-deployment branch")
	}
	if m := strings.Index(src, "shieldconfig.PublicWebMarker"); m < j || m > k {
		t.Fatal("main.go no longer writes the public web marker inside the secret-deployment branch")
	}
	for _, mustNot := range []string{"writeDomainEtc(d.dir, d.UID", `os.Chown(hosts, d.UID`} {
		if strings.Contains(src, mustNot) {
			t.Fatalf("main.go gives the RUNTIME's uid the hosts file: %q", mustNot)
		}
	}
}
