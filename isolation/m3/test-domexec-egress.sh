#!/bin/sh
# A NucBox Shield SECRET domain's egress prerequisites, checked for real: domexec, built static, runs as PID 1 of new
# pid/mount/net namespaces in an UNPRIVILEGED user namespace (--map-auto, so its setgroups/setgid/setuid and the sysctl
# write really happen), chrooted into an m3-shaped root (no /dev), with the null device on fd 3, /run the front's (uid
# 1001, 0700), and - for a secret domain - /secret.id, a measured /app.config and /etc laid out as monitor.writeDomainEtc
# lays it out (etc and nsswitch.conf root's, hosts the front's). m3/egress-probe.c stands in for both workloads, as
# /plat/front and as /plat/secretrun (the runtime of a secret domain) or the runtime's loader (a domain without secrets):
#   secret domain: the front, with NO capability, binds 127.64.0.2:443 and 127.64.0.3:443 (domexec lowered THIS
#     namespace's ip_unprivileged_port_start to 443) and rewrites its /etc/hosts; the runtime, which starts only after the
#     front says its listeners are up, has no capability, is filtered, has no AF_VSOCK, reads /etc/hosts and can change
#     nothing in /etc, and cannot take the front's address even with SO_REUSEPORT. Neither can change the floor.
#   domain without secrets: the floor stays 1024 and the front cannot bind 443 (only a secret domain's namespace opens).
# Then the monitor's own /etc layout with real ownership (TestASecretDomainsEtcUnderRoot, as root in a user namespace),
# and mutants of domexec.c, each of which must FAIL: the floor never lowered; the floor lowered for EVERY domain; the
# runtime of a secret domain unfiltered.
#
# usage: test-domexec-egress.sh   (needs gcc, and unshare --map-auto with a subuid range; else SKIPPED. go for the
#        monitor half, else that half is SKIPPED)
set -e
here=$(cd "$(dirname "$0")" && pwd)
m2=$(cd "$here/../m2" && pwd)
d=$(mktemp -d)
trap 'reclaim; rm -rf "$d"' EXIT
# /run and /etc/hosts end up owned by the mapped front uid, which the outer user cannot remove: a fresh user namespace
# with the same --map-auto mapping gives them back to root first
reclaim() { [ -d "$d/root" ] && unshare --map-root-user --map-auto sh -c "chown -R 0:0 '$d/root'; chmod -R u+rwx '$d/root'" 2>/dev/null; rm -rf "$d/root"; }
chmod 0755 "$d"
if ! command -v unshare >/dev/null 2>&1 || ! unshare --map-root-user --map-auto -U true 2>/dev/null; then
  echo "domexec egress: SKIPPED, no unshare --map-auto here"; exit 0
fi
gcc -static -O2 -o "$d/probe" "$here/egress-probe.c" 2>/dev/null

run_one() {  # <domexec binary> <secret: 1|0> [mode] [public web marker: 1|0]
  reclaim; mkdir -p "$d/root/plat/rt" "$d/root/run" "$d/root/tmp" "$d/root/proc" "$d/root/probe-out"
  chmod 0755 "$d/root" "$d/root/plat" "$d/root/plat/rt"; chmod 1777 "$d/root/probe-out"
  cp "$1" "$d/root/plat/domexec"
  for p in front secretrun rt/ld-linux-x86-64.so.2; do cp "$d/probe" "$d/root/plat/$p"; chmod 0755 "$d/root/plat/$p"; done
  chmod 0755 "$d/root/plat/domexec"
  own_hosts=""
  if [ "$2" = 1 ]; then
    printf '0x%s' "$(printf 'a7%.0s' $(seq 1 32))" > "$d/root/secret.id"; chmod 0444 "$d/root/secret.id"
    printf '{"bucket":"jot-notes","endpoint":"$R2_ENDPOINT"}' > "$d/root/app.config"; chmod 0444 "$d/root/app.config"
    mkdir "$d/root/etc"; chmod 0755 "$d/root/etc"
    printf 'hosts: files\n' > "$d/root/etc/nsswitch.conf"; chmod 0444 "$d/root/etc/nsswitch.conf"
    printf '127.0.0.1 localhost\n' > "$d/root/etc/hosts"; chmod 0644 "$d/root/etc/hosts"
    own_hosts="chown 1001:1001 '$d/root/etc/hosts' &&"
  fi
  if [ "${4:-0}" = 1 ]; then   # as monitor.writeDomainEtc and the marker lay out a public-web domain
    printf '1\n' > "$d/root/egress.public-web"; chmod 0444 "$d/root/egress.public-web"
    if [ -d "$d/root/etc" ]; then
      chmod 0644 "$d/root/etc/nsswitch.conf"; printf 'hosts: files dns\n' > "$d/root/etc/nsswitch.conf"; chmod 0444 "$d/root/etc/nsswitch.conf"
      printf 'nameserver 127.0.0.2\noptions use-vc timeout:10 attempts:2\n' > "$d/root/etc/resolv.conf"; chmod 0444 "$d/root/etc/resolv.conf"
    fi
  fi
  mode=${3:-app}
  timeout 60 unshare --map-root-user --map-auto -mpfn -- sh -c "chown 1001:1001 '$d/root/run' && chmod 0700 '$d/root/run' && $own_hosts exec chroot '$d/root' /plat/domexec 7 1000:1001 $mode 64 8000 3<>/dev/null" > "$d/console.txt" 2>&1 || true
}
report_ok() {  # <role> -> 0 if its report is clean
  f="$d/root/probe-out/$1.egress"
  [ -s "$f" ] && ! grep -q '^BAD' "$f" && grep -qE '^done ok=[0-9]+ bad=0$' "$f"
}
show() {  # <role>
  f="$d/root/probe-out/$1.egress"
  if [ -s "$f" ]; then grep -E '^BAD|^done|^uid' "$f" | tr '\n' ' '; else echo "no report; console: $(tr '\n' ' ' < "$d/console.txt" | cut -c1-240)"; fi
}
run_all() {  # <domexec.c>
  mkdir -p "$d/b/m3" "$d/b/m2" && cp "$1" "$d/b/m3/domexec.c" && cp "$m2/app-seccomp.h" "$m2/sha256-min.h" "$d/b/m2/"
  gcc -static -O2 -o "$d/domexec" "$d/b/m3/domexec.c" 2>/dev/null || { echo "FAIL domexec did not build"; return 1; }
  rc=0
  run_one "$d/domexec" 1
  for role in front runtime; do
    if report_ok $role; then echo "ok   secret domain, the $role from inside: $(grep -c '^ok' "$d/root/probe-out/$role.egress") checks: $(grep '^ok' "$d/root/probe-out/$role.egress" | cut -d: -f1 | sed 's/^ok  *//' | tr '\n' ';' | cut -c1-260)"
    else echo "FAIL secret domain, the $role from inside: $(show $role)"; rc=1; fi
  done
  grep -q '^uid=1001 secret=1 web=0$' "$d/root/probe-out/front.egress" 2>/dev/null && grep -q '^uid=1000 secret=1 web=0$' "$d/root/probe-out/runtime.egress" 2>/dev/null \
    && echo "ok   the front ran as 1001 and the runtime (/plat/secretrun) as 1000" || { echo "FAIL the uids: $(head -1 "$d/root/probe-out/front.egress" 2>/dev/null) / $(head -1 "$d/root/probe-out/runtime.egress" 2>/dev/null)"; rc=1; }
  if grep -q "^DOM7 egress: this namespace's unprivileged port floor is 443" "$d/console.txt"; then echo "ok   domexec stated the floor on the console"
  else echo "FAIL no floor statement on the console: $(tr '\n' ' ' < "$d/console.txt" | cut -c1-200)"; rc=1; fi
  run_one "$d/domexec" 1 run
  for role in front runtime; do
    if report_ok $role; then echo "ok   secret command domain, the $role: $(grep -c '^ok' "$d/root/probe-out/$role.egress") checks"
    else echo "FAIL secret command domain, the $role: $(show $role)"; rc=1; fi
  done
  grep -q 'mode=run http=8000' "$d/console.txt" || { echo "FAIL command mode did not launch"; rc=1; }
  run_one "$d/domexec" 1 run 1   # risc-box's shape: a public-web secret command domain
  for role in front runtime; do
    if report_ok $role && grep -q 'web=1' "$d/root/probe-out/$role.egress"; then echo "ok   public-web command domain, the $role: $(grep -c '^ok' "$d/root/probe-out/$role.egress") checks"
    else echo "FAIL public-web command domain, the $role: $(show $role)"; rc=1; fi
  done
  if grep -q "^DOM7 egress: this namespace's unprivileged port floor is 53" "$d/console.txt"; then echo "ok   domexec stated the public-web floor"
  else echo "FAIL no public-web floor statement: $(tr '\n' ' ' < "$d/console.txt" | cut -c1-200)"; rc=1; fi
  run_one "$d/domexec" 0 app 1   # a marker on a domain without secrets: domexec refuses to start it
  if grep -q "public web needs a secret domain" "$d/console.txt" && [ ! -s "$d/root/probe-out/front.egress" ]; then echo "ok   a public-web marker without secrets starts nothing"
  else echo "FAIL a public-web marker without secrets: $(tr '\n' ' ' < "$d/console.txt" | cut -c1-200)"; rc=1; fi
  run_one "$d/domexec" 0
  if report_ok front; then echo "ok   a domain without secrets: $(grep '^ok' "$d/root/probe-out/front.egress" | cut -d: -f1 | sed 's/^ok  *//' | tr '\n' ';')"
  else echo "FAIL a domain without secrets, the front: $(show front)"; rc=1; fi
  if report_ok runtime; then echo "ok   a domain without secrets, the runtime: filtered, no AF_VSOCK, no capability"
  else echo "FAIL a domain without secrets, the runtime: $(show runtime)"; rc=1; fi
  return $rc
}

set +e
run_all "$here/domexec.c"; g=$?
[ $g = 0 ] && echo "domexec egress: PASS" || echo "domexec egress: FAIL"

# the monitor's /etc with real ownership (as root in a user namespace)
mon=0
if command -v go >/dev/null 2>&1; then
  if (cd "$here" && go test -c -o "$d/monitor.test" ./monitor >/dev/null 2>&1); then
    out=$(cd "$here/monitor" && unshare --map-root-user --map-auto "$d/monitor.test" -test.run 'TestASecretDomainsEtcUnderRoot' -test.v 2>&1)
    if echo "$out" | grep -q -- '--- PASS: TestASecretDomainsEtcUnderRoot'; then echo "ok   monitor.writeDomainEtc as root: etc and nsswitch.conf uid 0, hosts the front's uid, modes 0755/0444/0644"
    else echo "FAIL monitor.writeDomainEtc as root: $(echo "$out" | tr '\n' ' ' | cut -c1-240)"; mon=1; fi
  else echo "FAIL the monitor test binary did not build"; mon=1; fi
else echo "monitor /etc as root: SKIPPED, no go here"; fi

mut() {  # <label> <sed expression>
  sed "$2" "$here/domexec.c" > "$d/mutant.c"
  if cmp -s "$d/mutant.c" "$here/domexec.c"; then echo "FAIL mutant $1: the edit did not apply"; return 1; fi
  if run_all "$d/mutant.c" > "$d/mutant.log" 2>&1; then echo "FAIL mutant $1 SURVIVED"; return 1; fi
  echo "ok   mutant $1 killed: $(grep -m1 '^FAIL' "$d/mutant.log" | cut -c1-200)"
}
k=0
mut "the floor never lowered" '/unprivileged_https_bind(public_web);   \/\* the front/d' || k=1
mut "the floor lowered for every domain" 's/^    lo_up();$/    lo_up(); unprivileged_https_bind(0);/' || k=1
mut "public web keeps the 443 floor" 's/const char \*floor = public_web ? "53\\n" : "443\\n";/const char *floor = "443\\n";/' || k=1
mut "the 53 floor for every secret domain" 's/const char \*floor = public_web ? "53\\n" : "443\\n";/const char *floor = "53\\n";/' || k=1
mut "public web without secrets" '/public web needs a secret domain/d' || k=1
mut "a secret domain's runtime unfiltered" 's/rt_pid = spawn(secret_pipe\[0\]>=0 ? secret_app : shield_app, uid, 1, 1);/rt_pid = spawn(secret_pipe[0]>=0 ? secret_app : shield_app, uid, 1, 0);/' || k=1
[ $k = 0 ] && echo "domexec egress mutants: all killed" || echo "domexec egress mutants: FAIL"
[ $g = 0 ] && [ $mon = 0 ] && [ $k = 0 ]
