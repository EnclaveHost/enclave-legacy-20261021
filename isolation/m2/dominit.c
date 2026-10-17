/* PID 1 of an M2 app domain (isolation/DESIGN.md section 10): M1's domain, now serving.
 *
 * The domain holds exactly one app and exposes exactly one port. This init:
 *   1. loads the vsock transport (the domain has no NIC: vsock to the host is its only channel) and,
 *      under SEV-SNP, the report interface;
 *   2. brings up loopback and starts /front, which mints the domain's TLS key in guest memory, terminates TLS on
 *      vsock port 443, serves the attestation document binding that key, and proxies everything else to the app;
 *   3. waits for the front's ONE message on the pipe it gave it (fd 3): "N" (no config) or "C" + the app's config.
 *      For a guest that serves a deployment, the front sends it only after the attested release has delivered the
 *      owner's config and secrets and the egress forwarders are up (front/provision.go); an empty pipe means the
 *      front died first, and the domain powers off rather than start an app without the config it should have;
 *   4. starts the app natively under `wasmtime serve` on 127.0.0.1:8080 (the runtime JIT-compiles it inside this
 *      guest, as in M1), with ENCLAVE_CONFIG when there is one. The app's stdin, stdout and stderr are /dev/null:
 *      this process's own are the serial console, a file the HOST reads, so anything the app or its runtime prints
 *      (a request it logs, its config, a panic, a trap) would otherwise reach the host. This tier has no owner-only
 *      log channel, so the app's output is discarded, not kept (Codex, 2026-09-25). Only init's and the front's own
 *      "DOM ..." lines reach the console. The app runs UNPRIVILEGED (APP_UID, drop_to_app): not root, no capability,
 *      no supplementary group, no_new_privs. Before this, the runtime ran as root beside the root front, so an escape
 *      from it reached everything in the guest: the front's key and memory, the console, the report interface
 *      (enclave-b4's finding on 298924ae; enclave-87's ruling). The front stays root;
 *   5. if either exits, powers the domain off: a domain that cannot serve should not linger.
 * Before any of it, the domain starts only with Yama's ptrace_scope held at 2 (defence in depth on top of the drop, the
 * NucBox monitor's rule, m3/monitor raisePtraceScope), user namespaces off and io_uring off (sysctl_hold).
 * The host ends a serving domain by stopping its VMM (lease end). */
#define _GNU_SOURCE
#include <cpuid.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <grp.h>
#include <limits.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "app-seccomp.h"   /* the app runtime's seccomp filter, shared with m3/domexec.c */

/* The app's own uid and gid: nobody else in the guest has them (the front and init are root). The image's files are
 * 0644/0755 root (m4/pack-initrd.sh), so the app can read /app.wasm and run /rt, and nothing else is its own but /data
 * and what it makes in /tmp. */
#define APP_UID 1000
#define APP_GID 1000

/* One integer from a /proc/sys file: 0 on success, -1 unreadable (errno says why), -2 not exactly one integer. */
static int read_sysctl_int(const char *path, int *v) {
    char b[32];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, b, sizeof b - 1);
    int e = errno;
    close(fd);
    if (n < 0) { errno = e; return -1; }
    b[n] = 0;
    char *end;
    errno = 0;
    long x = strtol(b, &end, 10);
    if (end == b || errno) return -2;
    while (*end == '\n' || *end == ' ') end++;
    if (*end || x < INT_MIN || x > INT_MAX) return -2;
    *v = (int)x;
    return 0;
}

/* Write a string to a /proc/sys file, replacing its value (O_TRUNC, as a shell's `>` does): 0, or -1 with errno. */
static int write_sysctl(const char *path, const char *s) {
    int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t n = strlen(s);
    ssize_t r = write(fd, s, n);
    int e = errno;
    close(fd);
    if (r != (ssize_t)n) { errno = r < 0 ? e : EIO; return -1; }
    return 0;
}

/* The kernel settings a domain starts only with, each SET and READ BACK (enclave-87's rulings on enclave-b4's and
 * enclave-bf's reviews of this file). -> 1 when the value read back is on the right side of `want` (at least it, or with
 * at_least 0 at most it), else 0: the sysctl absent, its value unparsable, the write refused, or the read-back wrong or
 * unreadable. A value already on the right side is kept and never written (Yama's 3 is not lowered to 2). `line` says
 * which, as the DOM line. `wr` is the write, passed in so a test can make one that "succeeds" and changes nothing: only
 * the read-back catches that.
 *   - kernel.yama.ptrace_scope >= 2: only CAP_SYS_PTRACE may attach (not 3, which nothing can lower before a reboot).
 *     The app, dropped to APP_UID, cannot attach to the root front anyway; Yama is the second guard.
 *   - user.max_user_namespaces <= 0: the app (no capability, no_new_privs) could otherwise unshare(CLONE_NEWUSER) and
 *     hold every capability inside its own namespace, the usual first step of a kernel privilege escalation (bf).
 *   - kernel.io_uring_disabled >= 2: io_uring is off for every process (the kernel is built with it; bf).
 * Nothing in the guest needs the last two: dominit creates no namespace after the kernel's own and uses no io_uring;
 * the front is Go, whose network poller is epoll; wasmtime serves and runs through tokio/mio, also epoll, and creates
 * no namespace. */
#define YAMA_PATH "/proc/sys/kernel/yama/ptrace_scope"
#define YAMA_WANT 2
static const char hold_refused[] = "the domain is not started";
static int sysctl_hold(const char *name, const char *path, int want, int at_least, int (*wr)(const char *, const char *),
                       char *line, size_t cap) {
    int was, now, r = read_sysctl_int(path, &was);
    if (r == -1) { snprintf(line, cap, "%s absent (%s: %s): %s", name, path, strerror(errno), hold_refused); return 0; }
    if (r == -2) { snprintf(line, cap, "%s unparsable: %s", name, hold_refused); return 0; }
    if (at_least ? was >= want : was <= want) {
        snprintf(line, cap, "%s=%d (already %s %d)", name, was, at_least ? ">=" : "<=", want);
        return 1;
    }
    char v[16];
    snprintf(v, sizeof v, "%d\n", want);
    if (wr(path, v) != 0) {
        snprintf(line, cap, "%s=%d, NOT set to %d (%s): %s", name, was, want, strerror(errno), hold_refused);
        return 0;
    }
    r = read_sysctl_int(path, &now);
    if (r == -1) { snprintf(line, cap, "%s=%d -> unreadable (%s): %s", name, was, strerror(errno), hold_refused); return 0; }
    if (r == -2 || (at_least ? now < want : now > want)) {
        snprintf(line, cap, "%s=%d -> not the %d asked: %s", name, was, want, hold_refused);
        return 0;
    }
    snprintf(line, cap, "%s=%d -> %d", name, was, now);
    return 1;
}

/* A run-mode app binds the port its bundle names (1-49999) as APP_UID, and binding below the kernel's
 * ip_unprivileged_port_start (1024 by default) needs a capability it no longer has. So only when its port is below it,
 * the start is lowered to EXACTLY that port (not 0: nothing below it becomes bindable), and read back. Every port from
 * it up then becomes bindable to the app, 443 included; that is harmless here: the front's forwarders already hold their
 * 127.64.x.y:443 before the app starts, its listener audit runs before the app, and nothing but the app dials loopback
 * (enclave-5d). A port at or above the start changes nothing. -> 1 when the app can bind its port, else 0; `line` says
 * what was done or why not. */
static int unpriv_port(int port, const char *path, int (*wr)(const char *, const char *), char *line, size_t cap) {
    int start, now, r = read_sysctl_int(path, &start);
    if (r != 0) { snprintf(line, cap, "ip_unprivileged_port_start unreadable: the app could not bind port %d", port); return 0; }
    if (port >= start) {
        snprintf(line, cap, "app port %d >= ip_unprivileged_port_start %d: unchanged", port, start);
        return 1;
    }
    char v[16];
    snprintf(v, sizeof v, "%d\n", port);
    if (wr(path, v) != 0 || read_sysctl_int(path, &now) != 0 || now > port) {
        snprintf(line, cap, "ip_unprivileged_port_start %d could not be lowered to the app's port %d", start, port);
        return 0;
    }
    snprintf(line, cap, "ip_unprivileged_port_start %d -> %d (the app's port %d; nothing below it)", start, now, port);
    return 1;
}

/* The drop, in the app's child while it is still root. The bounding set goes first (dropping from it needs
 * CAP_SETPCAP), then the ambient set, the supplementary groups, the gid and the uid (real, effective and saved: the
 * uid change clears the permitted, effective and ambient sets, but NOT the inheritable one, hence the capset), then
 * no_new_privs. Then every part is checked back from here. -> NULL, or the step that failed or did not hold.
 * Not root, the app is now bound by RLIMIT_NPROC (root was exempt): the kernel's default, threads-max/2, scales with the
 * guest's RAM; a small guest that shows "Resource temporarily unavailable" spawning threads is this (enclave-5d). */
static const char *drop_to_app(void) {
    for (int c = 0; c < 64; c++)
        if (prctl(PR_CAPBSET_DROP, c, 0, 0, 0) != 0) { if (errno == EINVAL) break; return "PR_CAPBSET_DROP"; }
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 && errno != EINVAL) return "PR_CAP_AMBIENT_CLEAR_ALL";
    if (setgroups(0, NULL) != 0) return "setgroups";
    if (setresgid(APP_GID, APP_GID, APP_GID) != 0) return "setresgid";
    if (setresuid(APP_UID, APP_UID, APP_UID) != 0) return "setresuid";
    struct { uint32_t version; int pid; } h = { 0x20080522 /* _LINUX_CAPABILITY_VERSION_3 */, 0 };
    struct { uint32_t effective, permitted, inheritable; } caps[2];
    memset(caps, 0, sizeof caps);
    if (syscall(SYS_capset, &h, caps) != 0) return "capset";
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return "PR_SET_NO_NEW_PRIVS";

    uid_t ru, eu, su;
    gid_t rg, eg, sg;
    if (getresuid(&ru, &eu, &su) != 0 || ru != APP_UID || eu != APP_UID || su != APP_UID) return "the uid did not hold";
    if (getresgid(&rg, &eg, &sg) != 0 || rg != APP_GID || eg != APP_GID || sg != APP_GID) return "the gid did not hold";
    if (getgroups(0, NULL) != 0) return "a supplementary group remains";
    if (setuid(0) == 0 || setgid(0) == 0) return "uid or gid 0 could be taken back";
    memset(caps, 0xff, sizeof caps);
    h.version = 0x20080522;
    h.pid = 0;
    if (syscall(SYS_capget, &h, caps) != 0) return "capget";
    for (int i = 0; i < 2; i++)
        if (caps[i].effective || caps[i].permitted || caps[i].inheritable) return "a capability remains";
    for (int c = 0; c < 64; c++) {
        int b = prctl(PR_CAPBSET_READ, c, 0, 0, 0);
        if (b < 0) break;
        if (b) return "the bounding set is not empty";
    }
    for (int c = 0; c < 64; c++) {
        int a = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, c, 0, 0);
        if (a < 0) break;
        if (a) return "an ambient capability remains";
    }
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return "no_new_privs is not set";
    return NULL;
}

/* What the dropped app must NOT be able to open (enclave-87): the console the host reads (and /dev/kmsg, which writes
 * to it), the SNP report interface (the device and configfs-tsm: with it the app could have a report made over bytes of
 * its choosing), raw memory, and the memory and descriptors of init and the front. Tried from the dropped child itself,
 * at every start, so the answer is this guest's own device modes, not an assumption about them; an absent path is
 * fine. -> NULL, or what could be opened. */
static pid_t front_pid_g = -1;
/* the tables, as pointers so the test harness (which includes this file) can aim one at a path the dropped uid CAN open
 * and see the check refuse it; the guest never changes them */
static const char *const reach_write_default[] = {"/dev/console", "/dev/ttyS0", "/dev/hvc0", "/dev/kmsg", NULL};
static const char *const reach_rw_default[] = {"/dev/sev-guest", "/dev/mem", NULL};
static const char *const *reach_write = reach_write_default;
static const char *const *reach_rw = reach_rw_default;
static const char *reach_tsm = "/sys/kernel/config/tsm/report";
static const char *app_reaches(void) {
    static char p[600];
    for (int i = 0; reach_write[i]; i++) {
        int fd = open(reach_write[i], O_WRONLY | O_NOCTTY | O_CLOEXEC);
        if (fd >= 0) { close(fd); return reach_write[i]; }
    }
    for (int i = 0; reach_rw[i]; i++) {
        int fd = open(reach_rw[i], O_RDWR | O_CLOEXEC);
        if (fd >= 0) { close(fd); return reach_rw[i]; }
    }
    snprintf(p, sizeof p, "%s/app-probe", reach_tsm);
    if (mkdir(p, 0700) == 0) {
        rmdir(p);
        snprintf(p, sizeof p, "%s (a report entry)", reach_tsm);
        return p;
    }
    pid_t who[] = {1, front_pid_g};
    static const char *const what[] = {"mem", "environ", "fd/1", NULL};
    for (int i = 0; i < 2; i++) {
        if (who[i] <= 0) continue;
        for (int j = 0; what[j]; j++) {
            snprintf(p, sizeof p, "/proc/%d/%s", (int)who[i], what[j]);
            int fd = open(p, O_RDONLY | O_CLOEXEC);
            if (fd >= 0) { close(fd); return p; }
        }
    }
    return NULL;
}

static void insmod(const char *p) {
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { printf("DOM insmod %s: %s\n", p, strerror(errno)); return; }
    long r = syscall(SYS_finit_module, fd, "", 4 /* MODULE_INIT_COMPRESSED_FILE */);
    if (r != 0 && errno != EEXIST) printf("DOM insmod %s failed: %s\n", p, strerror(errno));
    close(fd);
}

/* the kernel gives lo 127.0.0.1/8 itself once it is up */
static void lo_up(void) {
    struct ifreq ifr = {0};
    strcpy(ifr.ifr_name, "lo");
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0 || ioctl(s, SIOCGIFFLAGS, &ifr) < 0) { printf("DOM ERROR lo: %s\n", strerror(errno)); return; }
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) printf("DOM ERROR lo up: %s\n", strerror(errno));
    close(s);
}

/* extra: one more environment entry or NULL; fd3: a descriptor the child gets as fd 3, or -1. flags:
 *   SPAWN_QUIET  the child's stdin, stdout and stderr are /dev/null (tenant code: nothing it prints reaches the host's
 *                serial file). A quiet child keeps a close-on-exec copy of the console only to report its OWN exec
 *                failure, and one that cannot open /dev/null exits 126 rather than run with the console;
 *   SPAWN_DROP   the child becomes APP_UID (drop_to_app) and checks it can reach nothing it must not (app_reaches);
 *   SPAWN_FILTER the child installs app-seccomp.h's filter last, right before exec (it needs the drop's no_new_privs).
 * A drop, reach or filter failure exits 125, so the app never starts privileged or unfiltered, and the domain powers
 * off as for any app exit. The app gets all three; the front none. */
#define SPAWN_QUIET 1
#define SPAWN_DROP 2
#define SPAWN_FILTER 4
/* The seccomp STATEMENT channel (enclave-87: positive evidence that the filter is on): a close-on-exec pipe made just
 * before the app is spawned (so the front, already running, never holds it). The app's child writes app-seccomp.h's
 * statement to it once the filter is installed, before exec, and exec closes it: nothing the app runs can write it. */
static int seccomp_status_fd = -1;
#ifndef SECCOMP_DIR
#define SECCOMP_DIR "/run/enclave"                  /* root-only (0700): what the front reads into the attested self-test */
#endif
#define SECCOMP_STATEMENT SECCOMP_DIR "/seccomp"
/* Read the app child's seccomp statement (to EOF: its exec, or its exit on a failure, closes the other end). A valid one
 * is printed - the positive line - and written, root-only, where the front reads it into every attested self-test; none
 * means the child failed before exec (it has said why, exits 125, and the domain ends).
 * BOUNDED (enclave-5d's N1, enclave-87: required): this is PID 1, so a child that neither writes nor reaches exec within
 * SECCOMP_STATEMENT_MS must not hang the boot. It is killed, the console says so, and PID 1's wait loop sees the app end
 * and ends the domain - it never serves (fail closed). */
#ifndef SECCOMP_STATEMENT_MS
#define SECCOMP_STATEMENT_MS 10000
#endif
static void seccomp_statement_from(int fd, pid_t child) {
    char st[160];
    size_t got = 0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long left = SECCOMP_STATEMENT_MS - ((t1.tv_sec - t0.tv_sec) * 1000L + (t1.tv_nsec - t0.tv_nsec) / 1000000L);
        struct pollfd p = {.fd = fd, .events = POLLIN};
        int r = left > 0 ? poll(&p, 1, (int)left) : 0;
        if (r < 0 && errno == EINTR) continue;
        if (r == 0) {
            if (got) printf("DOM ERROR the app held init's seccomp statement pipe past its exec (no EOF within %d ms): killed, not started\n", SECCOMP_STATEMENT_MS);
            else printf("DOM ERROR the app gave no seccomp statement within %d ms: killed, not started\n", SECCOMP_STATEMENT_MS);
            if (child > 0) kill(child, SIGKILL);
            return;
        }
        if (r < 0) break;
        ssize_t n = read(fd, st + got, sizeof st - 1 - got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        got += (size_t)n;
        if (got == sizeof st - 1) break;
    }
    st[got] = 0;
    char hex[65];
    unsigned rules = 0;
    if (sscanf(st, "seccomp sha256=%64[0-9a-f] rules=%u", hex, &rules) != 2 || strlen(hex) != 64 || got == 0 || st[got - 1] != '\n') {
        if (got) printf("DOM ERROR the app's seccomp statement is malformed: the self-test will state none\n");
        return;
    }
    printf("DOM seccomp: app filter installed (sha256 %s, %u rules)\n", hex, rules);
    if (strncmp(SECCOMP_DIR, "/run/", 5) == 0) mkdir("/run", 0755);
    mkdir(SECCOMP_DIR, 0700);
    int w = open(SECCOMP_STATEMENT ".tmp", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (w < 0 || write(w, st, got) != (ssize_t)got || close(w) != 0 || rename(SECCOMP_STATEMENT ".tmp", SECCOMP_STATEMENT) != 0)
        printf("DOM ERROR could not record the app's seccomp statement for the front: %s\n", strerror(errno));
}

static pid_t spawn(char *const argv[], char *extra, int fd3, int flags);
/* The app, through the seccomp statement channel: a close-on-exec pipe made here (the front, already running, never
 * holds it), handed to the child, and read to EOF - until the child's exec closes its end - so the positive line and the
 * front's statement come from init once the filter is on. -> the app's pid, or -2 when no pipe could be made. */
static pid_t spawn_app(char *const argv[], char *extra, int flags) {
    int sfd[2];
    if (pipe2(sfd, O_CLOEXEC) != 0) {
        printf("DOM ERROR pipe: %s\n", strerror(errno));
        return -2;
    }
    seccomp_status_fd = sfd[1];
    pid_t pid = spawn(argv, extra, -1, flags);
    close(sfd[1]);
    seccomp_status_fd = -1;
    seccomp_statement_from(sfd[0], pid);
    close(sfd[0]);
    return pid;
}

static pid_t spawn(char *const argv[], char *extra, int fd3, int flags) {
    const int quiet = flags & SPAWN_QUIET, drop = flags & SPAWN_DROP;
    pid_t pid = fork();
    if (pid == 0) {
        if (fd3 == 3) fcntl(3, F_SETFD, 0);                      /* already fd 3: only drop CLOEXEC */
        else if (fd3 >= 0 && dup2(fd3, 3) < 0) _exit(127);       /* dup2 leaves the new fd 3 without CLOEXEC */
        int con = 1;
        if (quiet) {
            con = fcntl(1, F_DUPFD_CLOEXEC, 10);
            int nul = open("/dev/null", O_RDWR);
            if (nul < 0 || dup2(nul, 0) < 0 || dup2(nul, 1) < 0 || dup2(nul, 2) < 0) _exit(126);
            if (nul > 2) close(nul);
        }
        if (drop) {
            const char *bad = drop_to_app();
            if (bad) {
                if (con >= 0) dprintf(con, "DOM ERROR the app's privilege drop failed (%s: %s): not started\n", bad, strerror(errno));
                _exit(125);
            }
            const char *reach = app_reaches();
            if (reach) {
                if (con >= 0) dprintf(con, "DOM ERROR the app could still open %s after its privilege drop: not started\n", reach);
                _exit(125);
            }
        }
        if ((flags & SPAWN_FILTER) && app_seccomp_install() != 0) {
            if (con >= 0) dprintf(con, "DOM ERROR the app's seccomp filter could not be installed (%s): not started\n", strerror(errno));
            _exit(125);
        }
        if ((flags & SPAWN_FILTER) && seccomp_status_fd >= 0) {   /* the filter is on: say which, to init, before exec */
            char st[160];
            int n = app_seccomp_statement(st, sizeof st);
            if (n < 0 || write(seccomp_status_fd, st, (size_t)n) != n) {
                if (con >= 0) dprintf(con, "DOM ERROR the app's seccomp statement could not be written: not started\n");
                _exit(125);
            }
        }
        char *envp[] = {"HOME=/tmp", "PATH=/rt", extra, NULL};
        execve(argv[0], argv, envp);
        if (con >= 0) dprintf(con, "DOM ERROR exec %s: %s\n", argv[0], strerror(errno));
        _exit(127);
    }
    return pid;
}

/* The front's one message on the pipe: "N" (no config), or "C" + the app's config, at most the standard runtime's
 * ENCLAVE_CONFIG ceiling (64 KiB), then EOF. On "C" *env is a malloc'd "ENCLAVE_CONFIG=<config>" and *len the config's
 * length; on "N" *env stays NULL. Anything else - an empty pipe (the front died first), one byte over the ceiling, a
 * NUL, another tag - returns why, and the caller does not start the app. The read buffer is wiped either way. */
#define CFG_MAX 65536
static const char *read_front_msg(int fd, char **env, size_t *len) {
    static char msg[1 + CFG_MAX + 1];
    static const char pre[] = "ENCLAVE_CONFIG=";
    size_t n = 0;
    const char *why = NULL;
    for (;;) {
        ssize_t r = read(fd, msg + n, sizeof msg - n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        n += (size_t)r;
        if (n == sizeof msg) break;
    }
    *env = NULL;
    *len = 0;
    if (n == 0) why = "ended before it handed over the app's config";
    else if (n == 1 && msg[0] == 'N') why = NULL;
    else if (msg[0] != 'C' || n < 2) why = "sent no valid config message";
    else if (n == sizeof msg) why = "sent a config over the 64 KiB ENCLAVE_CONFIG ceiling";
    else if (memchr(msg + 1, 0, n - 1)) why = "sent a config with a NUL byte";
    else {
        *len = n - 1;
        *env = malloc(sizeof pre + *len);
        if (!*env) why = "sent a config there was no memory for";
        else {
            memcpy(*env, pre, sizeof pre - 1);
            memcpy(*env + sizeof pre - 1, msg + 1, *len);
            (*env)[sizeof pre - 1 + *len] = 0;
        }
    }
    explicit_bzero(msg, n);
    return why;
}

static double now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

int main(void) {
    mount("proc", "/proc", "proc", 0, 0);
    mount("sysfs", "/sys", "sysfs", 0, 0);
    mount("devtmpfs", "/dev", "devtmpfs", 0, 0);
    mount("tmpfs", "/tmp", "tmpfs", 0, "size=64m");
    mount("configfs", "/sys/kernel/config", "configfs", 0, 0);
    double boot_ms = now_ms();   /* monotonic since guest boot: how long the kernel took to reach us */

    unsigned a, b, c, d;
    __cpuid(0x8000001f, a, b, c, d);
    int snp = (a >> 4) & 1;      /* SNP active for THIS guest (the CPUID table under SNP is the PSP's) */
    struct sysinfo si;
    sysinfo(&si);
    printf("\nDOM snp=%d vcpus=%ld memMiB=%lu boot_ms=%.0f\n", snp, sysconf(_SC_NPROCESSORS_ONLN),
           (unsigned long)(si.totalram * si.mem_unit >> 20), boot_ms);

    /* the kernel settings the domain starts only with (sysctl_hold): before the front (and so before its key) and
     * before the app. Any one not held powers the domain off. */
    static const struct { const char *name, *path; int want, at_least; } holds[] = {
        {"yama ptrace_scope", YAMA_PATH, YAMA_WANT, 1},
        {"user.max_user_namespaces", "/proc/sys/user/max_user_namespaces", 0, 0},
        {"kernel.io_uring_disabled", "/proc/sys/kernel/io_uring_disabled", 2, 1},
    };
    for (size_t i = 0; i < sizeof holds / sizeof holds[0]; i++) {
        char hl[256];
        int held = sysctl_hold(holds[i].name, holds[i].path, holds[i].want, holds[i].at_least, write_sysctl, hl, sizeof hl);
        printf("DOM %s\n", hl);
        if (!held) {
            printf("DOM ERROR refusing to start: %s\n", hl);
            fflush(stdout);
            sync();
            reboot(RB_POWER_OFF);
            _exit(1);
        }
    }

    insmod("/vsock.ko.zst");
    insmod("/vmw_vsock_virtio_transport_common.ko.zst");
    insmod("/vmw_vsock_virtio_transport.ko.zst");
    if (snp) {
        insmod("/tsm_report.ko.zst");
        insmod("/sev-guest.ko.zst");
    }
    lo_up();

    /* -C cache=n: the runtime compiles the verified component INSIDE this domain every time, and keeps no
     * compiled artifact anywhere. wasmtime's module cache is ON by default (it writes under
     * $HOME/.cache/wasmtime), and a compiled cache is only admissible under the portable-runtime contract
     * if it is keyed by bundle hash + runtime identity AND authenticated (isolation/contract/RUNTIME.md
     * rule 5, contract.CacheKey). We hold no such cache, so the domain states cache: "none" in its runtime
     * identity - and this flag is what makes that statement true by construction rather than by the
     * accident of HOME being unset in the guest. */
    char *serve[] = {"/rt/ld-linux-x86-64.so.2", "--library-path", "/rt", "/rt/wasmtime", "serve", "-S", "cli",
                     "-C", "cache=n", "--addr", "127.0.0.1:8080", "/app.wasm", NULL};
    /* HOW the app runs is the bundle's own word, not the host's: /app.run exists only when the bundle's measured
     * manifest states world wasi:cli, and holds the port it serves HTTP on (assemble-app-image.sh writes it from
     * the bundle, so it is inside the launch measurement). Such an app is a command that binds that port itself
     * through wasi:sockets, as the platform's run mode does (wasm/wasm_manager.py): -S tcp/udp/inherit-network,
     * ENCLAVE_PORTS=http:N=N (logical = actual here: this domain holds one app), and a private scratch /data.
     * inherit-network reaches nothing but this domain's own loopback: the domain has no NIC, and its only channel,
     * vsock, is not an IP socket. Its config arrives as ENCLAVE_CONFIG like a served app's; its egress is the same
     * as a served app's, the front's per-origin forwarders on loopback (front/provision.go). No other ports. */
    int port = 0;
    FILE *rf = fopen("/app.run", "r");
    if (rf) {
        if (fscanf(rf, "%d", &port) != 1 || port < 1 || port > 49999) port = -1;
        fclose(rf);
    }
    if (port < 0) {
        printf("DOM ERROR /app.run does not name a port in 1-49999\n");
        fflush(stdout);
        reboot(RB_POWER_OFF);
    }
    char upstream[32], ports_env[64];
    snprintf(upstream, sizeof upstream, "127.0.0.1:%d", port ? port : 8080);
    snprintf(ports_env, sizeof ports_env, "ENCLAVE_PORTS=http:%d=%d", port, port);
    char *run[] = {"/rt/ld-linux-x86-64.so.2", "--library-path", "/rt", "/rt/wasmtime", "run", "-S", "cli",
                   "-S", "tcp", "-S", "udp", "-S", "inherit-network", "-S", "allow-ip-name-lookup",
                   "-C", "cache=n", "--dir", "/data::/data", "--env", ports_env, "/app.wasm", NULL};
    if (port) {
        char data_opts[80], pl[160];
        snprintf(data_opts, sizeof data_opts, "size=64m,mode=0700,uid=%d,gid=%d", APP_UID, APP_GID);   /* the app's own */
        mkdir("/data", 0700);
        if (mount("tmpfs", "/data", "tmpfs", 0, data_opts) != 0) {
            printf("DOM ERROR /data: %s: the app is not started\n", strerror(errno));
            fflush(stdout);
            reboot(RB_POWER_OFF);
            _exit(1);
        }
        if (!unpriv_port(port, "/proc/sys/net/ipv4/ip_unprivileged_port_start", write_sysctl, pl, sizeof pl)) {
            printf("DOM ERROR %s: the app is not started\n", pl);
            fflush(stdout);
            reboot(RB_POWER_OFF);
            _exit(1);
        }
        printf("DOM %s\n", pl);
        printf("DOM app mode run: a wasi:cli command serving HTTP on %d (ENCLAVE_PORTS http:%d=%d, /data 64 MiB scratch)\n",
               port, port, port);
    }
    /* The front first. It hands this process the app's config (or "none") on a pipe, and the app starts only then:
     * the release, the allowlist and the forwarders all happen before any tenant code runs. */
    int pfd[2];
    if (pipe2(pfd, O_CLOEXEC) < 0) {
        printf("DOM ERROR pipe: %s\n", strerror(errno));
        fflush(stdout);
        reboot(RB_POWER_OFF);
    }
    char *front[] = {"/front", "-port", "443", "-upstream", upstream, snp ? "-snp=true" : "-snp=false",
                     "-init-fd", "3", "-seccomp-statement", SECCOMP_STATEMENT, NULL};
    pid_t front_pid = spawn(front, NULL, pfd[1], 0);         /* the front stays root and unfiltered: it holds the key, the release and the vsock */
    front_pid_g = front_pid;                                   /* what the app's child checks it cannot open */
    close(pfd[1]);
    char *cfg_env = NULL;
    size_t cfg_len = 0;
    const char *why = read_front_msg(pfd[0], &cfg_env, &cfg_len);
    close(pfd[0]);
    if (why) {
        printf("DOM ERROR the front %s: the app is not started\n", why);
        fflush(stdout);
        sync();
        reboot(RB_POWER_OFF);
    }
    if (cfg_env) printf("DOM app config: %zu bytes (ENCLAVE_CONFIG)\n", cfg_len);   /* its length, never its content */
    else printf("DOM app config: none\n");

    /* the runtime passes ENCLAVE_CONFIG to the guest program from its own environment (--env NAME, no value), so the
     * value is never an argument */
    char **base = port ? run : serve, *app[48];
    int k = 0;
    for (int i = 0; base[i]; i++) {
        if (cfg_env && strcmp(base[i], "/app.wasm") == 0) {
            app[k++] = "--env";
            app[k++] = "ENCLAVE_CONFIG";
        }
        app[k++] = base[i];
    }
    app[k] = NULL;
    pid_t app_pid = spawn_app(app, cfg_env, SPAWN_QUIET | SPAWN_DROP | SPAWN_FILTER);   /* quiet, dropped to APP_UID, filtered */
    if (app_pid == -2) {
        fflush(stdout);
        reboot(RB_POWER_OFF);
    }
    if (cfg_env) {
        explicit_bzero(cfg_env, sizeof "ENCLAVE_CONFIG=" + cfg_len);
        free(cfg_env);
    }
    printf("DOM started app=%d front=%d at_ms=%.0f\n", app_pid, front_pid, now_ms());

    for (;;) {                   /* PID 1 reaps everything; either server ending ends the domain */
        int st = 0;
        pid_t w = wait(&st);
        if (w < 0 && errno == ECHILD) break;
        if (w == app_pid || w == front_pid) {
            printf("DOM ERROR %s exited status=%d\n", w == app_pid ? "app" : "front",
                   WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st));
            break;
        }
    }
    printf("DOM end\n");
    fflush(stdout);
    sync();
    reboot(RB_POWER_OFF);
    return 0;
}
