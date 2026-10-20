/* PID 1 of ONE app domain (isolation/m3/PLAN.md). The monitor starts this inside the domain's new
 * mount, PID, network, IPC and UTS namespaces, chrooted to the domain's own directory, and it:
 *   1. mounts the domain's private /proc and /tmp and brings its loopback up (root work, in the
 *      domain's namespaces, before any domain code runs);
 *   2. drops to the domain's unprivileged uid and starts the two workloads: the runtime serving the
 *      app, and the front that terminates TLS and asks the monitor for reports;
 *   3. prints what the domain can see, as evidence for the isolation checks;
 *   4. reaps, and exits when either workload exits, which the monitor treats as the domain ending;
 *   5. on SIGTERM, passes it to the front so the domain winds down gracefully. The monitor signals THIS
 *      process, whose handle it owns, rather than hunting for the front's pid in /proc — a number that
 *      could be recycled between being read and being signalled.
 *
 * EVERY setup step fails closed. A domain whose /proc, /tmp or loopback could not be set up, or whose
 * privilege drop did not complete, exits instead of running the tenant's app in a half-built world;
 * the monitor sees the exit and reclaims the domain.
 *
 * This is the INTERIM backend: what separates one domain from another here is the GUEST KERNEL
 * (namespaces, uids, cgroups), so the guest kernel is in the TCB for app-vs-app isolation. That is
 * WEAKER than the VMPL separation described in PLAN.md section 1, and is not a substitute for it. SNP
 * still excludes the host from all of it.
 *
 * usage: domexec <id> <runtime-uid>:<front-uid> [app|probe|run] [memMiB] [port] (run by the monitor, never by a domain)
 *   The runtime and the front run as DIFFERENT uids (enclave-87's ruling on enclave-bf's finding): the front is the
 *   trusted component in a domain and the runtime is not, so the runtime must not be able to signal, trace or read the
 *   front, replace its listen socket, or reach the report socket (the monitor gives /run to the front's uid alone). The
 *   adversary probe runs as the RUNTIME's uid: it stands in for a compromised runtime.
 *   app   (default) the runtime serving the tenant's app, plus the front
 *   probe the measured adversary probe (domprobe.c) as the domain's only workload, for the isolation
 *         tests: it stands in for a compromised runtime and reports what it could reach
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../m2/app-seccomp.h"   /* the app runtime's seccomp filter, shared with the SNP guest's m2/dominit.c */

static int shield_on = 0;
static char shield_workers[192], shield_vram[80];
static const char *dom_id = "?";
static volatile sig_atomic_t front_pid_g = -1;

/* Graceful stop: the monitor sends SIGTERM here, and the front is what needs to hear it. */
static void on_term(int sig) {
    (void)sig;
    if (front_pid_g > 0) kill(front_pid_g, SIGTERM);
}

/* Any failure in the domain's setup ends the domain. Running the tenant's app in a partly-built
 * namespace would be failing open: it is exactly the case where the isolation is not what the rest of
 * the system believes it is. */
static void die(const char *what) {
    printf("DOM%s ERROR %s: %s\n", dom_id, what, strerror(errno));
    fflush(stdout);
    _exit(1);
}

static void lo_up(void) {
    struct ifreq ifr = {0};
    strcpy(ifr.ifr_name, "lo");
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) die("lo socket");
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) die("lo flags");
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) die("lo up");
    close(s);
}

/* A SECRET domain's egress (m2/front shield_egress.go): once the release is verified, the FRONT binds one forwarder per
 * allowed origin on 127.64.0.N:443 in THIS network namespace, then fills /etc/hosts. 443 is below the kernel's default
 * unprivileged floor (1024), and the front holds no capability; so this namespace's floor is lowered to exactly 443.
 * net.ipv4.ip_unprivileged_port_start is PER NETWORK NAMESPACE: no other domain and not the guest's own namespace is
 * touched. Nothing gains a capability. The runtime that shares the namespace gains nothing it can use against the front:
 * its tenant code starts only after the forwarders are bound (secretrun waits on the front's pipe), a bound address it
 * cannot take over (another uid's listener), and anything it binds is reachable only from inside this domain, whose one
 * interface is lo. Read back; a floor that did not hold ends the domain. Called as root, before any workload starts.
 * A PUBLIC-WEB domain (the monitor's root-owned /egress.public-web, from the measured config) also gets the front's DNS
 * stub on 127.0.0.2:53, which resolv.conf names and which glibc can only reach on port 53: its floor is 53 instead,
 * with the same reasoning (the stub is bound before the tenant starts, and the namespace's one interface is lo). */
static void unprivileged_https_bind(int public_web) {
    static const char path[] = "/proc/sys/net/ipv4/ip_unprivileged_port_start";
    const char *floor = public_web ? "53\n" : "443\n";
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) die("open ip_unprivileged_port_start");
    if (write(fd, floor, strlen(floor)) != (ssize_t)strlen(floor)) die("set ip_unprivileged_port_start");
    close(fd);
    char b[16] = {0};
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || read(fd, b, sizeof b - 1) <= 0 || strcmp(b, floor) != 0) { errno = EPERM; die("ip_unprivileged_port_start did not hold"); }
    close(fd);
    printf("DOM%s egress: this namespace's unprivileged port floor is %s (the front's %s, no capability)\n", dom_id,
           public_web ? "53" : "443", public_web ? "forwarders, SOCKS front and DNS stub" : "forwarders");
}

/* What this domain can reach, printed once the workloads are running (so the process count is the
 * domain's real one). The host harness reads these lines off the console. */
static void probe(uid_t workload_uid, uid_t front_uid) {
    struct stat st;
    int sysfs = stat("/sys", &st) == 0, cfg = stat("/sys/kernel/config", &st) == 0;
    int doms = stat("/domains", &st) == 0, appok = stat("/app.wasm", &st) == 0;
    int procs = 0;
    DIR *d = opendir("/proc");
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) if (e->d_name[0] >= '1' && e->d_name[0] <= '9') procs++;
        closedir(d);
    }
    printf("DOM%s probe workload_uid=%d front_uid=%d sys=%d configfs=%d domains_dir=%d own_app=%d visible_pids=%d\n",
           dom_id, (int)workload_uid, (int)front_uid, sysfs, cfg, doms, appok, procs);
}

/* Evidence for the credential gate: while this process is still ROOT — and root is not a domain — ask
 * the monitor for a report. The monitor identifies callers by the socket's kernel credentials, so it
 * must refuse. A caller that could obtain a report without being a registered domain would be able to
 * name any app it liked. */
static void probe_report_as_root(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return;
    struct sockaddr_un sa = {0};
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, "/run/monitor.sock", sizeof sa.sun_path - 1);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        printf("DOM%s report_as_root=no-socket (%s)\n", dom_id, strerror(errno));
        close(fd);
        return;
    }
    static const char req[] = "{\"bind\":\"0000000000000000000000000000000000000000000000000000000000000000\"}\n";
    char buf[512] = {0};
    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    ssize_t n = write(fd, req, sizeof req - 1) > 0 ? read(fd, buf, sizeof buf - 1) : -1;
    /* Only an answer that actually carries a report counts as granted. Silence is not success: a read
     * that times out or is reset says nothing about what the monitor would have done, and calling it
     * "refused" would hide a real grant just as badly as calling it "GRANTED" invents one. */
    const char *verdict = n <= 0 ? "no-answer" : strstr(buf, "\"report\"") ? "GRANTED"
                        : strstr(buf, "\"error\"") ? "refused" : "unexpected";
    printf("DOM%s report_as_root=%s\n", dom_id, verdict);
    close(fd);
}

/* The null device, fd NULL_FD: the MONITOR opens /dev/null in the guest's own root and hands it to this process
 * (monitor/main.go cmd.ExtraFiles), because this process starts already CHROOTED into the domain's directory, which has
 * no /dev and must not get one (no device node, no mknod, no new filesystem for the tenant to see). main() checks it IS
 * the null device and marks it close-on-exec, so no workload inherits it except through the quiet spawn's dup2s.
 * enclave-d1's canary of 4cdd5169 (252602c8): the quiet runtime opened "/dev/null" INSIDE the chroot, got ENOENT and
 * exited 126 on every m3 domain, so domexec ended each domain before it served (enclave-87 chose this design). */
#define CONFIG_MAX_BYTES 32768
static int secret_pipe[2] = {-1,-1};
static char app_config_env[CONFIG_MAX_BYTES + sizeof "ENCLAVE_CONFIG="];
/* Read only the monitor's immutable copy from the measured bundle. Never print it. */
static void read_app_config(void) {
    int fd = open("/app.config", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { if (errno == ENOENT) return; die("open app config"); }
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0222)
        || st.st_size <= 0 || st.st_size > CONFIG_MAX_BYTES) die("app config permissions or size");
    const size_t prefix = sizeof "ENCLAVE_CONFIG=" - 1;
    memcpy(app_config_env, "ENCLAVE_CONFIG=", prefix);
    size_t n = 0;
    while (n < (size_t)st.st_size) {
        ssize_t got = read(fd, app_config_env + prefix + n, (size_t)st.st_size - n);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) die("read app config");
        n += (size_t)got;
    }
    if (memchr(app_config_env + prefix, 0, n)) die("app config contains NUL");
    app_config_env[prefix + n] = 0;
    close(fd);
}
static void config_argument(char **args) {
    if (!app_config_env[0]) return;
    size_t n = 0; while (args[n]) n++;
    /* The artifact is last; put inherited --env before it, with no value in argv. */
    char *artifact = args[n - 1];
    args[n - 1] = "--env"; args[n] = "ENCLAVE_CONFIG";
    args[n + 1] = artifact; args[n + 2] = NULL;
}
#define NULL_FD 3
/* The seccomp STATEMENT channel, fd SECCOMP_FD: a pipe the MONITOR hands this process (its read end stays with the
 * monitor). Close-on-exec from the start and closed here once the runtime is spawned, so only the runtime's child - this
 * file's code, after the filter is installed and before exec - writes to it: the front, the probe and everything the
 * runtime runs never hold it. The monitor carries what arrives into the attested self-test (seccomp=<hash>). Absent (an
 * older monitor): no statement, and the judge refuses a release that must state one. */
#define SECCOMP_FD 4
static int seccomp_fd = -1;

/* quiet: the child's stdin, stdout and stderr are the null device (NULL_FD). It is TENANT code (the runtime serving or
 * running the app), and this process's stdout is the monitor's, which is the guest console the HOST reads
 * (monitor/main.go runs this with cmd.Stdout/Stderr = its own): nothing an app prints (a request, its config, a panic)
 * may reach it. The same rule as the SEV-SNP guest's m2/dominit.c (77cf2d78). A quiet child keeps a close-on-exec copy
 * of the console only to report its OWN exec failure, and one whose null device cannot be installed exits 126 rather
 * than run with the console. The front (console-guarded, m2/front/console.go) and the adversary probe (our statements
 * only) keep the console.
 * filter: after the drop, the child sets no_new_privs and installs app-seccomp.h's filter, right before exec (enclave-87:
 * no AF_VSOCK, no io_uring, no namespaces, no ptrace, ... for the RUNTIME; never the front). A child that cannot exits 1,
 * and the domain ends as for any workload exit. */
static pid_t spawn(char *const argv[], uid_t uid, int quiet, int filter) {
    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        int con = 1;
        if (quiet) {
            con = fcntl(1, F_DUPFD_CLOEXEC, 10);
            /* dup2 clears close-on-exec on 0-2; NULL_FD itself stays close-on-exec and closes at exec */
            if (dup2(NULL_FD, 0) < 0 || dup2(NULL_FD, 1) < 0 || dup2(NULL_FD, 2) < 0) _exit(126);
        }
        /* Drop the supplementary groups FIRST. setuid alone would leave this process carrying the
         * monitor's groups — root's among them — so a domain workload could reach anything granted by
         * group membership. setgroups must happen while still privileged. A failure is reported on the
         * console copy (a quiet child's stdout is /dev/null), as die() would, then the child exits 1. */
        const char *drop = setgroups(0, NULL) != 0 ? "setgroups" : setgid((gid_t)uid) != 0 ? "setgid"
                         : setuid(uid) != 0 ? "setuid" : NULL;
        if (drop) {
            if (con >= 0) dprintf(con, "DOM%s ERROR %s: %s\n", dom_id, drop, strerror(errno));
            _exit(1);
        }
        /* and confirm it held: a privilege drop that can be undone is not a privilege drop */
        if (getuid() != uid || geteuid() != uid || setuid(0) == 0) {
            if (con >= 0) dprintf(con, "DOM%s ERROR privilege drop did not hold\n", dom_id);
            _exit(1);
        }
        if (filter && (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || app_seccomp_install() != 0)) {
            if (con >= 0) dprintf(con, "DOM%s ERROR the runtime's seccomp filter could not be installed: %s\n", dom_id, strerror(errno));
            _exit(1);
        }
        if (filter) {   /* the filter is on: the positive line on the console, and the statement to the monitor */
            char st[160], hex[65];
            unsigned rules = 0;
            int n = app_seccomp_statement(st, sizeof st);
            if (n < 0 || sscanf(st, "seccomp sha256=%64[0-9a-f] rules=%u", hex, &rules) != 2) _exit(1);
            if (con >= 0) dprintf(con, "DOM%s seccomp: runtime filter installed (sha256 %s, %u rules)\n", dom_id, hex, rules);
            if (seccomp_fd >= 0 && write(seccomp_fd, st, (size_t)n) != n) {
                if (con >= 0) dprintf(con, "DOM%s ERROR the runtime's seccomp statement could not be written: %s\n", dom_id, strerror(errno));
                _exit(1);
            }
        }
        if (secret_pipe[0] >= 0) {
            int keep = filter ? secret_pipe[0] : secret_pipe[1];
            if (dup2(keep, 7) < 0 || fcntl(7, F_SETFD, 0) < 0) _exit(126);
            if (secret_pipe[0] != 7) close(secret_pipe[0]);
            if (secret_pipe[1] != 7) close(secret_pipe[1]);
        }
        char *envp[48] = {"HOME=/tmp", "PATH=/plat", NULL};
        if (shield_on && filter) {
            const char *fixed[] = {
                "ENCLAVE_GGML_BACKEND_DIR=/plat/rt-shield/backends",
                "GGML_BACKEND_PATH=/plat/rt-shield/backends/libggml-shielded.so",
                "SHIELDED_HOST=unix:/run/enclave-shield/gpu0", "SHIELDED_PORT=19595",
                "SHIELDED_CALIB=/plat/rt-shield/calib/qwen2.5-0.5b-q8-gguf.calib",
                "ENCLAVE_GGML_EXTRA_BUFTS=0", "ENCLAVE_GGML_N_GPU_LAYERS=0", "ENCLAVE_GGML_N_CTX=512",
                "ENCLAVE_GGML_MAX_SESSIONS=8", "ENCLAVE_GGML_POOLED=1",
                "ENCLAVE_GGML_PARK_SLOTS=0", "ENCLAVE_GGML_PREFIX_SLOTS=0",
                "ENCLAVE_NN_SERVE_BYTES=2147483648", "ENCLAVE_NN_SERVE_KIND=RAM",
                "ENCLAVE_GGML_N_THREADS=2", "ENCLAVE_GGML_N_THREADS_BATCH=2",
                "ENCLAVE_GGML_N_BATCH=16", "ENCLAVE_GGML_N_UBATCH=16",
                "SHIELDED_REFILL_THREADS=2", "SHIELDED_POOL_DEPTH=8", "OMP_NUM_THREADS=2",
                "SHIELDED_MAX_M=64", "SHIELDED_OVERLAP_VERIFY=1", "SHIELDED_WEIGHT_BUDGET_FRAC=0.95",
                "ENCLAVE_MODELS=qwen2.5-0.5b-q8-gguf", "ENCLAVE_NN_PRELOADS=qwen2.5-0.5b-q8-gguf", NULL
            };
            int i=2;
            for (int j=0; fixed[j]; j++) envp[i++]=(char *)fixed[j];
            envp[i++]=shield_workers; envp[i++]=shield_vram; envp[i]=NULL;
        }
        if (filter && app_config_env[0]) {
            size_t n = 0; while (envp[n]) n++;
            envp[n] = app_config_env; envp[n + 1] = NULL;
        }
        execve(argv[0], argv, envp);
        if (con >= 0) dprintf(con, "DOM%s ERROR exec %s: %s\n", dom_id, argv[0], strerror(errno));
        _exit(127);
    }
    return pid;
}

/* a uid spelled in decimal from s up to exactly stop, nothing else, nonzero and not (uid_t)-1: -> it, or 0 */
static uid_t parse_uid(const char *s, const char *stop) {
    if (s >= stop || *s < '0' || *s > '9') return 0;
    char *e;
    errno = 0;
    unsigned long v = strtoul(s, &e, 10);
    if (errno || e != stop || v == 0 || v >= 0xFFFFFFFFUL) return 0;
    return (uid_t)v;
}

int main(int argc, char **argv) {
    if (argc < 3) { printf("DOM ERROR domexec <id> <runtime-uid>:<front-uid>\n"); return 2; }
    dom_id = argv[1];
    /* <runtime-uid>:<front-uid>, exactly two different non-root decimal uids, or nothing starts: a front sharing the
     * runtime's uid is the v42 residual this closes. Parsed strictly (enclave-5d): "1000:1001x" or "-1:1001" is refused,
     * not read as 1001 or uid 4294967295. */
    char *colon = strchr(argv[2], ':');
    uid_t uid = colon ? parse_uid(argv[2], colon) : 0, front_uid = colon ? parse_uid(colon + 1, colon + 1 + strlen(colon + 1)) : 0;
    if (uid == 0 || front_uid == 0) {
        printf("DOM%s ERROR the uids must be <runtime-uid>:<front-uid>, two non-root decimal uids (got %s): not started\n", dom_id, argv[2]);
        return 2;
    }
    if (front_uid == uid) { printf("DOM%s ERROR the front and the runtime must not share a uid (%u)\n", dom_id, (unsigned)uid); return 2; }
    /* the null device the monitor opened for us (NULL_FD, above): it must BE the null device (char 1:3), or the domain
     * does not start - a quiet workload with anything else on its stdio could reach the console or a file */
    struct stat nst;
    if (fstat(NULL_FD, &nst) != 0 || !S_ISCHR(nst.st_mode) || major(nst.st_rdev) != 1 || minor(nst.st_rdev) != 3) {
        printf("DOM%s ERROR the monitor handed no null device on fd %d, so the app's output could not be discarded: not started\n",
               dom_id, NULL_FD);
        return 2;
    }
    if (fcntl(NULL_FD, F_SETFD, FD_CLOEXEC) != 0) die("cloexec null device");
    struct stat sst;
    if (fstat(SECCOMP_FD, &sst) == 0 && S_ISFIFO(sst.st_mode)) {   /* the monitor's statement pipe, if it gave one */
        if (fcntl(SECCOMP_FD, F_SETFD, FD_CLOEXEC) != 0) die("cloexec seccomp statement");
        seccomp_fd = SECCOMP_FD;
    }

    if (mount("proc", "/proc", "proc", 0, 0) != 0) die("mount /proc");   /* this PID namespace only */
    if (mount("tmpfs", "/tmp", "tmpfs", 0, "size=64m,mode=1777") != 0) die("mount /tmp");
    lo_up();
    probe_report_as_root();

    /* Both workloads run in these namespaces, with this root: the runtime as the domain's uid, the front as its own
     * (front_uid). The runtime serves the app on the domain's OWN loopback: every domain uses 127.0.0.1:8080 and they
     * cannot collide or reach each other, because each has its own network namespace. */
    /* -C cache=n: compile inside the domain every time and keep no compiled artifact. See the same flag in
     * m2/dominit.c: wasmtime caches compiled modules by default, and an unauthenticated compiled cache is
     * refused by the portable-runtime contract (isolation/contract/RUNTIME.md rule 5). It also matters more
     * here than in M2, because several domains share this guest's filesystem. */
    read_app_config();
    char *rt[64] = {"/plat/rt/ld-linux-x86-64.so.2", "--library-path", "/plat/rt", "/plat/rt/wasmtime",
                  "serve", "-S", "cli", "-W", "threads,shared-everything-threads,component-model-threading,shared-memory,memory64,component-model-memory64", "-C", "cache=n", "--addr", "127.0.0.1:8080", "/app.wasm", NULL};
    char *front[32] = {"/plat/front", "-runtime-identity", "/plat/rt/runtime.json",
                     "-listen-unix", "/run/front.sock", "-report-unix", "/run/monitor.sock",
                     "-upstream", "127.0.0.1:8080", "-app-sha", "/app.sha256", "-app-mode", "serve",
                     "-cert-name-file", "/cert.name", NULL};
    /* RUN mode (enclave-catalog-bundle/2): the bundle's own manifest says the app is a wasi:cli COMMAND that binds
     * its declared HTTP port through wasi:sockets; the monitor passes that port (argv[5]) from the bundle it hashed,
     * never from the host's request. The same semantics as the Linux SNP tier's m2/dominit.c: -S tcp/udp/
     * inherit-network, ENCLAVE_PORTS=http:N=N, a private 64 MiB scratch /data, lost when the domain ends. Here
     * inherit-network reaches only this domain's OWN network namespace, whose one interface is its loopback. */
    int run_port = 0;
    char ports_env[2048], memory_env[64], memory_limit[64], upstream[32], data_opts[96];
    unsigned long app_mib = argc > 4 ? strtoul(argv[4], NULL, 10) : 0;
    if (app_mib < 64 || app_mib > 1048576) die("invalid app memory");
    snprintf(memory_env, sizeof memory_env, "ENCLAVE_MEM_MB=%lu", app_mib);
    snprintf(memory_limit, sizeof memory_limit, "max-memory-size=%llu", (unsigned long long)app_mib << 20);
    char *run[64] = {"/plat/rt/ld-linux-x86-64.so.2", "--library-path", "/plat/rt", "/plat/rt/wasmtime", "run",
                   "-S", "cli", "-S", "tcp", "-S", "udp", "-S", "inherit-network", "-S", "allow-ip-name-lookup",
                   "-C", "cache=n", "-W", "threads,shared-everything-threads,component-model-threading,shared-memory,memory64,component-model-memory64", "-W", memory_limit, "--dir", "/data::/data", "--env", ports_env, "--env", memory_env, "/app.wasm", NULL};
    char *run_front[32] = {"/plat/front", "-runtime-identity", "/plat/rt/runtime.json",
                         "-listen-unix", "/run/front.sock", "-report-unix", "/run/monitor.sock",
                         "-upstream", upstream, "-app-sha", "/app.sha256", "-app-mode", "run",
                         "-cert-name-file", "/cert.name", NULL};
    if (argc > 3 && strcmp(argv[3], "run") == 0) {
        run_port = argc > 5 ? atoi(argv[5]) : 0;
        if (run_port < 1 || run_port > 49999) {
            printf("DOM%s ERROR run mode needs the bundle's HTTP port in 1-49999\n", dom_id);
            return 2;
        }
        snprintf(ports_env, sizeof ports_env, "ENCLAVE_PORTS=http:%d=%d", run_port, run_port);
        FILE *pf = fopen("/app.ports", "r");
        if (pf) {
            char line[32], proto[4]; int pn;
            while (fgets(line, sizeof line, pf)) {
                if (sscanf(line, "%3[^:]:%d", proto, &pn) != 2 ||
                    (strcmp(proto,"tcp") && strcmp(proto,"udp")) || pn < 1 || pn > 49999) die("invalid measured ports");
                size_t used = strlen(ports_env);
                int n = snprintf(ports_env+used, sizeof ports_env-used, ",%s:%d=%d", proto,pn,pn);
                if (n < 0 || (size_t)n >= sizeof ports_env-used) die("too many measured ports");
            }
            if (ferror(pf)) die("read measured ports");
            fclose(pf);
        } else if (errno != ENOENT) die("open measured ports");
        snprintf(upstream, sizeof upstream, "127.0.0.1:%d", run_port);
        snprintf(data_opts, sizeof data_opts, "size=64m,mode=0700,uid=%u,gid=%u", (unsigned)uid, (unsigned)uid);
        mkdir("/data", 0700);
        if (mount("tmpfs", "/data", "tmpfs", 0, data_opts) != 0) die("mount /data");
    }
    config_argument(rt); config_argument(run);
    char *probe_argv[] = {"/plat/domprobe", (char *)dom_id, argc > 4 ? argv[4] : "0", NULL};
    struct sigaction sa_term = {0};
    sa_term.sa_handler = on_term;
    sigaction(SIGTERM, &sa_term, NULL);

    pid_t shield_pid = -1;
    struct stat profile_st;
    if (stat("/shield.profile", &profile_st) == 0) {
        if (!S_ISREG(profile_st.st_mode) || profile_st.st_uid != 0 || (profile_st.st_mode & 0222)) die("Shield profile permissions");
        FILE *f = fopen("/shield.profile", "r");
        int milli=0; char extra=0;
        if (!f || fscanf(f, "%d %c", &milli, &extra) != 1 || milli < 500 || milli > 1000) die("Shield profile");
        fclose(f);
        unsigned long long bytes = (12ULL<<30) * (unsigned)milli / 1000;
        snprintf(shield_workers,sizeof shield_workers,"SHIELDED_WORKERS=unix:/run/enclave-shield/gpu0|19595|0|%llu",bytes);
        snprintf(shield_vram,sizeof shield_vram,"ENCLAVE_VRAM_BYTES=%llu",bytes);
        shield_on=1;
        shield_pid=fork();
        if (shield_pid < 0) die("fork Shield broker");
        if (shield_pid == 0) {
            char uid_arg[32]; snprintf(uid_arg,sizeof uid_arg,"%u",(unsigned)uid);
            // This measured broker alone retains AF_VSOCK. It authenticates the runtime UID.
            char *av[]={"/plat/shieldbroker",uid_arg,NULL};
            char *env[]={"PATH=/plat",NULL};
            execve(av[0],av,env); _exit(127);
        }
        for (int i=0; access("/run/enclave-shield/gpu0",F_OK)!=0; i++) {
            int st;
            if (i>=1000 || waitpid(shield_pid,&st,WNOHANG)!=0) die("Shield broker readiness");
            usleep(10000);
        }
        front[2]="/plat/rt-shield/runtime.json";
        front[4]="/run/front/front.sock"; front[6]="/run/front/monitor.sock";
        run_front[4]="/run/front/front.sock"; run_front[6]="/run/front/monitor.sock";
        run_front[2]="/plat/rt-shield/runtime.json";
    } else if (errno != ENOENT) die("stat Shield profile");
    char **base = run_port ? run : rt;
    char *shield_app[64]; int ai=0;
    for (int i=0; base[i]; i++) {
        char *v=base[i];
        if (shield_on) {
            if (!strcmp(v,"/plat/rt/ld-linux-x86-64.so.2")) v="/plat/rt-shield/ld-linux-x86-64.so.2";
            else if (!strcmp(v,"/plat/rt")) v="/plat/rt-shield";
            else if (!strcmp(v,"/plat/rt/wasmtime")) v="/plat/rt-shield/wasmtime";
            else if (!strcmp(v,"/app.wasm")) {
                shield_app[ai++]="-S"; shield_app[ai++]="nn";
                shield_app[ai++]="-S"; shield_app[ai++]="nn-graph=ggml::/plat/models/qwen2.5-0.5b-q8-gguf";
            }
        }
        shield_app[ai++]=v;
    }
    shield_app[ai]=NULL;
    struct stat secret_st, web_st;
    char *secret_app[66];
    int public_web = 0;
    if (lstat("/egress.public-web", &web_st) == 0) {
        if (!S_ISREG(web_st.st_mode) || web_st.st_uid != 0 || (web_st.st_mode & 0222)) die("public web marker");
        public_web = 1;
    } else if (errno != ENOENT) die("public web marker stat");
    if (public_web && stat("/secret.id", &secret_st) != 0) die("public web needs a secret domain");
    if (stat("/secret.id", &secret_st) == 0) {
        if (shield_on || !S_ISREG(secret_st.st_mode) || secret_st.st_uid != 0 || (secret_st.st_mode & 0222) || secret_st.st_size != 66) die("secret deployment");
        /* 443 belongs to the front's authenticated egress listeners. A command app needs
         * an unprivileged HTTP port distinct from those listeners. */
        if (run_port && run_port < 1024) die("secret command HTTP port");
        unprivileged_https_bind(public_web);   /* the front's egress listeners, before anything is spawned */
        int raw[2]; if (pipe2(raw, O_CLOEXEC) != 0) die("secret pipe");
        // Keep both originals away from the fixed inherited fd before duplicating it.
        secret_pipe[0]=fcntl(raw[0],F_DUPFD_CLOEXEC,20);
        secret_pipe[1]=fcntl(raw[1],F_DUPFD_CLOEXEC,20);
        close(raw[0]);close(raw[1]);
        if (secret_pipe[0]<0 || secret_pipe[1]<0) die("secret pipe fds");
        secret_app[0]="/plat/secretrun";
        int i=0;for (;shield_app[i];i++) secret_app[i+1]=shield_app[i];secret_app[i+1]=NULL;
        char **secret_front = run_port ? run_front : front;
        int j=0;while(secret_front[j])j++;secret_front[j++]="-shield-secrets-fd";secret_front[j++]="7";secret_front[j]=NULL;
    } else if (errno != ENOENT) die("secret deployment stat");
    pid_t rt_pid, front_pid;
    if (argc > 3 && strcmp(argv[3], "probe") == 0) {
        if (seccomp_fd >= 0) { close(seccomp_fd); seccomp_fd = -1; }   /* the probe states no filter */
        rt_pid = spawn(probe_argv, uid, 0, 0);
        front_pid = -1;
        printf("DOM%s started adversary probe=%d (no app, no front)\n", dom_id, rt_pid);
    } else if (run_port) {
        rt_pid = spawn(secret_pipe[0]>=0 ? secret_app : shield_app, uid, 1, 1);                 /* the runtime: quiet and filtered */
        if (seccomp_fd >= 0) { close(seccomp_fd); seccomp_fd = -1; }   /* its child holds the statement pipe until exec */
        front_pid = spawn(run_front, front_uid, 0, 0);  /* the front: its own uid, neither quiet nor filtered */
        front_pid_g = front_pid;
        printf("DOM%s started runtime=%d front=%d mode=run http=%d (/data 64 MiB scratch)\n", dom_id, rt_pid, front_pid,
               run_port);
    } else {
        rt_pid = spawn(secret_pipe[0]>=0 ? secret_app : shield_app, uid, 1, 1);                  /* the runtime: quiet and filtered */
        if (seccomp_fd >= 0) { close(seccomp_fd); seccomp_fd = -1; }   /* its child holds the statement pipe until exec */
        front_pid = spawn(front, front_uid, 0, 0);      /* the front: its own uid, neither quiet nor filtered */
        front_pid_g = front_pid;
        printf("DOM%s started runtime=%d front=%d mode=serve\n", dom_id, rt_pid, front_pid);
    }
    if (secret_pipe[0]>=0) { close(secret_pipe[0]);close(secret_pipe[1]);secret_pipe[0]=secret_pipe[1]=-1; }
    usleep(200000);
    probe(uid, front_uid);

    for (;;) {
        int st = 0;
        pid_t w = wait(&st);
        if (w < 0 && errno == EINTR) continue;   /* the SIGTERM we forwarded, not a child exiting */
        if (w < 0 && errno == ECHILD) break;
        if (w == rt_pid || w == front_pid || w == shield_pid) {
            printf("DOM%s ERROR %s exited status=%d\n", dom_id, w == rt_pid ? "runtime" : w == front_pid ? "front" : "Shield broker",
                   WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st));
            break;
        }
    }
    printf("DOM%s end\n", dom_id);
    fflush(stdout);
    return 0;
}
