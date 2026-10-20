/* egress-probe.c - TEST ONLY (never in an image): stands in for a NucBox Shield domain's two workloads under domexec and
 * checks, from INSIDE each, what its egress path needs and what it must not grant (m3/test-domexec-egress.sh). Its role is
 * its argv[0]: a name containing "front" is the front; anything else (/plat/secretrun in a secret domain, the runtime's
 * loader otherwise) is the runtime. Writes "ok ..." / "BAD ..." lines and "done ok=N bad=M" to /probe-out/<role>.egress.
 *
 *   front, secret domain   CapEff 0; this namespace's ip_unprivileged_port_start is 443 and it cannot change it; bind +
 *                          listen on 127.64.0.2:443 and 127.64.0.3:443 succeed; /etc/hosts is its own, rewritable;
 *                          nsswitch.conf is not writable and /etc takes no new file. Then it writes "bound" on the secret
 *                          pipe (fd 7), as the real front writes the runtime's secrets only after its forwarders listen,
 *                          and holds its listeners while the runtime checks.
 *   front, public web      (the monitor's /egress.public-web) as a secret domain, but the floor is 53: it also binds
 *                          127.0.0.2:53 (the DNS stub resolv.conf names) and 127.0.0.2:1080 (the SOCKS front), and
 *                          resolv.conf is not its to change; the runtime cannot take 127.0.0.2:53 or change resolv.conf.
 *   front, no secrets      the floor is the kernel's 1024 and 127.64.0.2:443 is refused (EACCES): only a secret domain's
 *                          namespace is opened.
 *   runtime                CapEff 0; seccomp mode 2; socket(AF_VSOCK) refused (EPERM); the floor sysctl not writable.
 *                          In a secret domain, after the front's "bound": /etc/hosts readable and not writable,
 *                          nsswitch.conf not writable, no new file in /etc, and the front's 127.64.0.2:443 cannot be
 *                          taken, even with SO_REUSEPORT (EADDRINUSE: the listener is another uid's).
 * Built with gcc -static. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

static FILE *out;
static int n_ok, n_bad;
static void say(int good, const char *name, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void say(int good, const char *name, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(out, "%s %s: ", good ? "ok " : "BAD", name);
    vfprintf(out, fmt, ap);
    fputc('\n', out);
    va_end(ap);
    if (good) n_ok++; else n_bad++;
}

static long long status_hex(const char *field, int base) {
    FILE *s = fopen("/proc/self/status", "r");
    char line[256];
    long long v = -1;
    size_t n = strlen(field);
    while (s && fgets(line, sizeof line, s)) if (!strncmp(line, field, n) && line[n] == ':') v = strtoll(line + n + 1, NULL, base);
    if (s) fclose(s);
    return v;
}

static int floor_now(void) {
    char b[16] = {0};
    int fd = open("/proc/sys/net/ipv4/ip_unprivileged_port_start", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    int r = read(fd, b, sizeof b - 1) > 0 ? atoi(b) : -1;
    close(fd);
    return r;
}

/* bind (and listen) a TCP socket on ip:port, with SO_REUSEADDR as Go's listeners set it (the front's forwarders), and
 * SO_REUSEPORT too when `steal` (an attempt to share an address another uid holds); returns the fd, or -1 with errno */
static int bind_at(const char *ip, int port, int steal) {
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -1;
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (steal) setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, ip, &a.sin_addr);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0 || listen(s, 4) != 0) { int e = errno; close(s); errno = e; return -1; }
    return s;
}

/* open(path, flags) must FAIL with want */
static void refused_open(const char *name, const char *path, int flags, int want) {
    int fd = open(path, flags | O_CLOEXEC, 0644);
    int e = errno;
    say(fd < 0 && e == want, name, "%s", fd < 0 ? strerrorname_np(e) : "opened");
    if (fd >= 0) close(fd);
}

int main(int argc, char **argv) {
    int command = 0, secret_flag = 0, ports_flag = 0;
    for (int i=1; i<argc; i++) {
        if (!strcmp(argv[i], "run")) command = 1;
        if (!strcmp(argv[i], "-shield-secrets-fd") && i+1<argc && !strcmp(argv[i+1], "7")) secret_flag = 1;
        if (!strcmp(argv[i], "ENCLAVE_PORTS=http:8000=8000")) ports_flag = 1;
    }
    const int front = strstr(argv[0], "front") != NULL;
    struct stat st;
    const int secret = stat("/secret.id", &st) == 0;
    const int web = stat("/egress.public-web", &st) == 0;
    /* a public-web domain HAS a resolv.conf (root's), so "no new file in /etc" is checked on another name */
    const char *new_etc = web ? "/etc/host.conf" : "/etc/resolv.conf";
    char path[64];
    snprintf(path, sizeof path, "/probe-out/%s.egress", front ? "front" : "runtime");
    out = fopen(path, "w");
    if (!out) return 3;
    setvbuf(out, NULL, _IOLBF, 0);
    fprintf(out, "uid=%d secret=%d web=%d\n", (int)getuid(), secret, web);

    long long capeff = status_hex("CapEff", 16);
    say(capeff == 0, "no effective capability", "CapEff %llx", capeff);
    refused_open("the port floor is not this process's to change", "/proc/sys/net/ipv4/ip_unprivileged_port_start", O_WRONLY, EACCES);

    if (front) {
        int fl = floor_now();
        if (secret) {
            say(secret_flag, "front receives the authenticated release pipe argument", "%d", secret_flag);
            say(fl == (web ? 53 : 443), web ? "this public-web domain's namespace floor is 53" : "this secret domain's namespace floor is 443", "%d", fl);
            int a = bind_at("127.64.0.2", 443, 0), b = bind_at("127.64.0.3", 443, 0);
            if (web) {
                int dns = bind_at("127.0.0.2", 53, 0), socks = bind_at("127.0.0.2", 1080, 0);
                say(dns >= 0, "the front binds the DNS stub 127.0.0.2:53 with no capability", "%s", dns >= 0 ? "listening" : strerrorname_np(errno));
                say(socks >= 0, "the front binds the SOCKS front 127.0.0.2:1080", "%s", socks >= 0 ? "listening" : strerrorname_np(errno));
                refused_open("resolv.conf is not the front's to change", "/etc/resolv.conf", O_WRONLY, EACCES);
            }
            say(a >= 0, "the front binds 127.64.0.2:443 with no capability", "%s", a >= 0 ? "listening" : strerrorname_np(errno));
            say(b >= 0, "the front binds 127.64.0.3:443 with no capability", "%s", b >= 0 ? "listening" : strerrorname_np(errno));
            int h = open("/etc/hosts", O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC);
            static const char hosts[] = "127.0.0.1 localhost\n127.64.0.2 acct.r2.example\n";
            say(h >= 0 && write(h, hosts, sizeof hosts - 1) == (ssize_t)(sizeof hosts - 1), "the front rewrites its /etc/hosts", "%s", h >= 0 ? "written" : strerrorname_np(errno));
            if (h >= 0) close(h);
            refused_open("nsswitch.conf is not the front's to change", "/etc/nsswitch.conf", O_WRONLY, EACCES);
            refused_open("the front cannot add a file to /etc", new_etc, O_WRONLY | O_CREAT | O_EXCL, EACCES);
            fprintf(out, "done ok=%d bad=%d\n", n_ok, n_bad);
            fclose(out);
            /* only now may the runtime run: the real front writes its secrets after the forwarders listen */
            if (write(7, "bound\n", 6) != 6) return 4;
            close(7);
            sleep(5);   /* hold the listeners while the runtime checks (domexec ends the domain when either exits) */
            return 0;
        }
        say(fl == 1024, "a domain without secrets keeps the kernel's floor", "%d", fl);
        int a = bind_at("127.64.0.2", 443, 0);
        say(a < 0 && errno == EACCES, "without secrets the front cannot bind 127.64.0.2:443", "%s", a < 0 ? strerrorname_np(errno) : "listening");
        fprintf(out, "done ok=%d bad=%d\n", n_ok, n_bad);
        fclose(out);
        sleep(3);   /* let the runtime finish its report before the domain ends */
        return 0;
    }

    long long mode = status_hex("Seccomp", 10);
    say(mode == 2, "the runtime is filtered", "Seccomp %lld", mode);
    int v = socket(AF_VSOCK, SOCK_STREAM, 0);
    say(v < 0 && errno == EPERM, "the runtime has no AF_VSOCK", "%s", v < 0 ? strerrorname_np(errno) : "a socket");
    if (secret) {
        char b[8] = {0};
        ssize_t n = read(7, b, sizeof b - 1);   /* the front's go, as secretrun waits for the front's secrets */
        say(n == 6 && !strcmp(b, "bound\n"), "the runtime starts after the front's forwarders listen", "%zd bytes", n);
        int h = open("/etc/hosts", O_RDONLY | O_CLOEXEC);
        char hb[128] = {0};
        say(h >= 0 && read(h, hb, sizeof hb - 1) > 0 && strstr(hb, "127.64.0.2 acct.r2.example"), "the runtime resolves through the front's /etc/hosts", "%s", h >= 0 ? "read" : strerrorname_np(errno));
        if (h >= 0) close(h);
        refused_open("the runtime cannot change /etc/hosts", "/etc/hosts", O_WRONLY, EACCES);
        refused_open("the runtime cannot change nsswitch.conf", "/etc/nsswitch.conf", O_WRONLY, EACCES);
        refused_open("the runtime cannot add a file to /etc", new_etc, O_WRONLY | O_CREAT | O_EXCL, EACCES);
        int s = bind_at("127.64.0.2", 443, 1);
        say(s < 0 && errno == EADDRINUSE, "the runtime cannot take the front's forwarder address, even with SO_REUSEPORT", "%s", s < 0 ? strerrorname_np(errno) : "listening");
        if (web) {
            refused_open("the runtime cannot change resolv.conf", "/etc/resolv.conf", O_WRONLY, EACCES);
            int d = bind_at("127.0.0.2", 53, 1);
            say(d < 0 && errno == EADDRINUSE, "the runtime cannot take the front's DNS stub, even with SO_REUSEPORT", "%s", d < 0 ? strerrorname_np(errno) : "listening");
        }
    }
    if (command) {
        say(ports_flag, "command receives its measured HTTP port", "%d", ports_flag);
        int listener = bind_at("127.0.0.1", 8000, 0);
        say(listener >= 0, "command binds its own HTTP socket under the runtime filter", "%s", listener >= 0 ? "listening" : strerrorname_np(errno));
        if (listener >= 0) close(listener);
    }
    fprintf(out, "done ok=%d bad=%d\n", n_ok, n_bad);
    fclose(out);
    return 0;
}
