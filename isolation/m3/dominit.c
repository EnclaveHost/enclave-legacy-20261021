/* PID 1 of an M3 monitor guest (isolation/m3/PLAN.md, DESIGN.md section 12).
 *
 * M1 and M2 put one app inside one measured guest. M3 puts a MONITOR inside one measured guest and
 * loads apps into it at lease start, so the app is no longer part of the launch measurement and its
 * identity comes from what the monitor says instead (PLAN.md section 3).
 *
 * This init does the part that needs PID 1 and root, then hands over:
 *   1. mounts, including cgroup2 (the monitor gives each domain a share) and configfs (the monitor is
 *      the ONLY holder of the report interface: no domain ever sees /sys);
 *   2. loads the vsock transport (the guest's only channel to the host) and, under SNP, the report
 *      interface;
 *   3. delegates cpu, memory and pids to the cgroup subtree so the monitor can set per-domain limits;
 *   4. execs /monitor, which becomes PID 1 and does everything else.
 * Nothing here is privileged beyond what a guest kernel grants its own PID 1. */
#define _GNU_SOURCE
#include <cpuid.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <unistd.h>

static void insmod(const char *p) {
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { printf("MON insmod %s: %s\n", p, strerror(errno)); return; }
    long r = syscall(SYS_finit_module, fd, "", 4 /* MODULE_INIT_COMPRESSED_FILE */);
    if (r != 0 && errno != EEXIST) printf("MON insmod %s failed: %s\n", p, strerror(errno));
    close(fd);
}

static void write_file(const char *p, const char *s) {
    int fd = open(p, O_WRONLY);
    if (fd < 0) { printf("MON open %s: %s\n", p, strerror(errno)); return; }
    if (write(fd, s, strlen(s)) < 0) printf("MON write %s: %s\n", p, strerror(errno));
    close(fd);
}

static void lo_up(void) {
    struct ifreq ifr = {0};
    strcpy(ifr.ifr_name, "lo");
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0 || ioctl(s, SIOCGIFFLAGS, &ifr) < 0) { printf("MON ERROR lo: %s\n", strerror(errno)); return; }
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) printf("MON ERROR lo up: %s\n", strerror(errno));
    close(s);
}

static double now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

/* list_tree names what is under a directory, a few levels deep, on the current console line */
static void list_tree(const char *dir, int depth) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char p[512];
        snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
        printf(" %s", p);
        if (e->d_type == DT_DIR && depth < 3) list_tree(p, depth + 1);
    }
    closedir(d);
}

int main(void) {
    mount("proc", "/proc", "proc", 0, 0);
    mount("sysfs", "/sys", "sysfs", 0, 0);
    mount("devtmpfs", "/dev", "devtmpfs", 0, 0);
    mount("tmpfs", "/tmp", "tmpfs", 0, "size=64m");
    mount("configfs", "/sys/kernel/config", "configfs", 0, 0);
    mount("cgroup2", "/sys/fs/cgroup", "cgroup2", 0, 0);
    double boot_ms = now_ms();

    unsigned a, b, c, d;
    __cpuid(0x8000001f, a, b, c, d);
    int snp = (a >> 4) & 1;
    struct sysinfo si;
    sysinfo(&si);
    printf("\nMON snp=%d vcpus=%ld memMiB=%lu boot_ms=%.0f\n", snp, sysconf(_SC_NPROCESSORS_ONLN),
           (unsigned long)(si.totalram * si.mem_unit >> 20), boot_ms);

    insmod("/vsock.ko.zst");
    insmod("/vmw_vsock_virtio_transport_common.ko.zst");
    insmod("/vmw_vsock_virtio_transport.ko.zst");
    if (snp) {
        insmod("/tsm_report.ko.zst");
        insmod("/sev-guest.ko.zst");
    }
    lo_up();
    /* a domain's share is a child cgroup, so these controllers have to be available in the subtree */
    write_file("/sys/fs/cgroup/cgroup.subtree_control", "+cpu +memory +pids");

    char snpflag[16];
    snprintf(snpflag, sizeof snpflag, "-snp=%d", snp);   /* one argv element: Go bool flags need = */
    /* A Hyper-V child partition (windows/vbslike) has no hardware signer: its launcher names, on the
     * kernel command line, the host vsock port that signs report_data. Absent on QEMU, so nothing
     * changes there. The image is the same either way; only the launcher differs. */
    char hostflag[48] = "";
    {
        FILE *f = fopen("/proc/cmdline", "r");
        char line[1024] = "";
        if (f) { if (!fgets(line, sizeof line, f)) line[0] = 0; fclose(f); }
        char *p = strstr(line, "report_host=");
        if (p) snprintf(hostflag, sizeof hostflag, "-report-host=%d", atoi(p + 12));
        /* ON THE UKI PATH the whole command line is pinned. Under UEFI with Secure Boot off the host can replace the
         * UKI's .cmdline (LoadOptions from a boot entry) or extend it (SMBIOS type 11
         * io.systemd.stub.kernel-cmdline-extra), and the stub can add an extra initrd from files beside it on the ESP
         * (credentials, system/config extensions), unpacked under /.extra. None of that is measured
         * (isolation/m3/UEFI-BOOT.md). systemd-stub always leaves /.extra/os-release (the UKI's own .osrel), which is how
         * a stub boot is recognised; on it, a line that is not exactly the pinned one, or anything under /.extra besides
         * os-release, and this guest does not start. A direct boot (HCS linux-direct, QEMU -kernel) makes no UKI claim:
         * its loader supplies the line (OVMF prefixes "initrd=initrd"), so it is not pinned here. On the partition types run so
         * far (HCS, OpenHCL type 16) the host can read the guest's memory anyway: fail-closed hygiene, not a boundary
         * (a VBS-isolated type 1 changes that premise; see VBS-ISOLATION.md). */
        struct stat st;
        if (p && stat("/.extra", &st) == 0) {
            static const char pinned[] = "console=ttyS0 rdinit=/init loglevel=3 report_host=9001";
            size_t n = strcspn(line, "\n");
            if (n != sizeof pinned - 1 || memcmp(line, pinned, n) != 0) {
                printf("MON ERROR refusing to start: the kernel command line is not the pinned one (got \"%.*s\")\n",
                       (int)(n > 200 ? 200 : n), line);
                fflush(stdout); sync(); reboot(RB_POWER_OFF);
            }
            int other = 0;
            DIR *d = opendir("/.extra");
            struct dirent *e;
            while (d && (e = readdir(d)))
                if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..") && strcmp(e->d_name, "os-release")) other = 1;
            if (d) closedir(d);
            if (other) {
                printf("MON ERROR refusing to start: the boot stub added files under /.extra (credentials or extensions):");
                list_tree("/.extra", 0);
                printf("\n");
                fflush(stdout); sync(); reboot(RB_POWER_OFF);
            }
        }
    }
    /* A PROBE image - never a production medium - may carry /probe.ko (isolation/m3/probe/): loaded once, uncompressed,
     * after the guards above and before anything is served, and announced. The file is part of the initrd, so a probe
     * image never has a production image's hash; a production image has no such file and this does nothing. */
    {
        int fd = open("/probe.ko", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            printf("MON PROBE IMAGE: loading /probe.ko (this is not a production medium)\n");
            fflush(stdout);
            long r = syscall(SYS_finit_module, fd, "", 0);
            printf("MON PROBE finished: %s\n", r == 0 ? "loaded" : strerror(errno));
            close(fd);
        }
    }
    /* Presence is part of the measured image, not an untrusted host switch.
     * With this driver included, startup requires a normally version-checked
     * module load and every app report requires the guest TPM report. */
    char *vtpmflag = NULL;
    struct stat vtpm_stat;
    if (stat("/enclave_openhcl_tpm.ko", &vtpm_stat) == 0) {
        if (snp || !hostflag[0]) return 1;
        int fd = open("/enclave_openhcl_tpm.ko", O_RDONLY | O_CLOEXEC);
        if (fd < 0 || syscall(SYS_finit_module, fd, "", 0) != 0) {
            printf("MON ERROR required guest TPM driver failed: %s\n", strerror(errno));
            if (fd >= 0) close(fd);
            return 1;
        }
        close(fd);
        vtpmflag = "-vbs-tpm=/dev/tpm0";
    }
    char *argv[] = {"/monitor", snpflag, hostflag[0] ? hostflag : NULL, vtpmflag, NULL};
    char *envp[] = {"HOME=/tmp", "PATH=/plat", NULL};
    execve(argv[0], argv, envp);
    printf("MON ERROR exec /monitor: %s\n", strerror(errno));
    return 1;
}
