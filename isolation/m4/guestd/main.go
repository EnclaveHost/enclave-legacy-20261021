package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"enclave.host/isolation/contract"
	"enclave.host/isolation/m2/bootstrap"
	"enclave.host/isolation/m2/egress"
	"enclave.host/isolation/m2/release"
	"enclave.host/isolation/m2/vsock"
)

// realLauncher drives the M4a scripts the hardware suite scores (isolation/m4/test-m4.sh), not a reimplementation
// of them: build-app-guest.sh builds and predicts, m2/run-domain.sh boots and stops, m2/fwd forwards, and
// m2/client.mjs is the judge.
type realLauncher struct {
	m4, m2, fwd                                   string
	vcek, chain, product, minTCB, runtimeIdentity string
	runtimePins                                   map[string]string
	env                                           []string
	prefix                                        string        // the two-letter instance prefix whose units this guestd owns; "" = "gd"
	bootWait                                      time.Duration // until "DOM serving"; 0 = 180 s (release mode waits for a ticket too)
	aliveGrace                                    time.Duration // after this, a dead unit ends the wait even with no serial output; 0 = 5 s
}

func (l *realLauncher) run(ctx context.Context, dir, logName string, name string, args ...string) (string, error) {
	return l.runEnv(ctx, dir, logName, nil, name, args...)
}

func (l *realLauncher) runEnv(ctx context.Context, dir, logName string, extra []string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(append([]string{}, l.env...), extra...)
	out, err := cmd.CombinedOutput()
	_ = os.WriteFile(filepath.Join(dir, logName), out, 0o600)
	return string(out), err
}

var predicted = regexp.MustCompile(`(?m)^predicted measurement: ([0-9a-fA-F]{96})\s*$`)

func (l *realLauncher) Build(ctx context.Context, bundle, workdir string, vcpus int) (string, string, error) {
	image := filepath.Join(workdir, "guest.cpio.gz")
	out, err := l.run(ctx, workdir, "build.txt", "sh", filepath.Join(l.m4, "build-app-guest.sh"), bundle, image,
		strconv.Itoa(vcpus))
	if err != nil {
		return "", "", fmt.Errorf("build-app-guest.sh: %v", err)
	}
	raw, e := os.ReadFile(bundle)
	if e != nil {
		return "", "", e
	}
	manifest, _, e := contract.Parse(raw)
	if e != nil {
		return "", "", e
	}
	if manifest.Inference != nil {
		if e = os.WriteFile(image+".shield", []byte(manifest.Inference.Model), 0600); e != nil {
			return "", "", e
		}
	}
	m := predicted.FindStringSubmatch(out)
	if m == nil {
		return "", "", errors.New("build-app-guest.sh printed no predicted measurement")
	}
	return image, strings.ToLower(m[1]), nil
}

var hostLine = regexp.MustCompile(`unit=(\S+) cid=(\d+)`)

func (l *realLauncher) Start(ctx context.Context, image, tag, workdir string, vcpus, memMiB, cpuPct int, hostData string, cid uint32) (string, error) {
	out, err := l.runEnv(ctx, workdir, tag+".host", []string{"HOST_DATA=" + hostData, "GUEST_CID=" + strconv.FormatUint(uint64(cid), 10)},
		"sh", filepath.Join(l.m2, "run-domain.sh"),
		"start", image, "snp", tag, workdir, strconv.Itoa(vcpus), strconv.Itoa(memMiB), strconv.Itoa(cpuPct))
	m := hostLine.FindStringSubmatch(out)
	if err != nil || m == nil {
		return "", fmt.Errorf("run-domain.sh start: %v %s", err, strings.TrimSpace(out))
	}
	unit := m[1]
	if got, _ := strconv.ParseUint(m[2], 10, 32); uint32(got) != cid {
		// the ticket service and the egress server know this guest only by the CID guestd chose
		return unit, fmt.Errorf("run-domain.sh launched the guest with CID %d, not the %d guestd chose", got, cid)
	}
	serial := filepath.Join(workdir, tag+".serial")
	wait := l.bootWait
	if wait <= 0 {
		wait = 180 * time.Second
	}
	grace := l.aliveGrace
	if grace <= 0 {
		grace = 5 * time.Second
	}
	started := time.Now()
	deadline := started.Add(wait)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		b, _ := os.ReadFile(serial)
		if bytes.Contains(bytes.ReplaceAll(b, []byte{0}, nil), []byte("DOM serving")) {
			return unit, nil
		}
		// a unit that died - even before the guest printed anything (a QEMU that never booted) - ends the wait, so its
		// pool room comes back now and not after bootWait (enclave-99)
		if (len(b) > 0 || time.Since(started) > grace) && !l.Alive(unit) {
			return unit, errors.New("the guest ended during boot (see its serial log)")
		}
		time.Sleep(500 * time.Millisecond)
	}
	return unit, fmt.Errorf("the guest's front never served within %s", wait)
}

var fwdLine = regexp.MustCompile(`^FWD listening 127\.0\.0\.1:(\d+) `)

func (l *realLauncher) Forward(ctx context.Context, cid uint32, workdir string) (int, func(), error) {
	cmd := exec.Command(l.fwd, "-cid", strconv.FormatUint(uint64(cid), 10))
	out, err := cmd.StdoutPipe()
	if err != nil {
		return 0, nil, err
	}
	if err := cmd.Start(); err != nil {
		return 0, nil, err
	}
	stop := func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }
	lines := make(chan string, 16)
	go func() {
		f, _ := os.Create(filepath.Join(workdir, "fwd.log"))
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			if f != nil {
				fmt.Fprintln(f, sc.Text())
			}
			select {
			case lines <- sc.Text():
			default:
			}
		}
		if f != nil {
			f.Close()
		}
	}()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case s := <-lines:
			if m := fwdLine.FindStringSubmatch(s); m != nil {
				p, _ := strconv.Atoi(m[1])
				return p, stop, nil
			}
		case <-timeout:
			stop()
			return 0, nil, errors.New("the forwarder reported no port")
		case <-ctx.Done():
			stop()
			return 0, nil, ctx.Err()
		}
	}
}

// verifyArgs is the judge's command line. With a deployment bound, guestd's own verifier requires the report to carry
// it (--host-data): a guest that came up without its deployment id in HOST_DATA is never reported running for it.
func (l *realLauncher) verifyArgs(port int, measurement, appID, hostData, workdir string, releases []string) []string {
	args := []string{filepath.Join(l.m2, "client.mjs"),
		"https://127.0.0.1:" + strconv.Itoa(port), "--measurement", measurement, "--app-sha", appID, "--no-kds",
		"--vcek", l.vcek, "--amd-chain", l.product + "=" + l.chain, "--min-tcb", "@" + l.minTCB,
		"--runtime", l.runtimePath(releases), "--save", filepath.Join(workdir, "doc.json")}
	if hostData != "" {
		args = append(args, "--host-data", hostData)
	}
	if len(releases) > 0 {
		args = append(args, "--release", strings.Join(releases, ","))
	}
	return args
}

func (l *realLauncher) Verify(ctx context.Context, port int, measurement, appID, hostData, workdir string, releases []string) (string, string, error) {
	if _, err := l.RuntimeForReleases(releases); err != nil {
		return "", "", err
	}
	out, _ := l.run(ctx, workdir, "verify.txt", "node", l.verifyArgs(port, measurement, appID, hostData, workdir, releases)...)
	verdict, keySha := "", ""
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, "VERDICT ") && verdict == "" {
			verdict = ln
		}
		if strings.HasPrefix(ln, "RESULT spki_sha256=") && keySha == "" {
			keySha = strings.TrimPrefix(ln, "RESULT spki_sha256=")
		}
	}
	if strings.HasPrefix(verdict, "VERDICT attested") && strings.Contains(out, "\nRESULT gate=open") {
		return "attested", keySha, nil
	}
	if verdict == "" {
		verdict = "no verdict"
	}
	return "", "", errors.New(verdict)
}

func (l *realLauncher) Alive(unit string) bool {
	return unit != "" && exec.Command("systemctl", "--user", "is-active", "--quiet", unit).Run() == nil
}

func (l *realLauncher) Stop(tag, workdir string) error {
	_, err := l.run(context.Background(), workdir, tag+".stop", "sh", filepath.Join(l.m2, "run-domain.sh"), "stop",
		tag, workdir)
	return err
}

// Sweep stops the guest units a previous guestd left that were NOT adopted (keep): since F7 a guestd restart adopts
// every guest that verifies again as itself (persist.go), and only the rest end here. The supervisor re-provisions
// what it still holds a lease for.
func (l *realLauncher) Sweep(keep map[string]bool) ([]string, error) {
	prefix := l.unitPrefix()
	out, err := exec.Command("systemctl", "--user", "list-units", "--plain", "--no-legend", "--all", prefix+"*").Output()
	if err != nil {
		return nil, err
	}
	var stopped []string
	for _, u := range sweepUnits(string(out), prefix, keep) {
		if exec.Command("systemctl", "--user", "stop", u).Run() == nil {
			stopped = append(stopped, u)
		}
	}
	return stopped, nil
}

// unitPrefix is this guestd's guest units: "m2-" + its two-letter instance prefix. ONLY these are swept, so a second
// guestd on the host (another prefix) never stops the first one's guests.
func (l *realLauncher) unitPrefix() string {
	p := l.prefix
	if p == "" {
		p = "gd"
	}
	return "m2-" + p
}

// sweepUnits picks, from `systemctl list-units` output, the units a boot sweep stops: this guestd's prefix, not kept.
func sweepUnits(listing, prefix string, keep map[string]bool) []string {
	var out []string
	for _, ln := range strings.Split(listing, "\n") {
		f := strings.Fields(ln)
		if len(f) == 0 || !strings.HasPrefix(f[0], prefix) || keep[strings.TrimSuffix(f[0], ".service")] || keep[f[0]] {
			continue
		}
		out = append(out, f[0])
	}
	return out
}

// pyFetcher fetches through the platform's own CAR verifier (wasm/ipfs_fetch.py, via fetch-cid.py): the bytes a
// CID names, verified against it, or an error - never unverified bytes.
type pyFetcher struct{ script, repo, gateway, tmp string }

func (p *pyFetcher) Fetch(ctx context.Context, cid string, max int) ([]byte, error) {
	f, err := os.CreateTemp(p.tmp, "fetch-*")
	if err != nil {
		return nil, err
	}
	out := f.Name()
	f.Close()
	defer os.Remove(out)
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "python3", p.script, p.repo, cid, out, strconv.Itoa(max), p.gateway)
	cmd.Stderr = &stderr
	so, err := cmd.Output()
	if err != nil {
		return nil, errors.New(strings.TrimSpace(stderr.String()))
	}
	b, err := os.ReadFile(out)
	if err != nil {
		return nil, err
	}
	// the verifier printed the digest of what it wrote; what was read back must be that
	if want := strings.Fields(string(so)); len(want) != 3 || want[0] != "ok" || want[2] != componentSha(b) {
		return nil, fmt.Errorf("the fetcher's report %q does not describe the bytes it wrote", strings.TrimSpace(string(so)))
	}
	return b, nil
}

func sha256File(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}

func main() {
	home, _ := os.UserHomeDir()
	listen := flag.String("listen", "127.0.0.1:8095", "loopback address to serve the /vms contract on")
	root := flag.String("root", filepath.Join(home, "enclave-bench", "guestd"), "per-guest workdirs live here and only here")
	iso := flag.String("isolation", "", "the repository's isolation/ directory (required)")
	ovmf := flag.String("ovmf", filepath.Join(home, ".cache/enclave-isolation/fwbuild/OVMF.amdsev.fd"), "guest firmware; must be pinned as VERIFYING")
	vcek := flag.String("vcek", filepath.Join(home, ".cache/enclave-isolation/m3-clean/vcek.der"), "this chip's VCEK")
	product := flag.String("product", "Turin", "AMD product name for the chain")
	chain := flag.String("chain", "", "AMD cert chain PEM (default: test/fixtures/amd/<product>-cert_chain.pem)")
	minTCB := flag.String("min-tcb", filepath.Join(home, ".cache/enclave-isolation/m3-clean/min-tcb.json"), "TCB floor JSON")
	gateway := flag.String("gateway", "https://ipfs.enclave.host", "IPFS gateway for catalog components (untrusted: every block is verified)")
	authKey := flag.String("auth-key", "", "pairing key file (guestd-control/1); without it guestd runs its unauthenticated loopback-only lab mode")
	dataListen := flag.String("data-listen", "", "loopback address for the ciphertext data plane (enclave-splice/1, datapath.go); empty = none")
	dataIdle := flag.Duration("data-idle", 180*time.Second, "close a spliced connection after this long with no bytes in either direction")
	genKeyFile := flag.String("gen-key", "", "write a NEW pairing key to this file (mode 0600, never overwritten), print its kid, and exit")
	guestMem := flag.Int("guest-mem-mib", 0, "host RAM (MiB) set aside for guests: the guest pool's memory budget; unset = every create is refused (pool.go)")
	hostFloor := flag.Int("guest-host-floor-mib", 0, "a create must leave the host at least this much LIVE MemAvailable (MiB); 0 = off (pool.go). Deploy with it set, e.g. 16384")
	guestCPUs := flag.Int("guest-cpus", 0, "host cores set aside for guests: the guest pool's CPU budget, against each guest's CPUQuota; unset = every create is refused")
	legacyIso := flag.String("legacy-isolation", "", "with -release: the PREVIOUS isolation/ tree, to build the deployment guests the supervisor does not mark release (their image unchanged); empty = such a deployment is refused")
	idPrefix := flag.String("instance-prefix", "gd", "two lowercase letters for this guestd's instance ids and guest units (m2-<prefix>…); a SECOND guestd on a host needs its own, or its boot sweep stops the first one's guests")
	custodyAuthPort := flag.Uint("custody-auth-port", release.CustodyAuthPort, "vsock host port of the custody authorization service (-release); a LAB guestd uses 19445")
	ticketPort := flag.Uint("ticket-port", release.TicketPort, "vsock host port of the ticket service (-release); a LAB guestd uses its lab image's (19444) so it never holds production's")
	egressPortFlag := flag.Uint("egress-port", egressPort, "vsock host port of the egress server (-release); a LAB guestd moves it off production's too")
	isoRelease := flag.String("isolation-release", "", "the domain release(s) the -isolation tree was installed from, comma-separated: a 64-hex id, or @<release.json> (its sha256 IS the id). Named to the judge for every guest this tree builds and recorded with it; the judge's table (m2/judge.mjs LEGACY_WX_RELEASES) decides what that release may state. REQUIRED when the tree predates per-release W^X")
	legacyIsoRelease := flag.String("legacy-isolation-release", "", "the same, for the -legacy-isolation tree (REQUIRED with it when that tree predates per-release W^X)")
	unrecordedRel := flag.String("unrecorded-releases", "", "the release(s) named when ADOPTING an instance whose record names none (written by a guestd before per-release records): the pre-chain releases this host ran; empty = none named, and such a pre-chain guest is not adopted")
	directOn := flag.Bool("direct-bootstrap", false, "serve owner-committed packages on vsock 9446; requires -release and a dedicated bootstrapdirect measured tree")
	bootstrapPort := flag.Uint("bootstrap-port", bootstrap.PackagePort, "vsock port for bounded owner startup packages")
	releaseOn := flag.Bool("release", false, "deliver attested-release tickets (vsock host port 9444) and serve deployment guests' egress (9443) (release.go); off = neither, and /health says supports.release=false")
	adoptCheck := flag.Bool("adopt-check", false, "verify adoption of every existing guest without sweeping, stopping guests, or serving")
	adoptRuntimes := flag.String("adopt-runtimes", "", "explicit historical release=runtime.json pins, comma-separated; verified again on adoption")
	cpuTemplate := flag.String("cpu-template", "", "pinned CPU release template")
	shieldTemplate := flag.String("shield-template", "", "pinned measured Shield inference release template")
	shieldModel := flag.String("shield-model-file", "", "read-only public Q4 GGUF; hash verified inside the measured guest")
	shieldSHM := flag.String("shield-shm-dir", "", "directory with card-0 and card-1 masked transport rings")
	shieldRelease := flag.String("shield-release", "", "64-hex release ID for the Shield template")
	flag.Parse()
	if *guestMem < 0 || *guestCPUs < 0 || (*guestMem > 0) != (*guestCPUs > 0) {
		log.Fatal("-guest-mem-mib and -guest-cpus are set together, both positive (or neither: then every create is refused)")
	}

	if *genKeyFile != "" {
		kid, err := genKey(*genKeyFile)
		if err != nil {
			log.Fatalf("gen-key: %v", err)
		}
		fmt.Printf("kid %s written to %s (deliver the same file to the paired supervisor)\n", kid, *genKeyFile)
		return
	}

	// DISABLED unless asked for, by name. Nothing in production sets this.
	if os.Getenv("GUESTD_ENABLE") != "1" {
		log.Fatal("guestd is disabled: set GUESTD_ENABLE=1 to run it (a lab/staging backend, not a production service)")
	}
	if *iso == "" {
		log.Fatal("-isolation <repo>/isolation is required")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		log.Fatalf("-listen must be a loopback address: the /vms contract has no authentication of its own")
	}
	if *dataListen != "" {
		if h, _, err := net.SplitHostPort(*dataListen); err != nil || !net.ParseIP(h).IsLoopback() {
			log.Fatalf("-data-listen must be a loopback address: a bridge, not this process, decides who reaches it")
		}
	}
	if *chain == "" {
		*chain = filepath.Join(*iso, "..", "test/fixtures/amd", *product+"-cert_chain.pem")
	}
	// A measured table over a firmware that does not verify it proves nothing, and every structural check still
	// passes (isolation/m4/verifying-firmware.txt). So the firmware is pinned by digest, or guestd does not start.
	fw, err := sha256File(*ovmf)
	if err != nil {
		log.Fatalf("firmware: %v", err)
	}
	pins, err := os.ReadFile(filepath.Join(*iso, "m4", "verifying-firmware.txt"))
	if err != nil || !regexp.MustCompile(`(?m)^`+fw+`\s`).Match(pins) {
		log.Fatalf("firmware %s (sha256 %s) is not pinned as VERIFYING in m4/verifying-firmware.txt", *ovmf, fw)
	}
	for _, f := range []string{*vcek, *chain, *minTCB} {
		if _, err := os.Stat(f); err != nil {
			log.Fatalf("verification input missing: %v", err)
		}
	}
	if err := os.MkdirAll(filepath.Join(*root, "bin"), 0o700); err != nil {
		log.Fatal(err)
	}
	env := append(os.Environ(), "OVMF="+*ovmf)
	fwd := filepath.Join(*root, "bin", "fwd")
	build := exec.Command("go", "build", "-trimpath", "-o", fwd, "./fwd")
	build.Dir = filepath.Join(*iso, "m2")
	build.Env = append(env, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		log.Fatalf("building m2/fwd: %v %s", err, out)
	}
	wt, err := exec.LookPath("wasmtime")
	if err != nil {
		log.Fatal("no wasmtime on PATH: the guest image carries the host's runtime")
	}
	rid := filepath.Join(*root, "expected-runtime.json")
	ridOut, err := exec.Command(filepath.Join(*iso, "contract", "runtime-identity.sh"), wt).Output()
	if *cpuTemplate != "" {
		ridOut, err = os.ReadFile(filepath.Join(*cpuTemplate, "rt/runtime.json"))
	}
	if err != nil || os.WriteFile(rid, ridOut, 0o600) != nil {
		log.Fatalf("runtime identity: %v", err)
	}
	l := &realLauncher{m4: filepath.Join(*iso, "m4"), m2: filepath.Join(*iso, "m2"), fwd: fwd, vcek: *vcek,
		chain: *chain, product: *product, minTCB: *minTCB, runtimeIdentity: rid, env: env}
	l.runtimePins, err = parseRuntimePins(*adoptRuntimes)
	if err != nil {
		log.Fatal(err)
	}
	s := newServer(l, *root)
	if *cpuTemplate != "" {
		l.env = append(l.env, "APP_IMAGE_TEMPLATE="+*cpuTemplate)
	}
	if *directOn {
		if !*releaseOn || *legacyIso != "" || !filepath.IsAbs(*cpuTemplate) {
			log.Fatal("direct bootstrap requires -release, an explicit CPU template and no legacy tree")
		}
		for _, template := range []string{*cpuTemplate, *shieldTemplate} {
			if template == "" {
				continue
			}
			b, err := os.ReadFile(filepath.Join(template, "rt/direct-bootstrap.enabled"))
			if err != nil || string(b) != "1\n" {
				log.Fatal("direct bootstrap template lacks its measured mode marker")
			}
		}
	}
	if *shieldTemplate != "" || *shieldRelease != "" {
		ids, e := parseReleaseIDs(*shieldRelease)
		if e != nil || len(ids) != 1 || !filepath.IsAbs(*shieldTemplate) {
			log.Fatal("Shield needs an absolute template and exactly one pinned release")
		}
		out, e := exec.Command("python3", filepath.Join(*iso, "m4/release-manifest.py"), "verify", filepath.Dir(*shieldTemplate), "--expect", ids[0]).CombinedOutput()
		if e != nil {
			log.Fatalf("Shield release does not verify: %s", out)
		}
		model, e := os.ReadFile(filepath.Join(*shieldTemplate, "rt/shield-model"))
		if e != nil || strings.TrimSpace(string(model)) != contract.ShieldModel+"\n"+contract.Shield27BModel {
			log.Fatal("Shield release has no supported model marker")
		}
		if !filepath.IsAbs(*shieldModel) || !filepath.IsAbs(*shieldSHM) {
			log.Fatal("Shield needs absolute model and ring paths")
		}
		l.env = append(l.env, "SHIELDED_IMAGE_TEMPLATE="+*shieldTemplate, "SHIELDED_MODEL_FILE="+*shieldModel, "SHIELDED_SHM_DIR="+*shieldSHM)
		s.ShieldShareMemory = false
		if marker, err := os.ReadFile(filepath.Join(*shieldTemplate, "rt/shield-ram-admission.enabled")); err == nil && string(marker) == "1\n" {
			s.ShieldShareMemory = true
		}
		s.ShieldEnabled = true
		s.ShieldReleases = ids
		if l.runtimePins == nil {
			l.runtimePins = map[string]string{}
		}
		l.runtimePins[ids[0]] = filepath.Join(*shieldTemplate, "rt/runtime.json")
	}
	// Same executable and probe as runtime-set.sh, which emits the measured
	// marker dominit needs before passing SET flags. Legacy guests do not gain
	// this capability merely because the new release has it.
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 25*time.Second)
	probeOut, probeErr := exec.CommandContext(probeCtx, "sh", filepath.Join(*iso, "m4", "probe-set.sh"), wt).Output()
	probeCancel()
	s.RuntimeSET = probeErr == nil && string(probeOut) == "1\n"
	probeCtx, probeCancel = context.WithTimeout(context.Background(), 25*time.Second)
	probeOut, probeErr = exec.CommandContext(probeCtx, "sh", filepath.Join(*iso, "m4", "probe-mem64.sh"), wt).Output()
	probeCancel()
	s.RuntimeMem64 = probeErr == nil && string(probeOut) == "1\n"
	if *cpuTemplate != "" {
		set, e := os.ReadFile(filepath.Join(*cpuTemplate, "rt/set.enabled"))
		s.RuntimeSET = e == nil && string(set) == "1\n"
		mem, e := os.ReadFile(filepath.Join(*cpuTemplate, "rt/mem64.enabled"))
		s.RuntimeMem64 = e == nil && string(mem) == "1\n"
	}
	if why := releaseNamingRefusal(*releaseOn, *isoRelease, *legacyIso, *legacyIsoRelease); why != "" {
		log.Fatal(why)
	}
	if s.TreeReleases, err = parseReleaseIDs(*isoRelease); err != nil {
		log.Fatalf("-isolation-release: %v", err)
	}
	if *directOn {
		if len(s.TreeReleases) != 1 {
			log.Fatal("direct bootstrap requires exactly one pinned CPU release")
		}
		out, err := exec.Command("python3", filepath.Join(*iso, "m4/release-manifest.py"), "verify", filepath.Dir(*cpuTemplate), "--expect", s.TreeReleases[0]).CombinedOutput()
		if err != nil {
			log.Fatalf("direct bootstrap release does not verify: %s", out)
		}
	}
	if s.LegacyTreeReleases, err = parseReleaseIDs(*legacyIsoRelease); err != nil {
		log.Fatalf("-legacy-isolation-release: %v", err)
	}
	if s.UnrecordedReleases, err = parseReleaseIDs(*unrecordedRel); err != nil {
		log.Fatalf("-unrecorded-releases: %v", err)
	}
	// A tree whose own judge predates per-release W^X builds guests that state the LEGACY self-test; unnamed, their
	// records would say "none", and a later tree's judge would refuse them on adoption - the running guests dropped at
	// a tree switch (enclave-bf's hazard). So such a tree must be named, and a mislabel is a start-up error, not that.
	if why := needsRelease(*iso, *isoRelease); why != "" {
		log.Fatalf("-isolation-release: %s", why)
	}
	log.Printf("per-release W^X: this tree's guests are named %v; the legacy tree's %v; unrecorded adoptions %v",
		s.TreeReleases, s.LegacyTreeReleases, s.UnrecordedReleases)
	// The prefix names this guestd's instances AND its guest units, and the boot sweep below stops only those: a second
	// guestd on this host with the default prefix would stop the first one's guests. Two letters exactly, so no two
	// prefixes' unit patterns overlap.
	if !regexp.MustCompile(`^[a-z]{2}$`).MatchString(*idPrefix) {
		log.Fatalf("-instance-prefix %q: two lowercase letters", *idPrefix)
	}
	l.prefix, s.IDPrefix = *idPrefix, *idPrefix
	s.Budget = poolBudget{MemMiB: *guestMem, CPUPct: *guestCPUs * 100}
	if *hostFloor < 0 {
		log.Fatal("-guest-host-floor-mib is a MiB count, 0 or more")
	}
	s.HostFloorMiB = *hostFloor
	// F7: a previous guestd's guests are ADOPTED when they verify again as the same guest (persist.go); every other
	// guest unit is stopped and every other workdir scrubbed, as a boot sweep always did.
	actx, acancel := context.WithTimeout(context.Background(), 10*time.Minute)
	if *adoptCheck {
		dirs, err := filepath.Glob(filepath.Join(s.Root, s.idPrefix()+"*"))
		if err != nil {
			log.Fatal(err)
		}
		failed := false
		for _, dir := range dirs {
			why := s.adoptOne(context.Background(), dir)
			if why != "" {
				failed = true
				log.Printf("ADOPT REFUSED %s: %s", filepath.Base(dir), why)
			} else {
				log.Printf("ADOPT OK %s", filepath.Base(dir))
			}
		}
		for _, v := range s.vms {
			if v.stopFwd != nil {
				v.stopFwd()
			}
		}
		if failed {
			os.Exit(1)
		}
		return
	}
	keep, adopted, dropped := s.adoptOnBoot(actx)
	acancel()
	if len(adopted) > 0 {
		log.Printf("adopted %d guest(s) a previous guestd left, each verified again as the same guest: %v", len(adopted), adopted)
	}
	for _, d := range dropped {
		log.Printf("not adopted, ended: %s", d)
	}
	s.logPoolAfterRecovery() // adopted guests count against the budget, and may exceed it (pool.go: overcommitted)
	if stopped, err := l.Sweep(keep); err != nil {
		log.Fatalf("sweeping a previous run's guests: %v", err)
	} else if len(stopped) > 0 {
		log.Printf("stopped %d guest unit(s) with no adoptable record: %v", len(stopped), stopped)
	}
	s.Firmware = map[string]any{"path": *ovmf, "sha256": fw, "pinnedVerifying": true}
	// The catalog store, and the RuntimeID a derivation record must be pinned to: this host's, computed from the
	// same identity file the judge is given, by the contract's own function.
	var ident contract.RuntimeIdentity
	if err := json.Unmarshal(ridOut, &ident); err != nil {
		log.Fatalf("runtime identity: %v", err)
	}
	rtID, err := contract.RuntimeID(ident)
	if err != nil {
		log.Fatalf("runtime identity: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(*root, "store", "tmp"), 0o700); err != nil {
		log.Fatal(err)
	}
	st, err := newStore(filepath.Join(*root, "store"), &pyFetcher{script: filepath.Join(*iso, "m4", "guestd", "fetch-cid.py"),
		repo: filepath.Join(*iso, ".."), gateway: *gateway, tmp: filepath.Join(*root, "store", "tmp")}, hex.EncodeToString(rtID[:]))
	if err != nil {
		log.Fatal(err)
	}
	s.Store = st
	s.RuntimeID = hex.EncodeToString(rtID[:])
	if *dataListen != "" {
		s.Data = newDataPlane(s)
		s.Data.Idle = *dataIdle
		dl, err := net.Listen("tcp", *dataListen)
		if err != nil {
			log.Fatalf("data plane: %v", err)
		}
		log.Printf("data plane (enclave-splice/1) on %s: ciphertext only, admitted per verified instance identity", dl.Addr())
		go func() { log.Fatal(s.Data.Serve(dl)) }()
	}
	// This tree's guest front starts a DEPLOYMENT's app only after the attested release (m2/front/provision.go). A guestd
	// from this tree without -release would launch deployment guests that wait for a ticket nobody serves and then
	// power off, so it refuses to start instead (enclave-99's L5). Run it with -release, and -legacy-isolation for the
	// deployments that are not release guests.
	if !*releaseOn {
		log.Fatal("this guestd's guest image needs the attested release for every deployment guest: run it with -release " +
			"(and -legacy-isolation <previous isolation/ tree> for deployments the relay does not list)")
	}
	if *releaseOn {
		// The attested release (release.go): tickets to the ONE guest guestd launched for each deployment, and egress
		// to the origins that guest's own allowlist names. Both listen on vsock, where the peer's CID - set by this
		// host for its guests, and unforgeable by another VM - is the only identity either service takes.
		s.Release = true
		l.bootWait = 10 * time.Minute // a deployment guest waits for its ticket before its front serves
		if *legacyIso != "" {
			if _, err := os.Stat(filepath.Join(*legacyIso, "m4", "build-app-guest.sh")); err != nil {
				log.Fatalf("-legacy-isolation: %v", err)
			}
			// the legacy tree BUILDS the image (its front, its template); this tree's run-domain.sh boots it, with the
			// same kernel, firmware and command line (m1/domain.env), and a CID guestd chose
			legacy := *l
			legacy.m4 = filepath.Join(*legacyIso, "m4")
			legacy.bootWait = 0
			s.Legacy = &legacy
			if why := needsRelease(*legacyIso, *legacyIsoRelease); why != "" {
				log.Fatalf("-legacy-isolation-release: %s", why)
			}
			log.Printf("non-release deployment guests are built from %s", *legacyIso)
		}
		if *directOn {
			s.DirectBootstrap = true
			bl, err := vsock.Listen(uint32(*bootstrapPort))
			if err != nil {
				log.Fatalf("bootstrap packages: %v", err)
			}
			go func() { log.Fatal(s.serveBootstrap(context.Background(), bl, vsockCID)) }()
		} else {
			tl, err := vsock.Listen(uint32(*ticketPort))
			if err != nil {
				log.Fatalf("release tickets: %v", err)
			}
			go func() {
				log.Fatal(s.serveTickets(context.Background(), tl, vsockCID, log.New(os.Stderr, "release: ", log.LstdFlags)))
			}()
		}
		cl, err := vsock.Listen(uint32(*custodyAuthPort))
		if err != nil {
			log.Fatalf("custody authorization: %v", err)
		}
		go func() {
			log.Fatal(s.serveCustodyAuth(context.Background(), cl, vsockCID, log.New(os.Stderr, "custody: ", log.LstdFlags)))
		}()
		el, err := vsock.Listen(uint32(*egressPortFlag))
		if err != nil {
			log.Fatalf("egress: %v", err)
		}
		es := &egress.Server{
			Dialer: &egress.Dialer{Resolver: net.DefaultResolver, Own: hostAddrs, MaxConcurrent: 32, MaxPerMinute: 600},
			CIDOf:  vsockCID, Admit: s.admitCID, Log: log.New(os.Stderr, "egress: ", log.LstdFlags),
		}
		go func() { log.Fatal(es.Serve(context.Background(), el)) }()
		if *directOn {
			log.Printf("direct bootstrap ON: packages on vsock %d, egress on vsock %d", *bootstrapPort, *egressPortFlag)
		} else {
			log.Printf("attested release ON: tickets on vsock %d, egress on vsock %d (guests guestd launched only)", *ticketPort, *egressPortFlag)
		}
	}
	if *authKey != "" {
		k, err := loadKey(*authKey)
		if err != nil {
			log.Fatalf("auth-key: %v", err)
		}
		s.Auth = newControlAuth(k, time.Now)
		log.Printf("guestd-control/1: kid %s, instance %s; every request but the handshake is authenticated", s.Auth.kid, s.Auth.instance)
	} else {
		log.Print("NO pairing key: unauthenticated LAB mode, loopback only; /control/* refuses")
	}
	go func() {
		for range time.Tick(5 * time.Second) {
			s.tick()
			if s.Auth != nil {
				s.Auth.sweep()
			}
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		// F7: guests OUTLIVE this process. They run in their own user units; the next guestd adopts each that verifies
		// again as itself and ends the rest (persist.go). Ending them here would turn every guestd restart - a deploy
		// - into a relaunch of every app with a new key (seen on the production canary, 2026-09-24 20:43Z).
		// To end every guest deliberately: systemctl --user stop 'm2-<prefix>*'.
		log.Printf("exiting; guests keep running for the next guestd to adopt (end them with: systemctl --user stop '%s*')", l.unitPrefix())
		os.Exit(0)
	}()
	log.Printf("guestd serving the /vms contract on %s (firmware %s, root %s)", *listen, fw[:16], *root)
	log.Fatal(http.ListenAndServe(*listen, s))
}

// shutdown ends every guest through its lifecycle, the same single reclamation any other end takes.
func (s *server) shutdown() {
	s.mu.Lock()
	var all []*vm
	for _, v := range s.vms {
		all = append(all, v)
	}
	s.mu.Unlock()
	for _, v := range all {
		if v.lc.RequestEnd("guestd shutting down") {
			v.lc.Reclaim(func() { s.reclaim(v) })
		}
	}
	s.launching.Wait()
}

// vsockCID is a vsock stream's peer CID: for a guest this host launched, the CID guestd chose for it. Anything that is
// not a vsock stream has none (0), which neither release service admits.
func vsockCID(c net.Conn) uint32 {
	if a, ok := c.RemoteAddr().(vsock.Addr); ok {
		return a.CID
	}
	return 0
}

// hostAddrs is this host's own addresses, read at each dial: the egress dialer refuses them as destinations.
func hostAddrs() []netip.Addr {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range as {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out
}

// releaseNamingRefusal: on a -release guestd every tree must be NAMED - by the release it was installed from, or by an
// explicit `none` for a lab tree no published release came from - so that no guest is ever recorded unnamed and later
// judged under a rule its release predates (the seccomp statement after 5db18199, as the W^X scan before it). -> why
// not, or "".
func releaseNamingRefusal(releaseOn bool, isoRelease, legacyIso, legacyIsoRelease string) string {
	if releaseOn && strings.TrimSpace(isoRelease) == "" {
		return "-release needs -isolation-release: the release this tree was installed from (@<release dir>/release.json), " +
			"or `none` for a lab tree no published release came from"
	}
	if legacyIso != "" && strings.TrimSpace(legacyIsoRelease) == "" {
		return "-legacy-isolation needs -legacy-isolation-release: the release(s) that tree was installed from (@<release dir>/release.json)"
	}
	return ""
}

// parseReleaseIDs reads a release flag: comma-separated domain release ids, each 64 hex or @<release.json> (the id is
// that file's sha256, as the release publication defines it), lowercased, each once; `none` alone names none.
func parseReleaseIDs(v string) ([]string, error) {
	if strings.TrimSpace(v) == "none" {
		return nil, nil
	}
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.Split(v, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if p, ok := strings.CutPrefix(f, "@"); ok {
			b, err := os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			sum := sha256.Sum256(b)
			f = hex.EncodeToString(sum[:])
		}
		f = strings.ToLower(f)
		if !isHex(f, 32) {
			return nil, fmt.Errorf("%q is not a 64-hex release id", f)
		}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out, nil
}

// needsRelease: why guestd must not use a tree as named (flag: the raw -isolation-release value), or "". A tree whose
// own judge has no LEGACY_WX_RELEASES table predates per-release W^X: its guests state the legacy runtime self-test,
// and its OWN judge ignores --release, so a wrong name is not caught at launch - it is recorded, and a later tree's
// judge refuses the guest on adoption. So such a tree must be named, and by @<release.json> only: the id DERIVED from
// the release it was installed from, never typed (enclave-bf's residual on 89a76686).
func needsRelease(isoDir, flag string) string {
	b, err := os.ReadFile(filepath.Join(isoDir, "m2", "judge.mjs"))
	if err != nil {
		return fmt.Sprintf("cannot read the tree's judge: %v", err)
	}
	if bytes.Contains(b, []byte("LEGACY_WX_RELEASES")) {
		return ""
	}
	named := 0
	for _, f := range strings.Split(flag, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		if !strings.HasPrefix(f, "@") {
			return fmt.Sprintf("%s predates per-release W^X, so its release must be DERIVED (@<release dir>/release.json), not typed: %q", isoDir, f)
		}
		named++
	}
	if named == 0 {
		return fmt.Sprintf("%s predates per-release W^X (its judge has no LEGACY_WX_RELEASES): its guests state the legacy runtime self-test, so name the release it was installed from (@<release dir>/release.json), or a later tree's judge refuses them on adoption", isoDir)
	}
	return ""
}
