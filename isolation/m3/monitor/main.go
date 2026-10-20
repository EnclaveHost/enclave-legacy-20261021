// monitor: the one privileged component inside an M3 guest (isolation/m3/PLAN.md).
//
// M1 and M2 put one app inside one measured guest, so a verifier learned which app it was talking to
// from the launch measurement alone. M3 puts this monitor inside the measured guest and loads apps into
// it afterwards, which is what a VMPL design would also force (PLAN.md section 3: under IGVM the launch
// measurement covers the monitor and firmware, not the app). So identity moves:
//
//	the hardware signs the report -> the report's measurement names THIS monitor
//	                              -> the monitor names the app it loaded and hashed itself.
//
// Which makes three rules non-negotiable here:
//  1. the monitor is the ONLY holder of the report interface. No domain can see /sys, so no domain can
//     ask the hardware anything directly.
//  2. the app hash in a report comes from the monitor's OWN table, keyed by the kernel credentials of
//     the socket the request arrived on. A domain cannot ask for a report naming another app, because
//     the request has no field in which to say one.
//  3. the host chooses which app to load, but cannot misreport it: the monitor hashes the bytes it
//     received and names that hash.
//
// Two things follow from the monitor being privileged and shared, and both are handled here rather than
// assumed away:
//   - EVERY domain ends exactly once, however it ends. A crashed workload, a killed process tree and an
//     explicit destroy all run the same reclamation, which is idempotent and waits for the processes to
//     be gone before unmounting. A domain that died must not stay in the table, keep its port answering,
//     or hold its mounts and cgroup.
//   - work a domain asks of the monitor is BOUNDED. Callers are authenticated before their bytes are
//     parsed, requests are read under a size cap and a deadline, and reports are admitted under a global
//     and a per-domain limit. Otherwise a domain could move memory and work into the monitor, which runs
//     outside that domain's cgroup, and starve every other domain's reports.
//
// What separates one domain from another in THIS build is the guest kernel: namespaces, a uid and a
// cgroup each (see domexec.c). That is WEAKER than the VMPL separation M3b would give, and it puts the
// guest kernel inside the TCB for app-vs-app isolation — the set of things that must be correct for one
// app to stay protected from another. SNP still excludes the host from all of it.
package main

import (
	"bufio"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"enclave.host/isolation/contract"
	"enclave.host/isolation/m2/shieldconfig"
	"enclave.host/isolation/m2/vsock"
	"enclave.host/isolation/m3/vtpmclient"
)

// Bounds. A domain is untrusted, and the host is trusted only to choose what to load, so everything
// either of them sends is read under a cap and a clock.
const (
	maxReportRequest  = 1 << 10 // a request is a 64-hex binding in a small JSON object
	reportDeadline    = 20 * time.Second
	drainAfterRefusal = 1 << 10                // read this much of a refused caller's bytes so it sees the refusal, not a reset
	maxReportsTotal   = 16                     // reports in flight across all domains
	maxReportsPerDom  = 2                      // ...and from any one domain, so one cannot crowd out the rest
	maxRefusals       = 8                      // polite refusals in flight; beyond this, close at once
	drainWindow       = 250 * time.Millisecond // how long a refused peer's remaining bytes are absorbed
	maxCommandLine    = 64 << 10
	maxAppBytes       = 64 << 20
	maxControlConns   = 4
	controlDeadline   = 5 * time.Minute
	exitGrace         = 15 * time.Second // how long to wait for a killed domain's processes to go
)

// A domain's life has four states (isolation/contract lifecycle.go: starting, running, ending, ended),
// and they exist because startup and reclamation can race: a destroy can arrive while the domain is
// still being built, and its process can die during startup. The state machine is the contract's, so
// every backend ends a domain the same way; this file supplies what reclamation DOES here.

type domain struct {
	SecretDeployment string              `json:"-"`
	AppConfig        []byte              `json:"-"` // copied only from the measured bundle
	Ports            []string            `json:"ports,omitempty"`
	Inference        *contract.Inference `json:"inference,omitempty"`
	ID               int                 `json:"id"`
	Label            string              `json:"label"`
	AppSha           string              `json:"appSha256"`
	Port             uint32              `json:"port"`
	UID              int                 `json:"uid"`
	// FrontUID is the uid the domain's FRONT runs as, never the runtime's (UID): the front is the trusted component in a
	// domain and the runtime is not (enclave-87's ruling on enclave-bf's finding: a runtime sharing the front's uid could
	// obtain reports for keys of its choosing and replace the front's listen socket). Reports are answered for this uid
	// only (byUID), and the domain's /run is this uid's alone.
	FrontUID int `json:"frontUid"`
	CPU      int `json:"cpuPercent"`
	MemMiB   int `json:"memMiB"`
	// How the app runs, from the bundle the monitor hashed (never from the request): "serve" = the runtime serves a
	// wasi:http component; "run" = a wasi:cli command binds HTTP (enclave-catalog-bundle/2).
	Mode string `json:"mode"`
	HTTP int    `json:"http,omitempty"`
	// Name is the deployment name the domain may hold a WebPKI certificate for (<8 hex>.<zone>), as the LAUNCHER
	// states it at load. There is no SNP HOST_DATA on a Hyper-V partition, so this is the launcher's word, which is
	// honest only because the launcher is inside this tier's trust boundary already (T0-hv). Empty: no name.
	Name string `json:"name,omitempty"`
	// Boot is the monitor's per-boot nonce (see monitor.boot). Ids restart at 1 when the guest reboots, so an id alone
	// cannot say WHICH boot's domain it means; (boot, id) can. stop and destroy must name both.
	Boot string `json:"boot"`

	dir     string
	cgroup  string
	cmd     *exec.Cmd
	ln      *vsock.Listener
	appHash [32]byte

	// Probe: this domain runs the measured adversary probe (/plat/domprobe) instead of the app, for the isolation tests.
	// It is stated in the load answer, so a host knows which workload ran without reading the console (enclave-d1: a
	// probe domain's `mode` still says "serve", because the mode describes the bundle, not the workload).
	Probe    bool          `json:"probe,omitempty"`
	exited   chan struct{} // closed when the process tree is gone
	inFlight chan struct{} // this domain's share of concurrent report work

	life *contract.Lifecycle // starting -> running -> ending -> ended; reclamation exactly once

	// seccomp: the runtime's filter as domexec's runtime child stated it once installed (readSeccompStatement), carried
	// into every self-test this monitor measures for the domain; nil until then.
	seccomp atomic.Pointer[string]

	mu     sync.Mutex
	proc   *os.Process // a STABLE handle, set once Start returned. Never signal by raw pid.
	reaped bool        // Wait returned: the pid is gone and must never be signalled again
}

func (d *domain) lifecycle() *contract.Lifecycle {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.life == nil {
		d.life = contract.NewLifecycle(contract.Starting)
	}
	return d.life
}

// requestEnd records that a domain should end. It returns true when the caller should reclaim it now,
// and false when startup still owns it — in which case startup will reclaim it on the way out.
func (d *domain) requestEnd(why string) bool { return d.lifecycle().RequestEnd(why) }

// finishStart publishes the process handle and moves the domain to running. It returns the reason a
// reclamation asked for while startup held the domain, or "" if none did. Only ever forward: setting
// running unconditionally would resurrect a domain that had already ended.
func (d *domain) finishStart(proc *os.Process) string {
	d.mu.Lock()
	d.proc = proc
	d.mu.Unlock()
	return d.lifecycle().FinishStart()
}

// failStart takes a domain that never got going straight to ending, so the caller can reclaim it.
func (d *domain) failStart() { d.lifecycle().FailStart() }

func (d *domain) state() contract.State { return d.lifecycle().State() }

type reporter func(rd []byte) (report, certs []byte, err error)

type monitor struct {
	vtpm    *vtpmclient.Client // guest-owned hardware report channel; nil on unchanged legacy images
	mu      sync.Mutex
	doms    map[int]*domain
	byUID   map[int]*domain // by the FRONT's uid: the only caller a report is ever made for
	next    int
	snp     bool
	plat    string
	root    string
	basePrt uint32
	baseUID int

	hostPort  uint32 // non-zero: no hardware signs here; the host launcher signs report_data over vsock (T0-hv)
	tier      string // what a report from this monitor is: contract.TierSNP / TierHyperV
	format    string
	vmpl      int           // the level the PSP put in our own signed report: the level we can actually speak for
	vmplFloor int           // the lowest level this kernel will let us ask for. Its own claim, see tsmLevel
	vmpl0     string        // what happened when we asked for a report at level 0: refused, GRANTED, or n/a
	boundary  string        // the canonical tuple above, emitted ONCE and handed to every domain
	report    reporter      // the hardware path, or a stand-in under test
	tsmMu     sync.Mutex    // one configfs entry at a time
	reports   chan struct{} // global admission for report work
	refusals  chan struct{} // separate, small budget for politely closing refused callers
	// boot: 128 random bits minted when this monitor starts, returned in every load, list and state answer, and
	// REQUIRED on stop and destroy (enclave-63's G1). Domain ids are never reused within a boot, but they restart at
	// 1 after a reboot (and this kernel reboots when PID 1 dies: CONFIG_PANIC_TIMEOUT=-1), so a host holding "domain 3"
	// from an earlier boot would otherwise act on whatever the new boot numbered 3. It is not a secret and not
	// authentication: it only makes a stale reference fail as "rebooted" instead of landing on the wrong domain.
	boot string
	// noDomains, when set, is why this monitor loads no domain at all (raisePtraceScope: no Yama held at 2). main stops
	// before `ready` on it; load checks it too, so the gate does not depend on that ordering.
	noDomains string
}

var errNoHardwareReport = errors.New("no hardware report on this tier")

func main() {
	snp := flag.Bool("snp", false, "this guest is an SEV-SNP guest: hardware reports are available")
	reportHost := flag.Uint("report-host", 0, "vsock port on the HOST that signs report_data (a Hyper-V partition under windows/vbslike: no hardware signer here)")
	control := flag.Uint("control-port", 9000, "vsock port the host loads domains on")
	sock := flag.String("report-sock", "/run/monitor.sock", "unix socket domains ask for reports on")
	plat := flag.String("plat", "/plat", "read-only platform tree bind-mounted into every domain")
	root := flag.String("domains", "/domains", "directory holding one subtree per domain")
	basePort := flag.Uint("base-port", 40000, "domain N serves on this vsock port + N")
	baseUID := flag.Int("base-uid", 5000, "domain N runs as this uid + N")
	vtpmPath := flag.String("vbs-tpm", "", "required guest TPM report device for the measured VBS image")
	flag.Parse()

	m := newMonitor(*snp, *plat, *root, uint32(*basePort), *baseUID)
	if *reportHost != 0 {
		m.hostPort = uint32(*reportHost)
		m.report = m.hostReport
		m.tier, m.format = contract.TierHyperV, contract.FormatHyperV
	}
	if *vtpmPath != "" {
		if m.hostPort == 0 || m.snp {
			panic("VBS TPM transport requires the Hyper-V app backend")
		}
		var err error
		m.vtpm, err = vtpmclient.Open(*vtpmPath)
		must(err)
	}
	must(os.MkdirAll(m.root, 0o755))
	must(os.MkdirAll(filepath.Dir(*sock), 0o755))
	os.Remove(*sock)

	// The boundary self-test runs BEFORE anything can be served. It used to run after serveReports had
	// already started, which meant a domain could obtain a report before the monitor had established
	// whether anything bounded it at all.
	m.selfTest()

	rl, err := net.Listen("unix", *sock)
	must(err)
	must(os.Chmod(*sock, 0o666)) // every domain FRONT may ask (it is bind-mounted into /run, which only the front can enter); who is asking comes from the kernel, not the request
	go m.serveReports(rl)

	cl, err := vsock.Listen(uint32(*control))
	must(err)
	// ONE canonical record of the tuple, emitted exactly once. It used to appear on the MON ready line
	// too, and two sources of the same fact is one more than a checker can safely believe.
	fmt.Printf("MON boundary %s\n", m.boundary)
	// Yama's ptrace scope, set to 2 (only CAP_SYS_PTRACE may attach) and read back. It is THE guard between a tenant
	// runtime and its domain's front (the same uid), so without it there is no `ready`: the monitor stops here, as it does
	// with no vsock transport, and the line above says why (raisePtraceScope; enclave-bf's F1/F2, enclave-87's ruling).
	// load refuses on the same fact, should anything ever reach it.
	yama, ok := raisePtraceScope("/proc/sys/kernel/yama/ptrace_scope", 2)
	fmt.Printf("MON %s\n", yama)
	if !ok {
		m.noDomains = yama
		fmt.Printf("MON ERROR refusing to start: %s\n", yama)
		syscall.Sync()
		_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
		os.Exit(1)
	}
	// ...and no user namespaces and no io_uring, kernel-wide (holdSysctl; enclave-87, from enclave-bf's review of the SNP
	// guest's dominit): the runtime's seccomp filter refuses both too, and these hold for anything else in the guest.
	for _, h := range kernelHolds {
		line, held := holdSysctl(h.name, h.path, h.want, h.atLeast, h.refused, os.WriteFile)
		fmt.Printf("MON %s\n", line)
		if !held {
			m.noDomains = line
			fmt.Printf("MON ERROR refusing to start: %s\n", line)
			syscall.Sync()
			_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
			os.Exit(1)
		}
	}
	// "ready" must mean the control channel can exist. AF_VSOCK accepts a listen with NO transport registered, so a
	// guest whose kernel carries only another hypervisor's transport used to print ready and then never answer a
	// load (enclave-d1, the first UEFI boot on the NucBox). Name the transport that can carry the channel, or stop.
	transport := vsockTransport()
	if transport == "" {
		fmt.Printf("MON ERROR no vsock transport: neither Hyper-V's (hv_sock) nor virtio's is present, so no host can reach control port %d\n", *control)
		syscall.Sync()
		_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
		os.Exit(1)
	}
	// the boot nonce on its own line (the ready line's shape is parsed elsewhere): a reboot shows up in the log as a new one
	fmt.Printf("MON boot %s\n", m.boot)
	fmt.Printf("MON ready control_port=%d snp=%v transport=%s\n", *control, m.snp, transport)
	slots := make(chan struct{}, maxControlConns)
	for {
		c, err := cl.Accept()
		if err != nil {
			fmt.Printf("MON ERROR control accept: %v\n", err)
			return
		}
		if !fromHost(c) {
			c.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
			go func() { defer func() { <-slots }(); m.serveControl(c) }()
		default:
			c.Close() // the host is not owed unbounded concurrency either
		}
	}
}

// newBoot mints the per-boot nonce. getrandom blocks until the kernel's pool is ready and does not fail after that, so
// a failure here means the guest cannot mint anything unpredictable, and it must not serve.
func newBoot() string {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		panic("MON cannot mint a boot nonce: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

func newMonitor(snp bool, plat, root string, basePort uint32, baseUID int) *monitor {
	m := &monitor{doms: map[int]*domain{}, byUID: map[int]*domain{}, next: 1, snp: snp,
		plat: plat, root: root, basePrt: basePort, baseUID: baseUID,
		reports: make(chan struct{}, maxReportsTotal), refusals: make(chan struct{}, maxRefusals), boot: newBoot()}
	m.report = m.tsmReport
	m.tier, m.format = contract.TierSNP, contract.FormatSNP
	return m
}

// --- the host's control channel ----------------------------------------------------------------
// One JSON request per line. `load` is followed by exactly Size bytes of Wasm. The host picks what to
// load; it cannot choose what the monitor then says the app is.

type request struct {
	Cmd    string `json:"cmd"`
	Label  string `json:"label"`
	Name   string `json:"name"` // optional: the deployment name a certificate may be issued for (see domain.Name)
	Size   int    `json:"size"`
	CPU    int    `json:"cpu"`
	MemMiB int    `json:"mem"`
	ID     int    `json:"id"`
	// Boot: stop and destroy must carry the "boot" of the domain's load answer; see monitor.boot.
	Boot string `json:"boot"`
	// Probe runs the measured adversary probe (/plat/domprobe) as this domain's workload instead of the
	// runtime and front. It stands in for a tenant whose runtime has been compromised: native code with
	// the domain's uid and namespaces, trying to reach other domains and the monitor. The host can only
	// choose BETWEEN measured binaries, never supply one, and the probe only reports what it could reach.
	Probe bool `json:"probe"`
}

func (m *monitor) serveControl(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	enc := json.NewEncoder(c)
	for {
		c.SetDeadline(time.Now().Add(controlDeadline))
		line, err := readLine(br, maxCommandLine)
		if err != nil {
			return
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			enc.Encode(map[string]string{"error": "bad request: " + err.Error()})
			return
		}
		switch req.Cmd {
		case "load":
			d, err := m.load(br, req)
			if err != nil {
				fmt.Printf("MON ERROR load: %v\n", err)
				enc.Encode(map[string]string{"error": err.Error()})
				return // the stream position is no longer known: this connection is finished
			}
			enc.Encode(d)
		case "list":
			enc.Encode(map[string]any{"domains": m.snapshot(), "boot": m.boot})
		case "state":
			enc.Encode(m.state())
		case "stop":
			if refusal := m.otherBoot(req.Boot); refusal != nil {
				enc.Encode(refusal)
				continue
			}
			if err := m.stop(req.ID); err != nil {
				enc.Encode(map[string]string{"error": err.Error()})
				continue
			}
			enc.Encode(map[string]any{"stopped": req.ID})
		case "destroy":
			if refusal := m.otherBoot(req.Boot); refusal != nil {
				enc.Encode(refusal)
				continue
			}
			if err := m.destroy(req.ID); err != nil {
				enc.Encode(map[string]string{"error": err.Error()})
				continue
			}
			enc.Encode(map[string]any{"destroyed": req.ID})
		default:
			enc.Encode(map[string]string{"error": "unknown command " + req.Cmd})
		}
	}
}

// otherBoot refuses a stop or destroy that does not name THIS boot, touching nothing. No boot at all is refused
// too: accepting a bare id is exactly the ambiguity the nonce exists to remove. A mismatch answers `rebooted`, a
// distinct field the host reads as a KNOWN fact (every domain of the boot it named is gone), never as an error to
// retry; `boot` tells it which boot is running now.
func (m *monitor) otherBoot(b string) map[string]any {
	if b == "" {
		return map[string]any{"error": "stop and destroy name the boot as well as the id: send the \"boot\" from the " +
			"domain's load answer (ids restart at 1 when the guest reboots)", "bootRequired": true}
	}
	if b != m.boot {
		return map[string]any{"error": "this guest has rebooted since boot " + b + ": every domain of that boot is " +
			"gone, and nothing here was touched", "rebooted": true, "boot": m.boot}
	}
	return nil
}

// readLine reads one newline-terminated command, refusing anything longer than the cap rather than
// growing a buffer to fit whatever arrives.
func readLine(br *bufio.Reader, max int) ([]byte, error) {
	var out []byte
	for {
		chunk, err := br.ReadSlice('\n')
		out = append(out, chunk...)
		if len(out) > max {
			return nil, fmt.Errorf("command exceeds %d bytes", max)
		}
		if err == nil {
			return out, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}

func (m *monitor) load(br *bufio.Reader, req request) (*domain, error) {
	if m.noDomains != "" {
		return nil, fmt.Errorf("refused: %s", m.noDomains)
	}
	if req.Name != "" && !certNameOK(req.Name) {
		return nil, fmt.Errorf("name %q is not <8 lowercase hex>.<zone>", req.Name)
	}
	if req.Size <= 0 || req.Size > maxAppBytes {
		return nil, fmt.Errorf("size %d out of range (max %d)", req.Size, maxAppBytes)
	}
	app := make([]byte, req.Size)
	if _, err := io.ReadFull(br, app); err != nil {
		return nil, fmt.Errorf("reading app: %w", err)
	}
	// The monitor hashes what it actually received: ALL of it, bundle or bare artifact (contract.AppID).
	// This hash, not anything the host said, is what every report for this domain will name.
	sum := contract.AppID(app)
	// A bundle (isolation/contract) carries the manifest that decides the domain's share and the
	// artifact that runs; a bare artifact is accepted as before, with the request's numbers. A bundle
	// that does not parse -- non-canonical, or naming an artifact it does not carry -- has no identity
	// and is refused.
	artifact := app
	var manifest *contract.Manifest
	if man, art, err := contract.Parse(app); err == nil {
		manifest, artifact = &man, art
		if req.Label == "" {
			req.Label = man.Label
		}
	} else if err != contract.ErrNotBundle {
		return nil, fmt.Errorf("bundle refused: %w", err)
	}
	var appConfig []byte
	if manifest != nil {
		var err error
		appConfig, err = manifest.AppConfig()
		if err != nil {
			return nil, err
		}
	}
	pol := contract.EffectivePolicy(manifest, contract.Request{CPU: req.CPU, MemMiB: req.MemMiB})
	// Physical RAM is an availability allocation, separate from the immutable
	// catalog minimum in the hashed bundle. The launcher may raise that limit.
	if manifest != nil && req.MemMiB != 0 {
		if req.MemMiB < pol.MemMiB || req.MemMiB > 1048576 {
			return nil, fmt.Errorf("memory allocation is below the catalog minimum or outside host bounds")
		}
		pol.MemMiB = req.MemMiB
	}
	var inference *contract.Inference
	if manifest != nil {
		inference = manifest.Inference
		if inference != nil {
			if _, err := os.Stat(filepath.Join(m.plat, "shield-nucbox.enabled")); err != nil {
				return nil, fmt.Errorf("Shield profile is not in this measured image")
			}
			if inference.Model != contract.ShieldModel || inference.GPUMilli < 500 || inference.GPUMilli > 1000 {
				return nil, fmt.Errorf("NucBox Shield requires qwen2.5-0.5b-q8-gguf and 500..1000 GPU milli")
			}
			if pol.MemMiB < 8192 || pol.CPUPercent < 400 || manifest.Policy.Vcpus < 4 {
				return nil, fmt.Errorf("Shield profile requires 8192 MiB and four vCPUs")
			}
		}
	}

	m.mu.Lock()
	id := m.next
	m.next++
	m.mu.Unlock()

	// A bundle's manifest decides the run mode (contract.Parse already refused a wasi:cli bundle without a port in
	// range, and any other world); a bare artifact is served as before.
	mode, httpPort := "serve", 0
	if manifest != nil && manifest.World == contract.WorldCLI {
		mode, httpPort = "run", manifest.HTTP
	}
	// the front's uid comes from a range of its own, far above the runtimes' (UID = base + id), so no runtime uid is ever
	// a front's
	if id >= frontUIDOffset {
		return nil, fmt.Errorf("domain id %d would give its runtime a uid in the fronts' range", id)
	}
	secretDeployment := ""
	if manifest != nil {
		secretDeployment = manifest.SecretDeployment
	}
	d := &domain{SecretDeployment: secretDeployment, AppConfig: appConfig, Inference: inference, ID: id, Boot: m.boot, Label: req.Label, AppSha: hex.EncodeToString(sum[:]), appHash: sum, Mode: mode, HTTP: httpPort, Name: req.Name,
		Port: m.basePrt + uint32(id), UID: m.baseUID + id, FrontUID: m.baseUID + frontUIDOffset + id, CPU: pol.CPUPercent, MemMiB: pol.MemMiB,
		dir: filepath.Join(m.root, strconv.Itoa(id)), cgroup: "/sys/fs/cgroup/dom" + strconv.Itoa(id),
		Probe: req.Probe, exited: make(chan struct{}), inFlight: make(chan struct{}, maxReportsPerDom)}
	if manifest != nil {
		d.Ports = append([]string(nil), manifest.Ports...)
	}
	if err := m.start(d, artifact); err != nil {
		return nil, err // start() has already released whatever it managed to take
	}
	fmt.Printf("MON domain %d loaded label=%s app_sha256=%s port=%d uid=%d front_uid=%d cpu=%d%% mem=%dMiB mode=%s http=%d\n",
		d.ID, d.Label, d.AppSha, d.Port, d.UID, d.FrontUID, d.CPU, d.MemMiB, d.Mode, d.HTTP)
	return d, nil
}

// start builds the domain's root, its share, and the process tree that runs it. The domain is in the
// table BEFORE its first instruction, so however it ends — including during startup — the reaper can
// find it and retire it.
func (m *monitor) start(d *domain, app []byte) error {
	// Every failure below reclaims what this function took, rather than leaving that to a caller that
	// cannot know how far it got.
	fail := func(err error) error {
		m.abandon(d, "failed to start: "+err.Error())
		return err
	}
	for _, sub := range []string{"plat", "run", "tmp", "proc"} {
		if err := os.MkdirAll(filepath.Join(d.dir, sub), 0o755); err != nil {
			return fail(err)
		}
	}
	// The app is read-only to the domain, and so is its hash: the domain may read what it runs but
	// cannot change what the monitor will name.
	if err := os.WriteFile(filepath.Join(d.dir, "app.wasm"), app, 0o444); err != nil {
		return fail(err)
	}
	if err := os.WriteFile(filepath.Join(d.dir, "app.sha256"), []byte(d.AppSha), 0o444); err != nil {
		return fail(err)
	}
	if d.SecretDeployment != "" {
		if err := os.WriteFile(filepath.Join(d.dir, "secret.id"), []byte(d.SecretDeployment), 0444); err != nil {
			return fail(err)
		}
		// the resolver files its egress needs (writeDomainEtc): /etc/hosts is the FRONT's to fill, never the runtime's.
		// A public-web domain (its MEASURED config says so) also resolves through the front's DNS stub, and is marked
		// for domexec (the DNS port floor), secretrun (ENCLAVE_EGRESS) and the front (which checks the mode agrees).
		publicWeb := shieldconfig.PublicWebMode(string(d.AppConfig))
		if err := writeDomainEtc(d.dir, d.FrontUID, publicWeb); err != nil {
			return fail(err)
		}
		if publicWeb {
			if err := os.WriteFile(filepath.Join(d.dir, strings.TrimPrefix(shieldconfig.PublicWebMarker, "/")), []byte("1\n"), 0o444); err != nil {
				return fail(err)
			}
		}
	}
	if err := writeAppConfig(d.dir, d.AppConfig); err != nil {
		return fail(err)
	}
	if len(d.Ports) != 0 {
		if err := os.WriteFile(filepath.Join(d.dir, "app.ports"), []byte(strings.Join(d.Ports, "\n")+"\n"), 0444); err != nil {
			return fail(err)
		}
	}
	// root-owned and read-only, like the AppID: the domain reads the name it may certify but cannot change it
	if d.Name != "" {
		if err := os.WriteFile(filepath.Join(d.dir, "cert.name"), []byte(d.Name+"\n"), 0o444); err != nil {
			return fail(err)
		}
	}
	if d.Inference != nil {
		// Derived only from the hashed bundle, never from host flags/environment.
		if err := os.WriteFile(filepath.Join(d.dir, "shield.profile"), []byte(strconv.Itoa(d.Inference.GPUMilli)+"\n"), 0444); err != nil {
			return fail(err)
		}
		if err := os.Mkdir(filepath.Join(d.dir, "run", "enclave-shield"), 0755); err != nil {
			return fail(err)
		}
	}
	// the platform tree (runtime, front, domexec) read-only, and the monitor's socket, are all the
	// domain gets from outside itself
	platAt := filepath.Join(d.dir, "plat")
	if err := syscall.Mount(m.plat, platAt, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fail(fmt.Errorf("bind %s: %w", m.plat, err))
	}
	if err := syscall.Mount("", platAt, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_REC, ""); err != nil {
		return fail(fmt.Errorf("remount ro %s: %w", platAt, err))
	}
	runAt := filepath.Join(d.dir, "run")
	if d.Inference != nil {
		runAt = filepath.Join(runAt, "front")
		if err := os.Mkdir(runAt, 0700); err != nil {
			return fail(err)
		}
	}
	sockAt := filepath.Join(runAt, "monitor.sock")
	if f, err := os.OpenFile(sockAt, os.O_CREATE|os.O_RDONLY, 0o600); err == nil {
		f.Close()
	}
	if err := syscall.Mount("/run/monitor.sock", sockAt, "", syscall.MS_BIND, ""); err != nil {
		return fail(fmt.Errorf("bind report socket: %w", err))
	}
	// /run is the FRONT's alone (0700, its uid): it creates its listen socket there and reaches the report socket bind-mounted
	// there, and the runtime (another uid) can do neither - not replace the front's socket, not ask for a report
	if err := os.Chown(runAt, d.FrontUID, d.FrontUID); err != nil {
		return fail(err)
	}
	if err := os.Chmod(runAt, 0o700); err != nil {
		return fail(err)
	}
	if err := m.cgroup(d); err != nil {
		return fail(err)
	}
	// CLONE_INTO_CGROUP: the domain is inside its share before its first instruction. Writing
	// cgroup.procs after starting it would race the workloads domexec forks, and whatever won that race
	// would run outside the limit.
	cgFD, err := os.Open(d.cgroup)
	if err != nil {
		return fail(fmt.Errorf("opening cgroup: %w", err))
	}
	defer cgFD.Close()

	// THE NULL DEVICE for the domain's quiet workload (domexec.c NULL_FD, fd 3): opened HERE, in the guest's own root,
	// because domexec starts already chrooted into the domain's directory, which has no /dev and must not get one (no
	// device node and no new filesystem for the tenant). A domain that cannot have it does not start: its app's output
	// would otherwise have nowhere to go but the console. enclave-d1's canary of 4cdd5169 (252602c8): the quiet runtime
	// opened /dev/null inside the chroot, got ENOENT and exited, and every m3 domain ended before it served.
	nul, err := openNullDevice()
	if err != nil {
		return fail(err)
	}
	defer nul.Close() // the child has its own copy once started (launch); ours is only for the fork
	// THE SECCOMP STATEMENT (domexec.c SECCOMP_FD, fd 4; enclave-87: positive evidence): a pipe whose write end only the
	// runtime's child writes, once its filter is installed and before exec - domexec closes its own copy right after
	// spawning the runtime, so the front, the probe and whatever the runtime runs never hold it. What arrives goes into
	// every self-test this monitor measures for the domain (scanDomainWX).
	sr, sw, err := os.Pipe()
	if err != nil {
		return fail(fmt.Errorf("seccomp statement pipe: %w", err))
	}
	defer sw.Close() // likewise: the child has its own copy once started
	go m.readSeccompStatement(d, sr)
	ln, err := vsock.Listen(d.Port)
	if err != nil {
		return fail(fmt.Errorf("vsock port %d: %w", d.Port, err))
	}

	mode := "app"
	args := []string{strconv.Itoa(d.ID), fmt.Sprintf("%d:%d", d.UID, d.FrontUID), mode, strconv.Itoa(d.MemMiB)} // domexec: <runtime uid>:<front uid>
	switch {
	case d.Probe:
		args[2] = "probe"
	case d.Mode == "run":
		args[2] = "run"
		args = append(args, strconv.Itoa(d.HTTP))
	}
	cmd := exec.Command("/plat/domexec", args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{nul, sw} // fd 3 and fd 4 in domexec
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Chroot: d.dir,
		// its own mount, process, network, IPC and hostname namespaces. The network namespace is why
		// every domain can use 127.0.0.1:8080 without collision or reach.
		Cloneflags:   syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
		Unshareflags: syscall.CLONE_NEWNS,
		Setpgid:      true,
		UseCgroupFD:  true,
		CgroupFD:     int(cgFD.Fd()),
	}
	return m.launch(d, cmd, ln)
}

// launch starts a built domain's process tree and publishes it. Everything that can fail from here on
// abandons the domain, which is why this is separate: it is the only window in which a domain is in the
// tables but has no process, and it has to close that window whichever way it goes.
func (m *monitor) launch(d *domain, cmd *exec.Cmd, ln *vsock.Listener) error {
	// This function owns both from here on, so that abandoning the domain closes the listener too. Taking
	// the listener without recording it would leave a port answering for a domain that never ran.
	d.cmd, d.ln = cmd, ln
	// In the table before its first instruction, so a domain that dies during startup is still found
	// and reclaimed. While it is `starting`, a destroy does not tear it down: it records the request and
	// leaves it to this function, which is the only thing that knows how far the build got.
	m.register(d)
	if err := cmd.Start(); err != nil {
		m.abandon(d, "failed to start")
		return fmt.Errorf("starting domain: %w", err)
	}
	go func() {
		err := cmd.Wait()
		d.mu.Lock()
		d.reaped = true // the pid is gone from here on and must never be signalled again
		d.mu.Unlock()
		close(d.exited)
		// Whatever ended it — a crashed runtime, a killed front, domexec itself — the domain is over,
		// and everything it held goes back now rather than at some later destroy that may never come.
		m.retire(d, exitReason(err))
	}()

	// The monitor relays the domain's one port. TLS ends INSIDE the domain, so what passes here is
	// ciphertext: the monitor moves the bytes without being able to read them.
	if ln != nil {
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return // the listener is closed when the domain is retired
				}
				// Only the HOST may open a domain's port. vsock is not fully namespaced, so without this a
				// process inside one domain could connect to another domain's port and be relayed straight
				// to that domain's front — a cross-domain channel through the monitor itself.
				if !fromHost(c) {
					fmt.Printf("MON refused a connection to domain %d's port from inside the guest (%s)\n", d.ID, c.RemoteAddr())
					c.Close()
					continue
				}
				go relay(c, d.frontPath("front.sock"))
			}
		}()
	}

	// Publish the process handle and go live. If a destroy arrived while this was building, honour it
	// now — in that order, so reclamation always runs against a fully-built domain.
	if why := d.finishStart(cmd.Process); why != "" {
		m.retire(d, why)
		return fmt.Errorf("domain %d was ended during startup: %s", d.ID, why)
	}
	return nil
}

// fromHost reports whether a vsock peer is the hypervisor rather than something inside this guest.
func fromHost(c net.Conn) bool {
	a, ok := c.RemoteAddr().(vsock.Addr)
	return ok && a.CID == vsock.CIDHost
}

func exitReason(err error) string {
	if err == nil {
		return "its process tree exited"
	}
	return "its process tree exited: " + err.Error()
}

func (m *monitor) register(d *domain) {
	m.mu.Lock()
	m.doms[d.ID] = d
	m.byUID[d.FrontUID] = d
	m.mu.Unlock()
}

// deregister removes exactly this domain from both tables. Compare-and-delete, so a later domain that
// has taken the same id or uid is left alone. It reports whether the domain was still listed.
func (m *monitor) deregister(d *domain) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, listed := m.doms[d.ID]
	if m.doms[d.ID] == d {
		delete(m.doms, d.ID)
	}
	if m.byUID[d.FrontUID] == d {
		delete(m.byUID, d.FrontUID)
	}
	return listed
}

// abandon ends a domain that never got running. It goes STRAIGHT to the tables and the reclamation,
// without the starting-state deferral in requestEnd: that deferral exists to hand a domain back to
// start(), and this IS start() finishing with it. Leaving the tables matters as much as freeing the
// files — a registered domain whose files are gone would still be listed, and its uid would still
// authenticate for reports.
func (m *monitor) abandon(d *domain, why string) {
	listed := m.deregister(d)
	d.failStart()
	d.release()
	if listed {
		fmt.Printf("MON domain %d ended: %s\n", d.ID, why)
	}
}

// retire ends a domain exactly once, from whichever direction it ended: a crash, a destroy, or a failed
// start. It leaves the table first, so no new report request can find it while it is being reclaimed,
// and a request already in flight finishes against the domain it was admitted for.
func (m *monitor) retire(d *domain, why string) {
	listed := m.deregister(d)
	// Leaving the tables always happens: no new report request can find a domain that is ending. Whether
	// this caller also RECLAIMS it depends on the lifecycle — a domain still starting up belongs to
	// start(), which will reclaim it once it knows what it built.
	if !d.requestEnd(why) {
		return
	}
	if listed {
		fmt.Printf("MON domain %d ended: %s\n", d.ID, why)
	}
	d.release()
}

// release frees everything the domain holds. It runs once however often it is called, and it does not
// unmount until the processes are actually gone, because a live process holds those mounts busy.
func (d *domain) release() {
	d.lifecycle().Reclaim(func() {
		if d.ln != nil {
			d.ln.Close() // the port stops answering at once, ahead of the slower cleanup below
		}
		d.mu.Lock()
		proc, reaped := d.proc, d.reaped
		d.mu.Unlock()
		if proc != nil && !reaped {
			// Kill by CGROUP. That is the strong identity here: it names exactly this domain's
			// processes, however many there are, and it cannot be confused with anything else. A pid or
			// a process-group id can be recycled between being read and being signalled, and the signal
			// would then land on unrelated later work.
			//
			// The os.Process fallback is safe for a narrower reason, and not because it is necessarily
			// pidfd-backed — that is a runtime detail this code does not verify and should not rely on.
			// It is safe because we are the PARENT: until we reap the child, its pid is held by a zombie
			// and cannot be reused, and `reaped` above is set by the one goroutine that reaps it. So the
			// only pid we ever signal is one that is still ours.
			if err := os.WriteFile(filepath.Join(d.cgroup, "cgroup.kill"), []byte("1"), 0); err != nil {
				fmt.Printf("MON WARN domain %d cgroup.kill: %v\n", d.ID, err)
				proc.Kill() // fall back to the handle, which knows whether the process is already gone
			}
			select {
			case <-d.exited:
			case <-time.After(exitGrace):
				fmt.Printf("MON WARN domain %d did not exit within %s; reclaiming anyway\n", d.ID, exitGrace)
			}
		}
		for _, mp := range []string{d.frontPath("monitor.sock"), filepath.Join(d.dir, "plat")} {
			if err := syscall.Unmount(mp, syscall.MNT_DETACH); err != nil &&
				!errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOENT) {
				fmt.Printf("MON WARN domain %d unmount %s: %v\n", d.ID, mp, err)
			}
		}
		if err := os.RemoveAll(d.dir); err != nil {
			fmt.Printf("MON WARN domain %d removing %s: %v\n", d.ID, d.dir, err)
		}
		// a cgroup can only be removed once the kernel has reaped the last process in it
		for i := 0; ; i++ {
			err := os.Remove(d.cgroup)
			if err == nil || errors.Is(err, syscall.ENOENT) || os.IsNotExist(err) {
				break
			}
			if i == 50 {
				fmt.Printf("MON WARN domain %d cgroup %s not removed: %v\n", d.ID, d.cgroup, err)
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
}

func relay(c net.Conn, frontSock string) {
	defer c.Close()
	up, err := net.DialTimeout("unix", frontSock, 5*time.Second)
	if err != nil {
		return // the domain is not serving (yet, or any more): the client sees a closed connection
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, c); done <- struct{}{} }()
	go func() { io.Copy(c, up); done <- struct{}{} }()
	<-done
}

func (m *monitor) cgroup(d *domain) error {
	if err := os.MkdirAll(d.cgroup, 0o755); err != nil {
		return err
	}
	// cpu.max is "quota period": the ledger's cpuShare lands here, as in M1
	writes := [][2]string{
		{"cpu.max", fmt.Sprintf("%d 100000", d.CPU*1000)},
		{"memory.max", strconv.Itoa(d.MemMiB << 20)},
		{"pids.max", "128"},
	}
	for _, w := range writes {
		if err := os.WriteFile(filepath.Join(d.cgroup, w[0]), []byte(w[1]), 0); err != nil {
			return fmt.Errorf("%s: %w", w[0], err)
		}
	}
	return nil
}

// stop ends a domain the gentle way: signal its FRONT, which stops accepting, and let the domain's init
// notice its child is gone and wind the rest down. If it does not go within the grace period, retire
// kills it anyway — a lease that has ended has ended.
func (m *monitor) stop(id int) error {
	m.mu.Lock()
	d := m.doms[id]
	m.mu.Unlock()
	if d == nil {
		return fmt.Errorf("no domain %d", id)
	}
	d.mu.Lock()
	proc := d.proc
	d.mu.Unlock()
	if proc == nil || d.state() != contract.Running {
		fmt.Printf("MON domain %d stop: not running yet; ending it outright\n", d.ID)
		m.retire(d, "stopped at lease end")
		return nil
	}
	// Signal the domain's INIT through the handle we hold, and let it pass SIGTERM to the front. Hunting
	// for the front's pid in cgroup.procs and /proc would mean signalling a number that could have been
	// recycled between the read and the kill; this uses an identity we own.
	fmt.Printf("MON domain %d stop: signalling its init to wind down\n", d.ID)
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		fmt.Printf("MON domain %d stop: %v; ending it outright\n", d.ID, err)
		m.retire(d, "stopped at lease end")
		return nil
	}
	select {
	case <-d.exited:
		fmt.Printf("MON domain %d stopped gracefully\n", d.ID)
	case <-time.After(10 * time.Second):
		fmt.Printf("MON domain %d did not wind down in 10s; ending it outright\n", d.ID)
	}
	m.retire(d, "stopped at lease end")
	return nil
}

func (m *monitor) destroy(id int) error {
	m.mu.Lock()
	d := m.doms[id]
	m.mu.Unlock()
	if d == nil {
		return fmt.Errorf("no domain %d", id)
	}
	m.retire(d, "destroyed at lease end")
	return nil
}

func (m *monitor) snapshot() []*domain {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*domain, 0, len(m.doms))
	for _, d := range m.doms {
		out = append(out, d)
	}
	return out
}

// state is what the guest looks like from inside: enough for the harness to prove that a domain which
// crashed or was destroyed left nothing behind.
func (m *monitor) state() map[string]any {
	names := []string{}
	if dirs, err := os.ReadDir(m.root); err == nil {
		for _, e := range dirs {
			names = append(names, e.Name())
		}
	}
	cgroups := 0
	if cg, err := os.ReadDir("/sys/fs/cgroup"); err == nil {
		for _, e := range cg {
			if e.IsDir() && strings.HasPrefix(e.Name(), "dom") {
				cgroups++
			}
		}
	}
	mounts := 0
	if mi, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		for _, line := range strings.Split(string(mi), "\n") {
			if strings.Contains(line, m.root+"/") {
				mounts++
			}
		}
	}
	procs := 0
	if pd, err := os.ReadDir("/proc"); err == nil {
		for _, e := range pd {
			if _, err := strconv.Atoi(e.Name()); err != nil {
				continue
			}
			// userspace processes only: kernel threads have an empty cmdline
			if b, err := os.ReadFile("/proc/" + e.Name() + "/cmdline"); err == nil && len(b) > 0 {
				procs++
			}
		}
	}
	memTotal, memAvail := 0, 0
	if mi, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(mi), "\n") {
			var into *int
			switch {
			case strings.HasPrefix(line, "MemTotal:"):
				into = &memTotal
			case strings.HasPrefix(line, "MemAvailable:"):
				into = &memAvail
			default:
				continue
			}
			f := strings.Fields(line)
			if len(f) >= 2 {
				if kb, err := strconv.Atoi(f[1]); err == nil {
					*into = kb / 1024
				}
			}
		}
	}
	m.mu.Lock()
	n := len(m.doms)
	m.mu.Unlock()
	return map[string]any{"domains": n, "dirs": names, "cgroups": cgroups, "mounts": mounts,
		"userspace_procs": procs, "mem_total_mib": memTotal, "mem_available_mib": memAvail, "boot": m.boot}
}

// --- reports ------------------------------------------------------------------------------------
// A domain sends 32 bytes of binding (sha256 of its TLS key SPKI and the verifier's nonce) and nothing
// else (contract.ReportRequest). There is no field for the app, because the app is not the domain's to
// state; anything else the request carries is not read.

func (m *monitor) serveReports(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		// Admission BEFORE a goroutine exists: a flood must not make the monitor allocate one stack per
		// connection.
		select {
		case m.reports <- struct{}{}:
			go func() {
				refused := m.oneReport(c)
				// The global slot goes back BEFORE anything slow happens. A refused caller is then
				// closed politely on a separate, small budget, so one domain's refusals cannot occupy
				// the budget that every other domain's reports need.
				<-m.reports
				if refused {
					m.closePolitely(c)
					return
				}
				c.Close()
			}()
		default:
			// NEVER in the accept loop: answering and draining here would stall every other tenant's
			// connection behind one slow peer.
			answer(c, "monitor is at its report limit")
			m.closePolitely(c)
		}
	}
}

func answer(c net.Conn, why string) {
	c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	json.NewEncoder(c).Encode(map[string]string{"error": why})
}

// closePolitely absorbs a bounded amount of whatever a refused peer was still sending, so that closing
// the connection delivers the answer instead of resetting it — on its own small budget, and never while
// holding a report slot. When that budget is full, the connection is simply closed: a refused caller is
// owed an answer, not an unbounded amount of the monitor's attention.
func (m *monitor) closePolitely(c net.Conn) {
	select {
	case m.refusals <- struct{}{}:
		go func() {
			defer func() { <-m.refusals }()
			c.SetReadDeadline(time.Now().Add(drainWindow))
			io.Copy(io.Discard, io.LimitReader(c, drainAfterRefusal))
			c.Close()
		}()
	default:
		c.Close()
	}
}

// oneReport answers one request. It returns true when the answer was a refusal, so the caller can give
// the global slot back and then close the connection on the refusal budget instead of this one.
func (m *monitor) oneReport(c net.Conn) (refused bool) {
	c.SetDeadline(time.Now().Add(reportDeadline))
	enc := json.NewEncoder(c)

	// 1. WHO, before anything the caller sent is parsed. Peer credentials come from the kernel and cost
	//    one syscall; parsing first would let an unauthenticated caller spend the monitor's memory.
	uid, err := peerUID(c)
	if err != nil {
		enc.Encode(map[string]string{"error": "no peer credentials: " + err.Error()})
		return true
	}
	m.mu.Lock()
	d := m.byUID[uid]
	m.mu.Unlock()
	if d == nil {
		// only a domain's FRONT is answered: a runtime's uid, root, or anything else on this guest is either a bug or an
		// attempt to obtain a report without being a domain's front
		fmt.Printf("MON refused report request from uid %d (not a domain's front)\n", uid)
		enc.Encode(map[string]string{"error": "caller is not a domain's front"})
		return true
	}

	// 2. this domain's own share of concurrent work, so one domain cannot crowd out the others
	select {
	case d.inFlight <- struct{}{}:
		defer func() { <-d.inFlight }()
	default:
		enc.Encode(map[string]string{"error": "too many concurrent report requests from this domain"})
		return true
	}

	// 3. only now, and only a bounded number of bytes
	var raw json.RawMessage
	if err := json.NewDecoder(io.LimitReader(c, maxReportRequest)).Decode(&raw); err != nil {
		enc.Encode(map[string]string{"error": "bad request: " + err.Error()})
		return true
	}
	bind, err := contract.ParseReportRequest(raw)
	if err != nil {
		enc.Encode(map[string]string{"error": err.Error()})
		return true
	}
	if !m.snp && m.hostPort == 0 {
		enc.Encode(map[string]string{"error": errNoHardwareReport.Error()})
		return true
	}
	// [0:32] the domain's own key, bound to the verifier's challenge; [32:64] the app THIS monitor
	// loaded for THIS domain (contract.ReportData: the same 64 bytes on every backend)
	rdArr := contract.ReportData(bind, d.appHash)
	rd := rdArr[:]
	rep, certs, err := m.report(rd)
	if err != nil {
		enc.Encode(map[string]string{"error": err.Error()})
		return true
	}
	out := map[string]string{"report": base64.StdEncoding.EncodeToString(rep), "tier": m.tier, "format": m.format}
	if len(certs) > 0 {
		out["certs"] = base64.StdEncoding.EncodeToString(certs)
	}
	// The tuple travels WITH the report, so it can reach a verifier over the domain's attested TLS rather
	// than only on a serial console the HOST owns and could have written. It remains the measured
	// monitor's own word about its own probe; DESIGN.md states exactly what that is and is not worth.
	out["boundary"] = m.boundary
	// ...and so does this domain's W^X scan, made NOW by the monitor (root), because the front runs as its own uid
	// and cannot read the runtime (enclave-bf's finding on the front uid; enclave-87's ruling). The front puts it in
	// the document's RuntimeSelfTest; it refuses the document on anything but a clean scan.
	out["wx"] = m.scanDomainWX(d)
	enc.Encode(out)
	return false
}

// scanDomainWX is the W^X scan of ONE domain: every process in its cgroup (cgroup.procs), each read in full
// (contract.ScanWX: a process whose mappings cannot be read FAILS the scan; only one proven gone is skipped), each
// counted by role from its uid - the runtime (the domain's uid), the front (its own), init (domexec, root). ->
// "wx=clean maps=N runtime=R front=F init=I scope=cgroup:/domN", "wx=found pid P (role): <line>", or "wx=error: why".
// readSeccompStatement takes the one statement domexec's runtime child writes on fd 4 (to EOF: its exec closes it).
func (m *monitor) readSeccompStatement(d *domain, r *os.File) {
	defer r.Close()
	line, _ := bufio.NewReader(io.LimitReader(r, 256)).ReadString('\n')
	if line == "" {
		return // no filtered runtime (a probe domain), or it failed before its statement: the self-test states none
	}
	h, err := contract.ParseSeccompStatement([]byte(line))
	if err != nil {
		fmt.Printf("MON dom%d ERROR the runtime's seccomp statement: %v\n", d.ID, err)
		return
	}
	d.seccomp.Store(&h)
	fmt.Printf("MON dom%d seccomp: runtime filter installed (sha256 %s)\n", d.ID, h)
}

func (m *monitor) scanDomainWX(d *domain) string {
	raw, err := os.ReadFile(filepath.Join(d.cgroup, "cgroup.procs"))
	if err != nil {
		return "wx=error: the domain's cgroup: " + err.Error()
	}
	var pids []int
	for _, l := range strings.Fields(string(raw)) {
		if pid, perr := strconv.Atoi(l); perr == nil {
			pids = append(pids, pid)
		}
	}
	scope := "cgroup:/" + filepath.Base(d.cgroup)
	scan, err := contract.ScanWX(scope, pids, func(pid int) (string, error) {
		uid, err := contract.UIDOf(pid)
		if err != nil {
			return "", err
		}
		switch uid {
		case d.UID:
			return "runtime", nil
		case d.FrontUID:
			return "front", nil
		case 0:
			return "init", nil
		}
		return "other", nil
	})
	if err != nil {
		return "wx=error: " + err.Error()
	}
	if scan.Found != "" {
		return "wx=found " + scan.Found
	}
	// the runtime's filter: on every runtime process NOW (its Seccomp mode), and which one (domexec's statement)
	if err := scan.CheckRuntimeFiltered(); err != nil {
		return "wx=error: " + err.Error()
	}
	if h := d.seccomp.Load(); h != nil {
		scan.Seccomp = *h
	}
	return scan.Clean()
}

func peerUID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if serr != nil {
		return 0, serr
	}
	return int(cred.Uid), nil
}

// tsmLevel reads configfs-tsm's `privlevel_floor`: the lowest level this guest may request a report for.
// By default that is the guest's own VMPL, because arch/x86/coco/sev/core.c sets the VMPCK id from
// snp_vmpl and drivers/virt/coco/sev-guest/sev-guest.c copies it into privlevel_floor.
//
// It is NOT evidence of anything. vmpck_id is a module parameter (sev_guest.vmpck_id=N), so this number
// is the guest kernel's own claim about itself and whoever controls that kernel's command line chooses
// it. We read it because we need a level to ASK for, not because it proves a level. What a verifier
// pins is the VMPL field inside the signed report, and what bounds us from above is being refused at
// level 0 (see vmpl0 in main). The attribute only exists when the provider supports levels at all, so
// a missing file is an answer too.
func (m *monitor) tsmLevel() (int, error) {
	m.tsmMu.Lock()
	defer m.tsmMu.Unlock()
	dir := fmt.Sprintf("/sys/kernel/config/tsm/report/level%d", time.Now().UnixNano())
	if err := os.Mkdir(dir, 0o755); err != nil {
		return 0, err
	}
	defer os.Remove(dir)
	b, err := os.ReadFile(dir + "/privlevel_floor")
	if err != nil {
		return 0, fmt.Errorf("privlevel_floor: %w", err)
	}
	lvl, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, fmt.Errorf("privlevel_floor %q: %w", b, err)
	}
	return lvl, nil
}

// tsmReport asks the PSP through configfs-tsm. One entry per request, used under a lock, so an outblob
// always belongs to the inblob just written. No domain can reach this: /sys is not in any domain's
// mount namespace.
func (m *monitor) tsmReport(rd []byte) ([]byte, []byte, error) {
	return m.tsmReportAt(m.vmplFloor, rd)
}

// tsmReportAt is tsmReport for one named level. Asking for a level we are not entitled to must fail, and
// the startup probe depends on that failing rather than on anyone's claim about it.
func (m *monitor) tsmReportAt(level int, rd []byte) ([]byte, []byte, error) {
	m.tsmMu.Lock()
	defer m.tsmMu.Unlock()
	dir := fmt.Sprintf("/sys/kernel/config/tsm/report/mon%d", time.Now().UnixNano())
	if err := os.Mkdir(dir, 0o755); err != nil {
		return nil, nil, err
	}
	defer os.Remove(dir)
	// Ask for the report at the lowest level this kernel allows us, rather than letting it default: under
	// an SVSM the default 0 is below our floor and the kernel refuses it outright. A verifier is told
	// which level to expect and refuses anything else (relay/snp-verify.mjs expectedVmpl), so the two
	// have to agree deliberately.
	if level > 0 {
		if err := os.WriteFile(dir+"/privlevel", []byte(strconv.Itoa(level)), 0); err != nil {
			return nil, nil, fmt.Errorf("privlevel %d: %w", level, err)
		}
	}
	if err := os.WriteFile(dir+"/inblob", rd, 0); err != nil {
		return nil, nil, err
	}
	rep, err := os.ReadFile(dir + "/outblob")
	if err != nil {
		return nil, nil, err
	}
	certs, _ := os.ReadFile(dir + "/auxblob")
	return rep, certs, nil
}

// selfTest establishes, once, which privilege level this guest is at and whether anything more privileged
// is above it - and REFUSES TO RUN if the answer is incoherent. Three facts, worth three different amounts:
//
//	vmpl_floor  what this kernel says (tsmLevel). Cheap, and NOT evidence: a module parameter sets it.
//	vmpl        the level the PSP wrote into our own signed report. Signed, so a verifier can pin it - but
//	            a guest at VMPL0 holds every VMPCK and can request a report naming a LOWER level, so on its
//	            own this shows nothing about confinement.
//	vmpl0       whether we can obtain a report at level 0 AT ALL. This was documented here as "the one part
//	            that cannot be faked downwards, because our secrets page holds no VMPCK0 unless we really are
//	            at VMPL0". That is WRONG, measured 2026-09-23: tsm-report refuses a privlevel below its floor
//	            in its own check, and the floor is set by sev-guest's vmpck_id module parameter, so no VMPCK
//	            is consulted. A plain SNP guest at VMPL0 with vmpck_id=2 produces this exact tuple. The
//	            refusal is still worth PRINTING - an incoherent tuple is a fault in measured code, and this
//	            monitor still refuses to serve on one - but it does not establish confinement. The SVSM is
//	            identified by the launch measurement; see isolation/DESIGN.md and judge.mjs checkBoundary.
//
// Note what this monitor does NOT do: it only ever requests reports at its own floor (tsmReport passes
// m.vmplFloor). The measured code therefore cannot mint a downward-claiming report even if asked to.
func (m *monitor) selfTest() {
	if m.hostPort != 0 {
		// A Hyper-V child partition under the Windows launcher. No hardware signer and no privilege
		// levels: the launcher in the root partition signs, and says so. The tuple keeps the same shape
		// so the same gate reads it. It names no partition KIND: this guest boots the same payload in an HCS
		// child, a UEFI/OpenHCL partition or a KVM test guest and cannot tell which, so the kind is the
		// launcher's to state in the report it signs (it used to print "partition=hcs-child" everywhere).
		// hv_isolation/paravisor are the hypervisor's STATED configuration (hvisolation.go): they tell a
		// VBS-isolated partition from an unisolated OpenHCL one, and never change host_excluded.
		m.vmpl, m.vmplFloor, m.vmpl0 = -1, -1, "n/a"
		hv := readHvIsolation()
		fmt.Printf("MON hv %s\n", hv.raw())
		m.boundary = "tier=t0-hv vmpl=n/a vmpl_floor=n/a vmpl0=n/a host_excluded=no " + hv.fields()
		return
	}
	if !m.snp {
		m.vmpl, m.vmplFloor, m.vmpl0 = -1, -1, "n/a"
		m.boundary = "tier=t0 vmpl=n/a vmpl_floor=n/a vmpl0=n/a"
		return
	}
	m.vmpl = -1
	if lvl, err := m.tsmLevel(); err == nil {
		m.vmplFloor = lvl
	} else {
		m.vmplFloor = -1
		fmt.Printf("MON WARN could not read this guest's privilege level floor: %v\n", err)
	}
	if rep, _, err := m.tsmReport(make([]byte, 64)); err == nil {
		m.vmpl = reportVmpl(rep)
	} else {
		fmt.Printf("MON WARN could not read our own level from a report: %v\n", err)
	}
	m.vmpl0 = "n/a"
	if m.vmplFloor > 0 {
		if _, _, err := m.tsmReportAt(0, make([]byte, 64)); err == nil {
			m.vmpl0 = "GRANTED" // we hold VMPL0 while claiming to sit beneath something. Fatal.
		} else {
			m.vmpl0 = "refused"
		}
	}
	m.boundary = fmt.Sprintf("tier=t1 vmpl=%d vmpl_floor=%d vmpl0=%s", m.vmpl, m.vmplFloor, m.vmpl0)
	if why := boundaryFault(m.vmpl, m.vmplFloor, m.vmpl0); why != "" {
		fmt.Printf("MON BOUNDARY FAULT %s: %s\n", m.boundary, why)
		fmt.Printf("MON refusing to serve: no domain may get a report from a monitor that cannot say what bounds it\n")
		os.Exit(1)
	}
}

// boundaryFault returns "" when the three facts are coherent, and otherwise why they are not. Pure and
// separate from the hardware, so every bad case is testable without any.
//
// The rules, and what each is for:
//   - vmpl0 == "GRANTED" is always fatal: we can obtain a VMPL0 report, so nothing is above us, whatever
//     level our own report claims.
//   - floor > 0 demands vmpl == floor AND vmpl0 == "refused". A probe that did not run ("n/a") or a report
//     we could not read (-1) is a FAILURE, not a pass: silence is never evidence.
//   - floor == 0 demands vmpl == 0. A floor of 0 with a report claiming some lower privilege level is
//     precisely the downward-claim forgery, so it is refused rather than reported.
func boundaryFault(vmpl, floor int, probe string) string {
	switch probe {
	case "refused", "GRANTED", "n/a":
	default:
		return fmt.Sprintf("vmpl0=%q is not one of refused, GRANTED, n/a", probe)
	}
	if probe == "GRANTED" {
		return "this guest CAN obtain a report at VMPL0, so nothing more privileged is above it"
	}
	if floor < 0 {
		return "the kernel would not say which privilege level this guest is at"
	}
	if vmpl < 0 {
		return "could not read our own privilege level out of a signed report"
	}
	if floor == 0 {
		if vmpl != 0 {
			return fmt.Sprintf("the floor is 0, so we are at VMPL0, but our report claims VMPL%d: a guest at VMPL0 can request a lower level, and that is a forgery rather than confinement", vmpl)
		}
		return ""
	}
	if vmpl != floor {
		return fmt.Sprintf("our report says VMPL%d but the kernel's floor is %d; the two have to agree", vmpl, floor)
	}
	if probe != "refused" {
		return fmt.Sprintf("the floor is %d, so a report at VMPL0 must have been REFUSED, but the probe result was %q", floor, probe)
	}
	return ""
}

// reportVmpl reads the VMPL field out of an SNP attestation report (table 22: 4 bytes little-endian at
// offset 0x30). This is the PSP's word, inside the signed region, so a verifier can pin it -- which is
// not the same as it proving the guest is confined: a guest AT VMPL0 holds every VMPCK and can therefore
// ask for a report naming a lower level. Downward claims are cheap; being refused at level 0 is not.
func reportVmpl(rep []byte) int {
	if len(rep) < 0x34 {
		return -1
	}
	return int(binary.LittleEndian.Uint32(rep[0x30:0x34]))
}

// vsockTransport names the host-guest vsock transports this kernel can actually use, from sysfs: Hyper-V's hv_sock
// driver (VMBus, built into the NucBox's kernel) and a device bound to virtio's (QEMU/KVM). "" when there is neither.
func vsockTransport() string {
	var t []string
	if _, err := os.Stat("/sys/bus/vmbus/drivers/hv_sock"); err == nil {
		t = append(t, "hv_sock")
	}
	if ents, err := os.ReadDir("/sys/bus/virtio/drivers/vmw_vsock_virtio_transport"); err == nil {
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), "virtio") {
				t = append(t, "virtio")
				break
			}
		}
	}
	return strings.Join(t, "+")
}

func must(err error) {
	if err != nil {
		fmt.Printf("MON ERROR %v\n", err)
		os.Exit(1)
	}
}

// hostReport is the report backend of a Hyper-V child partition (windows/vbslike): nothing in the guest
// signs, so report_data goes to the host launcher over the guest's only channel and comes back inside a
// document the launcher signed with its own key. The launcher knows which partition asked from the
// connection itself, and refuses to sign an app hash it did not load into that partition. What comes back
// is the signed JSON, carried in the same `report` field the SNP path uses for the PSP's bytes.
func (m *monitor) hostReport(rd []byte) ([]byte, []byte, error) {
	c, err := vsock.Dial(vsock.CIDHost, m.hostPort)
	if err != nil {
		return nil, nil, fmt.Errorf("host report service: %w", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(c).Encode(map[string]string{"abi": contract.ABI, "reportData": hex.EncodeToString(rd)}); err != nil {
		return nil, nil, err
	}
	var resp struct {
		Report json.RawMessage `json:"report"`
		Error  string          `json:"error"`
	}
	if err := json.NewDecoder(bufio.NewReader(c)).Decode(&resp); err != nil {
		return nil, nil, fmt.Errorf("host report service: %w", err)
	}
	if resp.Error != "" {
		return nil, nil, errors.New("host report service: " + resp.Error)
	}
	if len(resp.Report) == 0 {
		return nil, nil, errors.New("host report service: empty answer")
	}
	if m.vtpm != nil {
		// rd is composed by oneReport from the authenticated front's binding and
		// this monitor's own app hash. The host never supplies either report input.
		hardware, err := m.vtpm.Report(rd)
		if err != nil {
			return nil, nil, fmt.Errorf("guest VBS report: %w", err)
		}
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(resp.Report, &envelope); err != nil || envelope == nil {
			return nil, nil, errors.New("invalid launcher report envelope")
		}
		// Supplement outside the launcher's signed doc. Existing judges retain
		// their existing verdict; only a VBS-aware verifier may use this evidence.
		envelope["vbsVmReport"], _ = json.Marshal(base64.StdEncoding.EncodeToString(hardware))
		raw, err := json.Marshal(envelope)
		return raw, nil, err
	}
	return []byte(resp.Report), nil, nil
}

// certNameOK: <8 lowercase hex>.<zone>, the app-zone name shape (isolation/m2/front certs.go nameFromHostData), at
// most 253 bytes, zone labels of lowercase letters, digits and hyphens.
func certNameOK(n string) bool {
	if len(n) > 253 || len(n) < 10 || n[8] != '.' {
		return false
	}
	for _, c := range n[:8] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	for _, lab := range strings.Split(n[9:], ".") {
		if lab == "" || len(lab) > 63 || lab[0] == '-' || lab[len(lab)-1] == '-' {
			return false
		}
		for _, c := range lab {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// openNullDevice opens /dev/null read-write and checks it IS the null device (character device 1:3): a domain's quiet
// workload gets it as its stdio (domexec.c NULL_FD), so anything else - a regular file an attacker left in the guest's
// /dev, a missing node - refuses the domain instead of reaching its output somewhere.
func openNullDevice() (*os.File, error) { return openNullDeviceAt("/dev/null") }

func openNullDeviceAt(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("opening %s for the domain's quiet workload: %w", path, err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		f.Close()
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFCHR || unixMajor(uint64(st.Rdev)) != 1 || unixMinor(uint64(st.Rdev)) != 3 {
		f.Close()
		return nil, fmt.Errorf("%s is not the null device (mode %o, rdev %d:%d): the domain is not started",
			path, st.Mode, unixMajor(uint64(st.Rdev)), unixMinor(uint64(st.Rdev)))
	}
	return f, nil
}

// Linux's encoding of a device number (glibc gnu_dev_major/minor), without a dependency on x/sys/unix.
func unixMajor(dev uint64) uint32 { return uint32((dev>>8)&0xfff) | uint32((dev>>32)&^0xfff) }
func unixMinor(dev uint64) uint32 { return uint32(dev&0xff) | uint32((dev>>12)&^0xff) }

// kernelHolds: the kernel settings beside Yama that the monitor starts only with. Nothing in the guest needs either:
//   - user.max_user_namespaces caps USER namespaces only. The monitor clones each domain with new mount, pid, net, ipc and
//     uts namespaces as root, never a user namespace, so the cap of 0 does not touch it;
//   - io_uring: the Go monitor and front poll with epoll, and wasmtime runs on tokio/mio, also epoll.
var kernelHolds = []struct {
	name, path string
	want       int
	atLeast    bool
	refused    string
}{
	{"user.max_user_namespaces", "/proc/sys/user/max_user_namespaces", 0, false, "domains refused (a runtime could create a user namespace)"},
	{"kernel.io_uring_disabled", "/proc/sys/kernel/io_uring_disabled", 2, true, "domains refused (a runtime could use io_uring)"},
}

// holdSysctl sets the sysctl at path to want - at least it (atLeast) or at most it - never moving a value already on the
// right side, and READS IT BACK. -> (the MON line, ok): ok is false, and the line ends in `refused`, when the sysctl is
// absent, unparsable, the write is refused, or the read-back is on the wrong side or unreadable. write is passed in so a
// test can make one that "succeeds" and changes nothing. The same rule as raisePtraceScope, and as the SNP guest's
// m2/dominit.c sysctl_hold.
func holdSysctl(name, path string, want int, atLeast bool, refused string, write func(string, []byte, os.FileMode) error) (string, bool) {
	right := func(v int) bool { return (atLeast && v >= want) || (!atLeast && v <= want) }
	side := map[bool]string{true: ">=", false: "<="}[atLeast]
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("%s absent: %s (%s: %v)", name, refused, path, err), false
	}
	was, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return fmt.Sprintf("%s unparsable (%q): %s", name, strings.TrimSpace(string(raw)), refused), false
	}
	if right(was) {
		return fmt.Sprintf("%s=%d (already %s %d)", name, was, side, want), true
	}
	if err := write(path, []byte(strconv.Itoa(want)+"\n"), 0); err != nil {
		return fmt.Sprintf("%s=%d, NOT set to %d (%v): %s", name, was, want, err, refused), false
	}
	raw, err = os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("%s=%d -> unreadable (%v): %s", name, was, err, refused), false
	}
	now, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || !right(now) {
		return fmt.Sprintf("%s=%d -> %q, not the %d asked: %s", name, was, strings.TrimSpace(string(raw)), want, refused), false
	}
	return fmt.Sprintf("%s=%d -> %d", name, was, now), true
}

// frontUIDOffset separates the fronts' uids from the runtimes': domain N's runtime is base-uid + N, its front
// base-uid + frontUIDOffset + N.
const frontUIDOffset = 1 << 20

// yamaRefused ends every line on which the monitor refuses all domains for want of Yama.
const yamaRefused = "domains refused (a same-uid runtime could attach to the front)"

// raisePtraceScope sets Yama's ptrace_scope at path to want (2: only CAP_SYS_PTRACE may attach; not 3, which cannot be
// lowered again before a reboot), never lowering a higher value, and reads it back. -> (the MON line, ok). ok is false,
// and the line ends in yamaRefused, unless the value READ BACK is at least want: Yama absent, unparsable, the write
// refused, or the read-back short or unreadable. Then no domain may load (monitor.load), because Yama is the guard that
// keeps the tenant runtime - the same uid, a sibling of the front - from attaching to the front or opening its
// /proc/<pid>/mem during the front's start-up; the front's non-dumpable flag is only defence in depth (enclave-bf's F1
// and F2 on d9176ed5; enclave-87's ruling).
func raisePtraceScope(path string, want int) (string, bool) {
	return raisePtraceScopeWith(path, want, os.WriteFile)
}

// raisePtraceScopeWith is raisePtraceScope with the write passed in: a test's write can "succeed" and change nothing, the
// case only the read-back catches.
func raisePtraceScopeWith(path string, want int, write func(string, []byte, os.FileMode) error) (string, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("yama absent: %s (%s: %v)", yamaRefused, path, err), false
	}
	was, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return fmt.Sprintf("yama ptrace_scope unparsable (%q): %s", strings.TrimSpace(string(raw)), yamaRefused), false
	}
	if was >= want {
		return fmt.Sprintf("yama ptrace_scope=%d (already >= %d)", was, want), true
	}
	if err := write(path, []byte(strconv.Itoa(want)+"\n"), 0); err != nil {
		return fmt.Sprintf("yama ptrace_scope=%d, NOT raised to %d (%v): %s", was, want, err, yamaRefused), false
	}
	raw, err = os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("yama ptrace_scope=%d -> unreadable (%v): %s", was, err, yamaRefused), false
	}
	now, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || now < want {
		return fmt.Sprintf("yama ptrace_scope=%d -> %q, not the %d asked: %s", was, strings.TrimSpace(string(raw)), want, yamaRefused), false
	}
	return fmt.Sprintf("yama ptrace_scope=%d -> %d", was, now), true
}

// Shield's broker is reachable by the runtime in /run/enclave-shield. Its
// report and TLS sockets remain behind a distinct 0700, front-owned directory.
func (d *domain) frontPath(name string) string {
	if d.Inference != nil {
		return filepath.Join(d.dir, "run", "front", name)
	}
	return filepath.Join(d.dir, "run", name)
}

// The monitor owns the domain root. No host-supplied path or environment selects this file.
// writeDomainEtc gives a SECRET domain the resolver files its outbound HTTPS needs (m2/front shield_egress.go):
//   - etc/ root's, 0755: no domain uid can add a file to it (a resolv.conf, a second hosts);
//   - etc/nsswitch.conf root's, 0444, "hosts: files": the only resolver is /etc/hosts (a domain has no DNS, no NIC);
//   - etc/hosts the FRONT's uid, 0644: once the release is verified the front writes the allowed names there, each on its
//     own forwarder's loopback address. The runtime (another uid) can read it and cannot change it, so a compromised
//     runtime cannot point an allowed name anywhere else, and an unlisted name simply does not resolve.
//
// A PUBLIC-WEB domain (m2/egress web.go) differs in two root-owned files: nsswitch.conf says "hosts: files dns", and
// resolv.conf (0444) names the front's DNS stub over TCP. /etc/hosts still comes first, so the configured names keep
// their forwarders; any other name is resolved by the host through the deployment's own route.
//
// Until the front writes it, it names localhost only. A domain without secrets gets no /etc, exactly as before.
func writeDomainEtc(dir string, frontUID int, publicWeb bool) error {
	etc := filepath.Join(dir, "etc")
	if err := os.Mkdir(etc, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(etc, 0o755); err != nil { // the mode, whatever the umask
		return err
	}
	nsswitch, resolv := "hosts: files\n", ""
	if publicWeb {
		nsswitch = "hosts: files dns\n"
		resolv = shieldconfig.PublicWebResolv
	}
	ns := filepath.Join(etc, "nsswitch.conf")
	if err := os.WriteFile(ns, []byte(nsswitch), 0o444); err != nil {
		return err
	}
	if err := os.Chmod(ns, 0o444); err != nil {
		return err
	}
	if resolv != "" {
		rc := filepath.Join(etc, "resolv.conf")
		if err := os.WriteFile(rc, []byte(resolv), 0o444); err != nil {
			return err
		}
		if err := os.Chmod(rc, 0o444); err != nil {
			return err
		}
	}
	hosts := filepath.Join(etc, "hosts")
	if err := os.WriteFile(hosts, []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		return err
	}
	if err := os.Chown(hosts, frontUID, frontUID); err != nil {
		return err
	}
	return os.Chmod(hosts, 0o644)
}

func writeAppConfig(dir string, config []byte) error {
	if len(config) == 0 {
		return nil
	}
	if len(config) > contract.MaxConfigBytes {
		return errors.New("app configuration exceeds byte limit")
	}
	return os.WriteFile(filepath.Join(dir, "app.config"), config, 0444)
}
