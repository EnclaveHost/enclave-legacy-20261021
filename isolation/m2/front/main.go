// front: the one port an app domain exposes (isolation/DESIGN.md section 10). It runs inside the
// domain, beside the app:
//   - mints the domain's TLS key in guest memory at start; the key is never written anywhere;
//   - terminates TLS on the domain's only channel;
//   - answers GET /.well-known/enclave-attestation?nonce=<64 hex> itself;
//   - answers GET /.well-known/enclave-ready: whether the app's port accepts connections yet (ready.go);
//   - proxies everything else, as plaintext on the guest's loopback, to the app (wasmtime serve, or a command
//     that binds its own port), with no X-Forwarded-For (ready.go).
//
// Two shapes, one binary:
//
//	M2, one app per guest: listen on vsock, and ask the hardware for the report directly (-snp).
//	M3, many domains per guest: listen on a unix socket the monitor relays (-listen-unix), and ask the
//	MONITOR for the report (-report-unix). The front then never touches the report interface, and the
//	app half of report_data is written by the monitor from its own table rather than by this process
//	(isolation/m3/PLAN.md section 3).
//
// Under SEV-SNP the report's 64-byte report_data is
//
//	[0:32]  the binding: sha256(transport key SPKI DER || nonce) under ABI/1, or, under ABI/2,
//	        contract.Bind2 over the same key and nonce AND this domain's runtime identity
//	[32:64] sha256 of the app .wasm                    names the app, as M1 did
//
// so a verifier that checks the report against the key ITS OWN handshake saw knows its traffic ends
// inside this measured domain. On T0 there is no hardware report, and the endpoint says so.
//
// ABI/2 (isolation/contract/RUNTIME.md) is used when the image carries a runtime identity beside the
// runtime (-runtime-identity, written by build-domain.sh). The app is a portable WebAssembly component
// compiled INSIDE this domain, so the runtime, its version, its execution mode, the ISA it targets and
// its CPU-feature policy are part of what the report vouches for; runtime.go checks the identity against
// this domain before the front states it, and the front refuses to serve if it cannot. Without that file
// the domain keeps ABI/1 unchanged.
package main

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"enclave.host/isolation/contract"
	"enclave.host/isolation/m2/bootstrap"
	"enclave.host/isolation/m2/domtls"
	"enclave.host/isolation/m2/release"
	"enclave.host/isolation/m2/vsock"
)

const attestPath = "/.well-known/enclave-attestation"

type doc struct {
	Tier         string `json:"tier"`
	Format       string `json:"format"`
	Report       string `json:"report,omitempty"` // base64 raw SNP report
	Certs        string `json:"certs,omitempty"`  // base64 auxblob (VCEK chain) when the host supplies one
	TransportKey string `json:"transportKey"`     // base64 SPKI DER; a verifier uses its handshake's, not this
	AppSha256    string `json:"appSha256"`
	Nonce        string `json:"nonce"`
	Reason       string `json:"reason,omitempty"`
	// Boundary is the monitor's own boundary self-test, relayed here so it reaches a verifier over THIS
	// connection - whose key is bound into the report above - rather than only on a serial console the
	// host owns and could write. Shape: "tier=t1 vmpl=2 vmpl_floor=2 vmpl0=refused".
	//
	// What it is worth: the monitor and this front are both inside the measured launch image, and the
	// monitor refuses to serve any report at all unless this tuple is coherent, so a verifier that has
	// checked the measurement knows measured code produced it and would not have produced a report
	// otherwise. What it is NOT: hardware proof. The PSP does not attest "this guest cannot reach VMPL0";
	// a verifier relies on the measured monitor truthfully reporting its own local refusal.
	Boundary string `json:"boundary,omitempty"`
	// ABI/2 only. Abi names the binding a verifier must recompute; Runtime is the identity that went
	// into it, and RuntimeSelfTest is what this domain CHECKED about itself before stating that identity
	// (runtime.go): that it may hold an executable page at all, and that no page in it is both writable
	// and executable. Same standing as Boundary above: measured code's own word, relayed over the
	// connection whose key is bound into the report, and the front exits rather than serving on a fault -
	// so a document that reaches a verifier at all is one where these held. Not hardware proof.
	Abi             string                    `json:"abi,omitempty"`
	Runtime         *contract.RuntimeIdentity `json:"runtime,omitempty"`
	RuntimeSelfTest string                    `json:"runtimeSelfTest,omitempty"`
}

type front struct {
	publicHTTPS  bool // set only by successful attested provisioning
	spki, appSha []byte
	rt           *runtimeState // ABI/2 when non-nil, ABI/1 when the image carries no runtime identity
	// seccompStatement: where init (dominit, root) records the app runtime's seccomp filter once it is installed; read
	// into every self-test this front measures (localSelfTest). "" = none (M3: the monitor states it instead).
	seccompStatement string
	snp              bool
	monitor          string      // M3: the monitor's socket, and then this process never opens configfs at all
	plane            *appidPlane // M4b: the measured SVSM names this plane and computes the binding itself
	boundary         string      // the self-test init produced; relayed verbatim, never composed here
	tunnels          *portTunnels
	app              http.Handler
	certs            *certState // a CA certificate for this domain's own key and deployment name (certs.go)
	ready            *readiness // GET /.well-known/enclave-ready: the app's port accepts (ready.go)
	tsmMu            sync.Mutex
}

func main() {
	// first, before anything can log: nothing but the front's own DOM statements reaches the host's console (console.go).
	// Package init() functions, this package's and every import's, run BEFORE this line: none may print (enclave-e3's L2).
	// ...and not dumpable, before the TLS key exists (dumpable.go). That is defence in depth: the runtime runs as this
	// domain's uid too, and what keeps it from ptracing this process or reading its memory is Yama, which the monitor
	// holds at >= 1 or refuses every domain. It prints nothing, so it can precede the guard.
	tid, tracer, threads, dumpErr := notDumpable()
	if err := guardConsole(); err != nil {
		die("console guard: %v", err)
	}
	if dumpErr != nil {
		die("not dumpable: %v", dumpErr)
	}
	if tracer != 0 {
		// a tracer attached before PR_SET_DUMPABLE 0 stays attached, on any thread (enclave-bf): refuse before any key exists
		fmt.Printf("DOM front: traced at start (thread %d, tracer %d): refusing\n", tid, tracer)
		os.Exit(1)
	}
	fmt.Printf("DOM front: not dumpable; none of its %d threads traced\n", threads)
	port := flag.Uint("port", 443, "vsock port to serve TLS on")
	listenUnix := flag.String("listen-unix", "", "serve TLS on this unix socket instead of vsock (M3)")
	reportUnix := flag.String("report-unix", "", "ask the monitor on this unix socket for reports (M3)")
	upstream := flag.String("upstream", "127.0.0.1:8080", "the app on the guest loopback")
	appShaPath := flag.String("app-sha", "/app.sha256", "hex sha256 of the app, written at build time")
	appWasmPath := flag.String("app-wasm", "/app.wasm", "the component init runs: when present, the AppID is derived from it (appidentity.go)")
	appBundlePath := flag.String("app-bundle", "/app.bundle", "the contract bundle /app.wasm was extracted from, when the image carries one")
	snp := flag.Bool("snp", false, "this domain is an SEV-SNP guest: serve hardware reports")
	boundaryPath := flag.String("boundary", "", "a file holding the boundary self-test this domain relays (M4b); "+
		"written by init after it probes for VMPCK absence, because the front cannot probe for it itself")
	appid := flag.String("appid", "", "ask the measured SVSM for reports through this plane sysfs dir (M4b): "+
		"the SVSM computes the binding from a key registered here, so this domain cannot choose either half of report_data")
	rtID := flag.String("runtime-identity", "/rt/runtime.json", "the runtime identity written into this image beside the runtime; absent means ABI/1")
	certZone := flag.String("cert-zone", "app.enclave.host", "the app zone this domain's deployment name lives in (<first 4 bytes of its HOST_DATA, hex>.<zone>); empty = never certify a name")
	certNameFile := flag.String("cert-name-file", "", "where there is no SEV-SNP HOST_DATA (a Hyper-V partition): a file holding the deployment name the LAUNCHER named this domain for; used only if it is <8 hex>.<-cert-zone>")
	seccompStatement := flag.String("seccomp-statement", "", "where init records the app runtime's seccomp filter once installed (SNP: dominit's "+
		"root-only /run/enclave/seccomp); read into every self-test this front measures. Empty = none")
	appMode := flag.String("app-mode", "serve", "how the app runs, for /.well-known/enclave-ready: serve (the runtime serves a wasi:http component) or run (a wasi:cli command binds -upstream itself)")
	initFD := flag.Int("init-fd", 0, "a pipe from init (M2): after provisioning, the front writes N (no config) or C+config there, and init starts the app only then (provision.go)")
	flag.Parse()

	// The AppID: derived from the code init will run whenever this image holds it (M2/M4a), so report_data[32:64] names
	// what runs, never just what a file says; otherwise (M3/M4b, where the monitor or the SVSM writes that half from the
	// code IT loaded) the build's statement, used only for this front's own records.
	var appSha []byte
	appFromCode := false
	if _, err := os.Stat(*appWasmPath); err == nil {
		id, how, err := loadedAppID(*appBundlePath, *appWasmPath, *appShaPath)
		if err != nil {
			die("app identity: %v", err)
		}
		appSha, appFromCode = id, true
		fmt.Printf("DOM app id %x (%s)\n", id, how)
	} else {
		raw, err := os.ReadFile(*appShaPath)
		must(err)
		appSha, err = hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(appSha) != 32 {
			die("app sha256 in %s is not 32 bytes of hex", *appShaPath)
		}
	}
	// Before anything is served: the runtime identity, checked against this domain. A fault here is
	// fatal on purpose - a domain that cannot substantiate what compiles its app attests nothing.
	rt, err := loadRuntime(*rtID)
	if err != nil {
		die("runtime identity: %v", err)
	}
	if rt != nil {
		fmt.Printf("DOM runtime %s/%s execution=%s target=%s host=%s features=%s wx=%s cache=%s id=%x\n",
			rt.ID.Name, rt.ID.Version, rt.ID.Execution, rt.ID.TargetISA, rt.ID.HostISA, rt.ID.CPUFeatures,
			rt.ID.WX, rt.ID.Cache, rt.RID)
		fmt.Printf("DOM runtime selftest exec_pages=%s wx=at-each-attestation\n", rt.ExecPages)
	} else {
		fmt.Printf("DOM runtime none: no identity at %s, this domain attests %s\n", *rtID, contract.ABI)
	}
	cert, spki, err := domtls.Mint("enclave-domain")
	must(err)
	var l net.Listener
	where := fmt.Sprintf("vsock=%d", *port)
	if *listenUnix != "" {
		os.Remove(*listenUnix)
		l, err = net.Listen("unix", *listenUnix)
		where = "unix=" + *listenUnix
	} else {
		l, err = vsock.Listen(uint32(*port))
	}
	must(err)

	if *appMode != "serve" && *appMode != "run" {
		die("-app-mode must be serve or run, not %q", *appMode)
	}
	f := &front{spki: spki, appSha: appSha, rt: rt, snp: *snp, monitor: *reportUnix, app: appProxy(*upstream), seccompStatement: *seccompStatement,
		ready: &readiness{upstream: *upstream, mode: *appMode, appID: hex.EncodeToString(appSha), dial: 2 * time.Second}}
	if *appid != "" {
		// ABI/2 or nothing on this path. The SVSM computes Bind2, which folds in a RuntimeID; a domain with no
		// runtime identity computes Bind, so the comparison below could never match and every /attest would
		// fail at serve time with a confusing message. Refuse at startup, where the cause is visible.
		if rt == nil {
			die("-appid needs a runtime identity: the SVSM binds %s (Bind2, with a RuntimeID) and this image "+
				"carries none, so no binding this domain computes could ever match", contract.ABI2)
		}
		// Register BEFORE serving, and die rather than serve without it. A front that answered /attest with
		// reports bound to no key - or to a key some earlier admission registered and the reclaim forgot -
		// would hand a verifier a document whose transport key it cannot match to this handshake. There is no
		// retry: the plane is admitted once, by init, before this process starts.
		// The boundary self-test is init's to produce, not the front's: it records that sev-guest REFUSED to
		// load for want of a VMPCK, which only a process that tried can say. Relayed verbatim - a front that
		// composed this string could state confinement it never tested.
		if *boundaryPath == "" {
			die("-appid needs -boundary: a document claiming VMPL2 with no boundary self-test is consistent " +
				"with a VMPL0 guest naming a lower level, and a verifier rejects it")
		}
		b, err := os.ReadFile(*boundaryPath)
		must(err)
		f.boundary = strings.TrimSpace(string(b))
		if f.boundary == "" {
			die("%s is empty: init did not state a boundary self-test", *boundaryPath)
		}
		f.plane = &appidPlane{dir: *appid}
		must(f.plane.registerKey(spki))
		fmt.Printf("DOM plane %s registered spki_sha256=%x\n", *appid, sha256.Sum256(spki))
	}
	// ErrorLog: a TLS handshake error names the client, and a recovered handler panic prints its value; both go
	// through the console filter, as the class alone (console.go)
	srv := &http.Server{Handler: f, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute, ErrorLog: consoleLog}
	// No session tickets: every connection then proves the attested key in a full handshake, so a
	// client pins by comparing that key, never by tracking which session came from which handshake.
	// The name this domain may certify comes from its own HOST_DATA (certs.go); the key is the attested one either way.
	f.certs = &certState{key: cert.PrivateKey.(crypto.Signer), spki: spki, self: &cert}
	// HOST_DATA, read once: it names the deployment this guest serves, for both its certificate and its release
	var hd []byte
	var hdErr error
	if f.plane == nil {
		hd, hdErr = f.hostData()
	}
	if f.plane == nil {
		if err := hdErr; err != nil {
			if n := launcherName(*certNameFile, *certZone); n != "" {
				f.certs.name = n
				fmt.Printf("DOM certificate: this domain may certify %s (named by the launcher at load: no HOST_DATA here, "+
					"so this is the launcher's word, T0-hv)\n", n)
			} else {
				fmt.Printf("DOM certificate: no HOST_DATA to name this domain (%v); self-signed only\n", err)
			}
		} else if f.certs.name = nameFromHostData(hd, *certZone); f.certs.name != "" {
			fmt.Printf("DOM certificate: this domain may certify %s (HOST_DATA %x...)\n", f.certs.name, hd[:8])
		} else {
			fmt.Printf("DOM certificate: HOST_DATA names no deployment; self-signed only\n")
		}
	}
	// M2: a guest that serves a deployment gets its owner's config and secrets through the attested release, and its
	// allowlist from them, BEFORE init starts the app (provision.go). Any failure ends the domain.
	warmupPath := ""
	if *initFD > 0 {
		initPipe := os.NewFile(uintptr(*initFD), "init-pipe")
		err := f.releaseForInit(initPipe, hd, hdErr, func() (string, error) {
			p := &provisioner{
				ticket:      func() (net.Conn, error) { return vsock.Dial(vsock.CIDHost, release.TicketPort) },
				egress:      func() (net.Conn, error) { return vsock.Dial(vsock.CIDHost, EgressPort) },
				report:      f.report,
				custodyAuth: func() (net.Conn, error) { return vsock.Dial(vsock.CIDHost, release.CustodyAuthPort) },
				appFromCode: appFromCode,
				relayHost:   release.RelayHost,
				etc:         "/etc", fwdPort: 443,
				audit: func(want []netip.AddrPort) error { return auditListeners("/proc/net", want) },
				logf:  func(format string, a ...any) { fmt.Printf(format+"\n", a...) },
			}
			prov, err := p.runStartup(context.Background(), func() (net.Conn, error) { return vsock.Dial(vsock.CIDHost, bootstrap.PackagePort) }, hd, spki, rt, appSha)
			if err != nil {
				return "", err
			}
			f.publicHTTPS = prov.fwd.Policy.PublicHTTPS
			warmupPath = configuredWarmup(prov.config)
			return prov.config, nil
		})
		if err != nil {
			die("release: %v", err)
		}
	}
	if !directBootstrap && *initFD > 0 && f.certs.name != "" && len(hd) == 32 && !isZero(hd) {
		go f.certs.watchDomains(context.Background(), "0x"+hex.EncodeToString(hd))
	}
	tl := tls.NewListener(l, &tls.Config{GetCertificate: f.certs.getCertificate, MinVersion: tls.VersionTLS13,
		SessionTicketsDisabled: true})

	// "serving" means both halves answer: TLS here, and the app behind it
	go func() {
		for deadline := time.Now().Add(120 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			if c, err := net.DialTimeout("tcp", *upstream, time.Second); err == nil {
				c.Close()
				break
			}
			if time.Now().After(deadline) {
				die("app never listened on %s", *upstream)
			}
		}
		fp := sha256.Sum256(spki)
		fmt.Printf("DOM serving %s spki_sha256=%x ready_ms=%.0f\n", where, fp, monoMs())
		if warmupPath != "" {
			fmt.Println("DOM warmup: started")
			fmt.Printf("DOM warmup: %s\n", bootWarmup(context.Background(), *upstream, warmupPath, 15*time.Minute))
		}
	}()
	_, hp, err := net.SplitHostPort(*upstream)
	must(err)
	var portNumber int
	_, err = fmt.Sscanf(hp, "%d", &portNumber)
	must(err)
	f.tunnels, err = loadPortTunnels("/app.ports", portNumber)
	must(err)
	must(srv.Serve(tl))
}

func (f *front) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, tunnelPrefix) {
		f.tunnels.ServeHTTP(w, r)
		return
	}
	switch r.URL.Path {
	case attestPath:
		f.attest(w, r)
		return
	case csrPath:
		f.certs.serveCSR(w, r)
		return
	case certPath:
		f.certs.serveInstall(w, r)
		return
	case readyPath:
		f.ready.serve(w, r)
		return
	}
	f.app.ServeHTTP(w, r)
}

func (f *front) attest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	nonce, err := hex.DecodeString(r.URL.Query().Get("nonce"))
	if err != nil || len(nonce) != 32 {
		http.Error(w, "nonce must be 32 bytes of hex", http.StatusBadRequest)
		return
	}
	d := doc{Tier: "T0", Format: "none", TransportKey: base64.StdEncoding.EncodeToString(f.spki),
		AppSha256: hex.EncodeToString(f.appSha), Nonce: hex.EncodeToString(nonce),
		Reason: "T0 domain: an ordinary KVM guest with no hardware attestation; the host can read its memory"}
	// The binding is the same in both shapes - the M2 one-guest domain and the M3 monitor relay - and it
	// covers this domain's TLS key and the verifier's nonce. Under ABI/2 it covers the runtime identity
	// too, so a document naming another runtime, version, execution mode, ISA or feature policy than the
	// one that asked for the report does not verify.
	bind, err := f.bind(nonce)
	if err != nil {
		http.Error(w, "binding: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if f.rt != nil {
		d.Abi, d.Runtime = contract.ABI2, &f.rt.ID
	} else {
		d.Abi = contract.ABI
	}
	var rep, certs []byte
	var boundary, tier, format, wx string
	switch {
	case f.plane != nil:
		// M4b: send the NONCE and nothing else. report_data[0:32] is Bind2(the key registered at startup,
		// this nonce, the RuntimeID compiled into the measured SVSM) and report_data[32:64] comes from
		// APP_TABLE indexed by the calling plane. Neither is a field of the request, so the binding this
		// front computed above is used only to CHECK what came back - never to ask for it.
		rep, err = f.plane.report(nonce)
		if err == nil {
			tier, format = "T1", "sev-snp-svsm-plane-v1"
			boundary = f.boundary
			// Fail closed on disagreement. The SVSM's binding must equal the one this domain would have
			// computed from its own key, this nonce and its own runtime identity; if it does not, either the
			// SVSM holds a different key or its compiled RuntimeID is not the identity this image states,
			// and serving the document would publish a binding this domain cannot honour at a handshake.
			if got := reportData0(rep); got != bind {
				http.Error(w, fmt.Sprintf("the SVSM's binding %x is not this domain's %x", got[:8], bind[:8]),
					http.StatusInternalServerError)
				return
			}
		}
	case f.monitor != "":
		// M3: send the binding and nothing else. The app half of report_data is the monitor's to write,
		// from the hash it took when it loaded this domain's app. The monitor also says what kind of
		// report it is (the PSP's bytes, or a launcher-signed document on a Hyper-V partition).
		rep, certs, boundary, tier, format, wx, err = f.askMonitor(bind[:])
		if err == errNoHardwareReport {
			d.Reason = "T0 domain: the monitor has no hardware report interface on this tier"
			err = nil
		}
	case f.snp:
		rd := make([]byte, 64)
		copy(rd, bind[:])
		copy(rd[32:], f.appSha)
		rep, certs, err = f.report(rd)
	}
	if err != nil {
		http.Error(w, "report: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// The runtime self-test, measured NOW for this document (runtime.go): by the monitor on M3 (the front cannot read
	// the runtime there), by this front elsewhere. A W+X mapping, or a scan that could not read a process, refuses the
	// document; a scan that covered no runtime says runtime=0, and the judge that relies on it rejects that.
	if f.rt != nil {
		st, serr := f.selfTest(wx)
		if serr != nil {
			fmt.Printf("DOM runtime selftest FAILED at an attestation: the document is refused\n")
			http.Error(w, "runtime self-test: "+serr.Error(), http.StatusInternalServerError)
			return
		}
		d.RuntimeSelfTest = st
	}
	if len(rep) > 0 {
		d.Tier, d.Format, d.Reason = "T1", "sev-snp-guest-domain-v1", ""
		if tier != "" && format != "" {
			d.Tier, d.Format = tier, format
		}
		d.Report = base64.StdEncoding.EncodeToString(rep)
		if len(certs) > 0 {
			d.Certs = base64.StdEncoding.EncodeToString(certs)
		}
		d.Boundary = boundary
	}
	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(d)
}

// hostData is this domain's SEV-SNP HOST_DATA, read back from a report of its own (bytes 0xC0..0xE0): what the
// launcher bound it to, signed by the PSP. The report asked for here binds nothing and is never served.
func (f *front) hostData() ([]byte, error) {
	var rep []byte
	var err error
	switch {
	case f.monitor != "":
		// Only a PSP-signed SNP report carries HOST_DATA at 0xC0. A monitor under a Hyper-V launcher returns the
		// launcher's signed JSON in the same field; read at 0xC0 it spelled "hostExcl..." and named a deployment
		// "686f7374" ("host"). Any format but SNP has no HOST_DATA, so no name.
		var format string
		rep, _, _, _, format, _, err = f.askMonitor(make([]byte, 32))
		if err == nil && format != contract.FormatSNP {
			return nil, fmt.Errorf("the monitor's report is %q, not an SEV-SNP report: it carries no HOST_DATA", format)
		}
	case f.snp:
		rep, _, err = f.report(make([]byte, 64))
	default:
		return nil, errors.New("no hardware report on this tier")
	}
	if err != nil {
		return nil, err
	}
	if len(rep) < 0xe0 {
		return nil, errors.New("the report is too short to carry HOST_DATA")
	}
	return rep[0xc0:0xe0], nil
}

// bind computes report_data[0:32] for this domain: contract.Bind under ABI/1, contract.Bind2 with the
// runtime identity folded in under ABI/2. The contract module is the one place either is defined, so the
// front and the verifier cannot drift apart in how they compute it.
func (f *front) bind(nonce []byte) ([32]byte, error) {
	if f.rt != nil {
		return contract.Bind2(f.spki, nonce, f.rt.RID)
	}
	return contract.Bind(f.spki, nonce)
}

// reportData0 is report_data[0:32] out of a signed SNP report. Used only to CHECK the SVSM's binding against
// the one this domain would have computed - never to construct one.
func reportData0(rep []byte) [32]byte {
	var out [32]byte
	if len(rep) >= 0x50+32 {
		copy(out[:], rep[0x50:0x50+32])
	}
	return out
}

var errNoHardwareReport = errors.New("no hardware report on this tier")

// askMonitor is the M3 path: one request, one answer, over the socket the monitor bind-mounted into
// this domain. The monitor identifies the caller from the socket's kernel credentials, so there is
// nothing in this request that could name a different domain or a different app. It also returns the
// monitor's W^X scan of this domain made for this request (wx: "wx=clean maps=... scope=...", or why not).
func (f *front) askMonitor(bind []byte) (rep, certs []byte, boundary, tier, format, wx string, err error) {
	c, err := net.DialTimeout("unix", f.monitor, 10*time.Second)
	if err != nil {
		return nil, nil, "", "", "", "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	if err := json.NewEncoder(c).Encode(map[string]string{"bind": hex.EncodeToString(bind)}); err != nil {
		return nil, nil, "", "", "", "", err
	}
	var resp struct{ Report, Certs, Boundary, Tier, Format, WX, Error string }
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return nil, nil, "", "", "", "", err
	}
	if resp.Error != "" {
		if strings.Contains(resp.Error, "no hardware report") {
			return nil, nil, "", "", "", resp.WX, errNoHardwareReport
		}
		return nil, nil, "", "", "", "", errors.New(resp.Error)
	}
	rep, err = base64.StdEncoding.DecodeString(resp.Report)
	if err != nil {
		return nil, nil, "", "", "", "", err
	}
	certs, _ = base64.StdEncoding.DecodeString(resp.Certs)
	return rep, certs, resp.Boundary, resp.Tier, resp.Format, resp.WX, nil
}

// selfTest is this document's runtime self-test. On M3 it is the MONITOR's scan (wx), which alone can read the
// runtime there: a clean one is used as it is, a missing one says wx=unmeasured (a judge rejects it), and anything
// else (a W+X mapping found, or a scan that failed) refuses the document. Elsewhere this front measures (localSelfTest).
func (f *front) selfTest(wx string) (string, error) {
	if f.monitor == "" {
		return localSelfTest(f.rt.ExecPages, f.seccompStatement)
	}
	switch {
	case wx == "":
		return "exec_pages=" + f.rt.ExecPages + " wx=unmeasured maps=0 scope=monitor", nil
	case strings.HasPrefix(wx, "wx=clean "):
		return "exec_pages=" + f.rt.ExecPages + " " + wx, nil
	default:
		return "", fmt.Errorf("the monitor's W^X scan of this domain: %s", wx)
	}
}

// report asks the PSP, through configfs-tsm, for a report carrying rd, plus the certificate table the
// host attached (empty unless the host loaded one). One entry, used serially, so the outblob read is
// always the one for the inblob just written. The certificates come from the host and prove nothing by
// themselves: a verifier chains the VCEK to AMD's pinned root.
func (f *front) report(rd []byte) ([]byte, []byte, error) {
	f.tsmMu.Lock()
	defer f.tsmMu.Unlock()
	dir := "/sys/kernel/config/tsm/report/front"
	if err := os.Mkdir(dir, 0o755); err != nil && !os.IsExist(err) {
		return nil, nil, err
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

// monotonic time since boot, the clock dominit's boot_ms uses
func monoMs() float64 {
	var ts syscall.Timespec
	syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 1 /* CLOCK_MONOTONIC */, uintptr(unsafe.Pointer(&ts)), 0)
	return float64(ts.Sec)*1e3 + float64(ts.Nsec)/1e6
}

// releaseForInit is the M2 release step: it decides whether this guest serves a deployment, runs the release through
// provision if it does, and hands init its config ("" = none). Only a SUCCESSFUL report whose HOST_DATA is all zero
// means "no deployment". A HOST_DATA read that FAILED is an error that ends the domain, never "none": a host that
// failed the guest's first report request would otherwise start the app with no config, secrets or allowlist, while
// the measurement and HOST_DATA a verifier reads later look right (enclave-e3's review of 7de792bc). Nothing is written
// to init on an error, so init powers the guest off rather than start the app.
func (f *front) releaseForInit(initPipe *os.File, hd []byte, hdErr error, provision func() (string, error)) error {
	if !(f.snp && f.plane == nil && f.monitor == "") {
		fmt.Printf("DOM release: none (not the M2 SNP path)\n")
		return handToInit(initPipe, "")
	}
	if hdErr != nil {
		initPipe.Close()
		return fmt.Errorf("HOST_DATA unreadable, so whether this guest serves a deployment is unknown: %w", hdErr)
	}
	if len(hd) != 32 {
		initPipe.Close()
		return fmt.Errorf("HOST_DATA is %d bytes, not 32", len(hd))
	}
	if isZero(hd) {
		fmt.Printf("DOM release: none (this guest's HOST_DATA names no deployment)\n")
		return handToInit(initPipe, "")
	}
	config, err := provision()
	if err != nil {
		initPipe.Close()
		return err
	}
	return handToInitMode(initPipe, config, f.publicHTTPS)
}

func must(err error) {
	if err != nil {
		die("%v", err)
	}
}

func die(f string, a ...any) {
	fmt.Printf("DOM ERROR front: "+f+"\n", a...)
	os.Exit(1)
}
