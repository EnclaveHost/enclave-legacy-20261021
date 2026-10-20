package main

// provision: what the front does for a guest that SERVES A DEPLOYMENT, between minting its key and the app's start
// (docs/security/attested-release.md; isolation/m2/release, egress, appconfig).
//
//  1. read the ticket guestd holds for this guest (vsock host port release.TicketPort), and refuse unless the
//     deployment it names IS this guest's HOST_DATA: the PSP signed HOST_DATA at launch, and the release binds it,
//     so a ticket routed to the wrong guest stops here, before it is burned at the relay;
//  2. mint a seal key and ask the hardware for a report whose report_data is the RELEASE binding (its own domain,
//     never Bind/Bind2) and the AppID this image carries;
//  3. present {id, ticket, sealKey, evidence} to the relay over TLS the guest runs itself, pinned to the relay's
//     name and roots, through the host's egress path;
//  4. verify the relay's signature over THIS request and the sealed reply against the PINNED release keys (contract
//     v1.2), and only then open it; derive the allowlist from it (egress.FromRelease: the owner's config, never the host's),
//     start one loopback listener per allowed origin and write /etc/hosts naming only those;
//  5. audit the guest's listening sockets: before the app starts, the ONLY IP listeners may be those forwarders;
//  6. hand init the resolved config (appconfig.Resolve, the standard runtime's substitution) for ENCLAVE_CONFIG.
//
// Any failure is fatal: a deployment's guest never starts its app without the owner's config (the host cannot
// downgrade it to "no config" by withholding the ticket), and never with a config that did not come sealed from the
// relay.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"enclave.host/isolation/contract"
	"enclave.host/isolation/m2/appconfig"
	"enclave.host/isolation/m2/egress"
	"enclave.host/isolation/m2/release"
)

type provisioner struct {
	ticket func() (net.Conn, error) // a stream to guestd's ticket service
	egress func() (net.Conn, error) // a stream to guestd's egress server
	report func(rd []byte) (rep, certs []byte, err error)
	// custody (custody.go): a stream to guestd's custody-authorization service, and whether this front derived its AppID
	// from the loaded code (a custody release refuses an image where it did not)
	custodyAuth func() (net.Conn, error)
	appFromCode bool
	relayHost   string
	roots       *x509.CertPool
	keys        []ed25519.PublicKey               // the relay's pinned release keys (release.PinnedRelayKeys)
	etc         string                            // "/etc" in a guest
	fwdPort     int                               // 443 in a guest
	audit       func(want []netip.AddrPort) error // auditListeners("/proc/net", …) in a guest
	window      time.Duration                     // retry a ticket-keeping refusal this long after the ticket arrived; 0 = release.ReleaseWindow
	retry       time.Duration                     // between those retries; 0 = the client's 5 s
	logf        func(string, ...any)
}

type provisioned struct {
	config   string // ENCLAVE_CONFIG, resolved; "" = the release carried no config
	envelope string // the ledger envelope's sha256 (hex): public (it is on chain), stated on the console
	fwd      *egress.Forwarder
	owner    *ownerStartup // direct startup only: owner-committed names (names.go)
}

func (p *provisioner) run(ctx context.Context, hostData, spki []byte, rt *runtimeState, appSha []byte) (*provisioned, error) {
	if len(hostData) != 32 || isZero(hostData) {
		return nil, errors.New("this guest's HOST_DATA names no deployment")
	}
	if rt == nil {
		return nil, fmt.Errorf("a release binds the runtime identity (%s), and this image carries none", contract.ABI2)
	}
	if len(appSha) != 32 {
		return nil, errors.New("no AppID to put in report_data[32:64]")
	}
	if len(p.keys) == 0 {
		// before the ticket is even read: this image cannot trust any reply (contract v1.2)
		return nil, errors.New("no relay release key is pinned in this image, so no release can be trusted")
	}
	var id [32]byte
	copy(id[:], hostData)

	tk, err := p.readTicket(ctx)
	if err != nil {
		return nil, err
	}
	ticketAt := time.Now()
	if tk.ID != id {
		return nil, fmt.Errorf("the host's ticket is for deployment 0x%x, and this guest serves HOST_DATA 0x%x: refused before the relay sees it", tk.ID[:4], id[:4])
	}

	sk, err := release.NewSealKey()
	if err != nil {
		return nil, err
	}
	bind, err := release.Binding(id, spki, tk.Ticket, rt.RID, sk.Public())
	if err != nil {
		return nil, err
	}
	rd := make([]byte, 64)
	copy(rd, bind[:])
	copy(rd[32:], appSha) // the AppID the measured image carries; the release package never writes this half
	rep, certs, err := p.report(rd)
	if err != nil {
		return nil, fmt.Errorf("the release report: %w", err)
	}
	rtJSON, err := json.Marshal(rt.ID)
	if err != nil {
		return nil, err
	}
	ev := release.Evidence{Format: contract.FormatSNP, Abi: contract.ABI2, Runtime: rtJSON,
		TransportKey: base64.StdEncoding.EncodeToString(spki), Report: base64.StdEncoding.EncodeToString(rep)}
	if len(certs) > 0 {
		ev.Certs = base64.StdEncoding.EncodeToString(certs)
	}
	relay := egress.Origin{Host: p.relayHost}
	cl := &release.Client{Host: p.relayHost, Roots: p.roots, Keys: p.keys, Retry: p.retry,
		Dial: func(context.Context) (net.Conn, error) { return egress.DialOrigin(p.egress, relay) }}
	// a relay that keeps the ticket (503 warming while it predicts this image's measurement, busy, 429) is retried with
	// the same ticket and evidence for release.ReleaseWindow from the ticket's arrival, within its 120 s TTL
	window := p.window
	if window <= 0 {
		window = release.ReleaseWindow
	}
	rctx, rcancel := context.WithDeadline(ctx, ticketAt.Add(window))
	defer rcancel()
	resp, err := cl.Release(rctx, id, tk.Ticket, sk, ev) // VERIFIED against the pinned keys (contract v1.2) ...
	if err != nil {
		return nil, err
	}
	rel, err := sk.Open(resp) // ... and only then opened
	if err != nil {
		return nil, fmt.Errorf("the relay's reply does not open under this guest's seal key: %w", err)
	}

	text, err := rel.ConfigText()
	if err != nil {
		return nil, err
	}
	out := &provisioned{envelope: rel.EnvelopeTag()}
	if rel.Custody != nil {
		// the owner moved this deployment's secrets to custodians: the relay must not ALSO carry values, and the values
		// come only from a threshold of custodians, released to this guest's attested key, and only into the config the
		// owner committed (custody.go). They become the release's secrets BEFORE the allowlist is derived, so an origin
		// named through a placeholder (${IMAGE_ENDPOINT}) is allowed exactly as for a relay-held value.
		if len(rel.Secrets) != 0 {
			return nil, errors.New("the release names a custody state AND carries relay-held secrets: refused")
		}
		if rel.Secrets, err = p.custodySecrets(ctx, rel.Custody, id, spki, rt, appSha, text); err != nil {
			return nil, err
		}
	}
	secrets := rel.Secrets
	pol, err := egress.FromRelease(rel, relay)
	if err != nil {
		return nil, fmt.Errorf("the allowlist: %w", err)
	}
	if text != "" {
		resolved, err := appconfig.Resolve(text, secrets)
		if err != nil {
			return nil, fmt.Errorf("the config: %w", err)
		}
		v, ok := appconfig.EnvValue(resolved)
		if !ok {
			return nil, fmt.Errorf("the resolved config is over the %d-byte ENCLAVE_CONFIG ceiling, and this guest has no config-file channel", appconfig.EnvMaxBytes)
		}
		out.config = v
	}
	// The values now live only inside out.config, which init receives and this process then drops. Go strings cannot
	// be zeroed, so they sit in this process's heap until reused: guest memory the host cannot read (SEV-SNP) and the
	// tenant cannot reach (the runtime gives it no access to other processes).
	rel.Secrets = nil
	secrets = nil
	return p.startForwarders(ctx, id, out, pol)
}

func (p *provisioner) startForwarders(ctx context.Context, id [32]byte, out *provisioned, pol *egress.Policy) (*provisioned, error) {
	out.fwd = &egress.Forwarder{Policy: pol, Port: p.fwdPort, Upstream: p.egress, Logf: domLogf(p.logf)}
	if err := out.fwd.Start(ctx); err != nil {
		return nil, err
	}
	if err := p.writeResolver(out.fwd); err != nil {
		out.fwd.Close()
		return nil, err
	}
	var want []netip.AddrPort
	if a, ok := out.fwd.PublicAddr(); ok {
		want = append(want, a)
	}
	for _, o := range pol.Origins {
		a, _ := out.fwd.Addr(o.Host)
		want = append(want, a)
	}
	if err := p.audit(want); err != nil {
		out.fwd.Close()
		return nil, err
	}
	p.logf("DOM release: deployment 0x%x... envelope %.16s... %d allowed origin(s), %d refused, config %d bytes",
		id[:4], out.envelope, len(pol.Origins), len(pol.Refused), len(out.config))
	return out, nil
}

// ticketWait bounds the wait for the ticket line once connected. guestd HOLDS this connection until the supervisor
// has fetched a ticket (it asks the relay only once guestd reports the guest waiting, and retries a refusal), for up
// to release.TicketHold; waiting a minute longer means it is always guestd's hold, not this deadline, that ends a
// guest whose ticket never comes (m4/guestd/release.go).
var ticketWait = release.TicketHold + time.Minute

// readTicket waits for guestd's ticket service: the guest may boot before guestd accepts, so the dial is retried for
// a bounded time, and one line is read.
func (p *provisioner) readTicket(ctx context.Context) (release.Ticket, error) {
	deadline := time.Now().Add(60 * time.Second)
	for {
		c, err := p.ticket()
		if err == nil {
			c.SetDeadline(time.Now().Add(ticketWait))
			t, rerr := release.ReadTicket(c)
			c.Close()
			return t, rerr
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return release.Ticket{}, errors.New("the host's ticket service never answered")
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// writeResolver makes the allowed names the ONLY names that resolve: /etc/hosts maps each to its forwarder, and
// nsswitch.conf says files and nothing else (the guest has no NIC and no DNS; an unlisted name simply fails).
func (p *provisioner) writeResolver(f *egress.Forwarder) error {
	if err := os.MkdirAll(p.etc, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(p.etc, "nsswitch.conf"), []byte("hosts: files\n"), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(p.etc, "hosts"), []byte(f.HostsFile()), 0o644)
}

// auditListeners reads the guest's IP socket tables and requires the listening set to be EXACTLY `want` (the
// forwarders) and no UDP socket at all (enclave-99's note 2: the tenant reaches the guest's loopback through
// wasi:http, so every listener on it is reachable by the tenant). It runs before the app starts, when every socket
// in the guest is the platform's. The front's own endpoint is vsock, which these tables do not hold.
func auditListeners(procNet string, want []netip.AddrPort) error {
	var got []string
	for _, t := range []string{"tcp", "tcp6"} {
		ls, err := socketTable(filepath.Join(procNet, t), true)
		if err != nil {
			return fmt.Errorf("listener audit: %w", err)
		}
		got = append(got, ls...)
	}
	for _, t := range []string{"udp", "udp6"} {
		ls, err := socketTable(filepath.Join(procNet, t), false)
		if err != nil {
			return fmt.Errorf("listener audit: %w", err)
		}
		if len(ls) > 0 {
			return fmt.Errorf("listener audit: a UDP socket is bound before the app started (%s)", strings.Join(ls, ", "))
		}
	}
	var exp []string
	for _, a := range want {
		exp = append(exp, a.String())
	}
	sort.Strings(got)
	sort.Strings(exp)
	if strings.Join(got, ",") != strings.Join(exp, ",") {
		return fmt.Errorf("listener audit: the guest listens on [%s], and only the egress forwarders [%s] may listen before the app starts",
			strings.Join(got, ", "), strings.Join(exp, ", "))
	}
	return nil
}

// socketTable parses /proc/net/{tcp,tcp6,udp,udp6}: every socket's local address, or (listenOnly) only those in
// state 0A, LISTEN. A missing table (no IPv6 in the kernel) is empty.
func socketTable(path string, listenOnly bool) ([]string, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	s := bufio.NewScanner(bytes.NewReader(raw))
	s.Scan() // the header
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) < 4 {
			continue
		}
		if listenOnly && f[3] != "0A" {
			continue
		}
		a, err := procAddr(f[1])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, a.String())
	}
	return out, s.Err()
}

// procAddr decodes a /proc/net local_address: hex IP in host byte order per 32-bit word, ":" hex port.
func procAddr(s string) (netip.AddrPort, error) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, errors.New("an address without a port")
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return netip.AddrPort{}, errors.New("an address that is neither IPv4 nor IPv6")
	}
	for i := 0; i < len(b); i += 4 { // each 32-bit word is little-endian on x86
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	a, _ := netip.AddrFromSlice(b)
	return netip.AddrPortFrom(a.Unmap(), uint16(port)), nil
}

func isZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// handToInit is the one message init waits for before it starts the app, on the pipe it gave this process: "N" (no
// config) or "C" followed by the resolved config, then EOF. A front that dies first leaves the pipe empty, and init
// powers the guest off rather than start an app that has no config it should have had.
func handToInit(w *os.File, config string) error {
	return handToInitMode(w, config, false)
}

// P is emitted only after the authenticated owner policy enabled the public HTTPS listener and its audit passed.
func handToInitMode(w *os.File, config string, publicHTTPS bool) error {
	defer w.Close()
	msg := make([]byte, 0, len(config)+1)
	if config == "" {
		msg = append(msg, 'N')
	} else {
		tag := byte('C')
		if publicHTTPS {
			tag = 'P'
		}
		msg = append(msg, tag)
		msg = append(msg, config...)
	}
	_, err := w.Write(msg)
	for i := range msg {
		msg[i] = 0
	}
	return err
}

// domLogf makes another package's log lines the front's own statements: "DOM " + the line. The egress forwarder logs
// only an origin index and a closed-set failure class (egress.dialClass), and stdout carries only DOM statements
// (enclave-e3's L1 on the console guard).
func domLogf(logf func(string, ...any)) func(string, ...any) {
	if logf == nil {
		return nil
	}
	return func(format string, a ...any) { logf("DOM "+format, a...) }
}
