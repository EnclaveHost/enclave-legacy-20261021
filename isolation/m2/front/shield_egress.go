package main

// shield_egress.go: outbound HTTPS for a NucBox Shield SECRET domain (isolation/m3, one app in a Hyper-V partition).
//
// The partition has no NIC, and the domain's network namespace holds only lo. Once the front has VERIFIED and OPENED
// the sealed secret release (shield_secrets.go), and BEFORE the runtime receives a byte of it, start():
//
//  1. derives the allowlist IN THE GUEST from the domain's measured /app.config RESOLVED with those secrets
//     (egress.ForShield): an endpoint that is itself a secret ("$R2_ENDPOINT") is judged on its resolved value, which
//     only this domain ever holds; no relay origin is added;
//  2. binds one forwarder per allowed origin on 127.64.0.N:443. domexec lowered THIS network namespace's
//     ip_unprivileged_port_start to 443 for a secret domain, so the front binds it with no capability. Each forwarder
//     carries a stream over AF_VSOCK to the host (CID 2, EgressPort) in egress-v1, naming its OWN bound origin - the
//     tenant cannot choose the destination - and the host's shielded-bridge -> shield-egress takes it from there;
//  3. writes /etc/hosts (the monitor made it, owned by this front's uid; nsswitch.conf is root's, "hosts: files"), so
//     the allowed names, and only they, resolve, each to its own forwarder;
//  4. audits the domain's IP sockets: before the app runs, the forwarders are the only listeners and nothing holds UDP.
//
// Any failure and the caller closes the runtime's pipe EMPTY: the runtime (secretrun) reads EOF, refuses, and the
// domain ends; the app never runs without the allowlist its owner's config states. Nothing here logs a hostname, a URL,
// a config byte, a secret or an error's text: the console gets counts and a fixed step name only.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"

	"enclave.host/isolation/contract"
	"enclave.host/isolation/m2/bootstrap"
	"enclave.host/isolation/m2/egress"
	"enclave.host/isolation/m2/release"
	"enclave.host/isolation/m2/shieldconfig"
)

type shieldEgress struct {
	deployment string                            // direct startup: monitor-owned /secret.id, measured in the app bundle
	config     string                            // the measured config the monitor wrote: "/app.config" (absent = none)
	configUID  int                               // who must own it: 0 (root, the monitor) in a domain
	hosts      string                            // "/etc/hosts": made by the monitor, owned by this front's uid
	port       int                               // 443 in a domain
	upstream   func() (net.Conn, error)          // a stream to the host's egress endpoint: vsock CID 2, EgressPort
	audit      func(want []netip.AddrPort) error // auditListeners("/proc/net", ...) in a domain
	logf       func(string, ...any)              // the front's console: DOM statements only

	// public web (egress web.go): the monitor's marker, which must agree with the mode the measured config states
	// ("" = never marked), and the listeners' addresses (tests only; "" = the domain's fixed 127.0.0.2 addresses)
	publicWebMarker string
	publicListen    string
	dnsListen       string
}

// egressStepError names WHICH step failed, and nothing of why: the reason can carry config or secret text.
type egressStepError struct{ step string }

func (e egressStepError) Error() string { return "egress " + e.step + " failed" }

func (e *shieldEgress) start(rel *release.Release) (*egress.Forwarder, error) {
	cfg, err := readMeasuredConfig(e.config, e.configUID)
	if err != nil {
		return nil, egressStepError{"config"}
	}
	pol, err := egress.ForShield(rel, cfg)
	if err != nil {
		return nil, egressStepError{"allowlist"}
	}
	return e.startPolicy(pol)
}

func (e *shieldEgress) startDirect(auth *bootstrap.Authorization, secrets map[string]string) (*egress.Forwarder, error) {
	cfg, err := readMeasuredConfig(e.config, e.configUID)
	if err != nil {
		return nil, egressStepError{"config"}
	}
	committed, err := auth.ConfigText()
	if err != nil || cfg != committed {
		return nil, egressStepError{"owner config binding"}
	}
	pol, err := egress.FromShieldBootstrap(auth, secrets)
	if err != nil {
		return nil, egressStepError{"allowlist"}
	}
	return e.startPolicy(pol)
}

func (e *shieldEgress) startPolicy(pol *egress.Policy) (*egress.Forwarder, error) {
	var err error
	// The monitor marked the domain public-web (resolv.conf, the DNS port floor, secretrun's ENCLAVE_EGRESS) from the
	// same measured bytes; a disagreement means the domain was not set up for the mode the config states.
	marked := false
	if e.publicWebMarker != "" {
		if marked, err = shieldconfig.PublicWebMarked(e.publicWebMarker, e.configUID); err != nil {
			return nil, egressStepError{"public web marker"}
		}
	}
	if marked != pol.PublicWeb {
		return nil, egressStepError{"public web marker"}
	}
	fwd := &egress.Forwarder{Policy: pol, Port: e.port, Upstream: e.upstream, Logf: domLogf(e.logf),
		PublicListen: e.publicListen, DNSListen: e.dnsListen}
	// the forwarders live as long as this front, which is as long as the domain
	if err := fwd.Start(context.Background()); err != nil {
		return nil, egressStepError{"listen"}
	}
	if err := writeHosts(e.hosts, fwd.HostsFile()); err != nil {
		fwd.Close()
		return nil, egressStepError{"hosts"}
	}
	if err := e.audit(fwd.Listeners()); err != nil {
		fwd.Close()
		return nil, egressStepError{"listener audit"}
	}
	e.say("DOM egress: %d allowed origin(s), %d config URL(s) refused; forwarders listening and /etc/hosts written before the runtime's secrets",
		len(pol.Origins), len(pol.Refused))
	if pol.PublicWeb {
		e.say("DOM egress: public web: SOCKS front and DNS stub listening; any public address over TCP through this deployment's route")
	}
	return fwd, nil
}

func (e *shieldEgress) say(format string, a ...any) {
	if e.logf != nil {
		e.logf(format, a...)
	}
}

// readMeasuredConfig is the domain's /app.config, held to the shape domexec already required before anything started
// (read_app_config: a regular root-owned file nobody may write, within the bundle's limit). Absent = no config.
func readMeasuredConfig(path string, owner int) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || !ok || int(sys.Uid) != owner || st.Mode().Perm()&0o222 != 0 ||
		st.Size() <= 0 || st.Size() > contract.MaxConfigBytes {
		return "", errors.New("the measured config is not a read-only file of the monitor's")
	}
	b, err := io.ReadAll(io.LimitReader(f, contract.MaxConfigBytes+1))
	if err != nil || len(b) > contract.MaxConfigBytes {
		return "", errors.New("the measured config could not be read whole")
	}
	return string(b), nil
}

// writeHosts replaces the CONTENT of the hosts file the monitor made for this front: never creates one (the front cannot
// write /etc itself), never follows a link, and only a regular file this process owns.
func writeHosts(path, text string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); !st.Mode().IsRegular() || !ok || int(sys.Uid) != os.Geteuid() {
		f.Close()
		return fmt.Errorf("%s is not a regular file of this front's", path)
	}
	if _, err := io.WriteString(f, text); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
