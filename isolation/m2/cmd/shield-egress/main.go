// shield-egress: the Windows host's end of outbound HTTPS for ONE NucBox Shield partition (isolation/m2/egress).
//
//	app (wasi:http) -> /etc/hosts -> the front's forwarder 127.64.0.N:443 -> AF_VSOCK CID 2 port 9443 (hv_sock)
//	  -> shielded-bridge.exe <vmId> 9443 <port> 0   binds THAT partition's service only, checks every peer's VmId
//	  -> shield-egress -listen 127.0.0.1:<port>      this program: the egress-v1 server (egress.Server)
//	  -> SOCKS5 CONNECT <judged public IP>:443        the host's loopback TUNA entry, and nothing else
//
// One process per partition, started by the manager (windows/vbslike/manager/egress.mjs) after the VM and stopped with
// it. What it enforces is m2's host side, unchanged:
//   - the guest names ONE DNS host on 443 per stream (the forwarder's bound origin, never tenant bytes); an IP literal,
//     a single label or another port is refused;
//   - EVERY resolved address must be public: loopback, RFC1918, link-local and metadata, CGNAT, multicast, reserved,
//     NAT64/6to4/Teredo, documentation ranges and this host's own addresses are refused (egress.RefuseAddr);
//   - the dial is the judged IP literal through the SOCKS entry (-socks) or the deployment's own route (-app-routes);
//     there is NO direct path, so an entry that is down is a refused stream, never a fallback;
//   - per-partition rate and concurrency caps (and shielded-bridge admits at most 64 streams at once);
//   - -allow, when given, is a host-side narrowing on top of the guest's own allowlist. The guest's list is derived
//     from secrets this host never sees, so without -allow the host checks shape and address, as m2's guestd does.
//   - a PUBLIC-WEB partition (its measured config says "egress": "public-web"; egress/web.go) also sends
//     "egress-web-v1 <host|ip> <port>" and "egress-dns-v1 <name> 0": any public address, any TCP port but 0 and 25,
//     resolved by DoH and dialed through the same route, with every rule above on every address. With -allow, a
//     literal is refused and a name must be on the list.
//
// It never logs a hostname, an address, a URL or a payload: one line per stream, "guest 1 egress open" or
// "guest 1 egress refused:<code>" from a closed set (egress.Reason). TLS runs inside the guest end to end; this process
// moves ciphertext. Lifetime: until stdin reaches EOF (the manager holds the pipe), so it cannot outlive its manager.
//
// usage: shield-egress -socks 127.0.0.1:30489 [-listen 127.0.0.1:0] [-allow https://a.example,https://b.example]
//
//	shield-egress -app-routes <routes.json> -deployment 0x<64 hex> [-listen ...] [-allow ...]
//
// Prints "shield-egress ready listen=127.0.0.1:<port>" on stdout once it accepts.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"

	"enclave.host/isolation/m2/egress"
)

// partition is the one guest this process serves: the bridge in front of it admits only that partition's VmId, so every
// stream is from it, and the per-guest caps are this partition's caps.
const partition uint32 = 1

// lookup is the host's resolver (Windows' own); a test replaces it.
var lookup egress.Resolver = net.DefaultResolver

var deploymentRE = regexp.MustCompile(`^0x[0-9a-f]{64}$`)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "shield-egress: %v\n", err)
		os.Exit(2)
	}
}

// config is what the flags say, checked before anything listens.
type config struct {
	blob       string // -blob-service: loopback address of the host blob cache ("" = off)
	listen     netip.AddrPort
	socks      string
	routes     string
	deployment string
	allow      *egress.Policy
}

func parse(args []string, errOut io.Writer) (*config, error) {
	fs := flag.NewFlagSet("shield-egress", flag.ContinueOnError)
	fs.SetOutput(errOut)
	listen := fs.String("listen", "127.0.0.1:0", "loopback IP:port the partition's shielded-bridge relays to (port 0: any free port, printed on ready)")
	socks := fs.String("socks", "", "the host's loopback SOCKS5 entry IP:port (TUNA); every dial goes through it")
	routes := fs.String("app-routes", "", "an expiring per-app routes file (egress.ReadAppRoute); exclusive with -socks")
	deployment := fs.String("deployment", "", "the deployment this partition serves (0x + 64 hex); required with -app-routes")
	allow := fs.String("allow", "", "optional comma-separated https origins: the host refuses any other name for this partition")
	blob := fs.String("blob-service", "", "optional loopback IP:port of the host's cache for public, pinned content: "+egress.BlobHost+":80 is dialed there instead of the app's route")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("unexpected arguments %q", fs.Args())
	}
	c := &config{socks: *socks, routes: *routes, deployment: *deployment}
	if *blob != "" {
		ap, err := netip.ParseAddrPort(*blob)
		if err != nil || !ap.Addr().IsLoopback() || ap.Port() == 0 {
			return nil, errors.New("-blob-service must be a loopback IP:port")
		}
		c.blob = ap.String()
	}
	a, err := netip.ParseAddrPort(*listen)
	if err != nil || !a.Addr().IsLoopback() {
		return nil, errors.New("-listen must be a loopback IP:port: the bridge for this partition is the only client")
	}
	c.listen = a
	switch {
	case c.socks != "" && c.routes != "":
		return nil, errors.New("-socks and -app-routes are mutually exclusive")
	case c.socks != "":
		if err := egress.ValidateSOCKSProxy(c.socks); err != nil {
			return nil, err
		}
		if c.deployment != "" {
			return nil, errors.New("-deployment is for -app-routes")
		}
	case c.routes != "":
		if !deploymentRE.MatchString(c.deployment) {
			return nil, errors.New("-app-routes needs -deployment 0x<64 lowercase hex>: a route is the deployment's own")
		}
	default:
		return nil, errors.New("no upstream: -socks or -app-routes is required, and there is no direct path")
	}
	if *allow != "" {
		c.allow = &egress.Policy{}
		for _, raw := range strings.Split(*allow, ",") {
			o, err := egress.ParseOrigin(strings.TrimSpace(raw))
			if err != nil {
				return nil, fmt.Errorf("-allow: an entry is not an https origin on 443: %v", err)
			}
			c.allow.Origins = append(c.allow.Origins, o)
		}
	}
	return c, nil
}

// server is the egress-v1 endpoint the flags describe: the m2 Server and Dialer, with this partition's one upstream.
func (c *config) server(logw io.Writer) *egress.Server {
	// a public-web guest's browser holds many connections and looks up many names (each one a dial in the window)
	d := &egress.Dialer{Resolver: lookup, Own: hostAddrs, MaxConcurrent: 96, MaxPerMinute: 2400, SOCKSProxy: c.socks, BlobService: c.blob}
	if c.routes != "" {
		file, dep := c.routes, c.deployment
		d.RouteFor = func(uint32) (egress.AppRoute, error) { return egress.ReadAppRoute(file, dep) }
	}
	if c.allow != nil {
		d.Allow = c.allow.Allows
	}
	return &egress.Server{Dialer: d,
		CIDOf: func(net.Conn) uint32 { return partition },
		Admit: func(cid uint32) bool { return cid == partition },
		Log:   log.New(logw, "shield-egress: ", log.LstdFlags)}
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, logw io.Writer) error {
	c, err := parse(args, logw)
	if err != nil {
		return err
	}
	l, err := net.Listen("tcp", c.listen.String())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// the manager's pipe: EOF (or any read error) ends this process, and with it every stream it carries
	go func() {
		io.Copy(io.Discard, stdin)
		cancel()
	}()
	mode := "socks"
	if c.routes != "" {
		mode = "app-routes"
	}
	allowed := 0
	if c.allow != nil {
		allowed = len(c.allow.Origins)
	}
	fmt.Fprintf(stdout, "shield-egress ready listen=%s upstream=%s host-allow=%d\n", l.Addr(), mode, allowed)
	if err := c.server(logw).Serve(ctx, l); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

// hostAddrs is this host's own addresses, read at each dial: never a destination.
func hostAddrs() []netip.Addr {
	var out []netip.Addr
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range as {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr())
		}
	}
	return out
}
