package main

// The oracle audit, as source checks (docs/security/attested-release.md, "the enumeration of every report path"; and
// enclave-99's note 2 on listeners). The runtime audit (provision.go auditListeners) checks the guest's sockets
// before the app starts; these check the CODE, so a new path to the report device or a new listener fails here
// before it can reach an image.
//
// Why it matters: the release binding is its own domain, and a report over it is worth a deployment's secrets. Every
// way this binary can ask the hardware (or a monitor, or the SVSM) for a report must be one of the known callers,
// each writing a report_data it composed itself: attestDoc (Bind/Bind2 over a verifier's nonce, or the hash of an
// owner-name challenge push in acme.go - the same public binding any caller can already ask for - never the release
// domain), hostData (all-zero report_data, never served) and the provisioner (the release binding, never served).
// And every socket this binary listens on must be one of: the front's own endpoint (vsock, or the M3 unix socket)
// and the egress forwarders - the tenant reaches the guest's loopback, so a listener there is the tenant's to call.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type site struct{ file, fn, what string }

// sites walks every non-test Go file in dirs and reports, per enclosing function, each selector or string literal
// that match() names.
func sites(t *testing.T, dirs []string, match func(n ast.Node) string) []site {
	t.Helper()
	var out []site
	fset := token.NewFileSet()
	for _, dir := range dirs {
		abs, err := filepath.Abs(dir)
		if err != nil {
			t.Fatal(err)
		}
		label := filepath.Base(abs)
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		if len(files) == 0 {
			t.Fatalf("%s has no Go files: the audit would see nothing there", dir)
		}
		for _, path := range files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				name := fd.Name.Name
				if fd.Recv != nil && len(fd.Recv.List) == 1 {
					rt := fd.Recv.List[0].Type
					if st, ok := rt.(*ast.StarExpr); ok {
						rt = st.X
					}
					if id, ok := rt.(*ast.Ident); ok {
						name = id.Name + "." + name
					}
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if w := match(n); w != "" {
						out = append(out, site{label + "/" + filepath.Base(path), name, w})
					}
					return true
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].file+out[i].fn+out[i].what < out[j].file+out[j].fn+out[j].what
	})
	return out
}

func render(ss []site) string {
	var b []string
	for _, s := range ss {
		b = append(b, s.file+" "+s.fn+": "+s.what)
	}
	return strings.Join(b, "\n")
}

// the packages this binary links from this module that could touch a report or a socket
var linked = []string{".", "../egress", "../release", "../appconfig", "../vsock", "../domtls", "../custody"}

func TestEveryReportPathIsAKnownOne(t *testing.T) {
	got := sites(t, linked, func(n ast.Node) string {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			// the three report sources: configfs-tsm (front.report), the M3 monitor, the M4b SVSM plane
			switch x.Sel.Name {
			case "report", "askMonitor":
				if id, ok := x.X.(*ast.Ident); ok && (id.Name == "f" || id.Name == "p") {
					return id.Name + "." + x.Sel.Name // p: the provisioner's report function (wired to f.report in main)
				}
				if s, ok := x.X.(*ast.SelectorExpr); ok && s.Sel.Name == "plane" && x.Sel.Name == "report" {
					return "f.plane.report"
				}
			}
		case *ast.BasicLit:
			if x.Kind == token.STRING && strings.Contains(x.Value, "/sys/kernel/config/tsm") {
				return "configfs-tsm path"
			}
		}
		return ""
	})
	want := strings.Join([]string{
		// custody: report_data = the CUSTODY binding (domain "enclave-custody-release-v1\n", or "enclave-custody-release-v2\n"
		// for a v2 pointer; distinct from Bind/Bind2 and from the relay release's) || the AppID from the loaded code; sent
		// to custodians only, never served
		"front/custody.go provisioner.custodySecrets: p.report",
		"front/main.go front.attestDoc: f.askMonitor",   // M3: the monitor writes the app half; the front sends Bind/Bind2
		"front/main.go front.attestDoc: f.plane.report", // M4b: the SVSM computes the binding; the front sends a nonce
		"front/main.go front.attestDoc: f.report",       // M2: Bind/Bind2 over the verifier's (or acme.go's push) nonce, served
		"front/main.go front.hostData: f.askMonitor",    // all-zero report_data, never served
		"front/main.go front.hostData: f.report",        // all-zero report_data, never served
		"front/main.go front.report: configfs-tsm path",
		"front/main.go main: f.report",                                             // wired as the provisioner's report function
		"front/provision.go provisioner.run: p.report",                             // the release binding || AppID, never served
		"front/shield_direct_custody.go front.shieldCustodyEvidence: f.askMonitor", // Shield custody domain + owner + v2 release binding; monitor supplies AppID
		"front/shield_secrets.go front.serveShieldSecrets: f.askMonitor",           // Shield secret purpose + seal key binding; monitor supplies AppID
	}, "\n")
	if g := render(got); g != want {
		t.Fatalf("the paths to a report changed; review each against the release binding's domain, then update this list.\ngot:\n%s\nwant:\n%s", g, want)
	}
}

func TestEveryListenerIsAKnownOne(t *testing.T) {
	got := sites(t, linked, func(n ast.Node) string {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return ""
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return ""
		}
		switch pkg.Name + "." + sel.Sel.Name {
		case "net.Listen", "net.ListenPacket", "net.ListenTCP", "net.ListenUDP", "net.ListenUnix", "net.ListenIP",
			"tls.Listen", "vsock.Listen", "syscall.Listen", "syscall.Bind", "http.ListenAndServe", "http.ListenAndServeTLS":
			return pkg.Name + "." + sel.Sel.Name
		}
		return ""
	})
	want := strings.Join([]string{
		"egress/forward.go Forwarder.Start: net.Listen",      // one loopback listener per allowed origin: the tenant's egress
		"egress/public.go Forwarder.startPublic: net.Listen", // owner-opted public HTTPS; SOCKS CONNECT only, host IP checks unchanged
		"egress/web.go Forwarder.startPublicWeb: net.Listen", // measured Shield public-web SOCKS; public-address guards before forwarding
		"egress/web.go Forwarder.startPublicWeb: net.Listen", // bounded TCP DNS stub; only public answers
		"front/main.go main: net.Listen",                     // M3: the unix socket the monitor relays (-listen-unix)
		"front/main.go main: vsock.Listen",                   // M2: the front's one port
		"vsock/vsock.go Listen: syscall.Listen",              // the vsock binding itself
	}, "\n")
	if g := render(got); g != want {
		t.Fatalf("the listeners changed; the tenant reaches the guest's loopback, so review each one, then update this list.\ngot:\n%s\nwant:\n%s", g, want)
	}
}
