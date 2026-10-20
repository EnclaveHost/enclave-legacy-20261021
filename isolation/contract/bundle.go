// Package contract is the backend-neutral part of an app domain: what an app IS (the bundle and its
// identity), what a report BINDS (key, nonce, app), what a domain may ASK (a report request has one
// field), and how a domain's life PROCEEDS (starting, running, ending, ended -- exactly one reclamation
// however it ends). Every isolation backend -- the Linux monitor inside an SEV-SNP guest
// (isolation/m3), the Windows launcher driving Hyper-V partitions (windows/vbslike) -- imports or
// mirrors this package and passes vectors.json, so the app-facing ABI is one thing and the hardware
// mechanism behind it is the backend's business.
//
// ABI version: enclave-domain-abi/1. Anything here that changes meaning bumps it.
package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"unicode/utf8"
)

const ABI = "enclave-domain-abi/1"

// The bundle: ONE portable artifact, the same bytes on every host, whose identity is the sha256 of
// exactly these bytes.
//
//	magic         "ENCLAVE-BUNDLE/1\n"                       17 bytes
//	u32le         manifest length
//	manifest      canonical JSON (keys sorted, no whitespace) -- see Canonical
//	u32le         artifact length
//	artifact      the app bytes (a Wasm component today)
//
// A bundle whose manifest is not in canonical form, or whose manifest names a different artifact
// hash than the artifact carried, is malformed and has no identity: Parse refuses it. That is what
// keeps "same app, same manifest" a single byte string with a single ID.
const BundleMagic = "ENCLAVE-BUNDLE/1\n"

const MaxManifestBytes = 64 << 10

const MaxConfigBytes = 32 << 10

// Public app configuration is measured with the artifact. Base64 keeps the bundle
// canonical across JSON encoders; it is not encryption or a secret channel.
func (m Manifest) AppConfig() ([]byte, error) {
	if m.SecretDeployment != "" && (!regexp.MustCompile(`^0x[0-9a-f]{64}$`).MatchString(m.SecretDeployment) || m.ConfigBase64 == "") {
		return nil, errors.New("secrets require a deployment-bound configuration bundle")
	}
	if m.ConfigBase64 == "" {
		return nil, nil
	}
	validWorld := (m.World == WorldHTTP && m.HTTP == 0) || (m.World == WorldCLI && m.HTTP >= 1 && m.HTTP <= MaxHTTPPort)
	if !validWorld || m.Inference != nil || (len(m.Ports) != 0 && m.SecretDeployment == "") {
		return nil, errors.New("app configuration requires a CPU HTTP component or single-port command bundle")
	}
	if err := ValidatePorts(m.Ports, m.World, m.HTTP); err != nil {
		return nil, err
	}
	if m.SecretDeployment != "" && m.World == WorldCLI && m.HTTP < 1024 {
		return nil, errors.New("secret command HTTP port must be unprivileged")
	}
	if len(m.ConfigBase64) > base64.StdEncoding.EncodedLen(MaxConfigBytes) {
		return nil, errors.New("app configuration exceeds byte limit")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(m.ConfigBase64)
	if err != nil || base64.StdEncoding.EncodeToString(b) != m.ConfigBase64 || len(b) > MaxConfigBytes || !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return nil, errors.New("invalid app configuration encoding")
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(b, &object) != nil || object == nil {
		return nil, errors.New("app configuration must be a JSON object")
	}
	return b, nil
}

type Manifest struct {
	SecretDeployment string     `json:"secretDeployment,omitempty"`
	ConfigBase64     string     `json:"configBase64,omitempty"`
	Inference        *Inference `json:"inference,omitempty"`
	ABI              string     `json:"abi"`
	Label            string     `json:"label,omitempty"`
	World            string     `json:"world,omitempty"` // WorldHTTP (served by the runtime) or WorldCLI (a command that listens itself)
	Ports            []string   `json:"ports,omitempty"` // V3: sorted measured tcp:N/udp:N tunnel destinations
	HTTP             int        `json:"http,omitempty"`  // WorldCLI only: the port the app serves HTTP on inside its domain
	Artifact         Artifact   `json:"artifact"`
	Policy           Policy     `json:"policy"`
}

// The two worlds a bundle may state. WorldHTTP: a wasi:http proxy component the runtime SERVES (it owns the
// listener). WorldCLI: a command component that binds its own port through wasi:sockets and serves HTTP there; the
// bundle then names that port (HTTP), so the domain knows where its front forwards without asking anyone.
// Absent world = WorldHTTP (every bundle before WorldCLI existed). A bundle that is not WorldCLI names no port, so
// every bundle built before this field keeps exactly its bytes and its AppID.
const (
	WorldHTTP   = "wasi:http"
	WorldCLI    = "wasi:cli"
	MaxHTTPPort = 49999 // the platform's declarable port range (1-49999)
)

// KindWasmComponent is the ONLY artifact kind a bundle may carry. The app is distributed as a portable
// WebAssembly component and compiled INSIDE its domain to the local ISA (x86-64 in a Linux or Hyper-V
// domain, ARM64 in a Pixel pVM). Native code and precompiled cwasm are never part of the app contract:
// they would tie the artifact to one host, and a domain that compiles what it verified is the point.
const KindWasmComponent = "wasm-component"

type Artifact struct {
	Kind   string `json:"kind"`   // must be KindWasmComponent
	Sha256 string `json:"sha256"` // hex sha256 of the artifact bytes carried in the bundle
}

// Policy is the share a domain gets. It is part of the identity because it is part of the bundle.
type Policy struct {
	CPUPercent int `json:"cpuPercent"`
	MemMiB     int `json:"memMiB"`
	Vcpus      int `json:"vcpus"`
}

// Canonical returns v as compact JSON with keys sorted at every level: the one byte form a
// manifest (or a report document) has, whatever encoder produced it.
func Canonical(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(b, &generic); err != nil {
		return nil, err
	}
	// encoding/json sorts map keys and emits no whitespace; HTML escaping is turned off so that the
	// bytes are what any standard JSON encoder produces (serde_json, JSON.stringify), not Go's \u003c.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(generic); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Build assembles a bundle from a manifest and the artifact it describes. The manifest's artifact
// hash is set from the bytes, so a caller cannot build a bundle that lies about its artifact.
func Build(m Manifest, artifact []byte) ([]byte, error) {
	if m.Artifact.Kind == "" {
		m.Artifact.Kind = KindWasmComponent
	}
	if m.Artifact.Kind != KindWasmComponent {
		return nil, fmt.Errorf("artifact kind %q is not distributable: the contract carries %s only", m.Artifact.Kind, KindWasmComponent)
	}
	sum := sha256.Sum256(artifact)
	m.Artifact.Sha256 = hex.EncodeToString(sum[:])
	if m.ABI == "" {
		m.ABI = ABI
	}
	mb, err := Canonical(m)
	if err != nil {
		return nil, err
	}
	if len(mb) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest exceeds %d bytes", MaxManifestBytes)
	}
	out := make([]byte, 0, len(BundleMagic)+8+len(mb)+len(artifact))
	out = append(out, BundleMagic...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(mb)))
	out = append(out, mb...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(artifact)))
	out = append(out, artifact...)
	return out, nil
}

// IsBundle reports whether bytes carry the bundle magic. Bytes that do not are a BARE artifact: a
// backend may accept one (isolation/m3 did before bundles existed) and its identity is then simply
// sha256(bytes), with the manifest taken as absent.
func IsBundle(b []byte) bool { return bytes.HasPrefix(b, []byte(BundleMagic)) }

// AppID is the identity of whatever bytes a domain was loaded with: the sha256 of ALL of them. For a
// bundle that covers the manifest and the artifact; for a bare artifact, the artifact.
func AppID(b []byte) [32]byte { return sha256.Sum256(b) }

var ErrNotBundle = errors.New("not a bundle")

// Parse checks a bundle and returns its manifest and artifact. It refuses a non-canonical manifest
// and an artifact hash that does not match the bytes, so anything Parse accepts has exactly one
// byte form and one ID.
func Parse(b []byte) (Manifest, []byte, error) {
	var m Manifest
	if !IsBundle(b) {
		return m, nil, ErrNotBundle
	}
	p := b[len(BundleMagic):]
	if len(p) < 4 {
		return m, nil, errors.New("bundle truncated at manifest length")
	}
	ml := binary.LittleEndian.Uint32(p)
	p = p[4:]
	if ml > MaxManifestBytes || uint64(ml) > uint64(len(p)) {
		return m, nil, errors.New("bundle manifest length out of range")
	}
	mb := p[:ml]
	p = p[ml:]
	if len(p) < 4 {
		return m, nil, errors.New("bundle truncated at artifact length")
	}
	al := binary.LittleEndian.Uint32(p)
	p = p[4:]
	if uint64(al) != uint64(len(p)) {
		return m, nil, fmt.Errorf("bundle artifact length %d does not match %d bytes present", al, len(p))
	}
	if err := json.Unmarshal(mb, &m); err != nil {
		return m, nil, fmt.Errorf("bundle manifest: %w", err)
	}
	canon, err := Canonical(m)
	if err != nil {
		return m, nil, err
	}
	if !bytes.Equal(canon, mb) {
		return m, nil, errors.New("bundle manifest is not in canonical form")
	}
	if m.ABI != ABI {
		return m, nil, fmt.Errorf("bundle abi %q is not %q", m.ABI, ABI)
	}
	if err := m.Inference.Validate(); err != nil {
		return m, nil, err
	}
	if err := ValidatePorts(m.Ports, m.World, m.HTTP); err != nil {
		return m, nil, err
	}
	switch m.World {
	case "", WorldHTTP:
		if m.HTTP != 0 {
			return m, nil, fmt.Errorf("bundle world %q is served by the runtime and names no port (http %d)", m.World, m.HTTP)
		}
	case WorldCLI:
		if m.HTTP < 1 || m.HTTP > MaxHTTPPort {
			return m, nil, fmt.Errorf("bundle world %s must name the port it serves HTTP on (1-%d), not %d", WorldCLI, MaxHTTPPort, m.HTTP)
		}
	default:
		return m, nil, fmt.Errorf("bundle world %q is not %s or %s", m.World, WorldHTTP, WorldCLI)
	}
	if m.Artifact.Kind != KindWasmComponent {
		return m, nil, fmt.Errorf("bundle artifact kind %q is not distributable: only %s is", m.Artifact.Kind, KindWasmComponent)
	}
	sum := sha256.Sum256(p)
	if m.Artifact.Sha256 != hex.EncodeToString(sum[:]) {
		return m, nil, errors.New("bundle manifest names a different artifact than it carries")
	}
	if _, err := m.AppConfig(); err != nil {
		return m, nil, err
	}
	return m, p, nil
}
