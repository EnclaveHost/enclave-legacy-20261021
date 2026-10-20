// Package egress is controlled per-app egress for a per-app SNP guest: outbound HTTPS to the destinations the
// OWNER's authenticated config names, and to the relay the platform pins, and nothing else.
//
// This is NOT "no egress by construction". The guarantee is narrower and stated plainly:
//
//   - the allowlist is derived INSIDE the guest from the config that arrived through the attested release (sealed
//     to the guest, read by the relay from the ledger envelope), never from anything the host delivered, plus the
//     relay origin compiled into the measured image;
//   - only https:// origins on port 443 whose host is a plain DNS name; no IP literals in any spelling, no userinfo,
//     no percent-encoding, no IDN (punycode ASCII is fine), no placeholder left in the authority;
//   - TLS runs inside the guest (the runtime validates the real hostname's certificate), so the host forwards
//     ciphertext. It necessarily OBSERVES each connection's destination hostname (it resolves it, so its DNS
//     resolver sees the query), the address it dials, the port, timing and volume: this is controlled egress, not
//     traffic-analysis privacy. It does not RECORD the destination: its log holds the guest CID and a bounded
//     outcome code only (forward.go), because a destination can come from a secret;
//   - the host dials by name at connect time and refuses loopback, link-local (metadata), private, CGNAT,
//     unspecified and its own addresses on the FINAL resolved IP (dialer.go).
//
// An owner who sets a top-level "egress" list in the config states the allowlist explicitly; otherwise every
// absolute https URL in the resolved config becomes reachable. The explicit string "public-https" instead grants
// arbitrary DNS origins on port 443 through the guest SOCKS forwarder. The host still checks every resolved address
// and peer against the same public-address policy. This mode is opt-in; it is never inferred from an app/tool name.
package egress

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"enclave.host/isolation/m2/appconfig"
	"enclave.host/isolation/m2/bootstrap"
	"enclave.host/isolation/m2/release"
	"enclave.host/isolation/m2/shieldconfig"
)

// Origin is one allowed destination: https, a normalized lowercase DNS name, port 443.
type Origin struct{ Host string }

func (o Origin) String() string { return "https://" + o.Host }

// label: LDH, 1..63, no leading/trailing hyphen. The LAST label must contain a letter, so no spelling a WHATWG
// parser would read as IPv4 (127.1, 2130706433, 0x7f.1, 1e3) can pass: an IPv4-looking last label is all-numeric
// or 0x-hex, and "0x7f" ends in 'f' but starts "0x" and is refused below.
var (
	labelRE    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	hasLetter  = regexp.MustCompile(`[a-z]`)
	hexLabelRE = regexp.MustCompile(`^0x[0-9a-f]*$`)
)

// ParseOrigin judges one URL string and returns its origin, or why it is not an allowed destination.
func ParseOrigin(raw string) (Origin, error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return Origin{}, errors.New("leading or trailing whitespace")
	}
	for _, r := range raw {
		// WHATWG strips tab/newline anywhere and C0/space at the ends; a string it would silently rewrite is refused
		if r < 0x20 || r == 0x7f {
			return Origin{}, errors.New("a control character")
		}
		if r > 0x7e {
			return Origin{}, errors.New("a non-ASCII character (an IDN host must be written in punycode)")
		}
	}
	if len(raw) < 8 || !strings.EqualFold(raw[:8], "https://") {
		return Origin{}, errors.New("not an https:// URL")
	}
	rest := raw[8:]
	// the authority ends at the first / ? # or \ (WHATWG treats a backslash as a slash in special schemes)
	end := strings.IndexAny(rest, "/?#\\")
	auth := rest
	if end >= 0 {
		auth = rest[:end]
	}
	switch {
	case auth == "":
		return Origin{}, errors.New("no host")
	case strings.ContainsAny(auth, "@"):
		return Origin{}, errors.New("userinfo in the authority")
	case strings.ContainsAny(auth, "[]"):
		return Origin{}, errors.New("an IPv6 literal")
	case strings.Contains(auth, "%"):
		return Origin{}, errors.New("percent-encoding in the host")
	case strings.ContainsAny(auth, "${}"):
		return Origin{}, errors.New("an unresolved placeholder in the authority")
	}
	host := auth
	if i := strings.LastIndexByte(auth, ':'); i >= 0 {
		if auth[i+1:] != "443" {
			return Origin{}, fmt.Errorf("port %q (only 443)", auth[i+1:])
		}
		host = auth[:i]
	}
	host = strings.ToLower(host)
	if strings.HasSuffix(host, ".") {
		return Origin{}, errors.New("a trailing dot (refused, so one origin has one spelling)")
	}
	if len(host) > 253 {
		return Origin{}, errors.New("host too long")
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return Origin{}, errors.New("a single-label host")
	}
	for _, l := range labels {
		if !labelRE.MatchString(l) {
			return Origin{}, fmt.Errorf("host label %q is not a DNS label", l)
		}
	}
	last := labels[len(labels)-1]
	if !hasLetter.MatchString(last) || hexLabelRE.MatchString(last) {
		return Origin{}, errors.New("the host reads as an IP address")
	}
	for _, l := range labels {
		if hexLabelRE.MatchString(l) {
			return Origin{}, errors.New("a hex label (an IPv4 spelling)")
		}
	}
	// A second opinion, BELT ONLY: Go's parser must see the SAME host and port, or the URL is refused. No input is
	// known that passes the strict rules above and parses differently here (enclave-99 mutated this check away and no
	// test noticed); it stays as a guard against a future loosening of the rules above, not as the defence.
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.User != nil || strings.ToLower(u.Hostname()) != host ||
		(u.Port() != "" && u.Port() != "443") {
		return Origin{}, errors.New("the URL parses differently under a second parser")
	}
	return Origin{Host: host}, nil
}

// Policy is the guest's allowlist.
type Policy struct {
	PublicWeb   bool     // Shield measured config explicitly permits public TCP; never inferred from secrets
	PublicHTTPS bool     // owner explicitly opted into arbitrary public DNS origins on 443
	Origins     []Origin // sorted, unique
	Refused     []string // the reasons config URLs were NOT allowed, for the guest's own log (no URL text: it may be secret)
}

// FromRelease builds the legacy allowlist from a release the release client OPENED (the
// config the owner set on chain, sealed to this guest by the relay), resolved in-guest, plus the pinned relay origin.
// A Release built any other way, e.g. from config the host handed over, is refused: the allowlist must be the
// owner's, never the host's (enclave-99).
func FromRelease(rel *release.Release, relay Origin) (*Policy, error) {
	if rel == nil || !rel.Attested() {
		return nil, errors.New("egress policy needs a release opened through the attested channel")
	}
	text, err := rel.ConfigText()
	if err != nil {
		return nil, err
	}
	resolved := ""
	if text != "" {
		if resolved, err = appconfig.Resolve(text, rel.Secrets); err != nil {
			return nil, err
		}
	}
	return derive(resolved, relay)
}

// FromBootstrap accepts only a fresh owner package authenticated by the guest's
// measured chain reader. No platform relay origin is implicitly authorized.
// For custody mode, secrets must come from custodySecrets, which verifies the
// bundle's exact ConfigSha256 before returning values to the front.
func FromBootstrap(auth *bootstrap.Authorization, secrets map[string]string) (*Policy, error) {
	text, err := auth.ConfigText()
	if err != nil {
		return nil, err
	}
	mode, err := auth.SecretsMode()
	if err != nil {
		return nil, err
	}
	if mode == "public" && len(secrets) != 0 {
		return nil, errors.New("public startup cannot receive secret values")
	}
	resolved := ""
	if text != "" {
		resolved, err = appconfig.Resolve(text, secrets)
		if err != nil {
			return nil, err
		}
	}
	return deriveOrigins(resolved, nil)
}

// ForShield is the allowlist of a NucBox Shield domain (one app in a Hyper-V partition, isolation/m3) that serves a
// secret deployment. Its two inputs arrive by two different measured paths, and both are required to be what they say:
//
//   - the secrets come from the release the front verified against the pinned relay keys and opened with its own seal
//     key (m2/front shield_secrets.go): a Release built any other way is refused, exactly as FromRelease refuses one;
//   - the config is the domain's measured /app.config (the monitor wrote it from the bundle it hashed). A Shield
//     release carries secrets only, so a release that also carries a config is refused rather than one of the two
//     silently winning.
//
// The config is RESOLVED with the secrets before anything is derived, so an endpoint that is itself a secret
// ("$R2_ENDPOINT") is judged on its resolved value, which only the guest ever sees. Unlike FromRelease there is NO relay
// origin: a Shield domain's release reaches it through its front, never through egress, so nothing outside the owner's
// config is reachable.
func ForShield(rel *release.Release, measuredConfig string) (*Policy, error) {
	if rel == nil || !rel.Attested() {
		return nil, errors.New("egress policy needs a release opened through the attested channel")
	}
	if text, err := rel.ConfigText(); err != nil || text != "" {
		return nil, errors.New("a Shield release carries secrets only: the domain's config is its measured /app.config")
	}
	resolved := ""
	if strings.TrimSpace(measuredConfig) != "" {
		var err error
		if resolved, err = appconfig.Resolve(measuredConfig, rel.Secrets); err != nil {
			return nil, err
		}
	}
	p, err := derivePolicy(resolved, nil, true)
	if err != nil {
		return nil, err
	}
	p.PublicWeb = shieldconfig.PublicWebMode(measuredConfig) // the measured bytes, never a resolved secret, decide the mode
	return p, nil
}

// FromShieldBootstrap derives Shield egress from the same verified owner package used
// for custody. Public-web is selected by committed bytes, never by secret substitution.
func FromShieldBootstrap(auth *bootstrap.Authorization, secrets map[string]string) (*Policy, error) {
	text, err := auth.ConfigText()
	if err != nil {
		return nil, err
	}
	mode, err := auth.SecretsMode()
	if err != nil {
		return nil, err
	}
	if mode == "public" && len(secrets) != 0 {
		return nil, errors.New("public startup cannot receive secret values")
	}
	resolved := ""
	if text != "" {
		resolved, err = appconfig.Resolve(text, secrets)
		if err != nil {
			return nil, err
		}
	}
	p, err := derivePolicy(resolved, nil, true)
	if err != nil {
		return nil, err
	}
	p.PublicWeb = shieldconfig.PublicWebMode(text)
	return p, nil
}

// derive builds the allowlist from the RESOLVED config and the relay origin the measured image pins. An explicit
// top-level "egress" list replaces derivation; the relay origin is always present and config can neither remove
// nor redirect it.
func derive(resolvedConfig string, relay Origin) (*Policy, error) {
	return deriveOrigins(resolvedConfig, []Origin{relay})
}

func deriveOrigins(resolvedConfig string, pinned []Origin) (*Policy, error) {
	return derivePolicy(resolvedConfig, pinned, false)
}

// Shield transport modes preserve its configured-origin behavior. SNP public-https
// remains an explicit grant of arbitrary public DNS origins on port 443.
func derivePolicy(resolvedConfig string, pinned []Origin, shield bool) (*Policy, error) {
	set := map[string]bool{}
	for _, origin := range pinned {
		if _, err := ParseOrigin(origin.String()); err != nil {
			return nil, fmt.Errorf("the pinned platform origin: %w", err)
		}
		set[origin.Host] = true
	}
	p := &Policy{}
	if strings.TrimSpace(resolvedConfig) != "" {
		var doc any
		if err := json.Unmarshal([]byte(resolvedConfig), &doc); err != nil {
			return nil, errors.New("the resolved config is not JSON")
		}
		var candidates []string
		obj, _ := doc.(map[string]any)
		mode, _ := obj["egress"].(string)
		if obj["egress"] != nil && !(shield && (mode == "public-https" || mode == "public-web")) {
			list, ok := obj["egress"].([]any)
			if obj["egress"] == "public-https" {
				p.PublicHTTPS = true
				ok = true
			}
			if !ok {
				return nil, errors.New(`"egress" must be a list of https origins or "public-https"`)
			}
			for _, e := range list {
				s, ok := e.(string)
				if !ok {
					return nil, errors.New(`"egress" must be a list of https origins or "public-https"`)
				}
				candidates = append(candidates, s)
			}
		} else {
			walkStrings(doc, func(s string) {
				if len(s) >= 8 && strings.EqualFold(s[:8], "https://") {
					candidates = append(candidates, s)
				}
			})
		}
		for _, c := range candidates {
			o, err := ParseOrigin(c)
			if err != nil {
				p.Refused = append(p.Refused, err.Error())
				continue
			}
			set[o.Host] = true
		}
	}
	for h := range set {
		p.Origins = append(p.Origins, Origin{Host: h})
	}
	sort.Slice(p.Origins, func(i, j int) bool { return p.Origins[i].Host < p.Origins[j].Host })
	return p, nil
}

func walkStrings(v any, f func(string)) {
	switch x := v.(type) {
	case string:
		f(x)
	case []any:
		for _, e := range x {
			walkStrings(e, f)
		}
	case map[string]any:
		for _, e := range x {
			walkStrings(e, f)
		}
	}
}

// Allows reports whether a hostname is an allowed origin (normalized the same way).
func (p *Policy) Allows(host string) bool {
	o, err := ParseOrigin("https://" + host + "/")
	if err != nil {
		return false
	}
	if p.PublicHTTPS {
		return true
	}
	for _, a := range p.Origins {
		if a.Host == o.Host {
			return true
		}
	}
	return false
}
