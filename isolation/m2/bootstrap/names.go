package bootstrap

// Owner-committed names: the optional "names" member of a startup package.
//
// A package may list the DNS names its measured guest is willing to certify for
// its own attested TLS key, and may select an ACME directory plus a DNS-01
// challenge responder for in-guest issuance. None of this proves that the owner
// controls a name: the listing only makes the guest willing to produce a CSR
// for it and to install a certificate for it. Control is proven, as for anyone,
// by a CA validating the name through its normal DNS authority, which is where
// the owner's own _acme-challenge delegation lives (ChallengeAlias).
//
// The member is absent from every package written before it existed, so those
// exact bytes keep their meaning and hash. Present, it is validated byte for
// byte the same way by sdk/bootstrap/package.mjs (testdata/names-vectors.json).
// It never carries credential material: EAB values are custody secrets named
// here by key, and resolved only inside the guest.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const (
	MaxOwnerNames = 10
	maxNameURL    = 512
	// NameGrace bounds how long names stay authorized after the last fresh
	// agreeing chain read. A lease end or owner change seen by the quorum ends
	// them at once (Refresh); an RPC outage ends them after this grace.
	NameGrace = 10 * time.Minute
)

type Names struct {
	Hosts []string  `json:"hosts"`
	ACME  *NameACME `json:"acme,omitempty"`
}

// NameACME selects the CA and the DNS-01 responder for in-guest issuance. All
// three are explicit: there is no default CA, responder or zone to fall back to.
type NameACME struct {
	Directory string   `json:"directory"`
	Challenge string   `json:"challenge"`
	Zone      string   `json:"zone"`
	EAB       *NameEAB `json:"eab,omitempty"`
}

// NameEAB names the custody secrets holding an external account binding. The
// values never appear in the public package.
type NameEAB struct {
	KID  string `json:"kid"`
	HMAC string `json:"hmac"`
}

var (
	dnsLabelRE   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	letterRE     = regexp.MustCompile(`[a-z]`)
	nameURLRE    = regexp.MustCompile(`^https://([^/]+)(/[A-Za-z0-9._~/-]*)?$`)
	secretNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
)

// DNSName: lowercase LDH labels, at least two, a top label with a letter (so
// never an IP literal), no wildcard, no trailing dot, at most 253 bytes.
func DNSName(s string) bool {
	if len(s) < 1 || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !dnsLabelRE.MatchString(l) {
			return false
		}
	}
	return letterRE.MatchString(labels[len(labels)-1])
}

// OwnerHost: a DNSName outside the platform zone, whose names keep their own
// HOST_DATA-derived path and authority.
func OwnerHost(s string) bool {
	return DNSName(s) && s != "enclave.host" && !strings.HasSuffix(s, ".enclave.host")
}

func nameURL(s string) bool {
	m := nameURLRE.FindStringSubmatch(s)
	return len(s) <= maxNameURL && m != nil && DNSName(m[1])
}

// noNull refuses a JSON null anywhere inside the names member: an explicit
// null must not read as "absent" in one language and as an error in another.
func noNull(raw json.RawMessage) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	for {
		t, e := d.Token()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		if t == nil {
			return errors.New("null in owner names")
		}
	}
}

// namesField validates the optional member as it appears in the exact package
// bytes (raw), after strictJSON decoded them into n.
func namesField(raw []byte, n *Names, secretsMode string) error {
	var top map[string]json.RawMessage
	if e := json.Unmarshal(raw, &top); e != nil {
		return errors.New("invalid startup package JSON")
	}
	member, present := top["names"]
	if !present {
		return nil
	}
	if n == nil || noNull(member) != nil {
		return errors.New("owner names must be an object without nulls")
	}
	return n.Validate(secretsMode)
}

func (n *Names) Validate(secretsMode string) error {
	if n == nil {
		return errors.New("owner names missing")
	}
	if len(n.Hosts) < 1 || len(n.Hosts) > MaxOwnerNames {
		return fmt.Errorf("owner names need 1 to %d hosts", MaxOwnerNames)
	}
	for i, h := range n.Hosts {
		if !OwnerHost(h) {
			return errors.New("owner name is not a lowercase DNS name outside enclave.host")
		}
		if i > 0 && n.Hosts[i-1] >= h {
			return errors.New("owner names must be strictly ascending and unique")
		}
	}
	if a := n.ACME; a != nil {
		if !nameURL(a.Directory) || !nameURL(a.Challenge) || !DNSName(a.Zone) {
			return errors.New("owner ACME selection needs HTTPS directory and challenge URLs and a DNS zone")
		}
		if len("_acme-challenge.")+32+1+len(a.Zone) > 253 {
			return errors.New("owner ACME challenge zone is too long")
		}
		if e := a.EAB; e != nil {
			if !secretNameRE.MatchString(e.KID) || !secretNameRE.MatchString(e.HMAC) || e.KID == e.HMAC {
				return errors.New("owner ACME EAB must name two distinct custody secrets")
			}
			if secretsMode != "custody-v2" {
				return errors.New("owner ACME EAB needs custody-v2 secrets")
			}
		}
	}
	return nil
}

// ChallengeLabel is the single DNS label a deployment's DNS-01 alias uses. It
// commits to the deployment AND its owner, so a delegation published for one
// owner stops working when the deployment changes hands.
func ChallengeLabel(deployment [32]byte, owner string) (string, error) {
	o, e := hex.DecodeString(strings.TrimPrefix(strings.ToLower(owner), "0x"))
	if e != nil || len(o) != 20 || !strings.HasPrefix(strings.ToLower(owner), "0x") || zero(o) || zero(deployment[:]) {
		return "", errors.New("challenge label needs a deployment and owner")
	}
	h := sha256.New()
	h.Write([]byte("enclave-acme-alias-v1\x00"))
	h.Write(deployment[:])
	h.Write(o)
	return hex.EncodeToString(h.Sum(nil))[:32], nil
}

// ChallengeAlias is the name the owner points _acme-challenge.<host> at (CNAME).
func ChallengeAlias(deployment [32]byte, owner, zone string) (string, error) {
	l, e := ChallengeLabel(deployment, owner)
	if e != nil || !DNSName(zone) {
		return "", errors.New("challenge alias needs a label and a DNS zone")
	}
	return "_acme-challenge." + l + "." + zone, nil
}

// NameGrant is what the owner's committed names authorize at this moment.
type NameGrant struct {
	Deployment [32]byte
	Owner      string // lowercase 0x address, as the ledger quorum read it
	Hosts      []string
	ACME       *NameACME
	Until      time.Time
}

// ErrRevoked: a fresh agreeing quorum reported the lease cancelled, suspended,
// released or ended, or the owner, runner, operator, app reference or envelope
// changed (or the authorization was never valid). Names never return for this
// guest.
var ErrRevoked = errors.New("owner-committed authorization revoked")

// NameGrant returns the committed names while the authorization is current;
// Hosts is empty when the package lists none.
func (a *Authorization) NameGrant() (NameGrant, error) {
	if !a.current() {
		return NameGrant{}, errors.New("startup authorization expired or unverified")
	}
	g := NameGrant{Deployment: a.snapshot.row.id, Owner: strings.ToLower(a.snapshot.row.owner)}
	if a.manifest.Names == nil {
		return g, nil
	}
	g.Hosts = append([]string(nil), a.manifest.Names.Hosts...)
	if src := a.manifest.Names.ACME; src != nil {
		cp := *src
		if src.EAB != nil {
			eab := *src.EAB
			cp.EAB = &eab
		}
		g.ACME = &cp
	}
	g.Until = time.Unix(int64(a.snapshot.timestamp), 0).Add(NameGrace)
	if lease := time.Unix(int64(a.snapshot.row.leaseUntil), 0); lease.Before(g.Until) {
		g.Until = lease
	}
	return g, nil
}

// Refresh reads a fresh agreeing snapshot. Unlike Revalidate, a read that fails
// (no two peers agree on the same block's raw facts, or none is fresh) leaves the
// authorization as it was - it still expires on its own clock, at most
// NameGrace after its last agreed snapshot - so an RPC outage or a single lying
// peer cannot revoke a running guest's names. What the quorum DOES agree on is
// judged at once: a lease it reports cancelled, suspended, released or ended, or
// any change of owner, runner, operator, app reference or envelope, revokes the
// names for good.
func (a *Authorization) Refresh(ctx context.Context) error {
	if a == nil || !a.valid || a.reader == nil {
		return ErrRevoked
	}
	next, e := a.reader.read(ctx, a.snapshot.row.id)
	if e != nil {
		return &snapshotUnavailable{e}
	}
	if e = a.reader.leaseCurrent(next); e != nil {
		a.valid = false
		return fmt.Errorf("%w: %v", ErrRevoked, e)
	}
	old, n := a.snapshot.row, next.row
	if next.number < a.snapshot.number || n.owner != old.owner || n.runner != old.runner || n.operator != old.operator || n.appRef != old.appRef || n.envelope != old.envelope {
		a.valid = false
		return ErrRevoked
	}
	a.snapshot = next
	return nil
}
