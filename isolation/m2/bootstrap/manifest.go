package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"enclave.host/isolation/m2/release"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

const MaxManifestBytes = 128 * 1024

// Manifest is a new, explicit owner intent. Legacy envelopes do not opt in
// and can never fall back to public/no-secrets startup on an error.
// ConfigText is exact text: custody commits to its bytes, not a reserialization.
type Manifest struct {
	Version     int              `json:"version"`
	ChainID     uint64           `json:"chainId"`
	Ledger      string           `json:"ledger"`
	Deployment  string           `json:"deployment"`
	Owner       string           `json:"owner"`
	AppRef      string           `json:"appRef"`
	AppID       string           `json:"appId"`
	RuntimeID   string           `json:"runtimeId"`
	ConfigText  string           `json:"configText"`
	SecretsMode string           `json:"secretsMode"`
	Custody     *release.Custody `json:"custody,omitempty"`
	// Names is optional and absent from every package written before it
	// existed, so those exact bytes keep their meaning (names.go).
	Names *Names `json:"names,omitempty"`
}
type Identity struct{ AppID, RuntimeID [32]byte }
type commitment struct {
	Version int    `json:"version"`
	SHA256  string `json:"sha256"`
}

// Usable fields are private and assigned only after a fresh ledger quorum.
type Authorization struct {
	reader   *Reader
	snapshot snapshot
	manifest Manifest
	valid    bool
}

func uniqueJSON(b []byte) error {
	if !utf8.Valid(b) {
		return errors.New("invalid JSON UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return errors.New("JSON nesting limit")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return errors.New("duplicate JSON key")
				}
				seen[s] = true
				if e = value(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e = value(depth + 1); e != nil {
					return e
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, e = d.Token()
		return e
	}
	if e := value(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}
func strictJSON(b []byte, out any) error {
	if e := uniqueJSON(b); e != nil {
		return e
	}
	if e := exactFields(b, reflect.TypeOf(out)); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

// encoding/json otherwise accepts case aliases such as Version/version as the
// same Go field. Reject those aliases before decoding an owner intent.
func exactFields(raw json.RawMessage, typ reflect.Type) error {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if string(bytes.TrimSpace(raw)) == "null" {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if e := json.Unmarshal(raw, &object); e != nil {
			return e
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name != "" && name != "-" {
				fields[name] = f.Type
			}
		}
		for name, value := range object {
			field, ok := fields[name]
			if !ok {
				return errors.New("unknown or noncanonical JSON field")
			}
			if e := exactFields(value, field); e != nil {
				return e
			}
		}
	case reflect.Slice:
		var values []json.RawMessage
		if e := json.Unmarshal(raw, &values); e != nil {
			return e
		}
		for _, value := range values {
			if e := exactFields(value, typ.Elem()); e != nil {
				return e
			}
		}
	}
	return nil
}
func digest32(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && s == strings.ToLower(s) && !zero(b)
}

func (r *Reader) Authorize(ctx context.Context, id [32]byte, raw []byte, loaded Identity) (*Authorization, error) {
	if len(raw) == 0 || len(raw) > MaxManifestBytes || zero(loaded.AppID[:]) || zero(loaded.RuntimeID[:]) {
		return nil, errors.New("startup package or loaded identity missing")
	}
	raw = append([]byte(nil), raw...)
	var m Manifest
	if e := strictJSON(raw, &m); e != nil {
		return nil, errors.New("invalid startup package JSON")
	}
	if m.Version != 1 || r == nil || m.ChainID != r.chainID || !strings.EqualFold(m.Ledger, r.ledger) || m.Deployment != "0x"+hex.EncodeToString(id[:]) || !address(m.Owner) {
		return nil, errors.New("startup package scope mismatch")
	}
	if m.AppID != hex.EncodeToString(loaded.AppID[:]) || m.RuntimeID != hex.EncodeToString(loaded.RuntimeID[:]) {
		return nil, errors.New("startup package does not authorize the loaded app and runtime")
	}
	if len(m.ConfigText) > 32768 {
		return nil, errors.New("startup config exceeds limit")
	}
	if m.ConfigText != "" {
		trim := strings.TrimSpace(m.ConfigText)
		if len(trim) == 0 || (trim[0] != '{' && trim[0] != '[') || uniqueJSON([]byte(m.ConfigText)) != nil {
			return nil, errors.New("startup config must be an unambiguous JSON object or array")
		}
	}
	switch m.SecretsMode {
	case "public":
		if m.Custody != nil {
			return nil, errors.New("public startup cannot carry custody")
		}
	case "custody-v2":
		if m.Custody == nil {
			return nil, errors.New("custody startup cannot omit its pointer")
		}
		if _, e := m.Custody.V2(); e != nil || m.Custody.ChainID != r.chainID {
			return nil, errors.New("invalid owner-committed custody pointer")
		}
	default:
		return nil, errors.New("explicit public or custody-v2 secrets mode required")
	}
	if e := namesField(raw, m.Names, m.SecretsMode); e != nil {
		return nil, e
	}
	st, e := r.read(ctx, id)
	if e != nil {
		return nil, &snapshotUnavailable{e}
	}
	// an agreed snapshot without a current lease: startup waits (AuthorizeWhenConfirmed) for a just-claimed lease to
	// become visible, and never starts on it
	if e = r.leaseCurrent(st); e != nil {
		return nil, &snapshotUnavailable{e}
	}
	if !strings.EqualFold(m.Owner, st.row.owner) || m.AppRef != st.row.appRef {
		return nil, errors.New("startup package owner or app reference changed")
	}
	if e = uniqueJSON([]byte(st.row.envelope)); e != nil {
		return nil, errors.New("invalid deployment envelope")
	}
	var envelope map[string]json.RawMessage
	if e = json.Unmarshal([]byte(st.row.envelope), &envelope); e != nil {
		return nil, errors.New("deployment envelope is not an object")
	}
	if _, ok := envelope["config"]; ok {
		return nil, errors.New("direct startup cannot mix legacy inline configuration")
	}
	if _, ok := envelope["configCid"]; ok {
		return nil, errors.New("direct startup cannot mix legacy configuration references")
	}
	var pin commitment
	if e = strictJSON(envelope["guestBootstrap"], &pin); e != nil || pin.Version != 1 || !digest32(pin.SHA256) {
		return nil, errors.New("deployment has no explicit startup package commitment")
	}
	sum := sha256.Sum256(raw)
	if pin.SHA256 != hex.EncodeToString(sum[:]) {
		return nil, errors.New("startup package differs from owner commitment")
	}
	return &Authorization{reader: r, snapshot: st, manifest: m, valid: true}, nil
}
func (a *Authorization) current() bool {
	return a != nil && a.valid && a.reader != nil && a.reader.now().Unix() < int64(a.snapshot.row.leaseUntil) && a.reader.now().Unix() <= int64(a.snapshot.timestamp)+int64(a.reader.maxAge.Seconds())
}
func (a *Authorization) ConfigText() (string, error) {
	if !a.current() {
		return "", errors.New("startup authorization expired or unverified")
	}
	return a.manifest.ConfigText, nil
}
func (a *Authorization) EnvelopeTag() (string, error) {
	if !a.current() {
		return "", errors.New("startup authorization expired or unverified")
	}
	h := sha256.Sum256([]byte(a.snapshot.row.envelope))
	return hex.EncodeToString(h[:]), nil
}
func (a *Authorization) SecretsMode() (string, error) {
	if !a.current() {
		return "", errors.New("startup authorization expired or unverified")
	}
	return a.manifest.SecretsMode, nil
}
func (a *Authorization) Custody() (*release.Custody, error) {
	if !a.current() {
		return nil, errors.New("startup authorization expired or unverified")
	}
	if a.manifest.Custody == nil {
		return nil, nil
	}
	b, _ := json.Marshal(a.manifest.Custody)
	var copy release.Custody
	json.Unmarshal(b, &copy)
	return &copy, nil
}

// Revalidate after custody/network preparation, immediately before app start.
// A renewal may extend the lease; owner/runner/config changes invalidate it.
func (a *Authorization) Revalidate(ctx context.Context) error {
	if a == nil || !a.valid || a.reader == nil {
		return errors.New("unverified startup authorization")
	}
	next, e := a.reader.read(ctx, a.snapshot.row.id)
	if e == nil {
		e = a.reader.leaseCurrent(next)
	}
	if e != nil {
		a.valid = false
		return e
	}
	old := a.snapshot.row
	n := next.row
	if next.number < a.snapshot.number || n.owner != old.owner || n.runner != old.runner || n.operator != old.operator || n.appRef != old.appRef || n.envelope != old.envelope {
		a.valid = false
		return errors.New("startup authorization changed")
	}
	a.snapshot = next
	return nil
}
