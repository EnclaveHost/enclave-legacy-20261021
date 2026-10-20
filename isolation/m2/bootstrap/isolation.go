package bootstrap

import (
	"encoding/json"
	"errors"
)

// IsolationRequire is the deployment envelope's isolation.require at the agreed snapshot this authorization stands on:
// the backend the OWNER committed the deployment to ("" when the envelope names none). A guest of a weaker tier uses it to
// refuse a package its owner committed to a stronger one: the AppID and RuntimeID can coincide across tiers (the same
// catalog bundle and wasmtime identity), so they alone cannot keep an SNP-committed package off an Enclave Shield
// partition. It reads only what Authorize already checked (unique keys, the startup commitment); a changed envelope
// revokes the authorization (Refresh, Revalidate) before this could report it.
func (a *Authorization) IsolationRequire() (string, error) {
	if !a.current() {
		return "", errors.New("startup authorization expired or unverified")
	}
	var envelope map[string]json.RawMessage
	if e := json.Unmarshal([]byte(a.snapshot.row.envelope), &envelope); e != nil || envelope == nil {
		return "", errors.New("deployment envelope is not an object")
	}
	raw, ok := envelope["isolation"]
	if !ok {
		return "", nil
	}
	var iso map[string]json.RawMessage
	if e := json.Unmarshal(raw, &iso); e != nil || iso == nil {
		return "", errors.New("deployment isolation options are not an object")
	}
	req, ok := iso["require"]
	if !ok {
		return "", nil
	}
	var s string
	if e := json.Unmarshal(req, &s); e != nil {
		return "", errors.New("isolation.require is not a string")
	}
	return s, nil
}
