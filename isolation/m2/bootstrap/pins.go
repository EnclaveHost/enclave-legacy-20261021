package bootstrap

import (
	"crypto/x509"
	_ "embed"
	"errors"
	"net/http"
	"time"

	"enclave.host/isolation/m2/release"
)

// These are measured source inputs, never a host-provided policy or mutable
// address-book lookup. Changing them produces a different guest measurement.
// RPC quorum is a trust assumption, not a light-client proof.
func MeasuredConfig(client *http.Client) Config {
	return Config{ChainID: 8453, Ledger: "0xB1783B61E1FDee6a6163DC3CdaC27bF32E7d117B",
		RPCs:          []string{"https://mainnet.base.org", "https://base-rpc.publicnode.com", "https://base.drpc.org"},
		Confirmations: 2, MaxAge: 90 * time.Second, Client: client}
}

// The existing ACME roots also support independently operated custodians.
// The additional public roots were extracted from the local system trust store;
// tests pin their DER fingerprints, rather than trusting that store at runtime.
//
//go:embed roots/gts-root-r4.pem
var gtsRootR4 []byte

//go:embed roots/digicert-global-root-g2.pem
var digicertGlobalRootG2 []byte

func MeasuredRoots() (*x509.CertPool, error) {
	p, err := release.RelayRoots()
	if err != nil {
		return nil, err
	}
	if !p.AppendCertsFromPEM(gtsRootR4) || !p.AppendCertsFromPEM(digicertGlobalRootG2) {
		return nil, errors.New("invalid measured bootstrap roots")
	}
	return p, nil
}
