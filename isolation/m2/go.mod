module enclave.host/isolation/m2

go 1.24

require enclave.host/isolation/contract v0.0.0

require github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1

require golang.org/x/crypto v0.37.0

replace enclave.host/isolation/contract => ../contract
