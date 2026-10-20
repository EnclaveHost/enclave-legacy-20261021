# Direct-only host control

`ISOLATION_DIRECT_ONLY=1` runs the supervisor as a host that serves **only**
owner-committed startup deployments (`guestBootstrap` in the ledger envelope) in
per-app SEV-SNP guests. It reads the deployment and catalog from explicitly
pinned contracts, gets the public startup package from replicas the operator
chose, and provisions a direct-bootstrap guest through a fresh guestd. No Enclave
relay, secrets, release-list, domain, certificate, DNS or catalog gateway is
needed for that path, and none is called.

Set up the manager first: [cold host setup](cold-host.md) covers the release
download and `guestd -cpu-release`.

## Operator environment

```sh
# the mode and the tier
ISOLATION_DIRECT_ONLY=1
ISOLATION_BACKEND=snp-guest-per-app
PROVISION_BACKEND=vm
VMMGR_URL=http://127.0.0.1:<guestd -listen port>
GUESTD_KEY_FILE=/srv/enclave/pair.key           # the file guestd -gen-key wrote; never published
GUESTD_DATA_ADDR=127.0.0.1:<guestd -data-listen port>

# chain authorities: immutable pins, no address book
ENCLAVE_CONTRACT_PINS_FILE=/srv/enclave/contract-pins.json
ADDRESS_BOOK_ADDRESS=
BASE_RPC=https://<rpc you trust first>

# owner package and component replicas (the same component list as guestd -gateway)
GUEST_BOOTSTRAP_GATEWAYS=http://<replica-a>:8189/ipfs,http://<replica-b>:8189/ipfs
IPFS_GATEWAY='["http://<replica-a>:8189","http://<replica-b>:8189"]'

# Enclave services: explicitly off (an unset SECRETS_API/DOMAINS_API means api.enclave.host)
SECRETS_API=
DOMAINS_API=
CERTS_API=
DNS_API=
APP_CERT_DOMAIN=
ISOLATION_RELEASE=

# this host's own identity on chain
REGISTRY_ENABLED=1
REGISTRY_PRIVATE_KEY=<this host's operator key>
ENCLAVE_REPO=<source repository the image is attested against>
PUBLIC_URL=https://<this host's endpoint>
CLAIM_ENABLED=1
SECRET=<a value generated on this host>
```

`GUEST_BOOTSTRAP_STORAGE_PLAN_FILE` can replace both replica variables. The
storage plan accepts HTTPS adapters only; literal-IP HTTP replicas go in
`GUEST_BOOTSTRAP_GATEWAYS`. The contract pin document is the version-1 format
`loadContractPins` reads: `registry`, `deployments`, `appCatalog` and
`proofOfTime` must be nonzero.

Startup exits with status 2 and lists every problem if the mode is set and any
of the following holds:

- the tier is not `snp-guest-per-app`/`vm`;
- the contracts are not pinned, or an address book is configured;
- no package replicas are named;
- the prefetch probe would use its Enclave default;
- any relay, domain, certificate or DNS service is configured, or left unset where
  its default is Enclave's;
- `ISOLATION_RELEASE` is on.

To enforce the host owner's wallet policy (refusals apply to this host only), add
`ENCLAVE_HOST_OWNERSHIP`, `ENCLAVE_HOST_REGISTRY_PIN`, `ENCLAVE_HOST_CATALOG_PIN`
(both must equal the contract pins), `ENCLAVE_HOST_POLICY_DIR` and optionally
`ENCLAVE_HOST_POLICY_ORIGINS`. That policy is unchanged by this mode.

## What the mode does

- **Claim.** A deployment without a `guestBootstrap` commitment is refused with a
  reason in the sweep log; it is never launched through the legacy relay path.
  The committed package is fetched by raw CID and must match the owner's ledger
  hash. Its chain, pinned ledger, deployment, current owner, app reference and
  the manager's RuntimeID must all match. Literal-IP HTTP replicas are accepted;
  HTTP names, credentials, queries and redirects are not. One replica refusing or
  serving wrong bytes leaves the others. The ledger row is read again after the
  component prefetch, and a changed owner, app reference or envelope stops the
  claim before any transaction.
- **Launch.** The derivation record comes from the pinned catalog's version entry
  (CID, memory, ports) and guestd's RuntimeID. guestd receives the exact package
  bytes, with no config, secrets or release ticket. `launchSpec` re-reads the
  ledger, re-checks the package (fetched again or from the hash-keyed memory
  cache) against the current scope, and refuses any launch without a
  commitment.
- **Restart.** A held guest is adopted only if it was started directly from the
  same package hash, AppID, RuntimeID and derivation record. Otherwise it is
  deleted and replaced.
- **Custody.** A `custody-v2` package's release is authorized by signing locally,
  for the vault in the owner's commitment only (unchanged).

With the variables above empty, custom-domain refresh, ACME, the guest WebPKI
certificate loop, secret fetches and the relay release list do not run.

## Evidence

`test/direct-only-supervisor.test.mjs` runs the real `supervisor.js` through
`DIRECT_CLAIM_SELFTEST`. Chain reads, the operator's transactions and guestd are
scripted; every other outbound `fetch` throws and is recorded. The tests check:

- **A full sweep.** The real code runs claim sweep → `considerClaim` →
  `tryClaim` → `adopt` → `launchSpec` → `spawnContainer` → ticket pump.
  - One literal-IP replica refuses and the other serves.
  - Every recorded fetch went to those two replicas; there were zero other calls.
  - Every chain read targeted the pinned ledger or catalog.
  - The one transaction was `claim` on the pinned ledger.
  - The derivation record sent to guestd equals the one written out in the test
    from the catalog's answer.
  - A legacy deployment in the same sweep is refused.
- **Hostile sources refused.** Corrupt bytes, another owner's package, redirects,
  an owner transfer, an owner change during prefetch, and an HTTP DNS name all
  stop before a claim transaction or guest create.
- **Restart.** The same committed guest is adopted with no transaction; a guest
  with a stale package is deleted and replaced.
- **Startup refusal.** An unset `SECRETS_API`/`DOMAINS_API`, missing pins, missing
  replicas, the Enclave prefetch-probe default and `ISOLATION_RELEASE=1` all
  refuse startup.

These are local tests with scripted chain and manager answers. They are not a
live claim, a hardware boot or evidence of independent operators.

## Trust assumptions and what remains

- **The supervisor itself.** It claims only when its own attestation document
  (`ATTESTATION_URL`, loopback, provided by the measured control image) shows a
  confidential CPU. A cold host therefore needs a measured control guest, not a
  bare process.
- **Chain reads.** Ledger and catalog reads use the first answering RPC in
  `BASE_RPC` plus public fallbacks, not an agreeing quorum. A wrong answer can
  make the host claim or skip work. It cannot start an app on another owner's
  configuration: the guest re-checks the commitment through its measured RPC
  quorum before starting.
- **Admission.** Without the wallet host policy, admission falls back to the
  catalog's approval state, which the catalog owner sets. Only the host owner's
  wallet policy removes that central gate, and owner acceptance plus policy
  commitment for that authority still need the owner's wallet.
- **Unsupported in this mode.** Browser naming and WebPKI certificates (ACME,
  platform certificates, custom domains) are off. Clients use the attestation-
  pinned [native client](native-client.md). Route publication belongs to the
  network agent, not this supervisor.
- **Retention.** The package and component replicas listed above are availability
  choices; their retention and independence are the operator's to establish.
  Today's public replicas are Enclave-operated.
- **Not yet done:**
  - a live claim and real hardware boot through this mode with a funded, active
    owner-committed deployment;
  - the control guest image carrying this configuration;
  - independent custody quorum availability for `custody-v2`;
  - production migration.
