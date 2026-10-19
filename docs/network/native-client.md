# Connect without Enclave discovery or a website CA

`network/native-client.mjs` and `scripts/network/native-get.mjs` provide a native
GET/HEAD client. The client resolves signed public records itself, checks an
agreeing Base RPC quorum against explicit contract addresses, and verifies a
fresh hardware attestation before sending application headers or a path.

```sh
node scripts/network/native-get.mjs /absolute/path/trust-profile.json /ping
```

Response bytes go to stdout. Status, selected route, verified identities, TLS key
digest, lease block and authorization deadline go to stderr. Non-2xx responses
produce a nonzero exit code. Redirects are returned, never followed. The library
accepts `request({path, method: 'GET' | 'HEAD', headers, maxBytes})`; it does not
retry application requests. It is not a browser proxy or a POST/streaming client.

## The caller's trust profile

Supply a JSON object with these fields. No discovery service supplies missing
trust settings, and no mutable address-book lookup replaces a pin.

| Field | Meaning |
| --- | --- |
| `version` | `1` |
| `deploymentId` | Full lower-case `0x` plus 64 hex characters, not an eight-character label |
| `hostname` | SNI and Host routing name; it is never DNS-resolved or treated as identity proof |
| `stateDir` | Absolute writable directory, owned by this client process, retained across runs |
| `chainId` | `8453` for Base |
| `rpc` | At least two HTTPS RPC origins with distinct hostnames; three allow a failed peer |
| `authorityPins` | Explicit `deployments`, `registry`, `connectivity`, and `sessionVaultFactory` addresses; zero disables optional authorities |
| `directories` | One to eight explicit HTTP(S) literal-IP origins serving `/v1/network/records` |
| `checkers` | Explicit trusted provider-qualification signer addresses |
| `expected` | For explicitly pinned apps: `appRef`, `configCid`, `appSha256`, and `runtimeId`; include applicable config/secret requirements. Omit when using `startup`. |
| `startup` | Alternative to `expected`: `{ "gateways": ["http://<literal-IP>:8189/ipfs"] }`, or exact public package bytes in `packageBase64`. This mode requires an explicit SNP runtime policy. |
| `linux` | SNP `measurement`, `runtime`, `minTcb`, and applicable `release`/`expectedVmpl` policy |

For offline SNP certificate verification, `linux` may contain `vcekBase64`,
`certChainPem`, `product` and `kds: false`. Supplied collateral still has to verify
against the verifier's pinned AMD root and match the signed report's chip and TCB.
Without held collateral, AMD KDS access is needed. The library also accepts the
existing explicit `shield` plus `hostSession`, or `pvm`, verification policies.
The live test below covers SNP only.

Obtain app and runtime expectations from independently trusted build/deployment
material. A config CID is not by itself the compiled guest's AppID. An owner
startup bundle can incorporate configuration and secret commitments. Do not
accept a peer's claimed expected hash as your own trust anchor. For deployments
using owner-committed startup, `startup` mode derives app and runtime IDs from the
exact package hash in the current deployment's ledger envelope. The package must
name that chain, pinned ledger, full deployment ID, current owner, current app
reference and the runtime selected by the client. It never falls back to a legacy
config or a host's claimed app identity. Public package bytes may travel over
explicitly selected literal-IP HTTP gateways: their hash and chain scope provide
authority. Credentials and redirects are forbidden. Modified bytes, changed
ownership and missing packages fail closed.

### Reproduce the measurement instead of copying a host profile

Start with a base profile containing the network pins, literal directory and
startup gateway addresses, and your SNP firmware floor/collateral policy. Omit
`expected`, and omit `linux.measurement`, `linux.runtime` and `linux.release`.
Choose an independently reviewed release ID and obtain that release's directory
and the app's contract bundle. Their transport need not be trusted: every release
file is verified against the selected pin, and the bundle's SHA-256 must equal
the owner-committed AppID. This command uses the existing image reconstruction
tool, which requires Go, Python and `sev-snp-measure` on the client machine:

```sh
node scripts/network/native-profile.mjs \
  --profile base-profile.json \
  --release /path/to/release --release-id <64-hex-reviewed-release> \
  --bundle /path/to/app.bundle --vcpus 1 \
  --out new-client-profile.json
node scripts/network/native-get.mjs new-client-profile.json /ping
```

The generator reads the owner commitment through the pinned RPC quorum, fetches
and verifies the public package, checks the exact bundle hash, reconstructs the
image and measurement, checks the resulting runtime identity, and re-reads chain
state before writing the new profile. It refuses to overwrite an existing file.
No host-supplied predicted measurement participates. A profile can be prepared for
an inactive deployment, but that never authorizes a connection: the native client
still requires an active public lease. Package updates selecting different app
bytes or runtime images need a freshly reproduced profile. Cached public package
bytes are rechecked against current owner scope before every use.

This removes the need to obtain per-app identity or predicted measurements from
Enclave's host/control service. Selecting trusted runtime source/release pins,
firmware floors, chain readers and checker keys remains the client's explicit
trust decision. This command does not automatically acquire release or bundle
files or prove their independent retention.

Keep `stateDir` persistent, with one process owning it. Signed policies, route
withdrawals and sequence floors survive restart. Corrupted state fails closed.
Deleting the directory loses previously observed replay floors; it is not a
recovery procedure. Changing the pinned authority/checker set selects a separate
state namespace and requires deliberate trust review.

## What is checked

1. Read the current deployment and runner registration from the configured RPC
   quorum using the pinned contracts. Match app reference and config CID to the
   caller's expectations; require a current public, active lease.
2. Fetch public signed records from the selected IP origins. Verify provider
   signatures, registry ownership where applicable, checker qualifications,
   owner network policy, runner delegation and route signatures locally.
3. Connect to a verified literal ingress IP. SNI selects the guest, without
   resolving the name. Before authentication the only HTTP request permitted by
   this proof path is a bounded nonce attestation request. It carries no app
   headers, cookies or credentials.
4. Verify the fresh proof binds the expected deployment, app, runtime and the
   actual TLS handshake key. Hardware policy refusal never becomes WebPKI or
   trust-on-first-use fallback. Check that key before sending readiness bytes on
   a new connection.
5. Re-read chain state and directory records after the proof. Refuse withdrawal,
   reassignment, app/config/owner change or loss of current route authorization.
6. Verify the TLS key and authorization deadline before the HTTP agent releases
   the application request. Proof authorization lasts at most 60 seconds from
   proof start and never past the current route/lease deadline. Bound response
   bytes and request duration, and do not follow redirects.

RPC quorum is an explicit trust assumption, not a chain light client. Provider
qualification checkers remain explicitly selected trust anchors. Owner network
policy replay protection covers observed signed versions; an unobserved newer
off-chain policy cannot be discovered if all copies withhold it. Neither copying
records nor changing DNS proves independently operated infrastructure.

## Live evidence, 2026-10-19

EyesOff deployment `0x9eb4e60063aa079cebed355f96b2d049457ae77bdbcd49086040282e1e4b871c`
returned HTTP 200 and `pong: true` through this path. A second run used an empty
client state directory in a Linux user/network/mount namespace with no default
route, no external DNS, and exact TCP forwarders for three public directories,
their app TLS ingress and three external RPCs. RPC hostnames were locally pinned
for that test. TLS forwarders allowed only the app SNI or configured RPC SNI;
`api.enclave.host` was refused even at provider IPs. Nan, minipc, the local control
forward and public DNS probes were unreachable. One configured directory was
deliberately unreachable. The client verified a fresh SNP proof, rechecked the
lease at Base block 52828489, and received the app's ping.

The app/runtime policy for this test was copied from the existing host's local
configuration and held certificate collateral. This proves the native transport
and verification path with explicit pins, not independently derived first-user
trust. The participating providers still share Enclave operation. Existing
browsers, production control/custody, deployment creation and storage writes are
not migrated by this client feature.
