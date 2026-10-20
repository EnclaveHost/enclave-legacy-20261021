# Connect without Enclave discovery or a website CA

`network/native-client.mjs` is a native HTTP client library for application APIs:
ordinary methods, bounded request bodies, and buffered or streamed responses.
`scripts/network/native-get.mjs` is its GET command-line wrapper. The client
resolves signed public records itself, checks an agreeing Base RPC quorum against
explicit contract addresses, and verifies a fresh hardware attestation before it
sends any application path, header, credential or body.

```sh
node scripts/network/native-get.mjs /absolute/path/trust-profile.json /ping
```

Response bytes go to stdout. Status, selected route, verified identities, TLS key
digest, lease block and authorization deadline go to stderr. Non-2xx responses
produce a nonzero exit code. Redirects are returned, never followed. The wrapper
is GET only; writes and streams use the library API below. It is not a browser
proxy.

## Library API: requests, writes and streams

```js
import {NativeClient} from './network/native-client.mjs';
const client = new NativeClient(profile, {maxConcurrent: 4});

// Buffered: resolves after the whole (bounded) response.
const r = await client.request({method: 'POST', path: '/v1/chat',
  headers: {authorization: 'Bearer …', 'content-type': 'application/json'},
  body: JSON.stringify({messages})});
// r.status, r.headers, r.body (Buffer), r.route, r.proof, r.expectation, r.leaseBlock, r.validUntil

// Streamed: resolves when response headers arrive; bytes arrive as the guest sends them.
const controller = new AbortController();
const s = await client.stream({method: 'POST', path: '/v1/chat/stream', headers, body, signal: controller.signal});
for await (const chunk of s.body) render(chunk);   // a Node Readable: iterate or pipe it
s.cancel();                                        // or controller.abort(); both close the connection
const {bytes, error} = await s.closed;             // always resolves
```

| Option | Meaning | Default | Allowed |
| --- | --- | --- | --- |
| `method` | `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS` | `GET` | `CONNECT`/`TRACE` refused |
| `path` | Origin-form path and query | `/` | starts with one `/`; no controls, spaces or `#`; up to 8192 characters |
| `headers` | Application headers, including credentials | `{}` | up to 100 names and 64 KiB; no CR/LF/NUL; one spelling per name |
| `body` | String, Buffer, typed array or ArrayBuffer, copied when called | none | not with GET/HEAD; up to `maxRequestBytes` |
| `maxRequestBytes` | Upload limit | 8 MiB | 0 to 64 MiB |
| `maxBytes` | Response limit | 8 MiB (`request`), 64 MiB (`stream`) | up to 64 MiB / 1 GiB |
| `timeoutMs` | `request`: the whole exchange. `stream`: until response headers | 30 s | 1 s to 120 s |
| `idleTimeoutMs` | `stream`: longest gap between delivered chunks | 60 s | 1 s to 10 min |
| `maxDurationMs` | `stream`: total lifetime | 10 min | 1 s to 1 h |
| `recheckMs` | `stream`: how often chain state is checked again | 30 s | 1 s to 5 min |
| `signal` | `AbortSignal`, cancels at any stage | none | must be a real `AbortSignal` |

Unknown options are refused. So are the framing and hop-by-hop headers `Host`,
`Connection`, `Upgrade`, `Content-Length`, `Transfer-Encoding`,
`Proxy-Authorization`, `Proxy-Connection`, `Keep-Alive`, `TE`, `Trailer` and
`Expect`. The client sets `Host` and `Content-Length` itself.

### Semantics

- **Order of checks.** These happen in order before any application byte is
  written:
  - discovery and a lease check;
  - a fresh hardware proof on a signed literal route;
  - a second read of the records and chain state, which must show the same
    deployment and route;
  - a handshake check: the TLS key must equal the attested key, the send
    deadline must not have passed, and the lease identity must not have changed.

  Node writes the request only after that last check passes. A refusal at any
  step sends nothing; the tests confirm the guest stand-in decrypts zero
  application bytes.
- **Snapshot.** Options, headers and body are copied synchronously when
  `request` or `stream` is called, so later caller mutation changes nothing.
  The signal is deliberately kept by reference. Streamed (unbounded) uploads are
  not supported.
- **One send.** Each call attests once and sends at most once. Route failover
  happens only during attestation, before any application byte. After the
  request is written, a reset, timeout or partial response is reported as an
  error and never retried; a POST may already have taken effect. Redirects are
  returned, not followed.
- **Backpressure and cleanup.**
  - `stream().body` applies backpressure through to the guest connection.
  - An idle gap counts whatever the cause, including a consumer that stops
    reading.
  - A limit, timeout, cancel, abort, guest reset or end of response closes the
    connection, clears the timers and frees the concurrency slot.
  - Errors reach iterators and pipes. A consumer that attaches no error handler
    does not crash the process.
- **Concurrency.** Authorization and connection setup are serialized per client.
  The queue is released when response headers arrive. At most `maxConcurrent`
  requests or streams (1–32, default 4) may be open per client; beyond that the
  call is refused at once.
- **What authorization covers.** `validUntil` is the latest moment a new send
  may start: the earliest of route expiry, lease snapshot expiry, and 60 s after
  the proof began. An established stream is not proof of continuing ownership.
  The client re-reads the lease every `recheckMs` and cuts the stream (`native
  authorization ended`) if the owner, runner, app, configuration or lease
  changed, or if current state can no longer be confirmed. A route withdrawal
  alone does not cut an open stream; `maxDurationMs` bounds it.
- **Logging.** Errors carry fixed messages and never include request header
  values or bodies.

### Gaps

- **Browsers.** There is no browser integration. Browsers cannot pin an attested
  key or skip WebPKI; this library runs in Node, not as a browser-wide proxy.
- **Authentication.** Credentials are whatever the application expects. The
  client passes them through only after the checks above and adds no
  Enclave-issued session.
- **Other transports.** Streamed request uploads, WebSocket/`Upgrade`,
  `100-continue` and HTTP/2 are not supported.
- **Proof scope.** The guest-side TLS key is attested once per request. Later
  requests attest again; no proof is cached across requests.

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
trust decision.

For a client with no release or bundle cache, replace `--release` and `--bundle`
with explicit public artifact sources:

```sh
node scripts/network/native-profile.mjs \
  --profile base-profile.json --release-id <64-hex-reviewed-release> \
  --artifact-gateways http://<provider-a>:8189/ipfs,http://<provider-b>:8189/ipfs \
  --vcpus 1 --out new-client-profile.json
```

Remote mode has no local-input fallback. It downloads the release manifest by
its pinned SHA-256 raw CID, validates its canonical form, paths, file count and
size limits, then streams every file into a newly created private directory.
Each file must match its committed digest and size. The bundle is addressed and
verified by the owner's AppID. Source failure or wrong bytes permits another
explicit source; redirects and credentials are forbidden. Partial output is
removed only after all active writers settle. Existing paths are never replaced.
The ordinary release verifier then checks the reconstructed tree and recomputes
the measured image. Temporary inputs are removed after the profile is prepared.

These gateways serve complete bytes at SHA-256 raw-CID URLs, including large
runtime files. This is HTTP content-addressed retrieval, not a claim that such
large raw blocks are available over the IPFS DHT/Bitswap network. The source may
be operated by anyone; it needs no app admission or identity authority. Client
software, the build tools and independently selected trust pins must already be
available. Remote acquisition alone does not prove future retention or independent
operation of the storage providers.

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

The owner-startup profile path was then verified separately against deployment
`0x87508b958c4d14381b58fe05a781efbd3f185a36d5239abdf37e8f242f944538`.
Its public package is replicated as
`bafkreigbngcd3wnrsi6z7yr2hx6bvunxlfzlvklr2ry3snqy62flxlndmi` on all four existing
bootstrap gateways. From a base profile with no app expectations, runtime identity
or measurement, the generator fetched the owner-committed bytes, checked a local
bundle against the committed AppID, verified release
`5ef70f6a950b1deadcf21119a0e02ba2f75dea029d870ef25a0e6d7940ac9aad`, and reconstructed
the same `caf11b48…a733a` measurement seen in the earlier real SNP boot. The
network-namespace run had no default route, external DNS, Enclave API, Nan or
minipc access; exact forwarders allowed only three RPC peers and two literal-IP
package replicas, with a third configured package source unreachable. The final
chain snapshot was Base block 52828852.

That deployment remains suspended and unleased. A separate fresh native request
was refused before package/directory fetch or attestation. This is live-chain
profile reproduction and refusal evidence, not a new hardware boot or active
end-to-end owner-startup request. Release and bundle files were already present
locally; independent cold artifact acquisition is not proved by this run. The
four replicas still have one operator. No wallet transaction was submitted.

A subsequent cold-artifact run retrieved the manifest, all 19 runtime files and
the app bundle through literal-IP HTTP replicas, checked every byte, and again
reproduced `caf11b48…a733a`. The previous local release, bundle store and transfer
archive were hidden in a private mount namespace. There was no default network
route, external DNS, Nan, minipc or API access; US-West's storage endpoint was
also blocked. All 21 verified download receipts came from CA-East. The final
owner/commitment read was Base block 52829232. This closes the local-artifact
dependency for profile preparation; it still does not claim a fresh guest boot
or an active owner-startup application session. The deployment remained suspended.

A second cold run swapped the unavailable storage provider: CA-East was blocked
and all 21 receipts came from EU-Central. It reproduced the same measurement and
rechecked the commitment at Base block 52829359. All four gateways now retain the
19 unique public objects (83,046,781 bytes), each verified through its HTTP service
after publication. This is currently Enclave-operated replication, not evidence
of independent operation or a long-term retention guarantee.

### Live write-transport and stream check

On 2026-10-19 the extended client ran against the existing EyesOff deployment
from a fresh client state in the isolated network harness: no default route or
external DNS, Nan/minipc/control API denied, and one directory refusing. Each
request used a fresh real SNP proof and attested TLS-key check. A bounded POST
to the unsupported `/ping` method returned HTTP 404; a streamed GET `/ping`
returned HTTP 200 and `pong`. No credentials, chat request or application
mutation were sent. This validates the live transport and streamed-body path;
incremental SSE and application-write semantics remain local fixture evidence.
