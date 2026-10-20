# Independent owner management

An owner can read a deployment's status, log tail, attestation document and CPU profile, start or stop a CPU capture,
obtain a private app's per-deployment access token, and restart it, without the Enclave API, the fleet tunnel
(`api.enclave.host/t/<name>`) or the address book. What it does need is stated exactly under "What each path depends
on" below. The owner's client:
- finds the host that the pinned ledger names as the deployment's current runner;
- authenticates that host's management endpoint;
- sends one signed request per operation.

The host's gateway authorizes each request from one chain snapshot that several RPCs agree on, then forwards it once to
its supervisor.

Modules (`network/`):
- `management-record.mjs`: signed endpoint records; browser-safe.
- `management-routes.mjs`: the operation table.
- `management-auth.mjs`: quorum authorization.
- `management-outcome.mjs`: answer classification.
- `management-gateway.mjs`: the host listener.
- `management-host.mjs`: the runnable host service.
- `management-client.mjs`: the native owner client.
- `management-browser.mjs`: the browser owner helper.

Directories (`public-directory.mjs`, `directory-server.mjs`) accept and replicate the records. The API contract for CLI
and dashboard integration is in `work/management-interface.txt`.

## Principals and trust roots

| Principal | Authenticated by | Used for |
| --- | --- | --- |
| Tenant app guest | Its fresh SNP proof bound to its TLS key ([native client](native-client.md)) | App traffic only |
| Host management endpoint | A record signed by the deployment's **current `runnerOperator`** on the pinned ledger | Locating and authenticating the gateway |
| The owner | A per-request `EnclaveSession v1` signature, authorized by the gateway from an agreeing chain snapshot | Every management operation |

The endpoint authority is the operator wallet that the ledger accepts as the runner. No measured host identity is
verified. The owner trusts the operator currently running the deployment, which already runs the supervisor and the app.
A tenant's SNP proof never stands in for the host, and the host-reported attestation document is data to verify
independently.

## Transports

Both transports reach the same gateway and carry the same owner authorization.

| | Native (`management-client.mjs`) | Browser (`management-browser.mjs`) |
| --- | --- | --- |
| Address | the record's literal public IP and port | the record's `browser.origin`, a DNS name |
| TLS check | **exact SPKI** equal to the record's `spkiSha256`, before any owner byte | the browser's own **WebPKI** validation. The page cannot see the key; nothing claims an SPKI check |
| Endpoint needs | no DNS name and no CA: a literal IP and the signed SPKI | DNS for the origin's name and a public CA |
| Result label | `transport: 'native-spki'` | `transport: 'browser-webpki'` |

**The browser path is optional and explicit.** It exists only when the operator publishes a **v2 record** with
`browser: {origin, dashboards}`:
- **origin:** an exact `https://` origin on a public DNS name. IPs, `localhost`, `.local`, `.invalid`, `.test`,
  `.example` and `.internal` are refused, as are paths, queries and credentials.
- **dashboards:** 1 to 8 exact `https` origins, with no wildcards.

The gateway answers CORS only for those dashboard origins. A request with any other `Origin` is refused before
authorization, and requests with no `Origin` (native) are unaffected. A directory cannot change the origin, because it
sits inside the operator signature, and floors refuse a replayed older record. If DNS or the CA path fails for the
management origin, the native path still reaches the endpoint.

### What each path depends on

- **Endpoint (native):** no DNS and no CA. A literal public IP, and the SPKI pinned by the operator-signed record.
- **Endpoint (browser):** DNS for the origin's name and a public CA.
- **Discovery:** literal-IP directory origins (native). The browser reads the profile's directories.
- **Authorization, on both sides:** the client's lease read and the gateway's authorization each need **two RPCs that
  agree**, through `LeaseReader`. Today `LeaseReader` accepts only `https:` RPC origins with distinct hosts, so those
  RPCs need DNS for their names and WebPKI for their certificates, unless they are literal IPs with IP-SAN certificates.
  Support for an operator's own local node over loopback HTTP is being added to `LeaseReader` by its owner; until it
  lands, a DNS or CA failure for the RPC names stops authorization even though the endpoint itself is reachable.
- **None of these are Enclave-operated by requirement.** The operator chooses the RPCs and directories.

## Records

```
v1: {version:1, runner, operator, chainId, deployments, address, port, spkiSha256, sequence, issuedAt, expiresAt}
v2: v1 + {browser: null | {origin, dashboards}}      signed: "enclave-network:management:v<version>\n" + canonical(record)
```

- **Withdrawal:** every endpoint field is null.
- **Lifetime:** at most 24 h.
- **Sequence:** a record's sequence may not exceed its own issue time, and the issue time may be at most 60 s ahead.
  So no record, even one signed by a key that is the operator for a moment, can raise a floor beyond what honest later
  records will pass. The host signs `sequence == issuedAt`.
- **Acceptance:** clients accept only a record for the lease's runner, signed by the lease's `runnerOperator`, on the
  same chain and ledger. The newest sequence wins, and equal sequences with different content are refused as
  equivocation.
- **Floors:** persistent floors refuse rollback. They are kept **per operator** of a runner, on one chain, ledger and
  registry:
  - a new operator (after rotation or transfer) is judged only against its own floor, never against a former
    operator's;
  - an operator that returns keeps its own earlier floor; no other key can erase it.

  The native client keeps one file per (network, runner, operator). The browser stores one composite floor
  `{version: 1, operators: {<operator>: {sequence, hash}}}` under `managementFloorKey` (network and runner). The
  composite is bounded at 64 operators and refuses rather than forgetting an operator.
- **Directories:** `POST /v1/network/management` admits a record only from the registry's active operator for the runner.
  Replicas copy records from peers, and clients read them in `/v1/network/records`. Each replica also persists per-operator floors, so a former operator cannot block a new one and an operator returning after a restart cannot replay older records. The same 64-operator bound applies per runner.

## Authorization at the gateway

These run in order for every request; the first failure refuses it.

1. **Target and body.** Only the operations in the table below, with exactly their body bytes, read under a body
   deadline. Only an `EnclaveSession` header: no bearer, no cookie.
2. **Signature.** The request signature over `enclave-management.invalid/<runner>` + target + body hash, within the 60 s
   window. The base is derived from the runner, never configured. The nonce is then **spent for good**: a refused request
   can never be replayed later into an accepted one.
3. **One agreed snapshot.** One chain snapshot that two RPCs return identically at a fixed, fresh, reorg-checked block
   (`LeaseReader.agreed`). It includes:
   - the ledger row: owner, runner, runnerOperator, active, lease end;
   - the runner's registry entry: active, and the same operator;
   - the vault factory's verdict;
   - the session: key, scope bits, liveness, expiry, environments;
   - the vault's owner;
   - either the vault's environment for the deployment, or the owner's ledger delegation (code support and storage
     slot).

   Nothing is cached between requests, and no fact comes from a different block. One lying or lagging RPC cannot forge
   an authorization; without agreement the request is refused before the supervisor sees anything.
4. **The decision.** Lease current and naming this runner; session live with the key and the operation's scope; the
   session may act for the deployment's **current** owner (vault environment, or production plus the owner's
   delegation).
5. **Deadlines.** One hard total deadline per operation bounds steps 3 to 5, so a hung chain read is a refusal.
   **Nothing is forwarded at or after** the earliest of that deadline, lease end, snapshot freshness and session expiry.
   This is checked before an upstream request exists.

**Admission.** Every stage has its own bounded capacity, so nothing an unauthenticated sender does takes what an owner
needs. A source is the connection's address, with IPv6 grouped by /64.

| Stage | Bounds (defaults; `limits`) |
| --- | --- |
| Before authorization (headers, body) | global `preAuth` 64; `preAuthPerSource` 4. A chunked body, or a declared length the operation cannot carry, is refused at once. The one small body (a CPU profile control, ≤64 bytes) has a 2 s deadline. |
| Chain authorization (costs RPC reads) | global `authorizing` 8; `authorizingPerSource` 2; `authorizingPerDeployment` 4; `authorizingPerKey` 2; `authPerMinute` 30 with `authBurst` 10 per source |
| Known-key reserve | `knownReserve` 4 extra slots, only for session keys that authorized here within `knownTtlMs` (15 min); they also skip the per-source caps |
| Refuse-only memory | for `negativeTtlMs` (15 s): a deployment the agreed snapshot showed is not leased to this runner, or a signer it showed is not a vault, is refused without a chain read. It can only refuse, never authorize |
| Forwarding | `long` 8 (logs, restart, attestation, CPU profile) and `short` 8; `forwardPerDeployment` 4 |
| Nonces | `nonces` 100,000. A live nonce is never evicted; when full, new requests get a 503 `replay_capacity` |

This bounds what any one source, key or deployment can take, and keeps recently active owners served while
strangers hold the general pools. **It is not immunity to a distributed flood:** many addresses can still fill the
shared pre-authorization and authorization pools, and behind a shared NAT or proxy, everyone is one source.

**After forwarding.**
- The supervisor verifies the same signature again under its own rules. It accepts the management base **only** on a
  request that arrives on loopback carrying the gateway's shared `MANAGEMENT_GATEWAY_TOKEN`
  (`x-enclave-management-gateway`). So a management-base signature delivered through any other ingress (the relay
  tunnel, `PUBLIC_URL`) cannot bypass the gateway's agreed-RPC authorization.
- While an answer flows, the authorization is re-read every `recheckMs` (never two rechecks at once). The answer is cut
  if the authorization no longer holds, and the cut time follows the newest snapshot, never past the hard bound.
- Every exit clears its timers and releases its slot.
- Each request is forwarded at most once.
- Answers say `x-enclave-management-forwarded: 0|1`.

| Operation | Request | Scope | Body | Response bound | Mutation |
| --- | --- | --- | --- | --- | --- |
| `status` | `GET /v1/deployments/<id>` | `api.status` | none | 1 MiB | no |
| `logs` | `GET …/logs[?tail=1..2000]` | `api.logs` | none | 8 MiB, streamed | no |
| `attestation` | `GET …/attestation[?nonce=<64 hex>]` | `api.status` | none | 4 MiB | no |
| `appToken` | `POST …/app-token` | `api.appAccess` | none | 8 KiB | no |
| `cpuProfile` | `GET …/cpu-profile` | `api.logs` | none | 24 MiB (≤16 MiB capture, base64) | no |
| `cpuProfileControl` | `POST …/cpu-profile` | `api.logs` | exactly `{"action":"start","seconds":N}` (N 1..60) or `{"action":"stop"}` | 64 KiB | yes |
| `restart` | `POST …/restart` | `api.restart` | none | 64 KiB | yes |

Refused with a 404, never forwarded: `/v1/admin/*`, listings, deletion, topups, the `/x/` data path, prefixes, encoded or
dot segments, extra query parameters and other methods.

The app token is the supervisor's **per-deployment, audience-pinned** app-origin token for a **private** deployment. It
opens that one app as its owner and nothing else; it is never a host-wide or control-plane credential. It is sensitive:
clients must not log it.

## Outcomes

Reads give a JSON object, or a refusal. **Mutations are not idempotent**, so only two answers are definite:
- **Success:** a well-formed answer. For restart, the JSON names this deployment; for a profile control, a gperftools
  state.
- **Refusal before any side effect:** a gateway answer marked "not forwarded", the supervisor's own pre-mutation refusal
  codes, or (for a profile control) the manager's 422 input refusal.

Everything else is `outcomeUnknown: true` and the operation **may have run**:
- a cut-off or malformed body;
- a malformed success;
- any 5xx;
- a profiler 409 (a capture can be left uncertain);
- an unexpected status;
- a browser network error, since a page cannot tell "not connected" from "sent".

The UI must say "check status" and never resend automatically. Neither client nor gateway retries.

## Host setup

1. **Native TLS key.** Create a self-signed P-256 management key and certificate (no CA involved). Keep it with the
   supervisor.
2. **Supervisor.** Set `MANAGEMENT_GATEWAY=1` and `MANAGEMENT_GATEWAY_TOKEN=<32-64 bytes of hex>`, and put the same
   token in a private file for the gateway (`upstreamTokenFile`). The supervisor then accepts the derived base
   `enclave-management.invalid/<keccak256(PUBLIC_URL)>`, but only from the gateway. The relay and `PUBLIC_URL` bases are
   unchanged.
3. **Browser transport (optional).** Obtain a WebPKI certificate for the browser origin's name and point that name at
   the gateway's address. The gateway selects that certificate by SNI on the same listener; native clients, dialing the
   IP without SNI, still get the pinned key.
4. **Run the service** where `127.0.0.1:<supervisor port>` is the supervisor, with at least two independent HTTPS RPCs:

   ```json
   {"runner":"0x…","chainId":8453,"authorityPins":{"deployments":"0x…","registry":"0x…","connectivity":"0x…","sessionVaultFactory":"0x…"},
    "rpc":["https://…","https://…","https://…"],"directories":["http://<literal-ip>:8188"],
    "listen":{"host":"0.0.0.0","port":8443},"public":{"address":"<public literal IP>","port":8443},
    "tlsKeyFile":"/etc/enclave/management.key","tlsCertFile":"/etc/enclave/management.crt",
    "operatorKeyFile":"/etc/enclave/operator.key","upstream":"http://127.0.0.1:8080","ttlMs":21600000,
    "stateDir":"/var/lib/enclave/management","upstreamTokenFile":"/etc/enclave/management-gateway.token",
    "browser":{"origin":"https://mgmt.example-operator.net","dashboards":["https://dashboard.example-owner.net"],
               "tlsKeyFile":"/etc/enclave/mgmt-web.key","tlsCertFile":"/etc/enclave/mgmt-web.crt"}}
   ```

   ```sh
   node network/management-host.mjs /etc/enclave/management.json
   ```

The operator key file must be private (mode 0600). It signs only the public record and is never transmitted.

- **Sequence.** It only moves forward, and with `stateDir` it is persisted before publication.
- **Renewal.** Records renew at half their lifetime; a failed publication retries within 60 s.
- **Withdrawal.** Refresh and withdrawal are serialized; nothing republishes after `withdraw()`.
- **Failed start.** A start that cannot sign closes its listener.
- **Chain reader.** The gateway's chain reader is the agreeing `LeaseReader`. There is no first-answer client anywhere
  on the host.

## Evidence

All of the following is in `test/management-plane.test.mjs`.
- **Real:** TLS, a test CA chain checked by Node's TLS for the browser origin, the directory server and `runDirectory`,
  P-256 and secp256k1 signatures, `LeaseReader.agreed` over three scriptable RPC clients, and the gateway.
- **Real supervisor:** the unmodified `supervisor.js` runs as a child process behind the gateway, with no self-test
  seam (`test/helpers/management-supervisor.mjs`). Its world is local:
  - chain reads go to a local JSON-RPC server via `BASE_RPC`;
  - the app manager is a local HTTP server via `VMMGR_URL`;
  - the deployment is seeded through its own `STATE_FILE`;
  - a preload refuses every non-loopback fetch.

  Status, logs, app token, CPU profile, profile start and restart each run exactly once. It refuses the management base
  without the token, with a wrong token, for another runner, from a non-loopback peer, and when `MANAGEMENT_GATEWAY` is
  off.
- **Browser page:** the page's fetch is emulated, enforcing preflight, `Access-Control-Allow-Origin`, exposed headers,
  `redirect: 'error'` and no credentials. The dashboard's own real-browser test is the browser workstream's.

## Not yet wired, and not provided

- CLI `enclave logs/attest/restart` and the dashboard UI (owned by the CLI and browser workstreams).
- Production: `MANAGEMENT_GATEWAY=1` in the host/control image, launching `management-host.mjs` beside the supervisor
  with its keys, deploying the updated directory server, and obtaining WebPKI certificates for any browser origin.
- **Full parity is future work.**
  - Only SessionVault sessions of the one pinned factory work; there is no EOA or SIWE per-request credential.
  - Logs are a tail, with no follow mode.
  - No deletion, topup, listing or custom-domain management goes through this plane.
- **Supervisor replay guard (legacy session-auth path).** The supervisor's own guard (`session-api-auth.mjs`
  `replayGuard`, outside this module) still evicts the oldest live nonces past 100,000 entries. The gateway's guard
  does not. This matters only to a header also captured by breaking the transport's TLS.
- **Authorization still needs two agreeing RPCs reachable over HTTPS;** see "What each path depends on".
- The management key is not bound to a measured host identity.
- Rate limiting is only the in-flight bound.
