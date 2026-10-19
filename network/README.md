# Application networking: the Enclave network

Every public app reaches the internet, and is reached, through the Enclave network: WireGuard circuits through
qualified providers, the owner's own WireGuard peer, or direct hosting on a host's own qualified public address, as the
owner's signed v5 network policy says. TLS ends inside the enclave; providers route raw TCP by SNI. The design is
`docs/design/enclave-network.md`; what is deployed and tested is `docs/design/enclave-network-status.md`.

TUNA (NKN) was retired on 2026-10-13 and its code removed: hosts refuse a configuration without `enclaveNetwork`, and
the relay refuses route publications that are not under a v5 policy.

## Pieces

| Piece | Files |
|---|---|
| Host privacy agent (admission, circuits, route publication) | `privacy-agent.mjs`, `enclave-network-host.mjs`, `wg-manager.mjs`, `wg-circuit-runtime.mjs`, `wg-control.mjs`, `wg-grants.mjs`, `route-publisher.mjs` |
| Circuit ingress worker (SNI gate, one per circuit; the name is historical, Linux runs it too) | `windows-circuit-worker.mjs`, `app-ingress.mjs`, `app-redirect.mjs`, `broker-client.mjs`, `app-broker.mjs` |
| WireGuard-in-WireGuard circuit process | `wg/` (Go, `enclave-wg`) |
| Windows circuit sandbox (AppContainer + WFP, tunnel mode) | `windows-firewall/` (Go, `enclave-circuit-firewall.exe`) |
| Provider daemon and qualification checker | `wg-provider/`, `../scripts/network/wg-qualify.mjs` |
| Policies, provider records, routes | `network-policy*.mjs`, `provider-directory.mjs`, `route-record.mjs`, `owner-signature.mjs` |
| Direct hosting (v5 `direct`) | `direct-runtime.mjs`, `direct-egress.mjs`, `traffic-meter.mjs`, `provider-qualification.mjs` |
| USDC settlement kept for paid Enclave-network providers (not wired into the agent today) | `usdc-bandwidth.mjs`, `tuna-usdc-settlement.mjs`, `connectivity-chain.mjs`, `connectivity-policy.mjs`, and the policy/selection helpers their tests use: `tuna-policy.mjs`, `circuit-policy.mjs`, `public-fallback.mjs` |

## Build

`node network/build.mjs /path/to/output` (Node 22, Go 1.23 or newer) writes the bundled privacy agent, the circuit
ingress worker, the provider daemon (`wg-provider.mjs`), the checker (`wg-qualify.mjs`), `enclave-wg` for Linux and
Windows, and `enclave-circuit-firewall.exe`.

## Run

`node privacy-agent.mjs --config /private/path/privacy-config.json`. The configuration (version 2) names the apps (their
expectation files and names), the host's measured platform (`linux`, `shield` or `pvm`), the chain RPCs and
`enclaveNetwork`: `{relay, checkers, apps: "all" | [ids], control, wgBinary, nodeBinary, workerModule, firewallBinary
(Windows), direct (optional: address, qualificationFile)}`. Settings left over from TUNA (`nknRpc`, `inventory`,
`control`, `runtime`, `defaults`, `tunaUSDC`, `currencyManagement`, the top-level `connectivity`/`direct` of TUNA-era
direct hosting, and per-app `walletsFile`/`ownerPolicyFile`) are ignored.

Routes are published to the relay's `/v1/network/tuna` (a historical path) as signed per-app records; DNS answers with
both exits of an app's circuits.

## Reconcile Linux app inventory without a control API

The build also emits `reconcile-apps.mjs`. Run it with explicit contract pins:

```sh
node reconcile-apps.mjs --config /private/privacy-config.json \
  --guestd-root /private/guestd-root --contract-pins /private/contracts.json \
  --names-file /private/app-names.json --dry-run
```

Remove `--dry-run` to write expectations and reload `enclave-network-agent.service`
(or select `--agent-unit`). `ENCLAVE_CONTRACT_PINS_FILE` can supply the pin path.
The version-1 Base pin document uses `network/contract-pins.mjs`'s complete schema;
missing or conflicting pins are errors, never an address-book fallback. The
configured RPCs must have at least two distinct HTTPS origins. Two peers must
agree on inventory and catalog bytes at the same recent confirmed block. The
current bounded inventory supports up to 10,000 deployments and 256 leased apps.

The optional names document is operator-local:

```json
{"version":1,"deployments":{"0x<64 lowercase hex digits>":["app.operator.example"]}}
```

Configured names replace the entry's names. Without that document, existing names
are preserved; a new entry gets `<deployment-prefix>.app.enclave.host`. An operator
using independent names should supply them explicitly. This configures ingress
names only; it does not register DNS or issue certificates. New custom domains no
longer synchronize implicitly from Enclave's domain API.

The reconciler reads local attested guest records and checks their component bytes
against the pinned catalog. It computes the canonical CID locally, without Kubo,
a pinning server, or a trusted component hash cache. The privacy agent still checks
the fresh lease, policy and actual guest proof before admitting traffic. This
reconciler does not replace those checks or establish independent TLS/custody.

### Circuit health probes

`enclaveNetwork.egressProbeUrls` optionally supplies two to eight HTTPS probe URLs
on distinct hostnames. Otherwise the agent uses the origins of its configured
chain RPCs. One successful transport response keeps egress healthy; a failed or
withholding probe cannot veto the other destinations. HTTP 4xx counts as a
transport response (RPC endpoints commonly refuse GET); 5xx and transport errors
do not. Losing probes are cancelled. These observations do not authorize a guest
or extend its lease or attestation. Choose independently operated destinations;
distinct hostnames alone do not prove independent ownership.

Control-circuit probes use the configured signed-record directories, or the
explicitly configured relay when no directories are supplied. The transport has
no built-in Enclave API probe URL.
