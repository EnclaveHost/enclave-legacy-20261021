# Routing owner-committed custom names through independent hosts

[Independent names](independent-names.md) lets a direct measured guest hold a
browser-trusted certificate for the names its owner committed. This page covers
the inbound half: how an independent direct host routes `https://shop.example.com`
to that guest. It uses no relay domain map, Enclave DNS zone or other central
service.

## What selects a deployment for a custom name

A direct host (`network/direct-runtime.mjs`, enabled by
`enclaveNetwork.direct.ownerNames`) routes a TLS ClientHello for an owner name
only when all four of these checks pass at that moment
(`network/owner-names.mjs`):

1. **Owner intent.** The name is listed in the exact startup package that the
   current lease's envelope commits to. The package is verified against the
   lease's chain, ledger, deployment, owner and app reference. Package bytes come
   from the operator's explicit gateways and are authenticated by the hash
   commitment, never by the gateway. A relay domain map, an unsigned alias or a
   host configuration file is never consulted.
2. **Name control.** The deployment's own guest, reached through the host's normal
   forward path (the same guestd splice that carries app traffic), presents a
   certificate for the name that:
   - chains to the public root store (Node's bundled Mozilla roots);
   - is valid now;
   - is on exactly the TLS key that the host's current attested guest proof
     bound (`AdmissionGate` proof `spkiSha256`).

   A package proves owner intent, not DNS ownership. Only a CA's DNS validation
   produces such a certificate, and the guest front installs nothing else
   (`isolation/m2/front/certs.go`).
3. **Current scope.** The proof was made under the lease scope that is still
   current: owner, envelope (startup commitment), runner, app reference, ledger
   and chain. The attested key must also be unchanged. Any change retires the
   route on the next ClientHello, with no waiting for a refresh.
4. **Admission.** The app is admitted on this host. That means a current lease
   held by this runner and a current guest proof, the same gate that platform
   labels use.

Proofs are made one name at a time:

- at most 10 names per app;
- a 5-second handshake deadline, after which the connection is closed;
- nothing is sent after the handshake;
- proofs run when an app is admitted and every 100 seconds after that;
- a proof lapses after 5 minutes unless it is re-made, and it is never extended.

### Conflicts

- **Platform labels** (the host's static `names`) are exclusive and always win a
  lookup on that host. An owner name equal to another app's label is never
  proven.
- **A deployment that lists another deployment's name** but cannot prove it is not
  a candidate. It can neither take the name nor veto it. Each deployment's proofs
  are stored separately, so one deployment's refresh never removes another's.
- **Two deployments that both prove a name:** the certificate with the later
  `notBefore` wins. A later DNS-validated issuance is the name controller's fresher
  statement. An exact tie selects neither deployment for that name only, and every
  other name keeps routing.
- **A previous DNS owner's still-valid certificate** loses to the current
  controller's newer one. Until the new controller issues, the old certificate
  remains valid WebPKI evidence. That is inherent to certificates, and CT
  monitoring is how an owner sees it.

## Owner runbook

1. **Commit the names** (`enclave bootstrap prepare … --names shop.example.com,www.example.com`),
   then publish and activate the package as usual.
2. **Get certificates on the guest key** before expecting traffic:
   - **In-guest ACME:** select the CA and responder in the package, and publish
     each `_acme-challenge.<host>. CNAME <alias>.` record that `bootstrap prepare`
     prints. DNS-01 needs no inbound route.
   - **External issuance:** fetch the guest's CSR through the platform label,
     which already routes, then post the chain to
     `/.well-known/enclave-cert?name=<host>`.

   Check `GET https://<label>/.well-known/enclave-names` for each name's
   certificate state.
3. **Point the names at the host that holds the lease:**
   - `shop.example.com. A <direct host IPv4>` and/or `AAAA <IPv6>`. Use the
     address from the deployment's **verified** direct route record (the signed,
     checker-qualified record a native client verifies), not an address someone
     tells you.
   - A subdomain may instead be a `CNAME` to a name whose A/AAAA records you, or
     an independently run read-only DNS zone (`relay/dns-relay.js
     DNS_READ_ONLY=1`), keep equal to the verified route address. An apex name
     needs A/AAAA records.
   - Keep the TTL short (60 to 300 seconds). When the lease moves to another
     runner, the old host stops routing the name at once and the new host starts
     only after its guest proves the name.
   - You may publish the addresses of several hosts. Only the lease holder with a
     proof answers, and clients that try the next address fail over.
4. **Optionally publish CAA** for each name, limited to the CA you selected.

A name listed in the package but not yet certified is refused at the TLS layer,
with no fallback and no Enclave certificate. That is the expected state while
issuance is in flight.

## Host operator configuration

```json
"enclaveNetwork": {
  "direct": {
    "address": "<qualified public IP>",
    "qualificationFile": "/srv/enclave/direct-qualification.json",
    "ownerNames": { "gateways": ["https://<package replica>/ipfs", "http://<literal IP replica>:8189/ipfs"] }
  }
}
```

- **Gateways:** 1 to 8, HTTPS or literal-IP HTTP, with no credentials or query.
  They are typically the same replicas that serve startup packages to guestd
  (`GUEST_BOOTSTRAP_GATEWAYS`).
- **Absence:** without `ownerNames`, the host serves platform labels only, exactly
  as before. There is no default gateway and no relay fallback.
- **Roots:** no configuration file can change the root store. `ownerNameRoots` is
  a code-level parameter of `createNetworkHost` for embedders and tests only.
- **Attested key:** the privacy agent passes the key of the current local guest
  proof (`attestedKey`). Without it, `ownerNames` refuses to start.
- **Status:** `direct.runtime.ownerStatus(id)` returns
  `{names: {<host>: 'proven' | reason}, routed: [...], error}`. The agent's status
  snapshot does not include it yet.

## What is not covered yet

- **Enclave-network circuits (wg providers).** Provider ingress
  (`network/wg-provider/provider.mjs`) still takes custom names only from a
  configured relay's `/v1/domains/map`, and `route()` picks the newest peer that
  holds a name. Integrating it needs these changes in the provider stream's files:
  - derive each ingress peer's candidate names from the verified package (its
    lease is already read);
  - after the grant, prove each name with `proveNameControl`, opening a
    connection to the peer's tunnel address;
  - store the proofs in an `OwnerNameTable`, and make `route(name)` call
    `table.select(name, live)`, with `live` checking the peer's lease, runner and
    expiry;
  - drop the relay map.

  The provider cannot see the guest's attested key, so it can bind the proof only
  to WebPKI and the peer's tunnel. Clients still verify attestation end to end.
- **Windows circuit worker.** `createAppIngress` accepts `admitName`. The worker
  (`network/windows-circuit-worker.mjs`, Windows stream) must pass a predicate
  backed by a host-side proof table.
- **Browser package verifier.** `site/js/core/startup-package.js` allows a fixed
  key list without `names`, so named packages are refused there. The browser
  stream should add `names` to that list and validate it exactly as
  `sdk/bootstrap/package.mjs` `validateNames` does: import it, or mirror the rules
  and test against `isolation/m2/bootstrap/testdata/names-vectors.json`.
- **Live evidence.** The end-to-end test
  (`test/independent-name-routing.test.mjs`) uses fixtures:
  - Node TLS servers stand in for guests;
  - a local test root stands in for the public CA;
  - a fixture lease stands in for the chain;
  - a fixture key stands in for the admission proof.

  Still needed: a real SEV-SNP guest on a qualified direct host, a real CA
  certificate (staging or production), and public DNS pointing at the host.
