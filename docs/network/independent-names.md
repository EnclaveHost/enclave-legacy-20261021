# Independent names and certificates for direct guests

**Activation status:** the host routing and package format have software tests. The measured guest implementation,
image release and real-CA/hardware rehearsal are separate activation requirements; this document is not evidence that
production guests already support these paths.

A direct measured guest (the `bootstrapdirect` front, started from an
owner-committed startup package) can serve the owner's own DNS names with a
browser-trusted certificate for **its own attested TLS key**. It needs no Enclave
domain map, CA account, expected-guest prediction or DNS-01 zone. The owner (or the
operator the owner works with) chooses the CA and the challenge responder.
Nothing falls back to an Enclave service when a choice is missing.

This is separate from the legacy paths, which are unchanged:

- The relay-fed custom-domain watcher (`front/domains.go` `watchDomains`) still
  runs only in non-direct guests.
- The supervisor's certificate relay (`isolation/m4/guestd/supervisor-guestcert.mjs`)
  and the relay's `/v1/certs/issue` are unchanged.
- The `<8 hex>.app.enclave.host` label derived from `HOST_DATA` keeps its own
  install rule.

## What a committed name is worth

A listed name is the owner's claim, not proof that the owner controls the name.
The guest will:

- produce a CSR for the name, for its own key (`GET /.well-known/enclave-csr?name=`);
- install a certificate for the name (`POST /.well-known/enclave-cert?name=`) only
  if all of these hold:
  - the leaf carries the guest's key;
  - the leaf is for that name and is valid now;
  - the chain verifies to the WebPKI roots measured into the image: ISRG X1/X2,
    Sectigo E46, USERTrust ECC, GTS R4 and DigiCert G2
    (`isolation/m2/bootstrap/pins.go`, `release/pins.go`).

So a certificate is served only when a CA validated the name through the name's
normal DNS authority. A package that lists someone else's name yields a CSR that
no CA will sign for anyone but that name's controller. A forged chain from an
unmeasured root, or a chain for another key, is refused. The tests
`front/names_test.go` and `test/dns-relay-attested.test.mjs` cover these cases.

## The package member

`names` is an optional member of the version 1 startup package. Packages written
before it existed keep their exact bytes, hash and meaning. Go
(`isolation/m2/bootstrap/names.go`) and JS (`sdk/bootstrap/package.mjs`
`validateNames`) apply the same validation, cross-checked by
`isolation/m2/bootstrap/testdata/names-vectors.json`.

```json
"names": {
  "hosts": ["shop.example.com", "www.example.com"],
  "acme": {
    "directory": "https://acme.zerossl.example/directory",
    "challenge": "https://challenge.owner-or-operator.example",
    "zone": "acme.owner-or-operator.example",
    "eab": { "kid": "ACME_EAB_KID", "hmac": "ACME_EAB_HMAC" }
  }
}
```

| Field | Rule |
| --- | --- |
| `hosts` | 1 to 10 names, strictly ascending and unique; lowercase LDH labels, at least two labels, a top label with a letter. No wildcard, trailing dot, IP literal or `enclave.host` name. |
| `acme` | Optional. Without it, issuance is external only (see below). |
| `acme.directory`, `acme.challenge` | `https://<dns name>[/path]`. No port, credentials, query or fragment; at most 512 bytes. |
| `acme.zone` | The responder's challenge zone: a DNS name of at most 204 bytes. |
| `acme.eab` | Optional. **Names** two distinct custody secrets and requires `secretsMode: "custody-v2"`. The values never appear in the package. |

A JSON `null` anywhere in the member, unknown or case-aliased keys, and duplicate
keys are refused in both languages.

Prepare a package with the CLI:

```sh
enclave bootstrap prepare <id> --contract-pins pins.json --config-file app.json \
  --app-id <hex> --runtime-id <hex> --custody-file custody.json --out startup.json \
  --names shop.example.com,www.example.com \
  --acme-directory https://<ca>/directory --acme-challenge https://<responder> \
  --acme-zone <responder zone> \
  --acme-eab-kid-secret ACME_EAB_KID --acme-eab-hmac-secret ACME_EAB_HMAC
```

The output's `dns` list gives the records to publish. Each one is a CNAME from
`_acme-challenge.<host>` to the deployment's alias.

## Proving control: the owner-bound challenge alias

```text
_acme-challenge.shop.example.com.  CNAME  _acme-challenge.<label>.<responder zone>.
label = hex(sha256("enclave-acme-alias-v1\0" || deploymentId[32] || owner[20]))[:32]
```

The label commits to the deployment **and its current owner**. If the deployment
changes hands, the new owner's guest writes to a different alias. The previous
owner's delegation then no longer validates for it, even on the same responder
(`TestChangedOwnerCannotUseThePreviousOwnersDelegation`).

The name's DNS controller decides which deployment can obtain certificates for
the name by publishing, or withdrawing, that CNAME.

## Issuance

### In-guest ACME (owner-selected CA and responder)

When `acme` is present, the front (`front/acme.go`) works as follows:

1. It mints an ACME account key in guest memory. The account key is never the TLS
   key. With `eab`, the binding comes from the owner's custody release inside the
   guest; the value must be base64url and at least 16 bytes.
2. It orders one name at a time, so each name is its own duplicate set.
3. It pushes the dns-01 value to `<challenge>/v1/txt` through the host's egress,
   with TLS verified against the measured roots. The push is:
   - signed with the attested TLS key over
     `"enclave-acme-push-sig-v1\n" || body`;
   - accompanied by the guest's attestation document, whose report binds that
     key and `sha256("enclave-acme-push-v1\n" || v, op, name, value,
     deploymentId, owner, ts, spki)`.
4. It installs the chain through the same install check as above. It reuses a
   certificate until two thirds of its lifetime, and backs off failures
   exponentially from 15 minutes to 24 hours.

Issuance starts only once the app serves, so the attestation's runtime self-test
covers the running app. The CA's terms of service are accepted on the owner's
behalf, because the owner selected the CA.

### External issuance (operator- or owner-selected, any ACME client)

With or without `acme`, anyone may fetch the guest's CSR for a committed name,
obtain a certificate with their own CA account and DNS authority, and post the
chain to `/.well-known/enclave-cert?name=<host>`. The guest's key never leaves the
guest, and the install check decides. This is how an operator keeps using its own
issuance tooling without any Enclave service.

## Running a challenge responder

`relay/dns-relay.js` with `DNS_CHALLENGE_AUTH=attested` is an authoritative
DNS-01 responder that anyone can run for their own zone:

```sh
DNS_CHALLENGE_AUTH=attested
CHALLENGE_ZONE=acme.owner-or-operator.example   # delegate this zone (NS) to the responder
NS_NAME=ns1.owner-or-operator.example           # NS_NAMES for several replicas
ATTESTED_MEASUREMENTS=<96 hex>[,<96 hex>…]       # the measured direct releases you trust
ATTESTED_MIN_TCB='{"genoa":{…}}'                 # optional firmware floor (requires "attested")
ATTESTED_KDS=1                                   # 0 = never contact AMD KDS; the guest must carry its VCEK
DNS_PORT=53 DNS_API_PORT=8153
```

The responder refuses to start if any fleet, HMAC, route-map, registry,
eligibility or legacy-zone setting is present, so it cannot silently fall back to
one. It writes a TXT value (set or delete) only when every one of these holds:

- The body is signed by the key it names.
- The attestation binds that key and this exact push.
- The launch measurement is pinned.
- The AMD chain verifies, with the TCB floor if one is configured.
- `HOST_DATA` is the deployment named in the push.
- The name is that deployment and owner's alias in this zone.
- The value is a dns-01 digest.
- The timestamp is within 300 seconds.

`ATTESTED_JUDGE_MODE=lab-unsigned` skips only the AMD chain. It exists for
synthetic lab tests and is reported on `/health`.

The responder does not read the chain. It relies on the pinned measured code
having verified the owner, lease and startup commitment against its own RPC
quorum before it asks. Its operator's trust is the list of pinned measurements.

**Request bounds.** Every request is answered exactly once.

- `/v1/txt`:
  - a 64 KiB body cap: a declared or streamed body over it gets 413;
  - `ATTESTED_PUSH_READ_MS` (default 10 s; 1 to 60 s) for the body to arrive, then 408;
  - at most 16 verifications at once across all peers (503 with `retry-after: 1`);
  - a per-peer rate limit.
- An unknown route is a JSON 404. A slot is returned on every outcome,
  including a client disconnect.

`ADDRESS_BOOK_ADDRESS` and `BASE_RPC` are among the settings that refuse
startup.

### Enclave Shield guests (separate opt-in)

`ATTESTED_SHIELD_POLICY` admits Enclave Shield (T0-hv) guests: an
`enclave-shield-app-policy/1` document of TPM roots, platforms and (VBS launch
digest, RuntimeID) pairs. Every verdict says tier `hv-node`, `hostExcluded:
false`. It is never SEV-SNP operator exclusion. It also requires:

```sh
ATTESTED_SHIELD_PROFILE=contracts/deployments/network-profile-base.json   # a reviewed authority profile
ATTESTED_SHIELD_PROFILE_DIGEST=sha256:ee957827032cf7208434e4c73f9e859a27e4fc5c6cab5f4a2153308c09eb4cb8
ATTESTED_SHIELD_RPCS=https://<rpc one>,https://<rpc two>                 # distinct hosts
# optional: ATTESTED_SHIELD_PINS=<contract-pins.json>, which must name the profile's registry
```

**Registry reads.**
- The node's operator attests its TPM boot at `POST /v1/shield-session/challenge`
  and `POST /v1/shield-session/attest`.
- For every registry read, two distinct RPCs must agree at one block on the raw
  facts: the registry's runtime code hash and length, `registrySchema()` and
  `get(hostId)`.
- Only then are the facts judged against the profile's registry pin. Today that
  pin is `0x868e…ccac`, schema 4, code `0x39911d6f…`, 5892 bytes.
- The responder decodes get() layouts 4 and 5 only. Other code or another
  schema refuses the host.
- The entry must name this endpoint, with the signer as its operator, and be
  active.

**Session lifecycle.**
- A host session lasts 10 minutes.
- One TPM endorsement key may hold at most 4 live sessions.
- A push is checked against every live session (at most 128):
  - each session's own IDKS selects the one that signed the guest's report;
  - only that session runs the full host and app verification.

  Measured cost: about 2 to 7 ms per accepted push and 5 ms for a refused one
  with 128 live sessions.
- When the matched host's registry check is older than 60 seconds, it is read
  again:
  - an agreed transfer, deactivation or refused registry ends the session (403);
  - an RPC outage is 503 and keeps the session until its expiry.

**Trust boundary.** The responder trusts:
- the operator's policy pins;
- the reviewed profile, pinned by its digest;
- its two or more RPCs (two must agree);
- the pinned Shield image's own chain checks.

It consults no address book, fleet, relay or default RPC.

## Lifecycle and state

- Names apply only while the guest's authorization is current.
- The front refreshes every minute
  (`bootstrap.Authorization.Refresh`).
- The chain reader first requires at least two fresh RPCs to report identical
  raw facts (block, hash, ledger row) for the same block. Only then does it judge
  that row (`chain.go` `leaseCurrent`).
- Within its 20-second deadline, the reader waits for every RPC's head:
  - A slow honest head still joins the read, so a fast pair that cannot agree
    cannot exclude it.
  - A block that later heads support and that is strictly newer replaces one
    chosen from a single bad fast head. The block never goes below the highest
    block already accepted.
  - A fresh agreeing pair returns without waiting for a hung RPC.
  - Freshness is checked again at acceptance.
  - An answer for a superseded target block never counts, and that round's
    remaining requests are cancelled.
  - Each vote is one distinct RPC host. Case and a trailing dot are
    canonicalized, IP literals are compared by address, and malformed names are
    refused.
  - Block headers must carry a `0x`-prefixed 32-byte hash.
- If that agreed row shows any of the following, the names are **revoked for
  good** at that refresh:
  - the lease cancelled or suspended (inactive), released (no runner or
    operator; the ledger's `release()` zeroes runner, operator and `leaseUntil`),
    or ended;
  - a change of owner, runner, operator, app reference or envelope.

  CA certificates stop being served at the next handshake, CSRs and installs are
  refused, and an ACME order still in flight installs nothing.
- One lying RPC cannot revoke what an honest pair reports live, and cannot keep
  alive what the pair reports ended.
- An RPC outage, meaning no two fresh RPCs agree on the same block's facts, does
  not revoke the names. They lapse at the last agreed snapshot plus `NameGrace`
  (10 minutes), and never later than the lease.
- Startup is unchanged and fails closed. On an agreed lease that is not yet
  current (a just-claimed lease not yet confirmed), the guest waits within its
  bounded window and never starts on it.
- `GET /.well-known/enclave-names` reports:
  - the committed hosts and whether they are authorized, with the expiry;
  - for each name, its certificate (issuer, serial, validity, renewal point) and
    in-guest issuance state (last attempt, last error, next attempt);
  - the CA, responder and challenge alias;
  - the limits below.

  It contains no key material.

## Limits that remain

- **Duplicate-certificate rate limits.** The TLS key lives only in guest memory,
  so every relaunch needs new certificates. Let's Encrypt allows 5 certificates
  per exact name set per week. Choose a CA without that cap, for example an EAB
  account such as ZeroSSL's, or limit relaunches. A host, or a second genuine
  instance launched under the same deployment, can spend this budget by
  relaunching. That is a denial-of-service exposure, not a key compromise.
  Persisting certificates across relaunches would need sealed state, which does
  not exist yet.
- **Failed validation limits.** A host the owner never delegated fails at the CA
  and backs off. Publish the CNAME before activating the package.
- At most 10 names per deployment, and no wildcards.
- **Reachability** is covered in
  [independent name routing](independent-name-routing.md). Direct hosts route a
  committed name only while the guest proves a public certificate for it on its
  attested key. Enclave-network provider ingress is still a gate there.

## Activation gates (not done by this change)

- The front's measurement changes, for both the direct and the legacy build. A
  new measured direct release must be built, its measurement published and pinned
  (`ATTESTED_MEASUREMENTS`, native-client and verifier policies), and validated
  on SEV-SNP hardware with a real report and VCEK. Until then only the synthetic
  tests here exist.
- No public certificate has been issued through this path, and no responder has
  been deployed.
- The provider ingress name list and the browser package verifier
  (`site/js/core/startup-package.js`) must accept the optional `names` member.
- Every challenge responder, CA directory and ingress in use today would be
  Enclave-operated or test infrastructure. Another responder run by Enclave is
  not organizational independence; independence needs a responder operated by
  the owner or by an unrelated operator.
