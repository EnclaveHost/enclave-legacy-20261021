# Custodian opt-in: Enclave Shield release recipients

A custody v2 custodian releases to SEV-SNP guests only, unless its **operator** builds its image with the optional,
**measured** Shield recipient opt-in. Then it may also release to an Enclave Shield partition: a Hyper-V partition on a
Windows TPM host at tier `hv-node/T0-hv`, with `hostExcluded: false`.

This is a weaker tier. The host's physical operator and hypervisor are trusted, and nothing excludes them. A release to
such a partition needs both of these:

1. **The custodian operator's opt-in.** It is baked into the image (this document), so it is covered by the launch
   measurement that committee members approve with `code-approve`.
2. **The deployment owner's Shield rules.** These are `enclave-custody-shield-rules/1`, with the exact acknowledgement
   `windows-tpm-host/hv-node/T0-hv/hostExcluded:false`, committed in the vault policy (`custody/v2/shield-rules.mjs`).
   Default and SNP rules never admit a Shield document. SNP evidence never reaches the Shield verifier.

Neither one alone releases anything.

## What the operator measures

`node scripts/build-custodian-v2.mjs ... --transport direct --shield-recipients shield.json`

```json
{
  "format": "enclave-custody-shield-operator/1",
  "acceptTier": "windows-tpm-host/hv-node/T0-hv/hostExcluded:false",
  "ekRoots": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "ekRootPins": ["<sha256 of each self-signed root's DER, lowercase hex>"],
  "limits": { "sessionLifeSec": 600, "maxSessions": 256, "maxPendingChallenges": 64,
              "maxAttestBytes": 4194304, "maxConcurrentAttests": 2 }
}
```

The build validates this file (`custody/v2/shield-operator.mjs validateShieldOperator`) before any build work. The
daemon validates it again at start, and an invalid one makes it refuse to start. It is never repaired, and never
silently dropped to SNP-only. The build refuses:

- **Keys.** Unknown or missing keys, or a format or `acceptTier` that is not exactly the one shown above.
- **`ekRoots`.** Anything other than PEM text made only of `CERTIFICATE` blocks:
  - a file path (the relay's root loader would read a path, so it is refused);
  - a key block;
  - more than 16 certificates or 256 KiB;
  - a certificate that does not parse, is a duplicate, or is not a CA certificate;
  - no self-signed root at all.
- **`ekRootPins`.** The pins must equal exactly the set of self-signed roots in `ekRoots`. A root without a pin, a pin
  without a root, a pin of an intermediate, or a repeated pin are all refused.
- **`limits`.** Every limit is required, is an integer, and must be in range:

  | limit | range | default | meaning |
  | --- | --- | --- | --- |
  | `sessionLifeSec` | 60..3600 | 600 | how long a host session this custodian verified counts |
  | `maxSessions` | 1..1024 | 256 | live verified host sessions (one per host endpoint and signing operator) |
  | `maxPendingChallenges` | 1..256 | 64 | issued, unanswered credential challenges (single use, 60 s) |
  | `maxAttestBytes` | 64 KiB..8 MiB | 4 MiB | body bound of `/v2/custody/shield-session/attest` **only** |
  | `maxConcurrentAttests` | 1..4 | 2 | attests being read or verified at once |

- **Transport.** `--transport tunnel` is refused. A Shield host reaches the custodian's own routes at its registered
  endpoint, and the Enclave relay's tunnel forwards only its fixed custody surfaces.

The image manifest records `shieldRecipients` (`format`, `acceptTier`, `ekRootPins`, `limits`), or `null`. The full
roots are in the measured bundle.

**Not from the host.** The opt-in, the roots and the limits are never read from:

- the fw_cfg host configuration (`custody/v2/host-config.mjs` reads a fixed field list and ignores anything else);
- the environment;
- the host's `/state` or `/receipts`;
- any fetched document.

A host that could choose the TPM roots could vouch for a host session of its own making.

## Who the custodian is to a host

Its **party** is its own committee encryption key, the `encKey` from its sealed state and the one listed for it in the
committee. The host operator's attach signature names that key, and the node targets each custodian by it
(`windows/node/shield-sessions.mjs custodianTargets`). `createCustodianV2` refuses an adapter for any other party. No
configuration or host can choose it.

## Routes

These exist only on an image with the opt-in. Without it they are an unknown route (404), exactly as before.

| route | body bound | answer |
| --- | --- | --- |
| `POST /v2/custody/shield-session/challenge` `{hostId, endpoint, hostChallenge, keys}` | 256 KiB | `{session, nonce, appNonce, credentialBlob, secret, party}` |
| `POST /v2/custody/shield-session/attest` `{session, rad, operatorSig}` | `limits.maxAttestBytes` | `{ok, party, until, tier:"hv-node", hostExcluded:false}` |

How the routes behave:

- **Rate limit.** Both routes are under the same per-client rate limit as every other POST.
- **Attest bounds, in order:**
  1. a `Content-Length` over the bound is refused (413) before anything is read;
  2. a streamed body is counted and refused (413) at the bound, and the rest is discarded, not buffered;
  3. at most `maxConcurrentAttests` are read or verified at once (otherwise 503, before reading);
  4. a body still arriving after 60 s is cut off. A client that goes away mid-body gives its slot back at once.

  So clients that hold the slots can delay Shield session renewals by at most that minute per attempt, under the
  per-client rate limit. They cannot affect releases that already have a live session, or any SNP path.
- **Session errors** come back as `{error: "shield_session", message}` with the session's own status:
  - 409: replayed, expired or never issued;
  - 403: the evidence is refused;
  - 422: malformed;
  - 429: too many.
- **Challenge admission** (`relay/shield-host-session.mjs`, shared with the market verifier and the DNS responder).
  Before any pending entry or credential exists, the EK certificate must pass the same two EK checks attest applies:
  - it chains to one of the measured pinned roots (the request's `ekChain` supplies intermediates only, never an
    anchor);
  - it is a leaf, not a CA certificate, and names an on-die TPM manufacturer (AMD or Intel) in its SAN.

  Anything else gets 403. Each EK holds at most 2 pending challenges (`MAX_PENDING_PER_EK`). So self-signed, other-CA,
  CA-as-leaf and discrete-TPM certificates take no pending capacity at all. A genuine certificate replayed by someone
  without its TPM takes at most 2 slots, and attest still runs the full hv-node verification.
- **Live sessions per TPM.** A host's endpoint, and so its host id, is the host's own claim until a release checks it
  against the registry. So each EK certificate keeps at most 4 live sessions, and a further one evicts that EK's
  oldest (`MAX_SESSIONS_PER_EK`). One TPM cannot fill `maxSessions` and lock out other hosts.
- **One session per endpoint and signer.** Attest accepts any signer (identity is deferred to the release), so a session
  is kept per (endpoint, signing key). Another party's attest for the same endpoint, with its own genuine TPM and key,
  adds its own entry and never replaces the lease holder's. A release uses only the session made by the operator its own
  agreed chain read names for the endpoint; any other signer's session releases nothing.
- **`/v2/custody/info`** adds `shieldRecipients: {tier:"hv-node/T0-hv", hostExcluded:false, party, path}` on such an
  image only.

**Why the attest bound is larger.** The attest body carries the host's raw TCG boot log, base64 inside a base64 JSON
frame, which is about 1.8 times the log. The verifier refuses a log over 4 MiB (`relay/vbs-tpm.mjs VBS_MAX_LOG_BYTES`).

- The default 4 MiB body carries a log of about 2.2 MiB.
- The 8 MiB ceiling carries a log of about 4.4 MiB.

**Memory.** The worst case is about `maxAttestBytes × maxConcurrentAttests` times a small constant (the body, its parse,
and the decoded log), so at most a few tens of MiB at the ceilings. Every other route keeps its 256 KiB bound.

## Rate limits and the client key

Every POST is rate limited per client (30 burst, 1/s), and each client may hold at most 64 outstanding release
challenges. The **client key** is the TCP peer address by default. A client-supplied `X-Forwarded-For` is ignored.

**Why a measured proxy list exists.** Every connection reaches the custodian through the host's forwarder: the QEMU
port forward, seen in the guest as `10.0.2.2`, behind the operator's Caddy. So on a default image **all clients share
one bucket**. That is safe, but one busy or hostile client can slow everyone.

**The opt-in.** An image built with `--trusted-proxy 10.0.2.2` (1 to 4 loopback or private IP literals; public
addresses, ranges, hostnames and duplicates are refused) reads `X-Forwarded-For`, but:

- **only** from those peers;
- **only** its rightmost entry, which is the address the proxy itself saw.

Caddy 2.11.7's `reverse_proxy` replaces a client's spoofed header with the address it saw (checked against the real
binary in `test/custody-v2-ingress-ratekey.test.mjs`).

**What this trusts.** The host can then choose rate buckets. That affects availability only, and the host can deny
service anyway. It never affects a release decision. Like the Shield opt-in, the list is measured, re-validated by the
daemon, and never read from the host configuration or the environment.

## What a release checks for a Shield document

This is custodian step 9 (`custody/v2/custodian.mjs`, `shield-evidence.mjs`). Steps 1 to 8 are the ones every release
passes: the challenge, the agreed chain read, the policy, the committee, the label proof, the owner, the live lease, and
the registered operator's signature.

1. **The adapter.** The opt-in is installed, and the rules parse as the owner's Shield rules.
2. **The host session.**
   - There is a live host session that **this custodian** challenged for `keccak256(endpoint)` of the release's own
     endpoint.
   - That session was made by the endpoint's registered operator, as named by the release's **own agreed chain read**.
     There is no relay verdict, no Enclave service, and no session shared between custodians.
3. **The report.**
   - It is signed under the IDKS from that session's TPM-authenticated boot log.
   - Its input is `sha256("enclave-custody-shield-v1\n" || v2 releaseBinding || ledger owner) || AppID`, where the
     ledger owner is the row owner the guest itself reads (for a session vault, that is the vault contract).
   - Authorization is unchanged: `beneficialOwnerOf(id)` must be the policy owner.
4. **The image.** The image and runtime pair is admitted by the owner's rules, and the platform is admitted.

## Status

- Nothing is built, measured or activated.
- Adding the opt-in, the router extraction and the new bundled modules changes the custodian bundle, and so the launch
  measurement. Every image built from this code, with or without the opt-in, needs a new `code-approve` by its
  committee.
- No real TPM, host or custodian session has run against this code.
