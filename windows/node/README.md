# windows/node: the Windows consumer node

The pieces a Windows 11 machine runs to join the fleet as a `windows-vbs-node` (contract:
`windows/vbs/EVIDENCE.md`). This directory holds the TPM half; the enclave half lives in
`windows/enclave-engine/`, the agent that drives both is `agent.mjs`.

## tpmattest.exe: the TPM half, driven over stdin/stdout

`tpmattest.c` is one MSVC tool (raw TPM 2.0 commands through TBS, no TSS) that the agent spawns
once per session and talks to line by line. Build with `build-tpmattest.cmd` (vcvars64 + `cl`,
links `tbs.lib bcrypt.lib ncrypt.lib crypt32.lib`). Run it elevated: `Tbsi_Get_OwnerAuth` (the
endorsement hierarchy's auth value, which Windows set at provisioning) is administrator-only.

At startup the tool opens TBS and creates the quoting key (AIK): `TPM2_CreatePrimary` in the NULL
hierarchy, RSA-2048, `fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|restricted|sign`,
RSASSA/SHA-256. The key stays loaded for the life of the process (it is ephemeral: a new one per
process, gone at reboot), so `keys`, `activate` and `quote` all refer to the same key. It prints
`ready tpmattest/1` and then waits for commands.

### Grammar

One command per line on stdin. Every reply is zero or more `<key> <value...>` lines followed by
exactly one terminator, `ok` or `err <step> <detail>`; the agent reads until the terminator. Byte
strings are lowercase hex (the agent base64s them for the tunnel).

| command | reply lines |
|---|---|
| `keys` | `ek-cert <hex DER>`, `ek-cert-source nv:0x01c00002 \| ncrypt:PCP_EKCERT \| none`, `aik-pub <hex TPMT_PUBLIC>`, `aik-name <hex 34 bytes = 0x000b \|\| sha256(TPMT_PUBLIC)>`; informational `ek-cert-nv-failed ...` / `ek-cert-store ...` lines when the TCG NV index is absent and the certificate came from Windows' EK cert store |
| `activate <credentialBlob hex> <secret hex>` | `endorsement-auth windows:<n>-bytes \| empty`, `ek-pub <hex TPMT_PUBLIC>`, `ek-name <hex>`, `ek-source createprimary:endorsement \| persistent:0x81010001`, `ek-cert-match yes \| no \| unknown`, `policy-hmac empty \| computed`, `credential <hex>` (the bytes ActivateCredential recovered) |
| `quote <extraData hex, 1..64 bytes>` | `attest <hex TPMS_ATTEST>`, `sig <hex 256-byte RSASSA-PKCS1v15-SHA256>`, `sig-scheme 0x0014 0x000b`, `aik-pub <hex>`; PCR selection sha256 {0, 7, 12, 13, 14} |
| `pcr <n>` | `pcr <n> <hex sha256 value>` read live |
| `log` | `log <path>` of the newest `C:\Windows\Logs\MeasuredBoot\*.log` (the current boot) |
| `quit` | `ok`, the AIK is flushed, exit 0 (EOF does the same) |

`err` details are `tpm-rc=0x<TPM_RC>` (the TPM's response code, with the session/parameter
number encoded as the spec does), `tbs=0x<TBS_RESULT>`, or a short text.

`activate` is handshake step 5's credential activation: it loads the EK with the TCG EK
Credential Profile default RSA-2048 template under `TPM_RH_ENDORSEMENT` (falling back to the
persistent handle 0x81010001 that Windows keeps), refuses to continue unless that key's modulus is
the one in the EK certificate, opens a policy session, runs `TPM2_PolicySecret` against the
endorsement hierarchy with the auth from `Tbsi_Get_OwnerAuth(TBS_OWNERAUTH_TYPE_ENDORSEMENT_20)`
(empty password if Windows has none), then `TPM2_ActivateCredential(AIK, EK)`. Every handle it
creates is flushed before the reply.

The credentialBlob/secret pair is what `windows/vbs/tools/makecredential.py` (the verifier's
`TPM2_MakeCredential` reference, pure Python) produces from the EK certificate and the AIK name.
`windows/vbs/tools/credential_roundtrip.py` drives the whole exchange against the tool and is the
proof recorded in `windows/vbs/evidence/credential-roundtrip.txt`.

### Session example

```
ready tpmattest/1
keys
ek-cert 308204ef...
ek-cert-source ncrypt:PCP_EKCERT
aik-pub 0001000b00050072...
aik-name 000bfe41...
ok
activate 00209063ba...acd441 879c35f7...dec733
endorsement-auth windows:20-bytes
ek-pub 0001000b000300b2...
ek-name 000b71ce...
ek-source createprimary:endorsement
ek-cert-match yes
policy-hmac empty
credential fd0d8a22...6627
ok
quote 114052a1...0e1e
attest ff544347801800...
sig 1ee73887...
sig-scheme 0x0014 0x000b
aik-pub 0001000b00050072...
ok
quit
ok
```

## agent.mjs: the node

`node agent.mjs` (Node 22+, `npm install` for `ws`) runs the three processes and the fleet tunnel:
the Vulkan worker (`shielded-worker.exe`, untrusted GPU half), the enclave host (`ee-host.exe` +
`ee-engine.dll` from `windows/enclave-engine`, the trusted half in VTL1) and `tpmattest.exe`, then
dials `RELAY_URL` and attaches by evidence exactly as `windows/vbs/EVIDENCE.md` describes (keys ->
credential -> transcript/report/quote/log -> attest -> hello). Over the tunnel it answers
`/availability` (`role windows-vbs-node`, `teeCpu windows-vbs-enclave`, shares 0 so no deployment is
placed on it), `/v1/health` and `POST /v1/completions` (`{prompt, max_tokens}`; greedy; the reply
carries the enclave's offload counters). `LOCAL_HTTP_PORT=9600` serves the same surface on loopback
for tests; `RELAY_URL=none` skips the tunnel. Configuration is by environment: see
`node-config.example.cmd`; `install-node.cmd <config>` registers a logon task (elevated, interactive
session) that starts it.

Proven on the NucBox K11 (2026-09-21): worker up in 6 s, enclave up in 12 s, TPM ready, a completion
through the agent = ` Paris. It is the largest city in` with 657 nodes offloaded and 0 verification
failures, the same text the enclave alone and the Linux reference produce.

`client.mjs <hub url> <name> "<prompt>" [n]` is the sealed-session client: it takes the node's pad key
from the hub's attested row (`/info/<name>` on `relay/local-hub.mjs`), seals the prompt with
tweetnacl's crypto_box to it, POSTs the blob to `/t/<name>/v1/session`, and opens the reply; the
relay, the tunnel and the node's own host never see the text. Proven through the local hub on
2026-09-21 with the same completions as the plaintext path.

### Artifact sources for the VM manager

The VM manager invokes `fetch-cid.py` in a separate process for each artifact.
An operator can place a JSON array of gateway origins in `artifact-gateways.json`
beside that script, or select an explicit file with `IPFS_GATEWAYS_FILE`.
The file is read on every fetch and overrides the manager's legacy gateway
argument, allowing gateway migration without restarting running guests. Invalid
or missing explicitly selected files fail closed. No legacy origin is appended.
Without a file, `IPFS_GATEWAYS` takes precedence over the positional gateway and
`IPFS_GATEWAY`. Every returned CAR block and the requested CID remain verified.
Keep this operator configuration under the same protected directory permissions
as the fetcher. Gateway selection does not authorize different artifact bytes.
