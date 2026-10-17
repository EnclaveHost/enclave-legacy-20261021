// THE POOL BADGES: the coloured pill that names a box's CPU or GPU pool, from the relay's /enclaves row.
// One source for every surface that names a pool: the Live enclaves rows (fleet-list) and a deployment's
// "21% [tee cpu]" allocation on the dashboard (deployments). The pill IS the pool label, so it is said once,
// in the colour that means it: jade only on hardware evidence, iris for Enclave Shield and a consumer PC,
// amber for the phone tier and for a box that reports no CPU TEE, plain for a box that has not said.
import { esc } from "./util.js";
import { enclaveClassOf, teeCpuOf } from "./pricing.js";

// The CPU pool: jade "TEE CPU" only when there is EVIDENCE the box's
// CPU is a confidential-computing TEE (the technology its own
// attestation document presented, or the relay's verified SEV-SNP
// attach, see teeCpuOf) -- never inferred from the box having no card.
// A separate root of trust is coming (hosts anchored on a phone), and
// those boxes must not inherit a green pill they did not prove: amber
// "NO TEE CPU" when the box reports a non-TEE document (a metal dev
// box), plain "CPU" when it has not said.
// THE PHONE TIER reads amber "pvm cpu": the relay verified the protected VM's chain, and the
// tier is under construction - CPU-only Wasm workloads inside the pVM (no model, no accelerator),
// admission by proven capability - so the badge is its identity and the tooltip is future tense. Never the jade
// "tee cpu" of the server contract, which this is not.
// THE CONSUMER PILL reads "cpu" in iris, the same rule the shielded GPU pool follows: the word
// names the pool; the ABSENCE of "tee" is the signal that this is not the platform's
// confidential-VM guarantee, and the evidence the tier DID present (a TPM quote, a measured-boot
// log and an enclave report, against a weaker threat model) is in the tooltip.
export function cpuPoolBadge(e){
  const tc = teeCpuOf(e);
  // Shield marketplace admission is a relay verdict, separate from a CPU TEE.
  const shieldCpu = e.tunnel === true && e.mode === "hv-node" && e.tier === "enclave-shield"
    && e.eligible === true && e.appEvidenceRequired === true;
  return shieldCpu
    ? '<span class="ap-badge info" title="Enclave Shield: the relay verifies each app’s measured partition and guest-held TLS key. The physical operator and hypervisor remain trusted.">cpu</span>'
    : tc.real && tc.phone && e.eligible === true && e.appEvidenceRequired === true
    ? '<span class="ap-badge warn" title="' + esc(tc.note) + '. The relay verified this phone’s protected-VM attestation chain when it attached and admitted its capability report (a CPU-only Wasm runtime: no model, no accelerator). It takes CPU-only deployments: before an app is served or given a certificate, the relay verifies a fresh attestation from the VM binding that app’s code and its TLS key, so TLS ends inside the protected VM.">pvm cpu</span>'
    : tc.real && tc.phone
    ? '<span class="ap-badge warn" title="' + esc(tc.note) + '. The relay verified this phone’s protected-VM attestation chain when it attached and admitted its capability report (a CPU-only Wasm runtime: no model, no accelerator). The tier runs CPU-only workloads; it is being built for Pixel 10 and Pixel 11 and is not available for deployments yet.">pvm cpu</span>'
    : tc.real && tc.phoneUntiered
    ? '<span class="ap-badge" title="' + esc(tc.note) + '.">pvm</span>'
    : tc.real && tc.consumer
    ? '<span class="ap-badge info" title="' + esc(tc.label) + ': ' + esc(tc.note)
      + '. The relay verified this PC’s TPM quote, measured-boot log and enclave report when it attached.'
      + (tc.dev ? ' This build is ' + esc(tc.dev) + ': admitted by a development policy.' : '')
      + '">cpu</span>'
    : tc.unverified
    ? '<span class="ap-badge warn" title="This tunnel box says its CPU is ' + esc(tc.label)
      + ', but the relay verified no hardware quote when it attached (token or operator attach). A self-report is not evidence:'
      + ' the box is not eligible for tenant work until it attaches with a verified quote.">unverified cpu</span>'
    : tc.real
    ? '<span class="ap-badge ok" title="' + esc(tc.label) + ' confidential VM: '
      + (tc.source === "relay"
          ? 'the relay verified a fresh hardware quote from this box when it attached'
          : 'this box’s attestation document presents a hardware quote')
      + ', so every vCPU it sells runs inside the measured enclave and is covered by'
      + ' its attestation.">tee cpu</span>'
    : tc.known
    ? '<span class="ap-badge warn" title="This box reports no CPU TEE (attestation format '
      + esc(tc.technology) + '): nothing it sells is covered by a hardware attestation.">no tee cpu</span>'
    : '<span class="ap-badge" title="This box has not reported whether its CPU is a TEE:'
      + ' its build predates the field, or its attestation document has not been read yet.'
      + ' Only a hardware quote earns the green pill.">cpu</span>';
}

// The GPU pool: jade "TEE GPU" for a card INSIDE the measured enclave,
// iris "GPU" for one on the untrusted host reached by masked offload --
// the ABSENCE of "tee" is the signal, and the tooltip says outright
// that this card is outside the enclave and outside its measurement.
// "" for a box with no card to sell.
export function gpuPoolBadge(e){
  const a = (e && e.availability) || {};
  const sh = a.shielded && a.shielded.vramGb > 0 ? a.shielded : null;
  return enclaveClassOf(e).inTee
    ? '<span class="ap-badge ok" title="This card is INSIDE the confidential'
      + ' enclave and covered by its attestation.">tee gpu</span>'
    : sh
    ? '<span class="ap-badge info" title="Enclave Shield: masked GPU offload protects activations and verifies results. The GPU remains outside the confidential boundary.">gpu</span>'
    : "";
}
