// What the PUBLIC app-host list is allowed to show.
//
// The incident. On 2026-09-23 the nucbox-k11 operator key ran out of Base gas, its five leases
// lapsed, and the relay was already excluding it from tenant compute (a VBS enclave whose app-zone
// TLS key and session key live in the host process is verified evidence for a different contract,
// not for this one). All of that is true and all of it is published. And for a day and a half the
// public list headed "what can I deploy on right now" showed that PC anyway, with a paragraph of
// security caveats where its capacity should have been - because the component kept an explicit
// exception for a consumer node at serving:false and printed e.ineligible underneath.
//
// Marketplace rows require a current serving/eligible verdict. Separately labeled owner-only
// inventory requires fresh, unexpired relay-authorized deployments. The evidence is not deleted - it is in
// /enclaves (status, eligible, ineligible, notClaiming) and in the architecture page's prose - it is
// just not a row in a list of machines a reader is about to buy from.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { appHostVisible, ownerHostedDeploymentCount, ownerHostCpuCapacity, ownerHostVisibleTo, pvmHostVisible, pvmHostVm, HOST_STALE_AFTER_SEC } from "../site/js/core/pricing.js";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const NOW = 1790266080;

// THE EXACT LIVE ROW, copied from https://api.enclave.host/enclaves on 2026-09-24T16:10Z.
// Attached, healthy, answering, tunnel mode vbs, operator key empty, relay verdict eligible:false.
const nucbox = {
  endpoint: "tunnel://nucbox-k11", name: "nucbox-k11", repo: "EnclaveHost/enclave",
  lastSeen: 1790266080, tunnel: true, mode: "vbs", tier: "vbs-dev",
  serving: false, eligible: false,
  ineligible: "verified enclave report, but the app-zone key and traffic run through the host: the isolation contract is not met",
  availability: {
    ok: true, role: "windows-vbs-node", gpu: false, teeCpu: "windows-vbs-enclave", tier: "vbs-dev",
    claimEnabled: false, gasRenewalsLeft: 0, registered: true, cpuShareFree: 0.75, nodeSlotsFree: 8,
    apps: { isolation: "vbs-enclave", inTee: true, running: 0, capacity: 8, scope: "market" },
    appTls: { served: true, keyIn: "host-process", terminatesIn: "host-process" },
    session: { keyIn: "host-process", alg: "ES256" },
    shielded: { worker: "vulkan", device: "AMD Radeon 780M Graphics", vramGb: 16, vramBudgetGb: 8, vramFreeGb: 8 },
  },
};

// A box that really is selling: serving, and the relay says eligible.
const selling = { name: "kryptos", tunnel: true, mode: "snp", lastSeen: NOW - 30, serving: true, eligible: true,
                  availability: { ok: true, gpu: true, teeCpu: "amd-sev-snp", gpuShareFree: 0.5, maxShare: 0.9, claimEnabled: true } };
const relayRow = { name: "us-west", relay: true, lastSeen: NOW - 30, serving: false,
                   availability: { relay: { sni: true, tunnelHub: true } } };

test("the live nucbox row - online, no gas, eligible:false, serving:false - is not in the public list", () => {
  assert.equal(appHostVisible(nucbox, NOW), false);
  // and not for any single reason alone: fix only the gas and it is still excluded
  assert.equal(appHostVisible({ ...nucbox, serving: true }, NOW), false, "eligible:false still excludes it");
  // ...fix only the relay verdict and it is still excluded, because it is taking no work
  assert.equal(appHostVisible({ ...nucbox, eligible: true }, NOW), false, "serving:false still excludes it");
  // both, and it belongs there
  assert.equal(appHostVisible({ ...nucbox, serving: true, eligible: true }, NOW), true);
});

test("a box's own word never overrides the relay's serving verdict", () => {
  const boasting = { ...nucbox, eligible: true, serving: false,
                     availability: { ...nucbox.availability, claimEnabled: true } };
  assert.equal(appHostVisible(boasting, NOW), false,
               "availability.claimEnabled is the BOX talking about itself; serving is the relay's answer");
});

test("a serving, eligible host is shown", () => {
  assert.equal(appHostVisible(selling, NOW), true);
});

test("relay-only rows are never app hosts", () => {
  assert.equal(appHostVisible(relayRow, NOW), false);
  assert.equal(appHostVisible({ ...relayRow, serving: true, eligible: true }, NOW), false,
               "relay:true is decided before anything else: it sells no compute at all");
});

test("unknown and unconfirmed are not yes", () => {
  assert.equal(appHostVisible({ name: "old", lastSeen: NOW, availability: { teeCpu: "amd-sev-snp" } }, NOW), false,
               "no serving verdict at all: a missing answer is not a yes");
  assert.equal(appHostVisible({ name: "x", serving: true, lastSeen: NOW, availability: {} }, NOW), false,
               "serving but nothing said about its CPU technology: unconfirmed eligibility");
  assert.equal(appHostVisible(null, NOW), false);
  assert.equal(appHostVisible(undefined, NOW), false);
});

test("an older relay that sends no eligible field is judged on the same evidence", () => {
  const { eligible, ...noVerdict } = { ...selling };
  assert.equal(appHostVisible({ ...noVerdict, serving: true }, NOW), true, "a confidential CPU still qualifies");
  const phone = { name: "pixel", tunnel: true, mode: "avf", serving: true, lastSeen: NOW,
                  availability: { teeCpu: "android-pvm" } };
  assert.equal(appHostVisible(phone, NOW), false, "verified evidence for a DIFFERENT contract is not this one");
});

test("stale and offline rows drop out even if they were serving when last heard", () => {
  assert.equal(appHostVisible({ ...selling, lastSeen: NOW - HOST_STALE_AFTER_SEC - 1 }, NOW), false);
  assert.equal(appHostVisible({ ...selling, lastSeen: NOW - HOST_STALE_AFTER_SEC + 1 }, NOW), true, "just inside the window is still live");
  assert.equal(appHostVisible({ ...selling, lastSeen: 0 }, NOW), true,
               "a row with no lastSeen at all is left to the relay, which already drops silent rows");
});

// The component, pinned: the predicate is only worth anything if the list actually calls it, and
// the two exceptions that caused this are gone rather than merely unreachable.
test("the fleet list keeps marketplace eligibility and separates owner-only inventory (pinned in source)", () => {
  const src = fs.readFileSync(path.join(ROOT, "site/components/fleet-list/fleet-list.js"), "utf8");
  assert.match(src, /const rows = \(this\.rows \|\| \[\]\)\.filter\(\(e\) => appHostVisible\(e\)\);/,
               "one filter, the shared rule, no local variant");
  const code = src.split("\n").filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join("\n");
  assert.doesNotMatch(code, /e\.ineligible/, "the security paragraph is not printed in the sales list");
  assert.doesNotMatch(code, /consumerNode\s*\(/, "the consumer-node exception is gone, not just unreachable");
  assert.doesNotMatch(code, /e\.relay === true/, "relay-only rows are filtered out, not rendered");
  assert.doesNotMatch(code, /availability\?\.claimEnabled|a\.claimEnabled/, "the box's own claim flag decides nothing here");
  assert.match(src, /No app hosts available right now/, "and the empty state says so plainly");
  assert.match(src, /ownerHostedDeploymentCount\(e\)/);
  assert.match(src, /fleet-owner-row/);
  assert.match(src, /Owner-only/);
});

test("every public consumer feeds the component the same unfiltered relay rows (pinned in source)", () => {
  // the three pages share one reader (js/core/fleet-read.js), which assigns the relay's rows
  const reader = fs.readFileSync(path.join(ROOT, "site/js/core/fleet-read.js"), "utf8");
  assert.match(reader, /sortFleet\(\(j && j\.enclaves\) \|\| \[\]\)/, "the reader assigns the relay's rows");
  assert.match(reader, /fl\.rows = v\.rows;/);
  assert.doesNotMatch(reader, /\.filter\(/, "the reader must not keep its own visibility rule");
  for (const page of ["site/js/pages/host.js", "site/js/pages/architecture.js", "site/js/pages/dashboard.js"]) {
    const src = fs.readFileSync(path.join(ROOT, page), "utf8");
    assert.match(src, /refreshFleetInto\(document\.querySelector\("\.[a-z]+-fleet c-fleet-list"\), Enclave\.base\)/, `${page} feeds the component through the shared reader`);
    assert.doesNotMatch(src, /\.filter\(\s*\(?e\)?\s*=>\s*e\.serving/, `${page} must not keep its own visibility rule`);
  }
});


test("owner-only inventory counts only fresh, unexpired relay-authorized deployments without granting marketplace visibility", () => {
  const id = "0x" + "a".repeat(64);
  const row = { ...nucbox, mode: "hv-node", ownerOnly: true, servesDeployments: [{ id, until: NOW + 60 }] };
  assert.equal(ownerHostedDeploymentCount(row, NOW), 1);
  assert.equal(appHostVisible(row, NOW), false);
  assert.equal(ownerHostedDeploymentCount({ ...row, servesDeployments: [...row.servesDeployments, ...row.servesDeployments] }, NOW), 1);
  for (const change of [{ ownerOnly: false }, { mode: "vbs" }, { eligible: true }, { relay: true },
    { lastSeen: 0 }, { lastSeen: NOW - HOST_STALE_AFTER_SEC - 1 }, { availability: { ok: false } },
    { servesDeployments: [] }, { servesDeployments: [{ id, until: NOW }] },
    { servesDeployments: [{ id: "bad", until: NOW + 60 }] }, { servesDeployments: [{ id }] }]) {
    assert.equal(ownerHostedDeploymentCount({ ...row, ...change }, NOW), 0, JSON.stringify(change));
  }
});


test("owner-only capacity shows the host's allocation and RAM figures without marketplace defaults", () => {
  assert.deepEqual(ownerHostCpuCapacity({ availability: { cpuShareFree: 0.73, nodeVcpus: 16, nodeRamGb: 112, ramGbFree: 83.8 } }),
    { fraction: 0.73, vcpus: 16, vcpusFree: 11.68, ramGb: 112, ramFreeGb: 83.8 });
  assert.deepEqual(ownerHostCpuCapacity({}), { fraction: null, vcpus: null, vcpusFree: null, ramGb: null, ramFreeGb: null });
  assert.equal(ownerHostCpuCapacity({ availability: { ramMbFree: 4096 } }).ramFreeGb, 4);
  assert.deepEqual(ownerHostCpuCapacity({ availability: { cpuShareFree: 0, nodeVcpus: 16, nodeRamGb: 112, ramGbFree: 0 } }),
    { fraction: 0, vcpus: 16, vcpusFree: 0, ramGb: 112, ramFreeGb: 0 });
  assert.equal(ownerHostCpuCapacity({ availability: { cpuShareFree: 3, nodeRamGb: 8, ramGbFree: 12 } }).ramFreeGb, 8);
  assert.equal(ownerHostCpuCapacity({ availability: { cpuShareFree: 3 } }).fraction, 1);
  assert.equal(ownerHostCpuCapacity({ availability: { cpuShareFree: NaN, ramGbFree: -1 } }).fraction, null);
});


test("owner-only rows appear only for the operator or a currently delegated wallet", () => {
  const operator = "0x" + "b".repeat(40), owner = "0x" + "c".repeat(40);
  const row = { ...nucbox, mode: "hv-node", ownerOnly: true, operator,
    served: [{ owner, expires: NOW + 60 }],
    servesDeployments: [{ id: "0x" + "a".repeat(64), until: NOW + 60 }] };
  for (const address of [null, undefined, "", "invalid", "0x" + "d".repeat(40), "0x" + "0".repeat(40)])
    assert.equal(ownerHostVisibleTo(row, address, NOW), false);
  assert.equal(ownerHostVisibleTo(row, operator, NOW), true);
  assert.equal(ownerHostVisibleTo(row, "0x" + "C".repeat(40), NOW), true);
  for (const expires of [NOW, NOW - 1, null, undefined, "bad"])
    assert.equal(ownerHostVisibleTo({ ...row, served: [{ owner, expires }] }, owner, NOW), false);
  assert.equal(ownerHostVisibleTo({ ...row, served: null }, owner, NOW), false);
  assert.equal(ownerHostVisibleTo({ ...row, lastSeen: NOW - HOST_STALE_AFTER_SEC - 1 }, owner, NOW), false);
  assert.equal(ownerHostVisibleTo({ ...row, servesDeployments: [] }, owner, NOW), false);
  assert.equal(ownerHostVisibleTo({ ...row, served: [], availability: { owners: [owner] } }, owner, NOW), false,
    "self-reported owners do not replace the relay's delegation list");
  assert.equal(appHostVisible({ ...row, serving: true, eligible: true }, NOW), false,
    "owner-only hosts cannot leak into the public branch");
});

// THE EXACT LIVE pVM ROW, copied from https://api.enclave.host/enclaves on 2026-10-08 (the relay then put no VM size on the
// row; the size test below adds the field the relay now sends).
const pvmRow = {"endpoint": "tunnel://pixel10-pvm-cpu", "id": "0xc6a1c08a638997e905d63b46de17896995a0c7be03b6d3f21f6a21c2db355658", "name": "pixel10-pvm-cpu", "repo": "EnclaveHost/enclave", "lastSeen": 1791468660, "tunnel": true, "mode": "avf", "publicUrl": "https://api.enclave.host/t/pixel10-pvm-cpu", "attach": "attestation", "measurement": "d2538636a5f3a67f6d50e565dba2235090c958c0bb5e7c5237791345e3a46f55", "tier": "pvm-cpu", "pvmCpu": {"runtime": "d3370878afa9d5ee064cdcd9c50572a6baa8e23de35f5f4a0c41b7ec8f80acba", "device": "", "checkedAt": 1791457316171}, "availability": {"ok": true, "role": "phone-anchor", "name": "pixel10-pvm-cpu", "phone": "Pixel 10 Pro XL", "gpu": false}, "relay": false, "serving": false, "eligible": false, "ineligible": "pVM CPU tier: CPU-only Wasm workloads on its owner's phone, not in the app serving set", "lane": "pvm-cpu"};

test("an attested, admitted pVM host is a status row: shown, never a marketplace host", () => {
  const now = pvmRow.lastSeen + 60;
  assert.equal(appHostVisible(pvmRow, now), false, "not serving, not eligible: never in the sales list");
  assert.equal(pvmHostVisible(pvmRow, now), true, "but shown as what it is");
  assert.equal(pvmHostVisible(pvmRow, pvmRow.lastSeen + HOST_STALE_AFTER_SEC + 1), false, "a stale phone drops out");
  // in the market (the relay's verdicts: eligible, serving): a marketplace row like any other host
  const market = { ...pvmRow, serving: true, eligible: true, appEvidenceRequired: true, ineligible: undefined };
  assert.equal(appHostVisible(market, now), true, "a pVM host the relay put in the market is a marketplace host");
  assert.equal(appHostVisible({ ...market, serving: false }, now), false, "not serving: not in the marketplace list");
  // only the relay's own stamps make it one: the lane and the tier from the relay's verdict, an attested AVF tunnel
  for (const over of [{ lane: undefined }, { tier: "vbs-dev" }, { mode: "snp" }, { tunnel: false }, { relay: true },
                      { availability: { ...pvmRow.availability, ok: false } }])
    assert.equal(pvmHostVisible({ ...pvmRow, ...over }, now), false, JSON.stringify(over));
});

test("a pVM host's size is its signed report's, and unknown stays unknown", () => {
  assert.deepEqual(pvmHostVm(pvmRow), { threads: null, memGb: null }, "the row as first captured carries no size");
  assert.deepEqual(pvmHostVm({ ...pvmRow, pvmCpu: { ...pvmRow.pvmCpu, vm: { threads: 8, memMib: 1994 } } }), { threads: 8, memGb: 1.9 });
  assert.deepEqual(pvmHostVm({ ...pvmRow, pvmCpu: { ...pvmRow.pvmCpu, vm: { threads: -1, memMib: "lots" } } }), { threads: null, memGb: null });
});

test("the fleet list renders pVM hosts with the same availability pool as other CPU rows, without a price (pinned in source)", () => {
  const src = fs.readFileSync(path.join(ROOT, "site/components/fleet-list/fleet-list.js"), "utf8");
  // a pVM host the relay put in the market (eligible + serving) is a marketplace row, priced like any other; only one it has
  // not is the price-less status row
  assert.match(src, /const pvmRows = \(this\.rows \|\| \[\]\)\.filter\(e => pvmHostVisible\(e\) && !appHostVisible\(e\)\);/);
  const badges = fs.readFileSync(path.join(ROOT, "site/js/core/pool-badges.js"), "utf8");
  assert.match(src, /cpuPoolBadge\(e\)/, "the market's CPU pool pill comes from the shared pool badges");
  assert.match(badges, /tc\.real && tc\.phone && e\.eligible === true && e\.appEvidenceRequired === true/, "the market's pvm cpu badge says it takes deployments");
  const block = src.slice(src.indexOf("const pvmItems = pvmRows.map"), src.indexOf("this._wireRate();"));
  assert.ok(block.length > 0);
  assert.match(block, /fleet-pvm-row/);
  assert.match(block, /Not taking deployments yet/);
  assert.match(block, /pool\(badge, Math\.floor\(cFree \* 100\), stats, null\)/, "the same pool (meter, % available, cells) as every CPU row, with no price");
  assert.match(block, /cpuComputeStat\(a, cFree,/, "and the same gflops cell (with its own source note)");
  assert.doesNotMatch(block, /perHr|enclavePriceOf/, "no rental price on a host that takes no deployments");
});
