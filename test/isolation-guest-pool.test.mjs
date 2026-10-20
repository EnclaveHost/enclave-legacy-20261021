// The per-app isolation tier's guest pool as the supervisor mirrors it (TASK 4c; isolation/m4/guestd/pool.go is the
// authority), driven through the GUEST_POOL_SELFTEST seam. What must hold:
//   - on the tier, the node a share is a fraction of is guestd's pool budget, not the control CVM: a 128 MB app still
//     needs 1%, and 1% of the unchanged posted price stays under the cap its owner set (a69dcbba: 9 µUSDC/s);
//   - what is free is the pool's room, never more than the share ledger, and 0 unless one smallest guest fits (and
//     while the pool is unheard, unconfigured or overcommitted);
//   - a claim is refused when the app's guest does not fit the pool by its RESERVATION, even when its share would;
//   - off the tier, none of it applies.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { fileURLToPath } from "node:url";
import fs from "node:fs";

const pexec = promisify(execFile);
const SUPERVISOR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "supervisor.js");
const TIER = "snp-guest-per-app";

// metal-iso0's control CVM (metal/config.iso.json: 4 CPUs, 6144 MiB) and its posted price (none set: the default 834)
async function seam(c, backend = TIER, env = {}) {
  c = { ...c, verdicts: c.verdicts?.map(v => ({ cpuMilli: 1000, ...v })) };
  const { stdout } = await pexec(process.execPath, [SUPERVISOR], {
    env: { ...process.env, SECRET: "test-secret", ISOLATION_BACKEND: backend, GUEST_POOL_SELFTEST: JSON.stringify(c), ISOLATION_SELFTEST: "",
           NODE_RAM_GB: "6", NODE_VCPUS: "4", NODE_GFLOPS: "250", SELL_CPU_PRICE6: "", SELL_GPU_PRICE6: "",
           INSTANCE_SELFTEST: "", POOL_SELFTEST: "", SWEEP_SELFTEST: "", REACH_SELFTEST: "", ACME_SELFTEST: "",
           CFG_EDIT_SELFTEST: "", ADDRESS_BOOK_ADDRESS: "", REGISTRY_ENABLED: "", CLAIM_ENABLED: "",
           ACME_EAB_KID: "", ACME_EAB_HMAC: "", APP_CERT_DOMAIN: "", DNS_API: "", ...env } });
  const lines = stdout.trim().split("\n").filter(Boolean);
  return JSON.parse(lines[lines.length - 1]);
}

const perGuest = { floorMiB: 1024, runtimeMiB: 384, unitOverheadMiB: 768 };
const pool = (budget, allocated = { memMiB: 0, cpuPct: 0 }, extra = {}) => {
  const free = budget ? { memMiB: Math.max(0, budget.memMiB - allocated.memMiB), cpuPct: Math.max(0, budget.cpuPct - allocated.cpuPct) }
                      : { memMiB: 0, cpuPct: 0 };
  return { budget, allocated, free, guests: 0, overcommitted: false, perGuest, ...extra };
};
const B = { memMiB: 32768, cpuPct: 800 };          // a 32 GiB, 8-core guest pool
const small = { memMb: 128 };                      // Steven's hello-world-sized app

test("on the tier a share is a fraction of the guest pool: a 128 MB app still needs 1%, and 1% of the posted price stays under its cap", async () => {
  const cvm = await seam({ shares: [small] });                   // guestd not heard yet: the CVM's own numbers
  const tier = await seam({ pool: pool(B), shares: [small] });
  assert.equal(cvm.node.pool, false);
  assert.equal(cvm.shares[0].cpuShare, 0.03, "against the 6 GiB control CVM a 128 MB app 'needs 3%' - the wrong pool");
  assert.deepEqual({ ...tier.node }, { vcpus: 8, ramGb: 32, gflops: 8 * (250 / 4), gflopsFloor: 8 * 1000 / 16, pool: true });
  assert.equal(tier.shares[0].cpuShare, 0.01, "against the guest pool it needs the 1% floor");
  // the host's price is unchanged by the pool, and what 1% of it costs a deployment is under a69dcbba's cap
  assert.equal(tier.sellCpuPrice6, 834);
  assert.equal(tier.sellCpuPrice6, cvm.sellCpuPrice6);
  const onePctRate6 = (10 / 1000) * tier.sellCpuPrice6;          // cpuMilli 10 of the whole-node price, µUSDC/s
  assert.ok(onePctRate6 <= 9, `1% costs ${onePctRate6} µUSDC/s, over a69dcbba's 9 µUSDC/s cap`);
  // app minimums are not deleted: a big app's declared memory still sets its floor against the pool
  const big = await seam({ pool: pool(B), shares: [{ memMb: 8192 }] });
  assert.equal(big.shares[0].cpuShare, 0.25);
});

test("a version's guest reserves its unit's ceilings, as guestd admits it", async () => {
  const r = await seam({ pool: pool(B), reservations: [{ memMb: 128 }, { memMb: 4096 }, {}] });
  assert.deepEqual(r.reservations, [
    { memMiB: 1024 + 768, cpuPct: 100 },          // the floor, plus the unit's QEMU allowance (a MemoryMax cap)
    { memMiB: 4096 + 384 + 768, cpuPct: 100 },
    { memMiB: 1024 + 768, cpuPct: 100 },          // no memMb: enclave-isolation-policy/1's floor of 128
  ]);
});

test("what is free is the pool's room, never more than the share ledger, and nothing unless a smallest guest fits", async () => {
  const half = await seam({ pool: pool(B, { memMiB: 16384, cpuPct: 400 }) });
  assert.equal(half.maxFreeCpu, 0.5);
  const ledger = await seam({ pool: pool(B, { memMiB: 16384, cpuPct: 400 }), shareFree: 0.2 });
  assert.equal(ledger.maxFreeCpu, 0.2, "the share ledger still caps it");
  // 1500 MiB free is 4.6% of the pool - but no guest (1792 MiB at the least) fits in it
  const sliver = await seam({ pool: pool(B, { memMiB: 32768 - 1500, cpuPct: 100 }) });
  assert.equal(sliver.maxFreeCpu, 0, "a pool too full for one more guest advertises no free share");
  for (const [what, p] of [["unheard", null], ["unconfigured", pool(null)],
                           ["overcommitted", pool(B, { memMiB: 40000, cpuPct: 900 }, { overcommitted: true })],
                           ["malformed", { budget: B }]]) {
    const r = await seam({ pool: p });
    assert.equal(r.maxFreeCpu, 0, `${what}: nothing is free`);
  }
  // guestd reports free 0 when overcommitted; the flag alone must still stop the offer, whatever `free` says
  const inconsistent = await seam({ pool: { ...pool(B), overcommitted: true } });
  assert.equal(inconsistent.maxFreeCpu, 0, "an overcommitted pool is never advertised");
  const unheard = await seam({});
  assert.deepEqual(unheard.guestPool, { heard: false });
  assert.match(half.guestPool.basis, /not observed use/);
  assert.match(half.guestPool.pricing, /share/);
});

const MGR = (p) => ({ backend: TIER, supports: { gpu: false, secrets: false, egress: false, config: false, ports: false }, pool: p });
const verdict = (manager, policy = { cpuPercent: 100, memMiB: 128, vcpus: 1 }) => ({ require: TIER, manager, gpuMilli: 0, config: "",
  appConfigCid: "", hasSecrets: false, firewall: [], volumes: [], isPublic: true, waf: null, policy });

test("a claim is refused when the app's guest does not fit the pool by its reservation, even though its share would", async () => {
  const tight = pool(B, { memMiB: 32768 - 1500, cpuPct: 0 });     // 1500 MiB and every core free
  const r = await seam({ pool: tight, shares: [small], verdicts: [
    verdict(MGR(pool(B))),                                         // room: claimable
    verdict(MGR(tight)),                                           // the share (1%) fits the ledger; the guest (1792 MiB) does not
    verdict(MGR(pool(B)), { cpuPercent: 100, memMiB: 40000, vcpus: 1 }),   // bigger than the whole pool
    verdict(MGR(pool(B, { memMiB: 0, cpuPct: 800 }))),             // memory free, every core reserved
    verdict(MGR(null)),                                            // an older guestd: no pool
    verdict(MGR(pool(null))),                                      // no budget configured
    verdict(MGR(pool(B, { memMiB: 40000, cpuPct: 900 }, { overcommitted: true }))),
    verdict(MGR(pool(B)), null),                                   // no policy to size by
  ] });
  assert.equal(r.shares[0].cpuShare, 0.01);
  assert.equal(r.verdicts[0], null);
  assert.match(r.verdicts[1], /cannot fit this app's guest: it reserves 1792 MiB \/ 100% CPU .*1500 MiB/);
  assert.match(r.verdicts[2], /requires 40000 MiB.*cannot fit this host/);
  assert.match(r.verdicts[3], /cannot fit this app's guest/);
  assert.match(r.verdicts[4], /no readable guest pool/);
  assert.match(r.verdicts[5], /no readable guest pool/);
  assert.match(r.verdicts[6], /overcommitted/);
  assert.match(r.verdicts[7], /no valid RAM requirement/);
});

// enclave-99's review of 829ea21b: after the control CVM's update reboot (the release that ships this change is one),
// every own lease is re-discovered and RESUMED through the claim gate, while guestd kept the guests - their rooms are
// already allocated. Judged against free alone, a pool sized to its guests refused every resume and darked them.
test("a resume of a guest guestd already holds is judged with the room that guest holds; a new claim on the same full pool is refused", async () => {
  const canary = { memMiB: 1792, cpuPct: 100 };
  const full = pool({ memMiB: 3 * 1792, cpuPct: 300 }, { memMiB: 3 * 1792, cpuPct: 300 }, { guests: 3 });   // exactly its budget
  const heldBy = (name, status = "running", reserved = canary) => ({ id: "gd" + name.slice(2, 10), name, status, ...(reserved ? { reserved } : {}) });
  const names = ["0x" + "4e".repeat(32), "0x" + "39".repeat(32), "0x" + "0d".repeat(32)];
  const r = await seam({ verdicts: [
    ...names.map((n) => ({ ...verdict(MGR(full)), held: heldBy(n) })),                 // the three canaries resume: none refused
    verdict(MGR(full)),                                                                  // a NEW claim on that pool: refused
    { ...verdict(MGR(full)), held: heldBy(names[0], "failed", null) },                   // guestd lost it (failed, holds nothing): a new guest
    { ...verdict(MGR(full), { cpuPercent: 100, memMiB: 4096, vcpus: 1 }), held: heldBy(names[0]) },  // a bigger version than the room it holds
    { ...verdict(MGR(pool({ memMiB: 8192, cpuPct: 300 }, { memMiB: 1792, cpuPct: 100 })), { cpuPercent: 100, memMiB: 4096, vcpus: 1 }),
      held: heldBy(names[0]) },                                                          // ...which fits once its own room is counted
    { ...verdict(MGR(pool({ memMiB: 3584, cpuPct: 200 }, { memMiB: 5376, cpuPct: 300 }, { overcommitted: true }))), held: heldBy(names[1]) },
    { ...verdict(MGR(null)), held: heldBy(names[2], "running", null) },                  // an older guestd (no pool, no `reserved`): adopt as before
    verdict(MGR(null)),                                                                  // ...but a new guest there is not placed
    { ...verdict(MGR(null)), held: heldBy(names[2], "failed", null) },                   // a FAILED guest there is not adopted
    { ...verdict(MGR(full)), held: heldBy(names[0], "failed") },                         // failed, its unit still stopping (reserved
                                                                                         // still listed): not a guest to resume into
  ] });
  assert.deepEqual(r.verdicts.slice(0, 3), [null, null, null], "every canary's resume must pass");
  assert.match(r.verdicts[3], /cannot fit this app's guest: it reserves 1792 MiB .* 0 MiB \/ 0% is free/);
  assert.match(r.verdicts[4], /cannot fit this app's guest/);
  assert.match(r.verdicts[5], /cannot fit .* 1792 MiB \/ 100% is free counting the room its current guest holds/);
  assert.equal(r.verdicts[6], null);
  assert.equal(r.verdicts[7], null, "an overcommitted pool still lets a running guest resume in its own room");
  assert.match(r.verdicts[8], /no readable guest pool/, "cannot adopt without an enforceable share budget");
  assert.match(r.verdicts[9], /no readable guest pool/);
  assert.match(r.verdicts[10], /no readable guest pool/);
  assert.match(r.verdicts[11], /cannot fit this app's guest: it reserves 1792 MiB .* 0 MiB \/ 0% is free$/);
});

test("an answer without a readable pool clears the mirror: nothing is offered or claimed, and the node keeps the budget last heard", async () => {
  const r = await seam({ pools: [pool(B), { budget: B }], shares: [small], verdicts: [verdict(MGR({ budget: B }))] });
  assert.equal(r.maxFreeCpu, 0);
  assert.deepEqual(r.guestPool, { heard: false });
  assert.match(r.verdicts[0], /no readable guest pool/);
  // sizing does not fall back to the control CVM (that would triple floors, and a resize could evict: enclave-5d)
  assert.equal(r.node.pool, true);
  assert.equal(r.node.ramGb, 32);
  assert.equal(r.shares[0].cpuShare, 0.01);
  const back = await seam({ pools: [pool(B), { budget: B }, pool(B, { memMiB: 16384, cpuPct: 400 })] });
  assert.equal(back.maxFreeCpu, 0.5, "the next readable answer restores the offer");
});

// a69dcbba (128 MB, cap 9 µUSDC/s) is claimable only while ceil(128 / B) is the 1% floor: B >= 12800 MiB
test("the budget floor for a 1% app: 12800 MiB is 1%, 12799 MiB is 2%, over a69dcbba's cap", async () => {
  const at = await seam({ pool: pool({ memMiB: 12800, cpuPct: 800 }), shares: [small] });
  const under = await seam({ pool: pool({ memMiB: 12799, cpuPct: 800 }), shares: [small] });
  assert.equal(at.shares[0].cpuShare, 0.01);
  assert.equal(under.shares[0].cpuShare, 0.02);
  assert.ok((10 / 1000) * at.sellCpuPrice6 <= 9);
  assert.ok((20 / 1000) * under.sellCpuPrice6 > 9, "at 2% the cap refuses it");
});

// considerClaim is not drivable through a seam; its call of the gate is pinned in source, as the repo pins such wiring
test("the claim path judges the pool with the version's policy and, on a resume, the guest guestd holds (pinned in source)", () => {
  const src = fs.readFileSync(SUPERVISOR, "utf8");
  const call = src.slice(src.indexOf("const isoWhy = isolationClaimVerdict({"), src.indexOf("if (isoWhy) return isoWhy;"));
  assert.match(call, /policy: isolationPolicyFor\(g\.min\)/);
  assert.match(src, /const resumeHeld = resume && ISOLATION_BACKEND \? await isolationHeldGuest\(d\.id\) : null;/);
  assert.match(src, /const isoHeld = resumeHeld;/);
  assert.match(call, /held: isoHeld, heldSameRecord,/);
  assert.match(src, /const heldSameRecord = isolationHeldSameRecord\(isoHeld, g, firewall, isoMgr && isoMgr\.catalog && isoMgr\.catalog\.runtimeId,[\s\S]{0,160}isolatedInference\(d\.gpuMilli,neededVolumes\(d,g\)\)/,
    "an adoption is the SAME record, derived as the spawn derives it (the parsed firewall)");
  // ONE derivation for the spawn and the resume's test (enclave-e3): spawnContainer builds its record through it
  const spawn = src.slice(src.indexOf("async function spawnContainer("), src.indexOf("let r = await vmReq(\"POST\", \"/vms\", body, SPAWN_TIMEOUT_MS);"));
  assert.match(spawn, /const derive = isolationSpawnDerivation\(\{ catalogRef, wasmRef: image && image\.reference, versionMemMb,/);
  const sameRecord = src.slice(src.indexOf("function isolationHeldSameRecord("), src.indexOf("async function managerPrefetchBody("));
  assert.match(sameRecord, /isolationSpawnDerivation\(\{ catalogRef: g\.ref, wasmRef: g\.wasmRef,/);
  assert.match(src, /const resume = leaseLive && d\.runner === _enclaveId;/, "a resume is this runner's own live lease");
});

// guestd's live host floor (pool.go hostRefusal), mirrored: no claim or advertised share guestd's floor would refuse
test("the host's live memory floor gates claims and caps the advertised share; without it nothing changes", async () => {
  const host = (avail, pendingMiB = 0, floorMiB = 16384) => ({ floorMiB, memAvailableMiB: avail, pendingMiB });
  const r = await seam({ pool: { ...pool(B), host: host(16384 + 20500) }, verdicts: [
    verdict(MGR({ ...pool(B), host: host(16384 + 1792) })),        // exactly room for one guest above the floor: claimable
    verdict(MGR({ ...pool(B), host: host(16384 + 1791) })),        // one MiB short: refused
    verdict(MGR({ ...pool(B), host: host(null) })),                // unreadable on guestd's side: refused
    verdict(MGR({ ...pool(B), host: { floorMiB: 0, memAvailableMiB: null } })),   // floor off: no host check
    verdict(MGR({ ...pool(B), host: host(16384 + 1792, 1792) })),  // enclave-99 #1: room for one, but one is still STARTING
  ] });
  assert.equal(r.verdicts[0], null);
  assert.match(r.verdicts[1], /too low on memory: .*under guestd's 16384 MiB floor/);
  assert.match(r.verdicts[2], /available memory is unknown/);
  assert.equal(r.verdicts[3], null);
  assert.match(r.verdicts[4], /too low on memory/, "room for one, but one is still starting");
  // enclave-e3: the reason is returned by the public claim-hint and re-logged by the sweep on every change, so it carries
  // no live number (MemAvailable would be reconstructable from "N MiB under ... counting P MiB"); the floor is config
  for (const v of [r.verdicts[1], r.verdicts[4]]) assert.deepEqual(v.match(/\d+/g), ["16384"], v);
  // a pendingMiB that is not a number makes the host UNKNOWN, never "nothing pending"
  const odd = await seam({ pool: { ...pool(B), host: { floorMiB: 16384, memAvailableMiB: 16384 + 20500, pendingMiB: "lots" } },
    verdicts: [verdict(MGR({ ...pool(B), host: { floorMiB: 16384, memAvailableMiB: 16384 + 20500 } }))] });
  assert.match(odd.verdicts[0], /available memory is unknown/);
  assert.equal(odd.maxFreeCpu, 0);
  // only JSON NUMBERS count: Number() would read these as 0 (nothing pending, or 0 available) or "0x10" as 16 (enclave-e3)
  for (const bad of ["", false, [], " ", "0x10", "16384", true, {}]) {
    const x = await seam({ pool: { ...pool(B), host: { floorMiB: 16384, memAvailableMiB: 16384 + 20500, pendingMiB: bad } },
      verdicts: [verdict(MGR({ ...pool(B), host: { floorMiB: 16384, memAvailableMiB: bad, pendingMiB: 0 } }))] });
    assert.equal(x.maxFreeCpu, 0, `pendingMiB ${JSON.stringify(bad)}: the host is unknown`);
    assert.match(x.verdicts[0], /available memory is unknown/, `memAvailableMiB ${JSON.stringify(bad)}`);
  }
  // a floor that is not a number is no floor this supervisor can mirror: an older guestd's shape, nothing changes
  assert.equal((await seam({ pool: { ...pool(B), host: { floorMiB: "16384", memAvailableMiB: 1, pendingMiB: 0 } } })).maxFreeCpu, 1);
  // 20500 MiB above the floor caps the pool's own 1.0 at 20500/32768 = 0.6256, quantized DOWN to 0.62 (enclave-99 #4)
  assert.equal(r.maxFreeCpu, 0.62);
  assert.deepEqual(r.guestPool.host, { floorMiB: 16384, admitsSmallestGuest: true }, "the report carries the verdict, not MemAvailable");
  assert.ok(!JSON.stringify(r.guestPool).includes(String(16384 + 20500)), "the live MemAvailable is not published");
  for (const [what, h] of [["below one guest", host(16384 + 1000)], ["unreadable", host(null)], ["starting guests take the room", host(16384 + 3000, 2000)]]) {
    const x = await seam({ pool: { ...pool(B), host: h } });
    assert.equal(x.maxFreeCpu, 0, `${what}: nothing is advertised`);
    assert.equal(x.guestPool.host.admitsSmallestGuest, false, what);
  }
  assert.equal((await seam({ pool: pool(B) })).maxFreeCpu, 1, "an older guestd (no host block) is unchanged");
});

// enclave-99 #2: on a RESUME, adopting the running guest of the SAME record takes no new memory; a held guest REPLACED
// (another record: the spawn deletes it first) frees only its RAM, not the 768 allowance, so the host check applies.
test("a resume adopting the same record skips the host check; a replacement is credited only its guest's RAM", async () => {
  const held = { name: "0x" + "4e".repeat(32), status: "running", reserved: { memMiB: 1792, cpuPct: 100 } };
  const near = { ...pool(B), host: { floorMiB: 16384, memAvailableMiB: 16384 + 700, pendingMiB: 0 } };   // ~700 MiB above the floor
  const r = await seam({ verdicts: [
    { ...verdict(MGR(near)), held, heldSameRecord: true },   // adoption: no new memory, claimable
    { ...verdict(MGR(near)), held, heldSameRecord: false },  // replacement: 700 - 1792 + (1792 - 768) = -68 -> refused
    { ...verdict(MGR({ ...near, host: { ...near.host, memAvailableMiB: 16384 + 768 } })), held, heldSameRecord: false },  // exactly 0 over: claimable
  ] });
  assert.equal(r.verdicts[0], null, "adopting the same record's running guest must pass (the resume path)");
  assert.match(r.verdicts[1], /too low on memory/, "700 - 1792 + 1024 = -68");
  assert.equal(r.verdicts[2], null);
  // a STARTING held guest is wholly in guestd's pending: deleting it returns all of its reservation (enclave-e3's nit)
  const starting = { ...held, status: "starting" };
  const edge = (over) => MGR({ ...near, host: { floorMiB: 16384, memAvailableMiB: 16384 + over, pendingMiB: 1792 } });
  const s2 = await seam({ verdicts: [
    { ...verdict(edge(0)), held: starting, heldSameRecord: false },    // 0 - 1792 - 1792 + 1792 = -1792: refused
    { ...verdict(edge(1792)), held: starting, heldSameRecord: false }, // 1792 - 1792 - 1792 + 1792 = 0: claimable
    { ...verdict(edge(1791)), held: starting, heldSameRecord: false }, // one MiB short: refused
  ] });
  assert.match(s2.verdicts[0], /too low on memory/);
  assert.equal(s2.verdicts[1], null, "a starting guest's whole reservation is credited");
  assert.match(s2.verdicts[2], /too low on memory/);
});

// enclave-e3: the resume's same-record test is a PURE helper, derived exactly as the spawn derives its record (the
// PARSED firewall: rec.firewall), and false whenever anything is missing or underivable (a replacement: conservative)
test("a held guest is the same record only when the spawn would send exactly that record", async () => {
  const RT = "ab".repeat(32);
  const g = { ref: "catalog://0x" + "11".repeat(32) + "/3", wasmRef: "ipfs://bafyexample", min: { memMb: 128 }, ports: "http" };
  const { recordOf } = await seam({ recordOf: { g, runtimeId: RT, ports: [] } });              // the spawn's own derivation (isolationSpawnDerivation)
  const { recordOf: rec8080 } = await seam({ recordOf: { g, runtimeId: RT, ports: ["http:8080"] } });
  const held = { name: "0x" + "4e".repeat(32), status: "running", recordSha256: recordOf };
  const r = await seam({ sameRecord: [
    { held, g, firewall: [], runtimeId: RT },                                        // 0 the same record: true
    { held: { ...held, recordSha256: rec8080 }, g: { ...g, ports: "http:8080" }, firewall: ["http:8080"], runtimeId: RT }, // 1 a declared port: true
    { held, g, firewall: ["http:8080"], runtimeId: RT },                             // 2 another port: another record
    { held, g: { ...g, min: { memMb: 256 } }, firewall: [], runtimeId: RT },          // 3 another policy
    { held, g, firewall: [], runtimeId: "cd".repeat(32) },                            // 4 another runtime
    { held: { ...held, recordSha256: undefined }, g, firewall: [], runtimeId: RT },   // 5 no recordSha256
    { held: { ...held, recordSha256: "XYZ" }, g, firewall: [], runtimeId: RT },       // 6 not a digest
    { held, g, firewall: [], runtimeId: null },                                       // 7 no manager / runtime
    { held, g: { ...g, ref: "not-a-catalog-ref" }, firewall: [], runtimeId: RT },     // 8 the derivation throws
    { held, g, firewall: ["tcp:5000"], runtimeId: RT },                               // 9 a port the tier refuses (throws)
    { held: null, g, firewall: [], runtimeId: RT },                                   // 10 nothing held
  ] });
  assert.deepEqual(r.sameRecord, [true, true, false, false, false, false, false, false, false, false, false]);
  // the bare "http" marker: parseFirewall drops it (firewall []), so the spawn's record has no port; the RAW g.ports
  // path the claim side used before threw on it and judged every such resume a replacement
  assert.equal(r.sameRecord[0], true);
});

test("off the tier nothing of the pool applies: the node is the NODE_* constants and free is the share ledger", async () => {
  const r = await seam({ pool: pool(B, { memMiB: 32000, cpuPct: 790 }), shares: [small], shareFree: 0.7 }, "");
  assert.equal(r.node.pool, false);
  assert.equal(r.node.ramGb, 6);
  assert.equal(r.maxFreeCpu, 0.7);
  assert.equal(r.shares[0].cpuShare, 0.03);
});


test("isolated claims check pricing shares separately from exact guest reservations", async () => {
  const c = {pool: pool(B, B), shareFree: 0.4,
    claimHeld: [null, {status: "running"}, {status: "starting"}, {status: "failed"}]};
  const r = await seam(c);
  assert.equal(r.maxFreeCpu, 0, "full pool remains unavailable to new claims");
  assert.deepEqual(r.claimFreeCpu, [0.4, 0.4, 0.4, 0.4], "share ledger caps the preliminary check; policy admission judges actual room");
  const off = await seam(c, "");
  assert.deepEqual(off.claimFreeCpu, [0.4, 0.4, 0.4, 0.4]);
});

test("large pricing share does not block a small reservation that fits; oversized guests still fail", async () => {
  const p = pool({memMiB: 81920, cpuPct: 2400}, {memMiB: 68608, cpuPct: 2000});
  const r = await seam({pool:p,shareFree:0.88,claimHeld:[null],verdicts:[
    verdict(MGR(p),{cpuPercent:100,memMiB:3456,vcpus:1}),
    verdict(MGR(p),{cpuPercent:500,memMiB:3456,vcpus:5})]});
  assert.ok(r.maxFreeCpu < 0.35);
  assert.ok(r.claimFreeCpu[0] >= 0.35);
  assert.equal(r.verdicts[0], null);
  assert.match(r.verdicts[1], /cannot fit/);
});
