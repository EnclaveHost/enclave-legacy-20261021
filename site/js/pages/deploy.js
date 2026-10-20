import { catalogAdmissionRefusal } from "../core/catalog-policy.js";
/* ============================================================
   Deploy flow - the on-chain create+fund+watch sequence behind
   the store's quick-deploy modal (apps.js imports it lazily) and
   the dashboard's retry/resume paths (<c-deployments>). A real
   deploy soft-navigates to the dashboard and streams its
   narrative into its own run (js/core/runlog - <c-deployments>'
   live strips and row Output panels follow it; deploys are
   concurrent, so fleets stream side by side).
   The deploy CONSOLE that used to live in front of this flow is
   gone: an app deploys from its card with one decision (the
   amount), and everything else - config, model volumes,
   protection, relay - is a tab on the deployment's dashboard row.
   ============================================================ */
import { appLabel, appEndpoint } from "../../components/deployments/deployments.js";
import { runlog } from "../core/runlog.js";
import { payForRuntime } from "../core/fund.js";
import { navigate } from "../boot.js";
import { esc, short, wait, fmtDur, showToast, statusCls } from "../core/util.js";
import { APP_DOMAIN, DEPLOYMENTS_ADDRESS, ACCOUNTS_ENABLED } from "../core/config.js";
import { Enclave, EnclaveError } from "../core/api.js";
import { vaultOp } from "../core/vault.js";
import { freeEnclavesFor } from "../core/pricing.js";
import { encCall, DEP_SEL, DEP_CREATED_TOPIC, depGet, depRate6, depSchemaRev, depMaxGpuMilli, waitReceipt, catVersionFee, catGetApp, catGetVersion } from "../core/chain.js";
import { connectWallet, refreshWallet, ensureBaseChain, sendTx } from "../core/wallet.js";
import { parseCatalogRef, publisherOfRef } from "../core/catalog.js";

/* the My Apps panel lives on the dashboard; resolve it at call time
   (present after the deploy flow navigates there, absent otherwise) */
const depsPanel = () => document.querySelector("c-deployments");

// the create() options envelope for a spec ({waf, config, gpuOptional}) - ""
// when none rides. `gpu.optional` only ever appears on a deployment that
// bought GPU share: without a slice there is no card requirement to soften,
// and every runner refuses the flag on a 0% GPU deployment rather than let an
// owner believe their app is preferring hardware it can never be given.
function envelopeOf(spec){
  const parts = { ...(spec.waf ? { waf: spec.waf } : {}), ...(spec.config ? { config: spec.config } : {}),
                  ...(spec.gpuOptional && Number(spec.gpuPct || 0) > 0 ? { gpu: { optional: true } } : {}) };
  return Object.keys(parts).length ? JSON.stringify(parts) : "";
}

/* logical "open ports" csv -> the create() call's portsCsv + appPort */
function portsSpec(raw){
  const fwCsv = String(raw || "").split(",").map(x => x.trim().toLowerCase()).filter(Boolean);
  const portsCsv = (fwCsv.length && !(fwCsv.length === 1 && fwCsv[0] === "http")) ? fwCsv.join(",") : "";
  const httpEntry = fwCsv.find(x => /^http:\d+$/.test(x));
  return { portsCsv, appPort: httpEntry ? parseInt(httpEntry.split(":")[1], 10) : 8080 };
}

/* The on-chain deploy flow behind the store's quick-deploy modal (apps.js
   imports this): soft-navigate to the dashboard, then create -> fund ->
   claim-hint -> watch, narrating into ITS OWN run (concurrent-safe: every
   call gets its own runlog writer, so a fleet of deploys stream side by
   side). Resolves once funding lands - the claim/status watch continues
   detached, freeing the caller for the next deploy.
   spec: { reference (catalog://<appId>/<idx>), gpuMilli, cpuMilli,
   ports (csv, informational - the version's record is what enclaves apply),
   isPublic, fundUsd, asset, waf, config }. Config/volumes ride the version's
   on-chain record (a config CID stays refused); the one deploy-time field is
   the options ENVELOPE riding create()'s last string: spec.waf (per-IP rate
   limit + request filter, interpreted by the enclave's proxy, never shown to
   the app) and spec.config (a per-deployment app-config override - it
   replaces the version's config as THIS deployment's ENCLAVE_CONFIG; callers
   must gate it on the fleet aggregate's configOverride flag). The dashboard's
   Config / Models / Protect / Network tabs rewrite the same envelope later. */
export async function deployOnChain(spec){
  // the on-chain share-cap gate runs BEFORE the dashboard redirect: a deploy
  // create() would refuse must be refused where the user is standing (the
  // store's quick-deploy modal) - not narrated into a run log they were just
  // navigated to. The caller re-checks earlier for richer UI; this is the
  // shared backstop for the races it can't see.
  const catalogRef = parseCatalogRef(spec.reference);
  if (!catalogRef) return showToast("Deploy refused: a catalog version is required.");
  try {
    const [app, version] = await Promise.all([catGetApp(catalogRef.appId), catGetVersion(catalogRef.appId,catalogRef.index)]);
    const refusal = catalogAdmissionRefusal(app,version,{forPrivate:spec.isPublic===false});
    if (refusal) return showToast("Deploy refused: " + refusal);
  } catch { return showToast("Deploy refused: could not verify current catalog moderation. Please retry."); }
  const capMsg = await gpuCapRefusal(spec.gpuMilli);
  if (capMsg) return showToast("Deploy refused: " + capMsg);
  // The version's publisher fee is snapshotted INTO the record by create():
  // resolve it fresh from the catalog right before the signature (fail
  // closed - an under-declared fee makes a record no runner will ever
  // claim, its funding unrecoverable, same as under-provisioned shares).
  let fee6 = 0n, feeTo = null;
  const cref = parseCatalogRef(spec.reference);
  if (cref){
    try { fee6 = await catVersionFee(cref.appId, cref.index); }
    catch(e){ return showToast("Deploy refused: couldn't read the app's publisher fee from the catalog - try again shortly."); }
    if (fee6 > 0n){
      feeTo = publisherOfRef(spec.reference);
      if (!feeTo) return showToast("Deploy refused: the app's publisher wallet isn't loaded yet - open the Apps page and retry.");
      if ((await depSchemaRev()) < 4)
        return showToast("Deploy refused: this app charges a publisher fee, which the live deployments ledger predates.");
    }
  }
  const fund = spec.fundUsd;
  const { portsCsv, appPort } = portsSpec(spec.ports);
  const asset = spec.asset || "USDC";
  let w = null, detached = false;
  try {
    // the run log lives on the dashboard: get there BEFORE the first wallet
    // step so the whole narrative streams where the user is looking (the
    // document never unloads - this async flow survives the soft navigation)
    await navigate("dashboard");
    w = runlog.startRun();
    // account-credit path: no connected wallet but a signed-in passkey/card
    // account - ONE passkey tap signs a vault op that creates + funds the
    // deployment from credit (the customer's vault owns the record on-chain).
    // Same run, same narrative, same claim watch as a wallet deploy.
    if (!Enclave.address && ACCOUNTS_ENABLED && Enclave.accountAuthed()){
      if (spec.waf){ w.line("warn", "[!] WAF options need a wallet deploy for now - credit deploys don't carry an options envelope yet"); return; }
      if (spec.config){ w.line("warn", "[!] a config override needs a wallet deploy for now - credit deploys don't carry an options envelope yet"); return; }
      if (fee6 > 0n){ w.line("warn", "[!] this app charges a publisher fee, which credit deploys don't support yet - deploy it from a wallet instead"); return; }
      if (!(fund > 0)){ w.line("warn", "[!] credit deploys need a budget (the vault funds the record as it creates it) - a $0 create needs a wallet deploy"); return; }
      try {
        adoptFreePct(await Enclave.getAvailability());
        if (queuedVerdict(spec.gpuMilli / 10, spec.cpuMilli / 10))
          w.line("warn", "[!] the fleet is full for this size right now - after funding, the deployment waits as Queued and starts automatically the moment capacity frees up (queued time is never billed; the balance only burns while the app runs)");
      } catch(e){}
      let crate6 = 0n;
      try { crate6 = await Promise.race([depRate6(spec.gpuMilli, spec.cpuMilli), wait(6000).then(() => 0n)]); } catch(e){}
      if (crate6 > 0n){
        const rate = Number(crate6) / 1e6;
        w.line("info", "    $" + fund + " of credit ≈ " + fmtDur(fund / rate) + " of runtime at $" + (rate * 3600).toFixed(2) + "/hr");
      }
      w.line("p", "$ EnclaveCreditVault.deployAndFund(…)  (passkey · one tap · your credit funds it)");
      w.line("info", "[*] confirm with your passkey…");
      let out;
      try {
        out = await vaultOp("deploy", {
          spec: { appRef: spec.reference, gpuMilli: spec.gpuMilli, cpuMilli: spec.cpuMilli,
                  appPort, ports: portsCsv, isPublic: !!spec.isPublic },
          fundUsd: fund,
          // The rate cap rides in the create() the passkey signs, and the relay
          // fills it (its quote IS the ceiling). Bound what we will sign by what
          // we just quoted above - doubled, because the relay quotes from a
          // 10-minute cached fleet price and this page from a live one, so honest
          // drift must not refuse a deploy. Omitted when the quote didn't land in
          // time: an unbounded check is one we cannot honestly make.
          ...(crate6 > 0n ? { maxRate6Max: String(crate6 * 2n) } : {}),
        });
      } catch(e){ w.line("warn", "[x] " + (e.message || String(e))); return; }
      const cid = out.deploymentId;
      w.setId(cid);
      w.line("ok", "[✓] created + funded " + cid + " from your credit");
      watchClaimAndRun(cid, null, w, spec.targetName || "")
        .catch(e => w.line("warn", "[x] " + (e.message || String(e))))
        .finally(() => w.end());
      detached = true;
      return;
    }
    // NO SIWE sign-in here: the create tx and the funding signature ARE the
    // proof of key ownership - a connected wallet is all the flow needs
    if (!Enclave.provider){
      w.line("info", "[*] connecting wallet…");
      await connectWallet();
      w.line("ok", "[✓] wallet " + short(Enclave.address));
    }
    w.line("dimln", "    if nothing happens, check your wallet - a popup may be waiting (or queued behind an old one; open the wallet and clear pending requests)");
    await ensureBaseChain();

    // capacity heads-up BEFORE the first signature (fresh read: the store's
    // quick-deploy modal reaches here without a capacity poll of its own). Not
    // a gate - the create is still right - but nobody should sign expecting an
    // instant boot when the fleet is full for this size.
    try {
      adoptFreePct(await Enclave.getAvailability());
      if (queuedVerdict(spec.gpuMilli / 10, spec.cpuMilli / 10))
        w.line("warn", "[!] the fleet is full for this size right now - after funding, the deployment waits as Queued and starts automatically the moment capacity frees up (queued time is never billed; the balance only burns while the app runs)");
    } catch(e){}

    // rate estimate straight from the contract (same ceil math as create) -
    // best-effort with a hard cap so a slow RPC can never stall the deploy
    let rate6 = 0n;
    try { rate6 = await Promise.race([depRate6(spec.gpuMilli, spec.cpuMilli), wait(6000).then(() => 0n)]); } catch(e){}
    // Does the deployer run their own enclave? A box that has declared THIS
    // wallet as its payout wallet hosts this deployment for nothing (ledger
    // rev 12), so the quote above is the price everywhere ELSE — worth saying
    // before somebody funds runtime they will never burn.
    let freeBoxes = [];
    try { freeBoxes = freeEnclavesFor(Enclave.address, await Enclave.getEnclaves()); } catch(e){}
    const freeNames = freeBoxes.map(e => e.name || e.endpoint).join(", ");
    if (rate6 > 0n){
      const rate = Number(rate6 + fee6) / 1e6;   // the publisher's cut rides on top, exactly as create() adds it
      w.line("info", fund > 0
        ? "    " + fund + " USDC ≈ " + fmtDur(fund / rate) + " of runtime at $" + (rate * 3600).toFixed(2) + "/hr"
        : "    no funding now: the record is created with an empty balance (it would burn $" + (rate * 3600).toFixed(2) + "/hr once funded)");
      if (fee6 > 0n)
        w.line("info", "    includes the app's publisher fee: $" + (Number(fee6) * 3600 / 1e6).toFixed(2) + "/hr, paid to " + short(feeTo) + " out of each funding");
    }
    if (freeBoxes.length){
      w.line("ok", "[✓] you host this yourself: " + freeNames + " pays out to this wallet, so running it there costs you nothing"
        + (fee6 > 0n ? " beyond the app's publisher fee" : " at all") + " - the rate above is what any OTHER enclave would charge");
      if (fee6 <= 0n && fund > 0)
        w.line("info", "    you can fund it anyway (it buys runtime on other enclaves if yours is ever down), or fund $0 and let your own box take it");
    }

    // 1) create: one tx from YOUR wallet - msg.sender owns the on-chain record.
    // No config PIN step: the appRef names the catalog version RECORD, and the
    // enclave takes config/volumes/ports straight from it (approval covered
    // them; a config CID stays refused). The last string carries "" or the
    // deployment-options envelope: the per-IP WAF (interpreted by the runner's
    // proxy, never handed to the app) and/or the deployer's inline config
    // override (replacing the version's config for this deployment only).
    const envelope = envelopeOf(spec);
    if (envelope){
      // the ledger's own bound on create()'s options field: rev <= 4 contracts
      // revert "configCid length" over 100 bytes - the wallet's simulation
      // fails and the signed tx never lands (observed live 2026-07-22, a
      // config override on the rev-4 ledger). Refuse before any wallet popup
      // so nobody signs a create that cannot mine.
      const cap = (await depSchemaRev()) >= 5 ? 4096 : 100;
      const bytes = new TextEncoder().encode(envelope).length;
      if (bytes > cap){
        w.line("warn", "[x] the deployment options envelope is " + bytes + " bytes but this ledger caps the field at " + cap + " bytes"
          + (cap === 100 ? " (CID-sized; create() reverts \"configCid length\")" : "")
          + " - " + (spec.config ? "config overrides need the rev-5 ledger upgrade" : "trim the options") + "; nothing was sent");
        return;
      }
    }
    if (spec.waf) w.line("info", "    protection on: " + JSON.stringify({ waf: spec.waf }) + " (enforced per requester IP by the enclave's proxy)");
    if (spec.config) w.line("info", "    config override on: this deployment runs on YOUR config (the version's config stays the default for everyone else)");
    w.line("p", "$ EnclaveDeployments.create(…)  (wallet · one tx · you own the record)");
    w.line("info", "[*] confirm the create transaction in your wallet…");
    // encode whichever create() shape the live contract speaks (depSchemaRev
    // sniffs once): rev 1 took a now-removed sshPubKey string before
    // configCid; rev 4 grew the publisher-fee snapshot (recipient, fee/sec)
    const rev = await depSchemaRev();
    // rev 8: the record also carries a SPEND CEILING. Default it to exactly
    // what we just quoted (the cheapest live enclave's price for these shares
    // plus the app's fee) so nothing dearer can ever claim it — including when
    // its host dies and the work goes back on the queue. The owner widens it
    // later from the dashboard (Rate cap) or `enclave rate-cap`.
    const maxRate6 = rate6 + fee6;
    if (rev >= 8){
      if (rate6 <= 0n){
        // no live price to cap against: create() would revert "maxRate <= fee"
        w.line("warn", "[x] couldn't read what the fleet charges for these shares right now, so there is no ceiling to set - nothing was sent. Try again in a moment.");
        return;
      }
      w.line("info", "    rate cap: $" + (Number(maxRate6) * 3600 / 1e6).toFixed(2) + "/hr — only enclaves at or under this can run it, now or after a failover");
    }
    const cdata = encCall(rev >= 8 ? DEP_SEL.create : rev >= 4 ? DEP_SEL.createV4 : rev >= 2 ? DEP_SEL.createV3 : DEP_SEL.createV1, [
      { t: "str", v: spec.reference }, { t: "uint", v: spec.gpuMilli }, { t: "uint", v: spec.cpuMilli },
      { t: "uint", v: appPort }, { t: "str", v: portsCsv }, { t: "bool", v: !!spec.isPublic },
      ...(rev >= 2 ? [] : [{ t: "str", v: "" }]), { t: "str", v: envelope },
      ...(rev >= 4 ? [{ t: "addr", v: feeTo || "0x" + "0".repeat(40) }, { t: "uint", v: fee6 }] : []),
      ...(rev >= 8 ? [{ t: "uint", v: maxRate6 }] : []),
    ]);
    const chash = await sendTx(DEPLOYMENTS_ADDRESS, cdata);
    w.line("dimln", "  ↳ sent " + chash + " · waiting for confirmation…");
    const rcpt = await waitReceipt(chash);
    const clog = (rcpt.logs || []).find(l => (l.topics || [])[0] === DEP_CREATED_TOPIC
      && (l.address || "").toLowerCase() === DEPLOYMENTS_ADDRESS.toLowerCase());
    if (!clog) throw new EnclaveError("create() confirmed but no Created event found in the receipt", 0);
    const id = clog.topics[1];
    w.setId(id);   // name the run explicitly: bytes32 ids read exactly like the tx hashes already in the log
    w.line("ok", "[✓] created " + id);

    // 2) fund: the credit lands in the deployment's on-chain balance. A $0
    // deploy SKIPS this step on purpose (payForRuntime refuses a zero amount,
    // and rightly - a zero top-up is a mistake, a zero create is a choice):
    // the record exists, reads awaiting_payment on the ledger (inert, nothing
    // burns), and is funded later from its row - or claimed for nothing by a
    // box that pays out to this wallet, whose zero price an empty balance
    // satisfies (rev 12 claimableBy). Only THAT case has a claim to watch for.
    if (!(fund > 0)){
      w.line("ok", "[✓] created unfunded - " + id + " sits inert (costs nothing) until it has balance");
      if (!freeBoxes.length){
        w.line("dimln", "    fund it any time: Top up on its row below (or the CLI's fund command) - enclaves claim it the moment it has balance");
        const dp = depsPanel(); if (dp) dp.refresh();
        return;
      }
      w.line("dimln", "    " + freeNames + " hosts it for nothing - watching for that claim");
    } else {
      let pricing = null;
      try { pricing = await (await fetch(Enclave.base + "/pricing", { signal: AbortSignal.timeout(8000) })).json(); } catch(e){}
      try {
        await payForRuntime({
          contract: DEPLOYMENTS_ADDRESS, deploymentRef: id,
          usdcDomain: pricing && pricing.usdcDomain, usdc: (pricing && pricing.usdc) || "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
          ethUsd: pricing && pricing.ethUsd,
        }, fund, asset, w.line);
      } catch(e){
        const rejected = (e && e.code === 4001) || /reject|denied|declin|cancell/i.test(e && e.message || "");
        w.line("warn", rejected ? "[x] funding rejected in wallet." : "[x] funding failed: " + (e.message || e));
        w.line("dimln", "    " + id + " exists on-chain but is unfunded (inert, costs nothing). Fund it any time - it starts once it has balance.");
        offerRetry(w, id, fund, asset);
        return;
      }
    }

    // 3+4) nudge the fleet, then watch the claim and the runner's status -
    // DETACHED: deployOnChain resolves here (the wallet work is done), so the
    // caller frees for the NEXT deploy of a fleet while this run's writer
    // keeps streaming into its own strip / row panel
    watchClaimAndRun(id, null, w, spec.targetName || "")
      .catch(e => w.line("warn", "[x] " + (e.message || String(e))))
      .finally(() => { w.end(); refreshWallet(); });
    detached = true;
  } catch(e){
    if (w) w.line("warn", "[x] " + (e.message || String(e)));
    if (w && e.status === 0) w.line("dimln", "    the API endpoint is unreachable right now - retry in a moment.");
  } finally {
    if (!detached && w) w.end();
    refreshWallet();
  }
}

/* The one deploy failure the reader can still fix from where they are
   standing: the record exists on-chain, it just has no balance. So the run log
   carries the click that fixes it - a run-log ACTION line (js/core/runlog),
   which <c-deployments> paints as a button and dispatches back into
   retryFunding below. Everything needed to re-sign rides in the descriptor, so
   the offer survives a reload exactly as the narrative around it does. */
function offerRetry(w, id, usd, asset){
  w.line("act", "[↻] Retry payment · " + (asset === "ETH" ? "≈ $" + usd + " of ETH" : "$" + usd + " USDC"),
         { kind: "fund", id: id, usd: usd, asset: asset });
}

/* Pay for a deployment that was created but never funded. Picks its own run's
   narrative back up (the deploy flow ended that writer when the funding
   failed) and, once the money lands, continues into the SAME claim/status
   watch the first attempt never reached - a retry finishes the story rather
   than starting a second one. `run` is that recorded run; null (the history
   was cleared) opens a fresh one named after the deployment. */
export async function retryFunding(id, usd, asset, run){
  if (!/^0x[0-9a-f]{64}$/i.test(id || "")) return;
  usd = Number(usd) || 0;
  asset = asset === "ETH" ? "ETH" : "USDC";
  // a run something else is already writing (a resumed watch) is not ours to append to
  let w = null;
  if (run){
    w = runlog.resume(run);
    if (!w) return showToast("that deploy is already running - watch its log");
  } else {
    w = runlog.startRun(); w.setId(id);
  }
  let detached = false;
  try {
    if (!(usd > 0)){ w.line("warn", "[x] no amount recorded for this retry - use Top up on the deployment's row instead"); return; }
    // the balance may have landed since: a tx the wallet reported as failed but
    // that mined anyway, another tab, the dashboard's Top up. Read the LEDGER
    // before asking for a second signature - a retry must never double-pay.
    let d = null;
    try { d = await depGet(id); } catch(e){}
    if (d && d.rate > 0 && d.balance6 >= d.rate){
      w.line("ok", "[✓] already funded - the ledger holds " + fmtDur(d.balance6 / d.rate) + " of runtime for it. Nothing was charged.");
      watchClaimAndRun(id, d, w, "")
        .catch(e => w.line("warn", "[x] " + (e.message || String(e))))
        .finally(() => { w.end(); refreshWallet(); });
      detached = true;
      return;
    }
    if (d && !d.active){
      w.line("warn", "[x] this deployment is suspended on the ledger - Resume it first (funding an inactive record reverts)");
      return;
    }
    if (!Enclave.provider){
      w.line("info", "[*] connecting wallet…");
      await connectWallet();
      w.line("ok", "[✓] wallet " + short(Enclave.address));
    }
    await ensureBaseChain();
    w.line("info", "[*] retrying the payment for " + id + "…");
    let pricing = null;
    try { pricing = await (await fetch(Enclave.base + "/pricing", { signal: AbortSignal.timeout(8000) })).json(); } catch(e){}
    await payForRuntime({
      contract: DEPLOYMENTS_ADDRESS, deploymentRef: id,
      usdcDomain: pricing && pricing.usdcDomain, usdc: (pricing && pricing.usdc) || "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      ethUsd: pricing && pricing.ethUsd,
    }, usd, asset, w.line);
    watchClaimAndRun(id, null, w, "")
      .catch(e => w.line("warn", "[x] " + (e.message || String(e))))
      .finally(() => { w.end(); refreshWallet(); });
    detached = true;
  } catch(e){
    const rejected = (e && e.code === 4001) || /reject|denied|declin|cancell/i.test(e && e.message || "");
    w.line("warn", rejected ? "[x] funding rejected in wallet." : "[x] funding failed: " + (e.message || e));
    offerRetry(w, id, usd, asset);        // still created, still unfunded, still fixable
  } finally {
    if (!detached){ w.end(); refreshWallet(); }
  }
}

/* Steps 3+4 of every deploy story - shared by the live flow above and a
   resumed watch (resumeDeployWatch): nudge the fleet, watch the ledger for a
   lease, follow the runner to "running", and land the row in the My Apps
   panel. `dPre` (a fresh depGet) skips the claim wait when the ledger already
   shows a live lease; `w` is the run's bound writer (its dead() aborts us if
   the run is ended from outside). */
async function watchClaimAndRun(id, dPre, w, prefer){
  // prefer: the modal's target pick - the relay then aims the hint at that
  // ONE box (first crack at claiming) instead of the full fan-out
  const hintBody = JSON.stringify(prefer ? { id, enclave: prefer } : { id });
  const leased = (d) => d && d.runner && !/^0x0+$/.test(d.runner) && d.leaseUntil * 1000 > Date.now();
  let claimed = leased(dPre) ? dPre : null;
  if (!claimed){
    // nudge the fleet - otherwise the next sweep (<=60s) picks it up
    w.line("info", "[*] hinting enclaves to claim…" + (prefer ? " (aimed at " + prefer + ")" : ""));
    try {
      const h = await (await fetch(Enclave.base + "/claim-hint", { method: "POST",
        headers: { "content-type": "application/json" }, body: hintBody })).json();
      if (h && h.accepted === false && h.reason) w.line("dimln", "    hint declined: " + h.reason + " (the sweep may still claim it)");
    } catch(e){ w.line("dimln", "    hint failed (" + (e.message || e) + "); the sweep claims funded work within ~1 min"); }

    let lastReason = "";
    for (let i = 0; i < 90 && !claimed; i++){
      if (w.dead && w.dead()) return;
      await wait(2000);
      let d = null; try { d = await depGet(id); } catch(e){}
      if (leased(d)) claimed = d;
      else if (i === 1) w.line("info", "[*] waiting for an enclave to claim (the lease appears on-chain)…");
      else if (i > 1 && i % 3 === 0){
        // Re-hint every ~6s until an enclave claims (was every 30s). The FIRST
        // hint usually races ahead of the funding tx being visible to the
        // fleet's (load-balanced) RPC node and is declined; a slow re-hint would
        // strand a funded deploy on the sweep path, where a GPU enclave sits out
        // the 120s CPU-first grace before it will take CPU work. Cheap + idempotent
        // (a claiming enclave just answers "evaluating"); we surface the decline
        // reason only when it CHANGES, so this stays quiet in the log.
        try {
          const h = await (await fetch(Enclave.base + "/claim-hint", { method: "POST",
            headers: { "content-type": "application/json" }, body: hintBody })).json();
          if (h && h.accepted === false && h.reason && h.reason !== lastReason){
            lastReason = h.reason;
            w.line("warn", "[!] fleet declines to claim: " + h.reason);
            if (/yanked|not.approved|rejected|delisted|unlisted/i.test(h.reason)){
              w.line("dimln", "    this host declines the release; another host may accept it under its own policy. The deployment remains queued.");
            } else if (/below|minimum/i.test(h.reason)){
              w.line("dimln", "    check the deployment's resource allocation against the app's requirements. The deployment remains queued.");
              break;
            }
          }
        } catch(e){}
      }
    }
    if (!claimed){
      w.line("warn", "[!] no enclave has claimed yet - the deployment stays on the queue (funded work is claimed as capacity frees up, and queued time is never billed). It appears below the moment one does.");
      const dp0 = depsPanel(); if (dp0) dp0.refresh(); return;
    }
  }
  w.line("ok", "[✓] claimed by enclave operator " + short(claimed.runnerOperator) + " · lease until " + new Date(claimed.leaseUntil * 1000).toLocaleTimeString());
  const label = appLabel(id);
  w.line("dimln", "    app origin: https://" + label + "." + APP_DOMAIN + "  (first request may take a moment: the enclave fetches + verifies your wasm from IPFS)");
  if (!Enclave.authed() && !Enclave.sessionMayServe()){
    // tokenless flows read the LEDGER (create/fund/claim all show), but the
    // runner's live status stream is an owner read (the wallet session, or a
    // host sign-in) - the app itself is already booting and reachable at the
    // origin above
    w.line("dimln", "    claimed and funded - the app boots now. Open the app origin above" +
      (!Enclave.address && Enclave.accountAuthed()
        ? "; the row below tracks its status."
        : ", or unlock live status/logs on the row below (one gas-free signature)."));
    const dp1 = depsPanel(); if (dp1) dp1.refresh(); return;
  }
  const final = await pollDeployment(id, w);
  const dp = depsPanel(); if (dp) dp.refresh({ highlight: (final && final.id) || id });
}
async function pollDeployment(id, w){
  const done = { running: 1, failed: 1, stopped: 1, error: 1 };
  let last = null, d = null;
  for (let i = 0; i < 180; i++){
    if (w.dead && w.dead()) return d;
    try { d = await Enclave.getDeployment(id); }
    catch(e){ w.line("dimln", "  … " + e.message); await wait(2500); continue; }
    if (d.status !== last){ last = d.status; w.line(statusCls(d.status), "  • " + d.status); }
    if (done[d.status]){
      if (d.status === "running"){
        const ep = appEndpoint(d);
        w.line("ok", "[✓] running" + (ep ? " · " + ep : ""));
        if (d.ratePerSecondUsdc) w.line("dimln", "    rate " + d.ratePerSecondUsdc + " USDC/s · " + (d.timeRemainingSec != null ? fmtDur(d.timeRemainingSec) + " funded" : "funded"));
        w.line("warn", "→ verify the attestation before sending data");
      } else {
        w.line("warn", "  ‹ ended: " + d.status + (d.error ? " · " + d.error : "") + " ›");
      }
      return d;
    }
    await wait(2500);
  }
  w.line("dimln", "  (still provisioning; track it in the panel below)");
  return d;
}

/* Resume the WATCH half of a deploy that a page unload cut off (a refresh
   mid-deploy): the async flow died with the old document, but the ledger
   didn't. Recover the deployment id - the run record's, or the create tx's
   receipt when the reload beat the "created" line - re-read the on-chain
   state, and keep narrating into the SAME recorded run. Reads only: no
   wallet step ever re-runs here. The dashboard's <c-deployments> calls this
   when it mounts and finds an interrupted run. */
export async function resumeDeployWatch(run){
  const w = runlog.resume(run);
  if (!w) return;                                       // something is already writing this run
  try {
    w.line("dimln", "// resumed after a reload - re-reading the ledger (nothing is re-sent or re-signed)");
    let id = /^0x[0-9a-f]{64}$/i.test(run.id || "") ? run.id.toLowerCase() : null;
    let d = null;
    if (id){ try { d = await depGet(id); } catch(e){} }
    if (!d){
      // no readable record under run.id: the reload may have hit before the
      // "created" line (no id recorded), or an older log stored the create TX
      // HASH as the id (bytes32 ids and tx hashes look identical). Either
      // way, the create tx's receipt names the real id.
      const sent = [...run.lines].reverse().map(l => /↳ sent (0x[0-9a-f]{64})/i.exec(l[1])).find(Boolean);
      const tx = (sent && sent[1]) || id;
      id = null;
      if (tx){
        try {
          const rcpt = await waitReceipt(tx, 5);
          const clog = (rcpt.logs || []).find(l => (l.topics || [])[0] === DEP_CREATED_TOPIC
            && (l.address || "").toLowerCase() === DEPLOYMENTS_ADDRESS.toLowerCase());
          if (clog) id = clog.topics[1];
        } catch(e){}
      }
      if (id){ try { d = await depGet(id); } catch(e){} }
    }
    if (!id){
      w.line("warn", "[!] this run was cut off before a create transaction confirmed - nothing reached the ledger. If your wallet shows a sent create(), refresh here in a minute; otherwise just deploy again (nothing was paid).");
      return;
    }
    w.setId(id);
    if (!d){
      w.line("warn", "[x] couldn't read " + id + " from the ledger right now - refresh in a moment.");
      return;
    }
    if (!d.active){
      w.line("warn", "  ‹ this deployment is stopped on the ledger (setActive(false) / terminated) ›");
      return;
    }
    if (!(d.balance6 > 0 || d.spent6 > 0)){
      w.line("warn", "[!] created, but no funding has landed on-chain - the reload likely hit before (or during) the funding step.");
      w.line("dimln", "    " + id + " sits inert (costs nothing). Fund it any time - enclaves claim it the moment it has balance.");
      // a run that offered a retry before the reload offers it again: the
      // amount and asset are in its own record, so the click still works
      const prev = [...run.lines].reverse().map(l => l[2]).find(a => a && a.kind === "fund");
      if (prev) offerRetry(w, id, prev.usd, prev.asset);
      return;
    }
    await watchClaimAndRun(id, d, w);
  } catch(e){
    w.line("warn", "[x] " + (e.message || String(e)));
  } finally {
    w.end();
  }
}

/* ============================================================
   Live capacity: the queue-wait verdict behind the deploy gates
   ============================================================ */
// Last-seen free capacity in whole percent (null = no availability read yet /
// fetch failed, so nobody warns on unknown). A pick ABOVE these is legal - the
// record queues on-chain until a runner with room claims it - but the user must know they're buying a queue slot, not an
// instant boot: confirmQueuedDeploy asks, and deployOnChain narrates it.
// A GPU app's CPU slice rides its card's node, so it checks cpuOnGpuNode.
const freePct = { gpu: null, cpuAny: null, cpuOnGpuNode: null };
function adoptFreePct(a){
  const gpuFree = (a.gpuShareFree != null ? a.gpuShareFree : (a.gpu !== false ? (a.maxShare || 0) : 0));
  const cpuFree = (a.cpuShareFree != null ? a.cpuShareFree : (a.gpu === false ? (a.maxShare || 0) : 1));
  freePct.gpu = Math.floor(gpuFree * 100);
  freePct.cpuAny = Math.floor(cpuFree * 100);
  freePct.cpuOnGpuNode = a.gpuEnclaveCpuShareFree != null ? Math.floor(a.gpuEnclaveCpuShareFree * 100) : freePct.cpuAny;
  return { gpuFree, cpuFree };
}
// null when capacity is unknown; otherwise the queue-wait verdict for a pick
function queuedVerdict(gpuPct, cpuPct){
  if (freePct.gpu == null) return null;
  const overG = gpuPct > 0 && gpuPct > freePct.gpu;
  const cpuFreeHere = gpuPct > 0 ? freePct.cpuOnGpuNode : freePct.cpuAny;
  const overC = cpuPct > cpuFreeHere;
  return (overG || overC) ? { overG, overC, cpuFreeHere } : null;
}
/* The on-chain per-deployment GPU-share cap as a refusal message (null =
   fits; pre-cap contracts read as uncapped). Shared so every entry point shows
   it WHERE THE USER IS - the quick-deploy modal, deployOnChain's
   pre-navigation toast - instead of first redirecting to the dashboard for a
   create() that would only revert. `minGpuPct` (when known) picks the honest
   message: an app whose MINIMUM exceeds the cap is publishable but
   undeployable, not a dial problem. */
export async function gpuCapRefusal(gpuMilli, minGpuPct){
  const cap = await depMaxGpuMilli();
  if (!(gpuMilli > cap)) return null;
  return minGpuPct != null && minGpuPct * 10 > cap
    ? "this app needs at least a " + minGpuPct + "% GPU share, but the platform currently caps deployments at " + (cap / 10) + "% of a card - it can't be deployed right now."
    : "the platform caps GPU deployments at " + (cap / 10) + "% of a card - lower the GPU share (asked: " + (gpuMilli / 10) + "%).";
}

/* The commit-time capacity gate behind the store's quick-deploy modal. THIS
   is the deliberate stop: a size the fleet can't start right now only
   proceeds through an explicit checkbox, because the user is about to sign
   final, non-withdrawable funding for a deployment that will sit Queued.
   With a target box the verdict is per-BOX (its own available pools);
   otherwise a fresh /availability read at click time. Resolves true to
   proceed - immediately when the size fits or capacity is unknown - false on
   cancel. */
export async function confirmQueuedDeploy(gpuPct, cpuPct, target){
  let queued, freeLine;
  if (target && !target.none){
    // per-BOX verdict: the modal targeted a specific enclave, so the wait
    // question is about ITS pools, phrased with its name
    queued = (gpuPct > 0 && gpuPct > target.free.gpuPct) || cpuPct > target.free.cpuPct;
    freeLine = gpuPct > 0
      ? target.free.gpuPct + "% of " + target.name + "'s card / " + target.free.cpuPct + "% of its node are free right now; this deployment asks for " + gpuPct + "% / " + cpuPct + "%"
      : target.free.cpuPct + "% of " + target.name + "'s node is free right now; this deployment asks for " + cpuPct + "%";
  } else {
    try { adoptFreePct(await Enclave.getAvailability()); } catch(e){}
    const q = queuedVerdict(gpuPct, cpuPct);
    queued = !!q;
    freeLine = q ? (gpuPct > 0
      ? freePct.gpu + "% of a card / " + q.cpuFreeHere + "% of its node are free right now; this deployment asks for " + gpuPct + "% / " + cpuPct + "%"
      : freePct.cpuAny + "% of the node is free right now; this deployment asks for " + cpuPct + "%") : "";
  }
  if (!queued) return true;
  return new Promise((resolve) => {
    const host = document.createElement("div");
    host.className = "qd-overlay"; host.id = "capConfirm";
    host.innerHTML =
      '<div class="qd-card capq" role="dialog" aria-modal="true" aria-label="Not enough free capacity">' +
        '<div class="qd-h">⚠ The fleet is full for this size</div>' +
        '<p class="qd-sub">' + esc(freeLine) + '. You can still deploy: the deployment is created on-chain, waits as <b>Queued</b>, and starts automatically the moment capacity frees up.</p>' +
        '<p class="qd-sub">Queued time is never billed - the balance only burns while the app runs. The funding stays on the deployment until it runs; cancelling returns only the unspent part held for the host, the rest is final.</p>' +
        '<label class="qd-tos"><input type="checkbox" class="capq-ck" /> <span>I understand this deployment will <b>wait in the queue</b> - possibly for a while - and start on its own once capacity frees up.</span></label>' +
        '<div class="qd-actions">' +
          '<button class="btn btn-primary capq-go" type="button" disabled>▸ Queue for Deployment</button>' +
          '<button class="btn capq-cancel" type="button">Cancel</button>' +
        '</div>' +
      '</div>';
    document.body.appendChild(host);
    const onKey = (e) => { if (e.key === "Escape") done(false); };
    const done = (ok) => { host.remove(); document.removeEventListener("keydown", onKey); resolve(ok); };
    document.addEventListener("keydown", onKey);
    const ck = host.querySelector(".capq-ck"), go = host.querySelector(".capq-go");
    ck.addEventListener("change", () => { go.disabled = !ck.checked; });
    go.addEventListener("click", () => done(true));
    host.querySelector(".capq-cancel").addEventListener("click", () => done(false));
    host.addEventListener("click", (e) => { if (e.target === host) done(false); });
  });
}
