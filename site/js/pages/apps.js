import {catalogAdmissionNotice} from "../core/catalog-policy.js";
/* ============================================================
   Apps page - the on-chain catalog store. Each listing renders
   as a <c-app-card>; the page owns the toolbar (filter/search),
   the publish form, and the wallet transactions the cards
   request via `card-action` events.
   ============================================================ */
import "../../components/header/header.js";
import "../../components/footer/footer.js";
import "../../components/toast/toast.js";
import "../../components/section-head/section-head.js";
import "../../components/app-card/app-card.js";
import "../../components/app-detail/app-detail.js";
import "../../components/app-reviews/app-reviews.js";
import { $, $$, esc, short, blen, fmtDur, showToast, on, tosAccepted, setTosAccepted } from "../core/util.js";
import { APP_CATALOG_ADDRESS, APP_CATALOG_CHAIN, FEATURED_ADDRESS, REVIEWS_ADDRESS, USDC_BASE, IPFS_UPLOAD_URL, IPFS_IMAGE_UPLOAD_URL, IPFS_JSON_UPLOAD_URL, IPFS_GATEWAY, MAX_WASM_MB, MAX_WASM_BYTES, MAX_IMAGE_MB, MAX_IMAGE_BYTES, BASE_CHAIN, ACCOUNTS_ENABLED } from "../core/config.js";
import { Enclave, EnclaveError } from "../core/api.js";
import { catConfigured, catExplorer, encCall, CAT_SEL, CAT_MAX, ROUTING_KEYS, APPROVAL, depPrices6, depMaxGpuMilli, depSchemaRev, rate6Of, waitReceipt, catSchemaRev, catMaxFeePerSec6, catVersionFee, featConfigured, featMaxBid, FEAT_SEL, revConfigured, REV_SEL } from "../core/chain.js";
import { FEATURED, loadCampaigns, featuredList, beaconView } from "../core/featured.js";
import { loadTallies, loadReviews, confirmReceipt } from "../core/reviews.js";
import { payForRuntime } from "../core/fund.js";
import { connectWallet, authenticate, ensureBaseChain, sendTx, usdcBalanceOf, personalSign } from "../core/wallet.js";
import { STORE, loadCatalog, noteCatalogWrite, selIdx, defaultIdx, appVerified, appPrivileged, visibleVerIdxs, validPortsCsv, specOf, fetchConfigCid, catalogRef, mediaOf, appMedia, mediaUrl, stripMedia, withMedia, signedUploadHeaders, putConfig, cpuFallbackOfConfig } from "../core/catalog.js";
import { minPctsOf, startSharesFor, shareRates, pickEnclaveFor, rankEnclavesFor, liftSharesForLedger } from "../core/pricing.js";
import { appResources } from "../core/app-resources.js";
import { protectionOf, PROTECTION_DOC } from "../core/protection.js";
import { navigate } from "../boot.js";

/* ---- render: filter + sort the catalog into <c-app-card>s ---- */
// The grid caps at 4 rows per page; the page size follows the responsive
// column count (same arithmetic as the grid's auto-fill: 300px min + 16px gap).
const MAX_ROWS = 4;
let storePage = 0;
let forceTallies = false;   // set by the ↻ handler: the next paint re-reads ratings too
/* appId -> the campaign that put it at the head of the Featured tab, or null for
   the editorial pick. Rebuilt on every render of that tab and empty on every
   other tab, so nothing downstream can mark a card gold on a page that has no
   featured group. */
const featuredIds = new Map();

/* Is the store grid ACTUALLY on screen? The catalog page mounts all three views
   (store, publish, one app's detail) and hides the others with [hidden], so the
   grid element exists and has a parent even when nobody can see it. Two things
   depend on the difference:
   - a metered view must be a view. A promoted card rendered into a hidden grid,
     or into a background tab, has not been shown to anybody and must not draw
     down a publisher's budget.
   - the paint itself. `enclave:featured` and a window resize used to re-render
     the grid whatever was on screen, which is work nobody sees and, with the
     featured head now inside the grid, a beacon nobody saw either.
   offsetParent is null for a hidden subtree, which is exactly the question. */
function storeVisible(){
  const store = document.getElementById("storeView");
  const grid = document.getElementById("storeGrid");
  if (!store || !grid || store.hidden || grid.offsetParent === null) return false;
  return typeof document.visibilityState !== "string" || document.visibilityState === "visible";
}
const gridCols = (grid) => Math.max(1, Math.floor((grid.clientWidth + 16) / (300 + 16)));
function renderPager(total, pages){
  const pager = $("#storePager"); if (!pager) return;
  pager.hidden = pages <= 1;
  if (pager.hidden) return;
  $("#pageStatus").textContent = "page " + (storePage + 1) + " / " + pages + " · " + total + " apps";
  $("#pagePrev").disabled = storePage <= 0;
  $("#pageNext").disabled = storePage >= pages - 1;
}
function renderApps(){
  const grid = $("#storeGrid"); if (!grid) return;
  if (!catConfigured()){
    grid.innerHTML = '<div class="store-note">The on-chain catalog isn’t wired up on this deployment yet.<br><span class="dim">Deploy <code>EnclaveAppCatalog</code> with <code>scripts/deploy-app-catalog.mjs</code>; it writes the address in for you.</span></div>';
    return;
  }
  if (!STORE.loaded){ grid.innerHTML = '<div class="loading" role="status">reading catalog from Base…</div>'; return; }
  const q = ($("#storeSearch") && $("#storeSearch").value || "").trim().toLowerCase();
  // Delisted apps are hidden from the public store, but their PUBLISHER (and
  // the catalog owner) still see them - that's the only path back: relist, or
  // publish a new version to the slug (which auto-relists).
  const me = (Enclave.address || "").toLowerCase();
  const isOwner = !!(STORE.owner && me && me === STORE.owner);
  const myApp = (a) => !!me && a.publisher.toLowerCase() === me;
  syncModTabs(me, isOwner);
  let apps;
  if (STORE.filter === "delisted"){
    // moderation view: the catalog owner sees EVERY delisted app; a publisher
    // sees only their own - their one path back (relist, or republish the slug).
    apps = STORE.apps.filter(a => a.versions.length && !a.active && (isOwner || myApp(a)));
  } else if (STORE.filter === "pending"){
    // the to-review queue: active apps whose latest release awaits the owner's
    // approval verdict. The owner sees every one; a publisher sees only their
    // own - where their release waits while the owner reviews it. An app with
    // an older approved version stays in the store meanwhile; this queue
    // tracks the release, not the listing.
    apps = STORE.apps.filter(a => a.versions.length && a.active && appPending(a)
                               && (isOwner || myApp(a)));
  } else if (STORE.filter === "rejected"){
    // moderation view: apps whose latest release was rejected (appRejected).
    // The owner sees every one (their rejection record); a publisher sees only
    // their own - the cue to yank the release or publish a fixed version.
    // Listing state doesn't matter here: a delisted app still shows.
    apps = STORE.apps.filter(a => appRejected(a) && (isOwner || myApp(a)));
  } else {
    // Approved - the public store, and everything the FEATURED tab shows after
    // its head group: active apps with a release the owner approved
    // (setApproval - the deploy gate), plus owner-endorsed/official ones, with
    // something visible (an app whose every version is yanked/rejected has
    // nothing to show a normal browser). `verified` stays a curation badge and
    // the sort key below, not the membership test. Everything else lives in the
    // moderation tabs above, each scoped to the owner + the affected publisher.
    apps = STORE.apps.filter(a => a.versions.length && a.active && visibleVerIdxs(a).length && (appApproved(a) || appVerified(a)));
  }
  // THE FEATURED HEAD. Featured is the default tab and is NOT a featured-only
  // filter: the same approved list, with the standing campaigns (or the
  // editorial pick) lifted to the front and marked gold. It is built as a
  // PARTITION of that one list, which is what keeps an app from appearing
  // twice: membership is decided once, by the approved rule, and this only
  // decides order. A featured app that is not currently approved and listed
  // never enters - featuredList() already requires it, and the partition would
  // drop it anyway.
  featuredIds.clear();
  if (STORE.filter === "featured"){
    const inStore = new Set(apps.map(a => a.appId));
    for (const f of featuredList()){
      if (!f || !f.app || !inStore.has(f.app.appId) || featuredIds.has(f.app.appId)) continue;
      featuredIds.set(f.app.appId, f.campaign || null);
    }
  }
  // search matches only what the viewer can see - a yanked version's CID must
  // not surface an app to someone who'd then find no trace of that version
  if (q) apps = apps.filter(a => (a.name + " " + a.description + " " + a.slug + " " + a.publisher + " " + visibleVerIdxs(a).map(i => a.versions[i].cid + " " + a.versions[i].version).join(" ")).toLowerCase().includes(q));
  // The store's sort, unchanged - applied WITHIN each group so the featured head
  // keeps its bid order (highest per-view bid first, ties to the older campaign)
  // and everything after it is the ordinary store order.
  const byRank = (x, y) => (Number(appVerified(y)) - Number(appVerified(x))) || (y.updatedAt - x.updatedAt);
  if (featuredIds.size){
    const order = [...featuredIds.keys()];
    const head = apps.filter(a => featuredIds.has(a.appId)).sort((x, y) => order.indexOf(x.appId) - order.indexOf(y.appId));
    const rest = apps.filter(a => !featuredIds.has(a.appId)).sort(byRank);
    apps = head.concat(rest);
  } else {
    apps.sort(byRank);
  }
  if (!apps.length){
    renderPager(0, 1);
    renderFeaturedNote(null);   // nothing on screen to describe: the note goes with it
    grid.innerHTML = '<div class="store-note">' + (STORE.apps.length ? "No apps match your filter." : "No apps published yet. Be the first with <b>+ Publish app</b>.") + '</div>';
    return;
  }
  const pageSize = gridCols(grid) * MAX_ROWS;
  const pages = Math.max(1, Math.ceil(apps.length / pageSize));
  storePage = Math.min(Math.max(storePage, 0), pages - 1);
  renderPager(apps.length, pages);
  const page = apps.slice(storePage * pageSize, (storePage + 1) * pageSize);
  // the note describes what is on THIS page, so it is written after the slice
  renderFeaturedNote(page.filter(a => featuredIds.has(a.appId)).map(a => featuredIds.get(a.appId)));
  grid.replaceChildren(...page.map(a => {
    const el = document.createElement("c-app-card");
    el.app = a;
    if (featuredIds.has(a.appId)){
      const camp = featuredIds.get(a.appId);
      el.classList.add("is-featured");
      // Truthful, and the two are different things: a PROMOTED card is one its
      // publisher pays per view for; a FEATURED one is the editorial pick and
      // bills nobody. The label must never say the first about the second.
      el.dataset.featuredLabel = camp ? "\u2605 Promoted" : "\u2605 Featured";
    }
    return el;
  }));
  // ONE metered view per promoted app, and only for a card that is on this page
  // AND on screen. Three ways a card can exist without having been seen, and
  // none of them may bill a publisher: a later pager page, a grid inside a
  // hidden view (an app's detail page or Publish, both mounted beside it), and a
  // background browser tab. beaconView dedupes per app per page load on top, so
  // a ratings repaint or a wallet connect re-render never counts twice.
  if (storeVisible()) for (const a of page) if (featuredIds.get(a.appId)) beaconView(a.appId);
  // ratings for exactly the tiles on screen - one eth_call for the page
  // (`enclave:reviews` repaints them when it lands)
  loadTallies(page.map(a => a.appId), forceTallies);
  forceTallies = false;
}
// the page size tracks the responsive column count - a resize that changes it
// re-slices the current page (module-load-once; inert off the store view)
let _resizeT;
addEventListener("resize", () => {
  clearTimeout(_resizeT);
  _resizeT = setTimeout(() => { if (storeVisible()) renderApps(); }, 200);
});

/* ---- the Featured tab's one-line note, and the way in to promoting ----
   What the aside's foot used to say, moved to where the group now is.

   It describes THE CARDS ON THIS PAGE, not the tab in general. The head group
   lives at the top of page one, so on page two, or under a search that matches
   none of it, there is no gold card on screen and a note claiming "the first
   card is promoted" would be pointing at somebody else's app. The wording also
   never borrows a word it has not earned: a PROMOTED card is one its publisher
   pays per view for, an editorial pick is FEATURED and bills nobody.

   `onPage` is one entry per featured card actually rendered: its campaign, or
   null for the editorial pick. */
function renderFeaturedNote(onPage){
  const note = $("#featuredNote"); if (!note) return;
  const on = STORE.filter === "featured";
  note.hidden = !on;
  if (!on) return;
  // null means the grid is showing no cards at all (a search that matches
  // nothing): there is no list for this note to be about, so it goes too.
  if (onPage === null){ note.hidden = true; return; }
  const here = onPage;
  const paid = here.filter(Boolean).length;
  const hint = $("#featuredHint");
  if (hint) hint.textContent =
    !featuredIds.size ? "no featured app right now - the whole store follows"
    : !here.length    ? "the featured apps are at the top of the first page"
    : paid === here.length
      ? (here.length === 1 ? "the gold card is promoted per view by its publisher"
                           : "the " + here.length + " gold cards are promoted per view by their publishers")
      : paid === 0
        ? (here.length === 1 ? "the gold card is an editorial pick - nobody paid for it"
                             : "the gold cards are editorial picks - nobody paid for them")
        : "the gold cards are featured; the ones marked promoted are paid for per view by their publishers";
  const pb = $("#featuredPromote");
  if (pb){
    pb.hidden = !featConfigured();
    if (!pb.dataset.wired){ pb.dataset.wired = "1"; pb.addEventListener("click", openPromote); }
  }
}

/* ---- promote modal: place a per-view bid + escrow a budget ---- */
let prHost = null, prEsc = null;
function closePromote(){
  if (!prHost) return;
  prHost.remove(); prHost = null;
  document.removeEventListener("keydown", prEsc);
}
async function featTx(data, verb){
  if (!Enclave.provider) await connectWallet();
  await ensureBaseChain();
  const hash = await sendTx(FEATURED_ADDRESS, data);
  showToast(verb + " · " + hash.slice(0, 12) + "…");
  await waitReceipt(hash);
  return hash;
}
function openPromote(){
  if (!featConfigured()) return;
  closePromote();
  const host = document.createElement("div");
  prHost = host;
  host.className = "qd-overlay";
  const standing = FEATURED.campaigns
    .filter(c => c.active && c.bidPerView6 > 0 && c.balance6 >= c.bidPerView6)
    .sort((x, y) => y.bidPerView6 - x.bidPerView6);
  const topPerK = standing.length ? (standing[0].bidPerView6 * 1000) / 1e6 : 0;
  host.innerHTML =
    '<div class="qd-card" role="dialog" aria-modal="true" aria-label="Promote your app">' +
      '<div class="qd-h">Promote <b>your app</b> at the top of the store</div>' +
      // There is no single slot any more: the store's default tab shows EVERY
      // standing campaign at its head, highest bid first, above the rest of the
      // catalogue. So a bid buys a place in that group and the rank inside it -
      // not a winner-takes-all box - and the copy has to say so, because the old
      // wording would read as "outbid them or get nothing".
      '<p class="qd-sub">Name a price per <b>1,000 views</b> and escrow a budget (USDC). Every funded campaign is shown at the top of the store, <b>highest bid first</b>; views are metered by the gateway (deduped per visitor per day) and drawn from your escrow at your bid. <b>Withdraw the unspent balance anytime.</b></p>' +
      '<p class="qd-sub">' + (topPerK > 0
        ? "Standing campaigns: <b>" + standing.length + "</b>, top bid <b>$" + topPerK.toFixed(2) + " / 1k views</b> - bid above it to lead the group."
        : "No standing campaigns - <b>any funded bid leads the group.</b>") + '</p>' +
      '<label class="qd-lbl" for="prApp">Your app</label>' +
      '<select class="qd-amt" id="prApp"></select>' +
      '<label class="qd-lbl" for="prBid">Bid ($ per 1,000 views)</label>' +
      '<input class="qd-amt" id="prBid" type="number" value="' + (topPerK > 0 ? (topPerK + 0.5).toFixed(2) : "1.00") + '" min="0.01" step="0.01" inputmode="decimal" />' +
      '<label class="qd-lbl" for="prDep">Budget to escrow now (USDC)</label>' +
      '<input class="qd-amt" id="prDep" type="number" value="10" min="0" step="any" inputmode="decimal" />' +
      '<div class="qd-est" id="prEst"></div>' +
      '<div class="qd-note" id="prNote" hidden></div>' +
      '<div class="pr-log" aria-live="polite"></div>' +
      '<div class="qd-actions">' +
        '<button class="btn btn-primary" id="prGo" type="button">▸ Place bid &amp; fund</button>' +
        '<button class="btn" id="prWithdraw" type="button" hidden>Withdraw balance</button>' +
        '<button class="btn qd-cancel" type="button">Cancel</button>' +
      '</div>' +
    '</div>';
  document.body.appendChild(host);
  prEsc = (e) => { if (e.key === "Escape") closePromote(); };
  document.addEventListener("keydown", prEsc);
  host.addEventListener("pointerdown", (e) => { if (e.target === host) closePromote(); });
  host.querySelector(".qd-cancel").addEventListener("click", closePromote);

  const sel = host.querySelector("#prApp"), bid = host.querySelector("#prBid"), dep = host.querySelector("#prDep");
  const estEl = host.querySelector("#prEst"), note = host.querySelector("#prNote"), go = host.querySelector("#prGo");
  const wd = host.querySelector("#prWithdraw"), logEl = host.querySelector(".pr-log");
  const plog = (cls, txt) => { const d = document.createElement("div"); d.className = "pr-line " + cls; d.textContent = txt; logEl.appendChild(d); logEl.scrollTop = logEl.scrollHeight; };

  const me = () => (Enclave.address || "").toLowerCase();
  const myApps = () => STORE.apps.filter(a => me() && a.publisher.toLowerCase() === me() && a.versions.length && a.active);
  const fillApps = () => {
    const apps = myApps();
    sel.innerHTML = apps.length
      ? apps.map(a => '<option value="' + esc(a.appId) + '">' + esc(a.name || a.slug) + '</option>').join("")
      : '<option value="">' + (me() ? "you haven’t published an app yet" : "connect a wallet to pick your app") + '</option>';
    refresh();
  };
  const campaignOf = (appId) => FEATURED.campaigns.find(c => c.appId === appId);
  let maxBid6 = 10000;   // contract default; refreshed below
  featMaxBid().then(m => { maxBid6 = Number(m) || maxBid6; refresh(); }).catch(() => {});

  function refresh(){
    const appId = sel.value;
    const c = appId ? campaignOf(appId) : null;
    const mineC = c && c.advertiser.toLowerCase() === me();
    wd.hidden = !(mineC && c.balance6 > 0);
    if (mineC) wd.textContent = "Withdraw $" + (c.balance6 / 1e6).toFixed(2);
    const bid6 = Math.round((parseFloat(bid.value) || 0) * 1000);   // $/1k -> per-view 6dp
    const dep6 = Math.round((parseFloat(dep.value) || 0) * 100) * 10000;
    const capPerK = (maxBid6 * 1000) / 1e6;
    let err = null;
    if (!appId) err = "Pick one of your published apps (only approved, listed apps are shown; a pending one waits until the owner approves it).";
    else if (c && !mineC) err = "This app already has a campaign placed by another wallet.";
    else if (!(bid6 > 0)) err = "Bid at least $0.01 per 1k views.";
    else if (bid6 > maxBid6) err = "The bid cap is $" + capPerK.toFixed(2) + " per 1k views.";
    else if (!c && !(dep6 > 0)) err = "Escrow at least $0.01 to put the bid in play.";
    note.hidden = !err; if (err) note.textContent = err;
    go.disabled = !!err;
    const total6 = (c ? c.balance6 : 0) + dep6;
    estEl.innerHTML = (bid6 > 0 && total6 > 0)
      ? "budget covers ≈ <b>" + Math.floor(total6 / bid6).toLocaleString() + " views</b> at this bid"
      : "";
  }
  sel.addEventListener("change", refresh);
  bid.addEventListener("input", refresh);
  dep.addEventListener("input", refresh);
  fillApps();
  if (!me()) connectWallet().then(fillApps).catch(() => {});

  go.addEventListener("click", async () => {
    const appId = sel.value; if (!appId) return;
    const bid6 = Math.round((parseFloat(bid.value) || 0) * 1000);
    const depUsd = parseFloat(dep.value) || 0;
    go.disabled = true; wd.disabled = true;
    try {
      const c = campaignOf(appId);
      if (!c || c.bidPerView6 !== bid6){
        plog("info", "[*] place bid: $" + ((bid6 * 1000) / 1e6).toFixed(2) + " / 1k views… (wallet)");
        await featTx(encCall(FEAT_SEL.place, [{ t: "bytes32", v: appId }, { t: "uint", v: bid6 }]), "placing bid");
        plog("ok", "[✓] bid placed");
      }
      if (depUsd > 0){
        await payForRuntime({
          contract: FEATURED_ADDRESS, deploymentRef: appId, usdc: USDC_BASE,
          buys: "escrows your promotion budget",
          creditLine: "    escrowed in your campaign - views draw it down at your bid; withdraw the rest anytime",
        }, depUsd, "USDC", plog);
      }
      await loadCampaigns(true);
      renderApps();                 // the head of the Featured tab reorders, not a single box
      plog("ok", "[✓] campaign live - the featured group follows the highest funded bid");
    } catch(e){ plog("err", "[✗] " + (e && e.message || e)); }
    go.disabled = false; wd.disabled = false;
    refresh();
  });
  wd.addEventListener("click", async () => {
    const appId = sel.value; if (!appId) return;
    go.disabled = true; wd.disabled = true;
    try {
      plog("info", "[*] withdraw the unspent balance… (wallet)");
      await featTx(encCall(FEAT_SEL.withdraw, [{ t: "bytes32", v: appId }, { t: "uint", v: 0 }]), "withdrawing");
      plog("ok", "[✓] balance returned to your wallet");
      await loadCampaigns(true);
      renderApps();
    } catch(e){ plog("err", "[✗] " + (e && e.message || e)); }
    go.disabled = false; wd.disabled = false;
    refresh();
  });
}

// Tab membership keys off the owner's per-version APPROVAL verdict (the
// deploy gate set by the approve/reject buttons) - NOT the separate
// `verified` endorsement badge. The app's current state is its LATEST
// release (newest non-yanked entry).
const latestApproval = (a) => {
  const vs = a.versions || [];
  for (let i = vs.length - 1; i >= 0; i--) if (!vs[i].yanked) return vs[i].approval;
  return -1;                                   // every version yanked - no release
};
// Rejected tab: the latest release was rejected. Both cleanup paths clear the
// app from the tab: publish a fixed version (a newer latest, pending) or yank
// the rejected one. Older rejected versions under a newer release are
// history, not the app's current state.
const appRejected = (a) => latestApproval(a) === APPROVAL.rejected;
// Pending queue: the latest release still awaits a verdict.
const appPending = (a) => latestApproval(a) === APPROVAL.pending;
// Store membership: some deployable release - non-yanked and approved (a
// newer pending version must not un-list the app while it's under review).
const appApproved = (a) => a.versions.some(v => !v.yanked && v.approval === APPROVAL.approved);

/* The Pending, Rejected and Delisted tabs are the catalog owner's moderation
   surface - always visible to them - and each is ALSO shown to a publisher
   with an app in that state; only their own appear there (pending = where
   their app waits for the owner's verdict; rejected = fix or yank the release;
   delisted = their path back to relist). Everyone else never sees any of them;
   a tab that just became hidden falls back to Approved. */
function syncModTabs(me, isOwner){
  const delisted = document.querySelector('#storeFilter button[data-filter="delisted"]');
  const pending = document.querySelector('#storeFilter button[data-filter="pending"]');
  const rejected = document.querySelector('#storeFilter button[data-filter="rejected"]');
  const mine = (a) => !!me && a.publisher.toLowerCase() === me;
  const hasOwnDelisted = STORE.apps.some(a => a.versions.length && !a.active && mine(a));
  const hasOwnPending = STORE.apps.some(a => a.versions.length && a.active && appPending(a) && mine(a));
  const hasOwnRejected = STORE.apps.some(a => appRejected(a) && mine(a));
  if (delisted) delisted.hidden = !(isOwner || hasOwnDelisted);
  if (pending) pending.hidden = !(isOwner || hasOwnPending);
  if (rejected) rejected.hidden = !(isOwner || hasOwnRejected);
  // A tab that just became hidden (the wallet disconnected, the last own
  // pending app cleared) falls back to the DEFAULT tab. That is Featured now,
  // and Featured is never hidden, so this always lands somewhere real - the
  // old fallback named Approved, which would leave the button row and
  // STORE.filter disagreeing the moment the default changed.
  const cur = document.querySelector('#storeFilter button[data-filter="' + STORE.filter + '"]');
  if (cur && cur.hidden){
    STORE.filter = "featured";
    $$("#storeFilter button").forEach(x => { const on = x.dataset.filter === "featured"; x.classList.toggle("on", on); x.setAttribute("aria-pressed", String(on)); });
  }
}

/* ---- quick deploy: the store card's one-decision modal. Wallet balance,
   an amount, the runtime it buys at the app's START shares - then the
   shared deployOnChain flow (public endpoint, catalog ports, USDC).
   Everything else about a deployment - its config, model volumes,
   protection, relay, version, shares - is a tab on its dashboard row. ---- */
let qdEsc = null;
function closeQuick(){
  const host = $("#quickDeploy"); if (host) host.remove();
  if (qdEsc){ document.removeEventListener("keydown", qdEsc); qdEsc = null; }
}
function quickDeploy(app, v, idx){
  closeQuick();
  // First paint sizes on the adopted aggregate; the TARGET enclave replaces
  // it the moment the fleet rows land (same live-update pattern as the
  // contract prices below) - the modal then names the box the app deploys
  // to and sizes the minimum shares against ITS hardware.
  // specOf, never the raw version: `gpuOptional` (and `volumes`) live in the
  // approved CONFIG, so sizing off `v` read the publisher's card as REQUIRED
  // and the first paint quoted a share the target pass then dropped to 0.
  const vspec = specOf(v);
  let mins = minPctsOf(vspec);
  // What this modal BUYS. Usually the floors - but a gpuOptional version has a
  // 0% GPU floor (its declared card is a preference, not a requirement), and
  // buying that floor deployed a model app onto CPU cores while the modal said
  // nothing about a card. startSharesFor buys the slice the version declares;
  // a deployer who wants it on cores instead resizes from the row's Version
  // tab afterwards (or creates at any dial from the CLI).
  // Recomputed with `mins` on every target change - the slice sizes against the
  // box this actually lands on, like the floors do.
  // A pre-13 ledger still refuses a GPU share under the CPU one, so every
  // start slice goes through liftSharesForLedger on the way out. Starting at 0
  // keeps that lift on until the sniff lands: the quick-deploy modal must never
  // offer a pair the live create() would revert on. It is the identity on 13+,
  // where a CPU-heavy app buys the small card slice it actually declared.
  let ledgerRev = 0;
  // `t` is the ranked target this would deploy to, and it decides WHICH node
  // floor the dial starts at: a box that serves this app on cores holds its
  // weights in node RAM, which on a cpuFallback version is a larger slice than
  // the same app needs beside a card.
  const startBuy = (hw, cap, t) => liftSharesForLedger(
    startSharesFor(vspec, hw, cap, t && t.weightsOnCores), ledgerRev);
  let buy = startBuy();
  let target = null;
  // constants first paint; the CONTRACT's live prices (incl. its ceil-to-a-
  // micro-USDC floor) replace them the moment the cached read lands - the
  // rate shown here must match what the deployment actually burns. A paid
  // app's publisher fee rides on top, exactly as create() adds it.
  let baseRate = shareRates(buy.gpuPct, buy.cpuPct).rate, fee = 0, pr6 = null;
  let rate = baseRate;
  const perHr = (rate * 3600).toFixed(2);
  // passkey/card account with no wallet: the deploy spends prepaid credit
  // (deployOnChain branches to the passkey-signed vault op itself) - the
  // modal speaks in dollars and shows the credit balance instead
  const acct = !Enclave.address && ACCOUNTS_ENABLED && Enclave.accountAuthed();
  // The least this modal deploys with. A WALLET deploy may be created EMPTY:
  // create() is a plain tx the ledger takes without a balance (the row reads
  // awaiting_payment - inert, nothing burns - until Top up funds it), and the
  // rev-12 free case never needs money at all: an enclave whose payout wallet
  // is the deployer's claims a zero-balance record at a zero price. A CREDIT
  // deploy funds inside the same passkey-signed vault op, and the relay
  // refuses an order that buys no runtime - so it keeps a positive floor.
  const minUsd = acct ? 0.01 : 0;
  const host = document.createElement("div");
  host.id = "quickDeploy"; host.className = "qd-overlay";
  host.innerHTML =
    '<div class="qd-card" role="dialog" aria-modal="true" aria-label="Deploy ' + esc(app.name || app.slug) + '">' +
      '<div class="qd-h">Deploy <b>' + esc(app.name || app.slug) + '</b> <span class="qd-ver">' + esc(v.version) + '</span></div>' +
      '<p class="qd-sub">Runs in a VM of its own on <b class="qd-shares"></b> at <b class="qd-rate">$' + perHr + '/hr</b>. ' +
        (acct ? 'It runs on your credit - it runs until the time you bought is used up, and you can top up or stop it whenever you like.'
              : 'Fund it from your wallet - it runs until the time you bought is used up, and you can top up or stop it whenever you like.') + '</p>' +
      (catalogAdmissionNotice(app, v) ? '<p class="qd-sub qd-catalog">' + esc(catalogAdmissionNotice(app, v)) + '</p>' : '') +
      '<p class="qd-sub qd-target" hidden></p>' +
      '<p class="qd-sub qd-prot" hidden></p>' +
      '<p class="qd-sub qd-fee" hidden></p>' +
      '<div class="qd-bal"><span>' + (acct ? 'Your credit' : 'Your wallet') + '</span><b class="qd-balv">…</b><button class="qd-connect btn btn-sm" type="button" hidden>Connect wallet</button></div>' +
      '<label class="qd-lbl" for="qdAmt">Amount to fund (' + (acct ? 'USD' : 'USDC · 0 = create now, fund later') + ')</label>' +
      '<input class="qd-amt" id="qdAmt" type="number" value="5" min="' + minUsd + '" step="any" inputmode="decimal" />' +
      '<div class="qd-est">buys ≈ <b class="qd-estv"></b> of runtime</div>' +
      '<div class="qd-note" hidden></div>' +
      // the ToS gate: assent persists per terms version (core/util TOS_VERSION),
      // so returning deployers find it pre-checked. target=_blank keeps the
      // modal (and its amount) alive while the terms are read.
      '<label class="qd-tos"><input type="checkbox" class="qd-tosck"' + (tosAccepted() ? " checked" : "") + ' /> <span>I have read and agree to the <a href="terms" target="_blank" rel="noopener">Terms of Service</a> - ' +
        (acct ? 'deploys spend prepaid, non-transferable account credit, and uptime isn’t guaranteed.'
              : 'payments are crypto-only, non-custodial and final, and uptime isn’t guaranteed.') + '</span></label>' +
      '<div class="qd-actions">' +
        '<button class="btn btn-primary qd-go" type="button">▸ Deploy</button>' +
        '<button class="btn qd-cancel" type="button">Cancel</button>' +
      '</div>' +
    '</div>';
  document.body.appendChild(host);
  qdEsc = (e) => { if (e.key === "Escape") closeQuick(); };
  document.addEventListener("keydown", qdEsc);
  // pointerDOWN, not click: a text selection that starts inside the card and
  // releases over the backdrop registers as a backdrop click and would dismiss
  host.addEventListener("pointerdown", (e) => { if (e.target === host) closeQuick(); });
  const amt = host.querySelector(".qd-amt"), estv = host.querySelector(".qd-estv"), note = host.querySelector(".qd-note");
  const go = host.querySelector(".qd-go"), balv = host.querySelector(".qd-balv");
  const conn = host.querySelector(".qd-connect");
  const tos = host.querySelector(".qd-tosck");
  // Three FATAL notes can pin the Deploy button off (the create would be
  // refused, or mint an unservable record): the fleet can't run the app at
  // all (capTarget), the on-chain GPU cap is below its minimum (capCap), a
  // fee-bearing app on a credit account (capFee). First one wins the note.
  let bal = null, capTarget = null, capCap = null, capFee = null, gpuCap = null;
  const fatal = () => capTarget || capCap || capFee;
  // The amount the modal would deploy with. `zero` is a TYPED 0 on a wallet
  // deploy (create now, fund later - see minUsd); a blank box is not that
  // decision, so it deploys nothing.
  const amountOf = () => {
    const raw = parseFloat(amt.value), usd = raw > 0 ? raw : 0;
    const zero = !acct && Number.isFinite(raw) && !(raw > 0);
    return { usd, zero, ok: usd > 0 ? usd >= minUsd : zero };
  };
  const est = () => {
    const { usd, zero, ok } = amountOf();
    estv.textContent = (usd > 0 && rate > 0) ? fmtDur(usd / rate) : "–";
    const shortOnFunds = bal != null && usd > bal;
    const capMsg = fatal();   // fatal outranks the adjustable short-on-funds note
    note.hidden = !shortOnFunds && !capMsg && !zero;
    if (capMsg) note.textContent = capMsg;
    else if (shortOnFunds) note.innerHTML = acct
      ? 'That’s more than your credit balance ($' + bal.toFixed(2) + '). <a href="checkout">Add credit</a> first.'
      : "That’s more than your wallet holds ($" + bal.toFixed(2) + " USDC).";
    else if (zero) note.textContent = "Deploys with no balance: one wallet tx (gas only) creates the record, which sits inert - costing nothing - until you fund it from its row on the dashboard. An enclave that pays out to your wallet runs it for free right away.";
    go.disabled = !ok || shortOnFunds || !tos.checked || !!capMsg;
    go.title = capMsg ? "" : tos.checked ? "" : "Agree to the Terms of Service above to deploy";
  };
  // The on-chain per-deployment GPU cap decides right at open whether this app
  // is deployable at all - say so here, in the modal, not after a redirect to
  // the dashboard. It is the app's FLOOR that decides that, not what the modal
  // buys: a soft GPU slice above the cap is simply trimmed to it (the card was
  // a preference), where a REQUIRED share above the cap can never be created.
  // The check re-runs whenever the mins change (the target landing/rerouting).
  const capCheck = () => {
    capCap = (gpuCap != null && mins.gpuPct * 10 > gpuCap)
      ? "This app needs at least a " + mins.gpuPct + "% GPU share, but the platform currently caps deployments at "
        + (gpuCap / 10) + "% of a card - it can’t be deployed right now."
      : null;
  };
  depMaxGpuMilli().then(cap => {
    gpuCap = cap;
    buy = startBuy(target && !target.none ? target.spec : undefined, cap / 10, target);
    capCheck(); recalc(); est();
  }).catch(() => {});
  // whether this ledger takes the two dials independently (rev 13+)
  depSchemaRev().then(r => {
    ledgerRev = r;
    buy = startBuy(target && !target.none ? target.spec : undefined, gpuCap != null ? gpuCap / 10 : 0, target);
    recalc(); est();
  }).catch(() => {});
  // the short-on-funds "Add credit" link: boot's interceptor does the SPA
  // navigation, the modal just has to get out of the way first (modified
  // clicks open a new tab - this one should stay put, amount intact)
  note.addEventListener("click", (e) => {
    if (e.target.closest("a") && !e.metaKey && !e.ctrlKey && !e.shiftKey && !e.altKey) closeQuick();
  });
  amt.addEventListener("input", est);
  tos.addEventListener("change", () => { setTosAccepted(tos.checked); est(); });
  const paintRate = () => {
    rate = baseRate + fee;
    const rEl = host.querySelector(".qd-rate"); if (rEl) rEl.textContent = "$" + (rate * 3600).toFixed(2) + "/hr";
    // Before launch, show the app's requirements for the selected placement.
    const sEl = host.querySelector(".qd-shares");
    if (sEl){
      sEl.textContent = appResources(vspec, { resources: { gpuShare: buy.gpuPct / 100 } });
    }
    est();
  };
  // rate from the CURRENT shares (they change when the target lands/reroutes):
  // the contract's live prices when they've arrived, client math until then
  const recalc = () => {
    baseRate = pr6 ? Number(rate6Of(pr6, buy.gpuPct * 10, buy.cpuPct * 10)) / 1e6
                   : shareRates(buy.gpuPct, buy.cpuPct, target && !target.none ? target.spec : undefined).rate;
    paintRate();
  };
  depPrices6().then(pr => { pr6 = pr; recalc(); }).catch(() => {});
  // the version's publisher fee (rev-5 catalogs; 0 = free) - shown up front
  // and folded into the burn rate, since create() snapshots it into the record
  catVersionFee(app.appId, idx).then(f => {
    if (!(f > 0n)) return;
    fee = Number(f) / 1e6;
    const fEl = host.querySelector(".qd-fee");
    if (fEl){ fEl.hidden = false; fEl.textContent = "The rate includes a $" + (fee * 3600).toFixed(2) + "/hr publisher fee, paid straight to this app's publisher."; }
    // credit checkout can't forward a publisher's cut yet (relay refuses the
    // spec too) - say so here, before any passkey prompt
    if (acct) capFee = "This app charges a publisher fee, which credit deploys don’t support yet - connect a wallet to deploy it.";
    paintRate();
  }).catch(() => {});
  // WHERE this deploys: the fleet ranking (core/pricing rankEnclavesFor) -
  // only claiming enclaves, cheapest fitting box on top as
  // "auto", every other candidate user-selectable. The mins (and so the
  // rate) resize to the chosen box's hardware; a fleet that can't run the
  // app pins Deploy off with the reason instead.
  let qdRows = null, qdPick = "";
  const fleetRowsNow = async () => {
    const r = await fetch(Enclave.base.replace(/\/v1\/?$/, "") + "/enclaves", { headers: { "Accept": "application/json" } });
    if (!r.ok) throw new Error("no fleet view");
    return (await r.json()).enclaves || [];
  };
  // the current target honoring the dropdown pick; { none } when unhostable,
  // null when there is no fleet view to target from (aggregate math stays)
  const computeTarget = () => {
    if (!qdRows || !qdRows.length) return null;
    const ranked = rankEnclavesFor(vspec, qdRows);
    if (!ranked.length) return pickEnclaveFor(vspec, qdRows);
    if (qdPick){
      const hit = ranked.find((c) => c.name === qdPick);
      if (hit) return { ...hit, ranked, picked: true };
      qdPick = "";                       // the chosen box left the fleet: back to auto
    }
    return { ...ranked[0], ranked, picked: false };
  };
  // WHAT the chosen host protects, in the threat model's words (core/protection.js). The pick is a preference, not a
  // binding: any eligible host may claim the deployment first, so the other kinds that could are named too, and the
  // dashboard row then shows the host that did.
  const paintProtection = (t) => {
    const pEl = host.querySelector(".qd-prot"); if (!pEl) return;
    const p = t && !t.none && protectionOf(t.row && t.row.mode);
    pEl.hidden = !p; if (!p) { pEl.innerHTML = ""; return; }
    const others = [...new Set((t.ranked || [t]).map((c) => c.row && c.row.mode))].filter((m) => m && m !== t.row.mode)
      .map((m) => protectionOf(m)).filter(Boolean).map((x) => x.label);
    pEl.innerHTML = "Protection on " + esc(t.name) + ': <span class="qd-prot-k">' + esc(p.label) + "</span>"
      + '<span class="qd-prot-d">' + esc(p.line) + "</span>"
      + '<span class="qd-prot-d">' + (others.length ? "Another eligible host may take it first (" + esc(others.join(" or ")) + "); your dashboard shows which host did. " : "")
      + '<a href="' + PROTECTION_DOC + '" target="_blank" rel="noopener">What each host protects ↗</a></span>';
  };
  const applyTarget = (t) => {
    target = t;
    paintProtection(t);
    const tEl = host.querySelector(".qd-target");
    if (!t){ capTarget = null; if (tEl) tEl.hidden = true; capCheck(); recalc(); return; }
    if (t.none){
      capTarget = "Not deployable right now: " + t.none + ".";
      if (tEl){ tEl.hidden = false; tEl.innerHTML = "✕ " + esc(t.none); }
      est(); return;
    }
    capTarget = null;
    mins = t.mins;
    buy = startBuy(t.spec, gpuCap != null ? gpuCap / 10 : 0, t);
    if (tEl){
      const ranked = t.ranked || [t];
      // one row per enclave; the ranking head IS the auto row (value "" =
      // no explicit pick), preselected and labelled recommended - see the
      // console's renderTargetRow for the same rule
      const optOf = (c, i) => esc(c.name) + " · " + c.spec.nodeVcpus + " vCPU / " + c.spec.nodeRamGb + " GB"
        + (c.mins.gpuPct > 0 ? " · " + c.spec.cardVramGb + " GB card" : "")
        + (c.queued ? " · full, queues" : "")
        + (i === 0 ? " · recommended" : "");
      tEl.hidden = false;
      tEl.innerHTML = "⤷ deploys to <select class=\"qd-tgtsel\" title=\"Every live enclave that can host this app. The recommended box is preselected and follows the fleet; pick another to use it instead.\">"
        + ranked.map((c, i) => "<option value=\"" + (i === 0 ? "" : esc(c.name)) + "\""
            + (qdPick === c.name || (!qdPick && i === 0) ? " selected" : "") + ">" + optOf(c, i) + "</option>").join("")
        + "</select>"
        + (t.queued ? " · <b>currently full - a deploy waits in its queue</b>" : "");
      const sel = tEl.querySelector(".qd-tgtsel");
      if (sel) sel.addEventListener("change", () => { qdPick = sel.value; applyTarget(computeTarget()); });
    }
    capCheck(); recalc();
  };
  fleetRowsNow().then(rows => { qdRows = rows; applyTarget(computeTarget()); }).catch(() => {});
  const loadBal = async () => {
    if (acct){
      // credit balance instead of a wallet: the vault op draws from it
      conn.hidden = true;
      try {
        const { getVault } = await import("../core/vault.js");
        const vlt = await getVault();
        if (vlt){ bal = parseFloat(vlt.balanceUsd) || 0; balv.textContent = "$" + vlt.balanceUsd; est(); return; }
      } catch(e){}
      balv.textContent = "no credit yet"; return;
    }
    if (!Enclave.address || !Enclave.provider){ balv.textContent = "not connected"; conn.hidden = false; return; }
    conn.hidden = true;
    try { bal = await usdcBalanceOf(Enclave.address); balv.textContent = bal.toFixed(2) + " USDC"; } catch(e){}
    est();
  };
  conn.addEventListener("click", async () => {
    conn.disabled = true;
    // connecting is all a deploy needs. A relay with wallet sessions reads live status through the session
    // (started from the header's sign-in), so no host sign-in rides along; without sessions, as before
    try {
      const sessions = await import("../core/sessions.js").then((S) => S.sessionsAvailable()).catch(() => false);
      if (!Enclave.token && !sessions) await authenticate(); else await connectWallet();
    }
    catch(e){ showToast(e.message || String(e)); }
    conn.disabled = false; loadBal();
  });
  host.querySelector(".qd-cancel").addEventListener("click", closeQuick);
  go.addEventListener("click", async () => {
    const { usd, ok } = amountOf(); if (!ok) return;
    // the flow lives in the deploy chunk; it navigates to the dashboard and
    // narrates into the run log (deployOnChain never throws)
    const m = await import("./deploy.js");
    // shares are re-derived NOW against a FRESH target pick: a box that
    // filled up since the modal opened REROUTES here (the mins below come
    // from the new pick and the modal repaints), a fleet that lost the
    // hardware refuses with nothing signed, and a share below the runners'
    // floor can never be minted (created shares are immutable, funding
    // unrecoverable)
    const wanted = qdPick;
    qdRows = await fleetRowsNow().catch(() => qdRows);
    const t2 = computeTarget();
    applyTarget(t2);
    if (t2 && t2.none) return;               // the modal stays; qd-target + the note say why
    // an explicit pick that vanished fell back to auto - never silently
    // under a wallet signature: the repainted dropdown shows the new box
    if (wanted && t2 && !t2.picked){
      showToast("The selected enclave (" + wanted + ") is no longer available - switched to auto (" + t2.name + "). Review and deploy again.");
      return;
    }
    // applyTarget(t2) above re-derived `buy` against the fresh pick; on the
    // no-fleet-view path there is no target to size from, so fall back to the
    // aggregate. The SHARES BOUGHT are these, not the floors: created shares
    // are immutable, so a soft-GPU app minted at its 0% floor would need a
    // resize (a second tx) before it ever touched the card it asked for.
    const m2 = t2 && !t2.none ? buy : startBuy(undefined, gpuCap != null ? gpuCap / 10 : 0);
    // full box? the queue-confirm overlay stacks over this modal; cancel
    // keeps the user here with their amount intact
    if (!(await m.confirmQueuedDeploy(m2.gpuPct, m2.cpuPct, t2))) return;
    closeQuick();
    // the appRef IS the version record: the enclave applies its config,
    // volumes and ports from the chain - nothing rides the deployment
    m.deployOnChain({ reference: catalogRef(app.appId, idx), gpuMilli: m2.gpuPct * 10, cpuMilli: m2.cpuPct * 10,
      ports: v.ports || "", isPublic: true, fundUsd: usd, asset: "USDC",
      targetName: t2 && !t2.none ? t2.name : "" });
  });
  paintRate(); loadBal();   // paintRate fills the shares line and calls est()
}

/* ---- write side: IPFS upload + publish/verify/yank/delist txs ---- */
// Client-side sanity checks (UX + catch mistakes). NOT a security control: the
// /add endpoint is public, so Caddy's request_body max_size is the real ceiling,
// and the attested wasm-manager is the authoritative "is it a runnable component"
// gate at deploy. WebAssembly.validate() can't help: it only validates core
// modules, and Enclave apps are components, so we check the binary preamble by hand.
async function validateWasm(file){
  if (!/\.wasm$/i.test(file.name || "")) throw new EnclaveError("Pick a .wasm file.", 0);
  if (file.size < 8) throw new EnclaveError("That file is too small to be a WebAssembly module.", 0);
  if (file.size > MAX_WASM_BYTES) throw new EnclaveError("Too large: max " + MAX_WASM_MB + " MB (this file is " + (file.size / 1048576).toFixed(1) + " MB).", 0);
  const h = new Uint8Array(await file.slice(0, 8).arrayBuffer());
  if (!(h[0] === 0x00 && h[1] === 0x61 && h[2] === 0x73 && h[3] === 0x6d))    // "\0asm" magic
    throw new EnclaveError("Not a WebAssembly file (missing the \\0asm magic bytes).", 0);
  // Preamble after the magic is version:u16 + layer:u16. Key on the layer, which is
  // stable across component-version bumps: 0 = core module, 1 = component.
  // Components only, with no exceptions: a guest that needs more than 4 GiB is
  // a memory64 COMPONENT, which keeps the whole socket/HTTP surface.
  const layer = h[6] | (h[7] << 8);
  if (layer === 0)
    throw new EnclaveError("This is a core wasm module, but Enclave runs wasi:http *components*. Rebuild for wasm32-wasip2 (cargo-component), wasm32-wasip3 (see the develop guide), or — for more than 4 GiB of memory — as a memory64 component.", 0);
  if (layer !== 1) throw new EnclaveError("Unrecognized wasm preamble (layer " + layer + "); expected a wasi:http component.", 0);
  return true;
}
// wasm64 detection: does this CORE module (layer 0) declare a 64-bit linear
// memory? Reads the memory section (id 5) — the first memory's limits flags
// carry the memory64 bit (0x04). Structural, not a byte scan (there is no
// import string to key on). Lockstep with the CLI's moduleMem64 and the
// runner's wasm_manager._module_mem64 (the launch authority).
function moduleMem64(u8){
  if (u8.length < 8 || !(u8[0] === 0 && u8[1] === 0x61 && u8[2] === 0x73 && u8[3] === 0x6d) || (u8[6] | (u8[7] << 8)) !== 0) return false;
  const uleb = (buf, i) => {
    let r = 0, s = 0;
    for (;;){
      const b = buf[i++];
      if (b === undefined) throw new Error("truncated");
      r += (b & 0x7f) * 2 ** s;
      if (!(b & 0x80)) return [r, i];
      s += 7; if (s > 35) throw new Error("uleb too long");
    }
  };
  try {
    for (let i = 8; i < u8.length; ){
      const sid = u8[i];
      const [size, j] = uleb(u8, i + 1);
      if (sid === 5){                             // memory section
        const [count, k] = uleb(u8, j);
        if (count === 0) return false;
        const [flags] = uleb(u8, k);
        return (flags & 0x04) !== 0;              // limits flag bit 2: 64-bit index
      }
      i = j + size;
    }
  } catch(_){ return false; }
  return false;
}
// wasm64 COMPONENT detection: a component (layer 1) whose first memory-bearing
// core module (section id 1) declares a 64-bit memory. Lockstep with the CLI's
// componentMem64 and the runner's wasm_manager._component_mem64.
function componentMem64(u8){
  if (u8.length < 8 || !(u8[0] === 0 && u8[1] === 0x61 && u8[2] === 0x73 && u8[3] === 0x6d) || (u8[6] | (u8[7] << 8)) !== 1) return false;
  const uleb = (buf, i) => {
    let r = 0, s = 0;
    for (;;){
      const b = buf[i++];
      if (b === undefined) throw new Error("truncated");
      r += (b & 0x7f) * 2 ** s;
      if (!(b & 0x80)) return [r, i];
      s += 7; if (s > 35) throw new Error("uleb too long");
    }
  };
  const hasMemory = (m) => {
    if (m.length < 8) return false;
    for (let i = 8; i < m.length; ){
      const sid = m[i];
      const [size, j] = uleb(m, i + 1);
      if (sid === 5){ const [count] = uleb(m, j); return count > 0; }
      i = j + size;
    }
    return false;
  };
  try {
    for (let i = 8; i < u8.length; ){
      const sid = u8[i];
      const [size, j] = uleb(u8, i + 1);
      const inner = u8.subarray(j, j + size);
      if (sid === 1){                             // core module: any 64-bit memory decides
        if (hasMemory(inner) && moduleMem64(inner)) return true;
      } else if (sid === 4){                      // nested component (a wasm64 app ships composed under a wasm32 proxy)
        if (componentMem64(inner)) return true;
      }
      i = j + size;
    }
  } catch(_){ return false; }
  return false;
}

function componentContract(u8){
  const none = { wasi: null, world: null };
  if (u8.length < 8 || !(u8[0] === 0 && u8[1] === 0x61 && u8[2] === 0x73 && u8[3] === 0x6d) || (u8[6] | (u8[7] << 8)) !== 1) return none;
  const uleb = (buf, i) => {                    // -> [value, nextIndex]; throws on malformed
    let r = 0, s = 0;
    for (;;){
      const b = buf[i++];
      if (b === undefined) throw new Error("truncated");
      r += (b & 0x7f) * 2 ** s;
      if (!(b & 0x80)) return [r, i];
      s += 7; if (s > 35) throw new Error("uleb too long");
    }
  };
  const W = [0x77, 0x61, 0x73, 0x69, 0x3a];     // "wasi:"
  const exports = new Set(), dec = new TextDecoder("latin1");
  try {
    for (let i = 8; i < u8.length; ){
      const sid = u8[i];
      const [size, j] = uleb(u8, i + 1);
      if (sid === 11){                          // top-level component export section
        const pay = u8.subarray(j, j + size);
        for (let p = 0; p + W.length <= pay.length; p++){
          if (pay[p] !== W[0] || pay[p+1] !== W[1] || pay[p+2] !== W[2] || pay[p+3] !== W[3] || pay[p+4] !== W[4]) continue;
          for (let back = 1; back <= 5 && p - back >= 0; back++){
            let ln, q;
            try { [ln, q] = uleb(pay, p - back); } catch(_){ continue; }
            if (q !== p || p + ln > pay.length) continue;
            const s = dec.decode(pay.subarray(p, p + ln));
            if (/^[A-Za-z0-9:/@.+-]+$/.test(s)) exports.add(s);
            break;
          }
        }
      }
      i = j + size;
    }
  } catch(_){ return none; }
  for (const [prefix, ver] of [["wasi:http/handler@0.3.", "0.3"], ["wasi:http/incoming-handler@0.2.", "0.2"],
                               ["wasi:cli/run@0.3.", "0.3"], ["wasi:cli/run@0.2.", "0.2"]]){
    const hit = [...exports].filter(e => e.startsWith(prefix)).sort();
    if (hit.length) return { wasi: ver, world: hit[0] };
  }
  return none;
}
// Raw ASCII substring scan over component bytes — the cooperative-threads
// marker (`[thread-`) is a length-prefixed core-import name sitting verbatim
// in the binary, same as the wasi: strings above.
function hasBytes(bytes, ascii){
  const pat = Array.from(ascii, (c) => c.charCodeAt(0));
  outer: for (let i = 0; i + pat.length <= bytes.length; i++){
    for (let j = 0; j < pat.length; j++) if (bytes[i + j] !== pat[j]) continue outer;
    return true;
  }
  return false;
}
// In-flight publish upload (XHR so we get upload progress - fetch can't report
// it). Tracked module-wide: a new file pick aborts the old upload, and the
// publish path refuses to run while one is active.
let pubXhr = null, pubSeq = 0, pubWasi = null, pubThreads = false, pubSet = false, pubMem64 = false;
async function putWasm(file, onProgress){
  if (!IPFS_UPLOAD_URL) throw new EnclaveError("Direct upload isn’t configured here; paste a CID you’ve pinned (e.g. `ipfs add app.wasm`).", 0);
  if (file.size > MAX_WASM_BYTES) throw new EnclaveError("Too large: max " + MAX_WASM_MB + " MB.", 0);
  // The pin is WALLET-AUTHORIZED (closes the open-pin storage DoS): read the
  // bytes, get a one-time token bound to them (signedUploadToken), hand it to
  // the gateway. Publishing needs a wallet anyway.
  let buf;
  try { buf = await file.arrayBuffer(); }
  catch(_){ throw new EnclaveError("Couldn’t read this file to sign it" + (file.size > 500*1048576 ? " (very large files: publish with the CLI instead)." : "."), 0); }
  const headers = await signedUploadHeaders(buf, IPFS_UPLOAD_URL);
  return await new Promise((resolve, reject) => {
    // raw bytes to the validating gateway; it re-checks the wasm preamble, verifies
    // the upload token authorizes exactly these bytes, pins, and returns { cid }.
    const xhr = new XMLHttpRequest();
    xhr.open("POST", IPFS_UPLOAD_URL);
    xhr.setRequestHeader("content-type", "application/wasm");
    for (const [name,value] of Object.entries(headers)) xhr.setRequestHeader(name,value);
    xhr.responseType = "json";
    xhr.upload.onprogress = (ev) => { if (ev.lengthComputable && onProgress) onProgress(ev.loaded, ev.total); };
    xhr.onerror = () => reject(new EnclaveError("upload failed: network error", 0));
    xhr.onabort = () => reject(new EnclaveError("upload canceled", 0));
    xhr.onload = () => {
      const j = xhr.response || {};
      if (xhr.status < 200 || xhr.status >= 300) return reject(new EnclaveError("upload rejected: " + (j.error || ("HTTP " + xhr.status)), 0));
      if (!j.cid) return reject(new EnclaveError("gateway returned no CID", 0));
      // The CID is the GATEWAY's answer and it goes into the publishVersion
      // transaction the publisher signs, so it is verified against the bytes
      // before it can be published - see verifyCid below. Nothing here trusts
      // this value on its own.
      resolve(j.cid);
    };
    pubXhr = xhr;
    xhr.send(file);
  });
}


/* Upload an app image (thumbnail/banner) to the validating gateway; returns
   { cid, svg }. Small + wallet-signed like the wasm; the gateway re-checks the
   bytes (raster magic, or the strict SVG validator) and pins. `svg` is the
   GATEWAY's verdict, not the file extension - it rides _media so renderers
   can request the svg content-type (see mediaUrl). */
async function putImage(file){
  if (!IPFS_IMAGE_UPLOAD_URL) throw new EnclaveError("Image upload isn’t configured here.", 0);
  if (!/\.(png|jpe?g|webp|gif|svg)$/i.test(file.name || "") && !/^image\/(png|jpeg|webp|gif|svg\+xml)$/i.test(file.type || ""))
    throw new EnclaveError("Pick a PNG, JPEG, WebP, GIF, or SVG image.", 0);
  if (file.size > MAX_IMAGE_BYTES) throw new EnclaveError("Image too large: max " + MAX_IMAGE_MB + " MB (this is " + (file.size / 1048576).toFixed(1) + " MB).", 0);
  let buf; try { buf = await file.arrayBuffer(); } catch(_){ throw new EnclaveError("Couldn’t read this image to sign it.", 0); }
  const headers = await signedUploadHeaders(buf, IPFS_IMAGE_UPLOAD_URL);
  const r = await fetch(IPFS_IMAGE_UPLOAD_URL, { method: "POST", headers: {
    "content-type": file.type || "application/octet-stream",
    ...headers,
  }, body: buf });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.cid) throw new EnclaveError("image upload rejected: " + (j.error || ("HTTP " + r.status)), 0);
  return { cid: j.cid, svg: !!j.svg };
}
// Lock the publish path while bytes are in flight: an enabled button next to a
// CID field still holding the PREVIOUS upload's CID is how a stale CID lands
// on-chain.
function setPubUploading(on){
  const btn = $("#pubSubmit"); if (btn){ btn.disabled = on; btn.textContent = on ? "uploading…" : "Publish to Base"; }
  const cidEl = $("#pubCid"); if (cidEl) cidEl.disabled = on;
}
// Does `cid` actually address these bytes? The upload gateway chose the CID and
// the publisher is about to sign it on-chain, so its own word is not evidence:
// the token binds sha256(bytes) and ipfs-add-gateway.py re-derives it, but that
// is the gateway checking itself, which a compromised one passes by pinning the
// real bytes and answering with a CID for someone else's. Then the publisher's
// wallet attests to wasm they never saw and every deployer of that version runs
// it.
//
// So read it back from a DIFFERENT gateway (IPFS_GATEWAY, ipfs.io - not
// ipfs.enclave.host, which would be asking the same host to confirm itself) and
// compare hashes.
//
// Three outcomes, and the middle one is the point:
//   match     -> publishable
//   MISMATCH  -> refuse. A gateway that answered with a CID for other bytes is
//                the whole threat; there is no benign reading.
//   unreachable/timeout -> WARN, do not block. Propagation lag is normal and
//                refusing here would break honest publishes far more often than
//                it would catch anything.
async function verifyCid(cid, bytes){
  const want = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))]
    .map(b => b.toString(16).padStart(2, "0")).join("");
  const url = IPFS_GATEWAY.replace(/\/+$/, "") + "/" + encodeURIComponent(cid);
  let got;
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(20000), cache: "no-store" });
    if (!r.ok) return { state: "unverified", detail: "HTTP " + r.status };
    const back = new Uint8Array(await r.arrayBuffer());
    got = [...new Uint8Array(await crypto.subtle.digest("SHA-256", back))]
      .map(b => b.toString(16).padStart(2, "0")).join("");
  } catch(e){
    return { state: "unverified", detail: e.name === "TimeoutError" ? "timed out" : (e.message || String(e)) };
  }
  return got === want ? { state: "ok" } : { state: "mismatch", want, got };
}

async function ensureCatalogChain(){
  if (APP_CATALOG_CHAIN === BASE_CHAIN) return ensureBaseChain();
  const hex = "0x" + APP_CATALOG_CHAIN.toString(16);
  let cur; try { cur = await Enclave.provider.request({ method: "eth_chainId" }); } catch { cur = null; }
  if (cur && String(cur).toLowerCase() === hex) return;
  try { await Enclave.provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: hex }] }); }
  catch(e){ throw new EnclaveError("Switch your wallet to chain " + APP_CATALOG_CHAIN + " to publish.", 0); }
}
function pubStatus(msg, err){ const el = $("#pubStatus"); if (!el) return; el.textContent = msg || ""; el.className = "pub-status" + (err ? " err" : ""); }
async function onPubFile(e){
  const f = e.target.files && e.target.files[0]; if (!f) return;
  const seq = ++pubSeq;                                     // supersedes any in-flight upload
  if (pubXhr){ try { pubXhr.abort(); } catch(_){} pubXhr = null; }
  $("#pubCid").value = "";                                  // never leave the previous CID publishable
  pubWasi = null;                                           // …nor the previous file's world contract
  pubThreads = false;
  pubSet = false;
  const hint = $("#pubFileHint"), bar = $("#pubUpBar");
  const mb = (f.size / 1048576).toFixed(2);
  hint.textContent = f.name + " · " + mb + " MB";
  try { await validateWasm(f); }
  catch(err){ if (seq !== pubSeq) return; pubStatus(err.message || String(err), true); e.target.value = ""; return; }
  if (seq !== pubSeq) return;
  // world contract from the bytes (publishApp stamps it into the config);
  // classification failure is not an upload failure
  try {
    const pubBytes = new Uint8Array(await f.arrayBuffer());
    pubWasi = componentContract(pubBytes).wasi;
    // cooperative threads (🧵): the coop runtime's core module imports
    // `[thread-new-indirect-v0]` and siblings — raw byte scan, same doctrine
    // as the wasi: world scan (publishApp stamps `threads: true`)
    pubThreads = hasBytes(pubBytes, "[thread-");
    // shared-everything threads (⚡): set-componentize's `[set-spawn-indirect]`
    // marker — same raw byte scan (publishApp stamps `set: true`)
    pubSet = hasBytes(pubBytes, "[set-spawn-indirect]");
    // wasm64 (memory64): structural memory-section sniff, not a marker scan
    // (publishApp stamps `mem64: true` — claim routing to mem64 engines)
    pubMem64 = componentMem64(pubBytes);
  } catch(_){ pubWasi = null; pubThreads = false; pubSet = false; pubMem64 = false; }
  if (seq !== pubSeq) return;
  setPubUploading(true);
  if (bar){ bar.hidden = false; bar.firstElementChild.style.width = "0%"; bar.setAttribute("aria-valuenow", "0"); }
  pubStatus("valid " + (pubWasi === "0.3" ? "WASIp3 " : pubWasi === "0.2" ? "WASIp2 " : "") + (pubThreads ? "threaded " : "") + (pubSet ? "parallel " : "") + (pubMem64 ? "memory64 (>4 GiB) component" : "component") + " · uploading to IPFS… 0%");
  try {
    const cid = await putWasm(f, (done, total) => {
      if (seq !== pubSeq || !total) return;
      const pct = Math.min(100, Math.floor(done / total * 100));
      if (bar){ bar.firstElementChild.style.width = pct + "%"; bar.setAttribute("aria-valuenow", String(pct)); }
      // 100% sent != done: the gateway still validates + pins before answering
      const label = done >= total ? "upload sent · gateway validating + pinning…"
                                  : "uploading to IPFS… " + pct + "% (" + (done / 1048576).toFixed(1) + " / " + mb + " MB)";
      pubStatus(label);
      hint.textContent = f.name + " · " + mb + " MB · " + (done >= total ? "pinning…" : pct + "%");
    });
    if (seq !== pubSeq) return;
    pubStatus("pinned · verifying the CID resolves to your exact bytes…");
    const v = await verifyCid(cid, await f.arrayBuffer());
    if (seq !== pubSeq) return;
    if (v.state === "mismatch"){
      // the gateway answered with a CID addressing DIFFERENT bytes
      $("#pubCid").value = "";
      hint.textContent = f.name + " · " + mb + " MB · CID REJECTED";
      pubStatus("the upload gateway returned a CID that does not contain your file "
        + "(your bytes hash " + v.want.slice(0, 16) + "…, that CID holds " + v.got.slice(0, 16) + "…) "
        + "- nothing was published; report this before retrying", true);
      return;
    }
    $("#pubCid").value = cid;
    hint.textContent = f.name + " · " + mb + " MB · " + (v.state === "ok" ? "verified" : "pinned");
    pubStatus(v.state === "ok"
      ? "verified · CID " + cid + " resolves to your exact bytes"
      : "pinned · CID " + cid + " (could not verify via " + IPFS_GATEWAY + " yet: " + v.detail
        + " - usually propagation lag; the CID came from the upload gateway, so confirm it independently before publishing)");
  } catch(err){
    if (seq !== pubSeq) return;
    hint.textContent = f.name + " · " + mb + " MB · upload failed";
    pubStatus(err.message || String(err), true);
  } finally {
    if (seq === pubSeq){ setPubUploading(false); pubXhr = null; if (bar) bar.hidden = true; }
  }
}
async function publishApp(){
  if (pubXhr) return pubStatus("the wasm is still uploading - wait for the CID to fill in before publishing", true);
  const slug = $("#pubSlug").value.trim(), version = $("#pubVersion").value.trim();
  const cid = $("#pubCid").value.trim(), name = $("#pubName").value.trim(), desc = $("#pubDesc").value.trim();
  // the app's EXACT minimum resources on four axes, published on-chain in MB /
  // GFLOPS (runners calculate the allocation shares from them)
  const vramMb = Math.round((parseFloat($("#pubVram").value) || 0) * 1024);
  const gpuGflops = Math.round((parseFloat($("#pubGpuT").value) || 0) * 1000);
  const memMb = Math.round(parseFloat($("#pubMem").value) || 0);
  const cpuGflops = Math.round(parseFloat($("#pubCpuG").value) || 0);
  const ports = $("#pubPorts").value.split(",").map(x => x.trim().toLowerCase()).filter(Boolean).join(",");
  // your hourly fee, published on-chain in USDC 6dp per SECOND (deployers'
  // fundings pay it straight to your wallet, pro-rata; immutable per version)
  const feeUsdHr = parseFloat($("#pubFee") && $("#pubFee").value) || 0;
  const feePerSec6 = Math.round(feeUsdHr * 1e6 / 3600);
  if (feePerSec6 < 0) return pubStatus("the hourly fee can't be negative", true);
  if (!catConfigured()) return pubStatus("catalog contract address isn’t set on this site yet", true);
  if (!slug || blen(slug) > CAT_MAX.slug) return pubStatus("app slug is required (≤ 40 bytes)", true);
  if (!version || blen(version) > CAT_MAX.version) return pubStatus("version label is required (≤ 32 bytes)", true);
  if (!cid || blen(cid) > CAT_MAX.cid) return pubStatus("enter a valid IPFS CID (≤ 100 bytes)", true);
  if (!name || blen(name) > CAT_MAX.name) return pubStatus("name is required (≤ 80 bytes)", true);
  if (blen(desc) > CAT_MAX.desc) return pubStatus("description too long (≤ 500 bytes)", true);
  if (!(memMb > 0 && memMb <= CAT_MAX.mb)) return pubStatus("memory must be at least 1 MB", true);
  if (!(vramMb >= 0 && vramMb <= CAT_MAX.mb)) return pubStatus("VRAM must be 0 or more GB", true);
  if (!(gpuGflops >= 0 && gpuGflops <= CAT_MAX.gflops))
    return pubStatus("GPU compute must be 0 or more TFLOPS (0 = CPU-only)", true);
  if (!(cpuGflops >= 1 && cpuGflops <= CAT_MAX.gflops))
    return pubStatus("CPU compute must be at least 1 GFLOPS - every app computes something", true);
  if (blen(ports) > 96) return pubStatus("open-ports config too long (≤ 96 bytes)", true);
  const pErr = validPortsCsv(ports); if (pErr) return pubStatus(pErr, true);
  const cfg = readPubConfig(); if (cfg.err) return pubStatus(cfg.err, true);
  // stamp the detected world contract (`wasi: "0.2"|"0.3"`) into the version
  // config — same envelope pattern as gpuOptional/_media, and the binary is
  // the authority over anything typed in the config box (claim routing:
  // runners send wasip3 versions only to p3-capable boxes). A hand-pasted
  // CID has no bytes to classify and publishes without the key.
  if (pubWasi || pubThreads || pubSet || pubMem64){
    try {
      const o = JSON.parse(cfg.val || "{}");
      if (o && typeof o === "object" && !Array.isArray(o)){
        if (pubWasi) o.wasi = pubWasi;
        // threads: set when the binary carries the marker, dropped when it
        // doesn't — an over-declared `threads` would route claims for nothing
        if (pubThreads) o.threads = true; else delete o.threads;
        // set: same binary-authoritative both directions
        if (pubSet) o.set = true; else delete o.set;
        // mem64: same binary-authoritative both directions (claim routing to
        // engines that can parse a 64-bit memory)
        if (pubMem64) o.mem64 = true; else delete o.mem64;
        cfg.val = JSON.stringify(o);
      }
    } catch(_){ /* readPubConfig already validated shape; never block on the stamp */ }
  }
  // fold the (already-uploaded) thumbnail/banner CIDs into the version config
  // under _media - they ride in the config since the catalog contract has no
  // media field. Re-check the ceiling: media adds ~150 bytes over the app config.
  const thumbCid = ($("#pubThumbCid") && $("#pubThumbCid").value || "").trim();
  const bannerCid = ($("#pubBannerCid") && $("#pubBannerCid").value || "").trim();
  const thumbSvg = !!($("#pubThumbCid") && $("#pubThumbCid").dataset.svg);
  const bannerSvg = !!($("#pubBannerCid") && $("#pubBannerCid").dataset.svg);
  const finalConfig = withMedia(cfg.val, thumbCid, bannerCid, thumbSvg, bannerSvg);
  // The live catalog's struct revision decides both the publish encoding and
  // the config ceiling, so it is read HERE rather than after the wallet
  // connect: past the inline limit a rev-7 catalog pins the config and stores
  // its CID, while an older one has nowhere to put a CID and the inline limit
  // is still the real one.
  let rev;
  try { rev = await catSchemaRev(); }
  catch(_){ return pubStatus("couldn't read the catalog's revision (RPC trouble) - nothing was sent; try again in a moment", true); }
  const cfgCeiling = rev >= 7 ? CAT_MAX.configMax : CAT_MAX.config;
  if (blen(finalConfig) > cfgCeiling) return pubStatus("app config + image references exceed " + cfgCeiling + " bytes - shorten the config", true);
  // Pre-flight against the loaded catalog. Both cases REVERT on-chain, which a
  // wallet surfaces as a gas-estimation hang and the form as a bare timeout -
  // refuse here with the actual reason instead.
  // 1) The CID claim, mirrored at THIS catalog's revision. Since rev 8 a claim
  //    binds only while its NEWEST listing is LIVE - owner-approved and not
  //    yanked - so a rejected, yanked, or still-pending listing blocks nothing
  //    and the error must not fire on it (the chain consults only the listing
  //    its reverse-lookup points at, which is the newest one). Below rev 8 the
  //    claim is absolute: the first lister owns the bytes forever. Either way
  //    the owning app re-listing its own CID is the metadata-fix path (same
  //    bytes, new config/specs/ports) and is allowed; each version is its own
  //    deployable record (deploys reference it as catalog://appId/index, so
  //    shared bytes never make versions ambiguous).
  if (STORE.apps){
    const me = (Enclave.address || "").toLowerCase();
    // find the newest listing of these bytes across every app - the one the
    // chain's reverse-lookup points at (pre-rev-8 catalogs cannot hold
    // cross-app duplicates, so newest and first coincide there)
    let holder = null, hit = null;
    for (const a of STORE.apps)
      for (const v of a.versions || [])
        if (v.cid === cid && (!hit || Number(v.createdAt) >= Number(hit.createdAt))){ holder = a; hit = v; }
    const sameApp = hit && holder.slug === slug && me && (holder.publisher || "").toLowerCase() === me;
    const claimLive = hit && (rev < 8 || (!hit.yanked && Number(hit.approval) === APPROVAL.approved));
    if (hit && !sameApp && claimLive){
      const claim = rev >= 8
        ? "this exact .wasm is already live on-chain as " + holder.slug + " " + hit.version
          + " - bytes stay claimed while an approved release of another app lists them."
        : "this exact .wasm is already on-chain as " + holder.slug + " " + hit.version
          + " - a CID belongs to the app that first listed it.";
      // The catalog owner holds the on-chain remedy: grantCid authorizes ONE
      // other app to list an already-claimed CID (bench builds and squatters
      // both land here; since rev 8 rejecting/yanking the holding release
      // also frees the bytes, so the grant is for when that release should
      // stay live). There is no grant getter, so the chain stays the
      // arbiter - an ungranted publish still reverts with the clear message
      // in the catch below. Offered only when the TARGET app already exists
      // under the connected wallet (its appId is on-chain; a brand-new slug
      // has none yet - publish it once with different bytes first).
      const mineApp = STORE.apps.find(x => x.slug === slug && me && (x.publisher || "").toLowerCase() === me);
      if (STORE.owner && me === STORE.owner && mineApp && mineApp.appId){
        if (!confirm(claim + "\n\nAs catalog owner you can grant this CID to " + slug
            + " and publish these exact bytes (grantCid, one tx), or cancel and rebuild so the bytes change.\n\nSend the grant now, then continue publishing?"))
          return pubStatus(claim + " Publish the fix as a new version of that app, or rebuild so the bytes (and CID) change.", true);
        pubStatus("granting CID to " + slug + "…");
        await ensureCatalogChain();
        const gh = await sendTx(APP_CATALOG_ADDRESS,
          encCall(CAT_SEL.grantCid, [{t:"str",v:cid},{v:mineApp.appId}]));
        pubStatus("grant sent · " + gh + " · waiting for confirmation…");
        await waitReceipt(gh);
        pubStatus("CID granted ✓ continuing publish…");
      } else {
        return pubStatus(claim + " Publish the fix as a new version of that app, or rebuild so the bytes (and CID) change.", true);
      }
    }
    // 2) version labels are immutable history within an app (your namespace)
    const mine = STORE.apps.find(a => a.slug === slug && Enclave.address && (a.publisher || "").toLowerCase() === Enclave.address.toLowerCase());
    if (mine && (mine.versions || []).some(v => v.version === version))
      return pubStatus("version " + version + " of " + slug + " already exists - labels are immutable history; bump it (e.g. 1.0.1).", true);
  }
  const btn = $("#pubSubmit"); btn.disabled = true; const lbl = btn.textContent; btn.textContent = "working…";
  try {
    if (!Enclave.provider) await connectWallet();
    await ensureCatalogChain();
    // `rev` was read above (it also sets the config ceiling). The site ships
    // ahead of the contract cutover, so all revisions must keep working:
    // version-level config needs rev 4 - rev 3 (the retired app-level layout)
    // would silently store it where nothing reads it.
    if (rev < 4 && finalConfig){
      pubStatus("this catalog revision doesn't store per-version configs - clear the App config box and images (or publish after the rev-4 catalog cutover)", true);
      btn.disabled = false; btn.textContent = lbl; return;
    }
    if (rev < 5 && feePerSec6 > 0){
      pubStatus("this catalog revision predates publisher fees - set the hourly fee to 0 (or publish after the rev-5 catalog cutover)", true);
      btn.disabled = false; btn.textContent = lbl; return;
    }
    if (feePerSec6 > 0){
      // publishVersion reverts above the on-chain cap; refuse here with the
      // actual ceiling instead of a wallet gas-estimation hang
      const max = Number(await catMaxFeePerSec6());
      if (feePerSec6 > max){
        pubStatus("the hourly fee is capped at $" + (max * 3600 / 1e6).toFixed(2) + "/hr right now - lower it", true);
        btn.disabled = false; btn.textContent = lbl; return;
      }
    }
    // A config past the on-chain ceiling is pinned instead, and the record keeps
    // only the ROUTING MANIFEST — the keys a runner reads before it can fetch
    // anything. Done BEFORE the wallet prompt so a rejected pin doesn't leave a
    // half-finished publish.
    let onchainConfig = finalConfig, configCid = "";
    if (blen(finalConfig) > CAT_MAX.config){
      // Derive and size-check the manifest BEFORE the pin: pinning is
      // irreversible and costs the publisher's daily byte budget, so a manifest
      // that would revert publishVersionCfg must be caught first, not after.
      const full = JSON.parse(finalConfig);
      const manifest = {};
      for (const k of ROUTING_KEYS) if (full[k] !== undefined) manifest[k] = full[k];
      onchainConfig = Object.keys(manifest).length ? JSON.stringify(manifest) : "";
      if (blen(onchainConfig) > CAT_MAX.config){
        pubStatus("the on-chain routing manifest (" + ROUTING_KEYS.join(", ") + ") is "
                  + blen(onchainConfig) + " bytes, over the " + CAT_MAX.config + "-byte record limit - shorten `volumes` or `_media`", true);
        btn.disabled = false; btn.textContent = lbl; return;
      }
      pubStatus("pinning the app config…");
      configCid = await putConfig(finalConfig);
    }
    pubStatus("confirm the transaction in your wallet…");
    // uint32[4] is a STATIC array: it ABI-encodes as four inline words, exactly
    // like four consecutive uint params, so the hand-rolled encoder just takes them in order
    const args = [
      {t:"str",v:slug},{t:"str",v:name},{t:"str",v:desc},{t:"str",v:version},{t:"str",v:cid},
      {t:"uint",v:vramMb},{t:"uint",v:gpuGflops},{t:"uint",v:memMb},{t:"uint",v:cpuGflops},{t:"str",v:ports},
    ];
    const data = configCid
      ? encCall(CAT_SEL.publishVersionCfg, [...args, {t:"str",v:onchainConfig}, {t:"str",v:configCid}, {t:"uint",v:feePerSec6}])
      : rev >= 5
      ? encCall(CAT_SEL.publishVersion, [...args, {t:"str",v:onchainConfig}, {t:"uint",v:feePerSec6}])
      : rev >= 3
      ? encCall(CAT_SEL.publishVersionV4, [...args, {t:"str",v:onchainConfig}])
      : encCall(CAT_SEL.publishVersionV2, args);
    const hash = await sendTx(APP_CATALOG_ADDRESS, data);
    pubStatus("sent · " + hash + " · waiting for confirmation…");
    await waitReceipt(hash);
    pubStatus("live on-chain ✓ " + hash);
    showToast("published " + slug + " " + version);
    await loadCatalog(true);
    closePublish(); resetPublish();
  } catch(e){
    const m = e.message || String(e);
    pubStatus(/cid (already listed|listed by another app)/i.test(m)
      ? (rev >= 8
        ? "rejected on-chain: a live (approved, not yanked) release of another app claims this CID - publish the fix under that app, ask the catalog owner to free or grant the bytes, or rebuild so the bytes change"
        : "rejected on-chain: this CID already belongs to another app (a CID is owned by the app that first listed it) - publish the fix under that app, or rebuild so the bytes change")
      : m, true);
  }
  finally { btn.disabled = false; btn.textContent = lbl; }
}
/* the App config box: a default/template ENCLAVE_CONFIG JSON published WITH
   the version (immutable, covered by the version's approval - publishers can
   never change an approved release's behavior; a new config = a new version =
   Pending again). Empty is fine; otherwise a JSON object within the cap. */
/* ---- publish-form image pickers (thumbnail + banner) ----
   Each picker uploads on select (putImage -> CID, wallet-signed), shows a live
   preview, and parks the CID in a hidden input; publishApp folds both into the
   version config under _media. `kind` is "Thumb" | "Banner" (the id fragment). */
const IMG_KIND = { thumb: "Thumb", banner: "Banner" };
async function onPubImage(e, kind){
  const K = IMG_KIND[kind]; const f = e.target.files && e.target.files[0]; if (!f) return;
  const cidEl = $("#pub" + K + "Cid"), prev = $("#pub" + K + "Prev"), hint = $("#pub" + K + "Hint"), clr = $("#pub" + K + "Clear");
  let objUrl = ""; try { objUrl = URL.createObjectURL(f); prev.classList.add("has"); prev.style.backgroundImage = "url('" + objUrl + "')"; } catch(_){}
  if (hint) hint.textContent = "uploading…";
  try {
    const { cid, svg } = await putImage(f);
    if (cidEl){ cidEl.value = cid; cidEl.dataset.svg = svg ? "1" : ""; }
    prev.classList.add("has");
    prev.style.backgroundImage = "url('" + mediaUrl(cid, svg) + "')";
    if (hint){ hint.textContent = "pinned"; hint.className = "hint ok"; }
    if (clr) clr.hidden = false;
  } catch(err){
    if (cidEl){ cidEl.value = ""; cidEl.dataset.svg = ""; }
    prev.classList.remove("has"); prev.style.backgroundImage = "";
    if (hint){ hint.textContent = err.message || String(err); hint.className = "hint err"; }
    e.target.value = "";
  } finally { if (objUrl) try { URL.revokeObjectURL(objUrl); } catch(_){} }
}
function clearPubImage(kind){
  const K = IMG_KIND[kind];
  const cidEl = $("#pub"+K+"Cid"); if (cidEl){ cidEl.value = ""; cidEl.dataset.svg = ""; }
  const prev = $("#pub"+K+"Prev"); if (prev){ prev.classList.remove("has"); prev.style.backgroundImage = ""; }
  const f = $("#pub"+K+"File"); if (f) f.value = "";
  const hint = $("#pub"+K+"Hint"); if (hint){ hint.textContent = ""; hint.className = "hint"; }
  const clr = $("#pub"+K+"Clear"); if (clr) clr.hidden = true;
}
// prefill a picker from an existing CID (add-version keeps the current media)
function setPubImage(kind, cid, svg){
  const K = IMG_KIND[kind];
  const cidEl = $("#pub"+K+"Cid"); if (cidEl){ cidEl.value = cid || ""; cidEl.dataset.svg = svg ? "1" : ""; }
  const prev = $("#pub"+K+"Prev");
  if (prev){ prev.classList.toggle("has", !!cid); prev.style.backgroundImage = cid ? "url('" + mediaUrl(cid, svg) + "')" : ""; }
  const clr = $("#pub"+K+"Clear"); if (clr) clr.hidden = !cid;
}
/* The publisher's GPU-need switch. It rides IN the version config as
   `gpuOptional: true` rather than a new on-chain column: config is already
   immutable per version, approved with it, and already where platform-read keys
   live (`volumes`). Only the app knows whether it degrades to CPU or cannot
   start without a card, and on-chain the vram/gflops axes are just numbers.

   Only offered when the version actually declares GPU specs — with both axes 0
   there is no requirement to soften, and runners refuse the flag rather than
   accept a no-op. Hiding it also RESETS it, so a spec edited down to 0 can't
   leave a stale `gpuOptional` in the published config. */
let pubGpuOptional = false;
function syncPubGpuNeed(){
  const declares = (parseFloat(($("#pubVram") || {}).value) || 0) > 0
                || (parseFloat(($("#pubGpuT") || {}).value) || 0) > 0;
  if (!declares) pubGpuOptional = false;
  const f = $("#pubGpuNeedField"); if (f) f.hidden = !declares;
  $$("#pubGpuNeed button").forEach(b => {
    const on = (b.dataset.gpuneed === "1") === !!pubGpuOptional;
    b.classList.toggle("on", on); b.setAttribute("aria-pressed", on ? "true" : "false");
  });
  const n = $("#pubGpuNeedNote");
  if (n) n.textContent = !declares ? ""
    : pubGpuOptional
      ? "Desired: the app starts without a card. Runners set NO GPU floor, so a deployment may buy 0% GPU and any enclave — including CPU-only ones — can serve it. The figures above become the slice a deployer buys to actually get the card."
      : "Required: the figures above are a hard minimum. Only a GPU enclave can run this app, and every deployment must buy at least the share they imply.";
  syncPubNoGpu();   // the coreless sizing exists only under "Desired" - and is reset when it doesn't
}
/* The coreless sizing, beside the GPU-need switch and for the same reason: the
   record holds ONE set of four axes, and on a soft-GPU app they describe this
   app beside the card it asked for - its own memory, with the weights resident
   in a VRAM slice. Serve it on cores and those weights move into node RAM next
   to the guest and every matmul becomes the node's work, which is a different
   node slice by a long way. Nothing on-chain can say that, so it rides in the
   config as `cpuFallback` and runners size a coreless placement from it.

   Offered only where "Desired" is: a Required card means there IS no coreless
   placement to size, and hiding the field RESETS it so a version switched back
   to Required can't ship a stale figure. Zeros mean "not declared" and the
   on-chain axes hold both ways - today's behaviour, unchanged. */
function syncPubNoGpu(){
  const f = $("#pubNoGpuField"); if (f) f.hidden = !pubGpuOptional;
  if (!pubGpuOptional){
    const m = $("#pubNoGpuMem"), c = $("#pubNoGpuCpuG");
    if (m) m.value = "0"; if (c) c.value = "0";
  }
  const n = $("#pubNoGpuNote");
  if (!n) return;
  const mem = Math.round(parseFloat(($("#pubNoGpuMem") || {}).value) || 0);
  const gf = Math.round(parseFloat(($("#pubNoGpuCpuG") || {}).value) || 0);
  n.textContent = !pubGpuOptional ? ""
    : (mem > 0 || gf > 0)
      ? "On an enclave with no card this app is sized at " + (mem > 0 ? mem + " MB RAM" : "")
        + (mem > 0 && gf > 0 ? " / " : "") + (gf > 0 ? gf + " GFLOPS CPU" : "")
        + " instead of the two fields above. A deployment dialled for the card case is refused by CPU-only enclaves rather than served too small - it keeps running wherever a card is."
      : "Left at 0, a coreless placement is sized by Memory and CPU compute above - the figures that describe this app WITH its card. If the weights it would hold on the card live in node RAM instead, say so here, or such a deployment lands on a node slice too small to start.";
}
function readPubConfig(){
  const raw = ($("#pubConfig") && $("#pubConfig").value || "").trim();
  if (!raw && !pubGpuOptional) return { val: "" };   // nothing to carry: no editor text, and no GPU-need/cpuFallback keys to stamp
  let o;
  try {
    o = raw ? JSON.parse(raw) : {};
    if (!o || Array.isArray(o) || typeof o !== "object") return { err: "app config must be a JSON object, e.g. {\"api_key\":\"…\"}" };
  } catch(e){ return { err: "app config isn't valid JSON (" + e.message + ")" }; }
  if (pubGpuOptional) o.gpuOptional = true; else delete o.gpuOptional;
  // ...and the node figures for the placement gpuOptional opens. Written only
  // when declared and only alongside it: `cpuFallback` on a Required-card
  // version sizes a placement that can never happen.
  const fbMem = Math.round(parseFloat(($("#pubNoGpuMem") || {}).value) || 0);
  const fbGf = Math.round(parseFloat(($("#pubNoGpuCpuG") || {}).value) || 0);
  if (pubGpuOptional && (fbMem > 0 || fbGf > 0)){
    if (fbMem < 0 || fbMem > 1048576) return { err: "\"without a card\" memory must be 0..1048576 MB" };
    if (fbGf < 0 || fbGf > 10000000) return { err: "\"without a card\" CPU compute must be 0..10000000 GFLOPS" };
    o.cpuFallback = {};
    if (fbMem > 0) o.cpuFallback.memMb = fbMem;
    if (fbGf > 0) o.cpuFallback.cpuGflops = fbGf;
  } else delete o.cpuFallback;
  // measure the minified form - withMedia re-serializes before publishing, so
  // pretty-printed whitespace in the editor never counts against the ceiling
  const val = JSON.stringify(o);
  // the hard ceiling: above CAT_MAX.config the publish path pins the config and
  // the record carries its CID, so only the pin/runner limit still binds
  if (blen(val) > CAT_MAX.configMax) return { err: "app config too long (≤ " + CAT_MAX.configMax + " bytes)" };
  return { val };
}
// pretty-print a config JSON string for the editor (on-chain configs are
// minified); non-JSON passes through untouched
function prettyConfig(s){
  if (!s) return "";
  try { return JSON.stringify(JSON.parse(s), null, 2); } catch(e){ return s; }
}

/* `write` names the record field this transaction sets ({appId, idx, field,
   value}; idx null = the app row itself). Once the receipt lands that value is
   what the chain holds, so it is painted from the receipt - not from the
   re-read, which at that instant is the likeliest read in the whole session to
   fail or answer from an unindexed replica (see noteCatalogWrite). */
async function catTx(data, verb, write){
  try {
    if (!Enclave.provider) await connectWallet();
    await ensureCatalogChain();
    const hash = await sendTx(APP_CATALOG_ADDRESS, data);
    showToast(verb + " · " + hash.slice(0, 12) + "…");
    await waitReceipt(hash);
    if (write) noteCatalogWrite(write.appId, write.idx, write.field, write.value);   // repaints on the spot
    // the re-read is now a background reconciliation: it picks up anything else
    // that moved, and its failure costs the owner nothing worth a toast
    if (!(await loadCatalog(true, { quiet: !!write })) && write)
      setTimeout(() => loadCatalog(true, { quiet: true }), 8000);
  } catch(e){ showToast(e.message || String(e)); }
}
const setActiveTx   = (app, active)  => catTx(encCall(CAT_SEL.setActive,   [{t:"str",v:app.slug},{t:"bool",v:active}]), active ? "relisting" : "delisting",
                                              { appId: app.appId, idx: null, field: "active", value: active });
const yankTx        = (app, idx)     => catTx(encCall(CAT_SEL.yankVersion, [{t:"str",v:app.slug},{t:"uint",v:idx}]),   "yanking",
                                              { appId: app.appId, idx, field: "yanked", value: true });
const setVerifiedTx = (appId, idx, v) => catTx(encCall(CAT_SEL.setVerified, [{t:"bytes32",v:appId},{t:"uint",v:idx},{t:"bool",v:v}]), v ? "verifying" : "unverifying",
                                              { appId, idx, field: "verified", value: v });
// owner-only deploy gate: the wallet signature on this tx IS the approval/rejection
const setApprovalTx = (appId, idx, st) => catTx(encCall(CAT_SEL.setApproval, [{t:"bytes32",v:appId},{t:"uint",v:idx},{t:"uint",v:st}]), st === APPROVAL.approved ? "approving" : "rejecting",
                                              { appId, idx, field: "approval", value: st });

/* ---- reviews (EnclaveReviews) ----
   Same shape as catTx, against the reviews contract: the wallet signature IS
   the review. The block re-reads afterwards so the average moves without a
   page refresh. */
async function revTx(data, verb){
  if (!Enclave.provider) await connectWallet();
  await ensureCatalogChain();
  const hash = await sendTx(REVIEWS_ADDRESS, data);
  showToast(verb + " · " + hash.slice(0, 12) + "…");
  await waitReceipt(hash);
  return hash;
}
async function postReviewTx(block, app, stars, body, deploymentId){
  block.setBusy(true);
  try {
    if (!Enclave.provider) await connectWallet();
    // the chain is the authority on eligibility: ask it before the wallet
    // opens, so a stale receipt reads as a sentence, not a reverted tx
    if (!(await confirmReceipt(app.appId, deploymentId))){
      block.recheckReceipt();
      throw new EnclaveError("That deployment no longer proves you ran this app - reload and try again.", 0);
    }
    await revTx(encCall(REV_SEL.post, [{ t:"bytes32", v: app.appId }, { t:"bytes32", v: deploymentId },
                                       { t:"uint", v: stars }, { t:"str", v: body || "" }]), "posting review");
    block.clearDraft();
    await loadReviews(app.appId, true);
    showToast("review posted · thanks");
  } catch(e){
    showToast(e && (e.code === 4001 || /reject|denied|declin|cancell/i.test(e.message || ""))
      ? "review canceled: you declined the wallet signature." : (e.message || String(e)));
  }
  block.setBusy(false);
}
async function hideReviewTx(block, app, reviewer, hidden){
  block.setBusy(true);
  try {
    await revTx(encCall(REV_SEL.setHidden, [{ t:"bytes32", v: app.appId }, { t:"addr", v: reviewer }, { t:"bool", v: hidden }]),
      hidden ? "hiding review" : "unhiding review");
    await loadReviews(app.appId, true);
  } catch(e){ showToast(e.message || String(e)); }
  block.setBusy(false);
}
function onReviewAction(e){
  const { act, app, stars, body, deploymentId, reviewer, hidden } = e.detail;
  const block = e.target.closest("c-app-reviews");
  if (act === "connect"){ connectWallet().then(() => block && block.recheckReceipt()).catch(err => showToast(err.message || String(err))); return; }
  if (!block || !app) return;
  if (act === "post") postReviewTx(block, app, stars, body, deploymentId);
  else if (act === "hide" || act === "unhide"){
    if (act === "hide" && !confirm("Hide this review? It stays on-chain but drops out of the app's rating - use this for abuse, not for criticism.")) return;
    hideReviewTx(block, app, reviewer, hidden);
  }
}

function resetPublish(){
  pubSeq++;                                                  // orphan any in-flight upload's callbacks
  if (pubXhr){ try { pubXhr.abort(); } catch(_){} pubXhr = null; }
  setPubUploading(false);
  const bar = $("#pubUpBar"); if (bar) bar.hidden = true;
  ["#pubSlug","#pubCid","#pubName","#pubDesc","#pubPorts","#pubConfig"].forEach(s => { const el = $(s); if (el) el.value = ""; });
  const f = $("#pubFile"); if (f) f.value = ""; const h = $("#pubFileHint"); if (h) h.textContent = "";
  clearPubImage("thumb"); clearPubImage("banner");
  $("#pubVersion").value = "1.0.0"; $("#pubVram").value = "0"; $("#pubGpuT").value = "0";
  $("#pubMem").value = "128"; $("#pubCpuG").value = "1"; pubStatus("");
  const nm = $("#pubNoGpuMem"), nc = $("#pubNoGpuCpuG");
  if (nm) nm.value = "0"; if (nc) nc.value = "0";
  pubGpuOptional = false; syncPubGpuNeed();   // hides and clears the coreless sizing too
}
// "1.0.0" -> "1.0.1", "v2" -> "v3", "2.1.0-beta" -> "2.1.1-beta": bump the last
// number in the label; it's a suggestion, the field stays editable.
function bumpVersion(s){
  const m = /^(.*?)(\d+)(\D*)$/.exec(s || "");
  return m ? m[1] + (parseInt(m[2], 10) + 1) + m[3] : (s ? s + ".1" : "1.0.1");
}
// version labels are unique per app FOREVER (yanked ones stay taken), so the
// suggested next version must skip every existing label - including yanked
// versions above the selected one - until it lands on a free label.
function nextFreeVersion(app, from){
  const taken = new Set((app.versions || []).map(v => v && v.version));
  let cand = bumpVersion(from);
  for (let i = 0; i < 1000 && taken.has(cand); i++) cand = bumpVersion(cand);
  return cand;
}
// The "add version" prefill for one of an app's versions, as a plain object -
// built both by the button (which stashes it) and by a refresh of
// /apps/publish?app=… (which re-derives it from the catalog).
/* One rule governs this function: on a rev-7 version, `v.config` IS NOT THE
   CONFIG. It is the ROUTING MANIFEST — {wasi, threads, set, gpuOptional,
   volumes, _media}, ~269 bytes — and the real config lives at v.configCid.
   Prefilling from the inline field therefore hands "add version" a stub, and
   because the form is the publish payload, pressing Publish writes that stub
   as the new version's config. Not a display glitch: a silent downgrade that
   ships. eyesoff-ai 1.0.13 was published that way on 2026-08-11 — 269 bytes of
   manifest where 1.0.12 had a 6,996-byte config — and nothing in the flow said
   a word.

   So the CID is resolved here, and a resolution FAILURE is never allowed to
   degrade into the manifest. An empty box with a loud note costs the publisher
   a retry; a manifest silently costs them their config. */
async function publishPrefillOf(app, vi){
  const v = app.versions[vi] || app.versions[app.versions.length - 1] || {};
  const media = mediaOf(v);
  let config = v.config || "", lost = "";
  if (v.configCid){
    const real = await fetchConfigCid(v.configCid);
    if (real == null){
      config = "";
      lost = " ⚠ could not load this version's config from " + v.configCid
           + " — the box below is EMPTY, not the real config. Reload before publishing, or the new version ships without it.";
    } else config = real;
  }
  return {
    slug: app.slug, name: app.name || "", desc: app.description || "",
    version: nextFreeVersion(app, v.version), cid: v.cid || "",
    vram: String((Number(v.vramMb) || 0) / 1024), gpuT: String((Number(v.gpuGflops) || 0) / 1000),
    mem: String(Number(v.memMb) || 128), cpuG: String(Math.max(1, Number(v.cpuGflops) || 1)),
    ports: v.ports || "", config: prettyConfig(stripMedia(config)),
    gpuOptional: (() => { try { return JSON.parse(config || "{}").gpuOptional === true; } catch { return false; } })(),
    cpuFallback: cpuFallbackOfConfig(config),
    thumb: media.thumbnail || "", banner: media.banner || "",
    thumbSvg: !!media.thumbnailSvg, bannerSvg: !!media.bannerSvg,
    note: "pre-filled from " + app.slug + " " + (v.version || "") + " - fix specs/ports and publish (same bytes), or pick a new .wasm if the code changed"
          + (app.active ? "" : " · publishing relists the app") + lost,
  };
}
// "add version": open the publish form pre-filled from an app's current
// version - INCLUDING its CID. Re-listing your own CID is the metadata-fix
// path (same bytes, corrected specs/ports); picking a new .wasm replaces it.
async function prefillPublish(app){
  const vi = selIdx(app);
  // stash, then navigate: "add version" fires from the app's own page
  // (apps?app=…), whose URL search differs from /apps/publish, so the router
  // SWAPS <main> - a form filled before the swap would be wiped. Persist the
  // prefill and let the publish view apply it after it mounts.
  // The app + picked version ALSO ride the URL (?app=<appId>&v=<idx>): the
  // stash is single-use, so a refresh/back/shared link rebuilds the same
  // prefill from the catalog off the URL instead.
  try { sessionStorage.setItem("enclave_prefill_publish", JSON.stringify(await publishPrefillOf(app, vi))); } catch(e){}
  openPublish(app.appId, vi);
}
// Fill the form from a prefill: the stashed one when "add version" just
// navigated here, else one re-derived from ?app=<appId>[&v=<idx>] (refresh,
// back/forward, shared link). Applied once per publish-view ENTRY - catalog/
// wallet repaints while the view is up must never wipe what the user typed.
let appliedPubKey = null;   // the ?app|v this entry already applied (cleared on leave)
async function applyPrefillPublish(){
  if (!$("#pubSlug")) return;
  let s; try { s = JSON.parse(sessionStorage.getItem("enclave_prefill_publish") || "null"); } catch(e){}
  const q = new URLSearchParams(location.search);
  const key = q.get("app") ? q.get("app") + "|" + (q.get("v") || "") : null;
  if (s){
    sessionStorage.removeItem("enclave_prefill_publish");
  } else {
    if (!key || key === appliedPubKey || !STORE.loaded) return;   // nothing to do, done already, or the catalog read is still in flight (renderActiveView retries on enclave:catalog)
    const appId = q.get("app");
    const app = STORE.byId[appId] || (STORE.apps || []).find(a => a.appId === appId);
    if (!app){ appliedPubKey = key; return; }   // unknown app: keep the blank form, stop retrying
    let vi = parseInt(q.get("v") ?? "", 10);
    if (!(Number.isInteger(vi) && vi >= 0 && vi < app.versions.length)) vi = selIdx(app);
    // claim the key BEFORE the await: the config fetch is a network round trip
    // and renderActiveView fires again on enclave:catalog, which would
    // otherwise start a second prefill and race this one into the form.
    appliedPubKey = key;
    s = await publishPrefillOf(app, vi);
    if (!$("#pubSlug")) return;            // navigated away mid-fetch
  }
  appliedPubKey = key;
  resetPublish();
  $("#pubSlug").value = s.slug || ""; $("#pubName").value = s.name || ""; $("#pubDesc").value = s.desc || "";
  $("#pubVersion").value = s.version || "1.0.0"; $("#pubCid").value = s.cid || "";
  $("#pubVram").value = s.vram || "0"; $("#pubGpuT").value = s.gpuT || "0";
  $("#pubMem").value = s.mem || "128"; $("#pubCpuG").value = s.cpuG || "1"; $("#pubPorts").value = s.ports || "";
  const pc = $("#pubConfig"); if (pc) pc.value = s.config || "";
  const nm = $("#pubNoGpuMem"), nc = $("#pubNoGpuCpuG");
  if (nm) nm.value = String((s.cpuFallback && s.cpuFallback.memMb) || 0);
  if (nc) nc.value = String((s.cpuFallback && s.cpuFallback.cpuGflops) || 0);
  pubGpuOptional = !!s.gpuOptional; syncPubGpuNeed();   // also syncs the coreless fields
  setPubImage("thumb", s.thumb || "", !!s.thumbSvg); setPubImage("banner", s.banner || "", !!s.bannerSvg);
  pubStatus(s.note || "");
}
/* ============================================================
   Hash-routed sub-page that replaces the store content
   (deliberately not a header tab):
     apps.html#publish - the publish form (/apps/publish is its
                         router alias; the legacy hash canonicalizes)
   Plain hash navigation gives us history, back/forward, and
   shareable links for free; the soft-nav router ignores '#'
   hrefs, so there's no double handling. The old deploy console
   (/apps/deploy) is gone: an app deploys from its card, and
   everything it used to configure is a tab on the dashboard row.
   ============================================================ */
function applyView(){
  const store = $("#storeView"), pub = $("#publishView"), det = $("#appDetailView");
  if (!store || !pub) return;
  // the PATHNAME names the view now (/apps/publish is a router alias of this
  // page); the legacy #publish hash stays honored and canonicalizes in place
  // to the pretty nested pathname (document.baseURI = the site root - the
  // alias document carries <base>)
  const sub = location.pathname.split("/").pop();
  const view = sub === "publish" || location.hash === "#publish" ? "publish" : "store";
  if (sub !== view && location.hash === "#publish")
    // a bare #publish (the toolbar link) must NOT inherit the detail page's
    // ?app - on /apps/publish that param means "prefill this app", which only
    // the Add version button intends
    history.replaceState(history.state, "", new URL(".", document.baseURI).pathname + "apps/publish");
  // the base Apps view splits into the grid and a single app's page: apps?app=<appId>
  const appId = view === "store" ? new URLSearchParams(location.search).get("app") : null;
  const detail = !!appId;
  store.hidden = view !== "store" || detail;
  if (det) det.hidden = !detail;
  pub.hidden = view !== "publish";
  document.title = view === "publish" ? "Publish · Enclave" : "Apps · Enclave";
  if (view !== "publish") appliedPubKey = null;         // next publish entry applies its prefill fresh
  if (view === "publish") applyPrefillPublish().catch(() => {});   // stashed "add version" prefill, or one rebuilt from ?app=<appId>&v=<idx>
  else if (detail) renderDetail(appId);
  else renderApps();   // the page size depends on the grid's real width - re-slice now that the store view is visible
  scrollTo(0, 0);
}
/* one app's full page (apps?app=<appId>) - renders <c-app-detail> into the
   detail wrap; re-run on catalog/wallet edges like the grid (renderActiveView) */
function renderDetail(appId){
  const host = $("#appDetailView"); if (!host) return;
  appId = appId || new URLSearchParams(location.search).get("app");
  if (!appId){ navigate("apps", { push: false }); return; }
  if (!catConfigured()){ host.innerHTML = '<div class="store-note">The on-chain catalog isn’t wired up on this deployment yet.</div>'; return; }
  if (!STORE.loaded){ host.innerHTML = '<div class="loading" role="status">reading catalog from Base…</div>'; return; }
  const app = STORE.byId[appId] || (STORE.apps || []).find(a => a.appId === appId);
  // Moderated history remains visible to its publisher and the catalog administrator.
  if (!app || !visibleVerIdxs(app).length || !(appApproved(app) || appVerified(app) || appPrivileged(app))){ host.innerHTML = '<div class="store-note">That app isn’t in the catalog. <a href="apps">← all apps</a></div>'; document.title = "Apps · Enclave"; return; }
  document.title = app.name + " · Enclave";
  let el = host.querySelector("c-app-detail");
  if (!el){ host.innerHTML = ""; el = document.createElement("c-app-detail"); host.appendChild(el); }
  el.app = app;
  // the ratings block is a SIBLING of the detail card, not part of it: it owns
  // its own reads (the reviews themselves) and its own lifecycle
  if (revConfigured()){
    let rv = host.querySelector("c-app-reviews");
    if (!rv){ rv = document.createElement("c-app-reviews"); host.appendChild(rv); }
    rv.app = app;
  }
}
/* pick the renderer for whichever view is live (grid vs a single app's page),
   so catalog/wallet refreshes repaint the right one */
function renderActiveView(){
  const sub = location.pathname.split("/").pop();
  // publish entered by URL (refresh/shared link): the ?app prefill may have
  // been waiting on this catalog read - idempotent via appliedPubKey
  if (sub === "publish") return void applyPrefillPublish().catch(() => {});
  const appId = new URLSearchParams(location.search).get("app");
  if (appId) renderDetail(appId); else renderApps();   // renderApps owns the featured head and its note
}
/* the toolbar's ↻ - a real re-read of the catalog (past the 2-minute freshness
   window), with the BUTTON as the progress indicator: its glyph spins and the
   grid stays up, dimmed, behind it. The last good paint is never traded for a
   skeleton, so a slow or rate-limited RPC round can't cost the visitor the apps
   they were looking at - and the repaint lands in whichever tab is selected,
   since renderActiveView re-runs the current filter over the fresh read. */
let refreshing = false;
async function refreshStore(){
  const btn = $("#storeRefresh"); if (!btn || refreshing) return;
  refreshing = true;
  btn.classList.add("busy"); btn.disabled = true;
  const grid = $("#storeGrid"); if (grid) grid.setAttribute("aria-busy", "true");
  try {
    // a read already in flight (the boot one) is the same read this click wants;
    // loadCatalog() would return instantly on its guard, so ride that one instead
    const cat = STORE.loading ? nextEvent("enclave:catalog") : loadCatalog(true);
    await Promise.all([cat, loadCampaigns(true)]);   // the featured group rides the same refresh
  } finally {
    refreshing = false;
    btn.classList.remove("busy"); btn.disabled = false;
    if (grid) grid.removeAttribute("aria-busy");
    forceTallies = true;    // ratings are their own read - re-read them for the repainted page
    renderActiveView();
  }
}
// resolve on the next `name` event, or after ms - a read that never lands (or
// dies before it emits) must not leave the spinner turning forever
const nextEvent = (name, ms = 20000) => new Promise(resolve => {
  const done = () => { clearTimeout(t); document.removeEventListener(name, done); resolve(); };
  const t = setTimeout(done, ms);
  document.addEventListener(name, done);
});
function openPublish(appId, vi){
  // same-document pathname flip: the router pushes /publish and re-signals
  // the view (no fetch, no <main> swap - apps/publish share one).
  // ?app=<appId>[&v=<idx>] makes the prefill survive a refresh: the URL is
  // the durable copy of what the single-use stash carries.
  navigate("publish" + (appId ? "?app=" + encodeURIComponent(appId) + (vi != null && vi >= 0 ? "&v=" + vi : "") : ""),
           { push: true });
}
function closePublish(){
  navigate("apps", { push: true });
}
// module-load-once; inert while another page's <main> is mounted
addEventListener("hashchange", () => { if (document.getElementById("publishView")) applyView(); });
function initStore(){
  const grid = $("#storeGrid"); if (!grid) return;
  // provenance mark: one icon straight to the catalog contract on Basescan
  // (Steven's call); full name + address in the tooltip
  const link = $("#catAddrLink");
  if (link){
    if (catConfigured()){ link.href = catExplorer() + "/address/" + APP_CATALOG_ADDRESS; link.title = "EnclaveAppCatalog · " + APP_CATALOG_ADDRESS; }
    else link.hidden = true;
  }
  $$("#storeFilter button").forEach(b => b.addEventListener("click", () => {
    $$("#storeFilter button").forEach(x => { x.classList.toggle("on", x === b); x.setAttribute("aria-pressed", String(x === b)); });
    STORE.filter = b.dataset.filter; storePage = 0; renderApps();
  }));
  // the swapped-in <main> ships Approved pre-lit, but the FILTER is module
  // state that survives soft navigations - stamp the buttons from it, or an
  // owner who left on Pending comes back to the pending QUEUE rendered under
  // a lit Approved tab (an "empty apps page" whenever the queue is empty)
  $$("#storeFilter button").forEach(x => { const sel = x.dataset.filter === STORE.filter; x.classList.toggle("on", sel); x.setAttribute("aria-pressed", String(sel)); });
  const s = $("#storeSearch"); if (s) s.addEventListener("input", () => { storePage = 0; renderApps(); });
  const pp = $("#pagePrev"); if (pp) pp.addEventListener("click", () => { storePage--; renderApps(); });
  const pn = $("#pageNext"); if (pn) pn.addEventListener("click", () => { storePage++; renderApps(); });
  const rf = $("#storeRefresh"); if (rf) rf.addEventListener("click", refreshStore);
  $("#pubCancel").addEventListener("click", closePublish);   // (+ Publish app is a plain <a href="#publish">)
  $("#pubSubmit").addEventListener("click", publishApp);
  const pf = $("#pubFile"); if (pf) pf.addEventListener("change", onPubFile);
  // the GPU-need switch, and the spec fields that decide whether it applies at all
  const gn = $("#pubGpuNeed");
  if (gn) gn.addEventListener("click", (e) => {
    const b = e.target.closest("button[data-gpuneed]"); if (!b) return;
    pubGpuOptional = b.dataset.gpuneed === "1"; syncPubGpuNeed();
  });
  ["#pubVram", "#pubGpuT"].forEach((sel) => { const el = $(sel); if (el) el.addEventListener("input", syncPubGpuNeed); });
  // the coreless sizing repaints its own note; the switch above owns whether it shows at all
  ["#pubNoGpuMem", "#pubNoGpuCpuG"].forEach((sel) => { const el = $(sel); if (el) el.addEventListener("input", syncPubNoGpu); });
  const row = $("#pubFileRow");
  if (row && !IPFS_UPLOAD_URL){ row.classList.add("disabled"); $("#pubFileHint").textContent = "upload disabled here; paste a CID below"; }
  const tf = $("#pubThumbFile"); if (tf) tf.addEventListener("change", (e) => onPubImage(e, "thumb"));
  const bf = $("#pubBannerFile"); if (bf) bf.addEventListener("change", (e) => onPubImage(e, "banner"));
  const tc = $("#pubThumbClear"); if (tc) tc.addEventListener("click", () => clearPubImage("thumb"));
  const bc = $("#pubBannerClear"); if (bc) bc.addEventListener("click", () => clearPubImage("banner"));
  const pm = $(".pub-media"); if (pm && !IPFS_IMAGE_UPLOAD_URL) pm.hidden = true;   // no image gateway here

  // wallet-tx / navigation actions the cards + detail page bubble up (data
  // down, events up) - the grid tile opens the page, the page carries the rest
  grid.addEventListener("card-action", onCardAction);
  const det = $("#appDetailView");
  if (det){ det.addEventListener("card-action", onCardAction); det.addEventListener("review-action", onReviewAction); }
}
function onCardAction(e){
  const { app, act, idx, verified } = e.detail;
  if (act === "open"){ navigate("apps?app=" + encodeURIComponent(app.appId), { push: true }); return; }
  if (act === "deploy") quickDeploy(app, app.versions[idx], idx);
  else if (act === "delist"){ if (confirm("Delist this whole app? It stays on-chain but is hidden from the store - you (and the catalog owner) still see it here, with a relist button.")) setActiveTx(app, false); }
  else if (act === "relist") setActiveTx(app, true);
  else if (act === "newver") prefillPublish(app).catch(() => {});
  else if (act === "yank"){ if (confirm("Yank version " + app.versions[idx].version + "? It stays on-chain but readers hide it.")) yankTx(app, idx); }
  else if (act === "verify") setVerifiedTx(app.appId, idx, verified);
  else if (act === "approve") setApprovalTx(app.appId, idx, APPROVAL.approved);
  else if (act === "reject"){ if (confirm("Reject version " + app.versions[idx].version + "? The enclave will refuse to deploy it until you approve it.")) setApprovalTx(app.appId, idx, APPROVAL.rejected); }
}

/* ============================================================
   boot
   ============================================================ */
on("enclave:catalog", (d) => {
  if (d.type === "error"){
    // a background reconciliation behind a write we already painted from its
    // receipt: the page is showing the confirmed state, so a failed read here
    // is nothing the owner has to act on (it retries on its own)
    if (d.quiet) return;
    if (STORE.apps && STORE.apps.length)          // stale view beats an error wall
      showToast("catalog refresh failed (" + d.message + ") · showing the last good read");
    else {
      const grid = $("#storeGrid");
      if (grid) grid.innerHTML = '<div class="store-note">Couldn’t read the catalog: ' + esc(d.message)
        + '<br><span class="dim">All public Base RPC endpoints refused - usually a transient rate limit; try Refresh in a moment.</span></div>';
    }
    return;
  }
  renderActiveView();
});
on("enclave:wallet", () => { if (STORE.loaded) renderActiveView(); });   // publisher/owner buttons follow the connected wallet
// campaign reads land after the catalog. Repaint only a grid somebody is
// looking at: on an app's detail page or Publish the store view is mounted but
// hidden, and applyView() renders it when it comes back.
on("enclave:featured", () => { if (STORE.loaded && storeVisible()) renderApps(); });
// ...and when the tab returns to the foreground, so a promoted card that was
// rendered into a background tab is metered when it is actually seen.
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && STORE.loaded && storeVisible()) renderApps();
});
// ratings land after the grid paints (and after a review tx) - repaint the
// tiles/detail so the stars appear without a navigation
on("enclave:reviews", (d) => { if (d.type !== "error" && STORE.loaded) renderActiveView(); });
// (the subscriptions are module-load-once; renderApps null-guards
// their mounts, so they're inert while another page's <main> is mounted)

/* called by the router every time this page's <main> is swapped in */
export function boot() {
  initStore();
  applyView();          // direct entries and soft-navs to apps.html#publish land on the publish view
  renderActiveView();   // grid, or a single app's page when apps?app=<appId>
  loadCatalog();
  loadCampaigns();      // featured-group bids (no-op until the contract is in the address book)
  // adopt the fleet's real hardware into the share math before anyone opens
  // quick-deploy - minimum dials divide by these numbers (see core/pricing.js)
  Enclave.getAvailability().catch(() => {});
}
