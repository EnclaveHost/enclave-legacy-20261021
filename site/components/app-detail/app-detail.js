/* ============================================================
   <c-app-detail> - one app's full page: banner, name, badges,
   publisher/version meta, description, version picker with the
   exact specs + ports, the wasm CID, and every action (deploy +
   the publisher/owner controls). Data flows IN through the `app`
   property; actions bubble OUT as the SAME `card-action`
   {app, act, idx, verified} events the compact tile used, so the
   Apps page handles them with one wallet-transaction router.
   The compact <c-app-card> tile carries only name/badges/desc and
   opens this page.
   ============================================================ */
import { EnclaveElement, register } from "../../js/lib/enclave-element.js";
import { esc, short, copyText } from "../../js/core/util.js";
import { IPFS_GATEWAY } from "../../js/core/config.js";
import { Enclave } from "../../js/core/api.js";
import { APPROVAL, catVersionFee } from "../../js/core/chain.js";
import { STORE, selIdx, appOfficial, mediaOf, mediaUrl, verVisible, visibleVerIdxs, specOf } from "../../js/core/catalog.js";
import { tallyOf, avgOf, starsHtml } from "../../js/core/reviews.js";
import { appResources } from "../../js/core/app-resources.js";

class AppDetail extends EnclaveElement {
  static properties = { app: null };
  static templateUrl = new URL("./app-detail.html", import.meta.url);

  renderedCallback() {
    const app = this.app; if (!app) return;
    const i = selIdx(app);
    const v = app.versions[i] || { cid:"", version:"–", vramMb:0, gpuGflops:0, memMb:0, cpuGflops:0, verified:false, yanked:false, approval:APPROVAL.pending };
    const me = (Enclave.address || "").toLowerCase();
    const isPub = me && app.publisher.toLowerCase() === me;
    const isOwner = me && STORE.owner && me === STORE.owner;
    const gw = IPFS_GATEWAY.replace(/\/+$/, "") + "/" + encodeURIComponent(v.cid);
    const isOfficial = appOfficial(app);

    const root = this.querySelector(".appd");
    root.className = "appd" + (v.verified ? " verified" : "") + (app.active ? "" : " delisted");

    // banner (selected version's media) - optional hero
    const media = mediaOf(v), banner = this.querySelector(".appd-banner");
    if (media.banner){
      banner.hidden = false;
      banner.style.backgroundImage = "url('" + mediaUrl(media.banner, media.bannerSvg) + "')";
    } else { banner.hidden = true; banner.style.backgroundImage = ""; }

    this.querySelector("h1").textContent = app.name;

    const badge = v.verified
      ? '<span class="app-badge" title="This version is marked verified by the catalog owner">✓ verified</span>'
      : (!STORE.owner || isOfficial) ? ''
      : '<span class="app-badge comm" title="Community-published; not owner-verified">community</span>';
    const apBadge = v.approval === APPROVAL.approved
      ? (isOfficial ? '' : '<span class="app-badge" title="Approved by the catalog owner; host admission still applies">✓ approved</span>')
      : v.approval === APPROVAL.rejected
      ? '<span class="app-badge rej" title="Rejected by the catalog owner; each host decides whether to accept it">✕ rejected</span>'
      : '<span class="app-badge unv" title="Awaiting catalog-owner approval; each host decides whether to accept it">pending</span>';
    const officialBadge = isOfficial
      ? '<span class="app-badge" title="Published by Enclave Host, Inc. (the catalog deployer wallet)">★ by Enclave</span>' : "";
    const delistBadge = app.active ? ''
      : '<span class="app-badge del" title="Delisted from recommendations; available under All releases. Relist to restore it, or publish a new version to this slug (that relists it automatically).">delisted</span>';
    this.querySelector(".app-badges").innerHTML = officialBadge + badge + apBadge + delistBadge;

    const nVis = visibleVerIdxs(app).length;   // all immutable releases remain visible
    // the rating rides in the meta line and links to the reviews block below
    // (unrated apps show nothing - see <c-app-reviews>)
    const t = tallyOf(app.appId), avg = avgOf(app.appId);
    const rating = avg == null ? '' :
      '<span>·</span><a class="appd-rating" href="#revsHead">' + starsHtml(avg)
      + '<span>' + avg.toFixed(1) + '</span><span>(' + t.count + ')</span></a>';
    this.querySelector(".appd-meta").innerHTML =
      '<span title="slug (stable id in the publisher’s namespace)">' + esc(app.slug) + '</span><span>·</span>'
      + '<span title="publisher (msg.sender)">' + short(app.publisher) + '</span><span>·</span>'
      + '<span>' + nVis + (nVis === 1 ? ' version' : ' versions') + '</span>' + rating;

    this.querySelector(".appd-desc").innerHTML = app.description ? esc(app.description) : '<span class="dim">no description</span>';

    const apLabel = (vv) => vv.approval === APPROVAL.rejected ? ' (rejected)' : vv.approval !== APPROVAL.approved ? ' (pending)' : '';
    // options keep the REAL on-chain index; versions the viewer may not see emit nothing
    const opts = app.versions.map((vv, idx) => !verVisible(app, vv) ? '' :
      '<option value="' + idx + '"' + (idx === i ? ' selected' : '') + '>' + esc(vv.version) + (vv.verified ? ' ✓' : '') + (vv.yanked ? ' (yanked)' : '') + apLabel(vv) + '</option>').join('');
    // specOf, not the raw version: `gpuOptional` lives in the approved config,
    // and without it this chip called a 34 GB-VRAM app's card REQUIRED while the
    // deploy paths treated it as optional - two screens, two different answers.
    const vspec = specOf(v);
    // publish stamp: the version's on-chain createdAt (block time of its
    // publishVersion tx). The fallback version object above has none - hide.
    const pub = Number(v.createdAt) ? new Date(Number(v.createdAt) * 1000) : null;
    const pubStamp = !pub ? '' :
      '<span class="vlbl" title="published (on-chain publishVersion timestamp): ' + pub.toISOString() + '">published '
      + pub.toLocaleDateString([], { year: "numeric", month: "short", day: "numeric" })
      + ' ' + pub.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) + '</span>';
    this.querySelector(".app-verrow").innerHTML =
      '<span class="vlbl">version</span><select class="ver-select" aria-label="Version">' + opts + '</select>'
      + pubStamp
      + '<span title="Resources this app version requires">' + esc(appResources(vspec)) + '</span>'
      + (v.ports ? '<span class="vlbl" title="open ports: ports this version may bind">⛨ ' + esc(v.ports) + '</span>' : '')
      + '<span class="vlbl appd-fee" hidden></span>'
      + (v.yanked ? '<span class="vyank">yanked</span>' : '');
    // the version's publisher fee (rev-5 catalogs; 0 = free, chip stays
    // hidden). Async on purpose - fees live outside the Version tuple; the
    // chip patches in when the read lands, guarded against a version switch.
    catVersionFee(app.appId, i).then(f => {
      const el = this.querySelector(".appd-fee");
      if (!el || !this.app || this.app.appId !== app.appId || selIdx(this.app) !== i || !(f > 0n)) return;
      el.hidden = false;
      el.title = "publisher fee: paid to " + app.publisher + " out of each funding, on top of the platform rate";
      el.textContent = "+$" + (Number(f) * 3600 / 1e6).toFixed(2) + "/hr to the publisher";
    }).catch(() => {});

    this.querySelector(".app-cid code").textContent = v.cid;

    this.querySelector(".app-actions").innerHTML =
      '<button class="btn btn-primary btn-sm" data-act="deploy" type="button">Deploy →</button>'
      + '<a class="btn btn-sm" href="' + gw + '" target="_blank" rel="noopener">fetch .wasm</a>'
      + (isPub ? '<button class="btn btn-sm" data-act="newver" type="button" title="Open the publish form pre-filled from this version (new file/CID required)">add version</button>' : '')
      + (isPub && !app.active ? '<button class="btn btn-sm" data-act="relist" type="button">relist</button>' : '')
      + (isPub && app.active ? '<button class="btn btn-sm" data-act="delist" type="button">delist</button>' : '')
      + (isPub && !v.yanked ? '<button class="btn btn-sm" data-act="yank" type="button">yank</button>' : '')
      + (isOwner ? '<button class="btn btn-sm" data-act="verify" data-v="' + (v.verified ? 0 : 1) + '" type="button">' + (v.verified ? 'unverify' : 'verify') + '</button>' : '')
      + (isOwner && v.approval !== APPROVAL.approved ? '<button class="btn btn-sm" data-act="approve" type="button">approve</button>' : '')
      + (isOwner && v.approval !== APPROVAL.rejected ? '<button class="btn btn-sm" data-act="reject" type="button">reject</button>' : '');

    if (!this._wired) {
      this._wired = true;
      this.addEventListener("change", (e) => {
        const sel = e.target.closest(".ver-select"); if (!sel) return;
        STORE.sel[this.app.appId] = parseInt(sel.value, 10);
        this.requestRender();
      });
      this.addEventListener("click", (e) => {
        const cp = e.target.closest(".app-cid .copybtn");
        if (cp){ const vv = this.app.versions[selIdx(this.app)]; copyText(vv ? vv.cid : "", cp); return; }
        const btn = e.target.closest("[data-act]"); if (!btn || btn.disabled) return;
        this.dispatch("card-action", { app: this.app, act: btn.dataset.act, idx: selIdx(this.app), verified: btn.dataset.v === "1" });
      });
    }
  }
}
register("c-app-detail", AppDetail);
