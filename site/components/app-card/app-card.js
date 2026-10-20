/* ============================================================
   <c-app-card> - one catalog listing, as a compact TILE: an
   optional thumbnail, the name, the status badges, and the
   description. Everything else (versions, specs, CID, deploy +
   owner/publisher actions) lives on the app's own page - the whole
   tile is a button that opens it. Data flows IN through the `app`
   property; the click flows OUT as a `card-action` {act:"open"}
   event (the LWC data-down/events-up pattern), which the Apps page
   turns into a navigation to apps?app=<appId>.
   ============================================================ */
import { EnclaveElement, register } from "../../js/lib/enclave-element.js";
import { esc } from "../../js/core/util.js";
import { Enclave } from "../../js/core/api.js";
import { APPROVAL } from "../../js/core/chain.js";
import { STORE, selIdx, appOfficial, appMedia, mediaUrl, placeholderArt } from "../../js/core/catalog.js";
import { tallyOf, avgOf, starsHtml } from "../../js/core/reviews.js";

class AppCard extends EnclaveElement {
  static properties = { app: null };
  static templateUrl = new URL("./app-card.html", import.meta.url);

  renderedCallback() {
    const app = this.app; if (!app) return;
    const i = selIdx(app);
    const v = app.versions[i] || { verified:false, yanked:false, approval:APPROVAL.pending };
    const isOfficial = appOfficial(app);

    const art = this.querySelector("article");
    art.className = "app-card" + (v.verified ? " verified" : "") + (app.active ? "" : " delisted");
    art.dataset.appid = app.appId;

    // thumbnail (from the default version's media); the band is always there -
    // fixed 16:9, generated placeholder when the app ships no art - so every
    // card is the same shape whether or not the publisher branded it
    const media = appMedia(app), thumb = this.querySelector(".app-thumb");
    thumb.hidden = false;
    thumb.style.backgroundImage = media.thumbnail
      ? "url('" + mediaUrl(media.thumbnail, media.thumbnailSvg) + "')"
      : placeholderArt(app.appId || app.slug, app.name || app.slug);

    // the title is a real link (the heading survives in the a11y tree; Enter
    // works natively) - the card-wide click handler below still opens for pointers
    const link = this.querySelector("h3 a");
    link.textContent = app.name;
    link.href = "apps?app=" + encodeURIComponent(app.appId);

    const badge = v.verified
      ? '<span class="app-badge" title="This version is marked verified by the catalog owner">✓ verified</span>'
      : (!STORE.owner || isOfficial) ? ''
      : '<span class="app-badge comm" title="Community-published; not owner-verified">community</span>';
    const apBadge = v.approval === APPROVAL.approved
      ? (isOfficial ? '' : '<span class="app-badge" title="Approved by the catalog owner; deployable">✓ approved</span>')
      : v.approval === APPROVAL.rejected
      ? '<span class="app-badge rej" title="Rejected by the catalog owner; deploys are refused">✕ rejected</span>'
      : '<span class="app-badge unv" title="Awaiting catalog-owner approval; deploys are refused until then">pending</span>';
    const officialBadge = isOfficial
      ? '<span class="app-badge" title="Published by Enclave Host, Inc. (the catalog deployer wallet)">★ by Enclave</span>' : "";
    const delistBadge = app.active ? ''
      : '<span class="app-badge del" title="Delisted: hidden from the public store; only you (its publisher) and the catalog owner see it.">delisted</span>';
    this.querySelector(".app-badges").innerHTML = officialBadge + badge + apBadge + delistBadge;

    // rating - only once someone has rated it. An unrated app shows nothing
    // rather than an empty five stars, which reads as "rated, and badly"
    // (tallies arrive async from EnclaveReviews; the grid repaints on
    // `enclave:reviews`, so this fills in without a card rebuild)
    const rate = this.querySelector(".app-rating"), t = tallyOf(app.appId), avg = avgOf(app.appId);
    if (avg == null){ rate.hidden = true; rate.innerHTML = ""; }
    else {
      rate.hidden = false;
      rate.innerHTML = starsHtml(avg) + '<span class="app-rating-n">' + avg.toFixed(1) + '</span>'
        + '<span class="app-rating-c">(' + t.count + ')</span>';
    }

    this.querySelector(".app-desc").innerHTML = app.description ? esc(app.description) : '<span class="dim">no description</span>';

    if (!this._wired) {
      this._wired = true;
      // preventDefault keeps the link's soft-nav (apps.js routes card-action)
      this.addEventListener("click", (e) => { e.preventDefault(); this.dispatch("card-action", { app: this.app, act: "open" }); });
    }
  }
}
register("c-app-card", AppCard);
