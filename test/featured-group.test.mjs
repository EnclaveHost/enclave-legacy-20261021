// The featured group at the head of the store's default tab.
//
// It used to be one box in the page header - an aside beside the heading, holding exactly one app.
// Steven asked for it to become the first tab instead: eligible featured apps at the top with the
// gold border, and every other approved app after them. That turns a single-winner pick into an
// ordered group, and the things that can go wrong are all about identity and order:
//
//   - the same app holding two campaigns must appear ONCE;
//   - the order must stay the contract's own ranking (highest bid, ties to the older campaign);
//   - a campaign for an app that is not approved and listed right now must not promote it;
//   - with no standing campaign at all, the editorial fallback must still produce exactly one pick;
//   - and "promoted" must never be said about an app nobody paid for.
import "./helpers/dom-stub.mjs";   // catalog.js subscribes to page events at module scope
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { STORE } from "../site/js/core/catalog.js";
import { FEATURED, featuredList, pickFeatured } from "../site/js/core/featured.js";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const APPROVED = 1, PENDING = 0, REJECTED = 2;

// a catalog app in the shape the store reads
const app = (id, over = {}) => ({
  appId: id, name: id, slug: id, description: "", publisher: "0x" + "1".repeat(40),
  active: true, updatedAt: 1000,
  versions: [{ approval: APPROVED, yanked: false, verified: false, cid: "bafy" + id, version: "1.0.0", config: "" }],
  ...over,
});
const campaign = (appId, bid, createdAt, over = {}) =>
  ({ appId, bidPerView6: bid, balance6: bid * 10, active: true, createdAt, ...over });

function load(apps, campaigns) {
  STORE.apps = apps;
  STORE.byId = Object.fromEntries(apps.map((a) => [a.appId, a]));
  STORE.loaded = true;
  FEATURED.campaigns = campaigns;
  FEATURED.loaded = true;
}
const ids = (list) => list.map((f) => f.app.appId);

test("standing campaigns all show, highest bid first, ties to the older campaign", () => {
  load([app("a"), app("b"), app("c")], [
    campaign("b", 50, 10),
    campaign("a", 200, 99),
    campaign("c", 50, 5),      // same bid as b, older -> ahead of b
  ]);
  assert.deepEqual(ids(featuredList()), ["a", "c", "b"]);
  assert.equal(pickFeatured().app.appId, "a", "the single-pick caller still gets the leader");
});

test("one app, two campaigns, one card", () => {
  load([app("a"), app("b")], [campaign("a", 300, 1), campaign("a", 100, 2), campaign("b", 50, 3)]);
  const list = featuredList();
  assert.deepEqual(ids(list), ["a", "b"]);
  assert.equal(list.filter((f) => f.app.appId === "a").length, 1, "deduplicated by app, not by campaign");
  assert.equal(list[0].campaign.bidPerView6, 300, "and it keeps its BEST campaign's rank");
});

test("a campaign cannot promote an app the store would not list", () => {
  load([
    app("pending", { versions: [{ approval: PENDING, yanked: false, verified: false, version: "1", cid: "x", config: "" }] }),
    app("rejected", { versions: [{ approval: REJECTED, yanked: false, verified: false, version: "1", cid: "x", config: "" }] }),
    app("delisted", { active: false }),
    app("yanked", { versions: [{ approval: APPROVED, yanked: true, verified: false, version: "1", cid: "x", config: "" }] }),
    app("ok"),
  ], [campaign("pending", 900, 1), campaign("rejected", 900, 2), campaign("delisted", 900, 3),
      campaign("yanked", 900, 4), campaign("ok", 10, 5)]);
  assert.deepEqual(ids(featuredList()), ["ok"], "paying does not approve, relist or unyank anything");
});

test("an unfunded or inactive campaign is not standing", () => {
  load([app("a"), app("b"), app("c")], [
    campaign("a", 100, 1, { active: false }),
    campaign("b", 100, 2, { balance6: 99 }),      // cannot cover one view at its own bid
    campaign("c", 0, 3, { balance6: 1000 }),      // no bid at all
  ]);
  assert.deepEqual(ids(featuredList()), [], "and with no standing campaign the editorial rule takes over");
});

test("with no standing campaign the editorial fallback gives exactly one, unpaid, pick", () => {
  const older = app("older", { updatedAt: 10, versions: [{ approval: APPROVED, yanked: false, verified: true, version: "1", cid: "x", config: "" }] });
  const newer = app("newer", { updatedAt: 99, versions: [{ approval: APPROVED, yanked: false, verified: true, version: "1", cid: "x", config: "" }] });
  load([older, newer, app("plain")], []);
  const list = featuredList();
  assert.deepEqual(ids(list), ["newer"], "the newest owner-endorsed app, and only it");
  assert.equal(list[0].campaign, null, "no campaign means nobody is billed and the label must not say promoted");
});

test("nothing to feature is an empty group, not a crash", () => {
  load([], []);
  assert.deepEqual(featuredList(), []);
  assert.equal(pickFeatured(), null);
  STORE.loaded = false;
  assert.deepEqual(featuredList(), [], "and before the catalog lands there is nothing to rank");
  STORE.loaded = true;
});

// The page wiring, pinned. The ordering and dedupe above are only worth
// something if the grid builds its list the way that guarantees them.
const apps = fs.readFileSync(path.join(ROOT, "site/js/pages/apps.js"), "utf8");
const html = fs.readFileSync(path.join(ROOT, "site/apps.html"), "utf8");
const css = fs.readFileSync(path.join(ROOT, "site/css/src/apps.css"), "utf8");

test("Featured is the first tab, selected, and the hero no longer holds the card", () => {
  const catalog = fs.readFileSync(path.join(ROOT, "site/js/core/catalog.js"), "utf8");
  assert.match(catalog, /filter:"featured"/, "fresh navigation opens on Featured");
  const seg = html.slice(html.indexOf('id="storeFilter"'), html.indexOf("</div>", html.indexOf('id="storeFilter"')));
  const order = [...seg.matchAll(/data-filter="([a-z]+)"/g)].map((m) => m[1]);
  assert.equal(order[0], "featured", "and it is the first button");
  assert.deepEqual(order, ["featured", "approved", "all", "pending", "rejected", "delisted"], "All releases remains accessible alongside the moderation views");
  assert.match(seg, /data-filter="featured" class="on" type="button" aria-pressed="true"/, "selected state is on the button and announced");
  assert.doesNotMatch(seg, /data-filter="approved"[^>]*class="on"/, "and Approved is no longer the selected one");
  assert.doesNotMatch(html, /featuredSlot/, "the hero's aside is gone, so the banner uses the full width");
  assert.match(apps, /STORE\.filter = "featured";/, "a tab that becomes hidden falls back to the DEFAULT tab, not to Approved");
});

test("the group is a partition of the approved list, which is what stops a double listing", () => {
  const fn = apps.slice(apps.indexOf("function renderApps()"), apps.indexOf("// the page size tracks"));
  assert.match(fn, /const inStore = new Set\(apps\.map\(a => a\.appId\)\);/, "only apps already in the list may be lifted");
  assert.match(fn, /if \(!f \|\| !f\.app \|\| !inStore\.has\(f\.app\.appId\) \|\| featuredIds\.has\(f\.app\.appId\)\) continue;/);
  assert.match(fn, /const head = apps\.filter\(a => featuredIds\.has\(a\.appId\)\)/);
  assert.match(fn, /const rest = apps\.filter\(a => !featuredIds\.has\(a\.appId\)\)\.sort\(byRank\);/);
  assert.match(fn, /apps = head\.concat\(rest\);/, "head and rest partition ONE array: no app can be in both");
  assert.match(fn, /if \(q\) apps = apps\.filter\(/, "search still narrows the combined list");
  assert.ok(fn.indexOf("if (q) apps = apps.filter(") < fn.indexOf("apps = head.concat(rest)"),
            "and it runs before the grouping, so a search that matches no featured app simply has no head");
});

test("only a promoted card that is on this page AND on screen is metered", () => {
  const fn = apps.slice(apps.indexOf("function renderApps()"), apps.indexOf("// the page size tracks"));
  assert.match(fn, /if \(storeVisible\(\)\) for \(const a of page\) if \(featuredIds\.get\(a\.appId\)\) beaconView\(a\.appId\);/);
  assert.ok(fn.indexOf("const page = apps.slice(") < fn.indexOf("beaconView"),
            "the page slice decides: a card on a later pager page has not been seen");
  const vis = apps.slice(apps.indexOf("function storeVisible()"), apps.indexOf("const gridCols ="));
  assert.match(vis, /store\.hidden \|\| grid\.offsetParent === null/, "a grid inside a hidden view is not on screen");
  assert.match(vis, /document\.visibilityState === "visible"/, "nor is one in a background tab");
  assert.match(apps, /_resizeT = setTimeout\(\(\) => \{ if \(storeVisible\(\)\) renderApps\(\); \}, 200\);/,
               "a resize must not repaint a hidden grid");
  assert.match(apps, /on\("enclave:featured", \(\) => \{ if \(STORE\.loaded && storeVisible\(\)\) renderApps\(\); \}\);/,
               "nor may a campaign read landing while the viewer is on an app's page");
});

test("the labels and the note say only what is true", () => {
  assert.match(apps, /el\.dataset\.featuredLabel = camp \? "\\u2605 Promoted" : "\\u2605 Featured";/,
               "paid is promoted; the editorial pick is not");
  const note = apps.slice(apps.indexOf("function renderFeaturedNote("), apps.indexOf("/* ---- promote modal"));
  assert.match(note, /!here\.length\s+\? "the featured apps are at the top of the first page"/,
               "on page two the note must not point at whatever card is first");
  assert.match(note, /if \(onPage === null\)\{ note\.hidden = true; return; \}/,
               "and with no cards at all there is no list for it to describe");
  assert.match(note, /nobody paid for it/, "the editorial pick says so");
  assert.match(note, /pb\.hidden = !featConfigured\(\)/, "promotion access is preserved, where the contract exists");
  // the promote dialog no longer describes a single winner-takes-all box
  assert.doesNotMatch(apps, /holds the slot|take the slot|win the slot/, "there is no single slot any more");
  assert.match(apps, /highest bid first/);
});

test("the gold is a card border and a badge, reusing the store grid", () => {
  assert.match(css, /\.store-grid c-app-card\.is-featured \.app-card\{border-color:rgba\(240,185,11/);
  assert.match(css, /\.store-grid c-app-card\.is-featured::after\{content:attr\(data-featured-label\)/);
  assert.match(css, /\.featured-foot\[hidden\]\{display:none;\}/,
               "[hidden] is a plain attribute selector and loses to .featured-foot's display:flex without this");
  assert.doesNotMatch(css, /\.featured-slot\{/, "the header aside's layout is gone with it");
  const visual = fs.readFileSync(path.join(ROOT, "site/css/src/visual.css"), "utf8");
  assert.doesNotMatch(visual, /\.store-hero>\.featured-slot/);
});
