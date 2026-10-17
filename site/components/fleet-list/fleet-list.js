/* ============================================================
   <c-fleet-list> - per-enclave capacity rows (the relay's
   /enclaves table). Assign `.rows` (already sorted upstream) and
   it renders each box as a summary ("$0.10 for 12 GB / 33 tflops of
   GPU", one line a pool) that expands to its full pools, five boxes a
   page. The units in those lines are the sort controls: GB or tflops on
   a GPU line sorts every host by its price per GB of VRAM or per TFLOPS,
   GB or gflops on a CPU line by RAM or CPU compute, the rating (stars,
   average, count) by rating; again reverses. The Sort by bar above the hosts offers
   every order as a dropdown, with the direction beside it.
   An opened host carries the Overview's "run the check now": an
   attested box (SEV-SNP, phone pVM, Enclave Shield) is challenged and
   verified in this browser (core/verify.js); any other says why not.
   Copy says "available",
   never "free": on a page that sells compute, "60 GB free" reads as
   a price, not as headroom.
   ============================================================ */
import { EnclaveElement, register } from "../../js/lib/enclave-element.js";
import { esc, fmtNum, short, showToast } from "../../js/core/util.js";
import { asOf } from "../../js/core/list-state.js";
import { starsHtml } from "../../js/core/reviews.js";
import { hrevConfigured, hrevTallies, hrevMine, encCall, HREV_SEL, waitReceipt, REVIEW_MAX_BODY } from "../../js/core/chain.js";
import { HOST_REVIEWS_ADDRESS } from "../../js/core/config.js";
import { Enclave } from "../../js/core/api.js";
import { connectWallet, ensureBaseChain, sendTx } from "../../js/core/wallet.js";
import { serverSpec, enclavePriceOf, enclaveClassOf, shieldedHostCapacity, computeEligibleOf, appHostVisible, ownerHostedDeploymentCount, ownerHostCpuCapacity, ownerHostVisibleTo, pvmHostVisible, pvmHostVm } from "../../js/core/pricing.js";
import { REGISTRY_ADDRESS } from "../../js/core/config.js";
import { catExplorer } from "../../js/core/chain.js";
import { cpuPoolBadge, gpuPoolBadge } from "../../js/core/pool-badges.js";
import { boxVerifiable, unverifiableReason, verifyBoxInBrowser, verificationHtml, EVIDENCE_OF } from "../../js/core/verify.js";

const PAGE = 5;   // hosts per page
// the sort keys, in the Sort by dropdown's order: the rating, then a pool kind and what its price is divided by.
// `opt` is the dropdown's name for it, `unit` what the line's button reads, `dir` the first direction (1 = low first),
// `asc` / `desc` what each direction is called.
const SORTS = {
  "rating":      { opt: "Rating", dir: -1, asc: "worst first", desc: "best first" },   // its button is the rating itself (the average)
  "gpu-gb":      { opt: "$ per GB VRAM",    unit: "GB",     what: "GB of VRAM" },
  "gpu-compute": { opt: "$ per GPU TFLOPS", unit: "tflops", what: "TFLOPS of GPU compute" },
  "cpu-gb":      { opt: "$ per GB RAM",     unit: "GB",     what: "GB of RAM" },
  "cpu-compute": { opt: "$ per CPU GFLOPS", unit: "gflops", what: "GFLOPS of CPU compute" },
};

class FleetList extends EnclaveElement {
  // error: why the latest read failed (null = it did not); staleAt: when the
  // rows shown were read, when they are the last good table (js/core/fleet-read.js)
  static properties = { rows: null, error: null, staleAt: 0 };
  static templateUrl = new URL("./fleet-list.html", import.meta.url);

  connectedCallback() {
    this._walletChanged ||= () => {
      // A wallet switch must update personal rows immediately, even while a
      // rating form had deferred ordinary telemetry refreshes.
      this._rateOpen = false;
      this._renderDeferred = false;
      super.requestRender();
    };
    document.addEventListener("enclave:wallet", this._walletChanged);
    super.connectedCallback();
  }
  disconnectedCallback() {
    document.removeEventListener("enclave:wallet", this._walletChanged);
    super.disconnectedCallback();
  }

  renderedCallback() {
    const list = this.querySelector(".fleet-list"); if (!list) return;
    // Marketplace capacity keeps its eligibility gate. Active owner-only hosts
    // get a separate status row with reported capacity, but no rental prices.
    const rows = (this.rows || []).filter((e) => appHostVisible(e));
    const ownerRows = (this.rows || []).filter(e => ownerHostVisibleTo(e, Enclave.address))
      .map(e => ({ row: e, count: ownerHostedDeploymentCount(e) }));
    // pVM CPU hosts the relay has not put in the market (not registered, or the market off): a status row with the same
    // pool and no price. One the relay holds eligible and serving is a marketplace row above, priced like any other.
    const pvmRows = (this.rows || []).filter(e => pvmHostVisible(e) && !appHostVisible(e));
    const meter = (pct) => '<i class="fleet-meter" aria-hidden="true"><b style="width:' + Math.max(0, Math.min(100, pct)) + '%"></b></i>';
    // one stat cell: bright available amount, then the "≈"/"/ total" context and
    // the label in dim ink so the number is what the eye lands on
    const stat = (avail, total, unit, label, title) =>
      '<span class="fleet-stat"' + (title ? ' title="' + esc(title) + '"' : '') + '>'
      + '<b><i>≈</i>' + avail + '<i> / ' + total + '</i>' + (unit ? " " + unit : "") + '</b>'
      + '<small>' + label + '</small></span>';
    // the price sits directly under the pool's label (its badge) - bright number,
    // dim "/hr" - in the label column's otherwise-empty second row, so it
    // costs no space and each pool names its own rate (card vs node). It is
    // the WHOLE card / node per hour, the ledger's basis; a share pays its
    // fraction. Trailing ".00" trims like the docs' rates.
    const perHr = (v) => "$" + (v * 3600).toFixed(2).replace(/\.00$/, "");
    // what everything this pool has available costs, for the collapsed line: the whole card/node rate times the
    // available share (a $3/hr card with a third available reads $1/hr). No posted rate, no price.
    // (under a cent but not nothing reads "<$0.01", never a "$0" that says it's free)
    const availPrice = (rate, frac) => {
      if (rate == null) return '';
      const v = rate * Math.max(0, Math.min(1, Number(frac) || 0));
      return '<span class="fleet-chip-price" title="' + perHr(rate) + '/hr for the whole pool, times the share available now">'
        + (v > 0 && v * 3600 < 0.005 ? '&lt;$0.01' : perHr(v)) + '<i>/hr</i></span> for ';
    };
    // one pool = a [label | meter | pct] header line, the price under the
    // label, stat cells underneath. The label is the pool's badge (see the
    // row builder): the pill names the pool, so nothing else has to.
    const pool = (label, pct, stats, price) =>
      '<div class="fleet-pool">'
      + '<span class="fleet-pool-label">' + label + '</span>'
      + meter(pct)
      + '<span class="fleet-pool-pct"><b>' + pct + '%</b> available</span>'
      // the label column's second row holds the pool's rate. A pool whose seller
      // has posted no ask simply leaves it empty rather than inventing one.
      + (price != null ? '<span class="fleet-pool-price"><b>' + perHr(price) + '</b>/hr</span>' : '')
      + '<span class="fleet-stats">' + stats + '</span>'
      + '</div>';
    const computeStat = gpu => {
      const value = n => n === null ? '—' : String(Math.round(n * 100) / 100);
      const title = gpu.names.join(', ') + '. ' + gpu.cardCount + ' GPU' + (gpu.cardCount === 1 ? '' : 's') + '. '
        + (gpu.basis === 'rated' ? 'Combined rated dense FP16 capacity. '
          : gpu.basis === 'measured' ? 'Measured masked field GEMM, converted at two operations per MAC to TFLOPS-equivalent. Not manufacturer-rated floating-point throughput. '
          : 'A complete comparable compute rate has not been reported. ')
        + 'Available capacity follows each card’s unallocated share. Aggregate capacity is not guaranteed single-request throughput.';
      return stat(value(gpu.availableTflops), value(gpu.tflops), '',
        gpu.basis === 'measured' ? 'tflops equiv. available' : 'tflops available', title);
    };
    const number = v => typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : null;
    // Use this host's GFLOPS report, never a conversion from vCPUs or
    // another host's spec. Older hosts report only total GFLOPS + share.
    const cpuGflopsAvail = (a, fraction) => {
      const total = number(a.nodeGflops), share = number(fraction);
      return number(a.cpuGflopsFree) ?? (total !== null && share !== null ? total * Math.min(1, share) : null);
    };
    const cpuComputeStat = (a, fraction, title) => {
      const total = number(a.nodeGflops), available = cpuGflopsAvail(a, fraction);
      const value = v => v === null ? '—' : fmtNum(v);
      return stat(value(available), value(total), '', 'gflops available', title ||
        'Reported CPU compute capacity in GFLOPS (billions of floating-point operations per second). '
        + 'Available capacity follows unallocated CPU shares, not instantaneous processor activity.');
    };
    // A FAILED read is not an empty fleet: say it failed (retrying) rather than "no hosts",
    // and under last-good rows say how old they are.
    const failed = this.error ? String(this.error) : "";
    const staleNote = failed && (rows.length || ownerRows.length || pvmRows.length)
      ? '<div class="fleet-stale" role="status">Showing hosts as of ' + esc(asOf(this.staleAt)) + ': the latest read failed (' + esc(failed) + '). Retrying.</div>'
      : "";
    // Each row kind below builds an ITEM: { key, name, title, cls, chips, detail }. `chips` is the collapsed
    // line, one per pool: "$0.10/hr for 12 GB / 33 tflops of GPU" (the hourly price of what it has available, that memory
    // and compute, its badge; no posted rate -> "12 GB / 33 tflops of GPU", unknown -> "—"); `detail` is the full
    // row it expands to.
    const sumNum = v => { const n = number(v); return n === null ? '—' : n >= 10 ? String(Math.round(n)) : n >= 1 ? fmtNum(n) : String(Math.round(n * 100) / 100); };
    // a line's units are its sort buttons (`kind` = "gpu" | "cpu"); the active one is marked on every row
    const sortBy = this._sort && SORTS[this._sort.key] ? this._sort : null;
    const unitBtn = (key) => '<button class="fleet-unit' + (sortBy && sortBy.key === key ? (sortBy.dir < 0 ? ' on desc' : ' on') : '')
      + '" type="button" data-sort="' + key + '" title="Sort hosts by price per ' + SORTS[key].what + '">' + SORTS[key].unit + '</button>';
    const chip = (badge, gb, compute, kind, price) => '<span class="fleet-chip">' + (price || '')
      + '<b>' + sumNum(gb) + '</b> ' + unitBtn(kind + '-gb') + ' / <b>' + sumNum(compute) + '</b> ' + unitBtn(kind + '-compute') + ' of ' + badge + '</span>';
    // what a host charges per unit of a pool: the whole pool's hourly rate over the whole pool's size (a share
    // pays its fraction of both, so this is the same for any share). No rate or no size -> null, sorted last.
    const unitPrice = (rate, amount) => { const r = number(rate), n = number(amount); return r !== null && n ? r * 3600 / n : null; };
    const nameOf = (e, dflt) => e.name || String(e.endpoint || "").replace(/^[a-z]+:\/\//, "").split(".")[0] || dflt;
    const head = (e) => { const r = this._ratingHtml(e); return r ? '<span class="fleet-head">' + r + '</span>' : ''; };
    const marketItems = rows.map(e => {
          const a = e.availability || {};
          const gpu = a.gpu === true;
          const gFree = a.gpuShareFree != null ? a.gpuShareFree : (gpu ? a.maxShare || 0 : 0);
          const cFree = a.cpuShareFree != null ? a.cpuShareFree : (gpu ? 0 : a.maxShare || 0);
          const gPct = Math.floor(gFree * 100), cPct = Math.floor(cFree * 100);
          // the relay names each row (tunnel enclaves: their tunnel name, e.g.
          // "metal0"); the endpoint-derived fallback covers older relays — and
          // strips ANY scheme, so a tunnel:// row never renders as a pseudo-URL
          const name = nameOf(e, "enclave");
          // A card on the box's UNTRUSTED host, reached by masked offload, is
          // not an in-enclave GPU (`gpu` alone no longer means "inside the
          // enclave"): `inTee` is where the silicon is.
          const cls = enclaveClassOf(e);
          const inTee = cls.inTee;
          // THE POOL LABELS ARE THE BADGES (core/pool-badges.js). Each pool is
          // named by what it is, in the colour that means it, right beside its
          // own meter; the header carries only the box's name and rating.
          const teeCpuBadge = cpuPoolBadge(e), cardBadge = gpuPoolBadge(e);
          // What is SELLABLE is the worker's budget, not the physical card: the
          // untrusted host keeps the rest (on a desktop, an X server). Showing the
          // physical total here while the GPU pool showed the budget is what put
          // two differently-sized GPU rows on one single-card box.
          const shPool = shieldedHostCapacity(e);
          const shPct = shPool ? Math.floor(shPool.frac * 100) : 0;
          const shVramTitle = shPool ? fmtNum(shPool.total) + ' GB combined worker budget across '
            + shPool.cardCount + ' GPU(s). ' + fmtNum(shPool.reservedGb)
            + ' GB reserved by apps. Available capacity follows unallocated shares, not instantaneous GPU activity.' : '';
          const s = serverSpec();   // adopted fleet hardware; display fallback for rows that omit their own
          const vramGb = a.cardVramGb || s.cardVramGb, tflops = a.cardTflops || s.cardTflops;
          const ramGb = a.nodeRamGb || s.nodeRamGb;
          const price = enclavePriceOf(e);   // this box's posted ask; the fleet price where it posts none
          return { key: "m:" + (e.id || e.endpoint || name), name, title: e.endpoint || "", cls: "", fb: this._fbHtml(e, sortBy),
            chips: (shPool ? chip(cardBadge, shPool.leasableGb, shPool.availableTflops, "gpu", availPrice(price.shielded, shPool.frac)) : "")
              + (inTee ? chip(cardBadge, a.vramFreeGb != null ? a.vramFreeGb : gFree * vramGb, gFree * tflops, "gpu", availPrice(price.full, gFree)) : "")
              + chip(teeCpuBadge, a.ramGbFree != null ? a.ramGbFree : cFree * ramGb, cpuGflopsAvail(a, cFree), "cpu", availPrice(price.node, cFree)),
            sortv: {
              "gpu-gb": shPool ? unitPrice(price.shielded, shPool.total) : inTee ? unitPrice(price.full, vramGb) : null,
              "gpu-compute": shPool ? unitPrice(price.shielded, shPool.tflops) : inTee ? unitPrice(price.full, tflops) : null,
              "cpu-gb": unitPrice(price.node, ramGb),
              "cpu-compute": unitPrice(price.node, a.nodeGflops),
              rating: this._ratingSort(e),
            },
            detail: head(e)
            + (shPool ? pool(cardBadge, shPct,
                stat(fmtNum(shPool.leasableGb), fmtNum(shPool.total), "GB", "vram available", shVramTitle)
                + computeStat(shPool), price.shielded) : "")
            // ONLY when the card is in the enclave. A shielded card already drew its
            // pool above, from the numbers the probe actually measured; drawing
            // this one too would advertise one piece of silicon twice.
            + (inTee ? pool(cardBadge, gPct,
                stat(fmtNum(a.vramFreeGb != null ? a.vramFreeGb : gFree * vramGb), fmtNum(vramGb), "GB", "vram available")
                + stat(Math.round(gFree * tflops), Math.round(tflops), "", "tflops available"), price.full) : "")
            + pool(teeCpuBadge, cPct,
                // prefer the enclave's own figure (the RAM-reservation ledger,
                // which is what actually gates admission) over the folded
                // fraction — same precedence the VRAM cell above uses
                stat(fmtNum(a.ramGbFree != null ? a.ramGbFree : cFree * ramGb), fmtNum(ramGb), "GB", "ram available")
                + cpuComputeStat(a, cFree),
                // A "held by models" cell used to sit here, reading
                // ramNnResidentMb against the node's RAM. It was written for a box
                // whose preloaded weights make the meter read ~85% used while every
                // tenant is idle -- worth naming, at that size. In practice the only
                // boxes reporting the field hold a fraction of a percent (metal0:
                // 0.6 of 64 GB), so it explained nothing and spent a third row of the
                // CPU pool saying so. The field still crosses the wire, so bring the
                // cell back if a box ever carries enough resident weight to need it.
                price.node)
            + this._verifyHtml(e)
            + '<div class="fleet-rateform" data-form="' + esc(e.id || "") + '" hidden></div>' };
        });
    const ownerItems = ownerRows.map(({ row: e, count }) => {
      const cpu = ownerHostCpuCapacity(e);
      const gpu = shieldedHostCapacity(e);
      const gpuCapacity = gpu ? pool(
        '<span class="ap-badge info" title="Enclave Shield masked GPU offload for authorized owners. This is not a confidential-computing GPU.">GPU</span>',
        Math.floor(gpu.frac * 100),
        stat(fmtNum(gpu.leasableGb), fmtNum(gpu.total), 'GB', 'vram available',
          'Unallocated GPU shares in the worker pool, not instantaneous GPU activity. '
          + fmtNum(gpu.reservedGb) + ' GB reserved by apps.')
        + computeStat(gpu), null) : '';
      const value = v => v === null ? '—' : fmtNum(v);
      const stats = stat(value(cpu.ramFreeGb), value(cpu.ramGb), 'GB', 'ram available')
        + cpuComputeStat(e.availability || {}, cpu.fraction);
      const cpuPct = cpu.fraction === null ? null : Math.floor(cpu.fraction * 100);
      const capacity = cpuPct === null
        ? '<div class="fleet-pool"><span class="fleet-pool-label"><span class="ap-badge info">CPU</span></span><span class="fleet-pool-pct">Availability unknown</span><span class="fleet-stats">' + stats + '</span></div>'
        : pool('<span class="ap-badge info">CPU</span>', cpuPct, stats, null);
      const name = nameOf(e, "host");
      return { key: "o:" + (e.id || e.endpoint || name), name, title: e.endpoint || "", cls: "fleet-owner-row",
        chips: '<span class="ap-badge info">Owner-only</span>'
          + (gpu ? chip('<span class="ap-badge info">GPU</span>', gpu.leasableGb, gpu.availableTflops, 'gpu') : '')
          + chip('<span class="ap-badge info">CPU</span>', cpu.ramFreeGb, cpuGflopsAvail(e.availability || {}, cpu.fraction), 'cpu'),
        detail: gpuCapacity + capacity
          + '<span class="fleet-owner-status">' + count + ' active deployment' + (count === 1 ? '' : 's') + '</span>'
          + '<span class="fleet-owner-note">Hosting for authorized owners. Unavailable for general deployments.</span>'
          + this._verifyHtml(e) };
    });
    const pvmItems = pvmRows.map(e => {
      // the SAME pool as every other CPU row (badge, meter, % available, ram + gflops cells), from the relay's verified
      // VM size (relay/pvm-cpu-tier.mjs pvmCpuAvailability); no price: the tier takes no deployments yet
      const a = e.availability || {};
      const vm = pvmHostVm(e);
      const cFree = typeof a.cpuShareFree === 'number' ? a.cpuShareFree : null;
      const ramGb = typeof a.nodeRamGb === 'number' ? a.nodeRamGb : vm.memGb;
      const ramFree = typeof a.ramGbFree === 'number' ? a.ramGbFree : (ramGb !== null && cFree !== null ? cFree * ramGb : null);
      const value = v => v === null ? '—' : fmtNum(v);
      const badge = '<span class="ap-badge warn" title="The relay verified this phone\u2019s protected-VM attestation chain when it attached and admitted its capability report: a CPU-only Wasm runtime, no model, no accelerator. Its size is the VM\u2019s own, from that signed report.">pvm cpu</span>';
      const stats = stat(value(ramFree), value(ramGb), 'GB', 'ram available') + cpuComputeStat(a, cFree,
        'GFLOPS measured inside the protected VM under the same runtime its apps get (an exactly counted f32 multiply-add '
        + 'workload on every vCPU at once), reported in its signed capability report. Not a native-core estimate.');
      const name = nameOf(e, "host");
      return { key: "p:" + (e.id || e.endpoint || name), name, title: e.endpoint || "", cls: "fleet-pvm-row", fb: this._fbHtml(e, sortBy),
        sortv: { rating: this._ratingSort(e) },
        chips: chip(badge, ramFree, cpuGflopsAvail(a, cFree), 'cpu'),
        detail: head(e)
        + (cFree === null
          ? '<div class="fleet-pool"><span class="fleet-pool-label">' + badge + '</span><span class="fleet-pool-pct">Availability unknown</span><span class="fleet-stats">' + stats + '</span></div>'
          : pool(badge, Math.floor(cFree * 100), stats, null))
        + '<span class="fleet-owner-note">A protected VM on its owner\u2019s phone, running CPU-only apps. Not taking deployments yet.</span>'
        + this._verifyHtml(e)
        + '<div class="fleet-rateform" data-form="' + esc(e.id || "") + '" hidden></div>' };
    });
    // One page of collapsed rows, at most ONE open. The open row, the page and the sort survive the host's 20 s
    // repaint (keyed by host, clamped when the fleet shrinks). Sorted: by the chosen unit price, hosts with none
    // (no such pool, no posted rate: owner-only and pVM rows) last, ties in the relay's order.
    let items = marketItems.concat(ownerItems, pvmItems);
    if (sortBy) {
      const v = (r) => (r.sortv && r.sortv[sortBy.key] != null ? r.sortv[sortBy.key] : null);
      items = items.map((r, i) => [r, i]).sort(([a, i], [b, j]) => {
        const x = v(a), y = v(b);
        if (x === null || y === null) return x === null && y === null ? i - j : x === null ? 1 : -1;
        return (x - y) * sortBy.dir || i - j;
      }).map(([r]) => r);
    }
    // the Sort by bar, always above the hosts: every order in a dropdown (Default = the relay's), and beside it
    // the direction, as a button that flips it. The units and ratings in the rows set the same sort.
    const uid = (this._uid ||= "fl" + Math.random().toString(36).slice(2, 8));
    const dirWord = (key, dir) => dir < 0 ? (SORTS[key].desc || "priciest first") : (SORTS[key].asc || "cheapest first");
    const sortBar = items.length
      ? '<div class="fleet-sortbar"><label for="' + uid + '-sort">Sort by</label>'
        + '<select class="fleet-sortsel" id="' + uid + '-sort"><option value="">Default</option>'
        + Object.entries(SORTS).map(([k, s]) => '<option value="' + k + '"' + (sortBy && sortBy.key === k ? ' selected' : '') + '>' + esc(s.opt) + '</option>').join('')
        + '</select>'
        + (sortBy ? '<button class="fleet-sortdir" type="button" title="Reverse the order">' + (sortBy.dir < 0 ? '↓ ' : '↑ ') + dirWord(sortBy.key, sortBy.dir) + '</button>' : '')
        + '</div>'
      : '';
    const pages = Math.max(1, Math.ceil(items.length / PAGE));
    this._page = Math.min(Math.max(0, this._page || 0), pages - 1);
    const first = this._page * PAGE;
    // an opened "Show the checks" stays open through the 20 s repaint (keyed by its box or app)
    const openMore = new Set([...list.querySelectorAll("details.lv-more[open]")].map((d) => d.closest("[data-vkey]")?.dataset.vkey).filter(Boolean));
    list.innerHTML = !items.length
      ? (failed
        ? '<div class="fleet-empty fleet-error" role="alert">Couldn’t load the app hosts: ' + esc(failed) + '. This is a failed read, not an empty fleet. Retrying.</div>'
        // Honest and short. It is said the same way whether the fleet is empty or every attached
        // box is excluded, because from a buyer's side those are the same fact: nothing to deploy on.
        : '<div class="fleet-empty">No app hosts available right now</div>')
      : staleNote + sortBar + items.slice(first, first + PAGE).map((r, i) => {
          const open = this._openKey === r.key, id = uid + "-" + (first + i);
          // the summary line: a toggle (the name, its rating on the line under it) and the pool lines, whose units are sort buttons. A click
          // anywhere on the line but a unit opens the host, as the whole line did when it was one button.
          return '<div class="fleet-row' + (r.cls ? ' ' + r.cls : '') + '" data-key="' + esc(r.key) + '"' + (r.title ? ' title="' + esc(r.title) + '"' : '') + '>'
            + '<div class="fleet-sum' + (open ? ' is-open' : '') + '">'
            + '<span class="fleet-who"><button class="fleet-tog" type="button" aria-expanded="' + open + '" aria-controls="' + id + '"><span class="fleet-name">' + esc(r.name) + '</span></button>'
            + (r.fb || '') + '</span>'
            + '<span class="fleet-chips">' + r.chips + '</span></div>'
            + '<div class="fleet-detail" id="' + id + '"' + (open ? '' : ' hidden') + '>' + r.detail + '</div>'
            + '</div>';
        }).join("");
    for (const k of openMore) { const d = list.querySelector('[data-vkey="' + CSS.escape(k) + '"] > details.lv-more'); if (d) d.open = true; }
    const setOpen = (sum, open) => {
      const d = sum.closest(".fleet-row").querySelector(".fleet-detail");
      sum.querySelector(".fleet-tog").setAttribute("aria-expanded", String(open));
      sum.classList.toggle("is-open", open);
      d.hidden = !open;
      const form = !open && d.querySelector(".fleet-rateform:not([hidden])");   // a rating form closes with its row
      if (form) this._closeRate(form, d.querySelector(".fleet-rate"));
    };
    for (const sum of list.querySelectorAll(".fleet-sum")) sum.addEventListener("click", (ev) => {
      if (ev.target.closest("[data-sort]")) return;
      const open = !sum.classList.contains("is-open");
      if (open) for (const o of list.querySelectorAll(".fleet-sum.is-open")) setOpen(o, false);
      setOpen(sum, open);
      this._openKey = open ? sum.closest(".fleet-row").dataset.key : null;
    });
    // a unit sorts every host by its price per that unit; the same unit again reverses; × clears
    const resort = (next, focus) => {
      this._sort = next; this._page = 0; this._sortFocus = focus;
      this._rateOpen = false; this._renderDeferred = false;
      super.requestRender();
    };
    for (const u of list.querySelectorAll("[data-sort]")) u.addEventListener("click", () => {
      const key = u.dataset.sort;
      resort({ key, dir: sortBy && sortBy.key === key ? -sortBy.dir : (SORTS[key].dir || 1) }, key);
    });
    const sel = list.querySelector(".fleet-sortsel");
    if (sel) sel.addEventListener("change", () => resort(sel.value ? { key: sel.value, dir: SORTS[sel.value].dir || 1 } : null, ".fleet-sortsel"));
    const sd = list.querySelector(".fleet-sortdir");
    if (sd) sd.addEventListener("click", () => resort({ key: sortBy.key, dir: -sortBy.dir }, ".fleet-sortdir"));
    // the repaint replaced the control that was used: keep keyboard focus on what it became
    if (this._sortFocus) {
      const f = this._sortFocus.startsWith(".") ? list.querySelector(this._sortFocus) : list.querySelector('[data-sort="' + this._sortFocus + '"]');
      this._sortFocus = null;
      if (f) f.focus();
    }
    this._wireRate();
    for (const b of list.querySelectorAll(".fleet-verify-run")) b.addEventListener("click", () => this._runVerify(b.dataset.box, b.dataset.mode));
    if (this._verFocus) {   // the repaint replaced the button that was clicked
      const b = list.querySelector('.fleet-verify-run[data-box="' + CSS.escape(this._verFocus) + '"]');
      this._verFocus = null;
      if (b) b.focus();
    }
    // footer row: a manual refresh (dispatches `refresh`; the HOST owns the
    // fetch and re-assigns .rows, which re-renders and re-arms the button) +
    // the on-chain registry this table mirrors, linked once the address book
    // has resolved (enclaves register there)
    this._loadRatings(rows.concat(pvmRows));      // stars per box, one eth_call for the panel
    const foot = this.querySelector(".fleet-foot");
    if (foot) {
      foot.innerHTML = (pages > 1
          ? '<span class="fleet-pager" role="group" aria-label="Host pages">'
            + '<button class="fleet-pg" type="button" data-step="-1" aria-label="Previous hosts"' + (this._page === 0 ? ' disabled' : '') + '>‹</button>'
            + '<span class="fleet-pg-n">' + (first + 1) + '–' + Math.min(first + PAGE, items.length) + ' of ' + items.length + '</span>'
            + '<button class="fleet-pg" type="button" data-step="1" aria-label="Next hosts"' + (this._page === pages - 1 ? ' disabled' : '') + '>›</button>'
            + '</span>'
          : '')
        + '<button class="fleet-refresh" type="button" title="re-fetch the live fleet view">↻ refresh</button>'
        + (/^0x[0-9a-fA-F]{40}$/.test(REGISTRY_ADDRESS || "")
          ? '<a class="contract-link" href="' + catExplorer() + '/address/' + REGISTRY_ADDRESS + '" target="_blank" rel="noopener" title="EnclaveRegistry · ' + REGISTRY_ADDRESS + '">'
            + '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
            + '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>'
            + '<line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="13" y2="17"/></svg> contract</a>'
          : "");
      const btn = foot.querySelector(".fleet-refresh");
      btn.addEventListener("click", () => {
        btn.disabled = true;
        this.dispatch("refresh");
        setTimeout(() => { btn.disabled = false; }, 4000);   // safety net if no host listener re-assigns .rows
      });
      for (const p of foot.querySelectorAll(".fleet-pg")) p.addEventListener("click", () => {
        this._page += Number(p.dataset.step);
        this._pgFocus = p.dataset.step;
        this._rateOpen = false; this._renderDeferred = false;   // a page turn drops an open rating form, as a wallet switch does
        super.requestRender();
      });
      // the repaint replaced the button that was clicked: keep keyboard focus on the pager
      if (this._pgFocus) {
        const p = foot.querySelector('.fleet-pg[data-step="' + this._pgFocus + '"]:not(:disabled)') || foot.querySelector(".fleet-pg:not(:disabled)");
        this._pgFocus = null;
        if (p) p.focus();
      }
    }
  }

  /* The host page re-assigns .rows on a 20s poll, and every assignment
     repaints the whole list - which would yank an open rating form out from
     under the wallet mid-edit (nothing "auto-hides" it; the row simply gets
     rebuilt). While a form is open the repaint is DEFERRED, then flushed when
     it closes, so fresh capacity numbers still land the moment the user is
     done. */
  requestRender(){
    if (this._rateOpen){ this._renderDeferred = true; return; }
    super.requestRender();
  }
  _closeRate(box, btn){
    this._rateOpen = false;
    if (box){ box.hidden = true; box.innerHTML = ""; }
    if (btn) btn.setAttribute("aria-expanded", "false");
    if (this._renderDeferred){ this._renderDeferred = false; super.requestRender(); }
  }

  /* ---- verifying a host in this browser ----
     The result is kept per box name and painted from that state, so the 20 s
     fleet repaint (which rebuilds every row) neither drops a verdict nor
     interrupts a check in flight. verifyBoxInBrowser reuses a result for 60 s. */
  _verifyHtml(e){
    if (!boxVerifiable(e))
      return '<div class="fleet-verify"><p class="lv-na">In-browser check: not available for <b>' + esc(e.name || "this host")
        + '</b>, ' + esc(unverifiableReason(e)) + '</p></div>';
    const v = (this._ver ||= {})[e.name] || {};
    const body = v.busy ? '<div class="lv-verdict" role="status">challenging ' + esc(e.name) + ' with a fresh nonce and verifying its evidence in your browser …</div>'
      : v.r ? verificationHtml(e.name, v.r)
      : v.err ? '<div class="lv-verdict bad" role="status">✗ could not run verification: ' + esc(v.err) + '</div>'
      : '';
    return '<div class="fleet-verify" data-vkey="box:' + esc(e.name) + '"' + (v.busy ? ' aria-busy="true"' : '') + '>'
      + '<div class="fleet-verify-h"><span>Is this box what it claims? Check ' + esc(EVIDENCE_OF[e.mode]) + ' yourself.</span>'
      + '<button class="btn btn-sm fleet-verify-run" type="button" data-box="' + esc(e.name) + '" data-mode="' + esc(e.mode) + '"' + (v.busy ? ' disabled' : '') + '>'
      + (v.r || v.err ? 'Verify again' : 'Verify in your browser') + ' <span class="arr">→</span></button></div>'
      + body + '</div>';
  }
  async _runVerify(name, mode){
    const ver = (this._ver ||= {});
    if (ver[name] && ver[name].busy) return;
    ver[name] = { busy: true }; this._verFocus = name; this.requestRender();
    try { ver[name] = { r: await verifyBoxInBrowser(name, { mode }) }; }
    catch (e) { ver[name] = { err: e && e.message ? e.message : String(e) }; }
    this._verFocus = name; this.requestRender();
  }

  /* ---- rating a host: the same 5-star control the app store uses ----
     The contract takes a RECEIPT - one of your funded deployments whose
     `runner` is this box - and checks it itself, so the form's job is to find
     that deployment first. Your deployment rows already name the enclave
     serving them (the relay stamps it), which is exactly the "runs here now"
     the receipt needs. No receipt = the form says why instead of offering a
     signature that would revert. */
  _wireRate(){
    for (const btn of this.querySelectorAll(".fleet-rate"))
      btn.addEventListener("click", () => this._openRate(btn));
  }
  async _openRate(btn){
    const encId = btn.dataset.encid, name = btn.dataset.rate;
    const box = this.querySelector('[data-form="' + CSS.escape(encId) + '"]');
    if (!box) return;
    if (!box.hidden) return this._closeRate(box, btn);
    box.hidden = false; btn.setAttribute("aria-expanded", "true");
    this._rateOpen = true;                 // hold off list repaints until this closes
    box.innerHTML = '<p class="fleet-gate dim">checking whether this enclave runs an app of yours…</p>';
    if (!Enclave.address){
      box.innerHTML = '<p class="fleet-gate">Only wallets whose apps this enclave has run can rate it. '
        + '<button class="btn btn-sm" data-act="connect" type="button">Connect wallet</button></p>';
      box.querySelector('[data-act="connect"]').addEventListener("click", () => connectWallet().then(() => this._openRate(btn)).catch(() => {}));
      return;
    }
    const [receipt, mine] = await Promise.all([
      this._receiptFor(name).catch(() => null),
      hrevMine(encId, Enclave.address).catch(() => null),
    ]);
    const already = mine && /^0x0*[1-9a-f]/i.test(mine.reviewer || "");
    if (!receipt && !already){
      box.innerHTML = '<p class="fleet-gate">Nothing of yours is running on <b>' + esc(name) + '</b> right now. '
        + 'Ratings come from wallets whose app this box actually ran - deploy here first, then rate it.</p>';
      return;
    }
    const d = { stars: already ? Number(mine.stars) : 0, body: already ? mine.body : "" };
    const pick = [1, 2, 3, 4, 5].map((n) =>
      '<label class="revs-pick-star' + (d.stars >= n ? " on" : "") + '">'
      + '<input class="sr-only" type="radio" name="hrevStars-' + esc(encId) + '" value="' + n + '"' + (d.stars === n ? " checked" : "") + '>'
      + '<span aria-hidden="true">★</span><span class="sr-only">' + n + (n === 1 ? " star" : " stars") + '</span></label>').join("");
    box.innerHTML = '<div class="revs-write">'
      + '<fieldset class="revs-pick"><legend>' + (already ? "Update your rating of " : "Rate ") + esc(name) + '</legend>' + pick + '</fieldset>'
      + '<textarea class="revs-body" rows="2" placeholder="How did this box run it? (optional)"></textarea>'
      + '<div class="revs-write-foot">'
        + '<span class="revs-count">' + REVIEW_MAX_BODY + ' left</span>'
        + (receipt ? '<span class="revs-receipt" title="the funded deployment this enclave is running for you">receipt ' + esc(short(receipt)) + '</span>'
                   : '<span class="revs-receipt" title="you have rated this box before, so an edit needs no fresh receipt">editing your rating</span>')
        + '<button class="btn btn-primary btn-sm" data-act="post" type="button" disabled>' + (already ? "Update rating" : "Post rating") + '</button>'
      + '</div></div>';
    const ta = box.querySelector(".revs-body"); ta.value = d.body || "";
    const post = box.querySelector('[data-act="post"]');
    const count = box.querySelector(".revs-count");
    const sync = () => {
      const on = box.querySelector('input[type="radio"]:checked');
      const left = REVIEW_MAX_BODY - new TextEncoder().encode(ta.value || "").length;
      count.textContent = left + " left"; count.classList.toggle("over", left < 0);
      post.disabled = this._busy || !on || left < 0;
      for (const l of box.querySelectorAll(".revs-pick-star"))
        l.classList.toggle("on", on && Number(l.querySelector("input").value) <= Number(on.value));
    };
    box.addEventListener("change", sync); ta.addEventListener("input", sync); sync();
    post.addEventListener("click", () => this._postRate(box, encId, name, receipt, post, sync));
  }

  /* One of MY deployments this box is running now (the relay stamps each row
     with the serving enclave's name). Funded is implied: a row only has a
     runner because a lease was claimed, and the contract re-checks anyway. */
  async _receiptFor(name){
    const res = await Enclave.listDeployments();
    const rows = Array.isArray(res) ? res : ((res && (res.deployments || res.items || res.data)) || []);
    const hit = rows.find((d) => d && d.enclave === name && /^0x[0-9a-f]{64}$/i.test(d.id || "")
      && ["running", "claimed", "provisioning"].includes(d.status || ""));
    return hit ? hit.id : null;
  }

  async _postRate(box, encId, name, receipt, btn, sync){
    const on = box.querySelector('input[type="radio"]:checked');
    if (!on) return;
    const body = box.querySelector(".revs-body").value || "";
    this._busy = true; btn.disabled = true; btn.textContent = "signing…";
    try {
      if (!Enclave.provider) await connectWallet();
      await ensureBaseChain();
      const data = encCall(HREV_SEL.post, [
        { t: "bytes32", v: encId },
        { t: "bytes32", v: receipt || "0x" + "0".repeat(64) },
        { t: "uint", v: Number(on.value) },
        { t: "str", v: body },
      ]);
      const hash = await sendTx(HOST_REVIEWS_ADDRESS, data);
      showToast("rating " + name + " · " + hash.slice(0, 12) + "…");
      await waitReceipt(hash);
      showToast("rated " + name);
      this._closeRate(box, this.querySelector('.fleet-rate[data-encid="' + CSS.escape(encId) + '"]'));
      this._tallyKey = null;                 // force a re-read so the stars move
      this._loadRatings(this.rows || []);
    } catch (e) {
      showToast("rating failed: " + ((e && (e.shortMessage || e.message)) || e));
      btn.textContent = "Post rating";
    } finally { this._busy = false; if (sync) sync(); }
  }

  /* The opened row's rating control: the "rate" button (the rating itself is on the summary, see _fbHtml).
     Absent contract (not deployed / not in the address book yet) renders nothing. */
  _ratingHtml(e){
    if (!hrevConfigured()) return "";
    return '<button class="fleet-rate btn btn-sm" type="button" data-rate="' + esc(e.name || "") + '" data-encid="' + esc(e.id || "") + '" aria-expanded="false" '
      + 'title="Rate this enclave - open to wallets whose app it is running">rate</button>';
  }

  /* The summary's rating, on the line under the name: the stars, the average and how many rated it
     ("★★★★☆ 4.6 (12)"), or "unrated". It is also the rating sort button: best first, again for the worst.
     Nothing while the tallies are unread, or when the contract isn't in the address book - an unrated fleet
     and an unreadable one are different claims. */
  _fbHtml(e, sortBy){
    if (!hrevConfigured() || !this._tallies) return "";
    const t = this._tallies[String(e.id || "").toLowerCase()], n = t ? Number(t.count) : 0;
    const on = sortBy && sortBy.key === "rating" ? (sortBy.dir < 0 ? " on desc" : " on") : "";
    if (!n) return '<button class="fleet-fb fleet-unrated' + on + '" type="button" data-sort="rating" '
      + 'title="No wallet has rated this enclave yet. Click to sort hosts by rating.">unrated</button>';
    const avg = Number(t.sum) / n;
    return '<button class="fleet-fb' + on + '" type="button" data-sort="rating" title="' + n + ' rating' + (n === 1 ? "" : "s")
      + ' from wallets whose apps this enclave ran. Click to sort hosts by rating.">'
      + starsHtml(avg) + '<small>' + avg.toFixed(1) + ' (' + n + ')</small></button>';
  }
  /* rating order: the average, then more ratings first among equals; an unrated host has none (sorted last,
     like a host without a price) */
  _ratingSort(e){
    const t = this._tallies && this._tallies[String(e.id || "").toLowerCase()], n = t ? Number(t.count) : 0;
    return n ? Number(t.sum) / n + Math.min(n, 1e6) / 1e8 : null;
  }

  /* One talliesOf call covers every visible box. Cached per paint; a fleet
     row set that hasn't changed doesn't re-read the chain. */
  async _loadRatings(rows){
    if (!hrevConfigured()) return;
    const ids = rows.map((e) => String(e.id || "")).filter((x) => /^0x[0-9a-f]{64}$/i.test(x));
    const key = ids.join(",");
    if (!ids.length || key === this._tallyKey) return;
    this._tallyKey = key;
    try {
      const rowsT = await hrevTallies(ids);
      this._tallies = Object.fromEntries(rowsT.map((r) => [String(r.enclaveId).toLowerCase(), r]));
      this.requestRender();    // repaint with the stars in place
    } catch { /* ratings are decoration: a chain hiccup must not blank the panel */ }
  }
}
register("c-fleet-list", FleetList);
