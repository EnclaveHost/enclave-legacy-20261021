/* ============================================================
   /sso/authorize - Sign in with Enclave for TENANT apps (EST1).

   A tenant app (eyesoff.ai et al) sends a visitor here to reuse
   their enclave.host login. This page authenticates them with the
   relay ACCOUNT session (passkey or wallet SIWE - openSignIn), has
   the relay mint a short-lived, audience-bound EST1 token naming
   the ACCOUNT itself (sub = acct id; the passkey IS the identity,
   relay/sso.js), and returns them to the app with the token in
   the URL fragment. The
   app verifies it inside its own enclave against the published
   signer address; the contract is enclave-apps/eyesoff-ai/
   PLATFORM-sso.md.

   The same invariant as /authorize, for the same reason: the set
   of RETURN ORIGINS is derived from the deployment id alone - its
   canonical <label>.app.enclave.host subdomain plus any custom
   domain the platform has VERIFIED for exactly that deployment
   (/v1/domains/map) - and redirect_uri is honored only if its
   origin is in that set. Otherwise ?aud=<real app>&redirect_uri=
   <attacker> would aim a freshly minted token at an attacker's
   origin. Unlike /authorize the custom-domain origin is allowed
   through (an SSO user should land back on the address they came
   from), which is safe here precisely because the set is built
   from verified ownership rows, never from the parameter.

   `state` is opaque and echoed verbatim: the app refuses a token
   whose state echo does not match the one it stored when it
   started the flow, so a crafted link cannot sign a visitor into
   an account they never chose. Token travels in the FRAGMENT -
   no server log, no Referer.

   A SIGNED-IN visitor passes through with no interaction at all:
   the operator's explicit decision (2026-08-17). Deployments are
   this platform's trust unit, so an app learning a signed-in
   visitor's account id is accepted, not gated on a click. The only
   interaction left is signing in when there is no session, and one
   tap back to a mobile app (a return to /sso-app: see below).

   `prompt=select_account` is the one exception, and the APP asks
   for it: a signed-in visitor then gets a two-button card, continue
   as the current account or use a different one. The second signs
   the account out (this browser only) and opens the chooser. It
   exists because the account session is one per browser and a
   wallet connection is a separate state domain: connecting another
   wallet never changes the account, so without this an app could
   only switch users by sending them to sign out of enclave.host.
   Absent the parameter nothing changes; an app cannot log a
   visitor out by linking here, only offer the choice.
   ============================================================ */
import "../../components/header/header.js";
import "../../components/footer/footer.js";
import "../../components/toast/toast.js";
import "../../components/section-head/section-head.js";
import { Enclave } from "../core/api.js";
import { APP_DOMAIN } from "../core/config.js";
import { $, esc, showToast } from "../core/util.js";
import { openSignIn, restoreAccountSession, signOutAccount } from "../core/account.js";

const card = (html) => '<div class="lk-card">' + html + '</div>';

/* Failure UX: the person came FROM an app, so every failure card leads back
   to it. `back` is only ever an origin DERIVED from the aud (the canonical
   subdomain) or the already-VALIDATED return target - never the raw
   redirect_uri parameter, which on the validation-failure path is exactly
   the thing that could not be trusted. */
function fatal(body, msg, back){
  const links = back
    ? '<a class="btn btn-primary" href="' + esc(back) + '">Back to ' + esc(new URL(back).host) + '</a> ' +
      '<a class="btn" href=".">enclave.host</a>'
    : '<a class="btn" href=".">Go to enclave.host</a>';
  body.innerHTML = card('<p class="co-note">' + esc(msg) + '</p>' + links);
}

/* Return origins this aud may receive a token at: the canonical subdomain,
   plus every custom domain VERIFIED for exactly this deployment. The map
   being unreachable only narrows the set - the subdomain still works. */
async function allowedOrigins(aud){
  const set = new Set(["https://" + aud.slice(2, 10).toLowerCase() + "." + APP_DOMAIN]);
  try {
    const m = await Enclave.domainsMap();
    for (const [host, dep] of Object.entries((m && m.domains) || {}))
      if (String(dep).toLowerCase() === aud.toLowerCase())
        set.add("https://" + String(host).toLowerCase());
  } catch(e){ /* canonical subdomain remains */ }
  return set;
}

/* Short, readable form of the signed-in account for the chooser card. */
function accountLabel(){
  const id = String(Enclave.accountId || "");
  if (/^0x[0-9a-fA-F]{40}$/.test(id)) return id.slice(0, 6) + "…" + id.slice(-4) + " (wallet)";
  if (id.startsWith("acct_")) return "your passkey account (" + id.slice(5, 13) + "…)";
  return id || "your account";
}

/* The account chooser card (prompt=select_account only). Resolves true to
   continue as the current account, false to use a different one. */
function confirmAccount(body, appHost){
  return new Promise((resolve) => {
    body.innerHTML = card(
      '<p class="co-note">Sign in to ' + esc(appHost) + ' as <b>' + esc(accountLabel()) + '</b>?</p>' +
      '<button class="btn btn-primary" id="ssoContinue" type="button">Continue as this account</button> ' +
      '<button class="btn" id="ssoSwitch" type="button">Use a different account</button>');
    $("#ssoContinue").addEventListener("click", () => resolve(true));
    $("#ssoSwitch").addEventListener("click", () => resolve(false));
  });
}

async function mount(){
  const body = $("#ssoBody"); if (!body) return;
  const q = new URL(location.href).searchParams;
  const aud = String(q.get("aud") || "").trim();
  const redirect = String(q.get("redirect_uri") || "").trim();
  const state = String(q.get("state") || "");
  const ttl = parseInt(q.get("ttl") || "", 10) || undefined;
  // "login" is the OpenID spelling of the same ask; both offer the choice
  const chooseAccount = ["select_account", "login"].includes(String(q.get("prompt") || ""));

  // display=popup: the app opened this page in a small window whose frame IS
  // the chrome - drop the site's own, the card carries the whole story
  if (q.get("display") === "popup"){
    for (const t of ["c-header", "c-footer"]){
      const el = document.querySelector(t);
      if (el) el.style.display = "none";
    }
  }

  if (!/^0x[0-9a-fA-F]{64}$/.test(aud))
    return fatal(body, "This sign-in link names no app. Open the app itself and use its sign-in button.");
  // id-derived, so it is a safe "back" destination even when redirect_uri is not
  const canonical = "https://" + aud.slice(2, 10).toLowerCase() + "." + APP_DOMAIN;

  body.innerHTML = card('<p class="co-note">Checking the app…</p>');
  const allowed = await allowedOrigins(aud);
  let target = "";   // validated origin + the caller's own path/query; fragment dropped
  try {
    const u = new URL(redirect);
    if (u.protocol === "https:" && allowed.has(u.origin)) target = u.origin + u.pathname + u.search;
  } catch(e){}
  if (!target)
    return fatal(body, "This link wants to send your sign-in somewhere that does not belong to that app, so nothing was signed. Open the app itself and use its sign-in button.", canonical);
  const appHost = new URL(target).host;

  try {
    restoreAccountSession();
    if (chooseAccount && Enclave.accountAuthed()){
      // the app asked the visitor to confirm WHO signs in: continue as the
      // account this browser holds, or sign it out (here only) and pick
      // another in the chooser
      if (!(await confirmAccount(body, appHost))){
        signOutAccount();
      }
    }
    if (!Enclave.accountAuthed()){
      // straight into the chooser (or a detected wallet's SIWE) - no
      // interstitial button: the app's own Sign in click brought them here,
      // and the ceremonies' buttons inside the modal carry the user
      // activation the credentials need
      body.innerHTML = card('<p class="co-note">Waiting for sign-in…</p>');
      await openSignIn();
    }

    // No consent interstitial and no wallet anywhere on this path - the
    // account IS the identity (sub = acct id), however it authenticates.
    // A signed-in visitor passes straight through.
    body.innerHTML = card('<p class="co-note">Signing you in to ' + esc(appHost) + '…</p>');
    const out = await Enclave.ssoToken(aud, ttl);
    if (!out || !out.token) return fatal(body, "The relay did not return a token. Try again.", target);

    // FRAGMENT handoff: reaches no server log and no Referer
    const back = target + "#sso=" + encodeURIComponent(out.token) +
      (state ? "&state=" + encodeURIComponent(state) : "");
    if (/^\/sso-app(\/|$)/.test(new URL(target).pathname)){
      // The mobile shell's return (enclave-apps mobile-shell): the app claims
      // https://<app>/sso-app as a verified Android app link, and Chrome hands
      // such a link to the app only on a navigation the user STARTS on another
      // site. A scripted redirect, or a tap on the app's own site, stays in
      // the browser tab and the token never reaches the app. So: one tap, here.
      body.innerHTML = card('<p class="co-note">Signed in to ' + esc(appHost) + '.</p>' +
        '<a class="btn btn-primary" id="ssoBack" href="#">Return to the app</a>');
      $("#ssoBack").href = back;
      return;
    }
    body.innerHTML = card('<p class="co-note">Returning to ' + esc(appHost) + '…</p>');
    location.replace(back);
  } catch(e){
    if (/rejected|cancelled|cancel/i.test((e && e.message) || "")) return fatal(body, "Cancelled. Nothing was signed.", target);
    showToast((e && e.message) || String(e));
    fatal(body, (e && e.message) || String(e), target);
  }
}

mount();
