/* ============================================================
   Site-wide configuration - endpoints, chains, contract
   addresses. One place to edit when anything is redeployed
   (scripts/sync-contract-addresses.sh rewrites the addresses).
   ============================================================ */

/* Production API gateway (mirrors openapi.json servers[0].url; the Deploy
   page lets a user point at an enclave directly and persists the override). */
export const DEFAULT_API_BASE = "https://api.enclave.host/v1";

/* Through the gateway each deployment gets its OWN origin:
   https://<label>.app.enclave.host (see appLabel in the deploy page). */
export const APP_DOMAIN = "app.enclave.host";

export const BASE_CHAIN = 8453, BASE_CHAIN_HEX = "0x2105";
export const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

/* ---- WalletConnect (optional second transport) -----------------------------
   Injected extensions cannot reach a wallet that is not a browser extension.
   A Trezor Safe 7 on Bluetooth is held by Trezor Suite - a native app - so no
   extension, and no WebUSB, ever sees it; WalletConnect is the only transport
   that does. Set this to a project id from dashboard.reown.com to offer it in
   the wallet chooser. EMPTY = the option is not shown and site/vendor/
   walletconnect.js is never fetched, so the injected path is untouched.

   Not a secret: a WalletConnect project id is a public client identifier that
   ships in every dApp's bundle (it scopes relay rate limits, nothing more). It
   is baked here rather than fetched so the chooser can decide synchronously.

   What it costs, stated plainly: session traffic is carried by Reown's relay,
   a third party. It cannot alter what gets signed - assertSiweLogin() checks
   the challenge grammar client-side BEFORE the wallet ever sees it, on every
   transport - but it does see that a session exists and relays its ciphertext.
   That is a deliberate trade for reaching non-extension wallets at all.

   CSP: the relay socket needs wss://relay.walletconnect.org to be reachable.
   The apex vhost currently serves `connect-src 'self' https: wss:` (checked
   live 2026-08-12), which already permits it — nothing to do. But site/
   deploy.sh syncs script-src ONLY, so connect-src is hand-held in
   /etc/caddy/Caddyfile on nan: if it is ever tightened to a host allowlist,
   that one host has to be carried across or pairing breaks with nothing in the
   UI to explain it. Nothing else needs allowing — the bundle also references
   rpc.walletconnect.org (unused; rpcMap pins Base to mainnet.base.org),
   pulse.walletconnect.org (telemetry) and verify/secure.walletconnect.org
   (iframes, so frame-src not connect-src), and all degrade silently. */
export const WALLETCONNECT_PROJECT_ID = "e935970def12ab5d05b6b8ff7abd8d75";

/* ---- loopback-only override gate -------------------------------------------
   Two reads below (enclave_addressbook, enclave_rpc) exist ONLY so the e2e
   suite can point the site at its local anvil - there the site is served from
   http://localhost:18899, so gating on the ORIGIN keeps that working while
   making both inert anywhere real.

   Why they need gating at all: a persisted enclave_rpc pins EVERY chain read
   to one endpoint, and js/core/addressbook.js resolves the contract addresses
   over those same reads - so a planted value rewrites DEPLOYMENTS_ADDRESS and
   PAYMENT_ROUTER_ADDRESS, and the wallet then signs create/fund/USDC transfers
   to an attacker's contract. Planting one needs an existing foothold on the
   origin (XSS, a hostile extension, a shared browser), but localStorage
   SURVIVES that foothold being closed: the payload outlives the hole it came
   through. That is the whole reason these two are worth gating and the
   sessionStorage addrbook cache below is not - a per-tab cache dies with the
   tab, and repopulating it needs script execution on the origin all over again.

   Gate on the origin rather than on the value: "is this RPC URL loopback?" can
   be satisfied by a value the attacker picks (a loopback port they got you to
   run), while "is this page on loopback?" cannot be satisfied on
   enclave.host at all. Inert in production no matter what the value says. */
const LOOPBACK_ORIGIN = (() => {
  try {
    const h = String(location.hostname || "").toLowerCase();
    return h === "localhost" || h.endsWith(".localhost") ||
           h === "127.0.0.1" || h === "::1" || h === "[::1]";
  } catch (e) { return false; }   // no `location` (node import) => production rules
})();
const devOverride = (k) => {
  if (!LOOPBACK_ORIGIN) return null;
  try { return localStorage.getItem(k); } catch (e) { return null; }
};

/* ---- accounts + order checkout (passkeys/SIWE against the relay, card via
   hosted Stripe Checkout, USDC via the PaymentRouter). LIVE since 2026-07-21;
   the localStorage override exists for tests and local dev (e2e seeds it via
   addInitScript), and "0" is the emergency per-browser off switch. ---- */
let _acct = null; try { _acct = localStorage.getItem("enclave_accounts"); } catch(e){}
export const ACCOUNTS_ENABLED = _acct != null ? _acct === "1" : true;

/* ---- on-chain contracts (Base) ----
   The baked addresses are FALLBACKS for first paint: when
   ADDRESS_BOOK_ADDRESS is set, js/core/addressbook.js resolves the live
   values from the on-chain EnclaveAddressBook and reassigns these bindings
   (`let` exports - importers see the update), so contract redeploys reach
   the site without a rebuild. The last resolve is cached in sessionStorage
   and applied synchronously below, so repeat visits never paint stale
   addresses even for a frame. */
/* localStorage "enclave_addressbook" override (absent in production; points a
   local run at a local chain's book) - loopback-origin only, see devOverride:
   this address is the root of contract-address resolution, so an attacker who
   sets it chooses every contract the wallet is asked to sign against. */
const _book = devOverride("enclave_addressbook");
export const ADDRESS_BOOK_ADDRESS = _book || "0xab214342d5A490150A4A977063A2f88E21F80907"; // EnclaveAddressBook on Base; written by scripts/deploy-address-book.mjs ("" = baked addresses only)
// KEEP THESE CURRENT. They are the fallback used before the address book
// resolves (and if it fails), and a RETIRED EnclaveDeployments still answers
// get() for the same deployment ids with a stale record — active:false, old
// shares, no lease. So a stale fallback does not fail loudly; it hands the
// console a plausible wrong answer, and any write goes to the dead ledger.
// Observed 2026-07-28: 0xa025ed60… read active:true/cpu 80/lease live on the
// live contract and active:false/cpu 10/no lease on the baked one.
export let APP_CATALOG_ADDRESS = "0x18419ca2b502d423a8de6269aeee171a378626e3"; // EnclaveAppCatalog on Base; matches the on-chain address book
export let DEPLOYMENTS_ADDRESS = "0xf9e71385c5cb49844f2457ba6567de0742f8b89a"; // EnclaveDeployments on Base; written automatically by scripts/deploy-deployments.mjs
export let REGISTRY_ADDRESS    = "";                            // EnclaveRegistry (fleet membership); resolved from the address book only
export let FEATURED_ADDRESS    = "";                            // EnclaveFeatured (featured-slot view bids); resolved from the address book only - "" = editorial featured pick, no bidding UI
export let REVIEWS_ADDRESS     = "";                            // EnclaveReviews (1-5 star ratings + comments); resolved from the address book only - "" = the store shows no ratings at all
export let HOST_REVIEWS_ADDRESS = "";                           // EnclaveHostReviews (1-5 star ratings for the ENCLAVES that run apps); book-resolved only - "" = the fleet panel shows no ratings
export let PAYMENT_ROUTER_ADDRESS = "";                         // PaymentRouter (order checkout, USDC -> treasury); resolved from the address book only - "" = card-only checkout
export let SECRET_VAULT_ADDRESS = "";                           // EnclaveSecretVault (secret custody, docs/security/secret-custody.md); book key "secretVault" only - "" = no custody option in the Secrets panel
// the custodian committee new custody policies seal to (a bytes32 committee id in EnclaveSecretVault); "" until one exists.
// An owner's existing policy keeps its own committee whatever this says.
export const CUSTODY_COMMITTEE = "0xf14080496fbb6f12aee6577fd3f0fdc2ba1226a159b727dbfc8bf0de07fe4f9c";   // the bootstrap committee (3 of 4, Enclave-operated: NOT decentralized)
export const APP_CATALOG_CHAIN   = 8453;                        // Base mainnet (kept in sync by the deploy script; 84532 = Base Sepolia)

/* apply an address-book map ({appCatalog, deployments}) onto the live
   bindings; returns which names changed. Called by js/core/addressbook.js. */
export function __applyAddresses(map){
  const ok = (a) => /^0x[0-9a-fA-F]{40}$/.test(a || "");
  const changed = [];
  if (map && ok(map.appCatalog) && map.appCatalog.toLowerCase() !== APP_CATALOG_ADDRESS.toLowerCase()){
    APP_CATALOG_ADDRESS = map.appCatalog; changed.push("APP_CATALOG_ADDRESS");
  }
  if (map && ok(map.deployments) && map.deployments.toLowerCase() !== DEPLOYMENTS_ADDRESS.toLowerCase()){
    DEPLOYMENTS_ADDRESS = map.deployments; changed.push("DEPLOYMENTS_ADDRESS");
  }
  if (map && ok(map.registry) && map.registry.toLowerCase() !== REGISTRY_ADDRESS.toLowerCase()){
    REGISTRY_ADDRESS = map.registry; changed.push("REGISTRY_ADDRESS");
  }
  if (map && ok(map.featured) && map.featured.toLowerCase() !== FEATURED_ADDRESS.toLowerCase()){
    FEATURED_ADDRESS = map.featured; changed.push("FEATURED_ADDRESS");
  }
  if (map && ok(map.reviews) && map.reviews.toLowerCase() !== REVIEWS_ADDRESS.toLowerCase()){
    REVIEWS_ADDRESS = map.reviews; changed.push("REVIEWS_ADDRESS");
  }
  if (map && ok(map.hostReviews) && map.hostReviews.toLowerCase() !== HOST_REVIEWS_ADDRESS.toLowerCase()){
    HOST_REVIEWS_ADDRESS = map.hostReviews; changed.push("HOST_REVIEWS_ADDRESS");
  }
  if (map && ok(map.secretVault) && map.secretVault.toLowerCase() !== SECRET_VAULT_ADDRESS.toLowerCase()){
    SECRET_VAULT_ADDRESS = map.secretVault; changed.push("SECRET_VAULT_ADDRESS");
  }
  if (map && ok(map.paymentRouter) && map.paymentRouter.toLowerCase() !== PAYMENT_ROUTER_ADDRESS.toLowerCase()){
    PAYMENT_ROUTER_ADDRESS = map.paymentRouter; changed.push("PAYMENT_ROUTER_ADDRESS");
  }
  return changed;
}
if (ADDRESS_BOOK_ADDRESS){
  try { __applyAddresses(JSON.parse(sessionStorage.getItem("enclave_addrbook") || "null")); } catch(e){}
}
export const APP_CATALOG_RPC     = "https://base-rpc.publicnode.com";  // preferred read endpoint (CORS-enabled; browsing needs no wallet). NOTE: deploy-app-catalog.mjs rewrites this to mainnet.base.org on every catalog deploy - restore publicnode after (it rate-limits hard enough to trip one catalog load; kept in the pool as last resort)
/* Failover pool: reads are stateless, and every public Base RPC rate-limits by
   IP - the official mainnet.base.org hard enough that one catalog load can
   trip "over rate limit". Calls start on the last endpoint that worked and
   rotate on failure. A localStorage "enclave_rpc" override (absent in
   production; the e2e suite seeds it) points every read at one endpoint, which
   is exactly why it is loopback-origin only - see devOverride above. */
const _rpc = devOverride("enclave_rpc");
export const APP_CATALOG_RPCS    = _rpc ? [_rpc] : [APP_CATALOG_RPC, "https://base.drpc.org", "https://1rpc.io/base", "https://mainnet.base.org"];

/* ---- IPFS ---- */
// Enable after the configured adapter release supports direct signatures.
export const IPFS_WALLET_AUDIENCE = "";
export const IPFS_UPLOAD_URL = "https://ipfs.enclave.host/add-wasm"; // validating upload gateway (server validates + pins); empty => paste-a-CID only
export const IPFS_IMAGE_UPLOAD_URL = "https://ipfs.enclave.host/add-image"; // validating image pin (app thumbnail/banner); empty => image upload off
export const IPFS_JSON_UPLOAD_URL = "https://ipfs.enclave.host/add-json";   // validating config pin (catalog rev-7 large app configs); empty => configs capped at the on-chain inline limit
export const IPFS_GATEWAY    = "https://ipfs.io/ipfs/";      // where the "fetch .wasm" links resolve
export const IPFS_IMG_GATEWAY = "https://ipfs.enclave.host/ipfs/"; // app media (thumbnail/banner) - served from our own gateway for speed/reliability
export const MAX_WASM_MB     = 2048;                         // upload ceiling (also enforced server-side by Caddy request_body max_size and the add-wasm gateway)
export const MAX_WASM_BYTES  = MAX_WASM_MB * 1024 * 1024;
export const MAX_IMAGE_MB    = 4;                            // thumbnail/banner ceiling (also enforced by the add-image gateway)
export const MAX_IMAGE_BYTES = MAX_IMAGE_MB * 1024 * 1024;
