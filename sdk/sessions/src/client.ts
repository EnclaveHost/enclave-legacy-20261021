import {
  createPublicClient, decodeErrorResult, encodeFunctionData, hashTypedData, http, keccak256, type Address, type Hex, type PublicClient,
} from "viem";
import { sessionVaultAbi, sessionVaultFactoryAbi, usdcAbi, addressBookAbi } from "./abi.js";
import { amountOf, encodeArgs, type ActionArgs } from "./args.js";
import { ACTIONS, BOOK_KEY_FACTORY, NETWORKS, type ActionName, type OnChainAction } from "./constants.js";
import { deserialize, serialize } from "./grant.js";
import { base64url, sha256Hex, type SessionSigner } from "./keys.js";
import { digestOf, grantDigest, sessionIdOf, typedData, type Grant, type PrimaryType } from "./typed.js";

// ============================================================================
// Errors
// ============================================================================

export type SessionErrorCode =
  | "not_live" | "expired" | "not_allowed" | "env" | "app" | "budget" | "period" | "rate" | "fee"
  | "signature" | "nonce" | "policy" | "relay" | "revert" | "config" | "price" | "delegation";

/** Every failure the UI or an agent must act on carries a code, never just text:
 *  budget/period -> offer a top-up, expired/not_live -> extend or sign in again,
 *  not_allowed/env/app -> the owner must act, delegation -> the owner's wallet has not
 *  let its vault act on the records the wallet holds (setDelegateCall). */
export class SessionError extends Error {
  constructor(public code: SessionErrorCode, message: string, public detail?: Record<string, unknown>) {
    super(message);
    this.name = "SessionError";
  }
}

const ERROR_CODES: Record<string, SessionErrorCode> = {
  NotLive: "not_live", Expired: "expired", NotAllowed: "not_allowed", EnvNotAllowed: "env",
  WrongEnvironment: "env", AppNotAllowed: "app", BudgetExceeded: "budget", PeriodLimit: "period",
  RateLimit: "rate", FeeTooHigh: "fee", BadSignature: "signature", BadNonce: "nonce", NonceUsed: "nonce",
  BadPolicy: "policy", UnknownAction: "policy", UnknownEnvironment: "policy", AppFeeTooHigh: "app",
  NotHeld: "env", NotMine: "env", NoAttestation: "policy", OverCap: "budget",
  // the deployment's price is outside what a session may pay or set: the owner's wallet acts
  RateCapOutOfRange: "price", FundRateTooLow: "price", LeaseUnsettled: "price",
};

/** Turn vault revert data into a SessionError (unknown data -> code "revert"). */
export function decodeVaultError(data: Hex | undefined): SessionError {
  if (data && data.length >= 10) {
    try {
      const e = decodeErrorResult({ abi: sessionVaultAbi, data });
      const args = (e.args ?? []) as readonly unknown[];
      // the LEDGER's owner gate, bubbled through the vault: on a record the owner's wallet holds it means
      // the wallet has not let this vault act for it (setDelegate) - or took that back
      if ((e.errorName as string) === "Error" && args[0] === "!owner")
        return new SessionError("delegation", "the ledger refused: your wallet has not let your session vault manage "
          + "the deployments it holds (grant it once with setDelegate, from the wallet)", { error: "Error", args });
      return new SessionError(ERROR_CODES[e.errorName] ?? "revert", `${e.errorName}(${args.map(String).join(", ")})`,
        { error: e.errorName, args });
    } catch { /* not ours */ }
  }
  return new SessionError("revert", "the vault refused the operation", { data });
}

// ============================================================================
// Relay HTTP
// ============================================================================

export class RelayClient {
  private readonly f: typeof fetch;
  constructor(public readonly base: string, fetchImpl?: typeof fetch) {
    this.f = fetchImpl ?? globalThis.fetch.bind(globalThis);
  }

  async request<T>(method: "GET" | "POST", path: string, body?: unknown, headers?: Record<string, string>): Promise<T> {
    const url = `${this.base.replace(/\/$/, "")}/v1/sessions${path}`;
    let res: Response;
    try {
      res = await this.f(url, {
        method,
        headers: { ...(body ? { "content-type": "application/json" } : {}), ...(headers ?? {}) },
        body: body ? serialize(body) : undefined,
      });
    } catch (e) {
      throw new SessionError("relay", `relay unreachable: ${(e as Error).message}`);
    }
    const text = await res.text();
    let json: Record<string, unknown> = {};
    try { json = text ? deserialize(text) : {}; } catch { /* non-JSON */ }
    if (!res.ok) {
      if (typeof json.revert === "string") throw decodeVaultError(json.revert as Hex);
      const code = (json.code as SessionErrorCode) ?? "relay";
      throw new SessionError(code, String(json.error ?? `relay HTTP ${res.status}`), json);
    }
    return json as T;
  }

  config() { return this.request<RelayConfig>("GET", "/config"); }
}

export interface RelayConfig {
  chainId: number;
  factory: Address;
  book: Address;
  usdc: Address;
  router: Address;
  relayer: Address;
  rpc?: string;
  site?: string;
}

// ============================================================================
// Chain reads
// ============================================================================

export interface SessionState {
  live: boolean;
  keyHash: Hex;
  measurement: Hex;
  actions: bigint;
  expiresAt: bigint;
  envs: number;
  state: number;
  anyApp: boolean;
  balance6: bigint;
  spent6: bigint;
  perPeriod6: bigint;
  maxFee6: bigint;
  maxAppFeeHour6: bigint;
  periodStart: bigint;
  period: number;
  opsPerPeriod: number;
  periodSpent6: bigint;
  periodOps: number;
  apps: Hex[];
}

export function chainClient(chainId: number, rpc?: string): PublicClient {
  const net = Object.values(NETWORKS).find((n) => n.chainId === chainId);
  const url = rpc ?? net?.rpc;
  if (!url) throw new SessionError("config", `no RPC for chain ${chainId}`);
  return createPublicClient({ transport: http(url, { retryCount: 2 }) }) as PublicClient;
}

export async function readSession(pc: PublicClient, vault: Address, sid: Hex): Promise<SessionState> {
  const [s, live, apps] = (await pc.readContract({
    address: vault, abi: sessionVaultAbi, functionName: "sessionOf", args: [sid],
  })) as unknown as [Omit<SessionState, "live" | "apps">, boolean, Hex[]];
  return { ...s, live, apps } as SessionState;
}

export async function resolveFactory(pc: PublicClient, book: Address): Promise<Address> {
  const key = `0x${Array.from(new TextEncoder().encode(BOOK_KEY_FACTORY), (b) => b.toString(16).padStart(2, "0")).join("").padEnd(64, "0")}` as Hex;
  return pc.readContract({ address: book, abi: addressBookAbi, functionName: "addr", args: [key] }) as Promise<Address>;
}

export async function vaultAddress(pc: PublicClient, factory: Address, owner: Address): Promise<Address> {
  return pc.readContract({ address: factory, abi: sessionVaultFactoryAbi, functionName: "vaultFor", args: [owner] }) as Promise<Address>;
}

/** What the session can still spend right now (budget and period window both). */
export function spendable(s: SessionState, now = BigInt(Math.floor(Date.now() / 1000))): bigint {
  const fresh = now >= s.periodStart + BigInt(s.period);
  const left = fresh ? s.perPeriod6 : (s.perPeriod6 > s.periodSpent6 ? s.perPeriod6 - s.periodSpent6 : 0n);
  return s.balance6 < left ? s.balance6 : left;
}

// ============================================================================
// The session (key holder side: browser tab or agent)
// ============================================================================

export interface SessionHandle {
  chainId: number;
  vault: Address;
  sid: Hex;
  owner?: Address;
  label?: string;
  relay: string;
  rpc?: string;
}

export interface CallResult { txHash: Hex; result: Hex; fee: bigint }

/** Portable calldata for any gas payer. Preparation signs an intent, but does not
 * submit it. The caller must check the receipt; preparation does not reserve a nonce. */
export interface PreparedSessionTransaction { chainId: number; to: Address; data: Hex; value: 0n }

async function directDeadline(pc: PublicClient, chainId: number, seconds = 600): Promise<bigint> {
  if (!Number.isSafeInteger(seconds) || seconds < 1 || seconds > 3600)
    throw new SessionError("config", "deadlineSeconds must be an integer from 1 to 3600");
  if (await pc.getChainId() !== chainId) throw new SessionError("config", "RPC chain does not match the session");
  return (await pc.getBlock()).timestamp + BigInt(seconds);
}

export class Session {
  readonly relay: RelayClient;
  private pc?: PublicClient;
  constructor(public readonly handle: SessionHandle, public readonly signer: SessionSigner,
    opts: { fetch?: typeof fetch; publicClient?: PublicClient } = {}) {
    this.relay = new RelayClient(handle.relay, opts.fetch);
    this.pc = opts.publicClient;
  }

  private chain(): PublicClient { return (this.pc ??= chainClient(this.handle.chainId, this.handle.rpc)); }

  status(): Promise<SessionState> { return readSession(this.chain(), this.handle.vault, this.handle.sid); }

  /** Authorize a zero-relay-fee operation using chain reads only. An owner or
   * independent gas payer can broadcast the returned calldata. The vault remains
   * authoritative for scope, attestation, budget, revocation and replay checks. */
  async prepareCall<A extends OnChainAction>(action: A, args: ActionArgs[A],
    opts: { lane?: bigint; deadlineSeconds?: number } = {}): Promise<PreparedSessionTransaction> {
    const lane = opts.lane ?? 0n;
    if (lane < 0n || lane >= (1n << 192n)) throw new SessionError("config", "lane must fit uint192");
    const deadline = await directDeadline(this.chain(), this.handle.chainId, opts.deadlineSeconds);
    const s = await this.status();
    if (!s.live) throw new SessionError("not_live", "this session is not live");
    if (((s.actions >> BigInt(ACTIONS[action])) & 1n) === 0n)
      throw new SessionError("not_allowed", `this session may not ${action}`);
    const amount = amountOf(action, args);
    if (amount > s.balance6) throw new SessionError("budget", `needs ${amount}, session has ${s.balance6}`);
    const data = encodeArgs(action, args);
    const nonce = (lane << 64n) | await this.seq(lane);
    const digest = digestOf(this.handle.chainId, this.handle.vault, "SessionCall", {
      sessionId: this.handle.sid, nonce, action: ACTIONS[action], argsHash: keccak256(data), fee: 0n, deadline,
    });
    const { r, s: sv } = await this.signer.signDigest(digest);
    return { chainId: this.handle.chainId, to: this.handle.vault, value: 0n,
      data: encodeFunctionData({ abi: sessionVaultAbi, functionName: "execute",
        args: [this.handle.sid, nonce, ACTIONS[action], data, 0n, deadline, this.signer.x, this.signer.y, r, sv] }) };
  }

  /** End and refund a session through any gas payer, without contacting a relay. */
  async prepareTermination(opts: { deadlineSeconds?: number } = {}): Promise<PreparedSessionTransaction> {
    const deadline = await directDeadline(this.chain(), this.handle.chainId, opts.deadlineSeconds);
    const digest = digestOf(this.handle.chainId, this.handle.vault, "SessionEnd", { sessionId: this.handle.sid, deadline });
    const { r, s } = await this.signer.signDigest(digest);
    return { chainId: this.handle.chainId, to: this.handle.vault, value: 0n,
      data: encodeFunctionData({ abi: sessionVaultAbi, functionName: "terminateBySession",
        args: [this.handle.sid, deadline, this.signer.x, this.signer.y, r, s] }) };
  }

  /** Check, quote, sign and submit one action. Throws SessionError with a code the
   *  caller can act on (budget -> top-up, expired -> extend, ...). */
  async call<A extends OnChainAction>(action: A, args: ActionArgs[A],
    opts: { lane?: bigint; maxFee?: bigint; deadlineSeconds?: number } = {}): Promise<CallResult> {
    const s = await this.status();
    const now = BigInt(Math.floor(Date.now() / 1000));
    if (!s.live) throw new SessionError(s.expiresAt < now ? "expired" : "not_live",
      s.expiresAt < now ? "this session has expired" : "this session has ended");
    const bit = BigInt(ACTIONS[action]);
    if (((s.actions >> bit) & 1n) === 0n) throw new SessionError("not_allowed", `this session may not ${action}`);
    const data = encodeArgs(action, args);
    const amount = amountOf(action, args);
    const q = await this.relay.request<{ fee: bigint; deadline: bigint; nonce: bigint }>("POST", "/quote", {
      vault: this.handle.vault, sid: this.handle.sid, action: ACTIONS[action], args: data,
    });
    const cap = opts.maxFee !== undefined && opts.maxFee < s.maxFee6 ? opts.maxFee : s.maxFee6;
    if (q.fee > cap) throw new SessionError("fee", `relay fee ${q.fee} exceeds this session's cap ${cap}`);
    const need = amount + q.fee;
    if (need > s.balance6) throw new SessionError("budget", `needs ${need}, session has ${s.balance6}`,
      { need, have: s.balance6 });
    if (need > spendable(s, now)) throw new SessionError("period", `needs ${need}, ${spendable(s, now)} left this period`,
      { need, left: spendable(s, now) });
    const lane = opts.lane ?? 0n;
    const nonce = lane === 0n ? q.nonce : (lane << 64n) | (await this.seq(lane));
    const deadline = opts.deadlineSeconds ? now + BigInt(opts.deadlineSeconds) : q.deadline;
    const digest = digestOf(this.handle.chainId, this.handle.vault, "SessionCall", {
      sessionId: this.handle.sid, nonce, action: ACTIONS[action], argsHash: keccak256(data), fee: q.fee, deadline,
    });
    const { r, s: sv } = await this.signer.signDigest(digest);
    const out = await this.relay.request<{ txHash: Hex; result: Hex }>("POST", "/execute", {
      vault: this.handle.vault, sid: this.handle.sid, nonce, action: ACTIONS[action], args: data, fee: q.fee,
      deadline, x: this.signer.x, y: this.signer.y, r, s: sv,
    });
    return { ...out, fee: q.fee };
  }

  private async seq(lane: bigint): Promise<bigint> {
    return BigInt(await this.chain().readContract({
      address: this.handle.vault, abi: sessionVaultAbi, functionName: "seqOf", args: [this.handle.sid, lane],
    }) as bigint);
  }

  /** Sign-out: the key ends its own session; the remaining budget returns to the owner. */
  async terminate(): Promise<{ txHash: Hex; refund6: bigint }> {
    const deadline = BigInt(Math.floor(Date.now() / 1000) + 600);
    const digest = digestOf(this.handle.chainId, this.handle.vault, "SessionEnd", { sessionId: this.handle.sid, deadline });
    const { r, s } = await this.signer.signDigest(digest);
    return this.relay.request("POST", "/end", {
      vault: this.handle.vault, sid: this.handle.sid, deadline, x: this.signer.x, y: this.signer.y, r, s,
    });
  }

  /** The Authorization header for one API request, bound to method, host+path,
   *  body hash and time (the relay rejects replays and anything older than 60 s). */
  async apiAuthorization(method: string, url: string, body?: string | Uint8Array): Promise<string> {
    return signApiRequest(this.signer, this.handle.vault, this.handle.sid, method, url, body);
  }
}

export async function signApiRequest(signer: SessionSigner, vault: Address, sid: Hex, method: string, url: string,
  body?: string | Uint8Array): Promise<string> {
  const u = new URL(url);
  const ts = Math.floor(Date.now() / 1000);
  const nb = new Uint8Array(12);
  globalThis.crypto.getRandomValues(nb);
  const n = base64url(nb);
  const msg = apiMessage(method, u.host + u.pathname + u.search, body, ts, n, vault, sid);
  const sig = await signer.signBytes(new TextEncoder().encode(msg));
  const enc = (v: bigint) => base64url(hexBytes(v));
  return `EnclaveSession v1 vault=${vault},sid=${sid},ts=${ts},n=${n},x=${enc(signer.x)},y=${enc(signer.y)},sig=${base64url(sig)}`;
}

/** The exact bytes an API request signature covers (shared with the relay's verifier). The vault
 *  and session id are signed too: one key may serve several sessions (an attested agent key), and a
 *  request signed for one must never verify under another. */
export function apiMessage(method: string, hostPath: string, body: string | Uint8Array | undefined, ts: number, n: string,
  vault: string, sid: string): string {
  const bodyHash = sha256Hex(body ?? new Uint8Array()).slice(2);
  return `enclave-api-v1\n${method.toUpperCase()}\n${hostPath}\n${bodyHash}\n${ts}\n${n}\n${vault.toLowerCase()}\n${sid.toLowerCase()}`;
}

function hexBytes(v: bigint): Uint8Array {
  const h = v.toString(16).padStart(64, "0");
  return Uint8Array.from(h.match(/../g)!, (b) => parseInt(b, 16));
}

// ============================================================================
// The owner (wallet side)
// ============================================================================

/** Anything that can produce an EIP-712 signature for the owner: a viem
 *  WalletClient account, or an EIP-1193 provider (MetaMask, WalletConnect). */
export interface OwnerSigner {
  address: Address;
  signTypedData(td: { domain: Record<string, unknown>; types: Record<string, readonly { name: string; type: string }[]>;
    primaryType: string; message: Record<string, unknown> }): Promise<Hex>;
}

export interface Eip1193 { request(args: { method: string; params?: unknown[] }): Promise<unknown> }

const DOMAIN_FIELDS = [
  { name: "name", type: "string" }, { name: "version", type: "string" },
  { name: "chainId", type: "uint256" }, { name: "verifyingContract", type: "address" },
];

export function ownerFromProvider(provider: Eip1193, address: Address): OwnerSigner {
  return {
    address,
    async signTypedData(td) {
      const payload = JSON.stringify({ ...td, types: { EIP712Domain: DOMAIN_FIELDS, ...td.types } },
        (_k, v) => (typeof v === "bigint" ? v.toString() : v));
      return (await provider.request({ method: "eth_signTypedData_v4", params: [address, payload] })) as Hex;
    },
  };
}

export interface UsdcDomain { name: string; version: string; chainId: number; verifyingContract: Address }

/** USDC's EIP-712 domain read from the token itself ("USD Coin" on Base, "USDC" on Base Sepolia). */
export async function usdcDomain(pc: PublicClient, usdc: Address, chainId: number): Promise<UsdcDomain> {
  const [name, version] = await Promise.all([
    pc.readContract({ address: usdc, abi: usdcAbi, functionName: "name" }) as Promise<string>,
    pc.readContract({ address: usdc, abi: usdcAbi, functionName: "version" }) as Promise<string>,
  ]);
  return { name, version, chainId, verifyingContract: usdc };
}

const RECEIVE_TYPES = {
  ReceiveWithAuthorization: [
    { name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" },
  ],
} as const;

/** USDC EIP-3009 authorization whose nonce commits to `commitment` (a grant or
 *  TopUp digest), so it can fund that one thing and nothing else. */
export async function signDeposit(owner: OwnerSigner, usdc: UsdcDomain, vault: Address, value: bigint,
  commitment: Hex, validBefore: bigint): Promise<{ validAfter: bigint; validBefore: bigint; sig: Hex }> {
  const sig = await owner.signTypedData({
    domain: usdc as unknown as Record<string, unknown>, types: RECEIVE_TYPES, primaryType: "ReceiveWithAuthorization",
    message: { from: owner.address, to: vault, value, validAfter: 0n, validBefore, nonce: commitment },
  });
  return { validAfter: 0n, validBefore, sig };
}

/** The owner's half of opening a session: sign the grant (and, with a budget,
 *  the matching USDC authorization), then have the relayer submit. */
export async function openSession(p: {
  relay: RelayClient; owner: OwnerSigner; chainId: number; vault: Address; grant: Grant; usdc?: UsdcDomain;
}): Promise<{ sid: Hex; txHash: Hex; vault: Address }> {
  const td = typedData(p.chainId, p.vault, "SessionGrant", p.grant as unknown as Record<string, unknown>);
  const ownerSig = await p.owner.signTypedData(td as never);
  let deposit;
  if (p.grant.budget > 0n) {
    if (!p.usdc) throw new SessionError("config", "a funded session needs the USDC domain");
    deposit = await signDeposit(p.owner, p.usdc, p.vault, p.grant.budget, grantDigest(p.chainId, p.vault, p.grant),
      p.grant.signBefore);
  }
  const out = await p.relay.request<{ txHash: Hex; vault: Address; sid: Hex }>("POST", "/open",
    { owner: p.owner.address, grant: p.grant, ownerSig, deposit });
  const expect = sessionIdOf(p.vault, p.grant.sessionKey, p.grant.grantNonce);
  if (out.sid !== expect) throw new SessionError("relay", `relay reported sid ${out.sid}, expected ${expect}`);
  return out;
}

/** Open a fresh session without relay discovery or submission. The caller chooses
 * the factory explicitly. A budget uses an owner-signed, grant-bound USDC deposit;
 * any gas payer may submit, but cannot alter the grant or redirect its funds. */
export async function prepareSessionOpen(p: {
  publicClient: PublicClient; factory: Address; owner: OwnerSigner; chainId: number; grant: Grant; usdc?: UsdcDomain;
}): Promise<PreparedSessionTransaction & { vault: Address; sid: Hex }> {
  if (await p.publicClient.getChainId() !== p.chainId) throw new SessionError("config", "RPC chain does not match the grant");
  if (p.grant.budget > 0n && (!p.usdc || p.usdc.chainId !== p.chainId))
    throw new SessionError("config", "a funded session needs the matching chain's USDC domain");
  const vault = await vaultAddress(p.publicClient, p.factory, p.owner.address);
  const ownerSig = await p.owner.signTypedData(typedData(p.chainId, vault, "SessionGrant",
    p.grant as unknown as Record<string, unknown>) as never);
  let data: Hex;
  if (p.grant.budget > 0n) {
    const deposit = await signDeposit(p.owner, p.usdc!, vault, p.grant.budget,
      grantDigest(p.chainId, vault, p.grant), p.grant.signBefore);
    data = encodeFunctionData({ abi: sessionVaultFactoryAbi, functionName: "openWithDepositFor",
      args: [p.owner.address, p.grant, ownerSig, deposit.validAfter, deposit.validBefore, deposit.sig] });
  } else {
    data = encodeFunctionData({ abi: sessionVaultFactoryAbi, functionName: "openFor", args: [p.owner.address, p.grant, ownerSig] });
  }
  return { chainId: p.chainId, to: p.factory, data, value: 0n, vault,
    sid: sessionIdOf(vault, p.grant.sessionKey, p.grant.grantNonce) };
}

export type OwnerOp =
  | { op: "topUp"; sessionId: Hex; amount: bigint }
  | { op: "extend"; sessionId: Hex; expiresAt: bigint }
  | { op: "terminate"; sessionId: Hex }
  | { op: "revokeAll"; withdraw: boolean }
  | { op: "withdraw"; amount: bigint }
  | { op: "promote"; deployment: Hex; app: string; publisher: Address; appRef: string; configCid: string;
      versionLabel: string; isPublic: boolean }
  | { op: "adopt"; deployment: Hex; environment: string }
  /** Moving prod -> staging clears the promotion: the record's existing production secrets become
   *  releasable to whatever a staging session points it at. Say so before asking for the signature. */
  | { op: "setEnvironment"; deployment: Hex; environment: string }
  | { op: "release"; deployment: Hex; to: Address };

const OP_TYPE: Record<OwnerOp["op"], PrimaryType> = {
  topUp: "TopUp", extend: "Extend", terminate: "Terminate", revokeAll: "RevokeAll", withdraw: "Withdraw",
  promote: "Promote", adopt: "Adopt", setEnvironment: "SetEnvironment", release: "Release",
};

function randomNonce(): Hex {
  const b = new Uint8Array(32);
  globalThis.crypto.getRandomValues(b);
  return `0x${Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")}` as Hex;
}

/** Sign one owner operation as readable typed data and have the relayer submit it
 *  (gasless). The owner can always call the vault directly instead. */
export async function ownerOperation(p: {
  relay: RelayClient; owner: OwnerSigner; chainId: number; vault: Address; op: OwnerOp; validSeconds?: number;
}): Promise<{ txHash: Hex }> {
  const opNonce = randomNonce();
  const signBefore = BigInt(Math.floor(Date.now() / 1000) + (p.validSeconds ?? 600));
  const { op, ...fields } = p.op;
  const message = { ...fields, opNonce, signBefore };
  const sig = await p.owner.signTypedData(typedData(p.chainId, p.vault, OP_TYPE[op], message) as never);
  return p.relay.request("POST", "/owner", { owner: p.owner.address, vault: p.vault, op, args: message, sig });
}

/** Top up from the owner's WALLET with one signature (USDC authorization whose
 *  nonce is the TopUp digest). */
export async function topUpFromWallet(p: {
  relay: RelayClient; owner: OwnerSigner; chainId: number; vault: Address; sessionId: Hex; amount: bigint; usdc: UsdcDomain;
}): Promise<{ txHash: Hex }> {
  const opNonce = randomNonce();
  const validBefore = BigInt(Math.floor(Date.now() / 1000) + 600);
  const commitment = hashTypedData(typedData(p.chainId, p.vault, "TopUp",
    { sessionId: p.sessionId, amount: p.amount, opNonce, signBefore: validBefore }) as never);
  const dep = await signDeposit(p.owner, p.usdc, p.vault, p.amount, commitment, validBefore);
  return p.relay.request("POST", "/owner", {
    owner: p.owner.address, vault: p.vault, op: "topUpWithAuthorization",
    args: { sessionId: p.sessionId, amount: p.amount, opNonce, validAfter: dep.validAfter, validBefore, sig: dep.sig },
    sig: "0x",
  });
}

export type { ActionName };
