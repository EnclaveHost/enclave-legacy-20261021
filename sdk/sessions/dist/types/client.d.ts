import { type Address, type Hex, type PublicClient } from "viem";
import { type ActionArgs } from "./args.js";
import { type ActionName, type OnChainAction } from "./constants.js";
import { type SessionSigner } from "./keys.js";
import { type Grant } from "./typed.js";
export type SessionErrorCode = "not_live" | "expired" | "not_allowed" | "env" | "app" | "budget" | "period" | "rate" | "fee" | "signature" | "nonce" | "policy" | "relay" | "revert" | "config" | "price" | "delegation";
/** Every failure the UI or an agent must act on carries a code, never just text:
 *  budget/period -> offer a top-up, expired/not_live -> extend or sign in again,
 *  not_allowed/env/app -> the owner must act, delegation -> the owner's wallet has not
 *  let its vault act on the records the wallet holds (setDelegateCall). */
export declare class SessionError extends Error {
    code: SessionErrorCode;
    detail?: Record<string, unknown> | undefined;
    constructor(code: SessionErrorCode, message: string, detail?: Record<string, unknown> | undefined);
}
/** Turn vault revert data into a SessionError (unknown data -> code "revert"). */
export declare function decodeVaultError(data: Hex | undefined): SessionError;
export declare class RelayClient {
    readonly base: string;
    private readonly f;
    constructor(base: string, fetchImpl?: typeof fetch);
    request<T>(method: "GET" | "POST", path: string, body?: unknown, headers?: Record<string, string>): Promise<T>;
    config(): Promise<RelayConfig>;
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
export declare function chainClient(chainId: number, rpc?: string): PublicClient;
export declare function readSession(pc: PublicClient, vault: Address, sid: Hex): Promise<SessionState>;
export declare function resolveFactory(pc: PublicClient, book: Address): Promise<Address>;
export declare function vaultAddress(pc: PublicClient, factory: Address, owner: Address): Promise<Address>;
/** What the session can still spend right now (budget and period window both). */
export declare function spendable(s: SessionState, now?: bigint): bigint;
export interface SessionHandle {
    chainId: number;
    vault: Address;
    sid: Hex;
    owner?: Address;
    label?: string;
    relay: string;
    rpc?: string;
}
export interface CallResult {
    txHash: Hex;
    result: Hex;
    fee: bigint;
}
/** Portable calldata for any gas payer. Preparation signs an intent, but does not
 * submit it. The caller must check the receipt; preparation does not reserve a nonce. */
export interface PreparedSessionTransaction {
    chainId: number;
    to: Address;
    data: Hex;
    value: 0n;
}
export declare class Session {
    readonly handle: SessionHandle;
    readonly signer: SessionSigner;
    readonly relay: RelayClient;
    private pc?;
    constructor(handle: SessionHandle, signer: SessionSigner, opts?: {
        fetch?: typeof fetch;
        publicClient?: PublicClient;
    });
    private chain;
    status(): Promise<SessionState>;
    /** Authorize a zero-relay-fee operation using chain reads only. An owner or
     * independent gas payer can broadcast the returned calldata. The vault remains
     * authoritative for scope, attestation, budget, revocation and replay checks. */
    prepareCall<A extends OnChainAction>(action: A, args: ActionArgs[A], opts?: {
        lane?: bigint;
        deadlineSeconds?: number;
    }): Promise<PreparedSessionTransaction>;
    /** End and refund a session through any gas payer, without contacting a relay. */
    prepareTermination(opts?: {
        deadlineSeconds?: number;
    }): Promise<PreparedSessionTransaction>;
    /** Check, quote, sign and submit one action. Throws SessionError with a code the
     *  caller can act on (budget -> top-up, expired -> extend, ...). */
    call<A extends OnChainAction>(action: A, args: ActionArgs[A], opts?: {
        lane?: bigint;
        maxFee?: bigint;
        deadlineSeconds?: number;
    }): Promise<CallResult>;
    private seq;
    /** Sign-out: the key ends its own session; the remaining budget returns to the owner. */
    terminate(): Promise<{
        txHash: Hex;
        refund6: bigint;
    }>;
    /** The Authorization header for one API request, bound to method, host+path,
     *  body hash and time (the relay rejects replays and anything older than 60 s). */
    apiAuthorization(method: string, url: string, body?: string | Uint8Array): Promise<string>;
}
export declare function signApiRequest(signer: SessionSigner, vault: Address, sid: Hex, method: string, url: string, body?: string | Uint8Array): Promise<string>;
/** The exact bytes an API request signature covers (shared with the relay's verifier). The vault
 *  and session id are signed too: one key may serve several sessions (an attested agent key), and a
 *  request signed for one must never verify under another. */
export declare function apiMessage(method: string, hostPath: string, body: string | Uint8Array | undefined, ts: number, n: string, vault: string, sid: string): string;
/** Anything that can produce an EIP-712 signature for the owner: a viem
 *  WalletClient account, or an EIP-1193 provider (MetaMask, WalletConnect). */
export interface OwnerSigner {
    address: Address;
    signTypedData(td: {
        domain: Record<string, unknown>;
        types: Record<string, readonly {
            name: string;
            type: string;
        }[]>;
        primaryType: string;
        message: Record<string, unknown>;
    }): Promise<Hex>;
}
export interface Eip1193 {
    request(args: {
        method: string;
        params?: unknown[];
    }): Promise<unknown>;
}
export declare function ownerFromProvider(provider: Eip1193, address: Address): OwnerSigner;
export interface UsdcDomain {
    name: string;
    version: string;
    chainId: number;
    verifyingContract: Address;
}
/** USDC's EIP-712 domain read from the token itself ("USD Coin" on Base, "USDC" on Base Sepolia). */
export declare function usdcDomain(pc: PublicClient, usdc: Address, chainId: number): Promise<UsdcDomain>;
/** USDC EIP-3009 authorization whose nonce commits to `commitment` (a grant or
 *  TopUp digest), so it can fund that one thing and nothing else. */
export declare function signDeposit(owner: OwnerSigner, usdc: UsdcDomain, vault: Address, value: bigint, commitment: Hex, validBefore: bigint): Promise<{
    validAfter: bigint;
    validBefore: bigint;
    sig: Hex;
}>;
/** The owner's half of opening a session: sign the grant (and, with a budget,
 *  the matching USDC authorization), then have the relayer submit. */
export declare function openSession(p: {
    relay: RelayClient;
    owner: OwnerSigner;
    chainId: number;
    vault: Address;
    grant: Grant;
    usdc?: UsdcDomain;
}): Promise<{
    sid: Hex;
    txHash: Hex;
    vault: Address;
}>;
/** Open a fresh session without relay discovery or submission. The caller chooses
 * the factory explicitly. A budget uses an owner-signed, grant-bound USDC deposit;
 * any gas payer may submit, but cannot alter the grant or redirect its funds. */
export declare function prepareSessionOpen(p: {
    publicClient: PublicClient;
    factory: Address;
    owner: OwnerSigner;
    chainId: number;
    grant: Grant;
    usdc?: UsdcDomain;
}): Promise<PreparedSessionTransaction & {
    vault: Address;
    sid: Hex;
}>;
export type OwnerOp = {
    op: "topUp";
    sessionId: Hex;
    amount: bigint;
} | {
    op: "extend";
    sessionId: Hex;
    expiresAt: bigint;
} | {
    op: "terminate";
    sessionId: Hex;
} | {
    op: "revokeAll";
    withdraw: boolean;
} | {
    op: "withdraw";
    amount: bigint;
} | {
    op: "promote";
    deployment: Hex;
    app: string;
    publisher: Address;
    appRef: string;
    configCid: string;
    versionLabel: string;
    isPublic: boolean;
} | {
    op: "adopt";
    deployment: Hex;
    environment: string;
}
/** Moving prod -> staging clears the promotion: the record's existing production secrets become
 *  releasable to whatever a staging session points it at. Say so before asking for the signature. */
 | {
    op: "setEnvironment";
    deployment: Hex;
    environment: string;
} | {
    op: "release";
    deployment: Hex;
    to: Address;
};
/** Sign one owner operation as readable typed data and have the relayer submit it
 *  (gasless). The owner can always call the vault directly instead. */
export declare function ownerOperation(p: {
    relay: RelayClient;
    owner: OwnerSigner;
    chainId: number;
    vault: Address;
    op: OwnerOp;
    validSeconds?: number;
}): Promise<{
    txHash: Hex;
}>;
/** Top up from the owner's WALLET with one signature (USDC authorization whose
 *  nonce is the TopUp digest). */
export declare function topUpFromWallet(p: {
    relay: RelayClient;
    owner: OwnerSigner;
    chainId: number;
    vault: Address;
    sessionId: Hex;
    amount: bigint;
    usdc: UsdcDomain;
}): Promise<{
    txHash: Hex;
}>;
export type { ActionName };
