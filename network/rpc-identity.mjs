// One rule for telling chain RPC peers apart, shared by every quorum reader (network/lease-reader.mjs,
// network/service-index.mjs and its CLI, custody/v2/quorum.mjs, windows/node/host-identity.mjs) so the rule cannot drift.
// Pure and browser-compatible: only URL, regular expressions and integer math. No Node APIs, no imports, no DNS.
//
// A peer's VOTE IDENTITY is the host its URL reaches:
//   * A name is lower-cased, without trailing dots (DNS treats rpc.example. and rpc.example as one name). A name with
//     an empty label (a..b) is malformed.
//   * An address literal is compared as an address. URL itself canonicalizes every IPv4 spelling (127.1, 0x8.8.8.8,
//     134744072) and IPv6 case and zero compression. On top of that, an IPv4 address written in IPv6 form is folded
//     back to it. An IPv4-mapped address (::ffff:0:0/96, RFC 4291) IS that IPv4 host to the local stack, so
//     [::ffff:8.8.8.8] is one vote with 8.8.8.8 and [::ffff:127.0.0.1] is the loopback listener 127.0.0.1. The NAT64
//     well-known prefix (64:ff9b::/96, RFC 6052) reaches that same IPv4 host through a translator, so it shares the
//     vote, but its traffic leaves this machine and it is never loopback. Other embeddings (the deprecated
//     IPv4-compatible ::/96, SIIT ::ffff:0:0:0/96) stay distinct IPv6 addresses.
//   * The port, path, query (an API key) and scheme of a PUBLIC host never make a second vote. Loopback hosts
//     (localhost, 127.0.0.1, [::1], and their mapped forms) are ONE host whatever the name; a caller that runs several
//     local test chains may tell them apart by port (`loopbackPorts`).
// No name is resolved: two names, or a name and an address, may reach one machine, and nothing here can tell. Distinct
// identities are distinct configured endpoints, NEVER proof of independent operators or organizations.
//
// URL POLICY: https for every host; plain http only on loopback (a local chain such as Anvil); no credentials and no
// fragment. Errors never echo the URL, whose path or query may hold an API key; `rpcLabel` gives a safe name.

export const LOOPBACK_HOSTS = Object.freeze(['localhost', '127.0.0.1', '[::1]']);
const loopbackSet = new Set(LOOPBACK_HOSTS);
// URL writes the embedded IPv4 address as the two final 16-bit pieces, compressing zeros: [::ffff:808:808],
// [::ffff:0:1], [64:ff9b::808:808], [64:ff9b::1], [64:ff9b::].
const MAPPED = /^\[::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})\]$/;
const NAT64 = /^\[64:ff9b::(?:([0-9a-f]{1,4}):)?([0-9a-f]{1,4})?\]$/;
const dotted = (hi = '0', lo = '0') => { const a = parseInt(hi, 16), b = parseInt(lo, 16); return [a >> 8, a & 255, b >> 8, b & 255].join('.'); };

/** Why an RPC URL is refused; `code` is one of url | scheme | secret | host. The message names no part of the URL. */
export class RpcUrlError extends Error {
  constructor(code) {
    super({ url: 'invalid RPC URL', scheme: 'RPC URLs must be HTTPS (plain HTTP only on loopback)',
      secret: 'RPC URLs may not carry credentials or a fragment', host: 'RPC URL has a malformed host' }[code]);
    this.name = 'RpcUrlError';
    this.code = code;
  }
}

/** A URL hostname -> { host: the canonical host, loopback: whether plain HTTP may reach it on this machine }, or null. */
export function canonicalHost(hostname) {
  const host = String(hostname).toLowerCase().replace(/\.+$/, '');
  if (!host || (!host.startsWith('[') && host.split('.').some((label) => !label))) return null;
  let m = MAPPED.exec(host);
  if (m) { const v4 = dotted(m[1], m[2]); return { host: v4, loopback: loopbackSet.has(v4) }; }
  m = NAT64.exec(host);
  if (m) return { host: dotted(m[1], m[2]), loopback: false };
  return { host, loopback: loopbackSet.has(host) };
}

/**
 * Check one RPC URL against the URL POLICY and name its vote. -> { url (the parsed URL), host, loopback, port, identity,
 * label }. `identity` is `host:<host>` for a public host; for loopback, `loopback` (one host) or, with
 * `loopbackPorts: true`, `loopback:<port>`. Throws RpcUrlError.
 */
export function rpcEndpoint(raw, { loopbackPorts = true } = {}) {
  let u;
  try { u = new URL(String(raw)); } catch { throw new RpcUrlError('url'); }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new RpcUrlError('scheme');
  const canon = canonicalHost(u.hostname);
  if (!canon) throw new RpcUrlError('host');
  if (u.protocol === 'http:' && !canon.loopback) throw new RpcUrlError('scheme');
  if (u.username || u.password || u.hash || String(raw).includes('#')) throw new RpcUrlError('secret');
  const port = u.port || (u.protocol === 'https:' ? '443' : '80');
  const identity = canon.loopback ? (loopbackPorts ? `loopback:${port}` : 'loopback') : `host:${canon.host}`;
  return { url: u, host: canon.host, loopback: canon.loopback, port, identity, label: label(u, canon.host) };
}

// (an IPv6 host keeps its brackets: URL writes it so, and the mapped forms fold to a dotted IPv4 address)
const label = (u, host) => `${u.protocol}//${host}${u.port ? `:${u.port}` : ''}`;

/** A name for an RPC URL that is safe in logs and evidence: scheme, canonical host and port only. */
export function rpcLabel(raw) {
  try { const u = new URL(String(raw)); const c = canonicalHost(u.hostname); return c ? label(u, c.host) : 'rpc'; } catch { return 'rpc'; }
}

/** Text (an error message from an RPC library, for instance) with every http(s) URL in it replaced by its rpcLabel. */
export function redactUrls(text) {
  return String(text).replace(/\bhttps?:\/\/[^\s"'<>]+/gi, (m) => {
    const tail = /[),.;\]]+$/.exec(m)?.[0] || '';
    return rpcLabel(m.slice(0, m.length - tail.length)) + tail;
  });
}
