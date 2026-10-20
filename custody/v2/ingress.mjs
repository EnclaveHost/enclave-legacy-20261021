// TLS is owned by this host operator. The proxy sees public protocol messages
// and HPKE ciphertext, never the sealed guest state or plaintext secret shares.
// The Shield host-session routes are forwarded too: on an image without the measured Shield opt-in the custodian answers
// them 404 itself (custody/v2/http.mjs). reverse_proxy sets X-Forwarded-For to the client address it saw; the custodian
// reads it only when measured with --trusted-proxy for its forwarder (custody/v2/http.mjs clientKeyFor).
export function directCustodyIngress({endpoint,mgmtPort}) {
  if(typeof endpoint!=='string'||!/^https:\/\/[a-z0-9.-]+\/?$/.test(endpoint))throw Error('direct endpoint must be an HTTPS origin');
  const u=new URL(endpoint);
  if(u.hostname.length>253||u.hostname.split('.').some(label=>!/^([a-z0-9]|[a-z0-9][a-z0-9-]{0,61}[a-z0-9])$/.test(label)))throw Error('invalid endpoint hostname');
  if(!Number.isInteger(mgmtPort)||mgmtPort<1||mgmtPort>65535)throw Error('invalid guest forwarding port');
  return `${u.origin} {
  @public_info {
    method GET
    path /v2/custody/info
  }
  @public_protocol {
    method POST
    path /v2/custody/evidence /v2/custody/challenge /v2/custody/release /v2/custody/join /v2/custody/approve /v2/custody/independent-genesis /v2/custody/code-approve /v2/custody/shield-session/challenge /v2/custody/shield-session/attest
  }
  handle @public_info {
    reverse_proxy 127.0.0.1:${mgmtPort}
  }
  handle @public_protocol {
    reverse_proxy 127.0.0.1:${mgmtPort}
  }
  handle {
    respond "Not found" 404
  }
}
`;
}
