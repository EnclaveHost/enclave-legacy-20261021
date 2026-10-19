// TLS is owned by this host operator. The proxy sees public protocol messages
// and HPKE ciphertext, never the sealed guest state or plaintext secret shares.
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
    path /v2/custody/evidence /v2/custody/challenge /v2/custody/release /v2/custody/join /v2/custody/approve /v2/custody/independent-genesis
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
