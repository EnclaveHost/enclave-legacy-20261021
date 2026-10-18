// Name resolution for a job's guest origin (https://<id8>.app.enclave.host), through public resolvers instead of the
// host's caching resolver. A job's app name is created minutes before its challenge; a local resolver that was asked
// first (readiness polls start at the claim, before the record exists) can cache NXDOMAIN for longer than the job's
// lease - production job 0x65cab071 (2026-10-18) never saw its guest ready from warden-host. Resolution is not
// evidence: the attested exchange still binds the guest's TLS key and nonce.
import dns from "node:dns";
import https from "node:https";

export const PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"];

// a lookup(hostname, options, callback) for net/tls/https options.lookup
export function publicLookup({ servers = PUBLIC_RESOLVERS, timeoutMs = 4000 } = {}) {
  const resolver = new dns.promises.Resolver({ timeout: timeoutMs, tries: 2 });
  resolver.setServers(servers);
  return (hostname, options, callback) => {
    if (typeof options === "function") { callback = options; options = {}; }
    const opts = typeof options === "number" ? { family: options } : options || {};
    (async () => {
      let v4 = [], v6 = [];
      if (opts.family !== 6) v4 = await resolver.resolve4(hostname).catch(() => []);
      if (opts.family === 6 || (!v4.length && opts.family !== 4)) v6 = await resolver.resolve6(hostname).catch(() => []);
      const all = [...v4.map((address) => ({ address, family: 4 })), ...v6.map((address) => ({ address, family: 6 }))];
      if (!all.length) throw Object.assign(new Error(`${hostname}: no A/AAAA record at the public resolvers`), { code: "ENOTFOUND", hostname });
      return all;
    })().then((all) => (opts.all ? callback(null, all) : callback(null, all[0].address, all[0].family)), (e) => callback(e));
  };
}

export const appLookup = publicLookup();

// the HTTP status of a GET (body discarded), resolved through appLookup; null when nothing answered
export function httpsStatus(url, { timeoutMs = 15_000, lookup = appLookup } = {}) {
  return new Promise((resolve) => {
    const req = https.get(url, { agent: false, lookup }, (res) => { res.resume(); res.on("end", () => resolve(res.statusCode)); res.on("error", () => resolve(null)); });
    req.setTimeout(timeoutMs, () => req.destroy(new Error("timeout")));
    req.on("error", () => resolve(null));
  });
}
