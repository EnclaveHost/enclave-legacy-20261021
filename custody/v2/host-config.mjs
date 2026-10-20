// The custodian's UNMEASURED host configuration (fw_cfg opt/org.enclave.custody, written by the host launcher:
// custody/v2/host.mjs), parsed. Moved out of custody/v2/daemon.mjs unchanged. Exactly these fields are read; anything
// else the host writes is ignored. In particular nothing here can turn on, configure or widen Enclave Shield recipients:
// that is MEASURED only (custody/v2/shield-operator.mjs).
export function parseHostConfig(text) {
  const c = JSON.parse(text);
  const out = {
    endpoint: String(c.endpoint || ""), registryId: String(c.registryId || "").toLowerCase(), hostUrl: String(c.hostUrl || "http://10.0.2.2:8796"),
    committeeId: c.committeeId ? String(c.committeeId).toLowerCase() : null, genesis: c.genesis === true, port: Number(c.port || 8787),
    vcek: c.vcek ? Buffer.from(String(c.vcek), "base64") : null,
  };
  if (!/^https:\/\/[a-z0-9.-]{1,253}(\/[A-Za-z0-9._~-]+){0,4}$/.test(out.endpoint)) throw new Error("host config: endpoint must be an https URL (an optional plain path prefix)");
  if (!/^0x[0-9a-f]{64}$/.test(out.registryId)) throw new Error("host config: registryId must be bytes32");
  if (out.committeeId && !/^0x[0-9a-f]{64}$/.test(out.committeeId)) throw new Error("host config: committeeId must be bytes32");
  return out;
}
