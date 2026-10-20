// EK certificates that must NOT get a host-session challenge from a party pinning `world`'s TPM roots
// (relay/shield-host-session.mjs): each is presented with `world`'s genuine AIK, so only the EK decides. Needs openssl.
//   selfSigned      a self-signed RSA leaf (no CA at all)
//   otherCa         a genuine-looking AMD EK under ANOTHER CA, with that CA's intermediate and root supplied as ekChain
//   rootAsLeaf      the pinned root itself presented as the EK (it chains trivially; it is a CA, not a TPM)
//   interAsLeaf     the pinned intermediate presented as the EK
//   discrete        a leaf issued by the pinned CA naming a discrete (not on-die) TPM manufacturer
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { issueEk } from "../fixtures/vbs-synthetic.mjs";

const b64 = (b) => Buffer.from(b).toString("base64");

export function maliciousEks(world, other) {
  const dir = fs.mkdtempSync(path.join(world.dir, "malicious-"));
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", path.join(dir, "ss.key"), "-out", path.join(dir, "ss.pem"),
    "-days", "2", "-subj", "/CN=self-signed EK", "-addext", "basicConstraints=critical,CA:FALSE"], { stdio: "pipe" });
  const selfSigned = new X509Certificate(fs.readFileSync(path.join(dir, "ss.pem"))).raw;
  const discrete = issueEk(world.dir, { manufacturer: "4E544300" }).cert;          // "NTC": a discrete TPM vendor id
  const keys = (ek, ekChain = []) => ({ ek: b64(ek), ekChain: ekChain.map(b64), aikPub: b64(world.aik.tpmtPublic), aikName: b64(world.aik.name) });
  return {
    selfSigned: { keys: keys(selfSigned), why: /does not chain to a pinned TPM root/ },
    otherCa: { keys: keys(other.ek.cert, [other.ca.inter, other.ca.root]), why: /does not chain to a pinned TPM root/ },
    rootAsLeaf: { keys: keys(world.ca.root), why: /not an on-die TPM's endorsement certificate/ },
    interAsLeaf: { keys: keys(world.ca.inter, [world.ca.root]), why: /not an on-die TPM's endorsement certificate/ },
    discrete: { keys: keys(discrete), why: /not an on-die TPM's endorsement certificate/ },
  };
}
