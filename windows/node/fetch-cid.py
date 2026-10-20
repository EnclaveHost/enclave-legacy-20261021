#!/usr/bin/env python3
"""fetch-cid.py -- fetch an app artifact by IPFS CID and VERIFY it against that CID, then write it.

    python fetch-cid.py <cid> <out path> [max bytes] [gateway]

The verification is the platform's own (wasm/ipfs_fetch.py, copied beside this file by sync-apps.sh):
the gateway is asked for a CAR and every block is hashed back to its CID, so a tampering or
substituting gateway fails here rather than handing the node somebody else's wasm. Exit 0 and print
"ok <bytes> <sha256>"; on failure exit 1 and print the reason.
"""
import sys, os, hashlib, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ipfs_fetch

def configured_gateway(argv, environ=os.environ):
    # Read operator-managed sources per fetch: a long-lived VM manager must not
    # retain the retired gateway from its startup environment. Invalid explicit
    # configuration fails closed, rather than falling back to the legacy relay.
    file = environ.get("IPFS_GATEWAYS_FILE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "artifact-gateways.json"))
    if "IPFS_GATEWAYS_FILE" in environ or os.path.exists(file):
        with open(file, encoding="utf-8-sig") as f:
            gateways = json.load(f)
        if not isinstance(gateways, list):
            raise ValueError("artifact gateway file must contain a URL array")
        return ipfs_fetch.gateway_config(gateways)
    return environ.get("IPFS_GATEWAYS") or (argv[4] if len(argv) > 4 else environ.get("IPFS_GATEWAY", "https://ipfs.enclave.host"))

def main():
    if len(sys.argv) < 3:
        print("usage: fetch-cid.py <cid> <out> [max bytes] [gateway]", file=sys.stderr); return 2
    cid, out = sys.argv[1], sys.argv[2]
    cap = int(sys.argv[3]) if len(sys.argv) > 3 else 128 * 1024 * 1024
    try:
        gw = configured_gateway(sys.argv)
        data = ipfs_fetch.fetch_verified(cid, gw, cap, 180)
    except Exception as e:
        print(f"fetch/verify failed for {cid}: {e}", file=sys.stderr); return 1
    tmp = out + ".part"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, out)
    print(f"ok {len(data)} {hashlib.sha256(data).hexdigest()}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
