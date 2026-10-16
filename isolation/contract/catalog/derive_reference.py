#!/usr/bin/env python3
"""An INDEPENDENT implementation of the catalog derivation (DERIVE.md), written from the spec and not from derive.go.

No backend uses this. It exists so that the Go rule every backend links is checked against a second reading of the
same text: derive_vectors.json is generated HERE, and derive_test.go must reproduce it byte for byte, and guestd's
stored mappings are reconstructed with it in isolation/m4/guestd/store_test.go.

    derive_reference.py bundle <record.json> <component> <out.bundle>   prints the mapping as canonical JSON
    derive_reference.py vectors > derive_vectors.json
"""
import hashlib, json, re, struct, sys

# contract/inference.go shieldProfiles: the measured Shield models and their minimum per-card share.
SHIELD_MIN_MILLI={"qwen2.5-0.5b-q8-gguf":65,"qwen3.8-27b-mtp-q4-vl-gguf":500,"z-image-turbo-q4km-sd":100}

MAGIC = b"ENCLAVE-BUNDLE/1\n"
ABI = "enclave-domain-abi/1"
V1 = "enclave-catalog-bundle/1"
V2 = "enclave-catalog-bundle/2"   # V1 + ONE declared HTTP port: a wasi:cli command component that listens on it
V3 = "enclave-catalog-bundle/3"
V4 = "enclave-catalog-bundle/4"
MAX_HTTP_PORT = 49999
PREAMBLE = b"\x00asm\x0d\x00\x01\x00"


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def validate(rec):
    p = rec.get("policy") or {}
    checks = [
        (rec.get("derivation") in (V1, V2, V3, V4), "derivation"),
        ((rec.get("derivation") in (V1,V4) and "http" not in rec) or
         (rec.get("derivation") in (V2, V3, V4) and isinstance(rec.get("http"), int) and not isinstance(rec.get("http"), bool)
          and 1 <= rec["http"] <= MAX_HTTP_PORT), "http"),
        (re.fullmatch(r"0x[0-9a-f]{64}", str((rec.get("catalog") or {}).get("app", ""))) is not None, "catalog.app"),
        (isinstance((rec.get("catalog") or {}).get("version"), int) and 0 <= rec["catalog"]["version"] < 2**32, "catalog.version"),
        (re.fullmatch(r"Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{50,120}|z[1-9A-HJ-NP-Za-km-z]{40,120}", str(rec.get("cid", ""))) is not None, "cid"),
        (isinstance(p.get("cpuPercent"), int) and 1 <= p["cpuPercent"] <= 1600, "policy.cpuPercent"),
        (isinstance(p.get("memMiB"), int) and 64 <= p["memMiB"] <= 65536, "policy.memMiB"),
        (isinstance(p.get("vcpus"), int) and 1 <= p["vcpus"] <= 16, "policy.vcpus"),
        (re.fullmatch(r"[0-9a-f]{64}", str(rec.get("runtimeId", ""))) is not None, "runtimeId"),
    ]
    ports = rec.get("ports", [])
    if rec.get("derivation") == V4:
        inf=rec.get("inference")
        if not isinstance(inf,dict) or set(inf)!={"model","gpuMilli"} or inf["model"] not in SHIELD_MIN_MILLI or type(inf["gpuMilli"]) is not int or not SHIELD_MIN_MILLI[inf["model"]]<=inf["gpuMilli"]<=1000:
            raise ValueError("invalid inference")
    elif "inference" in rec:
        raise ValueError("inference requires V4")
    if rec.get("derivation") == V3 or (rec.get("derivation")==V4 and ports):
        if not isinstance(ports, list) or not 1 <= len(ports) <= 32 or any(not isinstance(p, str) for p in ports):
            raise ValueError("invalid ports")
        if not rec.get("http") or ports != sorted(set(ports)):
            raise ValueError("noncanonical ports")
        for p in ports:
            m = re.fullmatch(r"(tcp|udp):([1-9][0-9]{0,4})", p)
            if not m or not 1 <= int(m[2]) <= MAX_HTTP_PORT or (m[1] == "tcp" and int(m[2]) == rec.get("http")):
                raise ValueError("invalid destination")
    elif ports:
        raise ValueError("only V3 names ports")
    for ok, field in checks:
        if not ok:
            raise ValueError("invalid " + field)


def derive(rec, component):
    validate(rec)
    if not component.startswith(PREAMBLE):
        raise ValueError("not a component")
    manifest = {"abi": ABI, "artifact": {"kind": "wasm-component", "sha256": hashlib.sha256(component).hexdigest()},
                "policy": {"cpuPercent": rec["policy"]["cpuPercent"], "memMiB": rec["policy"]["memMiB"],
                           "vcpus": rec["policy"]["vcpus"]},
                "world": "wasi:http"}          # label is empty, and an empty label is omitted
    if rec.get("http") and rec["derivation"] in (V2, V3, V4):                   # a command that serves HTTP on its declared port
        manifest["world"] = "wasi:cli"
        manifest["http"] = rec["http"]
    if rec["derivation"] in (V3,V4) and rec.get("ports"):
        manifest["ports"] = rec["ports"]
    if rec["derivation"] == V4:
        manifest["inference"] = rec["inference"]
    m = canonical(manifest)
    bundle = MAGIC + struct.pack("<I", len(m)) + m + struct.pack("<I", len(component)) + component
    record = {"derivation": rec["derivation"], "catalog": {"app": rec["catalog"]["app"], "version": rec["catalog"]["version"]},
              "cid": rec["cid"], "policy": manifest["policy"], "runtimeId": rec["runtimeId"]}
    if rec.get("http") and rec["derivation"] in (V2, V3, V4):
        record["http"] = rec["http"]
    if rec["derivation"] in (V3,V4) and rec.get("ports"):
        record["ports"] = rec["ports"]
    if rec["derivation"] == V4:
        record["inference"] = rec["inference"]
    mapping = {"record": record, "recordSha256": hashlib.sha256(canonical(record)).hexdigest(),
               "componentSha256": hashlib.sha256(component).hexdigest(), "componentBytes": len(component),
               "appId": hashlib.sha256(bundle).hexdigest(), "bundleBytes": len(bundle)}
    return bundle, mapping


def vectors():
    comp = PREAMBLE + bytes(range(64)) * 3
    good = {"derivation": V1, "catalog": {"app": "0x" + "ab" * 32, "version": 7},
            "cid": "bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy",
            "policy": {"cpuPercent": 100, "memMiB": 512, "vcpus": 1}, "runtimeId": "cd" * 32}
    out = {"component_hex": comp.hex(), "ok": [], "refused": []}

    def ok(name, rec):
        b, m = derive(rec, comp)
        out["ok"].append({"name": name, "record": rec, "bundleSha256": hashlib.sha256(b).hexdigest(), "mapping": m})

    ok("v1", good)
    ok("another catalog version, same component and policy: same AppID, different record",
       {**good, "catalog": {"app": good["catalog"]["app"], "version": 8}})
    ok("another pinned runtime: same AppID, different record", {**good, "runtimeId": "ef" * 32})
    ok("another policy: another AppID", {**good, "policy": {"cpuPercent": 200, "memMiB": 1024, "vcpus": 2}})
    ok("v2: a command serving HTTP on its declared port: another world, another AppID", {**good, "derivation": V2, "http": 8000})
    ok("v2: another port: another AppID", {**good, "derivation": V2, "http": 8001})
    v3 = {**good, "derivation": V3, "http": 8000, "ports": ["tcp:2222", "tcp:47984", "udp:47998"]}
    ok("v3: measured SSH and GameStream destinations", v3)
    ok("v3: changed destinations change AppID", {**v3, "ports": ["tcp:2222"]})
    v4={**good,"derivation":V4,"inference":{"model":"qwen2.5-0.5b-q8-gguf","gpuMilli":100}}
    ok("v4 measured GPU allocation",v4)
    ok("v4 changed allocation changes AppID",{**v4,"inference":{**v4["inference"],"gpuMilli":200}})
    ok("v4 command and protected port",{**v4,"http":8000,"ports":["tcp:2222"]})
    ok("v4 z-image at its minimum share",{**v4,"inference":{"model":"z-image-turbo-q4km-sd","gpuMilli":100}})
    for name, rec, comp_override in [
        ("v4 missing inference",{**good,"derivation":V4},None),
        ("v4 unsupported model",{**v4,"inference":{"model":"other","gpuMilli":100}},None),
        ("v4 undersized share",{**v4,"inference":{**v4["inference"],"gpuMilli":64}},None),
        ("v4 z-image undersized share",{**v4,"inference":{"model":"z-image-turbo-q4km-sd","gpuMilli":99}},None),
        ("v4 oversized share",{**v4,"inference":{**v4["inference"],"gpuMilli":1001}},None),
        ("v4 undeclared command port",{**v4,"ports":["tcp:2222"]},None),
        ("v1 cannot hide inference",{**v4,"derivation":V1},None),
        ("v3 empty", {**v3, "ports": []}, None),
        ("v3 duplicate", {**v3, "ports": ["tcp:2222", "tcp:2222"]}, None),
        ("v3 unsorted", {**v3, "ports": ["udp:2", "tcp:1"]}, None),
        ("v3 zero prefix", {**v3, "ports": ["tcp:02222"]}, None),
        ("v3 HTTP collision", {**v3, "ports": ["tcp:8000"]}, None),
        ("v2 unexpected ports", {**v3, "derivation": V2}, None),
        ("unknown derivation version", {**good, "derivation": "enclave-catalog-bundle/99"}, None),
        ("v1 naming a port", {**good, "http": 8000}, None),
        ("v2 naming no port", {**good, "derivation": V2}, None),
        ("v2 port out of range", {**good, "derivation": V2, "http": 50000}, None),
        ("v2 port zero", {**good, "derivation": V2, "http": 0}, None),
        ("uppercase catalog app", {**good, "catalog": {"app": "0x" + "AB" * 32, "version": 7}}, None),
        ("policy not pinned", {**good, "policy": {"cpuPercent": 100, "memMiB": 512, "vcpus": 0}}, None),
        ("cid with a gateway prefix", {**good, "cid": "ipfs://" + good["cid"]}, None),
        ("runtime id not pinned", {**good, "runtimeId": ""}, None),
        ("a core module", good, b"\x00asm\x01\x00\x00\x00" + bytes(16)),
        ("not wasm at all", good, b"MZ" + bytes(30)),
    ]:
        try:
            derive(rec, comp_override if comp_override is not None else comp)
        except ValueError:
            out["refused"].append({"name": name, "record": rec,
                                   "component_hex": (comp_override if comp_override is not None else comp).hex()})
            continue
        raise SystemExit("reference accepted a vector it must refuse: " + name)
    return out


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "vectors":
        print(json.dumps(vectors(), indent=1, sort_keys=True))
    elif len(sys.argv) == 5 and sys.argv[1] == "bundle":
        rec = json.load(open(sys.argv[2]))
        b, m = derive(rec, open(sys.argv[3], "rb").read())
        open(sys.argv[4], "wb").write(b)
        print(canonical(m).decode())
    else:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
