# TEST SUPPORT ONLY: stands in for shielded-bridge.exe on a partition's custody service (custody-transport.mjs), and for
# the hv_sock peer it would accept. argv: <vmId> <vsockPort> <workerPort> 0 [--worker-auth-stdin], as the real one: with
# the flag, the FIRST stdin line is the worker credential ("enclave-bridge-auth-v1 <64 hex>\n"), written at the head of
# every worker connection before any guest byte, exactly as shielded-bridge.rs does; the rest of stdin is the stop signal. (Python, not node, so that
# the fixture's partitions fit the 250 MiB test budget: a node child is ~50 MB, this ~10 MB.)
#
# It listens on a loopback "guest" port in place of the partition's hv_sock service. Each guest connection first states
# the partition it comes from ("VM <guid>\n"), standing in for the VmId the real bridge reads from the hv_sock peer
# address. A connection from another partition is closed, as the real bridge refuses it. The rest of the stream is relayed
# to the worker port and back, byte for byte. The ready line is the real one's. It lives until its stdin ends.
#   FAKE_CUSTODY_BRIDGE (env): ok | exit (refuse at once, as a 10013 bind failure) | hang (never ready)
#   FAKE_CUSTODY_LOG (env): a file each bridge appends JSON lines to: {vm, event, guestPort?}
# NOTHING here is hv_sock, Hyper-V or a partition: it is a fixture for the host-side lifecycle only.
import json, os, socket, sys, threading

vm, vsock_port, worker_port = sys.argv[1], sys.argv[2], int(sys.argv[3])
mode = os.environ.get("FAKE_CUSTODY_BRIDGE") or "ok"
auth = None
if len(sys.argv) == 6 and sys.argv[5] == "--worker-auth-stdin":
    line = sys.stdin.buffer.readline(89)
    ok = (len(line) == 88 and line.startswith(b"enclave-bridge-auth-v1 ") and line.endswith(b"\n")
          and all(c in b"0123456789abcdef" for c in line[23:87]))
    if not ok:
        sys.stderr.write("Error: the first stdin line is not a worker credential (enclave-bridge-auth-v1 <64 lowercase hex>)\n"); sys.exit(2)
    auth = line
elif len(sys.argv) != 5:
    sys.stderr.write("usage: shielded-bridge <partition GUID> <vsock port> <loopback worker port> <lifetime seconds> [--worker-auth-stdin]\n"); sys.exit(2)
lock = threading.Lock()

def log(**o):
    path = os.environ.get("FAKE_CUSTODY_LOG")
    if path:
        with lock, open(path, "a") as f:
            f.write(json.dumps({"vm": vm, **o}) + "\n")

def pump(src, dst):
    try:
        while True:
            b = src.recv(65536)
            if not b:
                break
            dst.sendall(b)
    except OSError:
        pass
    # either side ending ends both (shutdown, not just close: the other thread is blocked in recv on them)
    for s in (src, dst):
        try: s.shutdown(socket.SHUT_RDWR)
        except OSError: pass
        try: s.close()
        except OSError: pass

def guest(g):
    head = b""
    try:
        while b"\n" not in head:
            b = g.recv(256)
            if not b or len(head) > 64:
                g.close(); return
            head += b
    except OSError:
        g.close(); return
    line, rest = head.split(b"\n", 1)
    peer = line.decode("latin1").removeprefix("VM ")
    if peer.lower() != vm.lower():
        log(event="foreign-peer", **{"from": peer}); g.close(); return
    try:
        up = socket.create_connection(("127.0.0.1", worker_port))
        if auth:
            up.sendall(auth)
    except OSError:
        g.close(); return
    if rest:
        up.sendall(rest)
    threading.Thread(target=pump, args=(g, up), daemon=True).start()
    threading.Thread(target=pump, args=(up, g), daemon=True).start()

log(event="start", vsockPort=vsock_port)
if mode == "exit":
    sys.stderr.write("Error: Os { code: 10013, kind: PermissionDenied }\n"); sys.stderr.flush()
    log(event="exit"); sys.exit(2)

def accept(srv):
    while True:
        try:
            g, _ = srv.accept()
        except OSError:
            return
        threading.Thread(target=guest, args=(g,), daemon=True).start()

if mode != "hang":
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(16)
    log(event="ready", guestPort=srv.getsockname()[1])
    sys.stdout.write(f"shielded bridge ready vm={vm} port={vsock_port} worker=127.0.0.1:{worker_port}{' auth=stdin' if auth else ''}\n"); sys.stdout.flush()
    threading.Thread(target=accept, args=(srv,), daemon=True).start()
sys.stdin.buffer.read()          # until stdin ends, as the real bridge
log(event="stdin-eof")
os._exit(0)
