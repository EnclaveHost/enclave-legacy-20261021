//! Untrusted transport only: one Hyper-V partition to one loopback GPU worker.
//! The guest must mask and verify through ggml-shielded. This bridge does not
//! attest a GPU, admit a deployment, or accept addresses supplied by a guest.
//!
//! WORKER CREDENTIAL (opt-in, `--worker-auth-stdin`, supervised lifetime 0 only): the loopback worker port is reachable by
//! any local process, so a worker that must admit only this bridge (the manager's package 9446 and custody 9445 servers,
//! windows/vbslike/manager/bridge-auth.mjs) hands it a per-start credential as the FIRST stdin line,
//! "enclave-bridge-auth-v1 <64 lowercase hex>\n", and the bridge writes that exact line at the head of every worker
//! connection before relaying a guest byte. The credential is never in argv, the environment or any output. The rest of
//! stdin stays the stop signal. Without the flag (egress 9443, GPU 19595) nothing changes.
#[path = "../hvsock.rs"]
mod hvsock;
use std::io::{self, Read};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::sync::{Arc, atomic::{AtomicUsize, AtomicBool, Ordering}};
use std::time::{Duration, Instant};

const AUTH_FLAG: &str = "--worker-auth-stdin";
const AUTH_PREFIX: &[u8] = b"enclave-bridge-auth-v1 ";
const AUTH_LINE_BYTES: usize = 23 + 64 + 1;

/// The credential line exactly: the prefix, 64 lowercase hex digits, a newline.
fn valid_auth_line(l: &[u8]) -> bool {
    l.len() == AUTH_LINE_BYTES && l.starts_with(AUTH_PREFIX) && l[AUTH_LINE_BYTES - 1] == b'\n'
        && l[AUTH_PREFIX.len()..AUTH_LINE_BYTES - 1].iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<String> = std::env::args().collect();
    let auth_flag = a.len() == 6 && a[5] == AUTH_FLAG;
    if a.len() != 5 && !auth_flag {
        return Err("usage: shielded-bridge <partition GUID> <vsock port> <loopback worker port> <lifetime seconds> [--worker-auth-stdin]".into());
    }
    let vm = hvsock::parse_guid(&a[1]).ok_or("invalid partition GUID")?;
    if hvsock::guid_string(&vm) == "00000000-0000-0000-0000-000000000000" {
        return Err("wildcard partition is forbidden".into());
    }
    let port: u32 = a[2].parse()?;
    let worker: u16 = a[3].parse()?;
    let seconds: u64 = a[4].parse()?;
    if port == 0 || worker == 0 || seconds > 86400 {
        return Err("nonzero ports and lifetime 0..86400 required (0: supervised stdin)".into());
    }
    if auth_flag && seconds != 0 {
        return Err("--worker-auth-stdin needs lifetime 0: the credential and the stop signal both arrive on stdin".into());
    }
    // ONE buffered reader for stdin: the credential line first (with the flag), then the stop signal, so no byte is lost
    let mut input = io::BufReader::new(io::stdin());
    let auth: Option<Arc<Vec<u8>>> = if auth_flag {
        let mut line = Vec::with_capacity(AUTH_LINE_BYTES);
        let mut b = [0u8; 1];
        while line.len() < AUTH_LINE_BYTES {
            if input.read(&mut b)? == 0 { return Err("stdin ended before the worker credential line".into()); }
            line.push(b[0]);
            if b[0] == b'\n' { break; }
        }
        // the value is never echoed: only whether it is well formed
        if !valid_auth_line(&line) { return Err("the first stdin line is not a worker credential (enclave-bridge-auth-v1 <64 lowercase hex>)".into()); }
        Some(Arc::new(line))
    } else { None };
    let listener = hvsock::Listener::bind(&vm, port)?;
    let stopped = Arc::new(AtomicBool::new(false));
    if seconds == 0 {
        let stop = stopped.clone();
        std::thread::spawn(move || {
            let mut b = [0u8; 1];
            let _ = input.read(&mut b);
            stop.store(true, Ordering::SeqCst);
        });
    }
    let end = Instant::now() + Duration::from_secs(seconds);
    let active = Arc::new(AtomicUsize::new(0));
    // A timed bridge carries one GPU worker's few streams: 8 is plenty. A supervised (persistent) bridge carries an
    // app's whole public-web egress, and a client that stripes over many peers needs more: a Sia upload opens one
    // connection per host for 30 hosts at once (2026-10-14: sia-s3 got exactly 8 of 40 hosts, then nothing). 64 matches
    // the guest's own SOCKS front (publicSOCKSSlots). SHIELDED_BRIDGE_MAX_CONNS overrides either.
    let cap: usize = std::env::var("SHIELDED_BRIDGE_MAX_CONNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0 && n <= 1024)
        .unwrap_or(if seconds == 0 { 64 } else { 8 });
    println!("shielded bridge ready vm={} port={} worker=127.0.0.1:{} slots={}{}", a[1], port, worker, cap, if auth.is_some() { " auth=stdin" } else { "" });
    while !stopped.load(Ordering::SeqCst) && (seconds == 0 || Instant::now() < end) {
        let Some((guest, peer)) = listener.accept_timeout(500)? else { continue };
        if hvsock::guid_string(&peer) != hvsock::guid_string(&vm) || active.load(Ordering::SeqCst) >= cap {
            let _ = guest.shutdown(Shutdown::Both);
            continue;
        }
        let active = active.clone();
        let auth = auth.clone();
        active.fetch_add(1, Ordering::SeqCst);
        std::thread::spawn(move || {
            if let Err(e) = relay(guest, worker, seconds == 0, auth.as_deref().map(|v| v.as_slice())) { eprintln!("shielded bridge connection ended: {e}"); }
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
    // This executable is supervised per partition; process exit also closes
    // active sockets. Nothing persists beyond the explicit lifetime.
    Ok(())
}

fn relay(mut guest: TcpStream, port: u16, persistent: bool, auth: Option<&[u8]>) -> io::Result<()> {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut worker = TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;
    worker.set_nodelay(true)?;
    // the worker admits this connection only on the credential, which therefore precedes every guest byte
    if let Some(line) = auth {
        use std::io::Write;
        worker.write_all(line)?;
    }
    // A supervised (persistent) bridge carries an app's long-lived streams: a guest that stops reading for a while (a
    // single-threaded app hashing what it already received) must not have its stream cut under it. A write timeout here
    // ended each 4 MiB download after ~2.9 MB with EOF (s3-ipfs-adapter, 2026-10-13); the stream ends when either side
    // closes, or when the supervisor stops the bridge. Timed (non-persistent) bridges keep both limits.
    for socket in [&guest, &worker] {
        socket.set_read_timeout(if persistent { None } else { Some(Duration::from_secs(60)) })?;
        socket.set_write_timeout(if persistent { None } else { Some(Duration::from_secs(60)) })?;
    }
    let mut gr = guest.try_clone()?;
    let mut ww = worker.try_clone()?;
    // Each direction ends with a HALF-close of the other side's write, never a shutdown(Both) or a close: the worker
    // (shield-egress) receives a whole 4 MiB reply from the internet in a second or two and closes, while the guest is
    // still reading it slowly (wasm TLS, hashing). Shutting the hv_sock down at that moment discarded everything it
    // still held for the guest - each 4 MiB GET of s3-ipfs-adapter ended after ~2.8 MB, the same count every time
    // (2026-10-13, after the write timeout above was already gone). A half-close delivers the queued bytes, then EOF.
    let (finished, upstream_done) = std::sync::mpsc::channel::<()>();
    // Once the guest has closed its side, a peer that never closes (a Sia host keeps an idle mux connection open
    // indefinitely) would hold this stream, and one of the bridge's slots, for good: persistent streams have no read
    // timeout. So after the guest's half-close, a stream that carries nothing toward the guest for HALF_CLOSED_IDLE is
    // shut. Bytes still flowing (a slow download the guest already asked for) keep resetting the clock.
    const HALF_CLOSED_IDLE: Duration = Duration::from_secs(120);
    let started = Instant::now();
    let last_down = Arc::new(std::sync::atomic::AtomicU64::new(0)); // ms since `started` of the last byte to the guest
    let down_done = Arc::new(AtomicBool::new(false));
    let (last_down_w, down_done_w) = (last_down.clone(), down_done.clone());
    let upstream = std::thread::spawn(move || {
        let result = io::copy(&mut gr, &mut ww);
        let _ = ww.shutdown(Shutdown::Write);
        let _ = finished.send(());
        if persistent {
            loop {
                std::thread::sleep(Duration::from_secs(5));
                if down_done_w.load(Ordering::SeqCst) {
                    break;
                }
                let idle = started.elapsed().saturating_sub(Duration::from_millis(last_down_w.load(Ordering::SeqCst)));
                if idle >= HALF_CLOSED_IDLE {
                    // unblocks the read below; the guest side was already finished writing
                    let _ = ww.shutdown(Shutdown::Both);
                    break;
                }
            }
        }
        result
    });
    let result = (|| -> io::Result<u64> {
        use std::io::{Read, Write};
        let mut buf = vec![0u8; 64 << 10];
        let mut total = 0u64;
        loop {
            let n = match worker.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            last_down.store(started.elapsed().as_millis() as u64, Ordering::SeqCst);
            guest.write_all(&buf[..n])?;
            total += n as u64;
        }
        Ok(total)
    })();
    down_done.store(true, Ordering::SeqCst);
    let _ = guest.shutdown(Shutdown::Write);
    // The guest closes once it has read the rest (the upstream copy then ends); one that never does is cut after a
    // bounded wait (a read timeout set now would not reach the read already blocked), so it cannot hold one of the
    // bridge's 8 connection slots for good.
    let _ = upstream_done.recv_timeout(Duration::from_secs(120));
    let _ = guest.shutdown(Shutdown::Both);
    let up = upstream.join().unwrap_or_else(|_| Err(io::Error::other("relay thread panicked")));
    let _ = worker.shutdown(Shutdown::Both);
    // A big stream says how much it carried even when it ended cleanly (2026-10-13: a 4 MiB reply cut at ~3 MB left no
    // error anywhere on the host): what was written into the guest's hv_sock, against what shield-egress logs it got.
    if persistent {
        if let (Ok(g2w), Ok(w2g)) = (&up, &result) {
            if *w2g >= 1 << 20 { eprintln!("shielded bridge stream ended: guest->worker {g2w} B, worker->guest {w2g} B"); }
        }
    }
    // A stream that ended in an error says which way and how (the manager logs it): a cut download was invisible.
    if up.is_err() || result.is_err() {
        let said = |r: &io::Result<u64>| match r {
            Ok(n) => format!("ended after {n} B"),
            Err(e) => format!("{e} ({:?})", e.kind()),
        };
        return Err(io::Error::other(format!("guest->worker {}; worker->guest {}", said(&up), said(&result))));
    }
    Ok(())
}
