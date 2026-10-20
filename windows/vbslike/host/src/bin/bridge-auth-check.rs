//! A box-run check of shielded-bridge's WORKER CREDENTIAL (--worker-auth-stdin; windows/vbslike/manager/bridge-auth.mjs)
//! over Hyper-V socket LOOPBACK (no partition needed, as bridge-drain-check):
//!   bridge-auth-check <shielded-bridge.exe> [vsock port]
//! 1. with the flag and a credential on stdin: a local "worker" must receive EXACTLY the credential line, then the
//!    client's bytes, on the connection the bridge opens for a hv_sock client;
//! 2. without the flag (egress / GPU invocation): the worker receives only the client's bytes, as before;
//! 3. a malformed first stdin line, EOF before it, and the flag with a nonzero lifetime: the bridge exits nonzero
//!    BEFORE binding, and its output never contains what it was given.
//! The credential here is a random test value, never a deployed one. Prints PASS/FAIL per case; exit 0 only if all pass.
//!   bridge-auth-check --dial <vsock port> [hex bytes to send]
//! acts as a GUEST over loopback instead: dials the port, sends the bytes, prints what it reads until EOF (for driving the
//! manager's real package/custody servers behind a real bridge from a test script).
#[path = "../hvsock.rs"]
#[allow(dead_code)]
mod hvsock;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::Duration;

const LOOPBACK: &str = "e0e16197-dd56-4a10-9195-5ee7a155a838";
const HELLO: &[u8] = b"guest bytes after the credential\n";

fn test_credential() -> String {
    // 32 bytes from the OS (std's hasher keys are random per process): enough for a throwaway test value
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    (0..4).map(|i| { let mut h = RandomState::new().build_hasher(); h.write_u64(i); format!("{:016x}", h.finish()) }).collect()
}

/// One relayed connection: start the bridge, dial it over loopback, return what the worker received.
fn relayed(exe: &str, port: u32, stdin_line: Option<&str>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let worker = TcpListener::bind("127.0.0.1:0")?;
    let wport = worker.local_addr()?.port();
    let got = std::thread::spawn(move || -> Vec<u8> {
        let mut out = Vec::new();
        if let Ok((mut c, _)) = worker.accept() {
            let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
            let mut buf = [0u8; 512];
            while out.len() < 88 + HELLO.len() {
                match c.read(&mut buf) { Ok(0) | Err(_) => break, Ok(n) => out.extend_from_slice(&buf[..n]) }
            }
        }
        out
    });
    let mut args = vec![LOOPBACK.to_string(), port.to_string(), wport.to_string(), "0".to_string()];
    if stdin_line.is_some() { args.push("--worker-auth-stdin".into()); }
    let mut bridge = Command::new(exe).args(&args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    if let Some(l) = stdin_line { bridge.stdin.as_mut().ok_or("no stdin")?.write_all(l.as_bytes())?; }
    let mut ready = String::new();
    BufReader::new(bridge.stdout.take().ok_or("no stdout")?).read_line(&mut ready)?;
    print!("  bridge: {ready}");
    let vm = hvsock::parse_guid(LOOPBACK).ok_or("guid")?;
    let mut s = hvsock::dial(&vm, port, Duration::from_secs(5))?;
    s.write_all(HELLO)?;
    let out = got.join().map_err(|_| "worker thread panicked")?;
    drop(s);
    drop(bridge.stdin.take());                                   // stdin EOF: the supervised stop
    let _ = bridge.wait();
    if let Some(l) = stdin_line { if ready.contains(l.trim()) { return Err("the ready line contains the credential".into()); } }
    Ok(out)
}

/// A refused start: exit status nonzero, and nothing of `secret` in its output.
fn refused(exe: &str, port: u32, args_tail: &[&str], stdin: &[u8], secret: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut args = vec![LOOPBACK.to_string(), port.to_string(), "1".to_string()];
    args.extend(args_tail.iter().map(|s| s.to_string()));
    let mut c = Command::new(exe).args(&args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    { let mut i = c.stdin.take().ok_or("no stdin")?; i.write_all(stdin)?; }
    let o = c.wait_with_output()?;
    let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    if o.status.success() { return Err(format!("it started: {text}").into()); }
    if !secret.is_empty() && text.contains(secret) { return Err("its output contains what it was given".into()); }
    Ok(text.trim().to_string())
}

fn dial(port: u32, send: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let vm = hvsock::parse_guid(LOOPBACK).ok_or("guid")?;
    let mut s = hvsock::dial(&vm, port, Duration::from_secs(5))?;
    s.set_read_timeout(Some(Duration::from_secs(15)))?;
    if !send.is_empty() { s.write_all(send)?; }
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    println!("read {} hex {}", out.len(), out.iter().map(|b| format!("{b:02x}")).collect::<String>());
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<String> = std::env::args().collect();
    if a.get(1).map(|s| s.as_str()) == Some("--dial") {
        let port: u32 = a.get(2).ok_or("--dial <port> [hex]")?.parse()?;
        let hex = a.get(3).cloned().unwrap_or_default();
        let send: Vec<u8> = (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)).collect::<Result<_, _>>()?;
        return dial(port, &send);
    }
    let exe = a.get(1).ok_or("usage: bridge-auth-check <shielded-bridge.exe> [vsock port]")?.clone();
    let port: u32 = a.get(2).map(|p| p.parse()).transpose()?.unwrap_or(9978);
    let mut ok = true;
    let mut case = |name: &str, r: Result<String, Box<dyn std::error::Error>>| {
        match r { Ok(d) => println!("PASS {name}: {d}"), Err(e) => { ok = false; println!("FAIL {name}: {e}") } }
    };
    let cred = test_credential();
    let line = format!("enclave-bridge-auth-v1 {cred}\n");
    case("credential first, then the guest's bytes", relayed(&exe, port, Some(&line)).and_then(|got| {
        let want = [line.as_bytes(), HELLO].concat();
        if got == want { Ok(format!("worker received {} bytes: the 88-byte line, then the guest's", got.len())) }
        else { Err(format!("worker received {:?}", String::from_utf8_lossy(&got)).into()) }
    }));
    case("no flag: unchanged (egress / GPU)", relayed(&exe, port + 1, None).and_then(|got| {
        if got == HELLO { Ok("worker received only the guest's bytes".into()) } else { Err(format!("worker received {:?}", String::from_utf8_lossy(&got)).into()) }
    }));
    let junk = "enclave-bridge-auth-v1 THIS-IS-NOT-A-CREDENTIAL-0123456789abcdef";
    case("malformed first line", refused(&exe, port + 2, &["0", "--worker-auth-stdin"], format!("{junk}\n").as_bytes(), "THIS-IS-NOT"));
    case("EOF before the line", refused(&exe, port + 3, &["0", "--worker-auth-stdin"], b"", ""));
    case("flag with a nonzero lifetime", refused(&exe, port + 4, &["30", "--worker-auth-stdin"], line.as_bytes(), &cred));
    println!("{}", if ok { "ALL PASS" } else { "SOME FAILED" });
    std::process::exit(if ok { 0 } else { 1 });
}
