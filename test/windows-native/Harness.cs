// test/windows-native/Harness.cs -- the C# half of the native harness (test/windows-native/run.ps1 builds and runs it).
//
// run.ps1 copies EnclaveSetup.cs's ReleaseChannel class, unchanged, in place of the marker line below and compiles the
// result with Windows' own .NET Framework 4 csc (C# 5). Nothing is installed, elevated or written outside the work folder
// run.ps1 gives it.
//   Harness.exe verdicts <fixtures.json>          one line per case: "verdict<TAB>index<TAB>accept|refuse<TAB>detail"
//   Harness.exe transport <fixtures.json> <dir>   bounded transfer tests of ReleaseChannel.Fetch / Download / Resolve against
//                                                 an in-process loopback mirror that misbehaves: "PASS|FAIL<TAB>name<TAB>detail"
//   Harness.exe serve <fixtures.json> <portfile>  the same loopback mirror for cli/host.ps1's tests, until <portfile>.stop exists
// The mirror's scenarios (the first path segment): ok (the fixture's live envelope and setup), announce (Content-Length
// 50 GiB, one byte, then silence), flood (no length, 64 KiB chunks without end), trickle* (a length, then one byte every
// 200 ms), short (half the setup, then close), corrupt (the setup with one byte changed), nothing (404).
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

namespace Enclave.Native
{
// @@RELEASE_CHANNEL@@

    static class Harness
    {
        static int failed;
        static Dictionary<string, object> fx;
        static byte[] liveEnvelope, liveSetup;
        static long floodSent;

        static void Check(string name, bool ok, string detail)
        {
            Console.WriteLine((ok ? "PASS" : "FAIL") + "\t" + name + "\t" + (detail ?? "").Replace("\r", " ").Replace("\n", " "));
            if (!ok) failed++;
        }
        static string Hex(byte[] b) { return BitConverter.ToString(b).Replace("-", "").ToLowerInvariant(); }
        static DateTime Utc(string s) { return DateTime.Parse(s, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal); }

        static int Main(string[] args)
        {
            var js = new JavaScriptSerializer { MaxJsonLength = 64 * 1024 * 1024 };
            fx = (Dictionary<string, object>)js.DeserializeObject(File.ReadAllText(args[1]));
            var live = (Dictionary<string, object>)fx["live"];
            liveEnvelope = Convert.FromBase64String((string)live["envelope"]);
            liveSetup = new byte[(int)live["setupBytes"]];
            for (int i = 0; i < liveSetup.Length; i++) liveSetup[i] = (byte)((i * 31 + 7) & 0xff);
            if (args[0] == "verdicts") return Verdicts();
            if (args[0] == "serve")
            {
                int port = StartMirror();
                File.WriteAllText(args[2], port.ToString(CultureInfo.InvariantCulture));
                // until run.ps1 writes <portfile>.stop (or kills it), and never more than ten minutes
                var up = Stopwatch.StartNew();
                while (!File.Exists(args[2] + ".stop") && up.ElapsedMilliseconds < 600000) Thread.Sleep(200);
                return 0;
            }
            if (args[0] == "transport") return Transport(args[2]);
            Console.Error.WriteLine("verdicts | transport | serve");
            return 2;
        }

        // ---- verdicts: every fixture through ParsePolicy and Verify, as setup runs them ----
        static int Verdicts()
        {
            var cases = (IList)fx["cases"];   // JavaScriptSerializer may give object[] or ArrayList
            for (int i = 0; i < cases.Count; i++)
            {
                var c = (Dictionary<string, object>)cases[i];
                string verdict, detail;
                try
                {
                    var p = ReleaseChannel.ParsePolicy((string)c["policyJson"]);
                    if (!c.ContainsKey("envelope")) { verdict = "accept"; detail = string.Join(" ", p.Mirrors.ToArray()); }
                    else
                    {
                        var r = ReleaseChannel.Verify(Convert.FromBase64String((string)c["envelope"]), p, Utc((string)c["now"]));
                        verdict = "accept"; detail = r.Version + " " + r.Signers + " " + r.StatementSha256;
                    }
                }
                catch (Exception e) { verdict = "refuse"; detail = e.GetType().Name + ": " + e.Message; }
                Console.WriteLine("verdict\t" + i + "\t" + verdict + "\t" + detail.Replace("\t", " ").Replace("\r", " ").Replace("\n", " "));
            }
            return 0;
        }

        // ---- the misbehaving loopback mirror ----
        static int StartMirror()
        {
            var l = new TcpListener(IPAddress.Loopback, 0);
            l.Start();
            var t = new Thread(delegate ()
            {
                for (;;)
                {
                    TcpClient cl;
                    try { cl = l.AcceptTcpClient(); } catch { return; }
                    ThreadPool.QueueUserWorkItem(delegate { Serve(cl); });
                }
            }) { IsBackground = true };
            t.Start();
            return ((IPEndPoint)l.LocalEndpoint).Port;
        }
        static void Serve(TcpClient cl)
        {
            try
            {
                using (cl)
                using (var s = cl.GetStream())
                {
                    var head = new StringBuilder(); int b;
                    while (!head.ToString().EndsWith("\r\n\r\n") && head.Length < 8192 && (b = s.ReadByte()) >= 0) head.Append((char)b);
                    string path = head.ToString().Split(' ')[1];
                    string[] seg = path.Trim('/').Split('/');
                    string scenario = Regex.Replace(seg[0], "[0-9]+$", ""), file = seg[seg.Length - 1];
                    byte[] body = file == "latest.signed.json" ? liveEnvelope : liveSetup;
                    Action<string> send = delegate (string h) { var x = Encoding.ASCII.GetBytes(h); s.Write(x, 0, x.Length); };
                    var deadline = Stopwatch.StartNew();
                    if (scenario == "ok") { send("HTTP/1.1 200 OK\r\nContent-Length: " + body.Length + "\r\nConnection: close\r\n\r\n"); s.Write(body, 0, body.Length); }
                    else if (scenario == "corrupt") { var x = (byte[])body.Clone(); x[x.Length / 2] ^= 1; send("HTTP/1.1 200 OK\r\nContent-Length: " + x.Length + "\r\nConnection: close\r\n\r\n"); s.Write(x, 0, x.Length); }
                    else if (scenario == "short") { send("HTTP/1.1 200 OK\r\nContent-Length: " + body.Length + "\r\nConnection: close\r\n\r\n"); s.Write(body, 0, body.Length / 2); }
                    else if (scenario == "announce") { send("HTTP/1.1 200 OK\r\nContent-Length: 53687091200\r\nConnection: close\r\n\r\nx"); while (deadline.ElapsedMilliseconds < 30000 && cl.Connected) Thread.Sleep(200); }
                    else if (scenario == "flood")
                    {
                        send("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
                        var chunk = new byte[65536];
                        while (deadline.ElapsedMilliseconds < 30000) { s.Write(chunk, 0, chunk.Length); Interlocked.Add(ref floodSent, chunk.Length); }
                    }
                    else if (scenario == "trickle")
                    {
                        send("HTTP/1.1 200 OK\r\nContent-Length: " + body.Length + "\r\nConnection: close\r\n\r\n");
                        while (deadline.ElapsedMilliseconds < 30000) { s.WriteByte(body[0]); s.Flush(); Thread.Sleep(200); }
                    }
                    else send("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                }
            }
            catch { }   // the client hung up: that is what most scenarios are for
        }

        // ---- transport: ReleaseChannel.Fetch, Download and Resolve against the mirror ----
        static ReleaseChannel.Policy PolicyFor(string baseUrl, params string[] scenarios)
        {
            var live = (Dictionary<string, object>)fx["live"];
            var d = (Dictionary<string, object>)new JavaScriptSerializer().DeserializeObject((string)live["policyJson"]);
            var mirrors = new List<string>(); foreach (var s in scenarios) mirrors.Add(baseUrl + s + "/");
            d["mirrors"] = mirrors;
            return ReleaseChannel.ParsePolicy(new JavaScriptSerializer().Serialize(d));
        }
        static string Fails(Action a) { try { a(); return null; } catch (Exception e) { return e.Message + (e.InnerException != null ? " / " + e.InnerException.Message : ""); } }

        static int Transport(string dir)
        {
            int port = StartMirror();
            string b = "http://127.0.0.1:" + port + "/";
            var live = (Dictionary<string, object>)fx["live"];
            string setupName = (string)live["setupName"], setupSha = (string)live["setupSha256"]; long setupBytes = liveSetup.Length;
            Directory.CreateDirectory(dir);

            // Fetch: the bounds hold during the transfer
            var sw = Stopwatch.StartNew(); var got = new MemoryStream();
            long n = ReleaseChannel.Fetch(b + "ok/" + setupName, setupBytes, setupBytes, 10000, delegate (byte[] x, int k) { got.Write(x, 0, k); });
            Check("Fetch: the signed bytes from a good mirror", n == setupBytes && Hex(SHA256.Create().ComputeHash(got.ToArray())) == setupSha, n + " bytes");
            sw.Restart(); string why = Fails(delegate { ReleaseChannel.Fetch(b + "announce/" + setupName, setupBytes, setupBytes, 10000, delegate { }); });
            Check("Fetch: an announced 50 GiB refused before the body", why != null && why.Contains("announces") && sw.ElapsedMilliseconds < 3000, sw.ElapsedMilliseconds + " ms: " + why);
            long memBefore = GC.GetTotalMemory(true); long floodBefore = Interlocked.Read(ref floodSent);
            sw.Restart(); why = Fails(delegate { ReleaseChannel.Fetch(b + "flood/latest.signed.json", 65536, -1, 10000, delegate { }); });
            Check("Fetch: an endless body refused at the first byte over 64 KiB", why != null && why.Contains("more than") && sw.ElapsedMilliseconds < 5000, sw.ElapsedMilliseconds + " ms: " + why);
            Thread.Sleep(500);
            Check("Fetch: the endless mirror was cut off (not drained) and nothing was buffered",
                  Interlocked.Read(ref floodSent) - floodBefore < 64L * 1024 * 1024 && GC.GetTotalMemory(true) - memBefore < 32L * 1024 * 1024,
                  (Interlocked.Read(ref floodSent) - floodBefore) + " bytes sent by the mirror");
            sw.Restart(); why = Fails(delegate { ReleaseChannel.Fetch(b + "trickle/" + setupName, setupBytes, setupBytes, 1500, delegate { }); });
            Check("Fetch: a trickle is cut off at the hard deadline", why != null && sw.ElapsedMilliseconds >= 1400 && sw.ElapsedMilliseconds < 4000, sw.ElapsedMilliseconds + " ms: " + why);
            why = Fails(delegate { ReleaseChannel.Fetch(b + "short/" + setupName, setupBytes, setupBytes, 10000, delegate { }); });
            Check("Fetch: a short body is refused", why != null, why);

            // Download: failover past every kind of bad mirror; no part files; the deadline over all mirrors
            ReleaseChannel.AttemptCapMs = 1500;
            string outPath = Path.Combine(dir, setupName);
            var notes = new List<string>();
            sw.Restart();
            why = Fails(delegate { ReleaseChannel.Download(PolicyFor(b, "trickle", "corrupt", "short", "announce", "flood", "nothing", "ok"), setupName, setupSha, setupBytes, outPath, null, delegate (string m) { notes.Add(m); }); });
            Check("Download: past trickle, corrupt, short, announce, flood and 404 to the good mirror",
                  why == null && File.Exists(outPath) && Hex(SHA256.Create().ComputeHash(File.ReadAllBytes(outPath))) == setupSha && notes.Count == 6 && sw.ElapsedMilliseconds < 15000,
                  sw.ElapsedMilliseconds + " ms, " + notes.Count + " refused" + (why != null ? ": " + why : ""));
            Check("Download: no part file left behind", Directory.GetFiles(dir).Length == 1, string.Join(", ", Directory.GetFiles(dir)));
            why = Fails(delegate { ReleaseChannel.Download(PolicyFor(b, "nothing"), setupName, setupSha, setupBytes, outPath, null, delegate { }); });
            Check("Download: a file already there with the signed bytes is kept", why == null, why);
            File.WriteAllBytes(outPath, new byte[setupBytes]);
            why = Fails(delegate { ReleaseChannel.Download(PolicyFor(b, "corrupt", "short"), setupName, setupSha, setupBytes, outPath, null, delegate { }); });
            Check("Download: with no good mirror, a wrong file already there is left as it was (never replaced by unverified bytes)",
                  why != null && new FileInfo(outPath).Length == setupBytes && File.ReadAllBytes(outPath)[1] == 0 && Directory.GetFiles(dir).Length == 1, why);
            ReleaseChannel.AttemptCapMs = 1000; ReleaseChannel.DownloadDeadlineMs = 2500;
            sw.Restart();
            why = Fails(delegate { ReleaseChannel.Download(PolicyFor(b, "trickle1", "trickle2", "trickle3", "trickle4", "ok"), setupName, setupSha, setupBytes, Path.Combine(dir, "x.exe"), null, delegate { }); });
            Check("Download: one deadline over all mirrors (four trickling mirrors cannot take a second each and then some)",
                  why != null && why.Contains("deadline") && sw.ElapsedMilliseconds < 5000 && !File.Exists(Path.Combine(dir, "x.exe")), sw.ElapsedMilliseconds + " ms: " + why);
            ReleaseChannel.AttemptCapMs = 3600000; ReleaseChannel.DownloadDeadlineMs = 2 * 3600000;

            // Resolve: a trickling or flooding pointer does not stop the good one
            ReleaseChannel.EnvelopeDeadlineMs = 1500;
            ReleaseChannel.Release rel = null; var rnotes = new List<string>(); sw.Restart();
            why = Fails(delegate { rel = ReleaseChannel.Resolve(PolicyFor(b, "trickle", "flood", "announce", "ok"), delegate (string m) { rnotes.Add(m); }); });
            Check("Resolve: the good mirror's signed release, past trickle, flood and announce",
                  why == null && rel.Version == (string)live["version"] && rnotes.Count == 3 && rel.ServedBy.Count == 1 && rel.ServedBy[0].Contains("/ok/") && sw.ElapsedMilliseconds < 6000,
                  sw.ElapsedMilliseconds + " ms" + (why != null ? ": " + why : ""));
            Console.WriteLine("transport: " + failed + " failure(s)");
            return failed == 0 ? 0 : 1;
        }
    }
}
