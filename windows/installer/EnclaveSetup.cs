// EnclaveSetup.cs -- set this PC up as an Enclave host (docs/design/windows-host-installer.md).
//
// Compiled TOGETHER with windows/tray/EnclaveTray.cs (build-setup.cmd, /main:Enclave.Setup.SetupProgram), so it is the
// tray's own theme, buttons, masthead and dialogs. C# 5, the in-box compiler, ASCII source, like the tray.
//
//   1. welcome
//   2. download the host bundle from get.enclave.host (latest.json names it and its sha256), check it, expand it
//   3. check this PC (install-host.ps1 -CheckOnly); if Hyper-V must be turned on, it is, and setup resumes after the
//      restart by itself (HKLM RunOnce)
//   4. the owner picks the host's NAME, checked live against the relay (GET /v1/hosts/name/<name>)
//   5. install (install-host.ps1 -Name, its JSON lines shown step by step)
//   6. done: open Enclave Hosting (the tray) to set the payout wallet
//
// AN INDEPENDENT INSTALL (docs/network/independent-windows.md) is the same flow with the operator's own authorities:
//   EnclaveSetup.exe --release-policy <release-policy.json> --no-relay --public-url https://box.example.org
//                    --gateways https://gw1,https://gw2 --contract-pins <contract-pins.json> [--rpcs a,b] [--directories a,b]
//                    [--network-checkers 0x..,0x..] [--name-check chain|offline]
// With --release-policy the bundle is the highest version a statement signed by the policy's pinned key(s) names, from
// the policy's mirrors, checked here with Windows' own ECDSA (ReleaseChannel below); get.enclave.host's unsigned
// latest.json is not read. With --no-relay no relay is asked about the name: install-host.ps1 checks the endpoint on the
// pinned registry instead (or not at all, with --name-check offline, which it says). Without these arguments setup does
// exactly what it always did, and says that the download it checks is named by an UNSIGNED latest.json.
// It runs as administrator (requireAdministrator in its manifest): it turns on Hyper-V, installs services and writes to
// Program Files.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Collections;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;
using Enclave.Tray;

namespace Enclave.Setup
{
    static class SetupProgram
    {
        [System.Runtime.InteropServices.DllImport("user32.dll")] static extern bool SetProcessDPIAware();

        [STAThread]
        static int Main(string[] args)
        {
            try { SetProcessDPIAware(); } catch { }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            string resumeName = null, referral = null; bool uninstall = false, enclaveDns = true;
            var opt = new SetupOptions();
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--resume" && i + 1 < args.Length) resumeName = args[i + 1];
                if (args[i] == "--referral" && i + 1 < args.Length) referral = args[i + 1].Trim();
                if (args[i] == "--uninstall") uninstall = true;
                if (args[i] == "--no-enclavedns") enclaveDns = false;   // the owner unticked it before a restart
                // an independent install's options, given here or (after a restart) from the file setup saved them to
                if (args[i] == "--options" && i + 1 < args.Length) { try { opt = SetupOptions.Load(args[i + 1]); } catch (Exception e) { opt.Error = "the saved setup options could not be read: " + e.Message; } }
                if (i + 1 < args.Length) try { opt.Take(args[i], args[i + 1]); } catch (Exception e) { opt.Error = args[i] + ": " + e.Message; }
                if (args[i] == "--no-relay") opt.NoRelay = true;
            }
            if (opt.Error == null) opt.Error = opt.Check();
            if (opt.NoRelay && Array.IndexOf(args, "--enclavedns") < 0) enclaveDns = false;   // an Enclave service: off by default when independent
            if (referral != null && !SetupForm.ReferralOk(referral)) referral = null;   // never passed on unchecked
            // Never run from inside Program Files\Enclave: the uninstall deletes that folder, and an install replaces it (and
            // stops every process running from it). Windows' Installed apps starts the copy kept there, so it relaunches
            // itself from a temporary copy - with uninstall-host.ps1 beside it - and that copy does the work.
            string here = Path.GetDirectoryName(Application.ExecutablePath);
            string pf = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Enclave");
            if (string.Equals(here.TrimEnd('\\'), pf, StringComparison.OrdinalIgnoreCase))
            {
                string tmp = Path.Combine(Path.GetTempPath(), "Enclave-setup-" + Guid.NewGuid().ToString("N").Substring(0, 8));
                Directory.CreateDirectory(tmp);
                string copy = Path.Combine(tmp, "EnclaveSetup.exe");
                File.Copy(Application.ExecutablePath, copy, true);
                string script = Path.Combine(pf, "uninstall-host.ps1");
                if (File.Exists(script)) File.Copy(script, Path.Combine(tmp, "uninstall-host.ps1"), true);
                Process.Start(new ProcessStartInfo(copy, string.Join(" ", args)) { UseShellExecute = true, WorkingDirectory = tmp });
                return 0;
            }
            Application.Run(new SetupForm(resumeName, uninstall, referral, enclaveDns, opt));
            return 0;
        }
    }

    sealed class SetupForm : Form
    {
        // the LEGACY channel and relay: used only when no release policy / --no-relay was given
        const string Downloads = "https://get.enclave.host/windows/";
        const string Relay = "https://api.enclave.host";
        readonly SetupOptions opt;
        static readonly string WorkDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Enclave-setup");
        static readonly int Wide = Theme.Px(460);

        // .NET Framework's default may still be TLS 1.0; get.enclave.host and the relay need 1.2. 1.3 only where this
        // framework knows it (setting an unknown protocol throws). Static: however the window is made, HTTPS works.
        static SetupForm()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            try { ServicePointManager.SecurityProtocol |= (SecurityProtocolType)12288; } catch (NotSupportedException) { }
        }

        readonly Label heading = new Label(), body = new Label(), status = new Label(), nameNote = new Label(), caption = new Label();
        // progress: the rail (the whole setup, 0..1), its caption (percent and time so far), and the running step's spinner
        readonly ProgressRail rail = new ProgressRail();
        readonly System.Windows.Forms.Timer tick = new System.Windows.Forms.Timer { Interval = 100 };
        static readonly string[] Spinner = { "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏" };
        // the install script's steps, in order, each weighted by roughly how long it takes (the join waits on the network)
        static readonly string[] InstallSteps = { "checks", "hyperv", "identity", "name", "prereq", "files", "release", "shield", "keys", "config", "services", "join", "tray", "enclavedns", "done" };
        static readonly int[] InstallWeights = { 1, 1, 1, 1, 1, 1, 4, 2, 1, 1, 3, 5, 1, 2, 1 };
        static readonly string[] UninstallSteps = { "services", "shield", "tray", "files", "data", "done" };
        static readonly int[] UninstallWeights = { 2, 2, 1, 2, 1, 1 };
        readonly CheckBox removeData = new CheckBox();
        // the install's one extra: EnclaveDNS, ticked by default
        readonly CheckBox enclaveDns = new CheckBox();
        readonly Label enclaveDnsNote = new Label();
        string phase = "", runningKey, runningMsg;
        DateTime runningSince, startedAt;
        int frame;
        readonly TextBox nameBox = new TextBox(), refBox = new TextBox();
        readonly Label refLabel = new Label(), refNote = new Label();
        // The referral code this machine is installed with: attribution only (relay/referrals.mjs), optional, kept by the
        // install-host.ps1 -Referral of every later re-run and update.
        public static bool ReferralOk(string s) { return System.Text.RegularExpressions.Regex.IsMatch(s ?? "", @"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"); }
        string Referral { get { var r = refBox.Text.Trim(); return ReferralOk(r) ? r : ""; } }
        bool RefValid { get { var r = refBox.Text.Trim(); return r.Length == 0 || ReferralOk(r); } }
        readonly FlowLayoutPanel steps = new FlowLayoutPanel(), nameRow = new FlowLayoutPanel();
        readonly ThemeButton primary = new ThemeButton("Start", true), secondary = new ThemeButton("Cancel", false);
        readonly System.Windows.Forms.Timer nameTimer = new System.Windows.Forms.Timer { Interval = 450 };
        readonly SynchronizationContext ui;
        readonly Dictionary<string, Label> stepRows = new Dictionary<string, Label>();
        string bundleDir, version, name, resumeName;
        bool nameOk, busy;
        Action onPrimary;

        public SetupForm(string resumeName, bool uninstall, string referral, bool withEnclaveDns, SetupOptions options)
        {
            this.resumeName = resumeName;
            opt = options ?? new SetupOptions();
            enclaveDns.Checked = withEnclaveDns;
            refBox.Text = referral ?? "";
            Text = uninstall ? "Remove Enclave" : "Enclave setup";
            FormBorderStyle = FormBorderStyle.FixedSingle; MaximizeBox = false; StartPosition = FormStartPosition.CenterScreen;
            AutoScaleMode = AutoScaleMode.None; AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink;
            BackColor = Theme.Bg; ForeColor = Theme.Text; Font = Theme.Body;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
            var flow = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true,
                                             AutoSizeMode = AutoSizeMode.GrowAndShrink, Padding = new Padding(Theme.Px(20)), BackColor = Theme.Bg };
            // no in-window masthead: the title bar already says Enclave, with its mark
            heading.AutoSize = true; heading.MaximumSize = new Size(Wide, 0); heading.Font = Theme.Mono(13f, FontStyle.Bold); heading.ForeColor = Theme.Text;
            body.AutoSize = true; body.MaximumSize = new Size(Wide, 0); body.ForeColor = Theme.Muted; body.Margin = new Padding(3, Theme.Px(8), 3, Theme.Px(6));
            flow.Controls.Add(heading); flow.Controls.Add(body);
            rail.Width = Wide; rail.Margin = new Padding(3, Theme.Px(8), 3, 0); rail.Visible = false; flow.Controls.Add(rail);
            caption.AutoSize = true; caption.Font = Theme.Mono(8.5f, FontStyle.Regular); caption.ForeColor = Theme.Dim;
            caption.Margin = new Padding(3, Theme.Px(4), 3, 0); caption.Visible = false; flow.Controls.Add(caption);
            // the name row
            nameRow.FlowDirection = FlowDirection.TopDown; nameRow.AutoSize = true; nameRow.WrapContents = false; nameRow.BackColor = Theme.Bg;
            nameBox.Width = Theme.Px(300); nameBox.Font = Theme.Mono(11f, FontStyle.Regular); nameBox.BackColor = Theme.Surface2;
            nameBox.ForeColor = Theme.Text; nameBox.BorderStyle = BorderStyle.FixedSingle; nameBox.MaxLength = 32;
            nameBox.CharacterCasing = CharacterCasing.Lower; nameBox.Margin = new Padding(3, Theme.Px(6), 3, 0);
            nameNote.AutoSize = true; nameNote.MaximumSize = new Size(Wide, 0); nameNote.Font = Theme.Mono(8.5f, FontStyle.Regular);
            nameNote.Margin = new Padding(3, Theme.Px(6), 3, 0);
            refLabel.AutoSize = true; refLabel.Text = "Referral code (optional)"; refLabel.ForeColor = Theme.Muted;
            refLabel.Margin = new Padding(3, Theme.Px(14), 3, 0);
            refBox.Width = Theme.Px(300); refBox.Font = Theme.Mono(11f, FontStyle.Regular); refBox.BackColor = Theme.Surface2;
            refBox.ForeColor = Theme.Text; refBox.BorderStyle = BorderStyle.FixedSingle; refBox.MaxLength = 64;
            refBox.Margin = new Padding(3, Theme.Px(6), 3, 0); refBox.AccessibleName = "Referral code (optional)";
            refNote.AutoSize = true; refNote.MaximumSize = new Size(Wide, 0); refNote.Font = Theme.Mono(8.5f, FontStyle.Regular);
            refNote.Margin = new Padding(3, Theme.Px(6), 3, 0); refNote.ForeColor = Theme.Dim;
            refNote.Text = "If someone sent you here, their code. Letters, digits, '.', '_' or '-'.";
            nameRow.Controls.Add(nameBox); nameRow.Controls.Add(nameNote);
            nameRow.Controls.Add(refLabel); nameRow.Controls.Add(refBox); nameRow.Controls.Add(refNote);
            enclaveDns.AutoSize = true; enclaveDns.MaximumSize = new Size(Wide, 0); enclaveDns.ForeColor = Theme.Text; enclaveDns.BackColor = Theme.Bg;
            enclaveDns.FlatStyle = FlatStyle.Flat; enclaveDns.Margin = new Padding(3, Theme.Px(16), 3, 0);
            enclaveDns.Text = "Also install EnclaveDNS (recommended)";
            enclaveDns.AccessibleDescription = "EnclaveDNS lets this PC open .eth names, so Enclave stays reachable at EnclaveHost.eth if the enclave.host website ever goes down.";
            enclaveDnsNote.AutoSize = true; enclaveDnsNote.MaximumSize = new Size(Wide - Theme.Px(22), 0); enclaveDnsNote.Font = Theme.Mono(8.5f, FontStyle.Regular);
            enclaveDnsNote.ForeColor = Theme.Dim; enclaveDnsNote.Margin = new Padding(Theme.Px(22), Theme.Px(4), 3, 0);
            enclaveDnsNote.Text = "Enclave's own DNS resolver, running in an attested enclave. With it, this PC opens .eth names in the browser, "
                + "so you can still reach Enclave at EnclaveHost.eth if the enclave.host website ever goes down. It becomes this PC's DNS "
                + "(answers checked with DNSSEC; if it cannot be reached, this PC uses its usual DNS). Remove it any time from Installed apps.";
            nameRow.Controls.Add(enclaveDns); nameRow.Controls.Add(enclaveDnsNote);
            nameRow.Visible = false;
            flow.Controls.Add(nameRow);
            // the uninstall's one choice
            removeData.AutoSize = true; removeData.MaximumSize = new Size(Wide, 0); removeData.ForeColor = Theme.Text; removeData.BackColor = Theme.Bg;
            removeData.FlatStyle = FlatStyle.Flat; removeData.Margin = new Padding(3, Theme.Px(8), 3, 0); removeData.Visible = false;
            removeData.Text = "Also move this host's data aside (keys, records, logs)";
            flow.Controls.Add(removeData);
            // the steps
            steps.FlowDirection = FlowDirection.TopDown; steps.AutoSize = true; steps.WrapContents = false; steps.BackColor = Theme.Bg;
            steps.Margin = new Padding(3, Theme.Px(6), 3, 0); steps.MinimumSize = new Size(Wide, 0);
            flow.Controls.Add(steps);
            status.AutoSize = true; status.MaximumSize = new Size(Wide, 0); status.Font = Theme.Mono(8.5f, FontStyle.Regular);
            status.ForeColor = Theme.Dim; status.Margin = new Padding(3, Theme.Px(10), 3, 0);
            flow.Controls.Add(status);
            var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, WrapContents = false, AutoSize = true, BackColor = Theme.Bg,
                                                MinimumSize = new Size(Wide, 0), Margin = new Padding(3, Theme.Px(18), 3, 0) };
            buttons.Controls.Add(primary); buttons.Controls.Add(secondary);
            flow.Controls.Add(buttons);
            Controls.Add(flow);
            ui = SynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();
            primary.Click += delegate { if (!busy && primary.Enabled && onPrimary != null) onPrimary(); };
            secondary.Click += delegate { if (!busy) Close(); };
            nameBox.TextChanged += delegate { nameOk = false; primary.Enabled = false; nameNote.ForeColor = Theme.Dim; nameNote.Text = "checking…"; nameTimer.Stop(); nameTimer.Start(); };
            nameTimer.Tick += delegate { nameTimer.Stop(); CheckName(nameBox.Text.Trim()); };
            refBox.TextChanged += delegate
            {
                bool ok = RefValid;
                refNote.ForeColor = ok ? Theme.Dim : Theme.Amber;
                refNote.Text = ok ? "If someone sent you here, their code. Letters, digits, '.', '_' or '-'."
                                  : "A referral code is 1 to 64 letters, digits, '.', '_' or '-'.";
                primary.Enabled = nameOk && ok;
            };
            tick.Tick += delegate { Animate(); }; tick.Start();
            if (uninstall) Uninstall(); else if (resumeName != null) { name = resumeName; ResumeAfterRestart(); } else Welcome();
        }
        protected override void OnHandleCreated(EventArgs e) { base.OnHandleCreated(e); Theme.DarkFrame(Handle); }

        void Page(string h, string b, string primaryText, Action next)
        {
            heading.Text = h; body.Text = b; primary.Text = primaryText; primary.FitText(); primary.Enabled = next != null; onPrimary = next;
        }
        void Post(Action a) { ui.Post(delegate { a(); }, null); }
        void Work(Action job) { busy = true; rail.Busy = true; primary.Enabled = false; ThreadPool.QueueUserWorkItem(delegate { job(); }); }
        void Idle() { busy = false; rail.Busy = false; }

        /// <summary>Where the whole setup is, 0..1: the download is the first 30 %, the PC check the next 8 %, the install the
        /// rest by its steps' weights. A step counts once it is done; the rail's moving band shows a long one is working.</summary>
        void Progress(string key, string state, double downloadPct)
        {
            if (startedAt == DateTime.MinValue) startedAt = DateTime.Now;
            rail.Visible = caption.Visible = true;
            double v = rail.Value;
            if (phase == "download") v = .30 * downloadPct;
            else if (phase == "check") { if (state == "ok" && key == "checks") v = Math.Max(v, .34); if (state == "ok" && key == "hyperv") v = Math.Max(v, .38); }
            else if (phase == "install" || phase == "uninstall")
            {
                string[] names = phase == "install" ? InstallSteps : UninstallSteps;
                int[] weights = phase == "install" ? InstallWeights : UninstallWeights;
                double from = phase == "install" ? .38 : 0, span = 1 - from;
                int i = Array.IndexOf(names, key);
                if (i >= 0)
                {
                    int total = 0, upTo = 0;
                    for (int j = 0; j < weights.Length; j++) { total += weights[j]; if (j < i || (j == i && state == "ok")) upTo += weights[j]; }
                    v = Math.Max(v, from + span * upTo / total);
                }
            }
            rail.Value = v;
            Caption();
        }
        void Caption()
        {
            if (!caption.Visible) return;
            var t = DateTime.Now - startedAt;
            caption.Text = (int)Math.Round(rail.Value * 100) + "%  ·  " + (int)t.TotalMinutes + ":" + t.Seconds.ToString("00", CultureInfo.InvariantCulture) + " so far";
        }
        /// <summary>Every 100 ms: the running step's spinner and how long it has been running, and the caption's clock. A step
        /// that waits (the join can take minutes) visibly lives instead of looking frozen.</summary>
        void Animate()
        {
            if (runningKey != null && busy)
            {
                Label l;
                if (stepRows.TryGetValue(runningKey, out l))
                {
                    frame = (frame + 1) % Spinner.Length;
                    int secs = (int)(DateTime.Now - runningSince).TotalSeconds;
                    l.Text = Spinner[frame] + "  " + runningMsg + (secs >= 3 ? "  (" + secs + " s)" : "");
                }
            }
            if (busy) Caption();
        }

        Label Step(string key, string text)
        {
            Label l;
            if (!stepRows.TryGetValue(key, out l))
            {
                l = new Label { AutoSize = true, MaximumSize = new Size(Wide, 0), Font = Theme.Mono(9f, FontStyle.Regular), Margin = new Padding(3, Theme.Px(3), 3, 0) };
                stepRows[key] = l; steps.Controls.Add(l);
            }
            l.Text = text;
            return l;
        }
        void StepState(string key, string state, string message) { StepState(key, state, message, -1); }
        void StepState(string key, string state, string message, double downloadPct)
        {
            string glyph = state == "ok" ? "✓" : state == "fail" ? "✗" : state == "warn" ? "!" : state == "reboot" ? "↻" : Spinner[frame];
            var l = Step(key, glyph + "  " + message);
            l.ForeColor = state == "ok" ? Theme.Jade : state == "fail" ? Theme.Danger : state == "warn" || state == "reboot" ? Theme.Amber : Theme.Text;
            if (state == "run") { if (runningKey != key) runningSince = DateTime.Now; runningKey = key; runningMsg = message; }
            else if (runningKey == key) runningKey = null;
            if (state == "fail") rail.Failed = true;
            Progress(key, state, downloadPct);
        }

        // ---- 1. welcome ---------------------------------------------------------------------------------------------
        void Welcome()
        {
            if (opt.Error != null) { Page("Setup cannot start", opt.Error, "Close", delegate { Close(); }); return; }
            if (opt.NoRelay || opt.ReleasePolicy != null)
            {
                Page("Host apps on this PC, with your own authorities.",
                     (opt.ReleasePolicy != null ? "Setup downloads Enclave only as a release signed by the key(s) pinned in " + Path.GetFileName(opt.ReleasePolicy)
                        + ", from that policy's mirrors, and this PC keeps updating only that way. " : "Setup downloads Enclave from get.enclave.host (UNSIGNED: no release policy was given). ")
                     + (opt.NoRelay ? "This host uses no Enclave relay: it is " + opt.PublicUrl + ", checks its name on the pinned registry, runs its owner's apps (the Shield market "
                        + "needs a relay's attestation verdict), and pays its own registration from its operator key." : ""), "Start", Download);
                return;
            }
            Page("Host apps on this PC, and earn USDC.",
                 "Setup downloads Enclave (about 160 MB), checks that this PC can host (Windows 11 Pro, Secure Boot, an AMD processor's TPM, "
                 + "Hyper-V), and installs it. Apps run each in their own Enclave Shield partition. Joining the network costs you nothing: "
                 + "the first registration is paid for you once this PC proves its hardware.", "Start", Download);
        }

        // ---- 2. download ----------------------------------------------------------------------------------------------
        void Download()
        {
            if (opt.ReleasePolicy != null) { SignedDownload(); return; }
            Page("Downloading Enclave", "", "Next", null);
            phase = "download"; rail.Failed = false;
            StepState("download", "run", "asking get.enclave.host for the latest version (unsigned channel)", 0);
            Work(delegate
            {
                try
                {
                    SecureWorkDir();
                    var latest = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(new WebClient().DownloadString(Downloads + "latest.json"));
                    version = (string)latest["version"];
                    string file = (string)latest["file"], sha = ((string)latest["sha256"]).ToLowerInvariant();
                    string zip = Path.Combine(WorkDir, file);
                    if (!File.Exists(zip) || Sha256(zip) != sha)
                    {
                        var req = (HttpWebRequest)WebRequest.Create(Downloads + file);
                        using (var resp = req.GetResponse())
                        using (var src = resp.GetResponseStream())
                        using (var dst = File.Create(zip))
                        {
                            long total = resp.ContentLength, got = 0; var buf = new byte[1 << 16]; int n; int lastPct = -1;
                            while ((n = src.Read(buf, 0, buf.Length)) > 0)
                            {
                                dst.Write(buf, 0, n); got += n;
                                int pct = total > 0 ? (int)(got * 100 / total) : 0;
                                if (pct != lastPct) { lastPct = pct; long g2 = got; Post(delegate { StepState("download", "run", "downloading Enclave " + version + ": " + pct + "% (" + (g2 >> 20) + " MB)", pct / 100.0); }); }
                            }
                        }
                    }
                    string got2 = Sha256(zip);
                    if (got2 != sha) throw new Exception("the download hashes " + got2.Substring(0, 16) + ", not the published " + sha.Substring(0, 16) + ": not installing it");
                    bundleDir = Path.Combine(WorkDir, version);
                    if (Directory.Exists(bundleDir)) Directory.Delete(bundleDir, true);
                    ZipFile.ExtractToDirectory(zip, bundleDir);
                    Post(delegate { Idle(); StepState("download", "ok", "Enclave " + version + " downloaded; sha256 " + sha.Substring(0, 12) + "… matches the UNSIGNED latest.json", 1); Check(); });
                }
                catch (Exception e) { Post(delegate { Idle(); StepState("download", "fail", "download failed: " + e.Message); Page("The download did not work", "Check the internet connection and try again.", "Try again", Download); }); }
            });
        }

        /// <summary>The download under a release policy: every mirror asked, only statements signed by the pinned key(s) to the
        /// threshold counted, the highest version taken, and the zip accepted only with the signed size and sha256.</summary>
        void SignedDownload()
        {
            Page("Downloading Enclave", "", "Next", null);
            phase = "download"; rail.Failed = false;
            StepState("download", "run", "asking the release policy's mirrors for the latest signed release", 0);
            Work(delegate
            {
                try
                {
                    SecureWorkDir();
                    var policy = ReleaseChannel.LoadPolicy(opt.ReleasePolicy);
                    var notes = new List<string>();
                    var rel = ReleaseChannel.Resolve(policy, delegate (string m) { lock (notes) notes.Add(m); });
                    version = rel.Version;
                    string zip = Path.Combine(WorkDir, rel.File);
                    int lastPct = -1;
                    ReleaseChannel.Download(policy, rel, rel.File, rel.Sha256, rel.Bytes, zip, delegate (long got, long total)
                    {
                        int pct = total > 0 ? (int)(got * 100 / total) : 0;
                        if (pct == lastPct) return;
                        lastPct = pct;
                        Post(delegate { StepState("download", "run", "downloading Enclave " + rel.Version + ": " + pct + "% (" + (got >> 20) + " MB)", pct / 100.0); });
                    }, delegate (string m) { lock (notes) notes.Add(m); });
                    bundleDir = Path.Combine(WorkDir, version);
                    if (Directory.Exists(bundleDir)) Directory.Delete(bundleDir, true);
                    ZipFile.ExtractToDirectory(zip, bundleDir);
                    string skipped; lock (notes) skipped = notes.Count > 0 ? " (" + notes.Count + " mirror answer(s) refused: " + notes[0] + ")" : "";
                    Post(delegate { Idle(); StepState("download", "ok", "Enclave " + rel.Version + " signed by " + rel.Signers + " pinned key(s) and checked (sha256 "
                                                     + rel.Sha256.Substring(0, 12) + "…)" + skipped, 1); Check(); });
                }
                catch (Exception e) { Post(delegate { Idle(); StepState("download", "fail", "no signed release: " + e.Message); Page("No release signed by the pinned key(s)", "Nothing was installed. Check the release policy's mirrors and keys, then try again.", "Try again", Download); }); }
            });
        }

        // ---- 3. checks (and Hyper-V) ------------------------------------------------------------------------------------
        void Check()
        {
            Page("Checking this PC", "", "Next", null);
            phase = "check"; rail.Failed = false;
            RunScript(Path.Combine(bundleDir, "install-host.ps1"), "-CheckOnly", delegate (int code)
            {
                if (code == 0) ChooseName();
                else if (code == 3010) NeedsRestart();
                else Page("This PC cannot host yet", "Fix what is marked above, then run setup again.", "Check again", Check);
            });
        }

        void NeedsRestart()
        {
            Page("Restart to finish turning on Hyper-V",
                 "Windows needs a restart for Hyper-V. Setup starts again by itself after you sign in.", "Restart now", delegate
            {
                string self = Path.Combine(WorkDir, "EnclaveSetup.exe");
                try { File.Copy(Application.ExecutablePath, self, true); } catch { }
                // an independent install's options go in a file beside it: a RunOnce command line is limited to 260 characters
                string saved = null;
                if (opt.Any) { saved = Path.Combine(WorkDir, "setup-options.json"); opt.Save(saved); }
                using (var k = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"))
                    k.SetValue("EnclaveSetup", "\"" + self + "\" --resume " + (name ?? "-") + (Referral.Length > 0 ? " --referral " + Referral : "")
                               + (enclaveDns.Checked ? " --enclavedns" : " --no-enclavedns") + (saved != null ? " --options \"" + saved + "\"" : ""));
                Process.Start(new ProcessStartInfo("shutdown.exe", "/r /t 5 /c \"Enclave setup: restarting to turn on Hyper-V\"") { CreateNoWindow = true, UseShellExecute = false });
                Close();
            });
        }

        void ResumeAfterRestart()
        {
            if (name == "-") name = null;
            StepState("resume", "ok", "Hyper-V is on: continuing setup");
            Download();
        }

        // ---- 4. the name ----------------------------------------------------------------------------------------------
        void ChooseName()
        {
            Page("Name this host",
                 "This is how the network knows this PC: 3 to 32 lowercase letters, digits and hyphens. You cannot change it later "
                 + "without setting the host up again.", "Install", delegate { name = nameBox.Text.Trim(); nameRow.Visible = false; Install(); });
            nameRow.Visible = true; primary.Enabled = false;
            if (name != null) nameBox.Text = name; else { nameBox.Text = Environment.MachineName.ToLowerInvariant().Replace('_', '-'); }
            nameBox.Focus(); nameBox.SelectAll();
        }

        void CheckName(string candidate)
        {
            if (opt.NoRelay)
            {
                // no relay to reserve a route with: the name is this PC's label, and the endpoint is checked on chain by the installer
                bool fine = Regex.IsMatch(candidate, "^[a-z0-9](?:[a-z0-9-]{1,30})[a-z0-9]$") && !candidate.Contains("--");
                nameOk = fine; primary.Enabled = fine && RefValid;
                nameNote.ForeColor = fine ? Theme.Jade : Theme.Amber;
                nameNote.Text = !fine ? "3 to 32 lowercase letters, digits and hyphens"
                    : opt.NameCheck == "offline" ? "✓ '" + candidate + "' (" + opt.PublicUrl + " will NOT be checked on chain: --name-check offline)"
                    : "✓ '" + candidate + "'; " + opt.PublicUrl + " is checked on the pinned registry during install";
                return;
            }
            ThreadPool.QueueUserWorkItem(delegate
            {
                string reason = null; bool ok = false;
                try
                {
                    var j = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(
                        new WebClient().DownloadString(Relay + "/v1/hosts/name/" + Uri.EscapeDataString(candidate)));
                    object a, r; ok = j.TryGetValue("available", out a) && a is bool && (bool)a;
                    reason = j.TryGetValue("reason", out r) ? r as string : null;
                }
                catch (Exception e) { reason = "could not check the name: " + e.Message; }
                Post(delegate
                {
                    if (nameBox.Text.Trim() != candidate) return;           // the owner typed on
                    nameOk = ok; primary.Enabled = ok && RefValid;
                    nameNote.ForeColor = ok ? Theme.Jade : Theme.Amber;
                    nameNote.Text = ok ? "✓ '" + candidate + "' is available" : (reason ?? "not available");
                });
            });
        }

        // ---- 5. install -------------------------------------------------------------------------------------------------
        void Install()
        {
            Page("Installing '" + name + "'", "This takes a few minutes. Keep this PC on.", "Next", null);
            phase = "install"; rail.Failed = false;
            string owner = Environment.UserDomainName + "\\" + Environment.UserName;
            RunScript(Path.Combine(bundleDir, "install-host.ps1"), "-Name " + name + " -Owner \"" + owner + "\" -SetupExe \"" + Application.ExecutablePath + "\""
                      + (Referral.Length > 0 ? " -Referral " + Referral : "") + (enclaveDns.Checked ? " -EnclaveDNS" : "") + opt.InstallArgs(), delegate (int code)
            {
                if (code == 0) Done();
                else if (code == 3010) NeedsRestart();
                else Page("Setup did not finish", "See the step marked above. Run setup again after fixing it: it carries on where it stopped.", "Try again", Install);
            });
        }

        void Done()
        {
            rail.Value = 1; Caption();
            Page("'" + name + "' is an Enclave host",
                 "It starts with Windows and takes work from the network. Open Enclave Hosting to choose the wallet your earnings are paid to, "
                 + "and how much of this PC to offer.", "Open Enclave Hosting", delegate
            {
                string tray = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Enclave\Tray\EnclaveTray.exe");
                try { Process.Start(tray); } catch { }
                Close();
            });
            secondary.Text = "Close"; secondary.FitText();
        }

        // ---- uninstall (Settings > Apps > Installed apps > Enclave > Uninstall) ----------------------------------------------
        void Uninstall()
        {
            Page("Remove Enclave from this PC",
                 "This stops hosting and removes Enclave's services, Enclave Shield's virtual machines, the tray and the program files. "
                 + "This host's keys and records stay in C:\\ProgramData\\Enclave unless you tick the box, so you can reinstall it as the "
                 + "same host. Its operator key holds any earnings not yet paid out: keep it until they are. Hyper-V stays on.", "Remove", delegate
            {
                bool all = removeData.Checked; removeData.Visible = false;
                Page("Removing Enclave", "", "Next", null);
                phase = "uninstall"; rail.Failed = false;
                string script = Path.Combine(Path.GetDirectoryName(Application.ExecutablePath), "uninstall-host.ps1");
                if (!File.Exists(script)) script = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Enclave\uninstall-host.ps1");
                RunScript(script, all ? "-RemoveData" : "", delegate (int code)
                {
                    if (code == 0)
                    {
                        rail.Value = 1; Caption();
                        Page("Enclave is removed", all ? "This host's data was moved aside, not deleted (see above)."
                             : "This host's data is kept: run setup again to bring it back as the same host.", "Close", delegate { Close(); });
                        secondary.Visible = false;
                    }
                    else Page("Enclave was not fully removed", "See the step marked above, then try again.", "Try again", Uninstall);
                });
            });
            removeData.Visible = true;
        }
        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            base.OnFormClosed(e);
            // a temporary copy (see SetupProgram.Main) removes itself once it has exited
            string here = Path.GetDirectoryName(Application.ExecutablePath);
            if (Path.GetFileName(here).StartsWith("Enclave-setup-", StringComparison.OrdinalIgnoreCase) &&
                here.StartsWith(Path.GetTempPath().TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                try { Process.Start(new ProcessStartInfo("cmd.exe", "/c ping -n 3 127.0.0.1 >nul & rmdir /s /q \"" + here + "\"") { CreateNoWindow = true, UseShellExecute = false }); } catch { }
        }

        /// <summary>Run an install script with these arguments, showing its JSON lines as steps.</summary>
        void RunScript(string script, string args, Action<int> done)
        {
            Work(delegate
            {
                int code = 1;
                try
                {
                    var psi = new ProcessStartInfo("powershell.exe",
                        "-NoProfile -ExecutionPolicy Bypass -File \"" + script + "\" " + args)
                    { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
                    using (var p = Process.Start(psi))
                    {
                        var err = new StringBuilder();
                        p.ErrorDataReceived += (s, e) => { if (e.Data != null) lock (err) err.AppendLine(e.Data); };
                        p.OutputDataReceived += (s, e) =>
                        {
                            if (e.Data == null) return;
                            Dictionary<string, object> j = null;
                            try { j = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(e.Data); } catch { }
                            if (j == null || !j.ContainsKey("step")) return;
                            string step = (string)j["step"], state = (string)j["state"], msg = (string)j["message"];
                            Post(delegate { StepState(step, state, msg); });
                        };
                        p.BeginOutputReadLine(); p.BeginErrorReadLine();
                        // Wait for the SCRIPT, not for the end of its output: a process it starts (the tray did, 2026-10-12) can
                        // inherit the output pipe and hold it open for as long as it runs. WaitForExit(ms) returns when the script
                        // exits; the lines it wrote last get a moment to arrive, then setup moves on whatever still holds the pipe.
                        while (!p.WaitForExit(250)) { }
                        Thread.Sleep(750);
                        code = p.ExitCode;
                        string e2; lock (err) e2 = err.ToString();
                        if (code != 0 && code != 3010 && e2.Length > 0) { Post(delegate { status.Text = e2.Length > 600 ? e2.Substring(0, 600) : e2; }); }
                    }
                }
                catch (Exception e) { string m = e.Message; Post(delegate { StepState("setup", "fail", "setup could not run its installer: " + m); }); }
                int c = code;
                Post(delegate { Idle(); done(c); });
            });
        }

        /// <summary>
        /// ProgramData\Enclave-setup, where setup (and later update-host.ps1, as SYSTEM) keeps the zips, setup programs and
        /// expanded bundles it then RUNS. A folder made under ProgramData inherits "Users: create files", so any local account
        /// could plant or keep a file there that an elevated step later trusts. Setup accepts the folder only if it is
        /// SYSTEM's and Administrators' alone (protected, every rule for them, owned by one of them, not a link); otherwise it
        /// moves it aside, untouched, to Enclave-setup.untrusted-*, and makes a new one with exactly that access.
        /// </summary>
        static void SecureWorkDir()
        {
            var sy = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
            var ba = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
            if (Directory.Exists(WorkDir))
            {
                bool ok = (File.GetAttributes(WorkDir) & FileAttributes.ReparsePoint) == 0;
                var acl = Directory.GetAccessControl(WorkDir);
                var owner = acl.GetOwner(typeof(System.Security.Principal.SecurityIdentifier));
                ok = ok && acl.AreAccessRulesProtected && (sy.Equals(owner) || ba.Equals(owner));
                foreach (System.Security.AccessControl.FileSystemAccessRule r in acl.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier)))
                    if (!sy.Equals(r.IdentityReference) && !ba.Equals(r.IdentityReference)) ok = false;
                if (ok) return;
                Directory.Move(WorkDir, WorkDir + ".untrusted-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss") + "-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            }
            var ds = new System.Security.AccessControl.DirectorySecurity();
            ds.SetSecurityDescriptorSddlForm("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
            Directory.CreateDirectory(WorkDir, ds);
        }

        static string Sha256(string path)
        {
            using (var s = File.OpenRead(path)) using (var h = SHA256.Create())
                return BitConverter.ToString(h.ComputeHash(s)).Replace("-", "").ToLowerInvariant();
        }
    }

    /// <summary>An independent install's choices (--release-policy, --no-relay, --public-url, --gateways, --contract-pins, --rpcs,
    /// --directories, --network-checkers, --name-check), checked here for shape and passed on to install-host.ps1, which
    /// checks them again and records them. Saved to a file across the Hyper-V restart.</summary>
    sealed class SetupOptions
    {
        public string ReleasePolicy, PublicUrl, Gateways, ContractPins, Rpcs, Directories, NetworkCheckers, NameCheck, Error;
        public bool NoRelay;
        public bool Any { get { return NoRelay || ReleasePolicy != null; } }
        public void Take(string k, string v)
        {
            v = (v ?? "").Trim();
            if (k == "--release-policy") ReleasePolicy = Path.GetFullPath(v);
            else if (k == "--public-url") PublicUrl = v;
            else if (k == "--gateways") Gateways = v;
            else if (k == "--contract-pins") ContractPins = Path.GetFullPath(v);
            else if (k == "--rpcs") Rpcs = v;
            else if (k == "--directories") Directories = v;
            else if (k == "--network-checkers") NetworkCheckers = v;
            else if (k == "--name-check") NameCheck = v;
        }
        static bool Urls(string list) { if (string.IsNullOrEmpty(list)) return true; foreach (var u in list.Split(',')) if (!Regex.IsMatch(u.Trim(), @"^https://[^\s?#@""]+$")) return false; return true; }
        /// <summary>null when the options make sense together; otherwise what to fix.</summary>
        public string Check()
        {
            if (ReleasePolicy != null && !File.Exists(ReleasePolicy)) return "The release policy " + ReleasePolicy + " does not exist.";
            bool independentBits = PublicUrl != null || Gateways != null || ContractPins != null || Rpcs != null || Directories != null || NetworkCheckers != null || NameCheck != null;
            if (!NoRelay) return independentBits ? "--public-url, --gateways, --contract-pins, --rpcs, --directories, --network-checkers and --name-check are for an independent host: add --no-relay." : null;
            if (string.IsNullOrEmpty(PublicUrl) || string.IsNullOrEmpty(Gateways) || string.IsNullOrEmpty(ContractPins))
                return "An independent host (--no-relay) needs --public-url, --gateways and --contract-pins: nothing defaults to an Enclave service.";
            if (!Regex.IsMatch(PublicUrl, @"^https://[A-Za-z0-9.-]+(:\d+)?(/[A-Za-z0-9._~/-]*[A-Za-z0-9._~-])?$")) return "--public-url must be an https URL written exactly as it will be registered, with no trailing slash.";
            if (!Urls(Gateways) || !Urls(Rpcs) || !Urls(Directories)) return "--gateways, --rpcs and --directories must be comma-separated https URLs.";
            if (!string.IsNullOrEmpty(NetworkCheckers) && !Regex.IsMatch(NetworkCheckers, @"^0x[0-9a-fA-F]{40}(,0x[0-9a-fA-F]{40})*$")) return "--network-checkers must be comma-separated addresses.";
            if (!File.Exists(ContractPins)) return "The contract pin document " + ContractPins + " does not exist.";
            if (NameCheck != null && NameCheck != "chain" && NameCheck != "offline") return "--name-check is chain or offline for an independent host.";
            return null;
        }
        static string Q(string path) { return "\"" + path + "\""; }
        /// <summary>The install-host.ps1 arguments for these options (none for a legacy install).</summary>
        public string InstallArgs()
        {
            var b = new StringBuilder();
            if (ReleasePolicy != null) b.Append(" -ReleasePolicy " + Q(ReleasePolicy));
            if (!NoRelay) return b.ToString();
            b.Append(" -NoRelay -PublicUrl " + PublicUrl + " -Gateways " + Gateways + " -ContractPins " + Q(ContractPins));
            if (!string.IsNullOrEmpty(Rpcs)) b.Append(" -Rpcs " + Rpcs);
            if (!string.IsNullOrEmpty(Directories)) b.Append(" -Directories " + Directories);
            if (!string.IsNullOrEmpty(NetworkCheckers)) b.Append(" -NetworkCheckers " + NetworkCheckers);
            if (!string.IsNullOrEmpty(NameCheck)) b.Append(" -NameCheck " + NameCheck);
            return b.ToString();
        }
        public void Save(string path)
        {
            var d = new Dictionary<string, object> { { "releasePolicy", ReleasePolicy }, { "noRelay", NoRelay }, { "publicUrl", PublicUrl }, { "gateways", Gateways },
                { "contractPins", ContractPins }, { "rpcs", Rpcs }, { "directories", Directories }, { "networkCheckers", NetworkCheckers }, { "nameCheck", NameCheck } };
            File.WriteAllText(path, new JavaScriptSerializer().Serialize(d));
        }
        public static SetupOptions Load(string path)
        {
            var d = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(File.ReadAllText(path));
            Func<string, string> s = delegate (string k) { object v; return d.TryGetValue(k, out v) ? v as string : null; };
            object nr; return new SetupOptions { ReleasePolicy = s("releasePolicy"), NoRelay = d.TryGetValue("noRelay", out nr) && nr is bool && (bool)nr, PublicUrl = s("publicUrl"),
                Gateways = s("gateways"), ContractPins = s("contractPins"), Rpcs = s("rpcs"), Directories = s("directories"), NetworkCheckers = s("networkCheckers"), NameCheck = s("nameCheck") };
        }
    }

    /// <summary>
    /// The signed Windows release channel, as windows/node/release-channel.mjs defines it (test/windows-release-channel.test.mjs
    /// and test/windows-installer-independence.test.mjs hold the two to the same constants; test/windows-native/run.ps1 runs
    /// this class, cli/host.ps1 and the Node module over one fixture set and expects the same verdicts). A policy pins P-256
    /// keys ("ecdsa-p256:" + base64 SubjectPublicKeyInfo), a threshold and mirrors; a mirror's latest.signed.json carries the
    /// statement's exact bytes and raw r||s signatures over Context + those bytes. Verified with CNG (ECDsaCng over an
    /// ECCPUBLICBLOB built from the key's X and Y), which every Windows this installer supports has: no crypto of our own.
    /// Every name outside System, System.Collections.Generic, System.Globalization, System.IO, System.Net,
    /// System.Security.Cryptography, System.Text and System.Text.RegularExpressions is written in full, so the class also
    /// compiles on its own (test/windows-native/run.ps1 extracts it, as the coordinator's first native check did).
    /// </summary>
    static class ReleaseChannel
    {
        public const string PolicyFormat = "enclave-windows-release-policy/v1";
        public const string StatementFormat = "enclave-windows-release/v1";
        public const string EnvelopeFormat = "enclave-windows-release-envelope/v1";
        public const string EnvelopeName = "latest.signed.json";
        public const string Context = "enclave-windows-release-signature/v1\n";
        public const string P256SpkiPrefixHex = "3059301306072a8648ce3d020106082a8648ce3d03010703420004";
        const int BcryptEcdsaPublicP256Magic = 0x31534345;   // "ECS1"
        const long MaxZip = 2L * 1024 * 1024 * 1024;
        const int MaxEnvelope = 64 * 1024;
        // Hard deadlines over a whole exchange (connect, headers AND body), as in release-channel.mjs: a pointer gets
        // EnvelopeDeadlineMs; a file 60 s plus its signed size at MinRate bytes/s, at most AttemptCapMs per mirror, and all
        // mirrors together DownloadDeadlineMs. HttpWebRequest's Timeout and ReadWriteTimeout bound single waits only, so a
        // timer aborts the request when the deadline passes. Settable for the native harness.
        public static int EnvelopeDeadlineMs = 20000, AttemptCapMs = 3600000, DownloadDeadlineMs = 2 * 3600000;
        public const long MinRate = 128 * 1024;

        public sealed class Key { public string Id; public byte[] Blob; }
        public sealed class Policy { public string Channel; public int Threshold; public List<Key> Keys = new List<Key>(); public List<string> Mirrors = new List<string>(); }
        public sealed class Release { public string Version, File, Sha256, StatementSha256; public long Bytes; public int Signers; public List<string> ServedBy = new List<string>(); }

        static string Hex(byte[] b) { return BitConverter.ToString(b).Replace("-", "").ToLowerInvariant(); }
        static byte[] Sha(byte[] b) { using (var h = SHA256.Create()) return h.ComputeHash(b); }
        static Dictionary<string, object> Obj(object o, string what) { var d = o as Dictionary<string, object>; if (d == null) throw new Exception(what + " is not a JSON object"); return d; }
        static void Exact(Dictionary<string, object> d, string what, params string[] allowed)
        {
            foreach (var k in d.Keys) if (Array.IndexOf(allowed, k) < 0) throw new Exception(what + " has an unknown field: " + k);
        }
        static string Str(Dictionary<string, object> d, string k) { object v; return d.TryGetValue(k, out v) ? v as string : null; }
        // .NET's $ also matches before a final newline and its \d matches every script's digits; JavaScript's do neither.
        // \z and [0-9] make these patterns mean what they mean in release-channel.mjs.
        static bool Is(string s, string pattern) { return s != null && Regex.IsMatch(s, pattern, RegexOptions.CultureInvariant); }
        static byte[] B64(string s, string what)
        {
            if (!Is(s, @"^[A-Za-z0-9+/]+={0,2}\z")) throw new Exception(what + " is not base64");
            var b = Convert.FromBase64String(s);
            if (Convert.ToBase64String(b) != s) throw new Exception(what + " is not canonical base64");
            return b;
        }

        public static Key ParseKey(string spec)
        {
            if (spec == null || !spec.StartsWith("ecdsa-p256:", StringComparison.Ordinal)) throw new Exception("a release key must be ecdsa-p256:<base64 SPKI>");
            byte[] der = B64(spec.Substring(11), "release key"), prefix = new byte[27];
            for (int i = 0; i < 27; i++) prefix[i] = Convert.ToByte(P256SpkiPrefixHex.Substring(i * 2, 2), 16);
            if (der.Length != 91) throw new Exception("a release key must be an uncompressed P-256 public key");
            for (int i = 0; i < 27; i++) if (der[i] != prefix[i]) throw new Exception("a release key must be an uncompressed P-256 public key");
            // BCRYPT_ECCKEY_BLOB: magic, key length (32), then X and Y, which are the SPKI's last 64 bytes
            var blob = new byte[8 + 64];
            BitConverter.GetBytes(BcryptEcdsaPublicP256Magic).CopyTo(blob, 0);
            BitConverter.GetBytes(32).CopyTo(blob, 4);
            Array.Copy(der, 27, blob, 8, 64);
            using (var k = CngKey.Import(blob, CngKeyBlobFormat.EccPublicBlob)) { }   // refuses a point that is not on the curve
            return new Key { Id = Hex(Sha(der)), Blob = blob };
        }
        // A mirror's host is judged as WRITTEN, before Uri reads it: .NET's Uri.Host spells an IPv6 literal its own way (so
        // "[::1]" never matched it; native run 2026-10-20, fixture 29), and WHATWG URL in release-channel.mjs reads 127.1,
        // 2130706433 and 0x7f000001 as IPv4. The same three rules hold in all three verifiers: a name is a strict DNS name
        // (a canonical dotted quad if its last label looks numeric); an IPv6 literal must parse to exactly ::1 (compressed
        // or in full) and is written [::1]; plain http only for localhost, 127.0.0.1 or [::1].
        static readonly Regex RawHost = new Regex(@"^[A-Za-z][A-Za-z0-9+.-]*://(\[[^\]]*\]|[^/:]*)(:[0-9]{1,5})?(/|\z)", RegexOptions.CultureInvariant);   // the whole authority: host[:digits]
        const string DnsHost = @"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*\z";
        const string NumericLastLabel = @"(^|\.)([0-9]+|0[xX][0-9A-Fa-f]*)\z";
        const string DottedQuad = @"^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}\z";
        /// <summary>A mirror: printable ASCII without \ ? # @ % (no spelling .NET's Uri and Node's URL normalise differently),
        /// https (http only on localhost, 127.0.0.1 or [::1], exactly as release-channel.mjs), ending in "/".</summary>
        public static string Mirror(string m)
        {
            Uri u;
            if (!Is(m, @"^[!-~]+\z") || m.IndexOfAny(new[] { '\\', '?', '#', '@', '%' }) >= 0 || !Uri.TryCreate(m, UriKind.Absolute, out u)) throw new Exception("mirror " + m + " is not a plain URL");
            string raw = RawHost.Match(m).Groups[1].Value;
            bool v6 = raw.StartsWith("[", StringComparison.Ordinal);
            IPAddress a;
            bool hostOk = v6 ? u.HostNameType == UriHostNameType.IPv6 && IPAddress.TryParse(raw.Substring(1, raw.Length - 2), out a) && a.Equals(IPAddress.IPv6Loopback)
                             : Is(raw, DnsHost) && !(Is(raw, NumericLastLabel) && !Is(raw, DottedQuad)) && string.Equals(u.Host, raw, StringComparison.OrdinalIgnoreCase);
            if (!hostOk) throw new Exception("mirror " + m + " must name a DNS host, a dotted quad or [::1], written plainly");
            string host = raw.ToLowerInvariant();
            bool loop = u.Scheme == "http" && (v6 || host == "localhost" || host == "127.0.0.1");
            if (u.Scheme != "https" && !loop) throw new Exception("mirror " + m + " must be https");
            if (u.UserInfo.Length > 0 || u.Query.Length > 0 || u.Fragment.Length > 0) throw new Exception("mirror " + m + " must not carry credentials, a query or a fragment");
            string s = v6 ? u.Scheme + "://[::1]" + (u.IsDefaultPort ? "" : ":" + u.Port.ToString(CultureInfo.InvariantCulture)) + u.AbsolutePath : u.AbsoluteUri;
            return s.EndsWith("/") ? s : s + "/";
        }
        public static Policy LoadPolicy(string path)
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > 4 * 16 * 1024) throw new Exception("the release policy " + path + " is missing or too large");
            return ParsePolicy(Encoding.UTF8.GetString(File.ReadAllBytes(path)));
        }
        public static Policy ParsePolicy(string json)
        {
            var d = Obj(new System.Web.Script.Serialization.JavaScriptSerializer().DeserializeObject(json.TrimStart('﻿')), "the release policy");
            Exact(d, "the release policy", "format", "channel", "keys", "threshold", "mirrors");
            if (Str(d, "format") != PolicyFormat) throw new Exception("the release policy's format must be " + PolicyFormat);
            var p = new Policy { Channel = Str(d, "channel") };
            if (!Is(p.Channel, @"^[a-z0-9][a-z0-9._-]{0,31}\z")) throw new Exception("the release policy's channel is not valid");
            var keys = d.ContainsKey("keys") ? d["keys"] as System.Collections.IList : null; var mirrors = d.ContainsKey("mirrors") ? d["mirrors"] as System.Collections.IList : null;
            if (keys == null || keys.Count < 1 || keys.Count > 8) throw new Exception("the release policy needs 1 to 8 keys");
            foreach (var k in keys) { var key = ParseKey(k as string); foreach (var x in p.Keys) if (x.Id == key.Id) throw new Exception("the release policy lists a key twice"); p.Keys.Add(key); }
            object t; if (!d.TryGetValue("threshold", out t) || !(t is int) || (int)t < 1 || (int)t > p.Keys.Count) throw new Exception("the release policy's threshold must be 1 to the number of keys");
            p.Threshold = (int)t;
            if (mirrors == null || mirrors.Count < 1 || mirrors.Count > 8) throw new Exception("the release policy needs 1 to 8 mirrors");
            foreach (var m in mirrors) { var n = Mirror(m as string); if (p.Mirrors.Contains(n)) throw new Exception("the release policy lists a mirror twice"); p.Mirrors.Add(n); }
            return p;
        }
        static readonly string[] StatementFields = { "format", "channel", "version", "issuedAt", "expiresAt", "file", "sha256", "bytes",
                                                     "setup", "setupSha256", "setupBytes", "manifest", "manifestSha256", "manifestBytes" };
        static long Size(Dictionary<string, object> s, string k, long max)
        {
            object v; if (!s.TryGetValue(k, out v) || !(v is int || v is long)) throw new Exception("the signed statement's " + k + " is not a size");
            long n = Convert.ToInt64(v, CultureInfo.InvariantCulture); if (n < 1 || n > max) throw new Exception("the signed statement's " + k + " is out of range");
            return n;
        }
        static DateTime When(string s, string what)
        {
            DateTime t;
            if (!Is(s, @"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,3})?Z\z") ||
                !DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out t)) throw new Exception(what + " is not an ISO-8601 UTC time");
            return t;
        }
        /// <summary>1.2 and 1.2.0 are one Version: two different statements for it are equivocation (release-channel.mjs).</summary>
        public static string VersionKey(string v) { var x = Version.Parse(v); return Math.Max(0, x.Major) + "." + Math.Max(0, x.Minor) + "." + Math.Max(0, x.Build) + "." + Math.Max(0, x.Revision); }
        public static Release Verify(string envelopeJson, Policy p) { return Verify(Encoding.UTF8.GetBytes(envelopeJson), p, DateTime.UtcNow); }
        /// <summary>Verify one mirror's envelope: the signatures first (to the threshold, by distinct pinned keys), then the statement.</summary>
        public static Release Verify(byte[] raw, Policy p, DateTime nowUtc)
        {
            if (raw.Length > MaxEnvelope) throw new Exception("the envelope is too large");
            var js = new System.Web.Script.Serialization.JavaScriptSerializer();
            var env = Obj(js.DeserializeObject(Encoding.UTF8.GetString(raw).TrimStart('﻿')), "the envelope");
            Exact(env, "the envelope", "format", "statement", "signatures");
            if (Str(env, "format") != EnvelopeFormat) throw new Exception("not a signed release envelope");
            byte[] statement = B64(Str(env, "statement"), "the statement");
            if (statement.Length > 16 * 1024) throw new Exception("the statement is too large");
            byte[] ctx = Encoding.ASCII.GetBytes(Context), msg = new byte[ctx.Length + statement.Length];
            ctx.CopyTo(msg, 0); statement.CopyTo(msg, ctx.Length);
            var sigs = env.ContainsKey("signatures") ? env["signatures"] as System.Collections.IList : null;
            if (sigs == null || sigs.Count > 16) throw new Exception("the envelope's signatures are not a list of at most 16");
            var signed = new List<string>();
            foreach (var o in sigs)
            {
                var s = Obj(o, "a signature"); Exact(s, "a signature", "keyId", "sig");
                string id = Str(s, "keyId"); Key key = null;
                foreach (var k in p.Keys) if (k.Id == id) key = k;
                if (key == null || signed.Contains(id)) continue;
                byte[] sig = B64(Str(s, "sig"), "a signature");
                if (sig.Length != 64) continue;
                using (var ck = CngKey.Import(key.Blob, CngKeyBlobFormat.EccPublicBlob))
                using (var ec = new ECDsaCng(ck))
                {
                    ec.HashAlgorithm = CngAlgorithm.Sha256;
                    if (ec.VerifyData(msg, sig)) signed.Add(id);
                }
            }
            if (signed.Count < p.Threshold) throw new Exception(signed.Count + " valid signature(s) by pinned keys; the policy requires " + p.Threshold);
            var st = Obj(js.DeserializeObject(Encoding.UTF8.GetString(statement)), "the signed statement");
            Exact(st, "the signed statement", StatementFields);
            if (Str(st, "format") != StatementFormat) throw new Exception("the signed statement's format is not " + StatementFormat);
            if (Str(st, "channel") != p.Channel) throw new Exception("the signed statement is for channel " + Str(st, "channel") + ", not " + p.Channel);
            string v = Str(st, "version");
            if (!Is(v, @"^[0-9]{1,9}(\.[0-9]{1,9}){1,3}\z")) throw new Exception("the signed statement's version is not valid");
            if (When(Str(st, "issuedAt"), "issuedAt") > nowUtc.AddDays(1)) throw new Exception("the signed statement is issued in the future");
            if (st.ContainsKey("expiresAt") && When(Str(st, "expiresAt"), "expiresAt") <= nowUtc) throw new Exception("the signed statement expired at " + Str(st, "expiresAt"));
            string[,] art = { { "file", "sha256", "bytes", "enclave-host-" + v + ".zip" }, { "setup", "setupSha256", "setupBytes", "EnclaveSetup-" + v + ".exe" },
                              { "manifest", "manifestSha256", "manifestBytes", "manifest-" + v + ".json" } };
            long[] max = { MaxZip, 64L * 1024 * 1024, 16L * 1024 * 1024 };
            for (int i = 0; i < 3; i++)
            {
                if (Str(st, art[i, 0]) != art[i, 3]) throw new Exception("the signed statement's " + art[i, 0] + " must be " + art[i, 3]);
                if (!Is(Str(st, art[i, 1]), @"^[0-9a-f]{64}\z")) throw new Exception("the signed statement's " + art[i, 1] + " is not a sha256");
                Size(st, art[i, 2], max[i]);
            }
            return new Release { Version = v, File = Str(st, "file"), Sha256 = Str(st, "sha256"), Bytes = Size(st, "bytes", MaxZip),
                                 StatementSha256 = Hex(Sha(statement)), Signers = signed.Count };
        }
        /// <summary>
        /// GET url, handing each chunk to sink, bounded in bytes and time: an announced length over max (or other than expect,
        /// when expect is not negative) is refused before the body is read, a body longer than either at the first byte over,
        /// and the whole exchange is aborted at deadlineMs however slowly the bytes come. The request is aborted (not drained)
        /// on any failure, so a body that never ends cannot hold the dispose either. -> the bytes received.
        /// </summary>
        public static long Fetch(string url, long max, long expect, int deadlineMs, Action<byte[], int> sink)
        {
            var q = (HttpWebRequest)WebRequest.Create(url);
            q.Timeout = deadlineMs; q.ReadWriteTimeout = deadlineMs; q.KeepAlive = false;
            q.CachePolicy = new System.Net.Cache.RequestCachePolicy(System.Net.Cache.RequestCacheLevel.NoCacheNoStore);
            var clock = System.Diagnostics.Stopwatch.StartNew();
            bool late = false;
            using (new System.Threading.Timer(delegate { late = true; try { q.Abort(); } catch { } }, null, deadlineMs, System.Threading.Timeout.Infinite))
            {
                try
                {
                    using (var resp = q.GetResponse())
                    using (var src = resp.GetResponseStream())
                    {
                        try
                        {
                            if (resp.ContentLength > max) throw new Exception("announces " + resp.ContentLength + " bytes, more than " + max);
                            if (expect >= 0 && resp.ContentLength >= 0 && resp.ContentLength != expect) throw new Exception("announces " + resp.ContentLength + " bytes, the signed size is " + expect);
                            long got = 0; var buf = new byte[1 << 16]; int n;
                            while ((n = src.Read(buf, 0, buf.Length)) > 0)
                            {
                                got += n;
                                if (got > max) throw new Exception("sent more than " + max + " bytes");
                                if (expect >= 0 && got > expect) throw new Exception("sent more than the signed " + expect + " bytes");
                                if (clock.ElapsedMilliseconds > deadlineMs) throw new Exception("did not finish within " + deadlineMs / 1000 + " s");
                                sink(buf, n);
                            }
                            if (expect >= 0 && got != expect) throw new Exception("sent " + got + " bytes, the signed size is " + expect);
                            return got;
                        }
                        catch { try { q.Abort(); } catch { } throw; }
                    }
                }
                catch (Exception e)
                {
                    if (late || clock.ElapsedMilliseconds > deadlineMs) throw new Exception("did not finish within " + deadlineMs / 1000 + " s", e);
                    throw;
                }
            }
        }
        /// <summary>Every mirror's signed pointer; the highest version any of them proves. A mirror that serves nothing valid is
        /// noted and outvoted; two different signed statements for one version stop setup.</summary>
        public static Release Resolve(Policy p, Action<string> note)
        {
            Release best = null; var seen = new Dictionary<string, Release>(); var why = new List<string>();
            foreach (var m in p.Mirrors)
            {
                Release r;
                try
                {
                    using (var buf = new MemoryStream())
                    {
                        Fetch(m + EnvelopeName, MaxEnvelope, -1, EnvelopeDeadlineMs, delegate (byte[] b, int n) { buf.Write(b, 0, n); });
                        r = Verify(buf.ToArray(), p, DateTime.UtcNow);
                    }
                }
                catch (Exception e) { why.Add(m + ": " + e.Message); note(m + ": " + e.Message); continue; }
                Release other; string key = VersionKey(r.Version);
                if (seen.TryGetValue(key, out other))
                {
                    if (other.StatementSha256 != r.StatementSha256) throw new Exception("two different signed statements for version " + r.Version + ": not installing until the publisher explains");
                    other.ServedBy.Add(m); continue;
                }
                r.ServedBy.Add(m); seen[key] = r;
                if (best == null || Version.Parse(r.Version) > Version.Parse(best.Version)) best = r;
            }
            if (best == null) throw new Exception("no mirror served a release signed by the pinned key(s): " + string.Join("; ", why.ToArray()));
            return best;
        }
        /// <summary>A file the signed statement names, accepted only with the signed size and sha256, from the mirrors that served
        /// the statement first and then the others. An existing outPath with the signed size is hashed as a stream (never read
        /// whole) and kept if it matches. The part file has a random name and is created new; only a verified one becomes outPath.</summary>
        public static void Download(Policy p, string name, string sha, long bytes, string outPath, Action<long, long> progress, Action<string> note)
        {
            Download(p, null, name, sha, bytes, outPath, progress, note);
        }
        public static void Download(Policy p, Release servedBy, string name, string sha, long bytes, string outPath, Action<long, long> progress, Action<string> note)
        {
            var why = new List<string>();
            if (File.Exists(outPath) && (File.GetAttributes(outPath) & FileAttributes.ReparsePoint) == 0 && new FileInfo(outPath).Length == bytes)
                using (var f = File.OpenRead(outPath)) using (var h = SHA256.Create()) if (Hex(h.ComputeHash(f)) == sha) return;
            var order = new List<string>();
            if (servedBy != null) order.AddRange(servedBy.ServedBy);
            foreach (var m in p.Mirrors) if (!order.Contains(m)) order.Add(m);
            var clock = System.Diagnostics.Stopwatch.StartNew();
            foreach (var m in order)
            {
                long left = DownloadDeadlineMs - clock.ElapsedMilliseconds;
                if (left <= 0) { why.Add("the " + DownloadDeadlineMs / 1000 + " s deadline passed"); break; }
                int deadline = (int)Math.Min(left, Math.Min(AttemptCapMs, 60000 + (bytes * 1000 + MinRate - 1) / MinRate));
                string part = outPath + ".partial-" + Guid.NewGuid().ToString("N");
                try
                {
                    using (var h = SHA256.Create())
                    {
                        using (var dst = new FileStream(part, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                        {
                            long got = 0;
                            Fetch(m + name, bytes, bytes, deadline, delegate (byte[] b, int n)
                            {
                                dst.Write(b, 0, n); h.TransformBlock(b, 0, n, null, 0); got += n;
                                if (progress != null) progress(got, bytes);
                            });
                        }
                        h.TransformFinalBlock(new byte[0], 0, 0);
                        if (Hex(h.Hash) != sha) throw new Exception("hashes differently from the signed sha256");
                    }
                    if (File.Exists(outPath)) File.Delete(outPath);
                    File.Move(part, outPath);
                    return;
                }
                catch (Exception e) { try { File.Delete(part); } catch { } why.Add(m + ": " + e.Message); note(name + " from " + m + ": " + e.Message); }
            }
            throw new Exception(name + ": no mirror served the signed bytes (" + string.Join("; ", why.ToArray()) + ")");
        }
    }

    /// <summary>Setup's progress: a thin rail in the site's colours, filled jade to Value, and while Busy a soft band sweeping
    /// across the part still to do, so a step that waits is seen working. Failed turns the fill amber and stops the band.</summary>
    sealed class ProgressRail : Control
    {
        readonly System.Windows.Forms.Timer anim = new System.Windows.Forms.Timer { Interval = 33 };
        double value; bool busy, failed; int phase;
        public ProgressRail()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            Height = Theme.Px(6); BackColor = Theme.Bg;
            anim.Tick += delegate { phase = (phase + 1) % 90; Invalidate(); };
        }
        public double Value { get { return value; } set { this.value = Math.Max(0, Math.Min(1, value)); Invalidate(); } }
        public bool Busy { get { return busy; } set { busy = value; anim.Enabled = value && !failed; Invalidate(); } }
        public bool Failed { get { return failed; } set { failed = value; anim.Enabled = busy && !value; Invalidate(); } }
        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics; g.SmoothingMode = SmoothingMode.AntiAlias; g.Clear(Theme.Bg);
            float h = Height - 1, wAll = Width - 1, r = h / 2f;
            using (var p = Theme.Rounded(new RectangleF(0, 0, wAll, h), r)) using (var b = new SolidBrush(Theme.Line)) g.FillPath(b, p);
            float w = (float)(wAll * value);
            if (w > 0)
                using (var p = Theme.Rounded(new RectangleF(0, 0, Math.Max(w, h), h), r))
                using (var b = new SolidBrush(failed ? Theme.Amber : Theme.Jade)) g.FillPath(b, p);
            if (busy && !failed && wAll - w > 2)
            {
                float band = Math.Max(h * 4, wAll * .16f), x = w - band + (wAll - w + band) * phase / 90f;
                g.SetClip(new RectangleF(w, 0, wAll - w, h + 1));
                using (var lg = new LinearGradientBrush(new RectangleF(x, 0, band, h), Color.FromArgb(0, Theme.Jade), Color.FromArgb(0, Theme.Jade), LinearGradientMode.Horizontal))
                {
                    lg.InterpolationColors = new ColorBlend { Colors = new[] { Color.FromArgb(0, Theme.Jade), Color.FromArgb(170, Theme.Jade), Color.FromArgb(0, Theme.Jade) },
                                                              Positions = new[] { 0f, .5f, 1f } };
                    using (var p = Theme.Rounded(new RectangleF(0, 0, wAll, h), r)) g.FillPath(lg, p);
                }
                g.ResetClip();
            }
        }
        protected override void Dispose(bool disposing) { if (disposing) anim.Dispose(); base.Dispose(disposing); }
    }
}
