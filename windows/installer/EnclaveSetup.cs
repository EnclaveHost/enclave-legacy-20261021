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
// It runs as administrator (requireAdministrator in its manifest): it turns on Hyper-V, installs services and writes to
// Program Files.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
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
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--resume" && i + 1 < args.Length) resumeName = args[i + 1];
                if (args[i] == "--referral" && i + 1 < args.Length) referral = args[i + 1].Trim();
                if (args[i] == "--uninstall") uninstall = true;
                if (args[i] == "--no-enclavedns") enclaveDns = false;   // the owner unticked it before a restart
            }
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
            Application.Run(new SetupForm(resumeName, uninstall, referral, enclaveDns));
            return 0;
        }
    }

    sealed class SetupForm : Form
    {
        const string Downloads = "https://get.enclave.host/windows/";
        const string Relay = "https://api.enclave.host";
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
        static readonly string[] InstallSteps = { "checks", "hyperv", "name", "prereq", "files", "shield", "keys", "config", "services", "join", "tray", "enclavedns", "done" };
        static readonly int[] InstallWeights = { 1, 1, 1, 1, 4, 2, 1, 1, 3, 5, 1, 2, 1 };
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

        public SetupForm(string resumeName, bool uninstall, string referral, bool withEnclaveDns)
        {
            this.resumeName = resumeName;
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
                + "(answers checked with DNSSEC, with a fallback if it cannot be reached). Remove it any time from Installed apps.";
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
            Page("Host apps on this PC, and earn USDC.",
                 "Setup downloads Enclave (about 160 MB), checks that this PC can host (Windows 11 Pro, Secure Boot, an AMD processor's TPM, "
                 + "Hyper-V), and installs it. Apps run each in their own Enclave Shield partition. Joining the network costs you nothing: "
                 + "the first registration is paid for you once this PC proves its hardware.", "Start", Download);
        }

        // ---- 2. download ----------------------------------------------------------------------------------------------
        void Download()
        {
            Page("Downloading Enclave", "", "Next", null);
            phase = "download"; rail.Failed = false;
            StepState("download", "run", "asking get.enclave.host for the latest version", 0);
            Work(delegate
            {
                try
                {
                    Directory.CreateDirectory(WorkDir);
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
                    Post(delegate { Idle(); StepState("download", "ok", "Enclave " + version + " downloaded and checked (sha256 " + sha.Substring(0, 12) + "…)", 1); Check(); });
                }
                catch (Exception e) { Post(delegate { Idle(); StepState("download", "fail", "download failed: " + e.Message); Page("The download did not work", "Check the internet connection and try again.", "Try again", Download); }); }
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
                using (var k = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"))
                    k.SetValue("EnclaveSetup", "\"" + self + "\" --resume " + (name ?? "-") + (Referral.Length > 0 ? " --referral " + Referral : "")
                               + (enclaveDns.Checked ? "" : " --no-enclavedns"));
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
                      + (Referral.Length > 0 ? " -Referral " + Referral : "") + (enclaveDns.Checked ? " -EnclaveDNS" : ""), delegate (int code)
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

        static string Sha256(string path)
        {
            using (var s = File.OpenRead(path)) using (var h = SHA256.Create())
                return BitConverter.ToString(h.ComputeHash(s)).Replace("-", "").ToLowerInvariant();
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
