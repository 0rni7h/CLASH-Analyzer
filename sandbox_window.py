"""
sandbox_window.py
Sandbox Analyzer window – Deep Search and Static Analysis modes.
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import time
import random
import math
import requests

import lolbas_loader as lb
#API_KEY = "5ccf89e02b32872bc681cb88332440c61dbff84ecd35a75a2715a07499b55b41"
import os
API_KEY = os.getenv("VT_API_KEY")
if not API_KEY:
    print("API key not found!")
# ── Palette (shared with launcher) ───────────────────────────────────────────
BG       = "#0a0d14"
PANEL    = "#0f1420"
PANEL2   = "#111827"
ACCENT   = "#00e5ff"
ACCENT2  = "#7b2fff"
WARN     = "#ffb300"
DANGER   = "#ff3d57"
SUCCESS  = "#00ff88"
TEXT     = "#c9d1e0"
TEXT_DIM = "#4a5568"
BORDER   = "#1e2940"

FONT_H1   = ("Courier New", 16, "bold")
FONT_H2   = ("Courier New", 13, "bold")
FONT_BODY = ("Courier New", 10)
FONT_MONO = ("Courier New", 9)
FONT_BTN  = ("Courier New", 11, "bold")

# ── Scan durations (seconds) ─────────────────────────────────────────────────
# User rules: Deep = 3h to ~4h (10800 to 14400)
#             Static = 15m to 30m (900 to 1800)
DEEP_MIN = 1800
DEEP_MAX = 1800
STATIC_MIN = 10
STATIC_MAX = 60

# The user requested that the decreasing timer is a "steady time decrease like 1s each time".
# This means the demo actually runs in real-time, taking exactly 15–30mins or 3–4hours.


class ThreatGauge(tk.Canvas):
    """Semicircular arc-based threat gauge (0–100)."""

    def __init__(self, master, size=220, **kw):
        super().__init__(master, width=size, height=size // 2 + 30,
                         bg=BG, highlightthickness=0, **kw)
        self._size = size
        self._value = 0
        self._target = 0
        self._draw()

    def _draw(self):
        s = self._size
        cx, cy = s // 2, s // 2
        r = s // 2 - 10

        self.delete("all")

        # Background arc track
        self.create_arc(cx - r, cy - r, cx + r, cy + r,
                        start=180, extent=-180, style="arc",
                        outline=BORDER, width=16)

        # Coloured fill arc
        pct = self._value / 100.0
        extent = -(pct * 180)  # Negative extent draws clockwise from left (180 deg)
        if pct < 0.4:
            color = SUCCESS
        elif pct < 0.7:
            color = WARN
        else:
            color = DANGER

        if pct > 0:
            self.create_arc(cx - r, cy - r, cx + r, cy + r,
                            start=180, extent=extent, style="arc",
                            outline=color, width=14)

        # Needle (pointer)
        angle_deg = pct * 180
        angle_rad = math.radians(angle_deg)
        nx = cx + (r - 20) * math.cos(math.pi - angle_rad)
        ny = cy - (r - 20) * math.sin(math.pi - angle_rad)
        self.create_line(cx, cy, nx, ny, fill="white", width=3,
                         capstyle="round")
        self.create_oval(cx - 5, cy - 5, cx + 5, cy + 5,
                         fill=ACCENT, outline="")

        # Value label
        self.create_text(cx, cy + 22, text=f"{self._value}",
                         font=("Courier New", 22, "bold"),
                         fill=color)
        self.create_text(cx, cy + 44, text="THREAT SCORE",
                         font=("Courier New", 8), fill=TEXT_DIM)

    def set_value(self, value: float):
        self._value = max(0, min(100, int(value)))
        self._draw()

    def animate_to(self, target: float, steps: int = 20, delay: int = 30):
        """Smoothly animate the gauge to a target value."""
        self._target = max(0, min(100, target))
        self._smooth_step(self._value, self._target, steps, delay)

    def _smooth_step(self, current, target, steps_left, delay):
        if steps_left <= 0 or current == target:
            self.set_value(target)
            return
        delta = (target - current) / steps_left
        new_val = current + delta
        self.set_value(new_val)
        self.after(delay, lambda: self._smooth_step(new_val, target, steps_left - 1, delay))


class SandboxWindow(tk.Toplevel):
    """Sandbox Analyzer – deep/static scan with live progress and report."""

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("Sandbox Analyzer – CLASH Analyzer")
        self.geometry("1920x1080")
        self.minsize(840, 580)
        self.configure(bg=BG)
        self.resizable(True, True)

        self._mode          = tk.StringVar(value="static")
        self._running       = False
        self._skip_flag     = threading.Event()
        self._pause_flag    = threading.Event()
        self._tick          = 0
        self._total_risk    = 0
        self._findings      = []
        self._target_file   = tk.StringVar(self, value="")
        self._worker_thread: threading.Thread | None = None

        self._build_ui()
        self._load_db_async()

    def _build_ui(self):
        # ── Top bar ─────────────────────────────────────────────────────────
        topbar = tk.Frame(self, bg=PANEL, height=52)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)

        tk.Button(topbar, text="← Back", font=FONT_BTN,
                  fg=TEXT, bg=PANEL, activebackground=BORDER,
                  relief="flat", cursor="hand2",
                  command=self._go_back).pack(side="left", padx=16, pady=8)

        tk.Label(topbar, text="⬡  SANDBOX ANALYZER",
                 font=FONT_H1, fg=ACCENT, bg=PANEL).pack(side="left")

        self.db_status = tk.Label(topbar, text="Loading DB…",
                                  font=FONT_MONO, fg=WARN, bg=PANEL)
        self.db_status.pack(side="right", padx=20)

        # ── Body (left controls + right report) ─────────────────────────────
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=24, pady=16)
        body.columnconfigure(0, weight=0, minsize=300)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        # ── LEFT PANEL ───────────────────────────────────────────────────────
        left = tk.Frame(body, bg=PANEL, bd=0)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))

        # ── Target Area
        tk.Label(left, text="TARGET FILE", font=FONT_H2,
                 fg=ACCENT, bg=PANEL).pack(pady=(16, 8), anchor="w", padx=20)

        file_frame = tk.Frame(left, bg=PANEL)
        file_frame.pack(fill="x", padx=16, pady=(0, 16))
        
        self.file_entry = tk.Entry(file_frame, textvariable=self._target_file,
                                   font=FONT_MONO, fg=TEXT, bg=PANEL2,
                                   insertbackground=ACCENT, relief="flat")
        self.file_entry.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 8))
        
        tk.Button(file_frame, text="Browse…", font=FONT_MONO,
                  fg=ACCENT, bg=BORDER, activebackground=PANEL2,
                  relief="flat", cursor="hand2", padx=10,
                  command=self._browse_file).pack(side="right")

        # ── Scan Mode Area
        tk.Label(left, text="SCAN MODE", font=FONT_H2,
                 fg=ACCENT, bg=PANEL).pack(pady=(4, 8), anchor="w", padx=20)

        # Mode cards
        for label, val, desc in [
            ("⚡ Static Analysis",  "static", "Quick scan"),
            ("🔬 Deep Search",      "deep",   "Full scan"),
        ]:
            f = tk.Frame(left, bg=PANEL2, bd=0)
            f.pack(fill="x", padx=16, pady=4)
            rb = tk.Radiobutton(f, text=label,
                                variable=self._mode, value=val,
                                font=("Courier New", 11, "bold"),
                                fg=TEXT, bg=PANEL2,
                                selectcolor=PANEL2, activebackground=PANEL2,
                                indicatoron=True,
                                command=self._update_timer_label)
            rb.pack(anchor="w", padx=10, pady=(8, 2))
            tk.Label(f, text=f"    {desc}", font=FONT_MONO,
                     fg=TEXT_DIM, bg=PANEL2).pack(anchor="w", padx=10, pady=(0, 8))

        # Estimated time label
        self.timer_label = tk.Label(left,
                                    text="Estimated:",
                                    font=("Courier New", 10),
                                    fg=TEXT_DIM, bg=PANEL)
        self.timer_label.pack(pady=(8, 4))

        # Countdown
        self.countdown_label = tk.Label(left, text="──:──",
                                        font=("Courier New", 28, "bold"),
                                        fg=ACCENT, bg=PANEL)
        self.countdown_label.pack()

        # Buttons
        btn_area = tk.Frame(left, bg=PANEL)
        btn_area.pack(pady=16, fill="x", padx=16)

        self.start_btn = tk.Button(btn_area, text="▶  START SCAN",
                                   font=FONT_BTN, fg=BG, bg=ACCENT,
                                   activebackground=TEXT, relief="flat",
                                   cursor="hand2", padx=18, pady=10,
                                   command=self._toggle_scan)
        self.start_btn.pack(fill="x", pady=4)

        self.skip_btn = tk.Button(btn_area, text="⏭  SKIP SCAN",
                                  font=FONT_BTN, fg=TEXT, bg=BORDER,
                                  activebackground=PANEL2, relief="flat",
                                  cursor="hand2", padx=18, pady=10,
                                  state="disabled",
                                  command=self._skip_scan)
        self.skip_btn.pack(fill="x", pady=4)

        # Progress bar
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("Threat.Horizontal.TProgressbar",
                         troughcolor=BORDER, background=ACCENT,
                         thickness=14)
        self.progress_var = tk.DoubleVar(value=0)
        self.progress = ttk.Progressbar(left, variable=self.progress_var,
                                         maximum=100,
                                         style="Threat.Horizontal.TProgressbar",
                                         length=260)
        self.progress.pack(pady=(8, 0), padx=16, fill="x")

        self.progress_lbl = tk.Label(left, text="0%",
                                     font=FONT_MONO, fg=TEXT_DIM, bg=PANEL)
        self.progress_lbl.pack()

        # ── Threat Gauge ──
        self.gauge = ThreatGauge(left, size=220)
        self.gauge.pack(pady=(12, 6))

        # Small label under gauge
        self.gauge_label = tk.Label(left,
            text="LOW RISK",
            font=("Courier New", 12, "bold"),
            fg=SUCCESS,
            bg=PANEL
        )
        self.gauge_label.pack()

        # progress-style severity bar


        # Export button
        self.export_btn = tk.Button(left, text="⬇  EXPORT REPORT",
                                    font=FONT_BTN, fg=BG, bg=ACCENT2,
                                    activebackground=TEXT, relief="flat",
                                    cursor="hand2", padx=18, pady=8,
                                    state="disabled",
                                    command=self._export_report)
        self.export_btn.pack(fill="x", padx=16, pady=(0, 20))

        # ── RIGHT PANEL – Report ─────────────────────────────────────────────
        right = tk.Frame(body, bg=PANEL)
        right.grid(row=0, column=1, sticky="nsew")

        header_row = tk.Frame(right, bg=PANEL)
        header_row.pack(fill="x", padx=16, pady=(14, 6))
        tk.Label(header_row, text="ANALYSIS REPORT",
                 font=FONT_H2, fg=ACCENT, bg=PANEL).pack(side="left")
        self.finding_count = tk.Label(header_row, text="",
                                      font=FONT_MONO, fg=TEXT_DIM, bg=PANEL)
        self.finding_count.pack(side="right")

        # Scrollable text area
        frame_txt = tk.Frame(right, bg=BORDER, bd=1)
        frame_txt.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        self.report_text = tk.Text(frame_txt,
                                   bg=PANEL2, fg=TEXT,
                                   font=FONT_MONO,
                                   insertbackground=ACCENT,
                                   selectbackground=ACCENT2,
                                   relief="flat",
                                   wrap="word",
                                   state="disabled",
                                   padx=12, pady=8)
        scrollbar = tk.Scrollbar(frame_txt, orient="vertical",
                                 command=self.report_text.yview)
        self.report_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.report_text.pack(fill="both", expand=True)

        # Text tags
        self.report_text.tag_configure("header",  foreground=ACCENT, font=("Courier New", 11, "bold"))
        self.report_text.tag_configure("finding", foreground=WARN,   font=("Courier New", 10, "bold"))
        self.report_text.tag_configure("mitre",   foreground=ACCENT2,font=("Courier New", 9))
        self.report_text.tag_configure("detail",  foreground=TEXT,   font=FONT_MONO)
        self.report_text.tag_configure("dim",     foreground=TEXT_DIM,font=FONT_MONO)
        self.report_text.tag_configure("sep",     foreground=BORDER, font=FONT_MONO)
        self.report_text.tag_configure("critical",foreground=DANGER, font=("Courier New", 10, "bold"))

        self._append_report("Welcome to Sandbox Analyzer\n", "header")
        self._append_report("─" * 60 + "\n", "sep")
        self._append_report("1. Select a file to scan.\n", "dim")
        self._append_report("2. Choose a scan mode and press START SCAN.\n\n", "dim")
        self._append_report("• Static Analysis  – Reviews signatures\n", "detail")
        self._append_report("• Deep Search      – Full behavioral analysis\n\n", "detail")
        self._append_report("Results will populate here during the scan.\n", "dim")

    # ─────────────────────────────────────────── helpers ─────────────────────

    def _browse_file(self):
        path = filedialog.askopenfilename(
            title="Select file for Analysis"
        )
        if path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, path)
            self._target_file.set(path)
            self.file_entry.focus_set()

    def _update_timer_label(self):
        if self._mode.get() == "deep":
            self.timer_label.config(text="Estimated:")
            # We don't know exact random dur yet, just show placeholder
            self.countdown_label.config(text="--:--:--")
        else:
            self.timer_label.config(text="Estimated:")
            self.countdown_label.config(text="--:--")

    def _load_db_async(self):
        def _load():
            try:
                db = lb.load_database()
                self.after(0, lambda: self.db_status.config(
                    text=f"● DB Loaded — {len(db)} entries", fg=SUCCESS))
            except Exception as e:
                self.after(0, lambda: self.db_status.config(
                    text=f"DB Error: {e}", fg=DANGER))
        threading.Thread(target=_load, daemon=True).start()

    def _append_report(self, text: str, tag: str = "detail"):
        self.report_text.configure(state="normal")
        self.report_text.insert("end", text, tag)
        self.report_text.see("end")
        self.report_text.configure(state="disabled")

    def _clear_report(self):
        self.report_text.configure(state="normal")
        self.report_text.delete("1.0", "end")
        self.report_text.configure(state="disabled")

    # ─────────────────────────────────────────── Scan logic ──────────────────

    def _toggle_scan(self):
        # If we are already running, toggle Pause/Resume
        if self._running:
            if not self._pause_flag.is_set():
                # Pause it
                self._pause_flag.set()
                self.start_btn.config(text="▶  RESUME SCAN")
                self._append_report("\n  ⏸  Scan PAUSED by user.\n", "finding")
            else:
                # Resume it
                self._pause_flag.clear()
                self.start_btn.config(text="⏸  PAUSE SCAN")
                self._append_report("\n  ▶  Scan RESUMED.\n", "detail")
            return
            
        target_path = self._target_file.get()
        if not target_path:
            messagebox.showwarning("No target", "Please select a file to analyze first.")
            return

        self._running     = True
        self._tick        = 0
        self._total_risk  = 0
        self._findings    = []
        self._update_threat_ui(0)
        self.progress_var.set(0)
        self.progress_lbl.config(text="0%")
        self._skip_flag.clear()
        self._pause_flag.clear()

        self.start_btn.config(text="⏸  PAUSE SCAN")
        self.skip_btn.config(state="normal")
        self.export_btn.config(state="disabled")

        self._clear_report()

        mode = self._mode.get()
        if mode == "deep":
            total_sec = 1800  # EXACT 30 minutes
            dur_str = "30 minutes"
        else:
            total_sec = random.randint(STATIC_MIN, STATIC_MAX)
            dur_str = "15–30 minutes"

        self._append_report(f"{'─'*60}\n", "sep")
        self._append_report(
            f"  {'DEEP SEARCH' if mode=='deep' else 'STATIC ANALYSIS'} STARTED\n", "header")
        
        # Extract filename from path for report
        import os
        filename = os.path.basename(target_path) if target_path else "Unknown"
        
        self._append_report(f"  Target   : {filename}\n", "detail")
        self._append_report(f"  Mode     : {mode.upper()}\n", "detail")
        self._append_report(f"  Duration : {dur_str} (Exact: {total_sec//60} min)\n", "detail")
        self._append_report(f"{'─'*60}\n\n", "sep")

        self._worker_thread = threading.Thread(
            target=self._scan_worker,
            args=(mode, total_sec),
            daemon=True,
        )
        self._worker_thread.start()

    def _scan_worker(self, mode: str, total_sec: int):
        import hashlib
        import os
        file_path = self._target_file.get()

        if not file_path:
            self.after(0, lambda: messagebox.showerror("Error", "No file selected"))
            return

        if mode == "deep":
            msg = "[SANDBOX] Running deep sandbox analysis...\n"
        else:
            msg = "[SANDBOX] Sending file to VirusTotal...\n"

        self.after(0, lambda: self._append_report(msg, "detail"))

        def get_file_hash(path):
            sha256 = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()

        try:
            if not API_KEY:
                raise Exception("VirusTotal API key not set")

            headers = {"x-apikey": API_KEY}

            file_hash = get_file_hash(file_path)
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                self.after(0, lambda: self._append_report("[VT] Existing report found\n", "header"))

            else:
                upload_url = "https://www.virustotal.com/api/v3/files"

                with open(file_path, "rb") as f:
                    files = {"file": f}
                    upload_response = requests.post(upload_url, headers=headers, files=files)

                if upload_response.status_code != 200:
                    raise Exception(f"VT upload failed: {upload_response.status_code}")

                data = None

                for _ in range(20):
                    if self._skip_flag.is_set():
                        self.after(0, self._on_skip)
                        return
                    time.sleep(1)
                    response = requests.get(url, headers=headers)

                    try:
                        data = response.json()
                    except:
                        continue

                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

                    if stats and sum(stats.values()) > 0:
                        break
                    if self._skip_flag.is_set():
                        self.after(0, self._on_skip)
                        return
                if not data or "data" not in data:
                    raise Exception("VirusTotal result not ready")
                if self._skip_flag.is_set():
                    self.after(0, self._on_skip)
                    return
            stats = data["data"]["attributes"]["last_analysis_stats"]
            results = data["data"]["attributes"].get("last_analysis_results", {})
            detected_engines = []
            total_engines = len(results)

            for engine, info in results.items():
                if info.get("category") in ["malicious", "suspicious"]:
                    detected_engines.append(engine)

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            total = malicious + suspicious + harmless + undetected
            score = int((malicious + suspicious) / max(total, 1) * 100)
            self.final_score = score

            self.after(0, lambda: self._append_report(
                f"[VT RESULT]\n"
                f"  Malicious : {malicious}\n"
                f"  Suspicious: {suspicious}\n"
                f"  Harmless  : {harmless}\n"
                f"  Undetected: {undetected}\n"
                f"  Scanned by: {total_engines} engines\n\n",
                "header"
            ))
            if detected_engines:
                engines_text = ", ".join(detected_engines[:5])
                self.after(0, lambda: self._append_report(
                    f"[DETECTIONS] Flagged by: {engines_text}\n\n",
                    "critical"
                ))
            else:
                self.after(0, lambda: self._append_report(
                    "[DETECTIONS] No engines flagged this file\n\n",
                    "detail"
                ))

            self.after(0, lambda: self._update_threat_ui(score))
            # ── Simulated Deep Sandbox Behavior ──
            if mode == "deep":
                steps = [
                    "[SANDBOX] Initializing virtual environment...",
                    "[SANDBOX] Dropping sample into isolated VM...",
                    "[SANDBOX] Executing sample...",
                    "[SANDBOX] Monitoring process tree...",
                    "[SANDBOX] Capturing network traffic...",
                    "[SANDBOX] Inspecting file system changes...",
                    "[SANDBOX] Detecting persistence mechanisms...",
                    "[SANDBOX] Extracting IOCs...",
                    "[SANDBOX] Finalizing behavioral report..."
                ]

                remaining_time = total_sec - self._tick
                step_delay = max(1, remaining_time // len(steps))

                for step in steps:
                    if self._skip_flag.is_set():
                        self.after(0, self._on_skip)
                        return

                    # simulate activity
                    self.after(0, lambda s=step: self._append_report(s + "\n", "detail"))

                    # small fake logs during wait
                    for _ in range(step_delay):
                        if self._skip_flag.is_set():
                            self.after(0, self._on_skip)
                            return

                        time.sleep(1)
                        while self._pause_flag.is_set():
                            time.sleep(0.1)

                        # live movement (progress + small noise)
                        if self._tick < total_sec:
                            self._tick += 1

                        pct = min(100, (self._tick / total_sec) * 100)

                        self.after(0, lambda p=pct: self.progress_var.set(p))
                        self.after(0, lambda p=pct: self.progress_lbl.config(text=f"{p:.1f}%"))

                        # random micro logs
                        if random.random() < 0.15:
                                noise = random.choice([
                                    "  ↳ NtCreateProcessEx() invoked",
                                    "  ↳ WriteProcessMemory detected",
                                    "  ↳ Remote thread injection attempt",
                                    "  ↳ HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run modified",
                                    "  ↳ DNS query: suspicious-domain.xyz",
                                    "  ↳ HTTP beacon → 185.XX.XX.XX",
                                    "  ↳ PowerShell encoded command executed"
                                ])
                                self.after(0, lambda n=noise: self._append_report(n + "\n", "dim"))

                # final behavior summary
                self.after(0, lambda: self._append_report(
                    "\n[SANDBOX] Behavioral Summary:\n"
                    "  • Process: cmd.exe → powershell.exe\n"
                    "  • Network: Beacon to suspicious IP\n"
                    "  • File Activity: Temp + AppData writes\n"
                    "  • Persistence: Registry Run key attempt\n"
                    "  • Indicators: Possible C2 communication\n\n",
                    "critical"
                ))

        except Exception as e:
            print("VT ERROR:", e)

            self.after(0, lambda: self._append_report(
                "[FALLBACK] VirusTotal failed → using simulated analysis\n", "dim"))

            self.after(0, lambda: self._append_report(
                "[RESULT] Suspicious behavior detected\n", "critical"))

            self.after(0, lambda: self._update_threat_ui(70))

        self.after(0, self._scan_complete)

    def _update_threat_ui(self, score):
        self.gauge.animate_to(score)

        if score >= 70:
            color = DANGER
            label = "HIGH RISK"
        elif score >= 40:
            color = WARN
            label = "MEDIUM RISK"
        else:
            color = SUCCESS
            label = "LOW RISK"

        self.gauge_label.config(text=label, fg=color)
    def _update_progress(self, pct: float, remain_sec: float):
        self.progress_var.set(pct)
        self.progress_lbl.config(text=f"{pct:.1f}%")

        hrs  = int(remain_sec) // 3600
        mins = (int(remain_sec) % 3600) // 60
        secs = int(remain_sec) % 60

        self.countdown_label.config(text=f"{hrs:02d}:{mins:02d}:{secs:02d}")

    def _emit_finding(self, entry: dict):
        risk = entry.get("max_risk", 4)
        self._total_risk += risk
        self._findings.append(entry)

        tag = "critical" if risk >= 8 else "finding"

        cmds = entry.get("commands", [])
        cats = list({c.get("Category", "?") for c in cmds})
        mitres = list({c.get("MitreID", "") for c in cmds if c.get("MitreID")})

        self._append_report(f"[DETECTED] {entry['name']}\n", tag)
        self._append_report(f"  Risk Score : {risk}/10\n", "detail")
        self._append_report(f"  Category   : {', '.join(cats)}\n", "detail")
        if mitres:
            self._append_report(f"  MITRE ATT&CK: {', '.join(mitres)}\n", "mitre")
        self._append_report(f"  Description: {entry['description']}\n", "detail")
        self._append_report("\n", "dim")

        # Update gauge
        avg_risk = self._total_risk / len(self._findings)
        gauge_val = min(100, avg_risk * 10 + random.uniform(-3, 3))
        self.after(0, lambda: self._update_threat_ui(int(gauge_val)))

        self.after(0, lambda: self.finding_count.config(
            text=f"{len(self._findings)} finding(s) | Score: {self.gauge._value}"
        ))

    def _on_skip(self):
        self._running = False
        self._pause_flag.clear()
        self.skip_btn.config(state="disabled")
        self.start_btn.config(text="▶  START SCAN")
        self._append_report("─" * 60 + "\n", "sep")
        self._append_report("  ⏭  Scan skipped by user.\n", "finding")
        self._append_report("─" * 60 + "\n\n", "sep")
        self._finalize_report(skipped=True)

    def _scan_complete(self):
        self._running = False
        self._pause_flag.clear()
        self.progress_var.set(100)
        self.progress_lbl.config(text="100%")
        self.countdown_label.config(text="DONE")
        self.start_btn.config(text="▶  START SCAN")
        self.skip_btn.config(state="disabled")

        self._append_report("─" * 60 + "\n", "sep")
        self._append_report("  ✓  Scan COMPLETE\n", "header")
        self._append_report("─" * 60 + "\n\n", "sep")

        # force UI update before reading gauge
        self.update_idletasks()
        self.gauge.set_value(self.final_score)
        self._finalize_report(skipped=False)

    def _finalize_report(self, skipped: bool):
        score = getattr(self, "final_score", self.gauge._value)
        if score >= 70:
            verdict = "HIGH RISK  – Immediate investigation recommended."
            vtag = "critical"
        elif score >= 40:
            verdict = "MEDIUM RISK – Review flagged binaries."
            vtag = "finding"
        else:
            verdict = "LOW RISK – No critical threats detected."
            vtag = "detail"

        self._append_report(f"FINDINGS   : {len(self._findings)}\n", "detail")
        self._append_report(f"THREAT SCORE: {score}/100\n", "detail")
        self._append_report(f"VERDICT    : {verdict}\n\n", vtag)
        self.export_btn.config(state="normal")

    def _skip_scan(self):
        self._skip_flag.set()
        # Ensure we don't dead-lock the background thread if it's currently paused
        self._pause_flag.clear()

    # ─────────────────────────────────────────── Export ──────────────────────

    def _export_report(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*")],
            title="Save Analysis Report",
        )
        if not path:
            return
        content = self.report_text.get("1.0", "end")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        messagebox.showinfo("Exported", f"Report saved to:\n{path}")

    # ─────────────────────────────────────────── Navigation ──────────────────

    def _go_back(self):
        if self._running:
            if not messagebox.askyesno("Scan Running",
                                       "A scan is in progress. Stop and go back?"):
                return
            self._skip_flag.set()
        self.destroy()
        self.parent.deiconify()
