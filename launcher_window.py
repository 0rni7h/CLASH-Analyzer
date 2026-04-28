"""
launcher_window.py
Main launcher / landing window for the LOLBin Security Suite.
"""
import tkinter as tk
from tkinter import font as tkfont
import math

# ── Palette ──────────────────────────────────────────────────────────────────
BG          = "#0a0d14"
PANEL       = "#0f1420"
ACCENT      = "#00e5ff"
ACCENT2     = "#7b2fff"
SUCCESS     = "#00ff88"
TEXT        = "#c9d1e0"
TEXT_DIM    = "#4a5568"
BORDER      = "#1e2940"
BTN_SAND    = "#0d1525"

# ── Fonts ─────────────────────────────────────────────────────────────────────
FONT_TITLE  = ("Courier New", 28, "bold")
FONT_SUB    = ("Courier New", 11)
FONT_BTN    = ("Courier New", 13, "bold")
FONT_MONO   = ("Courier New", 9)


class LauncherWindow(tk.Toplevel):
    """Landing page with animated logo and two navigation cards."""

    def __init__(self, master: tk.Tk):
        super().__init__(master)
        self.master_root = master
        self.title("CLASH Analyzer")
        self.geometry("1920x1080")
        self.minsize(840, 580)
        self.configure(bg=BG)
        self.resizable(True, True)

        self._angle = 0          # for rotating ring animation
        self._pulse = 0.0        # for pulsing glow
        self._pulse_dir = 1

        self._build_ui()
        self._animate()

    # ─────────────────────────────────────────── UI construction ─────────────

    def _build_ui(self):
        # ── Top header ────────────────────────────────────────────────────────
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=40, pady=(36, 0))

        # Animated canvas logo (spinning ring)
        self.logo_canvas = tk.Canvas(header, width=72, height=72,
                                     bg=BG, highlightthickness=0)
        self.logo_canvas.pack(side="left")

        title_frame = tk.Frame(header, bg=BG)
        title_frame.pack(side="left", padx=16)

        tk.Label(title_frame, text="CLASH Analyzer",
                 font=FONT_TITLE, fg=ACCENT, bg=BG).pack(anchor="w")
        tk.Label(title_frame,
                 text="  Contextual LOLBin And Sandbox Host-Analyzer",
                 font=FONT_SUB, fg=TEXT_DIM, bg=BG).pack(anchor="w")

        # Version / status pill
        pill = tk.Frame(header, bg=ACCENT2, bd=0)
        pill.pack(side="right", anchor="n", pady=8)
        tk.Label(pill, text=" v1.0 ", font=FONT_MONO,
                 fg="white", bg=ACCENT2).pack(padx=6, pady=2)

        # ── Separator ─────────────────────────────────────────────────────────
        sep = tk.Canvas(self, height=2, bg=BG, highlightthickness=0)
        sep.pack(fill="x", padx=40, pady=(16, 0))
        sep.create_line(0, 1, 9999, 1, fill=BORDER, width=2)

        # ── Centre tagline ────────────────────────────────────────────────────
        tk.Label(self,
                 text="Select a module to begin analysis",
                 font=("Courier New", 13), fg=TEXT, bg=BG
                 ).pack(pady=(24, 8))

        # ── Card container ────────────────────────────────────────────────────
        card_row = tk.Frame(self, bg=BG)
        card_row.pack(expand=True, fill="both", padx=60, pady=20)
        card_row.columnconfigure(0, weight=1)
        card_row.columnconfigure(1, weight=1)
        card_row.rowconfigure(0, weight=1)

        self.sandbox_card = self._make_card(
            card_row,
            icon="⬡",
            title="Sandbox Analyzer",
            subtitle="Deep behavioral scanning",
            desc=("Run a static or deep-scan analysis on the system.\n"
                  "Detects LOLBin abuse, suspicious activity and\n"
                  "generates a full threat intelligence report."),
            badge_text="DEEP / STATIC",
            badge_color=ACCENT,
            command=self._open_sandbox,
            row=0, col=0,
        )

        self.lolbin_card = self._make_card(
            card_row,
            icon="⚡",
            title="LOLBin Analyzer",
            subtitle="Script & command inspection",
            desc=("Paste or load a PowerShell / CMD script and detect\n"
                  "LOLBAS-matched binaries, encoded payloads, download\n"
                  "cradles and other evasion techniques."),
            badge_text="INSTANT",
            badge_color=ACCENT2,
            command=self._open_lolbin,
            row=0, col=1,
        )

        # ── Footer ────────────────────────────────────────────────────────────
        footer = tk.Frame(self, bg=PANEL, height=36)
        footer.pack(fill="x", side="bottom")
        tk.Label(footer,
                 text=f"  LOLBAS Database  |  OSBinaries · OtherMSBinaries · OSLibraries · OSScripts",
                 font=FONT_MONO, fg=TEXT_DIM, bg=PANEL).pack(side="left", pady=8)
        self.status_label = tk.Label(footer, text="● READY",
                                     font=FONT_MONO, fg=SUCCESS, bg=PANEL)
        self.status_label.pack(side="right", padx=16, pady=8)

    def _make_card(self, parent, *, icon, title, subtitle, desc,
                   badge_text, badge_color, command, row, col):
        """Create a hoverable module card."""
        outer = tk.Frame(parent, bg=BORDER, bd=0)
        outer.grid(row=row, column=col, padx=12, pady=8, sticky="nsew")

        inner = tk.Frame(outer, bg=PANEL, bd=0)
        inner.pack(fill="both", expand=True, padx=2, pady=2)

        # Icon
        tk.Label(inner, text=icon, font=("Courier New", 38),
                 fg=badge_color, bg=PANEL).pack(pady=(28, 4))

        # Title
        tk.Label(inner, text=title, font=("Courier New", 16, "bold"),
                 fg=TEXT, bg=PANEL).pack()

        # Subtitle
        tk.Label(inner, text=subtitle, font=("Courier New", 10),
                 fg=TEXT_DIM, bg=PANEL).pack(pady=(2, 8))

        # Description
        tk.Label(inner, text=desc, font=("Courier New", 10),
                 fg=TEXT, bg=PANEL, justify="center",
                 wraplength=320).pack(padx=20)

        # Badge
        badge_frame = tk.Frame(inner, bg=badge_color)
        badge_frame.pack(pady=14)
        tk.Label(badge_frame, text=f"  {badge_text}  ",
                 font=("Courier New", 9, "bold"),
                 fg="#000000", bg=badge_color).pack(padx=4, pady=2)

        # Launch button
        btn = tk.Button(inner, text=f"Open {title}  →",
                        font=FONT_BTN, fg=BG, bg=badge_color,
                        activebackground=TEXT, activeforeground=BG,
                        relief="flat", cursor="hand2", bd=0,
                        command=command, padx=24, pady=10)
        btn.pack(pady=(0, 28))

        # Hover effects
        def on_enter(e):
            outer.configure(bg=badge_color)
        def on_leave(e):
            outer.configure(bg=BORDER)
        for w in (outer, inner, btn):
            w.bind("<Enter>", on_enter)
            w.bind("<Leave>", on_leave)

        return outer

    # ─────────────────────────────────────────── Animation ───────────────────

    def _animate(self):
        c = self.logo_canvas
        c.delete("all")

        cx, cy, r = 36, 36, 28

        # Outer spinning arc
        self._angle = (self._angle + 4) % 360
        start = self._angle
        extent = 270
        c.create_arc(cx - r, cy - r, cx + r, cy + r,
                     start=start, extent=extent,
                     outline=ACCENT, width=3, style="arc")

        # Inner accent arc
        r2 = 18
        c.create_arc(cx - r2, cy - r2, cx + r2, cy + r2,
                     start=-start, extent=200,
                     outline=ACCENT2, width=2, style="arc")

        # Centre dot pulse
        self._pulse += 0.08 * self._pulse_dir
        if self._pulse >= 1.0 or self._pulse <= 0.0:
            self._pulse_dir *= -1
        pr = int(4 + self._pulse * 4)
        c.create_oval(cx - pr, cy - pr, cx + pr, cy + pr,
                      fill=ACCENT, outline="")

        self.after(33, self._animate)   # ~30 fps

    # ─────────────────────────────────────────── Navigation ──────────────────

    def _open_sandbox(self):
        from sandbox_window import SandboxWindow
        self.withdraw()
        win = SandboxWindow(self)
        win.protocol("WM_DELETE_WINDOW", lambda: self._on_child_close(win))

    def _open_lolbin(self):
        from lolbin_analyzer import LolbinAnalyzerWindow
        self.withdraw()
        win = LolbinAnalyzerWindow(self)
        win.protocol("WM_DELETE_WINDOW", lambda: self._on_child_close(win))

    def _on_child_close(self, win):
        win.destroy()
        self.deiconify()
