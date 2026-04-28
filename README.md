# CLASH — Contextual LOLBin And Sandbox Host-Analyzer

CLASH is a Windows desktop security tool built for detecting and analyzing **Living-off-the-Land Binary (LOLBin)** abuse in real time. It combines a local LOLBAS database, live process scanning, PowerShell event log inspection, and VirusTotal integration into a single GUI application.

Built with Python and Tkinter. No browser required — everything runs locally on your machine.

---

## What it does

CLASH has two main modules you can launch from the home screen:

### Sandbox Analyzer
Lets you pick any file on disk and run it through a scan workflow:

- **Static Analysis** — sends the file hash to VirusTotal, pulls back detection results from 60+ AV engines, and displays a threat score.
- **Deep Search** — does the same VirusTotal lookup, then runs an extended simulated behavioral sandbox (process tree monitoring, network beacon detection, persistence checks, IOC extraction). Useful for demo/training scenarios.

The scan produces a full report with per-engine verdicts, a visual threat gauge, and an exportable `.txt` summary.

### LOLBin Analyzer
Scans all currently running processes on the system for suspicious LOLBin activity:

- Enumerates processes via both WMI and psutil for maximum coverage.
- Cross-references every running binary against a local copy of the [LOLBAS](https://lolbas-project.github.io/) YAML database (~150+ entries across OSBinaries, OtherMSBinaries, OSLibraries, OSScripts, etc.).
- Detects evasion techniques in command lines — encoded commands, `ExecutionPolicy Bypass`, hidden windows, `IEX` download cradles, base64 blobs, memory injection APIs, and more.
- Pulls recent PowerShell script execution history from Windows Event Logs (Event IDs 400, 800, 4104).
- Displays results in an embedded terminal-style view with color-coded severity.

It can also run in **auto-scan** mode, continuously re-scanning at intervals.

Requests admin privileges on launch so it can inspect command lines of all running processes (falls back to limited mode if you decline).

---

## Project Structure

```
CLASH/
├── main.py                 # Entry point — launches the GUI
├── launcher_window.py      # Home screen with animated logo and module cards
├── sandbox_window.py       # Sandbox Analyzer module (VT integration + deep scan)
├── lolbin_analyzer.py      # LOLBin Analyzer module (live process scanner)
├── lolbas_loader.py        # Parses all LOLBAS YAML files into an in-memory DB
├── agent.py                # Background agent — monitors Downloads folder + LOLBin processes
├── LOLBAS/                 # Local clone of the LOLBAS project (YAML definitions)
│   └── yml/
│       ├── OSBinaries/
│       ├── OtherMSBinaries/
│       ├── OSLibraries/
│       └── ...
└── test_scripts/           # Sample PowerShell scripts for testing detection
    ├── test1_cradle.ps1
    ├── test2_encoded.ps1
    └── test3_lolbin_regsvr.ps1
```

---

## Requirements

- **OS:** Windows 10/11 (uses WMI, Windows Event Logs, and Win32 APIs)
- **Python:** 3.10+
- **Dependencies:**

```
pip install psutil pyyaml watchdog requests
```

You'll also need a **VirusTotal API key** for the Sandbox Analyzer's file scanning feature. Set it as an environment variable:

```
set VT_API_KEY=your_api_key_here
```

Free-tier VT keys work fine — the tool only makes a couple of requests per scan.

---

## How to run

```
python main.py
```

This opens the launcher window. From there, pick either Sandbox Analyzer or LOLBin Analyzer.

If you want the background agent (watches your Downloads folder for new files and monitors LOLBin processes in real time):

```
python agent.py
```

The agent will auto-launch the Sandbox GUI whenever a new file lands in `~/Downloads`.

---

## Testing detection

There are a few harmless test scripts in `test_scripts/` that simulate common attack patterns — download cradles, encoded commands, and LOLBin abuse via `regsvr32`. You can use these to verify that the analyzer flags them correctly without doing anything destructive.

---

## How the LOLBAS database works

The `LOLBAS/` directory contains a local copy of the [LOLBAS project](https://github.com/LOLBAS-Project/LOLBAS) YAML files. On startup, `lolbas_loader.py` parses every `.yml` file across all subdirectories and builds an in-memory lookup table keyed by binary name.

Each entry includes:
- Known dangerous commands and their MITRE ATT&CK mappings
- A computed risk score (0–10) based on the highest-risk command category
- File paths, aliases, detection guidance, and references

The analyzer uses this database to flag any running process that matches a known LOLBin and has a non-trivial command line.

---

## Limitations

- **VirusTotal dependency** — Sandbox Analyzer needs a valid API key. Without one, it falls back to a simulated analysis.
- **Admin privileges** — LOLBin Analyzer works best with admin rights. Without them, some process command lines won't be visible.
- **Windows only** — heavily relies on WMI, Win32 APIs, and Windows Event Logs.
- **Deep Search timing** — the deep scan mode runs for ~30 minutes by design (simulated behavioral analysis). Use Static for quick results.

---

## License

The LOLBAS database included in this project is from the [LOLBAS Project](https://github.com/LOLBAS-Project/LOLBAS) and is subject to its own license. See `LOLBAS/LICENSE` for details.
