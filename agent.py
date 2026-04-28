import time
import threading
import psutil
import subprocess
import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
recent_files = {}

DOWNLOADS_PATH = os.path.join(os.path.expanduser("~"), "Downloads")

# LOLBin process names to watch
LOLBINS = ["powershell.exe", "certutil.exe", "mshta.exe", "cmd.exe",
           "regsvr32.exe", "rundll32.exe", "wscript.exe", "cscript.exe",
           "bitsadmin.exe", "msiexec.exe"]

# Script file extensions that indicate a script is being executed
SCRIPT_EXTENSIONS = (".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
                     ".wsf", ".wsh", ".hta", ".sct")

# Suspicious command-line flags/patterns (case-insensitive)
SUSPICIOUS_PATTERNS = [
    re.compile(r"-[Ee]nc(?:odedCommand)?(?:\s|$)", re.IGNORECASE),
    re.compile(r"-[Ee]xec(?:ution)?[Pp]olicy\s+[Bb]ypass", re.IGNORECASE),
    re.compile(r"-[Ww]indow[Ss]tyle\s+[Hh]idden", re.IGNORECASE),
    re.compile(r"-[Nn]o[Pp](?:rofile)?(?:\s|$)", re.IGNORECASE),
    re.compile(r"-[Nn]on[Ii](?:nteractive)?(?:\s|$)", re.IGNORECASE),
    re.compile(r"\bInvoke-Expression\b|\bIEX\b", re.IGNORECASE),
    re.compile(r"\bDownloadString\b|\bDownloadFile\b", re.IGNORECASE),
    re.compile(r"\bNet\.WebClient\b", re.IGNORECASE),
    re.compile(r"-urlcache", re.IGNORECASE),          # certutil abuse
    re.compile(r"/i:http", re.IGNORECASE),             # regsvr32 abuse
    re.compile(r"mshta\s+(http|javascript:)", re.IGNORECASE),
]

containment = False
if not os.path.exists(DOWNLOADS_PATH):
    os.makedirs(DOWNLOADS_PATH)

# Track PIDs we've already alerted on so we don't spam
_alerted_pids: set[int] = set()

# -------- FILE MONITOR --------
class FileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            now = time.time()

            # remove old entries
            for k in list(recent_files.keys()):
                if now - recent_files[k] >= 10:
                    del recent_files[k]

            if event.src_path in recent_files:
                return

            recent_files[event.src_path] = now

            print(f"[AGENT] New file detected: {event.src_path}")
            trigger_sandbox(event.src_path)


def start_file_monitor():
    observer = Observer()
    observer.schedule(FileHandler(), DOWNLOADS_PATH, recursive=False)
    observer.start()
    return observer


# -------- SANDBOX TRIGGER --------
def trigger_sandbox(file):
    print(f"[SANDBOX] Launching GUI scan for {file}")

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

    subprocess.Popen([
        "python",
        os.path.join(BASE_DIR, "main.py"),
        file
    ])

# -------- LOLBIN MONITOR --------
def _is_suspicious_cmdline(name: str, cmdline: list[str]) -> tuple[bool, str]:
    """
    Check if the full command line of a LOLBin process is suspicious.
    Returns (is_suspicious, reason).
    """
    full_cmd = " ".join(cmdline)

    # 1. Check if a script file is being executed
    for arg in cmdline[1:]:                       # skip the binary itself
        arg_lower = arg.lower().strip('"').strip("'")
        for ext in SCRIPT_EXTENSIONS:
            if arg_lower.endswith(ext):
                return True, f"Executing script: {arg}"

    # 2. Check for suspicious flag/pattern matches
    for pat in SUSPICIOUS_PATTERNS:
        m = pat.search(full_cmd)
        if m:
            return True, f"Suspicious pattern: {m.group(0).strip()}"

    # 3. certutil / bitsadmin download usage
    if "certutil" in name.lower() and ("-urlcache" in full_cmd.lower() or
                                        "-decode" in full_cmd.lower()):
        return True, "Certutil download/decode"

    if "bitsadmin" in name.lower() and "/transfer" in full_cmd.lower():
        return True, "BITSAdmin file transfer"

    return False, ""


def monitor_processes():
    global containment

    while True:
        # Clean up stale PIDs that no longer exist
        active_pids = {p.pid for p in psutil.process_iter(['pid'])}
        _alerted_pids.intersection_update(active_pids)

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid  = proc.info['pid']
                name = proc.info['name']

                if not name:
                    continue
                if name.lower() not in [l.lower() for l in LOLBINS]:
                    continue
                if pid in _alerted_pids:
                    continue                          # already handled

                # Grab the full command line — this is the key fix
                try:
                    cmdline = proc.cmdline()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    continue                          # can't inspect → skip

                if not cmdline:
                    continue

                suspicious, reason = _is_suspicious_cmdline(name, cmdline)

                if suspicious:
                    _alerted_pids.add(pid)
                    full_cmd_str = " ".join(cmdline)
                    print(f"[LOLBIN ALERT] PID {pid} | {name}")
                    print(f"  Command : {full_cmd_str[:200]}")
                    print(f"  Reason  : {reason}")

                    containment = True
                    print("[CONTAINMENT] Enabled")

                    proc.kill()

                    ai_decision(f"{name} — {reason}")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            except Exception as e:
                print(f"[ERROR] {e}")

        time.sleep(2)


# -------- AI SIMULATION --------
def ai_decision(event):
    print("[AI] Analyzing behavior...")

    if "powershell" in event.lower():
        print("[AI] Malicious → Stay in containment")
    else:
        print("[AI] Likely safe → Can exit containment")


# -------- MAIN --------
if __name__ == "__main__":
    observer = start_file_monitor()

    t = threading.Thread(target=monitor_processes)
    t.daemon = True
    t.start()

    print("[SYSTEM] Agent running...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        observer.join()
