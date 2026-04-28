"""
main.py
Entry point for the LOLBin Security Suite.
Run: python main.py
"""
import tkinter as tk
import sys
from launcher_window import LauncherWindow


def main():
    root = tk.Tk()
    root.withdraw()

    if len(sys.argv) > 1:
        # File passed from agent
        from sandbox_window import SandboxWindow
        app = SandboxWindow(root)
        app._target_file.set(sys.argv[1])
        app.after(500, app._toggle_scan)  # auto start scan
    else:
        app = LauncherWindow(root)

    root.mainloop()

if __name__ == "__main__":
    main()

