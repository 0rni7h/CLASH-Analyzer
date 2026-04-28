"""
lolbas_loader.py
Loads all LOLBAS YAML entries from the local database into memory.
"""
import os
import glob
import yaml

# Sub-directories inside LOLBAS/yml/ to scan
LOLBAS_SUBDIRS = [
    "OSBinaries",
    "OtherMSBinaries",
    "OSLibraries",
    "OSScripts",
    "OtherBinaries",
    "OtherScripts",
    "HonorableMentions",
]

# Risk score per LOLBAS category (0–10)
CATEGORY_RISK = {
    "Execute":          9,
    "Download":         8,
    "Upload":           7,
    "Copy":             6,
    "Encode":           7,
    "Decode":           7,
    "Compile":          8,
    "AWL Bypass":       10,
    "UAC Bypass":       10,
    "Dump":             9,
    "Credentials":      9,
    "ADS":              7,
    "Reconnaissance":   5,
    "SRP Bypass":       8,
    "Defense Evasion":  9,
    "Lateral Movement": 9,
    "Persistence":      9,
}

_db: dict = {}  # name (lower) → entry dict


def _find_yml_root(start: str) -> str | None:
    """Walk up from `start` to find the LOLBAS/yml directory."""
    candidate = os.path.join(start, "LOLBAS", "yml")
    if os.path.isdir(candidate):
        return candidate
    parent = os.path.dirname(start)
    if parent == start:
        return None
    return _find_yml_root(parent)


def load_database(base_dir: str | None = None) -> dict:
    """
    Parse every YAML file in the LOLBAS sub-directories and return a dict
    keyed by binary name (lower-case).

    Args:
        base_dir: Root of the project.  Defaults to the directory containing
                  this file.
    """
    global _db
    if _db:
        return _db

    if base_dir is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))

    yml_root = _find_yml_root(base_dir)
    if yml_root is None:
        raise FileNotFoundError(
            f"Could not locate LOLBAS/yml/ directory inside {base_dir}"
        )

    entries: dict = {}

    for subdir in LOLBAS_SUBDIRS:
        pattern = os.path.join(yml_root, subdir, "*.yml")
        for fpath in glob.glob(pattern):
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                    data = yaml.safe_load(fh)
                if not isinstance(data, dict):
                    continue

                name: str = data.get("Name", os.path.basename(fpath))
                key = name.lower()

                # Compute max risk score from commands
                commands = data.get("Commands", []) or []
                max_risk = 0
                for cmd in commands:
                    cat = cmd.get("Category", "")
                    risk = CATEGORY_RISK.get(cat, 4)
                    if risk > max_risk:
                        max_risk = risk

                entries[key] = {
                    "name":        name,
                    "description": data.get("Description", ""),
                    "commands":    commands,
                    "full_path":   [p.get("Path", "") for p in (data.get("Full_Path") or [])],
                    "detection":   data.get("Detection", []) or [],
                    "resources":   data.get("Resources", []) or [],
                    "source_dir":  subdir,
                    "max_risk":    max_risk,
                    "aliases":     [a.get("Alias", "") for a in (data.get("Aliases") or [])],
                }
            except Exception:
                continue  # Skip malformed files

    _db = entries
    return _db


def get_all_binary_names() -> list[str]:
    """Return a list of all known binary/script names (lower-case)."""
    db = load_database()
    names = list(db.keys())
    # Also include aliases
    for entry in db.values():
        for alias in entry.get("aliases", []):
            if alias:
                names.append(alias.lower())
    return names


def lookup(name: str) -> dict | None:
    """Look up a single binary by name (case-insensitive)."""
    db = load_database()
    return db.get(name.lower())


def get_all_entries() -> list[dict]:
    """Return all database entries as a list."""
    return list(load_database().values())


if __name__ == "__main__":
    db = load_database()
    print(f"Loaded {len(db)} LOLBAS entries.")
    sample = next(iter(db.values()))
    print(f"Sample: {sample['name']} — risk={sample['max_risk']}"
          f" — {len(sample['commands'])} command(s)")
