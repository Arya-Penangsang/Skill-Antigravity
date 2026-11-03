"""
File Integrity Monitoring (FIM) & System Drop Scanner
Monitors sensitive filesystem directories to detect dropped binaries, masquerading DLLs, and scripts.
Inspired by SystemFileScanner.py & baseline telemetry from research archives.
"""

import os
import hashlib
from typing import Dict, Any, List

class FileIntegrityScanner:
    """Snapshots sensitive OS directories to detect unauthorized file creations or modifications."""

    DEFAULT_WATCH_PATHS = [
        os.environ.get("TEMP", "C:\\Windows\\Temp"),
        os.environ.get("APPDATA", "C:\\Users\\Default\\AppData\\Roaming"),
        os.environ.get("LOCALAPPDATA", "C:\\Users\\Default\\AppData\\Local"),
    ]

    DANGEROUS_EXTENSIONS = [".exe", ".dll", ".bat", ".cmd", ".vbs", ".ps1", ".scr", ".pif", ".hta", ".js", ".jar"]

    def __init__(self, watch_dirs: List[str] = None):
        self.watch_dirs = [os.path.abspath(d) for d in (watch_dirs or self.DEFAULT_WATCH_PATHS) if os.path.exists(d)]
        self.baseline_snapshot: Dict[str, Dict[str, Any]] = {}
        self.post_snapshot: Dict[str, Dict[str, Any]] = {}

    def _scan_directory(self, directory: str, max_depth: int = 2) -> Dict[str, Dict[str, Any]]:
        """Walks directory up to max_depth and logs file metadata."""
        tree = {}
        base_depth = directory.rstrip(os.path.sep).count(os.path.sep)
        try:
            for root, dirs, files in os.walk(directory):
                current_depth = root.count(os.path.sep) - base_depth
                if current_depth > max_depth:
                    continue
                for f in files:
                    full_p = os.path.join(root, f)
                    try:
                        stat = os.stat(full_p)
                        tree[full_p] = {
                            "size": stat.st_size,
                            "mtime": stat.st_mtime,
                            "ext": os.path.splitext(f)[1].lower()
                        }
                    except (PermissionError, FileNotFoundError, OSError):
                        pass
        except Exception:
            pass
        return tree

    def take_baseline(self) -> int:
        """Takes baseline snapshot across watch directories before malware execution."""
        self.baseline_snapshot = {}
        for d in self.watch_dirs:
            self.baseline_snapshot.update(self._scan_directory(d))
        return len(self.baseline_snapshot)

    def take_post_execution(self) -> Dict[str, Any]:
        """Scans again and computes new drops, modifications, and high-risk executables."""
        self.post_snapshot = {}
        for d in self.watch_dirs:
            self.post_snapshot.update(self._scan_directory(d))

        dropped_files = []
        modified_files = []
        high_risk_drops = []

        for f_path, meta in self.post_snapshot.items():
            if f_path not in self.baseline_snapshot:
                # Newly dropped file
                entry = {
                    "path": f_path,
                    "size": meta["size"],
                    "extension": meta["ext"],
                    "is_executable": meta["ext"] in self.DANGEROUS_EXTENSIONS
                }
                dropped_files.append(entry)
                if entry["is_executable"]:
                    # Compute hash for dropped binary
                    try:
                        with open(f_path, "rb") as bf:
                            entry["sha256"] = hashlib.sha256(bf.read()).hexdigest()
                    except Exception:
                        entry["sha256"] = "Unreadable"
                    high_risk_drops.append(entry)

            elif self.baseline_snapshot[f_path]["mtime"] != meta["mtime"]:
                modified_files.append(f_path)

        return {
            "total_new_drops": len(dropped_files),
            "high_risk_executable_drops": high_risk_drops,
            "modified_files_count": len(modified_files),
            "dropper_behavior_confirmed": len(high_risk_drops) > 0
        }
