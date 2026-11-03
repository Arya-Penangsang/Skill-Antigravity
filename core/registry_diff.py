"""
Registry Snapshot and Difference Engine (Regshot Technique)
Detects Windows registry modifications, autorun persistence, and hidden keys.
Inspired by Syai Labs & Yohanes Syailendra, M.Kom practical registry triage methods.
"""

import sys
import winreg
from typing import Dict, Any, List

class RegistryDiffEngine:
    """Snapshots sensitive registry keys and computes differential state."""

    TARGET_HIVES = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"),
    ]

    def __init__(self):
        self.pre_snapshot = {}
        self.post_snapshot = {}

    def _read_key_values(self, hkey, subkey_path: str) -> Dict[str, str]:
        """Safely reads all values from a registry key path."""
        values = {}
        try:
            with winreg.OpenKey(hkey, subkey_path, 0, winreg.KEY_READ) as key:
                num_values = winreg.QueryInfoKey(key)[1]
                for i in range(num_values):
                    name, val, _ = winreg.EnumValue(key, i)
                    values[name] = str(val)
        except (FileNotFoundError, PermissionError, OSError):
            pass
        return values

    def take_pre_snapshot(self) -> Dict[str, Dict[str, str]]:
        """Takes baseline snapshot before malware/sample execution."""
        snapshot = {}
        for hkey, path in self.TARGET_HIVES:
            hive_name = "HKCU" if hkey == winreg.HKEY_CURRENT_USER else "HKLM"
            full_path = f"{hive_name}\\{path}"
            snapshot[full_path] = self._read_key_values(hkey, path)
        self.pre_snapshot = snapshot
        return snapshot

    def take_post_snapshot(self) -> Dict[str, Dict[str, str]]:
        """Takes post-execution snapshot."""
        snapshot = {}
        for hkey, path in self.TARGET_HIVES:
            hive_name = "HKCU" if hkey == winreg.HKEY_CURRENT_USER else "HKLM"
            full_path = f"{hive_name}\\{path}"
            snapshot[full_path] = self._read_key_values(hkey, path)
        self.post_snapshot = snapshot
        return snapshot

    def compute_diff(self) -> Dict[str, Any]:
        """Compares baseline and post snapshots to detect injected persistence."""
        added = []
        modified = []
        removed = []

        all_keys = set(self.pre_snapshot.keys()).union(set(self.post_snapshot.keys()))

        for key_path in all_keys:
            pre_vals = self.pre_snapshot.get(key_path, {})
            post_vals = self.post_snapshot.get(key_path, {})

            # Check for added and modified
            for val_name, post_val in post_vals.items():
                if val_name not in pre_vals:
                    added.append({
                        "key": key_path,
                        "value_name": val_name,
                        "data": post_val,
                        "type": "PERSISTENCE_ADDED"
                    })
                elif pre_vals[val_name] != post_val:
                    modified.append({
                        "key": key_path,
                        "value_name": val_name,
                        "old_data": pre_vals[val_name],
                        "new_data": post_val,
                        "type": "PERSISTENCE_MODIFIED"
                    })

            # Check for removed
            for val_name, pre_val in pre_vals.items():
                if val_name not in post_vals:
                    removed.append({
                        "key": key_path,
                        "value_name": val_name,
                        "data": pre_val,
                        "type": "PERSISTENCE_REMOVED"
                    })

        return {
            "total_changes": len(added) + len(modified) + len(removed),
            "added_entries": added,
            "modified_entries": modified,
            "removed_entries": removed,
            "suspicious_persistence_detected": len(added) > 0 or len(modified) > 0
        }
