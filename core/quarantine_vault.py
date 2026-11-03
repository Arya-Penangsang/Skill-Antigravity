"""
Quarantine Vault Engine
Safely neutralizes and isolates malicious binaries using XOR stream obfuscation.
Inspired by quarantaene.py from Python AntiVirus research archive.
"""

import os
import json
import hashlib
import shutil
from datetime import datetime
from typing import Dict, Any, Optional

class QuarantineVault:
    """Manages secure quarantine storage, neutralizing executables to prevent accidental execution."""

    XOR_KEY = 0x5A # Bitmask key to scramble binary headers (turns MZ / PE into unexecutable gibberish)

    def __init__(self, vault_dir: str = "quarantine"):
        self.vault_dir = vault_dir
        os.makedirs(self.vault_dir, exist_ok=True)
        self.metadata_file = os.path.join(self.vault_dir, "vault_ledger.json")
        self._init_ledger()

    def _init_ledger(self):
        if not os.path.exists(self.metadata_file):
            with open(self.metadata_file, "w", encoding="utf-8") as f:
                json.dump({"vault_created": datetime.utcnow().isoformat(), "entries": []}, f, indent=4)

    def _load_ledger(self) -> Dict[str, Any]:
        try:
            with open(self.metadata_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"vault_created": datetime.utcnow().isoformat(), "entries": []}

    def _save_ledger(self, data: Dict[str, Any]):
        with open(self.metadata_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

    def quarantine_sample(self, file_path: str, threat_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Encrypts sample with XOR key, renames to .quarantined, and logs to ledger."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Sample not found: {file_path}")

        file_name = os.path.basename(file_path)
        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        quarantine_filename = f"{sha256[:16]}_{file_name}.quarantined"
        quarantine_path = os.path.join(self.vault_dir, quarantine_filename)

        # Scramble bytes using XOR
        scrambled = bytearray(b ^ self.XOR_KEY for b in raw_bytes)

        with open(quarantine_path, "wb") as f:
            f.write(scrambled)

        # Attempt to delete original live file
        original_removed = False
        try:
            os.remove(file_path)
            original_removed = True
        except Exception:
            pass

        entry = {
            "original_filename": file_name,
            "original_path": os.path.abspath(file_path),
            "quarantined_filename": quarantine_filename,
            "quarantined_path": os.path.abspath(quarantine_path),
            "sha256": sha256,
            "file_size": len(raw_bytes),
            "quarantined_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "original_removed": original_removed,
            "threat_info": threat_info or {}
        }

        ledger = self._load_ledger()
        ledger["entries"].append(entry)
        self._save_ledger(ledger)

        return entry

    def restore_sample(self, identifier: str, dest_dir: str) -> str:
        """Restores and de-XORs a quarantined file back to its original executable format."""
        ledger = self._load_ledger()
        target_entry = None
        for entry in ledger.get("entries", []):
            if identifier in [entry["quarantined_filename"], entry["sha256"], entry["sha256"][:16], entry["original_filename"]]:
                target_entry = entry
                break

        if not target_entry:
            raise ValueError(f"Quarantined entry not found for identifier: {identifier}")

        q_path = target_entry["quarantined_path"]
        if not os.path.exists(q_path):
            # Check local vault directory
            q_path = os.path.join(self.vault_dir, target_entry["quarantined_filename"])
            if not os.path.exists(q_path):
                raise FileNotFoundError(f"Quarantined file missing from disk: {q_path}")

        with open(q_path, "rb") as f:
            scrambled = f.read()

        # Reverse XOR
        restored_bytes = bytearray(b ^ self.XOR_KEY for b in scrambled)

        os.makedirs(dest_dir, exist_ok=True)
        dest_path = os.path.join(dest_dir, target_entry["original_filename"])
        with open(dest_path, "wb") as f:
            f.write(restored_bytes)

        return dest_path

    def list_entries(self):
        return self._load_ledger().get("entries", [])
