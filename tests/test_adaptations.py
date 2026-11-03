"""
Unit tests for QuarantineVault, NISTNetworkForensics, and FileIntegrityScanner.
"""

import os
import shutil
import unittest
from core.quarantine_vault import QuarantineVault
from core.network_forensics import NISTNetworkForensics
from core.file_integrity import FileIntegrityScanner

class TestAdaptations(unittest.TestCase):

    def setUp(self):
        self.test_dir = os.path.abspath("test_tmp_env")
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)
        if os.path.exists("test_quarantine"):
            shutil.rmtree("test_quarantine", ignore_errors=True)

    def test_quarantine_and_restore(self):
        vault = QuarantineVault(vault_dir="test_quarantine")
        sample_file = os.path.join(self.test_dir, "fake_malware.exe")
        original_content = b"MZ\x90\x00\x03\x00\x00\x00This is simulated malicious payload!"
        with open(sample_file, "wb") as f:
            f.write(original_content)

        # 1. Quarantine
        entry = vault.quarantine_sample(sample_file, threat_info={"score": 85})
        self.assertTrue(os.path.exists(entry["quarantined_path"]))
        self.assertFalse(os.path.exists(sample_file)) # Original disarmed

        # Verify header is scrambled (not MZ anymore)
        with open(entry["quarantined_path"], "rb") as qf:
            scrambled = qf.read()
            self.assertNotEqual(scrambled[:2], b"MZ")

        # 2. Restore
        restore_dir = os.path.join(self.test_dir, "restored")
        restored_path = vault.restore_sample(entry["quarantined_filename"], restore_dir)
        self.assertTrue(os.path.exists(restored_path))

        with open(restored_path, "rb") as rf:
            restored_content = rf.read()
            self.assertEqual(restored_content, original_content)
            self.assertEqual(restored_content[:2], b"MZ")

    def test_nist_network_forensics(self):
        raw_events = [
            {"method": "GET", "path": "/api/v1/checkin", "headers": {"User-Agent": "Bot/2.0"}, "timestamp": 1700000000},
            {"method": "POST", "path": "/upload/exfil", "headers": {"User-Agent": "Bot/2.0"}, "payload_snippet": "password=secret", "timestamp": 1700000005}
        ]
        forensics = NISTNetworkForensics(raw_events).process()

        self.assertIn("NET-EVD-", forensics["evidence_id"])
        self.assertEqual(forensics["summary"]["total_packets"], 2)
        self.assertTrue(forensics["summary"]["data_exfiltration_detected"])
        self.assertEqual(forensics["summary"]["threat_level"], "CRITICAL")
        self.assertEqual(len(forensics["phases"]["phase_3_analysis"]["mitre_mapping"]), 2)

    def test_file_integrity_scanner(self):
        watch_folder = os.path.join(self.test_dir, "watch")
        os.makedirs(watch_folder, exist_ok=True)

        scanner = FileIntegrityScanner(watch_dirs=[watch_folder])
        baseline_count = scanner.take_baseline()
        self.assertEqual(baseline_count, 0)

        # Drop a suspicious executable
        dropped_exe = os.path.join(watch_folder, "payload.exe")
        with open(dropped_exe, "wb") as f:
            f.write(b"MZ\x00fake")

        diff = scanner.take_post_execution()
        self.assertEqual(diff["total_new_drops"], 1)
        self.assertTrue(diff["dropper_behavior_confirmed"])
        self.assertEqual(diff["high_risk_executable_drops"][0]["extension"], ".exe")

if __name__ == "__main__":
    unittest.main()
