"""
Unit tests for PackerDetector, RegistryDiffEngine, and NetworkSinkhole.
"""

import unittest
from core.packer_detector import PackerDetector
from core.registry_diff import RegistryDiffEngine
from core.network_sinkhole import NetworkSinkhole
import urllib.request

class TestExtensions(unittest.TestCase):

    def test_packer_detector_non_pe(self):
        detector = PackerDetector(b"This is just plain text")
        result = detector.analyze()
        self.assertFalse(result["is_packed"])
        self.assertEqual(result["detected_compiler"], "Unknown (Non-PE)")

    def test_registry_diff_engine(self):
        engine = RegistryDiffEngine()
        # Mock pre and post snapshots
        engine.pre_snapshot = {
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run": {
                "ExistingApp": "C:\\Program Files\\app.exe"
            }
        }
        engine.post_snapshot = {
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run": {
                "ExistingApp": "C:\\Program Files\\app.exe",
                "MalwarePersistence": "C:\\Windows\\Temp\\payload.exe"
            }
        }
        diff = engine.compute_diff()
        self.assertEqual(diff["total_changes"], 1)
        self.assertTrue(diff["suspicious_persistence_detected"])
        self.assertEqual(diff["added_entries"][0]["value_name"], "MalwarePersistence")

    def test_network_sinkhole(self):
        sinkhole = NetworkSinkhole(http_port=18088)
        sinkhole.start()
        try:
            req = urllib.request.Request("http://127.0.0.1:18088/c2_beacon", headers={"User-Agent": "MalwareAgent/1.0"})
            with urllib.request.urlopen(req) as resp:
                data = resp.read()
                self.assertEqual(data, b"OK")
        finally:
            captured = sinkhole.stop()

        self.assertGreaterEqual(len(captured), 1)
        self.assertEqual(captured[0]["path"], "/c2_beacon")
        self.assertEqual(captured[0]["headers"].get("User-Agent"), "MalwareAgent/1.0")

if __name__ == "__main__":
    unittest.main()
