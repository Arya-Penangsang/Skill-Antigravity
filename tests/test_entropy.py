import os
import unittest
from core.static_analyzer import StaticAnalyzer

class TestEntropy(unittest.TestCase):
    def test_entropy_zero_for_empty(self):
        self.assertEqual(StaticAnalyzer.calculate_entropy(b""), 0.0)

    def test_entropy_zero_for_single_repeated_byte(self):
        data = b"A" * 1000
        self.assertEqual(StaticAnalyzer.calculate_entropy(data), 0.0)

    def test_entropy_high_for_random_data(self):
        random_bytes = os.urandom(2048)
        entropy = StaticAnalyzer.calculate_entropy(random_bytes)
        self.assertGreater(entropy, 7.5)

if __name__ == "__main__":
    unittest.main()
