import math
import pytest
from core.static_analyzer import StaticAnalyzer

def test_entropy_zero_for_empty():
    assert StaticAnalyzer.calculate_entropy(b"") == 0.0

def test_entropy_zero_for_single_repeated_byte():
    data = b"A" * 1000
    assert StaticAnalyzer.calculate_entropy(data) == 0.0

def test_entropy_high_for_random_data():
    import os
    random_bytes = os.urandom(2048)
    entropy = StaticAnalyzer.calculate_entropy(random_bytes)
    assert entropy > 7.5
